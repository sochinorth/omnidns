// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cache.h"
#include "fakeip.h"
#include "match.h"
#include "util/hash.h"
#include "util/hmap.h"
#include "util/s3fifo.h"
#include "util/time.h"

/*
 * Entry layout: one allocation holding the header, the binding pointers,
 * the lowercased qname and the packed deps (fingerprint, len, name)*.
 * The message lives in its own compact allocation (dns_msg_copy).
 */
struct centry {
	struct s3_node s3;
	uint64_t hash;
	uint64_t gen;
	uint32_t inserted, lifetime;
	uint16_t qtype, qclass;
	uint16_t ndeps, nbinds;
	uint8_t qlen;
	size_t bytes;
	struct dns_msg msg;
	struct binding **binds;
	uint8_t *qname;
	uint8_t *deps;
	uint8_t tail[];
};

struct ckey {
	const uint8_t *qname;
	uint8_t qlen;
	uint16_t qtype, qclass;
};

struct cache {
	struct hmap map;
	struct s3fifo s3;
	struct fakeip_db *fdb;
	uint32_t max_entries;
	size_t max_bytes;
	size_t bytes;
};

#define ENTRY_OVERHEAD 64	/* hmap slot, s3 ghost, allocator slack */

static uint64_t key_hash(const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass)
{
	uint64_t t = (uint64_t)qtype << 16 | qclass;

	return dns_name_hash(qname, qlen) ^ (t * 0x9e3779b97f4a7c15ull);
}

static bool key_eq(const void *val, const void *key, void *ctx)
{
	const struct centry *e = val;
	const struct ckey *k = key;

	return e->qtype == k->qtype && e->qclass == k->qclass &&
	       dns_name_eq(e->qname, e->qlen, k->qname, k->qlen);
}

static void entry_free(struct cache *c, struct centry *e)
{
	uint16_t i;

	for (i = 0; i < e->nbinds; i++)
		fakeip_unref(c->fdb, e->binds[i]);
	c->bytes -= e->bytes;
	dns_msg_free(&e->msg);
	free(e);
}

/* Drop an entry still linked in the s3 queues. */
static void entry_drop(struct cache *c, struct centry *e)
{
	s3_remove(&c->s3, &e->s3);
	hmap_del_ptr(&c->map, e->hash, e);
	entry_free(c, e);
}

static void s3_on_evict(struct s3fifo *s, struct s3_node *n)
{
	struct cache *c = s->priv;
	struct centry *e = container_of(n, struct centry, s3);

	hmap_del_ptr(&c->map, e->hash, e);
	entry_free(c, e);
}

static const struct s3_ops cache_s3_ops = {
	.evict = s3_on_evict,
};

static void evict_bytes(struct cache *c)
{
	size_t low = c->max_bytes / 8 * 7;
	uint32_t n, k;

	if (c->bytes <= c->max_bytes)
		return;
	while (c->bytes > low && (n = s3_count(&c->s3))) {
		k = (uint32_t)((c->bytes - low) * n / c->bytes) + 1;
		if (!s3_evict(&c->s3, k >= n ? 0 : n - k))
			break;
	}
}

static void maybe_evict(struct cache *c)
{
	s3_maybe_evict(&c->s3);
	evict_bytes(c);
}

struct cache *cache_new(uint32_t max_entries, size_t max_bytes, struct fakeip_db *fdb)
{
	struct cache *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	c->fdb = fdb;
	c->max_entries = max_entries ? max_entries : 1;
	c->max_bytes = max_bytes;
	if (s3_init(&c->s3, c->max_entries, &cache_s3_ops, c)) {
		free(c);
		return NULL;
	}
	return c;
}

void cache_flush(struct cache *c)
{
	struct centry *e;
	uint32_t it = 0;

	while ((e = hmap_next(&c->map, &it)))
		entry_drop(c, e);
}

uint32_t cache_sweep_expired(struct cache *c)
{
	uint32_t now = omni_now(), it = 0, n = 0;
	struct centry *e;

	while ((e = hmap_next(&c->map, &it))) {
		if (now > e->inserted && now - e->inserted >= e->lifetime) {
			entry_drop(c, e);
			n++;
		}
	}
	return n;
}

void cache_free(struct cache *c)
{
	if (!c)
		return;
	cache_flush(c);
	hmap_free(&c->map);
	s3_destroy(&c->s3);
	free(c);
}

void cache_set_limits(struct cache *c, uint32_t max_entries, size_t max_bytes)
{
	c->max_entries = max_entries ? max_entries : 1;
	c->max_bytes = max_bytes;
	c->s3.cap = c->max_entries;
	maybe_evict(c);
}

uint32_t cache_count(const struct cache *c)
{
	return hmap_len(&c->map);
}

size_t cache_bytes(const struct cache *c)
{
	return c->bytes;
}

static struct centry *find(struct cache *c, const uint8_t *qname, uint8_t qlen,
			   uint16_t qtype, uint16_t qclass, uint64_t *hash)
{
	struct ckey k = { .qname = qname, .qlen = qlen, .qtype = qtype, .qclass = qclass };

	*hash = key_hash(qname, qlen, qtype, qclass);
	return hmap_get(&c->map, *hash, &k, key_eq, NULL);
}

/* Re-match every dep against cfg; true if all still map to the same rule. */
static bool deps_valid(const struct centry *e, const struct config *cfg)
{
	const uint8_t *p = e->deps;
	uint64_t fp;
	uint16_t i, idx;

	for (i = 0; i < e->ndeps; i++) {
		memcpy(&fp, p, 8);
		idx = match_lookup_wire(cfg->idx, p + 9, p[8]);
		if (idx == MATCH_NONE || idx >= cfg->nrules || cfg->rules[idx].fingerprint != fp)
			return false;
		p += 9 + p[8];
	}
	return true;
}

int cache_lookup(struct cache *c, const struct config *cfg,
		 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
		 struct dns_msg *out)
{
	uint32_t now = omni_now(), age;
	struct centry *e;
	uint64_t h;
	uint16_t i;

	dns_msg_reset(out);
	e = find(c, qname, qlen, qtype, qclass, &h);
	if (!e)
		return -ENOENT;
	age = now > e->inserted ? now - e->inserted : 0;
	if (age >= e->lifetime) {
		entry_drop(c, e);
		return -ENOENT;
	}
	if (e->gen != cfg->gen) {
		if (!deps_valid(e, cfg)) {
			entry_drop(c, e);
			return -ENOENT;
		}
		e->gen = cfg->gen;
	}
	if (dns_msg_copy(out, &e->msg))
		return -ENOENT;
	for (i = 0; i < out->nrr; i++)
		out->rr[i].ttl = out->rr[i].ttl > age ? out->rr[i].ttl - age : 0;
	s3_touch(&e->s3);
	return 0;
}

static size_t deps_packed_len(const struct cache_dep *deps, uint16_t ndeps)
{
	size_t n = 0;
	uint16_t i;

	for (i = 0; i < ndeps; i++)
		n += 9 + deps[i].name.len;
	return n;
}

static struct centry *entry_new(const uint8_t *qname, uint8_t qlen,
				const struct cache_dep *deps, uint16_t ndeps,
				struct binding *const *binds, uint16_t nbinds)
{
	size_t bsz = (size_t)nbinds * sizeof(*binds), dsz = deps_packed_len(deps, ndeps);
	struct centry *e = calloc(1, sizeof(*e) + bsz + qlen + dsz);
	uint8_t *p;
	uint16_t i;

	if (!e)
		return NULL;
	e->binds = (struct binding **)e->tail;
	if (nbinds)
		memcpy(e->binds, binds, bsz);
	e->nbinds = nbinds;
	e->qname = e->tail + bsz;
	memcpy(e->qname, qname, qlen);
	dns_name_lower(e->qname, qlen);
	e->qlen = qlen;
	e->deps = p = e->qname + qlen;
	for (i = 0; i < ndeps; i++) {
		memcpy(p, &deps[i].fingerprint, 8);
		p[8] = deps[i].name.len;
		memcpy(p + 9, deps[i].name.data, deps[i].name.len);
		dns_name_lower(p + 9, deps[i].name.len);
		p += 9 + deps[i].name.len;
	}
	e->ndeps = ndeps;
	e->bytes = sizeof(*e) + bsz + qlen + dsz + ENTRY_OVERHEAD;
	return e;
}

int cache_insert(struct cache *c, const struct config *cfg,
		 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
		 const struct dns_msg *resp, uint32_t lifetime,
		 const struct cache_dep *deps, uint16_t ndeps,
		 struct binding *const *binds, uint16_t nbinds)
{
	struct centry *e, *old;
	uint64_t h;
	uint16_t i;

	if (ndeps > CACHE_MAX_DEPS || nbinds > CACHE_MAX_BINDS)
		return -E2BIG;
	if (!lifetime)
		return 0;
	e = entry_new(qname, qlen, deps, ndeps, binds, nbinds);
	if (!e)
		return -ENOMEM;
	if (dns_msg_copy(&e->msg, resp)) {
		free(e);
		return -ENOMEM;
	}
	memset(&e->msg.edns, 0, sizeof(e->msg.edns));
	e->msg.id = 0;
	e->bytes += dns_msg_footprint(&e->msg);
	if (e->bytes > c->max_bytes) {
		dns_msg_free(&e->msg);
		free(e);
		return -E2BIG;
	}
	old = find(c, qname, qlen, qtype, qclass, &h);
	if (old)
		entry_drop(c, old);
	e->hash = h;
	e->qtype = qtype;
	e->qclass = qclass;
	e->gen = cfg->gen;
	e->inserted = omni_now();
	e->lifetime = lifetime;
	if (hmap_put(&c->map, h, e)) {
		dns_msg_free(&e->msg);
		free(e);
		return -ENOMEM;
	}
	for (i = 0; i < nbinds; i++)
		fakeip_ref(binds[i]);
	c->bytes += e->bytes;
	s3_insert(&c->s3, &e->s3, h);
	maybe_evict(c);
	return 0;
}
