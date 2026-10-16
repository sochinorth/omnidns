// SPDX-License-Identifier: MIT
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
 * Entry layout: everything in ONE allocation.
 *
 *   struct centry              header (48 B on LP64)
 *   struct binding *binds[nbinds]
 *   deps[dsz]                  packed (fingerprint u64, len u8, name)*,
 *                              len 0 = the qname
 *   msg[mlen]                  the answer as dns_build() wrote it: header,
 *                              question (the key: qname in the case it was
 *                              inserted with, uncompressed at offset 12,
 *                              then qtype and qclass), the records; no OPT,
 *                              id 0
 *
 * A hit is served from msg by dns_reply_render(), which patches id, flags,
 * question case and aged TTLs and appends OPT, so nothing is rebuilt.
 */
struct centry {
	struct s3_node s3;	/* s3.hash = low 32 bits of the key hash */
	uint32_t gen;		/* low 32 bits of the config generation */
	uint32_t inserted, lifetime;
	uint32_t bytes;		/* accounted size (allocation + overhead) */
	uint16_t mlen;		/* msg bytes (a message is <= 65535) */
	uint16_t dsz;		/* packed deps bytes (<= 32 * 264) */
	uint8_t ndeps, nbinds;
	uint8_t qlen;
	struct binding *tail[];	/* binds, then deps, msg (see above) */
};

_Static_assert(CACHE_MAX_DEPS <= UINT8_MAX && CACHE_MAX_BINDS <= UINT8_MAX, "centry counts");
/* 24 (s3) + 16 + 7 = 47 B on LP64, padded: the tail starts pointer-aligned */
_Static_assert(sizeof(struct centry) == sizeof(struct s3_node) + 24 || sizeof(void *) != 8,
               "centry layout");

static inline struct binding **e_binds(const struct centry *e)
{
	return (struct binding **)e->tail;
}

static inline const uint8_t *e_deps(const struct centry *e)
{
	return (const uint8_t *)(e->tail + e->nbinds);
}

static inline const uint8_t *e_msg(const struct centry *e)
{
	return e_deps(e) + e->dsz;
}

static inline const uint8_t *e_qname(const struct centry *e)
{
	return e_msg(e) + 12;
}

static inline uint16_t get16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

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
	uint32_t swept;		/* omni_now() of the last cache_sweep_expired() */
};

#define ENTRY_OVERHEAD CACHE_ENTRY_OVERHEAD

uint64_t cache_hash(const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass)
{
	uint64_t t = (uint64_t)qtype << 16 | qclass;

	return dns_name_hash(qname, qlen) ^ (t * 0x9e3779b97f4a7c15ull);
}

static bool key_eq(const void *val, const void *key, void *ctx)
{
	const struct centry *e = val;
	const struct ckey *k = key;

	const uint8_t *q = e_qname(e);

	return e->qlen == k->qlen && get16(q + e->qlen) == k->qtype &&
	       get16(q + e->qlen + 2) == k->qclass && dns_name_eq(q, e->qlen, k->qname, k->qlen);
}

static void entry_free(struct cache *c, struct centry *e)
{
	uint16_t i;

	for (i = 0; i < e->nbinds; i++)
		fakeip_unref(c->fdb, e_binds(e)[i]);
	c->bytes -= e->bytes;
	free(e);
}

/* Drop an entry still linked in the s3 queues. */
static void entry_drop(struct cache *c, struct centry *e)
{
	s3_remove(&c->s3, &e->s3);
	hmap_del_ptr(&c->map, e->s3.hash, e);
	entry_free(c, e);
}

static void s3_on_evict(struct s3fifo *s, struct s3_node *n)
{
	struct cache *c = s->priv;
	struct centry *e = container_of(n, struct centry, s3);

	hmap_del_ptr(&c->map, e->s3.hash, e);
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

	/*
	 * Expiry has a resolution of one second: a second sweep within the
	 * same second finds nothing (every entry it could drop, the first one
	 * dropped). Skipping it keeps a failing bind, which sweeps before its
	 * retry, from walking the whole cache each time.
	 */
	if (now == c->swept)
		return 0;
	c->swept = now;
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
	s3_set_cap(&c->s3, c->max_entries);
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
                           uint16_t qtype, uint16_t qclass, uint64_t hash)
{
	struct ckey k = { .qname = qname, .qlen = qlen, .qtype = qtype, .qclass = qclass };

	return hmap_get(&c->map, hash, &k, key_eq, NULL);
}

/*
 * Re-match every dep against cfg; true if all still map to the same rule.
 * A dep stored with length 0 is the entry's qname (stored in its original
 * case; match_lookup_wire renders names as lowercase text, so case does not
 * matter).
 */
static bool deps_valid(const struct centry *e, const struct config *cfg)
{
	const uint8_t *p = e_deps(e);
	uint64_t fp;
	uint16_t i, idx;

	for (i = 0; i < e->ndeps; i++) {
		memcpy(&fp, p, 8);
		if (p[8])
			idx = match_lookup_wire(cfg->idx, p + 9, p[8]);
		else
			idx = match_lookup_wire(cfg->idx, e_qname(e), e->qlen);
		if (idx == MATCH_NONE || idx >= cfg->nrules || cfg->rules[idx].fingerprint != fp)
			return false;
		p += 9 + p[8];
	}
	return true;
}

int cache_lookup(struct cache *c, const struct config *cfg,
                 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
                 uint64_t hash, struct cache_hit *hit)
{
	uint32_t now = omni_now(), age;
	struct centry *e;

	e = find(c, qname, qlen, qtype, qclass, hash);
	if (!e)
		return -ENOENT;
	age = now > e->inserted ? now - e->inserted : 0;
	if (age >= e->lifetime) {
		entry_drop(c, e);
		return -ENOENT;
	}
	if (e->gen != (uint32_t)cfg->gen) {
		if (!deps_valid(e, cfg)) {
			entry_drop(c, e);
			return -ENOENT;
		}
		e->gen = (uint32_t)cfg->gen;
	}
	s3_touch(&e->s3);
	hit->msg = e_msg(e);
	hit->len = e->mlen;
	hit->age = age;
	return 0;
}

/* Build an entry in one allocation. Returns NULL with *err set. */
static struct centry *entry_new(uint8_t qlen, const uint8_t *msg, size_t mlen,
				const uint8_t *deps, size_t dsz, uint16_t ndeps,
				struct binding *const *binds, uint16_t nbinds, int *err)
{
	size_t bsz = (size_t)nbinds * sizeof(*binds), sz = sizeof(struct centry) + bsz + dsz + mlen;
	struct centry *e = malloc(sz);

	if (!e) {
		*err = -ENOMEM;
		return NULL;
	}
	memset(e, 0, sizeof(*e));
	if (nbinds)
		memcpy(e->tail, binds, bsz);
	e->nbinds = (uint8_t)nbinds;
	e->ndeps = (uint8_t)ndeps;
	e->dsz = (uint16_t)dsz;
	if (dsz)
		memcpy((uint8_t *)e_deps(e), deps, dsz);
	memcpy((uint8_t *)e_msg(e), msg, mlen);
	e->mlen = (uint16_t)mlen;
	e->qlen = qlen;
	e->bytes = (uint32_t)(sz + ENTRY_OVERHEAD);
	return e;
}

int cache_insert(struct cache *c, const struct config *cfg,
                 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
                 uint64_t hash, const uint8_t *msg, size_t mlen, uint32_t lifetime,
                 const uint8_t *deps, size_t dsz, uint16_t ndeps,
                 struct binding *const *binds, uint16_t nbinds)
{
	struct centry *e, *old;
	uint16_t i;
	int err;

	if (ndeps > CACHE_MAX_DEPS || dsz > UINT16_MAX || nbinds > CACHE_MAX_BINDS)
		return -E2BIG;
	if (mlen > UINT16_MAX || mlen < 12 + (size_t)qlen + 4 || get16(msg + 4) != 1 ||
	    !dns_name_eq(msg + 12, qlen, qname, qlen) || get16(msg + 12 + qlen) != qtype ||
	    get16(msg + 12 + qlen + 2) != qclass)
		return -EINVAL;
	if (!lifetime)
		return 0;
	e = entry_new(qlen, msg, mlen, deps, dsz, ndeps, binds, nbinds, &err);
	if (!e)
		return err;
	if (e->bytes > c->max_bytes) {
		free(e);
		return -E2BIG;
	}
	old = find(c, qname, qlen, qtype, qclass, hash);
	if (old)
		entry_drop(c, old);
	e->gen = (uint32_t)cfg->gen;
	e->inserted = omni_now();
	e->lifetime = lifetime;
	if (hmap_put(&c->map, hash, e)) {
		free(e);
		return -ENOMEM;
	}
	for (i = 0; i < nbinds; i++)
		fakeip_ref(binds[i]);
	c->bytes += e->bytes;
	s3_insert(&c->s3, &e->s3, hash);
	maybe_evict(c);
	return 0;
}
