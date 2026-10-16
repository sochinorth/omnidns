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
 *   struct centry              header (56 B on LP64, 48 B on ILP32)
 *   struct binding *binds[nbinds]
 *   struct crr rr[nrr]         compact RR records (16 B each)
 *   deps[dsz]                  packed (fingerprint u64, len u8, name)*
 *   data[dlen]                 the key qname (case as inserted) at offset 0,
 *                              then every owner name and rdata, interned:
 *                              a byte string already present in data (an
 *                              owner equal to the qname, a CNAME target, an
 *                              earlier owner, or any suffix of those) is
 *                              referenced instead of stored again.
 *
 * Everything else a lookup needs to rebuild the message (flags, question
 * presence) is in the header; the cached message's id and EDNS are always
 * zero, so they are not kept. Offsets into data are 16-bit: a message whose
 * interned owners and rdata cannot all start below 64 KiB is not cached
 * (only possible for a large TCP answer that expands past 64 KiB).
 */
struct crr {
	uint16_t owner_off, rdata_off;	/* into data */
	uint32_t ttl;
	uint16_t type, cls;
	uint16_t rdlen;
	uint8_t owner_len;
	uint8_t section;
};

_Static_assert(sizeof(struct crr) == 16, "crr layout");

struct centry {
	struct s3_node s3;	/* s3.hash = low 32 bits of the key hash */
	uint32_t gen;		/* low 32 bits of the config generation */
	uint32_t inserted, lifetime;
	uint32_t bytes;		/* accounted size (allocation + overhead) */
	uint16_t qtype, qclass;
	uint16_t flags;		/* header flags incl. 4-bit rcode */
	uint16_t nrr;
	uint16_t ndeps, nbinds;
	uint16_t dsz;		/* packed deps bytes (<= 32 * 264) */
	uint8_t qlen;
	bool has_q;
	struct binding *tail[];	/* binds, then rr, deps, data (see above) */
};

/* 24 (s3) + 16 + 16 = 56 B on LP64; the tail starts pointer-aligned */
_Static_assert(sizeof(struct centry) == sizeof(struct s3_node) + 32, "centry layout");
_Static_assert(sizeof(struct centry) % _Alignof(struct crr) == 0, "crr alignment");

static inline struct binding **e_binds(const struct centry *e)
{
	return (struct binding **)e->tail;
}

static inline const struct crr *e_rr(const struct centry *e)
{
	return (const struct crr *)(e->tail + e->nbinds);
}

static inline const uint8_t *e_deps(const struct centry *e)
{
	return (const uint8_t *)(e_rr(e) + e->nrr);
}

static inline const uint8_t *e_data(const struct centry *e)
{
	return e_deps(e) + e->dsz;
}

static inline const uint8_t *e_qname(const struct centry *e)
{
	return e_data(e);
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
};

#define ENTRY_OVERHEAD CACHE_ENTRY_OVERHEAD

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
	       dns_name_eq(e_qname(e), e->qlen, k->qname, k->qlen);
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
                           uint16_t qtype, uint16_t qclass, uint64_t *hash)
{
	struct ckey k = { .qname = qname, .qlen = qlen, .qtype = qtype, .qclass = qclass };

	*hash = key_hash(qname, qlen, qtype, qclass);
	return hmap_get(&c->map, *hash, &k, key_eq, NULL);
}

/* Re-match every dep against cfg; true if all still map to the same rule. */
static bool deps_valid(const struct centry *e, const struct config *cfg)
{
	const uint8_t *p = e_deps(e);
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

/* Make room for nrr RRs and len bytes in a reset message (nrr == 0). */
static int msg_reserve(struct dns_msg *m, uint16_t nrr, size_t len)
{
	if (nrr > m->rr_cap) {
		struct dns_rr *rr = realloc(m->rr, nrr * sizeof(*rr));

		if (!rr)
			return -ENOMEM;
		m->rr = rr;
		m->rr_cap = nrr;
	}
	if (len > m->buf_cap) {
		uint8_t *b = realloc(m->buf, len);

		if (!b)
			return -ENOMEM;
		m->buf = b;
		m->buf_cap = len;
	}
	return 0;
}

/*
 * Rebuild the cached message into out (already reset), TTLs aged by age.
 * The result has the layout dns_msg_copy produces: per RR, the owner then
 * the rdata, back to back in buf.
 */
static int inflate(const struct centry *e, struct dns_msg *out, uint32_t age)
{
	const struct crr *crr = e_rr(e);
	const uint8_t *data = e_data(e);
	size_t len = 0;
	uint8_t *p;
	uint16_t i;

	out->flags = e->flags;
	if (e->has_q) {
		memcpy(out->qname.data, e_qname(e), e->qlen);
		out->qname.len = e->qlen;
		out->qtype = e->qtype;
		out->qclass = e->qclass;
		out->has_q = true;
	}
	for (i = 0; i < e->nrr; i++)
		len += (size_t)crr[i].owner_len + crr[i].rdlen;
	if (msg_reserve(out, e->nrr, len))
		return -ENOMEM;
	p = out->buf;
	for (i = 0; i < e->nrr; i++) {
		const struct crr *c = &crr[i];
		struct dns_rr *rr = &out->rr[i];

		memcpy(p, data + c->owner_off, c->owner_len);
		rr->owner = p;
		rr->owner_len = c->owner_len;
		p += c->owner_len;
		if (c->rdlen)
			memcpy(p, data + c->rdata_off, c->rdlen);
		rr->rdata = p;
		rr->rdlen = c->rdlen;
		p += c->rdlen;
		rr->section = c->section;
		rr->type = c->type;
		rr->cls = c->cls;
		rr->ttl = c->ttl > age ? c->ttl - age : 0;
	}
	out->nrr = e->nrr;
	out->buf_len = len;
	return 0;
}

int cache_lookup(struct cache *c, const struct config *cfg,
                 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
                 struct dns_msg *out)
{
	uint32_t now = omni_now(), age;
	struct centry *e;
	uint64_t h;

	dns_msg_reset(out);
	e = find(c, qname, qlen, qtype, qclass, &h);
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
	if (inflate(e, out, age)) {
		dns_msg_reset(out);
		return -ENOENT;
	}
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

static uint8_t *pack_deps(uint8_t *p, const struct cache_dep *deps, uint16_t ndeps)
{
	uint16_t i;

	for (i = 0; i < ndeps; i++) {
		memcpy(p, &deps[i].fingerprint, 8);
		p[8] = deps[i].name.len;
		memcpy(p + 9, deps[i].name.data, deps[i].name.len);
		dns_name_lower(p + 9, deps[i].name.len);
		p += 9 + deps[i].name.len;
	}
	return p;
}

/* Interning searches at most this much of data: bounds the work for huge
 * answers; typical answers fit entirely. */
#define INTERN_WINDOW 4096

/*
 * Place s[0..len) in data[0..*dlen): reuse an existing occurrence, else
 * append. Returns its offset, or -1 if it would not be addressable.
 */
static int32_t intern(uint8_t *data, size_t *dlen, const uint8_t *s, size_t len)
{
	const uint8_t *hit;
	size_t off;

	if (!len)
		return 0;
	hit = memmem(data, *dlen < INTERN_WINDOW ? *dlen : INTERN_WINDOW, s, len);
	if (hit)
		return (int32_t)(hit - data);	/* < INTERN_WINDOW */
	off = *dlen;
	if (off > UINT16_MAX)
		return -1;
	memcpy(data + off, s, len);
	*dlen += len;
	return (int32_t)off;
}

/*
 * Build an entry for resp in one allocation. The data area is first sized
 * for the worst case (nothing interned), then the allocation is shrunk to
 * what was used. Returns NULL with *err set.
 */
static struct centry *entry_new(const uint8_t *qname, uint8_t qlen, const struct dns_msg *resp,
				const struct cache_dep *deps, uint16_t ndeps,
				struct binding *const *binds, uint16_t nbinds, int *err)
{
	size_t bsz = (size_t)nbinds * sizeof(*binds), dsz = deps_packed_len(deps, ndeps);
	size_t rsz = (size_t)resp->nrr * sizeof(struct crr), hsz, dmax = qlen, dlen;
	struct centry *e, *n;
	struct crr *crr;
	uint8_t *data;
	uint16_t i;

	for (i = 0; i < resp->nrr; i++)
		dmax += (size_t)resp->rr[i].owner_len + resp->rr[i].rdlen;
	hsz = sizeof(*e) + bsz + rsz + dsz;
	e = calloc(1, hsz + dmax);
	if (!e) {
		*err = -ENOMEM;
		return NULL;
	}
	if (nbinds)
		memcpy(e->tail, binds, bsz);
	e->nbinds = nbinds;
	e->nrr = resp->nrr;
	e->ndeps = ndeps;
	e->dsz = (uint16_t)dsz;
	pack_deps((uint8_t *)e_deps(e), deps, ndeps);
	crr = (struct crr *)e_rr(e);
	data = (uint8_t *)e_data(e);
	memcpy(data, qname, qlen);
	e->qlen = qlen;
	dlen = qlen;
	for (i = 0; i < resp->nrr; i++) {
		const struct dns_rr *rr = &resp->rr[i];
		int32_t oo = intern(data, &dlen, rr->owner, rr->owner_len);
		int32_t ro = intern(data, &dlen, rr->rdata, rr->rdlen);

		if (oo < 0 || ro < 0) {
			free(e);
			*err = -E2BIG;
			return NULL;
		}
		crr[i].owner_off = (uint16_t)oo;
		crr[i].rdata_off = (uint16_t)ro;
		crr[i].owner_len = rr->owner_len;
		crr[i].rdlen = rr->rdlen;
		crr[i].section = rr->section;
		crr[i].type = rr->type;
		crr[i].cls = rr->cls;
		crr[i].ttl = rr->ttl;
	}
	if (dlen < dmax) {
		n = realloc(e, hsz + dlen);
		if (n)
			e = n;
		else
			dlen = dmax;	/* keep the larger block, account for it */
	}
	e->bytes = (uint32_t)(hsz + dlen + ENTRY_OVERHEAD);
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
	int err;

	if (ndeps > CACHE_MAX_DEPS || nbinds > CACHE_MAX_BINDS)
		return -E2BIG;
	if (!lifetime)
		return 0;
	e = entry_new(qname, qlen, resp, deps, ndeps, binds, nbinds, &err);
	if (!e)
		return err;
	if (e->bytes > c->max_bytes) {
		free(e);
		return -E2BIG;
	}
	e->flags = resp->flags;
	e->has_q = resp->has_q;
	old = find(c, qname, qlen, qtype, qclass, &h);
	if (old)
		entry_drop(c, old);
	e->qtype = qtype;
	e->qclass = qclass;
	e->gen = (uint32_t)cfg->gen;
	e->inserted = omni_now();
	e->lifetime = lifetime;
	if (hmap_put(&c->map, h, e)) {
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
