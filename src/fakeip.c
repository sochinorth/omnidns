// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "fakeip.h"
#include "log.h"
#include "nft.h"
#include "util/hash.h"
#include "util/time.h"

struct rule_str {
	uint64_t hash;
	uint32_t ref;
	char s[];
};

struct mark_cnt {
	uint32_t mark;
	uint32_t cnt;
};

struct fakeip_db {
	bool has4, has6;
	struct ip_prefix p4, p6;
	uint32_t max_bindings;
	uint32_t grace;
	uint8_t secret[16];
	struct nft_ctx *nft;
	struct hmap by_key;	/* khash -> binding */
	struct hmap by_fake;	/* fhash -> binding */
	struct hmap rules;	/* interned rule_id strings */
	struct hmap marks;	/* mark -> count */
	struct s3fifo s3;
};

/* lookup key, endpoint already lowercased */
struct bkey {
	const char *rule_id;
	uint32_t mark;
	uint8_t family;
	uint8_t endpoint_len;
	const uint8_t *endpoint;
	const uint8_t *real;
};

struct fkey {
	uint8_t family;
	const uint8_t *fake;
};

static inline int alen(int family)
{
	return family == 4 ? 4 : 16;
}

static int norm_family(int family)
{
	if (family == 4 || family == AF_INET)
		return 4;
	if (family == 6 || family == AF_INET6)
		return 6;
	return 0;
}

static inline uint8_t lower(uint8_t c)
{
	return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static bool binding_evictable(const struct binding *b, uint32_t now)
{
	return b->safe_until < now && !b->refcnt;
}

static bool binding_detached(const struct binding *b)
{
	return !b->s3.list.next;
}

/* ---- pools ---- */

static const struct ip_prefix *db_pool(const struct fakeip_db *db, int family)
{
	if (family == 4)
		return db->has4 ? &db->p4 : NULL;
	if (family == 6)
		return db->has6 ? &db->p6 : NULL;
	return NULL;
}

static uint64_t pool_usable(const struct ip_prefix *p, int family)
{
	unsigned h;

	if (family == 4) {
		if (p->plen > 30)
			return 0;
		return (1ull << (32 - p->plen)) - 2;
	}
	h = 128 - p->plen;
	if (!h)
		return 0;
	return h >= 64 ? UINT64_MAX : (1ull << h) - 1;
}

static uint32_t load32be(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static uint64_t load64be(const uint8_t *p)
{
	return (uint64_t)load32be(p) << 32 | load32be(p + 4);
}

static void store32be(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

/* the (off+1)-th address of the pool; off < pool_usable() */
static void pool_addr(const struct ip_prefix *p, int family, uint64_t off, uint8_t *out)
{
	uint64_t v = off + 1;
	int i;

	if (family == 4) {
		store32be(out, load32be(p->addr) + (uint32_t)v);
		return;
	}
	memcpy(out, p->addr, 16);
	for (i = 15; i >= 0 && v; i--) {
		v += out[i];
		out[i] = v & 0xff;
		v >>= 8;
	}
}

static bool prefix_match(const struct ip_prefix *p, int family, const uint8_t *addr)
{
	unsigned full = p->plen / 8, rem = p->plen % 8;

	if (p->plen > (family == 4 ? 32 : 128))
		return false;
	if (memcmp(p->addr, addr, full))
		return false;
	if (rem && ((p->addr[full] ^ addr[full]) & (0xff00 >> rem)))
		return false;
	return true;
}

/* addr inside the pool and not excluded */
static bool pool_allocatable(const struct ip_prefix *p, int family, const uint8_t *addr)
{
	uint64_t usable = pool_usable(p, family), host;
	unsigned h;

	if (!prefix_match(p, family, addr))
		return false;
	if (family == 4) {
		h = 32 - p->plen;
		host = load32be(addr) & (h >= 32 ? UINT32_MAX : ((1u << h) - 1));
		return host >= 1 && host <= usable;
	}
	h = 128 - p->plen;
	if (h > 64 && memcmp(addr, p->addr, 8))
		return false;	/* beyond the low 2^64 addresses */
	host = load64be(addr + 8) & (h >= 64 ? UINT64_MAX : ((1ull << h) - 1));
	return host >= 1 && host <= usable;
}

/* ---- keys ---- */

static uint64_t key_hash(const struct fakeip_db *db, const struct bkey *k)
{
	uint8_t buf[8 + 4 + 1 + 1 + 255 + 16], *p = buf;
	uint64_t rh = siphash24(db->secret, k->rule_id, strlen(k->rule_id));
	int i;

	for (i = 0; i < 8; i++)
		*p++ = rh >> (8 * i);
	for (i = 0; i < 4; i++)
		*p++ = k->mark >> (8 * i);
	*p++ = k->family;
	*p++ = k->endpoint_len;
	memcpy(p, k->endpoint, k->endpoint_len);
	p += k->endpoint_len;
	memcpy(p, k->real, alen(k->family));
	p += alen(k->family);
	return siphash24(db->secret, buf, p - buf);
}

static uint64_t fake_hash(int family, const uint8_t *fake)
{
	uint8_t buf[17];

	buf[0] = family;
	memcpy(buf + 1, fake, alen(family));
	return omni_hash(buf, 1 + alen(family));
}

static bool key_eq(const void *val, const void *key, void *ctx)
{
	const struct binding *b = val;
	const struct bkey *k = key;

	return b->mark == k->mark && b->family == k->family &&
	       b->endpoint_len == k->endpoint_len &&
	       !memcmp(b->endpoint, k->endpoint, k->endpoint_len) &&
	       !memcmp(b->real, k->real, alen(k->family)) &&
	       !strcmp(b->rule_id, k->rule_id);
}

static bool fake_eq(const void *val, const void *key, void *ctx)
{
	const struct binding *b = val;
	const struct fkey *k = key;

	return b->family == k->family && !memcmp(b->fake, k->fake, alen(k->family));
}

/* ---- rule_id interning ---- */

static bool rule_eq(const void *val, const void *key, void *ctx)
{
	return !strcmp(((const struct rule_str *)val)->s, key);
}

static const char *rule_get(struct fakeip_db *db, const char *id)
{
	uint64_t h = omni_hash(id, strlen(id));
	struct rule_str *r = hmap_get(&db->rules, h, id, rule_eq, NULL);
	size_t len;

	if (r) {
		r->ref++;
		return r->s;
	}
	len = strlen(id);
	r = malloc(sizeof(*r) + len + 1);
	if (!r)
		return NULL;
	r->hash = h;
	r->ref = 1;
	memcpy(r->s, id, len + 1);
	if (hmap_put(&db->rules, h, r)) {
		free(r);
		return NULL;
	}
	return r->s;
}

static void rule_put(struct fakeip_db *db, const char *s)
{
	struct rule_str *r = (struct rule_str *)(s - offsetof(struct rule_str, s));

	if (--r->ref)
		return;
	hmap_del_ptr(&db->rules, r->hash, r);
	free(r);
}

/* ---- mark refcounts ---- */

static bool mark_eq(const void *val, const void *key, void *ctx)
{
	return ((const struct mark_cnt *)val)->mark == *(const uint32_t *)key;
}

static int mark_inc(struct fakeip_db *db, uint32_t mark)
{
	uint64_t h = omni_hash(&mark, sizeof(mark));
	struct mark_cnt *m = hmap_get(&db->marks, h, &mark, mark_eq, NULL);

	if (m) {
		m->cnt++;
		return 0;
	}
	m = malloc(sizeof(*m));
	if (!m)
		return -ENOMEM;
	m->mark = mark;
	m->cnt = 1;
	if (hmap_put(&db->marks, h, m)) {
		free(m);
		return -ENOMEM;
	}
	return 0;
}

static void mark_dec(struct fakeip_db *db, uint32_t mark)
{
	uint64_t h = omni_hash(&mark, sizeof(mark));
	struct mark_cnt *m = hmap_get(&db->marks, h, &mark, mark_eq, NULL);

	if (!m || --m->cnt)
		return;
	hmap_del_ptr(&db->marks, h, m);
	free(m);
}

/* ---- binding lifecycle ---- */

static void binding_free(struct fakeip_db *db, struct binding *b)
{
	rule_put(db, b->rule_id);
	free(b);
}

/* Remove from the maps (not from s3) and release the mark. */
static void binding_unmap(struct fakeip_db *db, struct binding *b)
{
	hmap_del_ptr(&db->by_key, b->khash, b);
	hmap_del_ptr(&db->by_fake, b->fhash, b);
	mark_dec(db, b->mark);
}

/* Full removal; the binding is freed unless still referenced. */
static void binding_drop(struct fakeip_db *db, struct binding *b, bool nft_del)
{
	s3_remove(&db->s3, &b->s3);
	b->s3.list.next = b->s3.list.prev = NULL;
	binding_unmap(db, b);
	if (nft_del)
		nft_elem_del(db->nft, b->family, b->fake);
	if (!b->refcnt)
		binding_free(db, b);
}

static bool s3_can_evict(struct s3fifo *s, struct s3_node *n)
{
	return binding_evictable(container_of(n, struct binding, s3), omni_now());
}

static void s3_on_evict(struct s3fifo *s, struct s3_node *n)
{
	struct binding *b = container_of(n, struct binding, s3);
	struct fakeip_db *db = s->priv;

	b->s3.list.next = b->s3.list.prev = NULL;
	binding_unmap(db, b);
	nft_elem_del(db->nft, b->family, b->fake);
	binding_free(db, b);
}

static const struct s3_ops fakeip_s3_ops = {
	.can_evict = s3_can_evict,
	.evict = s3_on_evict,
};

static void fail_hook(void *priv, uint64_t ticket, int err)
{
	struct fakeip_db *db = priv;
	struct binding *b;
	uint32_t it = 0, n = 0;

	while ((b = hmap_next(&db->by_key, &it))) {
		if (b->ticket != ticket)
			continue;
		binding_drop(db, b, false);
		n++;
	}
	if (n)
		log_warn("fakeip: nft batch %llu failed (%d), dropped %u bindings",
			 (unsigned long long)ticket, err, n);
}

/* ---- public ---- */

static void set_pools(struct fakeip_db *db, const struct ip_prefix *p4,
		      const struct ip_prefix *p6)
{
	db->has4 = p4 != NULL;
	db->has6 = p6 != NULL;
	if (p4)
		db->p4 = *p4;
	if (p6)
		db->p6 = *p6;
}

struct fakeip_db *fakeip_new(const struct ip_prefix *p4, const struct ip_prefix *p6,
			     uint32_t max_bindings, uint32_t grace,
			     const uint8_t secret[16], struct nft_ctx *nft)
{
	struct fakeip_db *db = calloc(1, sizeof(*db));

	if (!db)
		return NULL;
	if (!max_bindings)
		max_bindings = 1;
	set_pools(db, p4, p6);
	db->max_bindings = max_bindings;
	db->grace = grace;
	memcpy(db->secret, secret, 16);
	db->nft = nft;
	if (s3_init(&db->s3, max_bindings, &fakeip_s3_ops, db)) {
		free(db);
		return NULL;
	}
	if (nft)
		nft_set_fail_hook(nft, fail_hook, db);
	return db;
}

void fakeip_free(struct fakeip_db *db)
{
	struct binding *b;
	uint32_t it = 0;
	void *v;

	if (!db)
		return;
	while ((b = hmap_next(&db->by_key, &it)))
		free(b);
	it = 0;
	while ((v = hmap_next(&db->rules, &it)))
		free(v);
	it = 0;
	while ((v = hmap_next(&db->marks, &it)))
		free(v);
	hmap_free(&db->by_key);
	hmap_free(&db->by_fake);
	hmap_free(&db->rules);
	hmap_free(&db->marks);
	s3_destroy(&db->s3);
	if (db->nft)
		nft_set_fail_hook(db->nft, NULL, NULL);
	free(db);
}

bool fakeip_has_pool(const struct fakeip_db *db, int family)
{
	return db_pool(db, norm_family(family)) != NULL;
}

static uint32_t safe_until_for(const struct fakeip_db *db, uint32_t now, uint32_t ttl)
{
	uint64_t t = (uint64_t)now + ttl + db->grace;

	return t > UINT32_MAX ? UINT32_MAX : (uint32_t)t;
}

/*
 * Probe for a fake for khash. Returns 0 with the address in `fake` and
 * *victim set to an evictable occupant (or NULL for a free slot), or -ENOSPC.
 */
static int probe(struct fakeip_db *db, int family, uint64_t khash, uint32_t now,
		 uint8_t *fake, struct binding **victim)
{
	const struct ip_prefix *p = db_pool(db, family);
	uint64_t usable = pool_usable(p, family), off;
	struct fkey fk = { .family = family, .fake = fake };
	struct binding *o;
	int i;

	if (!usable)
		return -ENOSPC;
	off = khash % usable;
	for (i = 0; i < FAKEIP_MAX_PROBE && (uint64_t)i < usable; i++) {
		pool_addr(p, family, off, fake);
		o = hmap_get(&db->by_fake, fake_hash(family, fake), &fk, fake_eq, NULL);
		if (!o || binding_evictable(o, now)) {
			*victim = o;
			return 0;
		}
		if (++off == usable)
			off = 0;
	}
	return -ENOSPC;
}

static uint32_t evict_target(const struct fakeip_db *db)
{
	return (uint32_t)((uint64_t)db->max_bindings * 7 / 8);
}

static int find_slot(struct fakeip_db *db, int family, uint64_t khash, uint32_t now,
		     uint8_t *fake, struct binding **victim)
{
	if (!probe(db, family, khash, now, fake, victim))
		return 0;
	if (s3_count(&db->s3) > evict_target(db))
		s3_evict(&db->s3, evict_target(db));
	return probe(db, family, khash, now, fake, victim);
}

static struct binding *binding_create(struct fakeip_db *db, const struct bkey *k,
				      uint64_t khash, uint32_t now, uint32_t ttl, int *err)
{
	struct binding *b, *victim;
	uint8_t fake[16];
	int r;

	r = find_slot(db, k->family, khash, now, fake, &victim);
	if (r)
		goto fail;
	if (!victim && hmap_len(&db->by_key) >= db->max_bindings) {
		s3_evict(&db->s3, evict_target(db));
		if (hmap_len(&db->by_key) >= db->max_bindings) {
			r = -ENOSPC;
			goto fail;
		}
	}
	r = -ENOMEM;
	b = calloc(1, sizeof(*b) + k->endpoint_len);
	if (!b)
		goto fail;
	b->rule_id = rule_get(db, k->rule_id);
	if (!b->rule_id)
		goto fail_free;
	if (mark_inc(db, k->mark))
		goto fail_rule;
	b->khash = khash;
	b->mark = k->mark;
	b->family = k->family;
	memcpy(b->fake, fake, alen(k->family));
	memcpy(b->real, k->real, alen(k->family));
	b->fhash = fake_hash(b->family, b->fake);
	b->endpoint_len = k->endpoint_len;
	memcpy(b->endpoint, k->endpoint, k->endpoint_len);
	b->safe_until = safe_until_for(db, now, ttl);
	if (hmap_put(&db->by_key, khash, b))
		goto fail_mark;
	if (hmap_put(&db->by_fake, b->fhash, b)) {
		hmap_del_ptr(&db->by_key, khash, b);
		goto fail_mark;
	}
	/* the victim is gone from the kernel by the replace below, no nft del */
	if (victim)
		binding_drop(db, victim, false);
	s3_insert(&db->s3, &b->s3, khash);
	b->ticket = nft_elem_add(db->nft, b->family, b->fake, b->real, b->mark, victim != NULL);
	return b;

fail_mark:
	mark_dec(db, k->mark);
fail_rule:
	rule_put(db, b->rule_id);
fail_free:
	free(b);
fail:
	*err = r;
	return NULL;
}

struct binding *fakeip_bind(struct fakeip_db *db, const char *rule_id, uint32_t mark,
			    const uint8_t *endpoint, uint8_t endpoint_len,
			    int family, const uint8_t *real, uint32_t ttl, int *err)
{
	uint8_t ep[255];
	struct bkey k = {
		.rule_id = rule_id, .mark = mark, .endpoint_len = endpoint_len,
		.endpoint = ep, .real = real,
	};
	uint32_t now = omni_now(), su;
	struct binding *b;
	uint64_t khash;
	int i;

	k.family = norm_family(family);
	if (!db_pool(db, k.family)) {
		*err = -EAFNOSUPPORT;
		return NULL;
	}
	for (i = 0; i < endpoint_len; i++)
		ep[i] = lower(endpoint[i]);
	khash = key_hash(db, &k);
	b = hmap_get(&db->by_key, khash, &k, key_eq, NULL);
	if (!b)
		return binding_create(db, &k, khash, now, ttl, err);
	s3_touch(&b->s3);
	su = safe_until_for(db, now, ttl);
	if (su > b->safe_until)
		b->safe_until = su;
	return b;
}

void fakeip_ref(struct binding *b)
{
	b->refcnt++;
}

void fakeip_unref(struct fakeip_db *db, struct binding *b)
{
	if (--b->refcnt)
		return;
	if (binding_detached(b))
		binding_free(db, b);
}

struct binding *fakeip_lookup(struct fakeip_db *db, int family, const uint8_t *fake)
{
	struct fkey fk = { .family = norm_family(family), .fake = fake };

	if (!fk.family)
		return NULL;
	return hmap_get(&db->by_fake, fake_hash(fk.family, fake), &fk, fake_eq, NULL);
}

bool fakeip_in_pool(const struct fakeip_db *db, int family, const uint8_t *addr)
{
	const struct ip_prefix *p;

	family = norm_family(family);
	p = db_pool(db, family);
	return p && prefix_match(p, family, addr);
}

static bool fits_pool(const struct ip_prefix *p, const struct binding *b)
{
	return p && pool_allocatable(p, b->family, b->fake);
}

int fakeip_set_config(struct fakeip_db *db, const struct ip_prefix *p4,
		      const struct ip_prefix *p6, uint32_t max_bindings, uint32_t grace)
{
	uint32_t now = omni_now(), it = 0;
	struct binding *b;

	while ((b = hmap_next(&db->by_key, &it)))
		if (!fits_pool(b->family == 4 ? p4 : p6, b) && !binding_evictable(b, now))
			return -EBUSY;
	it = 0;
	while ((b = hmap_next(&db->by_key, &it)))
		if (!fits_pool(b->family == 4 ? p4 : p6, b))
			binding_drop(db, b, true);
	set_pools(db, p4, p6);
	db->max_bindings = max_bindings ? max_bindings : 1;
	db->s3.cap = db->max_bindings;
	db->grace = grace;
	s3_maybe_evict(&db->s3);
	return 0;
}

uint32_t fakeip_live_count(struct fakeip_db *db)
{
	uint32_t now = omni_now(), it = 0, n = 0;
	struct binding *b;

	while ((b = hmap_next(&db->by_key, &it)))
		n += !binding_evictable(b, now);
	return n;
}

uint32_t fakeip_marks_in_use(struct fakeip_db *db, uint32_t *out, uint32_t max)
{
	struct mark_cnt *m;
	uint32_t it = 0, n = 0;

	while (n < max && (m = hmap_next(&db->marks, &it)))
		out[n++] = m->mark;
	return n;
}

void fakeip_maybe_evict(struct fakeip_db *db)
{
	s3_maybe_evict(&db->s3);
}

uint32_t fakeip_count(const struct fakeip_db *db)
{
	return hmap_len(&db->by_key);
}

struct binding *fakeip_next(struct fakeip_db *db, uint32_t *it)
{
	return hmap_next(&db->by_key, it);
}
