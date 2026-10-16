// SPDX-License-Identifier: MIT
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "dns/wire.h"
#include "fakeip.h"
#include "log.h"
#include "nft.h"
#include "util/hash.h"
#include "util/time.h"

/*
 * Policy: an interned (rule_id, mark) pair, refcounted by the bindings
 * (attached or detached-but-referenced) whose b->policy is its id.
 */
struct policy {
	uint32_t hash;		/* low 32 bits of policy_hash() (all hmap keeps) */
	uint32_t mark;
	uint32_t ref;
	uint16_t id;
	char rule_id[];
};

#define POLICY_NONE UINT32_MAX	/* bkey.policy: pair not interned */

struct fakeip_db {
	bool has4, has6;
	struct ip_prefix p4, p6;
	uint32_t max_bindings;
	uint32_t grace;
	uint8_t secret[16];
	struct nft_ctx *nft;
	struct hmap by_key;	/* key_hash() -> binding (= b->s3.hash) */
	struct hmap by_fake;	/* fake_hash() -> binding */
	struct hmap policies;	/* policy_hash() -> struct policy */
	struct policy **pol;	/* by id; NULL = free slot */
	uint16_t *pol_free;	/* stack of free ids below pol_n */
	uint32_t pol_n;		/* ids handed out so far (high-water mark) */
	uint32_t pol_nfree;
	uint32_t pol_cap;	/* allocated length of pol and pol_free */
	struct s3fifo s3;
	/*
	 * Eviction stall (see evict_to()): the last pass found nothing
	 * evictable. Until one of the pinned bindings can become evictable,
	 * passes are skipped: stall_until is the earliest safe_until of an
	 * unreferenced binding (UINT32_MAX: none, only an unref can help).
	 */
	bool stalled;
	uint32_t stall_until;
	uint32_t scan_min;	/* that minimum, gathered during a pass */
	uint32_t scans;		/* eviction passes run (tests) */
};

/* lookup key, endpoint already lowercased */
struct bkey {
	const char *rule_id;
	uint32_t mark;
	uint32_t policy;	/* id of (rule_id, mark) or POLICY_NONE */
	uint64_t phash;		/* policy_hash(rule_id, mark) */
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

	/* interned: equal ids <=> equal (rule_id, mark) */
	return b->policy == k->policy && b->family == k->family &&
	       b->endpoint_len == k->endpoint_len &&
	       !memcmp(b->endpoint, k->endpoint, k->endpoint_len) &&
	       !memcmp(b->real, k->real, alen(k->family));
}

static bool fake_eq(const void *val, const void *key, void *ctx)
{
	const struct binding *b = val;
	const struct fkey *k = key;

	return b->family == k->family && !memcmp(b->fake, k->fake, alen(k->family));
}

/* ---- policy table ---- */

static uint64_t policy_hash(const char *rule_id, uint32_t mark)
{
	return omni_hash(rule_id, strlen(rule_id)) ^ (uint64_t)mark * 0x9e3779b97f4a7c15ull;
}

static bool policy_eq(const void *val, const void *key, void *ctx)
{
	const struct policy *p = val;
	const struct bkey *k = key;

	return p->mark == k->mark && !strcmp(p->rule_id, k->rule_id);
}

/* id of k's (rule_id, mark) or POLICY_NONE; does not take a reference */
static uint32_t policy_find(const struct fakeip_db *db, const struct bkey *k)
{
	const struct policy *p = hmap_get(&db->policies, k->phash, k, policy_eq, NULL);

	return p ? p->id : POLICY_NONE;
}

static int policy_grow(struct fakeip_db *db)
{
	uint32_t cap = db->pol_cap ? db->pol_cap * 2 : 16;
	struct policy **pol;
	uint16_t *fr;

	if (cap > FAKEIP_MAX_POLICIES)
		cap = FAKEIP_MAX_POLICIES;
	pol = realloc(db->pol, cap * sizeof(*pol));
	if (!pol)
		return -ENOMEM;
	db->pol = pol;
	fr = realloc(db->pol_free, cap * sizeof(*fr));
	if (!fr)
		return -ENOMEM;
	db->pol_free = fr;
	db->pol_cap = cap;
	return 0;
}

/* Take a reference on k's (rule_id, mark), interning it if new. Returns
 * the id, or -ENOSPC (FAKEIP_MAX_POLICIES distinct pairs live) / -ENOMEM. */
static int policy_get(struct fakeip_db *db, const struct bkey *k)
{
	uint32_t id = policy_find(db, k);	/* k->policy may be stale */
	struct policy *p;
	size_t len;

	if (id != POLICY_NONE) {
		db->pol[id]->ref++;
		return id;
	}
	if (!db->pol_nfree && db->pol_n == FAKEIP_MAX_POLICIES)
		return -ENOSPC;
	if (!db->pol_nfree && db->pol_n == db->pol_cap && policy_grow(db))
		return -ENOMEM;
	len = strlen(k->rule_id);
	p = malloc(sizeof(*p) + len + 1);
	if (!p)
		return -ENOMEM;
	id = db->pol_nfree ? db->pol_free[db->pol_nfree - 1] : db->pol_n;
	p->hash = (uint32_t)k->phash;
	p->mark = k->mark;
	p->ref = 1;
	p->id = id;
	memcpy(p->rule_id, k->rule_id, len + 1);
	if (hmap_put(&db->policies, k->phash, p)) {
		free(p);
		return -ENOMEM;
	}
	if (db->pol_nfree)
		db->pol_nfree--;
	else
		db->pol_n++;
	db->pol[id] = p;
	return id;
}

static void policy_put(struct fakeip_db *db, uint16_t id)
{
	struct policy *p = db->pol[id];

	if (--p->ref)
		return;
	hmap_del_ptr(&db->policies, p->hash, p);
	db->pol[id] = NULL;
	db->pol_free[db->pol_nfree++] = id;	/* pol_nfree < pol_n <= pol_cap */
	free(p);
}

/* ---- binding lifecycle ---- */

static void binding_free(struct fakeip_db *db, struct binding *b)
{
	policy_put(db, b->policy);
	free(b);
}

/* Remove from the maps (not from s3). */
static void binding_unmap(struct fakeip_db *db, struct binding *b)
{
	hmap_del_ptr(&db->by_key, b->s3.hash, b);
	hmap_del_ptr(&db->by_fake, fake_hash(b->family, b->fake), b);
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
	struct binding *b = container_of(n, struct binding, s3);
	struct fakeip_db *db = s->priv;

	if (binding_evictable(b, omni_now()))
		return true;
	if (!b->refcnt && b->safe_until < db->scan_min)
		db->scan_min = b->safe_until;
	return false;
}

/* b may become evictable at b->safe_until: a stalled pass may be retried then */
static void stall_wake(struct fakeip_db *db, const struct binding *b)
{
	if (b->safe_until < db->stall_until)
		db->stall_until = b->safe_until;
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
	while ((v = hmap_next(&db->policies, &it)))
		free(v);
	hmap_free(&db->by_key);
	hmap_free(&db->by_fake);
	hmap_free(&db->policies);
	free(db->pol);
	free(db->pol_free);
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

/*
 * Evict down to `target`. When a pass ends short of it, every binding left
 * was visited and found pinned (s3_evict() gives up only after a full
 * stalled round), so another pass is pointless until one can be evicted:
 * time passes the earliest safe_until of an unreferenced binding, a
 * binding's last reference goes (fakeip_unref()), a new binding arrives
 * with an earlier safe_until, or the configuration changes. Without this,
 * a full table of live bindings cost every failing bind a scan of all of
 * them.
 */
static void evict_to(struct fakeip_db *db, uint32_t target)
{
	if (s3_count(&db->s3) <= target)
		return;
	if (db->stalled && omni_now() <= db->stall_until)
		return;
	db->scan_min = UINT32_MAX;
	db->scans++;
	s3_evict(&db->s3, target);
	db->stalled = s3_count(&db->s3) > target;
	db->stall_until = db->scan_min;
}

static int find_slot(struct fakeip_db *db, int family, uint64_t khash, uint32_t now,
                     uint8_t *fake, struct binding **victim)
{
	if (!probe(db, family, khash, now, fake, victim))
		return 0;
	evict_to(db, evict_target(db));
	return probe(db, family, khash, now, fake, victim);
}

static struct binding *binding_create(struct fakeip_db *db, const struct bkey *k,
                                      uint64_t khash, uint32_t now, uint32_t ttl, int *err)
{
	struct binding *b, *victim;
	uint8_t fake[16];
	int r, pid;

	/*
	 * Policy first: the evictions below may drop the last other binding
	 * of this pair. A full table is rare (65535 distinct (rule, mark)
	 * pairs need as many bindings): make room from expired bindings once.
	 */
	pid = policy_get(db, k);
	if (pid == -ENOSPC && fakeip_evict_expired(db))
		pid = policy_get(db, k);
	if (pid < 0) {
		r = pid;
		goto fail;
	}
	r = find_slot(db, k->family, khash, now, fake, &victim);
	if (r)
		goto fail_policy;
	if (!victim && hmap_len(&db->by_key) >= db->max_bindings) {
		evict_to(db, evict_target(db));
		if (hmap_len(&db->by_key) >= db->max_bindings) {
			r = -ENOSPC;
			goto fail_policy;
		}
	}
	r = -ENOMEM;
	b = calloc(1, offsetof(struct binding, endpoint) + k->endpoint_len);
	if (!b)
		goto fail_policy;
	b->policy = pid;
	b->family = k->family;
	memcpy(b->fake, fake, alen(k->family));
	memcpy(b->real, k->real, alen(k->family));
	b->endpoint_len = k->endpoint_len;
	memcpy(b->endpoint, k->endpoint, k->endpoint_len);
	b->safe_until = safe_until_for(db, now, ttl);
	if (hmap_put(&db->by_key, khash, b))
		goto fail_free;
	if (hmap_put(&db->by_fake, fake_hash(b->family, b->fake), b)) {
		hmap_del_ptr(&db->by_key, khash, b);
		goto fail_free;
	}
	/* the add below replaces the victim's elements, no nft del */
	if (victim)
		binding_drop(db, victim, false);
	s3_insert(&db->s3, &b->s3, khash);
	stall_wake(db, b);
	b->ticket = nft_elem_add(db->nft, b->family, b->fake, b->real, k->mark);
	return b;

fail_free:
	free(b);
fail_policy:
	policy_put(db, pid);
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

	k.family = norm_family(family);
	if (!db_pool(db, k.family)) {
		*err = -EAFNOSUPPORT;
		return NULL;
	}
	/*
	 * A walk that latched its mark before a reload changed the fwmask
	 * would queue an element jumping to a deleted chain, failing the whole
	 * batch and with it every unrelated binding in it. Fail only this one.
	 * (Existing bindings always have a known mark, see kept_marks in main.c.)
	 */
	if (!nft_mark_known(db->nft, mark)) {
		*err = -ESTALE;
		return NULL;
	}
	memcpy(ep, endpoint, endpoint_len);
	dns_name_lower(ep, endpoint_len);
	khash = key_hash(db, &k);
	k.phash = policy_hash(rule_id, mark);
	k.policy = policy_find(db, &k);
	/* no binding can carry a pair that is not interned */
	b = k.policy == POLICY_NONE ? NULL : hmap_get(&db->by_key, khash, &k, key_eq, NULL);
	if (!b)
		return binding_create(db, &k, khash, now, ttl, err);
	s3_touch(&b->s3);
	su = safe_until_for(db, now, ttl);
	if (su > b->safe_until)
		b->safe_until = su;
	return b;
}

const char *fakeip_rule_id(const struct fakeip_db *db, const struct binding *b)
{
	return db->pol[b->policy]->rule_id;
}

uint32_t fakeip_mark(const struct fakeip_db *db, const struct binding *b)
{
	return db->pol[b->policy]->mark;
}

uint32_t fakeip_policy_count(const struct fakeip_db *db)
{
	return hmap_len(&db->policies);
}

uint32_t fakeip_policy_refs(const struct fakeip_db *db, const char *rule_id, uint32_t mark)
{
	struct bkey k = { .rule_id = rule_id, .mark = mark, .phash = policy_hash(rule_id, mark) };
	uint32_t id = policy_find(db, &k);

	return id == POLICY_NONE ? 0 : db->pol[id]->ref;
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
	else
		stall_wake(db, b);
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
	s3_set_cap(&db->s3, db->max_bindings);
	db->grace = grace;
	db->stalled = false;
	fakeip_maybe_evict(db);
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

uint32_t fakeip_evict_expired(struct fakeip_db *db)
{
	uint32_t now = omni_now(), it = 0, n = 0;
	struct binding *b;

	while ((b = hmap_next(&db->by_key, &it))) {
		if (binding_evictable(b, now)) {
			binding_drop(db, b, true);
			n++;
		}
	}
	return n;
}

void fakeip_maybe_evict(struct fakeip_db *db)
{
	/* s3_maybe_evict()'s watermark, through the stall check */
	if (s3_count(&db->s3) > db->max_bindings)
		evict_to(db, evict_target(db));
	s3_ghost_trim(&db->s3, omni_now());
}

uint32_t fakeip_evict_scans(const struct fakeip_db *db)
{
	return db->scans;
}

uint32_t fakeip_count(const struct fakeip_db *db)
{
	return hmap_len(&db->by_key);
}

struct binding *fakeip_next(struct fakeip_db *db, uint32_t *it)
{
	return hmap_next(&db->by_key, it);
}
