// SPDX-License-Identifier: MIT
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

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
	uint32_t hash;		/* low 32 bits of policy_hash() (hmap keeps 31) */
	uint32_t mark;
	uint32_t ref;
	uint16_t id;
	char rule_id[];
};

#define POLICY_NONE UINT32_MAX	/* bkey.policy: pair not interned */
/* rule id of placeholders (fakeip_adopt()): no UCI section is named so */
#define ADOPTED ""

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
	 * unreferenced binding (UINT32_MAX: none, only an unref can help),
	 * gathered during the pass and lowered by stall_wake() after it.
	 */
	bool stalled;
	uint32_t stall_until;
	uint32_t scans;		/* eviction passes run (tests) */
	uint32_t nplaceholders;	/* adopted bindings not yet claimed or evicted */
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

/* out of the table, kept for its references (list_del() clears the links) */
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

static void store64be(uint8_t *p, uint64_t v)
{
	store32be(p, v >> 32);
	store32be(p + 4, (uint32_t)v);
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
	       !memcmp(binding_endpoint(b), k->endpoint, k->endpoint_len) &&
	       !memcmp(binding_real(b), k->real, alen(k->family));
}

static bool fake_eq(const void *val, const void *key, void *ctx)
{
	const struct binding *b = val;
	const struct fkey *k = key;

	return b->family == k->family && !memcmp(binding_fake(b), k->fake, alen(k->family));
}

/* a zeroed binding with its key fields and tail filled in; NULL on ENOMEM */
static struct binding *binding_new(int pid, int family, const uint8_t *fake,
                                   const uint8_t *real, const uint8_t *endpoint,
                                   uint8_t endpoint_len)
{
	struct binding *b = calloc(1, binding_size(family, endpoint_len));
	size_t n = alen(family);

	if (!b)
		return NULL;
	b->policy = pid;
	b->family = family;
	b->endpoint_len = endpoint_len;
	memcpy(b->tail, fake, n);
	memcpy(b->tail + n, real, n);
	memcpy(b->tail + 2 * n, endpoint, endpoint_len);
	return b;
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

static bool is_placeholder(const struct fakeip_db *db, const struct binding *b)
{
	return !db->pol[b->policy]->rule_id[0];
}

/* ---- binding lifecycle ---- */

static void binding_free(struct fakeip_db *db, struct binding *b)
{
	if (is_placeholder(db, b))
		db->nplaceholders--;
	policy_put(db, b->policy);
	free(b);
}

/* Remove from the maps, once out of s3; freed unless still referenced. */
static void binding_unmap(struct fakeip_db *db, struct binding *b, bool nft_del)
{
	hmap_del_ptr(&db->by_key, b->s3.hash, b);
	hmap_del_ptr(&db->by_fake, fake_hash(b->family, binding_fake(b)), b);
	if (nft_del)
		nft_elem_del(db->nft, b->family, binding_fake(b));
	if (!b->refcnt)
		binding_free(db, b);
}

static void binding_drop(struct fakeip_db *db, struct binding *b, bool nft_del)
{
	s3_remove(&db->s3, &b->s3);
	binding_unmap(db, b, nft_del);
}

/* b may become evictable at b->safe_until: a stalled pass may be retried then */
static void stall_wake(struct fakeip_db *db, const struct binding *b)
{
	if (b->safe_until < db->stall_until)
		db->stall_until = b->safe_until;
}

/* Map b and queue it for eviction; nothing is mapped on failure. */
static int binding_insert(struct fakeip_db *db, struct binding *b, uint64_t khash)
{
	if (hmap_put(&db->by_key, khash, b))
		return -ENOMEM;
	if (hmap_put(&db->by_fake, fake_hash(b->family, binding_fake(b)), b)) {
		hmap_del_ptr(&db->by_key, khash, b);
		return -ENOMEM;
	}
	s3_insert(&db->s3, &b->s3, khash);
	stall_wake(db, b);
	return 0;
}

static bool s3_can_evict(struct s3fifo *s, struct s3_node *n)
{
	struct binding *b = container_of(n, struct binding, s3);
	struct fakeip_db *db = s->priv;

	if (binding_evictable(b, omni_now()))
		return true;
	if (!b->refcnt)
		stall_wake(db, b);
	return false;
}

/* unlinked by s3 already, and unreferenced (s3_can_evict()) */
static void s3_on_evict(struct s3fifo *s, struct s3_node *n)
{
	binding_unmap(s->priv, container_of(n, struct binding, s3), true);
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

/* now + secs, saturated */
static uint32_t until(uint32_t now, uint64_t secs)
{
	uint64_t t = now + secs;

	return t > UINT32_MAX ? UINT32_MAX : (uint32_t)t;
}

/* a placeholder the kernel already maps exactly as k wants: k may take it over */
static bool claimable(const struct fakeip_db *db, const struct binding *o, const struct bkey *k)
{
	return is_placeholder(db, o) && o->family == k->family &&
	       db->pol[o->policy]->mark == k->mark &&
	       !memcmp(binding_real(o), k->real, alen(k->family));
}

/*
 * Probe for a fake for khash. Returns 0 with the address in `fake` and
 * *victim set to an evictable occupant or a claimable placeholder (or NULL
 * for a free slot), or -ENOSPC. While placeholders exist, the whole probe
 * window is searched for one to claim before a free slot is taken: with
 * the secret of the earlier process, a key's old fake lies in its window.
 */
static int probe(struct fakeip_db *db, const struct bkey *k, uint64_t khash, uint32_t now,
                 uint8_t *fake, struct binding **victim)
{
	int family = k->family;
	const struct ip_prefix *p = db_pool(db, family);
	uint64_t usable = pool_usable(p, family), off;
	uint8_t cand[16];
	struct fkey fk = { .family = family, .fake = cand };
	struct binding *o;
	bool found = false;
	int i;

	if (!usable)
		return -ENOSPC;
	off = khash % usable;
	for (i = 0; i < FAKEIP_MAX_PROBE && (uint64_t)i < usable; i++) {
		pool_addr(p, family, off, cand);
		o = hmap_get(&db->by_fake, fake_hash(family, cand), &fk, fake_eq, NULL);
		if (o && db->nplaceholders && claimable(db, o, k)) {
			memcpy(fake, cand, 16);
			*victim = o;
			return 0;
		}
		if (!found && (!o || binding_evictable(o, now))) {
			memcpy(fake, cand, 16);
			*victim = o;
			found = true;
			if (!db->nplaceholders)
				return 0;
		}
		if (++off == usable)
			off = 0;
	}
	return found ? 0 : -ENOSPC;
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
	db->stall_until = UINT32_MAX;
	db->scans++;
	s3_evict(&db->s3, target);
	db->stalled = s3_count(&db->s3) > target;
}

static int find_slot(struct fakeip_db *db, const struct bkey *k, uint64_t khash, uint32_t now,
                     uint8_t *fake, struct binding **victim)
{
	if (!probe(db, k, khash, now, fake, victim))
		return 0;
	evict_to(db, evict_target(db));
	return probe(db, k, khash, now, fake, victim);
}

static struct binding *binding_create(struct fakeip_db *db, const struct bkey *k,
                                      uint64_t khash, uint32_t now, uint32_t ttl, int *err)
{
	struct binding *b, *victim;
	uint8_t fake[16];
	bool claim;
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
		*err = pid;
		return NULL;
	}
	r = find_slot(db, k, khash, now, fake, &victim);
	if (r)
		goto fail_policy;
	claim = victim && claimable(db, victim, k);
	if (!victim && hmap_len(&db->by_key) >= db->max_bindings) {
		evict_to(db, evict_target(db));
		if (hmap_len(&db->by_key) >= db->max_bindings) {
			r = -ENOSPC;
			goto fail_policy;
		}
	}
	r = -ENOMEM;
	b = binding_new(pid, k->family, fake, k->real, k->endpoint, k->endpoint_len);
	if (!b)
		goto fail_policy;
	b->safe_until = until(now, (uint64_t)ttl + db->grace);
	/* clients of the earlier process may hold a claimed fake longer */
	if (claim && b->safe_until < victim->safe_until)
		b->safe_until = victim->safe_until;
	if (binding_insert(db, b, khash)) {
		free(b);
		goto fail_policy;
	}
	/* the add below replaces the victim's elements, no nft del */
	if (victim)
		binding_drop(db, victim, false);
	/* a claimed placeholder: the kernel has this very mapping (ticket 0
	 * counts as done) */
	b->ticket = claim ? 0 : nft_elem_add(db->nft, b->family, binding_fake(b),
	                                     binding_real(b), k->mark);
	return b;

fail_policy:
	policy_put(db, pid);
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
	if (!rule_id[0]) {	/* reserved for placeholders */
		*err = -EINVAL;
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
	su = until(now, (uint64_t)ttl + db->grace);
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

static struct binding *lookup_any(struct fakeip_db *db, int family, const uint8_t *fake)
{
	struct fkey fk = { .family = norm_family(family), .fake = fake };

	if (!fk.family)
		return NULL;
	return hmap_get(&db->by_fake, fake_hash(fk.family, fake), &fk, fake_eq, NULL);
}

struct binding *fakeip_lookup(struct fakeip_db *db, int family, const uint8_t *fake)
{
	struct binding *b = lookup_any(db, family, fake);

	return b && !is_placeholder(db, b) ? b : NULL;
}

bool fakeip_placeholder(struct fakeip_db *db, int family, const uint8_t *fake, uint32_t *mark)
{
	struct binding *b = lookup_any(db, family, fake);

	if (!b || !is_placeholder(db, b))
		return false;
	if (mark)
		*mark = fakeip_mark(db, b);
	return true;
}

uint32_t fakeip_placeholders(const struct fakeip_db *db)
{
	return db->nplaceholders;
}

int fakeip_adopt(struct fakeip_db *db, int family, const uint8_t *fake, const uint8_t *real,
                 uint32_t mark, uint32_t hold)
{
	/*
	 * The endpoint is the fake itself: no name is known, and placeholders
	 * of one (mark, real) would otherwise share one key hash, making
	 * by_key chains (and adopting or evicting them) quadratic. No bind
	 * matches the key (the rule id is reserved) and no PTR answer reads it
	 * (fakeip_lookup() skips placeholders).
	 */
	struct bkey k = {
		.rule_id = ADOPTED, .mark = mark, .family = norm_family(family),
		.endpoint = fake, .endpoint_len = alen(norm_family(family)), .real = real,
	};
	const struct ip_prefix *p = db_pool(db, k.family);
	struct binding *b;
	uint64_t khash;
	int pid;

	if (!p || !pool_allocatable(p, k.family, fake))
		return -EINVAL;
	if (!nft_mark_known(db->nft, mark))
		return -ESTALE;
	if (lookup_any(db, k.family, fake))
		return -EEXIST;
	if (hmap_len(&db->by_key) >= db->max_bindings)
		return -ENOSPC;
	k.phash = policy_hash(ADOPTED, mark);
	khash = key_hash(db, &k);
	pid = policy_get(db, &k);
	if (pid < 0)
		return pid;
	b = binding_new(pid, k.family, fake, real, fake, k.endpoint_len);
	if (b) {
		b->safe_until = until(omni_now(), hold);	/* hold includes the grace */
		if (!binding_insert(db, b, khash)) {
			db->nplaceholders++;
			return 0;
		}
		free(b);
	}
	policy_put(db, pid);
	return -ENOMEM;
}

/* ---- hold file ---- */

/*
 * Big-endian. Header: magic, format version, record count, fingerprint
 * (hold_fingerprint()), CLOCK_BOOTTIME second of the write. Record: family,
 * three zero bytes, remaining hold in seconds, fake (v4: 4 bytes, then 12
 * zero bytes).
 */
#define HOLD_MAGIC	"OMNIHOLD"
#define HOLD_VERSION	1
#define HOLD_HDR	32
#define HOLD_REC	24

struct hold_rec {
	uint8_t family;
	uint32_t hold;
	uint8_t fake[16];
};

struct fakeip_hold {
	uint32_t n;
	struct hold_rec rec[];	/* sorted by (family, fake) */
};

/* ties a file to one table instance (its secret) and layout, without
 * revealing the secret */
static uint64_t hold_fingerprint(const uint8_t secret[16])
{
	uint8_t in[16] = "omnidns hold";

	store32be(in + 12, NFT_LAYOUT_VERSION);
	return siphash24(secret, in, sizeof(in));
}

static int write_all(int fd, const uint8_t *p, size_t len)
{
	while (len) {
		ssize_t w = write(fd, p, len);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		p += w;
		len -= (size_t)w;
	}
	return 0;
}

int fakeip_hold_save(struct fakeip_db *db, const char *path, uint64_t clock)
{
	uint32_t now = omni_now(), it = 0, n = 0;
	struct binding *b;
	uint8_t *buf, *p;
	char tmp[4096];
	int fd, ret;

	ret = snprintf(tmp, sizeof(tmp), "%s.%ld.tmp", path, (long)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmp))
		return -ENAMETOOLONG;
	buf = calloc(1, HOLD_HDR + (size_t)hmap_len(&db->by_key) * HOLD_REC);
	if (!buf)
		return -ENOMEM;
	p = buf + HOLD_HDR;
	while ((b = hmap_next(&db->by_key, &it))) {
		if (binding_evictable(b, now))
			continue;
		p[0] = b->family;
		store32be(p + 4, b->safe_until > now ? b->safe_until - now : 0);
		memcpy(p + 8, binding_fake(b), binding_alen(b));
		p += HOLD_REC;
		n++;
	}
	memcpy(buf, HOLD_MAGIC, 8);
	store32be(buf + 8, HOLD_VERSION);
	store32be(buf + 12, n);
	store64be(buf + 16, hold_fingerprint(db->secret));
	store64be(buf + 24, clock);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		ret = -errno;
		free(buf);
		return ret;
	}
	ret = write_all(fd, buf, (size_t)(p - buf));
	free(buf);
	if (close(fd) && !ret)
		ret = -errno;
	/* no fsync: the file lives on tmpfs, and only for this boot */
	if (!ret && rename(tmp, path))
		ret = -errno;
	if (ret)
		unlink(tmp);
	return ret;
}

static int hold_cmp(const void *a, const void *b)
{
	const struct hold_rec *x = a, *y = b;

	if (x->family != y->family)
		return x->family < y->family ? -1 : 1;
	return memcmp(x->fake, y->fake, 16);
}

static int hold_parse(const uint8_t *buf, size_t len, const uint8_t secret[16],
                      uint32_t max_records, uint64_t clock, struct fakeip_hold **out)
{
	static const uint8_t zero[16];
	struct fakeip_hold *h;
	uint64_t written, elapsed;
	uint32_t n, i;

	if (len < HOLD_HDR || memcmp(buf, HOLD_MAGIC, 8) || load32be(buf + 8) != HOLD_VERSION)
		return -EINVAL;
	n = load32be(buf + 12);
	if (n > max_records)
		return -E2BIG;
	if (len - HOLD_HDR != (uint64_t)n * HOLD_REC)
		return -EINVAL;		/* truncated, or trailing bytes */
	if (load64be(buf + 16) != hold_fingerprint(secret))
		return -ESTALE;
	written = load64be(buf + 24);
	if (written > clock)
		return -ERANGE;
	elapsed = clock - written;
	h = malloc(sizeof(*h) + (size_t)n * sizeof(h->rec[0]));
	if (!h)
		return -ENOMEM;
	h->n = n;
	for (i = 0; i < n; i++) {
		const uint8_t *r = buf + HOLD_HDR + (size_t)i * HOLD_REC;
		struct hold_rec *e = &h->rec[i];
		uint32_t hold = load32be(r + 4);

		if ((r[0] != 4 && r[0] != 6) || memcmp(r + 1, zero, 3) ||
		    (r[0] == 4 && memcmp(r + 12, zero, 12))) {
			free(h);
			return -EINVAL;
		}
		e->family = r[0];
		e->hold = hold > elapsed ? (uint32_t)(hold - elapsed) : 0;
		memcpy(e->fake, r + 8, 16);
	}
	qsort(h->rec, n, sizeof(h->rec[0]), hold_cmp);
	for (i = 1; i < n; i++) {
		if (!hold_cmp(&h->rec[i - 1], &h->rec[i])) {
			free(h);
			return -EINVAL;
		}
	}
	*out = h;
	return 0;
}

struct fakeip_hold *fakeip_hold_load(const char *path, const uint8_t secret[16],
                                     uint32_t max_records, uint64_t clock, int *err)
{
	struct fakeip_hold *h = NULL;
	uint64_t max = HOLD_HDR + (uint64_t)max_records * HOLD_REC;
	struct stat st;
	uint8_t *buf = NULL;
	size_t len = 0;
	ssize_t r;
	int fd, ret;

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		*err = -errno;
		return NULL;
	}
	/* whatever it says, it is never read twice */
	unlink(path);
	if (fstat(fd, &st)) {
		ret = -errno;
		goto out;
	}
	ret = -EINVAL;
	if (!S_ISREG(st.st_mode))
		goto out;
	ret = -E2BIG;
	if ((uint64_t)st.st_size > max)
		goto out;
	ret = -ENOMEM;
	/* one spare byte: a file that grew after the fstat is not a valid one */
	buf = malloc((size_t)st.st_size + 1);
	if (!buf)
		goto out;
	for (;;) {
		r = read(fd, buf + len, (size_t)st.st_size + 1 - len);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			ret = -errno;
			goto out;
		}
		if (!r || (len += (size_t)r) == (size_t)st.st_size + 1)
			break;
	}
	ret = len == (size_t)st.st_size ? hold_parse(buf, len, secret, max_records, clock, &h)
	                                : -EINVAL;
out:
	free(buf);
	close(fd);
	*err = ret;
	return h;
}

void fakeip_hold_free(struct fakeip_hold *h)
{
	free(h);
}

uint32_t fakeip_hold_count(const struct fakeip_hold *h)
{
	return h->n;
}

bool fakeip_hold_find(const struct fakeip_hold *h, int family, const uint8_t *fake,
                      uint32_t *hold)
{
	struct hold_rec k = { .family = norm_family(family) };
	const struct hold_rec *e;

	memcpy(k.fake, fake, alen(k.family));
	e = bsearch(&k, h->rec, h->n, sizeof(k), hold_cmp);
	if (e && hold)
		*hold = e->hold;
	return e != NULL;
}

uint32_t fakeip_adopt_elems(struct fakeip_db *db, const struct nft_elem *el, uint32_t nel,
                            uint32_t hold, const struct fakeip_hold *h)
{
	uint32_t i, kept = 0, t;

	for (i = 0; i < nel; i++) {
		const struct nft_elem *e = &el[i];

		t = hold;
		if (e->ok && (!h || fakeip_hold_find(h, e->family, e->fake, &t)) &&
		    !fakeip_adopt(db, e->family, e->fake, e->real, e->mark, t)) {
			kept++;
			continue;
		}
		nft_elem_del(db->nft, e->family, e->fake);
	}
	return kept;
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
	return p && pool_allocatable(p, b->family, binding_fake(b));
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

uint32_t fakeip_remask_blockers(struct fakeip_db *db)
{
	/* not evict_expired() + live_count(): those read the clock apart */
	fakeip_evict_expired(db);
	return fakeip_count(db);
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
