// SPDX-License-Identifier: MIT
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/uloop.h>

#include "cache.h"
#include "config.h"
#include "dns/svcb.h"
#include "fakeip.h"
#include "log.h"
#include "match.h"
#include "nft.h"
#include "omnidns.h"
#include "resolve.h"
#include "upstream.h"
#include "util/pool.h"

#define PTR_TTL		60
#define DNS_R_YXDOMAIN	6

#define RULE_ID_INLINE	48

struct latch {
	bool on;
	char *rule_id;			/* id_buf, or allocated when longer */
	uint32_t mark;
	struct upstream_set *up;
	char id_buf[RULE_ID_INLINE];
};

#define DEPS_INLINE	128

struct dep_memo {
	uint16_t off;			/* into deps */
	uint16_t rule;			/* index in the config of gen0 */
};

/*
 * Requests come from a pool (see req_get()): a request that ended keeps its
 * two messages' storage, its bindings array and its held-answer buffer for
 * the next one, so that a typical miss allocates none of them. Everything
 * else is zeroed.
 */
struct resolve_req {
	struct omni *o;			/* first: the pool's link while kept */
	resolve_cb cb;
	void *ctx;
	struct uloop_timeout defer;
	struct upstream_query *uq;
	struct nft_waiter nw;
	bool starting;
	uint64_t gen0;

	struct dns_name qname;
	uint16_t qtype, qclass, rd;
	uint64_t key_hash;		/* cache_hash() of the question, computed once */

	/* walk state */
	struct dns_name name;
	struct upstream_set *cur_up;
	struct latch latch;
	struct dns_msg resp;
	bool synth;			/* a CNAME was synthesized from a DNAME */
	uint16_t nresp, steps;		/* responses (in r->resp: the last one) */
	struct dns_msg prefix;

	/*
	 * deps: packed as cache_insert takes them, each name once; memo[i]
	 * locates dependency i and remembers its rule. The first nwalk are the
	 * walk's names (loop detection looks only at those).
	 */
	uint8_t *deps;
	uint16_t dsz, dcap, ndeps, nwalk;
	bool deps_full;			/* more than CACHE_MAX_DEPS: not cached */
	struct dep_memo memo[CACHE_MAX_DEPS];
	uint8_t deps_inline[DEPS_INLINE];

	/* commit */
	struct binding **binds;
	uint16_t nbinds, binds_cap, wait_i;
	uint32_t lifetime;
	bool cache_it;			/* insert the answer when delivering it */

	/* the answer: alen bytes in wire, or in held while held_on */
	bool bare;			/* header and question only, with rcode */
	bool held_on;
	uint8_t rcode;
	uint32_t alen, held_cap;
	uint8_t *held;
};

enum { SCAN_ALIAS, SCAN_DONE, SCAN_QUERY };
enum { ACT_SKIP = 0, ACT_KEEP, ACT_DROP, ACT_BIND, ACT_HINTS };
enum { LIFE_NONE, LIFE_POS, LIFE_NEG };

struct plan {
	uint8_t act;
	bool sv_ok;			/* sv holds the parsed rdata */
	uint32_t mark;
	const char *rule_id;
	struct svcb_view sv;		/* SVCB/HTTPS queries: by find_svcb_alias */
};

/*
 * Scratch for terminal processing, one entry per answer record of the
 * response in hand: for SVCB/HTTPS queries, find_svcb_alias() parses each
 * candidate record into it once, then terminal() plans. It is only used
 * synchronously within one scan() (never across a wait for an upstream or
 * nft), so a single static array serves every request, and so does one
 * buffer for a rewritten SVCB rdata (never longer than the original).
 */
static struct plan plan[DNS_MAX_RRS];
static uint8_t hint_buf[UINT16_MAX];

static struct resolve_stats stats;

const struct resolve_stats *resolve_get_stats(void)
{
	return &stats;
}

/* ---- small helpers ---- */

static bool owned(const struct dns_rr *rr, const struct dns_name *n)
{
	return dns_name_eq(rr->owner, rr->owner_len, n->data, n->len);
}

static const struct dns_rr *find_rr(const struct dns_msg *m, const struct dns_name *n,
                                    uint16_t type)
{
	uint16_t i;

	for (i = 0; i < m->nrr && m->rr[i].section == DNS_S_AN; i++)
		if (m->rr[i].type == type && owned(&m->rr[i], n))
			return &m->rr[i];
	return NULL;
}

static const struct dns_rr *find_soa(const struct dns_msg *m)
{
	uint16_t i;

	for (i = 0; i < m->nrr; i++)
		if (m->rr[i].section == DNS_S_NS && m->rr[i].type == DNS_T_SOA)
			return &m->rr[i];
	return NULL;
}

/* The most specific DNAME in AN whose owner is a proper ancestor of n. */
static const struct dns_rr *find_dname(const struct dns_msg *m, const struct dns_name *n)
{
	const struct dns_rr *best = NULL;
	uint16_t i;

	for (i = 0; i < m->nrr && m->rr[i].section == DNS_S_AN; i++) {
		const struct dns_rr *rr = &m->rr[i];

		if (rr->type != DNS_T_DNAME || owned(rr, n) ||
		    !dns_name_is_under(n->data, n->len, rr->owner, rr->owner_len))
			continue;
		if (!best || rr->owner_len > best->owner_len)
			best = rr;
	}
	return best;
}

static bool is_svcb(uint16_t t)
{
	return t == DNS_T_SVCB || t == DNS_T_HTTPS;
}

static int afamily(uint16_t qtype)
{
	return qtype == DNS_T_A ? 4 : qtype == DNS_T_AAAA ? 6 : 0;
}

static bool rr_same(const struct dns_rr *a, const struct dns_rr *b)
{
	return a->type == b->type && a->rdlen == b->rdlen &&
	       dns_name_eq(a->owner, a->owner_len, b->owner, b->owner_len) &&
	       !memcmp(a->rdata, b->rdata, a->rdlen);
}

static int prefix_add(struct resolve_req *r, const struct dns_rr *rr)
{
	uint16_t i;

	for (i = 0; i < r->prefix.nrr; i++)
		if (rr_same(&r->prefix.rr[i], rr))
			return 0;
	return dns_msg_add_rr(&r->prefix, DNS_S_AN, rr->owner, rr->owner_len, rr->type,
	                      rr->cls, rr->ttl, rr->rdata, rr->rdlen);
}

/* Index of the dependency on name among the first n, or -1. */
static int dep_find(const struct resolve_req *r, const uint8_t *name, uint8_t len, uint16_t n)
{
	uint16_t i;

	for (i = 0; i < n; i++) {
		const uint8_t *d = r->deps + r->memo[i].off;

		if (d[8] ? dns_name_eq(d + CACHE_DEP_HDR, d[8], name, len) :
		           dns_name_eq(r->qname.data, r->qname.len, name, len))
			return i;
	}
	return -1;
}

static int dep_add(struct resolve_req *r, const uint8_t *name, uint8_t len, uint16_t idx)
{
	size_t need = (size_t)r->dsz + CACHE_DEP_HDR + len;

	if (r->ndeps == CACHE_MAX_DEPS) {
		r->deps_full = true;
		return 0;
	}
	if (need > r->dcap) {
		uint16_t cap = (uint16_t)(need > 2u * r->dcap ? need : 2u * r->dcap);
		uint8_t *d = r->deps == r->deps_inline ? malloc(cap) : realloc(r->deps, cap);

		if (!d)
			return -ENOMEM;
		if (r->deps == r->deps_inline)
			memcpy(d, r->deps_inline, r->dsz);
		r->deps = d;
		r->dcap = cap;
	}
	r->memo[r->ndeps].off = r->dsz;
	r->memo[r->ndeps++].rule = idx;
	r->dsz += cache_dep_put(r->deps + r->dsz, r->o->cfg->rules[idx].fingerprint, name, len,
	                        r->qname.data, r->qname.len);
	return 0;
}

/*
 * The rule for name, recorded as a dependency. A name already recorded is
 * not matched again (while the config is the one the walk started with).
 * NULL when nothing matches, or out of memory.
 */
static const struct rule *dep_match(struct resolve_req *r, const uint8_t *name, uint8_t len)
{
	const struct config *cfg = r->o->cfg;
	int i = cfg->gen == r->gen0 ? dep_find(r, name, len, r->ndeps) : -1;
	uint16_t idx;

	if (i >= 0)
		return &cfg->rules[r->memo[i].rule];
	idx = match_lookup_wire(cfg->idx, name, len);
	if (idx == MATCH_NONE || idx >= cfg->nrules || dep_add(r, name, len, idx))
		return NULL;
	return &cfg->rules[idx];
}

static bool visited(const struct resolve_req *r, const struct dns_name *n)
{
	return dep_find(r, n->data, n->len, r->nwalk) >= 0;
}

static int bind_add(struct resolve_req *r, struct binding *b)
{
	struct binding **nb;
	uint16_t i;

	for (i = 0; i < r->nbinds; i++)
		if (r->binds[i] == b)
			return 0;
	if (r->nbinds == r->binds_cap) {
		uint16_t cap = r->binds_cap ? r->binds_cap * 2 : 4;

		if (cap > DNS_MAX_RRS * 16)
			return -E2BIG;
		nb = realloc(r->binds, cap * sizeof(*nb));
		if (!nb)
			return -ENOMEM;
		r->binds = nb;
		r->binds_cap = cap;
	}
	fakeip_ref(b);
	r->binds[r->nbinds++] = b;
	return 0;
}

static void set_up(struct upstream_set **slot, struct upstream_set *u)
{
	upstream_set_get(u);
	upstream_set_put(*slot);
	*slot = u;
}

/* ---- the answer ---- */

/*
 * An answer is written into wire as it is decided, record by record
 * (dns_build_add()), with what its lifetime needs noted on the way: the
 * lowest answer TTL and the first authority SOA, among every record
 * added (also those a cut leaves out). One answer is built at a time, all
 * of it synchronously; one that has to wait (for nft, or out of
 * resolve_start()) is copied to its request first, see hold().
 *
 * The compression table points into the names written, so they must stay
 * in place until the answer is done: the question, r->prefix and r->resp
 * do, as do bindings and the static synthetic SOA. hint_buf, reused by the
 * next rewrite, holds SVCB rdata, which is never compressed.
 */
static uint8_t wire[DNS_MAX_MSG];

static struct {
	struct dns_builder b;
	uint32_t an_ttl;
	bool soa;
	uint32_t soa_ttl, soa_min;
} ans;

static void ans_begin(struct resolve_req *r, int rcode)
{
	r->bare = r->held_on = false;
	r->rcode = rcode & DNS_F_RCODE;
	ans.an_ttl = UINT32_MAX;
	ans.soa = false;
	/* cannot fail: the question fits in 64 KiB */
	dns_build_begin(&ans.b, wire, sizeof(wire), 0, DNS_F_QR | DNS_F_RA | r->rd | r->rcode,
	                r->qname.data, r->qname.len, r->qtype, r->qclass);
}

static int ans_add(enum dns_section sec, const uint8_t *owner, uint8_t owner_len,
                   uint16_t type, uint16_t cls, uint32_t ttl,
                   const uint8_t *rd, uint16_t rdlen)
{
	if (sec == DNS_S_AN && ttl < ans.an_ttl)
		ans.an_ttl = ttl;
	if (sec == DNS_S_NS && type == DNS_T_SOA && !ans.soa) {
		/* rdata as parsed or synthesized: it ends with MINIMUM */
		ans.soa = true;
		ans.soa_ttl = ttl;
		ans.soa_min = (uint32_t)rd[rdlen - 4] << 24 | (uint32_t)rd[rdlen - 3] << 16 |
		              (uint32_t)rd[rdlen - 2] << 8 | rd[rdlen - 1];
	}
	return dns_build_add(&ans.b, sec, owner, owner_len, type, cls, ttl, rd, rdlen);
}

static int ans_rr(enum dns_section sec, const struct dns_rr *rr)
{
	return ans_add(sec, rr->owner, rr->owner_len, rr->type, rr->cls, rr->ttl, rr->rdata,
	               rr->rdlen);
}

/* The answer is complete; its lifetime as kind gives it. */
static void ans_done(struct resolve_req *r, int kind)
{
	const struct config *cfg = r->o->cfg;
	uint32_t v;

	r->alen = (uint32_t)dns_build_end(&ans.b);
	r->lifetime = 0;
	if (kind == LIFE_NONE || (r->rcode != DNS_R_NOERROR && r->rcode != DNS_R_NXDOMAIN))
		return;
	if (kind == LIFE_POS) {
		r->lifetime = ans.an_ttl;
	} else if (ans.soa) {
		v = ans.soa_ttl < ans.soa_min ? ans.soa_ttl : ans.soa_min;
		if (v > cfg->neg_ttl_max)
			v = cfg->neg_ttl_max;
		r->lifetime = v < ans.an_ttl ? v : ans.an_ttl;
	}
}

/* held-answer buffer: its first size, and the most a kept request keeps */
#define HELD_MIN	512
#define HELD_KEEP	2048

/*
 * Copy the answer out of wire, which other requests build into while this
 * one waits. A bare answer needs nothing: it is written when delivered.
 */
static int hold(struct resolve_req *r)
{
	uint32_t cap = r->alen > HELD_MIN ? r->alen : HELD_MIN;

	if (r->bare || r->held_on)
		return 0;
	if (r->held_cap < r->alen) {
		free(r->held);
		r->held = malloc(cap);
		r->held_cap = r->held ? cap : 0;
		if (!r->held)
			return -ENOMEM;
	}
	memcpy(r->held, wire, r->alen);
	r->held_on = true;
	return 0;
}

/* ---- request lifecycle ---- */

/* Free what a kept request keeps (when the pool lets it go). */
static void req_release(void *p)
{
	struct resolve_req *r = p;

	dns_msg_free(&r->resp);
	dns_msg_free(&r->prefix);
	free(r->binds);
	free(r->held);
}

/*
 * At most 64 ended requests are kept (a burst: a UDP read pass starts up to
 * 64), with up to a few KB of message storage each, and 4 once they go
 * unused (util/pool.h); requests in flight are bounded by max_pending.
 */
static struct pool req_pool = POOL_INIT(struct resolve_req, 64, 4, req_release);

static struct resolve_req *req_get(void)
{
	struct dns_msg resp, prefix;
	struct binding **binds;
	uint16_t binds_cap;
	uint8_t *held;
	uint32_t held_cap;
	struct resolve_req *r;
	bool fresh;

	r = pool_get(&req_pool, &fresh);
	if (!r || fresh)
		return r;
	resp = r->resp;
	prefix = r->prefix;
	binds = r->binds;
	binds_cap = r->binds_cap;
	held = r->held;
	held_cap = r->held_cap;
	memset(r, 0, sizeof(*r));
	r->resp = resp;
	r->prefix = prefix;
	r->binds = binds;
	r->binds_cap = binds_cap;
	r->held = held;
	r->held_cap = held_cap;
	return r;
}

static void req_free(struct resolve_req *r)
{
	uint16_t i;

	if (r->uq)
		upstream_cancel(r->uq);
	nft_wait_cancel(&r->nw);
	uloop_timeout_cancel(&r->defer);
	for (i = 0; i < r->nbinds; i++)
		fakeip_unref(r->o->fdb, r->binds[i]);
	if (r->latch.rule_id != r->latch.id_buf)
		free(r->latch.rule_id);
	upstream_set_put(r->latch.up);
	upstream_set_put(r->cur_up);
	dns_msg_recycle(&r->resp);
	dns_msg_recycle(&r->prefix);
	if (r->held_cap > HELD_KEEP) {
		free(r->held);
		r->held = NULL;
		r->held_cap = 0;
	}
	if (r->deps != r->deps_inline)
		free(r->deps);
	pool_put(&req_pool, r);
}

void resolve_shutdown(void)
{
	pool_drain(&req_pool);
}

/*
 * The answer leaves as bytes, built once: the cache stores them and the
 * server renders every reply from them, fresh or cached. wire is consumed
 * by the callback before anything else can build.
 */
static void deliver_now(struct resolve_req *r)
{
	const uint8_t *msg = r->held_on ? r->held : wire;
	struct omni *o = r->o;

	if (r->bare) {
		ans_begin(r, r->rcode);
		r->alen = (uint32_t)dns_build_end(&ans.b);
		msg = wire;
	}
	/* not when the config changed under the walk (its deps are stale) */
	if (r->cache_it && o->cfg->gen == r->gen0)
		cache_insert(o->cache, o->cfg, r->qname.data, r->qname.len, r->qtype,
		             r->qclass, r->key_hash,
		             msg, r->alen, r->lifetime, r->deps, r->dsz, r->ndeps,
		             r->binds, r->nbinds);
	r->cb(r->ctx, msg, r->alen);
	req_free(r);
}

static void defer_cb(struct uloop_timeout *t)
{
	deliver_now(container_of(t, struct resolve_req, defer));
}

static void finish_rcode(struct resolve_req *r, int rcode);

static void deliver(struct resolve_req *r)
{
	if (r->starting) {
		if (hold(r)) {
			finish_rcode(r, DNS_R_SERVFAIL);
			return;
		}
		uloop_timeout_set(&r->defer, 0);
		return;
	}
	deliver_now(r);
}

/* A bare answer: written when it is delivered, so it never needs holding. */
static void finish_rcode(struct resolve_req *r, int rcode)
{
	if (rcode == DNS_R_SERVFAIL)
		stats.servfail++;
	r->bare = true;
	r->rcode = rcode & DNS_F_RCODE;
	r->cache_it = false;
	deliver(r);
}

static void servfail(struct resolve_req *r)
{
	finish_rcode(r, DNS_R_SERVFAIL);
}

/* Reply with the final answer, cached (when the config did not change). */
static void finish_cached(struct resolve_req *r)
{
	if (r->nbinds)
		stats.fakeip_answers++;
	r->cache_it = r->o->cache && r->lifetime && !r->deps_full;
	deliver(r);
}

/* ---- synthetic records ---- */

static int put_name(uint8_t *p, const char *text)
{
	struct dns_name n;

	dns_name_from_text(&n, text);
	memcpy(p, n.data, n.len);
	return n.len;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

/* rd is static: the compression table points into its names */
static int add_synth_soa(struct resolve_req *r, uint32_t ttl)
{
	static const uint32_t fixed[] = { 1, 3600, 600, 86400 };
	static uint8_t rd[128];
	int n, i;

	n = put_name(rd, "omnidns.invalid.");
	n += put_name(rd + n, "hostmaster.omnidns.invalid.");
	for (i = 0; i < 4; i++, n += 4)
		put32(rd + n, fixed[i]);
	put32(rd + n, ttl);
	n += 4;
	return ans_add(DNS_S_NS, r->qname.data, r->qname.len, DNS_T_SOA, DNS_C_IN, ttl, rd,
	               (uint16_t)n);
}

static void finish_block(struct resolve_req *r)
{
	const struct config *cfg = r->o->cfg;
	static const uint8_t zero[16];
	int fam = afamily(r->qtype), ret;

	stats.blocked++;
	ans_begin(r, cfg->block_mode == BLOCK_NXDOMAIN ? DNS_R_NXDOMAIN : DNS_R_NOERROR);
	if (cfg->block_mode == BLOCK_NULL && fam)
		ret = ans_add(DNS_S_AN, r->qname.data, r->qname.len, r->qtype, DNS_C_IN,
		              cfg->block_ttl, zero, fam == 4 ? 4 : 16);
	else
		ret = add_synth_soa(r, cfg->block_ttl);
	if (ret) {
		servfail(r);
		return;
	}
	ans_done(r, LIFE_NONE);
	r->lifetime = cfg->block_ttl;
	finish_cached(r);
}

/* ---- PTR for fake addresses ---- */

static bool label_is(const uint8_t *l, const char *s)
{
	size_t n = strlen(s), i;

	if (l[0] != n)
		return false;
	for (i = 0; i < n; i++)
		if ((l[1 + i] | 0x20) != s[i])
			return false;
	return true;
}

static int hexval(uint8_t c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	c |= 0x20;
	return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* Parse a reverse name into an address; returns the family (4/6) or 0. */
static int ptr_addr(const uint8_t *name, uint8_t len, uint8_t *addr)
{
	const uint8_t *lab[40];
	int nl = 0, i, j, v;
	uint8_t off = 0;

	while (off < len && name[off]) {
		if (nl == 40)
			return 0;
		lab[nl++] = name + off;
		off += 1 + name[off];
	}
	if (nl == 6 && label_is(lab[4], "in-addr") && label_is(lab[5], "arpa")) {
		for (i = 0; i < 4; i++) {
			if (lab[i][0] < 1 || lab[i][0] > 3)
				return 0;
			for (v = 0, j = 1; j <= lab[i][0]; j++) {
				if (lab[i][j] < '0' || lab[i][j] > '9')
					return 0;
				v = v * 10 + lab[i][j] - '0';
			}
			if (v > 255)
				return 0;
			addr[3 - i] = (uint8_t)v;
		}
		return 4;
	}
	if (nl == 34 && label_is(lab[32], "ip6") && label_is(lab[33], "arpa")) {
		memset(addr, 0, 16);
		for (i = 0; i < 32; i++) {
			if (lab[i][0] != 1 || (v = hexval(lab[i][1])) < 0)
				return 0;
			addr[15 - i / 2] |= (uint8_t)(i & 1 ? v << 4 : v);
		}
		return 6;
	}
	return 0;
}

/* A PTR query for a fake-pool address: its family (addr filled), else 0. */
static int ptr_fake(const struct fakeip_db *fdb, const uint8_t *qname, uint8_t qlen,
                    uint16_t qtype, uint8_t *addr)
{
	int fam;

	if (qtype != DNS_T_PTR || !fdb)
		return 0;
	fam = ptr_addr(qname, qlen, addr);
	return fam && fakeip_in_pool(fdb, fam, addr) ? fam : 0;
}

static bool try_ptr(struct resolve_req *r)
{
	struct fakeip_db *fdb = r->o->fdb;
	struct binding *b;
	uint8_t addr[16];
	int fam = ptr_fake(fdb, r->qname.data, r->qname.len, r->qtype, addr);

	if (!fam)
		return false;
	b = fakeip_lookup(fdb, fam, addr);
	if (b) {
		ans_begin(r, DNS_R_NOERROR);
		if (ans_add(DNS_S_AN, r->qname.data, r->qname.len, DNS_T_PTR, DNS_C_IN, PTR_TTL,
		            binding_endpoint(b), b->endpoint_len))
			return servfail(r), true;
	} else {
		ans_begin(r, DNS_R_NXDOMAIN);
		if (add_synth_soa(r, r->o->cfg->block_ttl))
			return servfail(r), true;
	}
	ans_done(r, LIFE_NONE);
	deliver(r);
	return true;
}

/* ---- answer assembly ---- */

static bool strip_type(const struct resolve_req *r, uint16_t t)
{
	return t == DNS_T_RRSIG || t == DNS_T_NSEC || t == DNS_T_NSEC3 ||
	       (t == DNS_T_DS && r->qtype != DNS_T_DS);
}

static bool svcb_has_hints(const struct svcb_view *v)
{
	uint16_t off;

	for (off = 0; off + 4 <= v->params_len;
	     off += 4 + (v->params[off + 2] << 8 | v->params[off + 3])) {
		uint16_t key = (uint16_t)(v->params[off] << 8 | v->params[off + 1]);

		if (key == SVCB_KEY_IPV4HINT || key == SVCB_KEY_IPV6HINT)
			return true;
	}
	return false;
}

/*
 * May this SVCB/HTTPS record leave as received, outside what plan_svcb()
 * decides (passed through, or kept as additional data)? Its hints are
 * addresses of its effective target (the TargetName, or the owner for "."),
 * whose rule may be block or fakeip whatever the owner's: they may leave
 * only when that target matched a plain forward rule (then recorded as a
 * dependency). The caller makes sure no latch is on. An AliasMode record
 * leaves as received: clients ignore its SvcParams (RFC 9460 2.4.2). An
 * unparsable record never leaves, since its params cannot be checked for
 * hints.
 */
static bool svcb_ok(struct resolve_req *r, const struct dns_rr *rr)
{
	const struct rule *rule;
	struct svcb_view sv;
	bool root;

	if (svcb_parse(rr->rdata, rr->rdlen, &sv))
		return false;
	if (!sv.priority || !svcb_has_hints(&sv))
		return true;
	root = svcb_target_is_root(&sv);
	rule = dep_match(r, root ? rr->owner : sv.target, root ? rr->owner_len : sv.target_len);
	return rule && rule->action == RULE_FORWARD;
}

/*
 * Address records (A/AAAA/SVCB/HTTPS) outside the answer section. In the
 * authority section they never belong, so they are always dropped. In the
 * additional section they are kept only for names whose rule is a plain
 * forward, and only when nothing in this walk latched or bound: real
 * addresses of fakeip or blocked names must never reach the client via glue
 * (e.g. SRV/MX additional data). An SVCB/HTTPS record must also pass
 * svcb_ok(): its hints are its target's addresses. That decision depends on
 * rules, so the owner (and target) is recorded as a cache dependency.
 */
static bool glue_ok(struct resolve_req *r, const struct dns_rr *rr)
{
	const struct rule *rule;

	if (rr->section == DNS_S_AN ||
	    (rr->type != DNS_T_A && rr->type != DNS_T_AAAA &&
	     rr->type != DNS_T_SVCB && rr->type != DNS_T_HTTPS))
		return true;
	if (rr->section == DNS_S_NS || r->latch.on || r->nbinds)
		return false;
	rule = dep_match(r, rr->owner, rr->owner_len);
	return rule && rule->action == RULE_FORWARD && (!is_svcb(rr->type) || svcb_ok(r, rr));
}

static bool all_glue_ok(struct resolve_req *r)
{
	uint16_t i;

	for (i = 0; i < r->resp.nrr; i++)
		if (!glue_ok(r, &r->resp.rr[i]))
			return false;
	return true;
}

/* Add NS/AR of the last response to the answer (glue as glue_ok() allows). */
static int copy_tail(struct resolve_req *r, bool strip_sec)
{
	const struct dns_msg *m = &r->resp;
	uint16_t i;
	int ret;

	for (i = 0; i < m->nrr; i++) {
		const struct dns_rr *rr = &m->rr[i];

		if (rr->section == DNS_S_AN || (strip_sec && strip_type(r, rr->type)) ||
		    !glue_ok(r, rr))
			continue;
		ret = ans_rr(rr->section, rr);
		if (ret)
			return ret;
	}
	return 0;
}

static int copy_prefix(struct resolve_req *r)
{
	uint16_t i;
	int ret;

	for (i = 0; i < r->prefix.nrr; i++) {
		ret = ans_rr(DNS_S_AN, &r->prefix.rr[i]);
		if (ret)
			return ret;
	}
	return 0;
}

/* rr is a DNAME of the prefix (one the walk followed), or an RRSIG over it. */
static bool followed_dname(const struct resolve_req *r, const struct dns_rr *rr)
{
	bool sig = rr->type == DNS_T_RRSIG && rr->rdlen >= 2 &&
	           (rr->rdata[0] << 8 | rr->rdata[1]) == DNS_T_DNAME;
	uint16_t j;

	if (rr->type != DNS_T_DNAME && !sig)
		return false;
	for (j = 0; j < r->prefix.nrr; j++) {
		const struct dns_rr *d = &r->prefix.rr[j];

		if (d->type == DNS_T_DNAME &&
		    (sig ? dns_name_eq(d->owner, d->owner_len, rr->owner, rr->owner_len) :
		           rr_same(d, rr)))
			return true;
	}
	return false;
}

/*
 * Every answer record belongs to the chain: its owner is a name of this
 * walk (the qname or an alias target followed, all recorded as the first
 * nwalk dependencies), or it is a DNAME the walk followed (in the prefix)
 * or that DNAME's RRSIG. A DNAME owner is never matched against the rules,
 * so any other record it owns, like records of any other name, must not
 * ride along in a passed-through answer.
 */
static bool all_an_chain(const struct resolve_req *r)
{
	const struct dns_msg *m = &r->resp;
	uint16_t i;

	for (i = 0; i < m->nrr && m->rr[i].section == DNS_S_AN; i++) {
		const struct dns_rr *rr = &m->rr[i];

		if (dep_find(r, rr->owner, rr->owner_len, r->nwalk) < 0 &&
		    !followed_dname(r, rr))
			return false;
	}
	return true;
}

/*
 * Every SVCB/HTTPS answer record may leave as received (svcb_ok()). Those
 * plan_svcb() kept as they are pass this too; any other one (at a walk name
 * before the final one, or not of the queried type) is checked here, and
 * fails the response over to assembly, which leaves it out.
 */
static bool an_svcb_ok(struct resolve_req *r)
{
	const struct dns_msg *m = &r->resp;
	uint16_t i;

	for (i = 0; i < m->nrr && m->rr[i].section == DNS_S_AN; i++)
		if (is_svcb(m->rr[i].type) && !svcb_ok(r, &m->rr[i]))
			return false;
	return true;
}

static bool can_pass_through(struct resolve_req *r)
{
	return r->nresp == 1 && !r->synth && !r->latch.on && !r->nbinds && all_an_chain(r) &&
	       an_svcb_ok(r) && all_glue_ok(r);
}

/*
 * The response's records become the answer, all of them as received (what
 * was added so far is dropped). Only the header is ours: id 0, no OPT
 * (which also drops an extended rcode), our flags (AA and AD cleared) and
 * the client's question.
 */
static int pass_through(struct resolve_req *r)
{
	const struct dns_msg *m = &r->resp;
	uint16_t i;
	int ret = 0;

	ans_begin(r, m->flags & DNS_F_RCODE);
	for (i = 0; !ret && i < m->nrr; i++)
		ret = ans_rr(m->rr[i].section, &m->rr[i]);
	return ret;
}

/* Answer = prefix + negative response (its SOA kept). */
static void finish_negative(struct resolve_req *r)
{
	int rcode = r->resp.flags & DNS_F_RCODE, ret;

	if (can_pass_through(r)) {
		ret = pass_through(r);
	} else {
		ans_begin(r, rcode);
		ret = copy_prefix(r);
		if (!ret)
			ret = copy_tail(r, false);
	}
	if (ret) {
		servfail(r);
		return;
	}
	ans_done(r, LIFE_NEG);
	finish_cached(r);
}

/* ---- commit: wait for every binding's nft batch ---- */

static void commit_wait(struct resolve_req *r);

static void nft_done(struct nft_waiter *w, int err)
{
	struct resolve_req *r = container_of(w, struct resolve_req, nw);

	if (err) {
		servfail(r);
		return;
	}
	r->wait_i++;
	commit_wait(r);
}

static void commit_wait(struct resolve_req *r)
{
	struct omni *o = r->o;
	uint16_t i;

	for (; r->wait_i < r->nbinds; r->wait_i++) {
		struct binding *b = r->binds[r->wait_i];

		if (!nft_ticket_done(o->nft, b->ticket)) {
			if (hold(r)) {
				servfail(r);
				return;
			}
			r->nw.cb = nft_done;
			nft_wait(o->nft, &r->nw, b->ticket);
			return;
		}
	}
	/* a failed batch drops its bindings from the DB */
	for (i = 0; i < r->nbinds; i++)
		if (fakeip_lookup(o->fdb, r->binds[i]->family, binding_fake(r->binds[i])) !=
		    r->binds[i]) {
			servfail(r);
			return;
		}
	finish_cached(r);
}

/* ---- terminal processing ---- */

struct hint_ctx {
	struct resolve_req *r;
	const char *rule_id;
	uint32_t mark;
	const uint8_t *endpoint;
	uint8_t endpoint_len;
	uint32_t ttl;
};

/*
 * At most RESOLVE_MAX_FAKES distinct fakes per answer (-EDQUOT beyond: the
 * address is omitted), so one hostile answer cannot drain the pool.
 */
#define RESOLVE_MAX_FAKES 32

/* TTL of rewritten records and their bindings: capped by fakeip_ttl_max. */
static uint32_t fake_ttl(const struct resolve_req *r, uint32_t ttl)
{
	return ttl < r->o->cfg->fakeip_ttl_max ? ttl : r->o->cfg->fakeip_ttl_max;
}

static struct binding *do_bind(struct resolve_req *r, const char *rule_id, uint32_t mark,
                               const uint8_t *ep, uint8_t eplen, int fam,
                               const uint8_t *real, uint32_t ttl, int *err)
{
	struct binding *b;

	if (r->nbinds >= RESOLVE_MAX_FAKES) {
		*err = -EDQUOT;
		return NULL;
	}
	b = fakeip_bind(r->o->fdb, rule_id, mark, ep, eplen, fam, real, ttl, err);
	if (!b && *err == -ENOSPC && cache_sweep_expired(r->o->cache))
		b = fakeip_bind(r->o->fdb, rule_id, mark, ep, eplen, fam, real, ttl, err);
	if (!b) {
		if (*err == -ENOSPC)
			log_rl(LOG_WARNING, "fake IP pool exhausted (rule %s, IPv%d)",
			       rule_id, fam);
		return NULL;
	}
	*err = bind_add(r, b);
	return *err ? NULL : b;
}

static int hint_fn(void *ctx, int family, const uint8_t *in, uint8_t *out)
{
	struct hint_ctx *h = ctx;
	struct binding *b;
	int err;

	if (!fakeip_has_pool(h->r->o->fdb, family))
		return 1;
	b = do_bind(h->r, h->rule_id, h->mark, h->endpoint, h->endpoint_len,
	            family, in, h->ttl, &err);
	if (!b)
		return err == -EDQUOT ? 1 : err;
	memcpy(out, binding_fake(b), family == 4 ? 4 : 16);
	return 0;
}

static int emit_hints(struct resolve_req *r, const struct dns_rr *rr,
                      const struct plan *p, bool *changed)
{
	struct hint_ctx h = {
		.r = r, .rule_id = p->rule_id, .mark = p->mark, .ttl = fake_ttl(r, rr->ttl),
	};
	uint16_t len;
	int ret;

	if (svcb_target_is_root(&p->sv)) {
		h.endpoint = r->name.data;
		h.endpoint_len = r->name.len;
	} else {
		h.endpoint = p->sv.target;
		h.endpoint_len = p->sv.target_len;
	}
	/* fakes have the size of the addresses they replace */
	ret = svcb_rewrite_view(&p->sv, hint_fn, &h, !fakeip_has_pool(r->o->fdb, 6),
	                        hint_buf, rr->rdlen, &len);
	if (ret)
		return ret;
	if (len != rr->rdlen || memcmp(hint_buf, rr->rdata, len))
		*changed = true;
	return ans_add(DNS_S_AN, rr->owner, rr->owner_len, rr->type, rr->cls, h.ttl, hint_buf, len);
}

static int emit_addr(struct resolve_req *r, const struct dns_rr *rr, const struct plan *p)
{
	int fam = afamily(rr->type), err;
	uint32_t ttl = fake_ttl(r, rr->ttl);
	struct binding *b;

	b = do_bind(r, p->rule_id, p->mark, r->name.data, r->name.len, fam,
	            rr->rdata, ttl, &err);
	if (!b)
		return err == -EDQUOT ? 0 : err;
	return ans_add(DNS_S_AN, rr->owner, rr->owner_len, rr->type, rr->cls, ttl,
	               binding_fake(b), rr->rdlen);
}

/*
 * Decide one ServiceMode RR (match its effective target). An AliasMode RR
 * (to ".", or scan() would have followed it) is kept as received: clients
 * ignore its SvcParams (RFC 9460 2.4.2).
 */
static int plan_svcb(struct resolve_req *r, struct plan *p)
{
	const struct rule *rule;
	const uint8_t *t;
	uint8_t tlen;

	if (!p->sv_ok) {
		p->act = ACT_DROP;
		return 0;
	}
	p->act = ACT_KEEP;
	if (!p->sv.priority)
		return 0;
	t = svcb_target_is_root(&p->sv) ? r->name.data : p->sv.target;
	tlen = svcb_target_is_root(&p->sv) ? r->name.len : p->sv.target_len;
	rule = dep_match(r, t, tlen);
	if (!rule)
		return -ENOENT;
	if (rule->action == RULE_BLOCK) {
		p->act = ACT_DROP;
	} else if (r->latch.on) {
		p->act = ACT_HINTS;
		p->rule_id = r->latch.rule_id;
		p->mark = r->latch.mark;
	} else if (rule->action == RULE_FAKEIP) {
		p->act = ACT_HINTS;
		p->rule_id = rule->id;
		p->mark = rule->mark;
	}
	return 0;
}

/* NODATA after dropping everything: prefix + (upstream SOA | synthetic SOA). */
static int build_nodata(struct resolve_req *r)
{
	const struct dns_rr *soa = find_soa(&r->resp);
	int ret;

	ans_begin(r, DNS_R_NOERROR);
	ret = copy_prefix(r);
	if (ret)
		return ret;
	if (soa)
		return ans_rr(DNS_S_NS, soa);
	return add_synth_soa(r, r->o->cfg->block_ttl);
}

/*
 * Fill plan[] for the answer records. *changed: some record is not kept as
 * is (dropped, bound or hint-rewritten).
 */
static int plan_terminal(struct resolve_req *r, uint16_t *nkept, bool *dropped,
                         bool *changed)
{
	const struct dns_msg *m = &r->resp;
	int fam = afamily(r->qtype), ret;
	uint16_t i;

	for (i = 0; i < m->nrr && m->rr[i].section == DNS_S_AN; i++) {
		const struct dns_rr *rr = &m->rr[i];
		struct plan *p = &plan[i];

		p->act = ACT_SKIP;
		if (rr->type != r->qtype || !owned(rr, &r->name))
			continue;
		if (fam && r->latch.on) {
			if (!fakeip_has_pool(r->o->fdb, fam) || rr->rdlen != (fam == 4 ? 4 : 16)) {
				p->act = ACT_DROP;
			} else {
				p->act = ACT_BIND;
				p->rule_id = r->latch.rule_id;
				p->mark = r->latch.mark;
			}
		} else if (is_svcb(r->qtype)) {
			ret = plan_svcb(r, p);
			if (ret)
				return ret;
		} else {
			p->act = ACT_KEEP;
		}
		if (p->act == ACT_DROP)
			*dropped = true;
		else
			(*nkept)++;
		if (p->act != ACT_KEEP)
			*changed = true;
	}
	return 0;
}

/* Assemble prefix + planned records + tail; changed as from plan_terminal. */
static int build_terminal(struct resolve_req *r, bool changed, bool *rewritten)
{
	const struct dns_msg *m = &r->resp;
	uint16_t i;
	int ret;

	ans_begin(r, m->flags & DNS_F_RCODE);
	ret = copy_prefix(r);
	for (i = 0; !ret && i < m->nrr && m->rr[i].section == DNS_S_AN; i++) {
		switch (plan[i].act) {
		case ACT_KEEP:
			ret = ans_rr(DNS_S_AN, &m->rr[i]);
			break;
		case ACT_BIND:
			ret = emit_addr(r, &m->rr[i], &plan[i]);
			*rewritten = true;
			break;
		case ACT_HINTS:
			ret = emit_hints(r, &m->rr[i], &plan[i], rewritten);
			break;
		}
	}
	if (ret)
		return ret;
	/* hints were planned, but there was nothing to rewrite */
	if (changed && !*rewritten && can_pass_through(r))
		return pass_through(r);
	return copy_tail(r, *rewritten);
}

static void terminal(struct resolve_req *r)
{
	bool dropped = false, changed = false, rewritten;
	uint16_t nkept = 0;
	int ret, kind = LIFE_POS;

	ret = plan_terminal(r, &nkept, &dropped, &changed);
	rewritten = dropped;
	if (!ret && !nkept) {
		ret = build_nodata(r);
		kind = LIFE_NEG;
	} else if (!ret && !changed && can_pass_through(r)) {
		ret = pass_through(r);
	} else if (!ret) {
		ret = build_terminal(r, changed, &rewritten);
	}
	if (ret) {
		servfail(r);
		return;
	}
	ans_done(r, kind);
	r->wait_i = 0;
	commit_wait(r);
}

/* ---- the walk ---- */

static void walk(struct resolve_req *r, bool scan);

static void upstream_done(void *ctx, int err, struct dns_msg *resp)
{
	struct resolve_req *r = ctx;

	r->uq = NULL;
	if (err || !resp) {
		servfail(r);
		return;
	}
	/*
	 * take the message over; nothing references the previous one, whose
	 * storage the upstream client may reuse for its next response
	 */
	dns_msg_reset(&r->resp);
	dns_msg_swap(&r->resp, resp);
	r->nresp++;
	walk(r, true);
}

static void query(struct resolve_req *r)
{
	r->uq = upstream_query(r->cur_up, r->name.data, r->name.len, r->qtype,
	                       upstream_done, r);
	if (!r->uq)
		servfail(r);
}

static int latch_set(struct resolve_req *r, const struct rule *rule)
{
	size_t n = strlen(rule->id) + 1;

	r->latch.rule_id = n <= sizeof(r->latch.id_buf) ? r->latch.id_buf : malloc(n);
	if (!r->latch.rule_id)
		return -ENOMEM;
	memcpy(r->latch.rule_id, rule->id, n);
	r->latch.on = true;
	r->latch.mark = rule->mark;
	set_up(&r->latch.up, rule->up);
	return 0;
}

/* Steps 1-4. Returns true when the walk continues asynchronously or ended. */
static bool policy_step(struct resolve_req *r)
{
	const struct rule *rule;
	struct upstream_set *want;

	rule = dep_match(r, r->name.data, r->name.len);
	if (!rule)
		return servfail(r), true;
	r->nwalk = r->ndeps;
	if (rule->action == RULE_BLOCK)
		return finish_block(r), true;
	if (!r->latch.on && rule->action == RULE_FAKEIP && latch_set(r, rule))
		return servfail(r), true;
	want = r->latch.on ? r->latch.up : rule->up;
	if (!want)
		return servfail(r), true;
	if (r->nresp && want->id == r->cur_up->id)
		return false;
	if (r->nresp)
		stats.requeries++;
	set_up(&r->cur_up, want);
	query(r);
	return true;
}

static int alias_to(struct resolve_req *r, const struct dns_name *target)
{
	if (++r->steps > RESOLVE_MAX_STEPS || visited(r, target)) {
		servfail(r);
		return SCAN_DONE;
	}
	r->name = *target;
	return SCAN_ALIAS;
}

static int synth_cname(struct resolve_req *r, const struct dns_rr *dname,
                       struct dns_name *target)
{
	struct dns_name t;
	int ret;

	ret = dns_rr_target(dname, &t);
	if (ret)
		return ret;
	ret = dns_name_dname_subst(r->name.data, r->name.len, dname->owner,
	                           dname->owner_len, t.data, t.len, target);
	if (ret)
		return ret;
	r->synth = true;
	return dns_msg_add_rr(&r->prefix, DNS_S_AN, r->name.data, r->name.len,
	                      DNS_T_CNAME, DNS_C_IN, dname->ttl, target->data, target->len);
}

static int scan_dname(struct resolve_req *r, const struct dns_rr *dname)
{
	const struct dns_rr *cname = find_rr(&r->resp, &r->name, DNS_T_CNAME);
	struct dns_name target;
	int ret;

	ret = prefix_add(r, dname);
	if (!ret && cname) {
		ret = dns_rr_target(cname, &target);
		if (!ret)
			ret = prefix_add(r, cname);
	} else if (!ret) {
		ret = synth_cname(r, dname, &target);
		if (ret == -EOVERFLOW) {
			ans_begin(r, DNS_R_YXDOMAIN);
			if (copy_prefix(r)) {
				servfail(r);
			} else {
				ans_done(r, LIFE_NONE);
				deliver(r);
			}
			return SCAN_DONE;
		}
	}
	if (ret) {
		servfail(r);
		return SCAN_DONE;
	}
	return alias_to(r, &target);
}

static int scan_alias(struct resolve_req *r, const struct dns_rr *rr)
{
	struct dns_name target;

	if (dns_rr_target(rr, &target) || prefix_add(r, rr)) {
		servfail(r);
		return SCAN_DONE;
	}
	return alias_to(r, &target);
}

/* The AliasMode record to follow; parses the records it looks at into plan[]. */
static const struct plan *find_svcb_alias(const struct resolve_req *r)
{
	const struct dns_msg *m = &r->resp;
	uint16_t i;

	for (i = 0; i < m->nrr && m->rr[i].section == DNS_S_AN; i++) {
		const struct dns_rr *rr = &m->rr[i];
		struct plan *p = &plan[i];

		if (rr->type != r->qtype || !owned(rr, &r->name))
			continue;
		p->sv_ok = !svcb_parse(rr->rdata, rr->rdlen, &p->sv);
		if (p->sv_ok && !p->sv.priority && !svcb_target_is_root(&p->sv))
			return p;
	}
	return NULL;
}

static int scan_svcb_alias(struct resolve_req *r, const struct plan *p)
{
	const struct dns_rr *rr = &r->resp.rr[p - plan];
	struct dns_name target;

	memcpy(target.data, p->sv.target, p->sv.target_len);
	target.len = p->sv.target_len;
	if (prefix_add(r, rr)) {
		servfail(r);
		return SCAN_DONE;
	}
	return alias_to(r, &target);
}

/* Step 5: follow the current response from r->name. */
static int scan(struct resolve_req *r)
{
	const struct dns_msg *m = &r->resp;
	const struct dns_rr *rr;
	const struct plan *alias;
	int rcode = m->flags & DNS_F_RCODE;
	bool asked;

	if (r->qtype != DNS_T_DNAME && r->qtype != DNS_T_CNAME &&
	    (rr = find_dname(m, &r->name)))
		return scan_dname(r, rr);
	if (r->qtype != DNS_T_CNAME && (rr = find_rr(m, &r->name, DNS_T_CNAME)))
		return scan_alias(r, rr);
	if (is_svcb(r->qtype) && (alias = find_svcb_alias(r)))
		return scan_svcb_alias(r, alias);
	if (find_rr(m, &r->name, r->qtype)) {
		terminal(r);
		return SCAN_DONE;
	}
	asked = m->has_q && dns_name_eq(dns_msg_qname(m), m->qlen, r->name.data, r->name.len);
	if (rcode != DNS_R_NOERROR || asked || find_soa(m)) {
		finish_negative(r);
		return SCAN_DONE;
	}
	return SCAN_QUERY;	/* dangling: the upstream did not chase the alias */
}

static void walk(struct resolve_req *r, bool scanning)
{
	for (;;) {
		if (!scanning && policy_step(r))
			return;
		scanning = false;
		switch (scan(r)) {
		case SCAN_ALIAS:
			continue;
		case SCAN_QUERY:
			query(r);
			return;
		default:
			return;
		}
	}
}

/* ---- entry points ---- */

int resolve_lookup(struct omni *o, const struct dns_msg *query, struct cache_hit *hit)
{
	const uint8_t *qname = dns_msg_qname(query);
	uint8_t addr[16];

	if (!query->has_q)
		return -ENOENT;
	/* for resolve_start_miss(): the insert after a miss hashes no more */
	hit->hash = cache_hash(qname, query->qlen, query->qtype, query->qclass);
	/* the precedence resolve_start() applies: ANY and fake PTR come first */
	if (!o->cache || query->qtype == DNS_T_ANY ||
	    ptr_fake(o->fdb, qname, query->qlen, query->qtype, addr))
		return -ENOENT;
	if (cache_lookup(o->cache, o->cfg, qname, query->qlen, query->qtype, query->qclass,
	                 hit->hash, hit))
		return -ENOENT;
	stats.requests++;
	stats.cache_hits++;
	return 0;
}

static struct resolve_req *start(struct omni *o, const struct dns_msg *query,
                                 uint64_t key_hash, resolve_cb cb, void *ctx)
{
	struct resolve_req *r;

	if (!query->has_q)
		return NULL;
	r = req_get();
	if (!r)
		return NULL;
	r->o = o;
	r->cb = cb;
	r->ctx = ctx;
	r->defer.cb = defer_cb;
	r->starting = true;
	r->gen0 = o->cfg->gen;
	memcpy(r->qname.data, dns_msg_qname(query), query->qlen);
	r->qname.len = query->qlen;
	r->qtype = query->qtype;
	r->qclass = query->qclass;
	r->key_hash = key_hash;
	r->rd = query->flags & DNS_F_RD;
	r->name = r->qname;
	r->deps = r->deps_inline;
	r->dcap = sizeof(r->deps_inline);
	stats.requests++;

	if (r->qtype == DNS_T_ANY)
		finish_rcode(r, DNS_R_NOTIMP);
	else if (!try_ptr(r))
		walk(r, false);
	r->starting = false;
	return r;
}

struct resolve_req *resolve_start(struct omni *o, const struct dns_msg *query,
                                  resolve_cb cb, void *ctx)
{
	if (!query->has_q)
		return NULL;
	return start(o, query, cache_hash(dns_msg_qname(query), query->qlen, query->qtype,
	                                  query->qclass), cb, ctx);
}

struct resolve_req *resolve_start_miss(struct omni *o, const struct dns_msg *query,
                                       const struct cache_hit *miss, resolve_cb cb, void *ctx)
{
	return start(o, query, miss->hash, cb, ctx);
}

void resolve_cancel(struct resolve_req *r)
{
	if (r)
		req_free(r);
}
