// SPDX-License-Identifier: GPL-2.0-only
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

#define PTR_TTL		60
#define DNS_R_YXDOMAIN	6

struct latch {
	bool on;
	char *rule_id;
	uint32_t mark;
	struct upstream_set *up;
};

struct resolve_req {
	struct omni *o;
	resolve_cb cb;
	void *ctx;
	struct uloop_timeout defer;
	struct upstream_query *uq;
	struct nft_waiter nw;
	bool starting, deferred;
	uint64_t gen0;

	struct dns_name qname;
	uint16_t qtype, qclass, rd;

	/* walk state */
	struct dns_name name;
	struct upstream_set *cur_up;
	struct latch latch;
	struct dns_msg resp;
	bool have_resp, requeried, synth;
	uint16_t nresp, steps;
	struct dns_msg prefix;
	struct cache_dep *deps;
	uint16_t ndeps, deps_cap;

	/* commit */
	struct binding **binds;
	uint16_t nbinds, binds_cap, wait_i;
	struct dns_msg out;
	uint32_t lifetime;
};

enum { SCAN_ALIAS, SCAN_DONE, SCAN_QUERY };
enum { ACT_SKIP = 0, ACT_KEEP, ACT_DROP, ACT_BIND, ACT_HINTS };
enum { LIFE_NONE, LIFE_POS, LIFE_NEG };

struct plan {
	uint8_t act;
	const char *rule_id;
	uint32_t mark;
};

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

static int add_rr(struct dns_msg *m, enum dns_section sec, const struct dns_rr *rr)
{
	return dns_msg_add_rr(m, sec, rr->owner, rr->owner_len, rr->type, rr->cls,
			      rr->ttl, rr->rdata, rr->rdlen);
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
	return add_rr(&r->prefix, DNS_S_AN, rr);
}

static int dep_add(struct resolve_req *r, const uint8_t *name, uint8_t len, uint64_t fp)
{
	struct cache_dep *d;

	if (r->ndeps == r->deps_cap) {
		uint16_t cap = r->deps_cap ? r->deps_cap * 2 : 4;

		d = realloc(r->deps, cap * sizeof(*d));
		if (!d)
			return -ENOMEM;
		r->deps = d;
		r->deps_cap = cap;
	}
	d = &r->deps[r->ndeps++];
	memcpy(d->name.data, name, len);
	d->name.len = len;
	dns_name_lower(d->name.data, len);
	d->fingerprint = fp;
	return 0;
}

static bool visited(const struct resolve_req *r, const struct dns_name *n)
{
	uint16_t i;

	for (i = 0; i < r->ndeps; i++)
		if (dns_name_eq(r->deps[i].name.data, r->deps[i].name.len, n->data, n->len))
			return true;
	return false;
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

/* ---- lifetime ---- */

static uint32_t min_an_ttl(const struct dns_msg *m, uint32_t v)
{
	uint16_t i;

	for (i = 0; i < m->nrr; i++)
		if (m->rr[i].section == DNS_S_AN && m->rr[i].ttl < v)
			v = m->rr[i].ttl;
	return v;
}

static uint32_t neg_lifetime(const struct config *cfg, const struct dns_msg *m)
{
	const struct dns_rr *soa = find_soa(m);
	uint32_t v, min;

	if (!soa || dns_soa_minimum(soa, &min))
		return 0;
	v = soa->ttl < min ? soa->ttl : min;
	if (v > cfg->neg_ttl_max)
		v = cfg->neg_ttl_max;
	return min_an_ttl(m, v);
}

static uint32_t lifetime_of(const struct config *cfg, const struct dns_msg *m, int kind)
{
	int rc = m->flags & DNS_F_RCODE;

	if (kind == LIFE_NONE || (rc != DNS_R_NOERROR && rc != DNS_R_NXDOMAIN))
		return 0;
	if (kind == LIFE_POS)
		return min_an_ttl(m, UINT32_MAX);
	return neg_lifetime(cfg, m);
}

/* ---- request lifecycle ---- */

static void req_free(struct resolve_req *r)
{
	uint16_t i;

	if (r->uq)
		upstream_cancel(r->uq);
	nft_wait_cancel(&r->nw);
	uloop_timeout_cancel(&r->defer);
	for (i = 0; i < r->nbinds; i++)
		fakeip_unref(r->o->fdb, r->binds[i]);
	free(r->binds);
	free(r->latch.rule_id);
	upstream_set_put(r->latch.up);
	upstream_set_put(r->cur_up);
	dns_msg_free(&r->resp);
	dns_msg_free(&r->prefix);
	dns_msg_free(&r->out);
	free(r->deps);
	free(r);
}

static void deliver_now(struct resolve_req *r)
{
	r->cb(r->ctx, &r->out);
	req_free(r);
}

static void defer_cb(struct uloop_timeout *t)
{
	deliver_now(container_of(t, struct resolve_req, defer));
}

static void deliver(struct resolve_req *r)
{
	if (r->starting) {
		r->deferred = true;
		uloop_timeout_set(&r->defer, 0);
		return;
	}
	deliver_now(r);
}

static void out_init(struct resolve_req *r, int rcode)
{
	dns_msg_reset(&r->out);
	dns_msg_set_question(&r->out, r->qname.data, r->qname.len, r->qtype, r->qclass);
	r->out.flags = DNS_F_QR | DNS_F_RA | r->rd;
	dns_msg_set_rcode(&r->out, rcode);
}

static void finish_rcode(struct resolve_req *r, int rcode)
{
	if (rcode == DNS_R_SERVFAIL)
		stats.servfail++;
	out_init(r, rcode);
	deliver(r);
}

static void servfail(struct resolve_req *r)
{
	finish_rcode(r, DNS_R_SERVFAIL);
}

/* Cache the final answer (when the config did not change) and reply. */
static void finish_cached(struct resolve_req *r)
{
	struct omni *o = r->o;

	if (r->nbinds)
		stats.fakeip_answers++;
	if (o->cache && r->lifetime && o->cfg->gen == r->gen0)
		cache_insert(o->cache, o->cfg, r->qname.data, r->qname.len, r->qtype,
			     r->qclass, &r->out, r->lifetime, r->deps, r->ndeps,
			     r->binds, r->nbinds);
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

static int add_synth_soa(struct resolve_req *r, uint32_t ttl)
{
	static const uint32_t fixed[] = { 1, 3600, 600, 86400 };
	uint8_t rd[128];
	int n, i;

	n = put_name(rd, "omnidns.invalid.");
	n += put_name(rd + n, "hostmaster.omnidns.invalid.");
	for (i = 0; i < 4; i++, n += 4)
		put32(rd + n, fixed[i]);
	put32(rd + n, ttl);
	n += 4;
	return dns_msg_add_rr(&r->out, DNS_S_NS, r->qname.data, r->qname.len, DNS_T_SOA,
			      DNS_C_IN, ttl, rd, (uint16_t)n);
}

static void finish_block(struct resolve_req *r)
{
	const struct config *cfg = r->o->cfg;
	static const uint8_t zero[16];
	int fam = afamily(r->qtype), ret;

	stats.blocked++;
	out_init(r, cfg->block_mode == BLOCK_NXDOMAIN ? DNS_R_NXDOMAIN : DNS_R_NOERROR);
	if (cfg->block_mode == BLOCK_NULL && fam)
		ret = dns_msg_add_rr(&r->out, DNS_S_AN, r->qname.data, r->qname.len,
				     r->qtype, DNS_C_IN, cfg->block_ttl, zero,
				     fam == 4 ? 4 : 16);
	else
		ret = add_synth_soa(r, cfg->block_ttl);
	if (ret) {
		servfail(r);
		return;
	}
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
static int ptr_addr(const struct dns_name *n, uint8_t *addr)
{
	const uint8_t *lab[40];
	int nl = 0, i, j, v;
	uint8_t off = 0;

	while (off < n->len && n->data[off]) {
		if (nl == 40)
			return 0;
		lab[nl++] = n->data + off;
		off += 1 + n->data[off];
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

static bool try_ptr(struct resolve_req *r)
{
	struct fakeip_db *fdb = r->o->fdb;
	struct binding *b;
	uint8_t addr[16];
	int fam;

	if (r->qtype != DNS_T_PTR || !fdb)
		return false;
	fam = ptr_addr(&r->qname, addr);
	if (!fam || !fakeip_in_pool(fdb, fam, addr))
		return false;
	b = fakeip_lookup(fdb, fam, addr);
	if (b) {
		out_init(r, DNS_R_NOERROR);
		if (dns_msg_add_rr(&r->out, DNS_S_AN, r->qname.data, r->qname.len,
				   DNS_T_PTR, DNS_C_IN, PTR_TTL, b->endpoint, b->endpoint_len))
			return servfail(r), true;
	} else {
		out_init(r, DNS_R_NXDOMAIN);
		if (add_synth_soa(r, r->o->cfg->block_ttl))
			return servfail(r), true;
	}
	deliver(r);
	return true;
}

/* ---- answer assembly ---- */

static bool strip_type(const struct resolve_req *r, uint16_t t)
{
	return t == DNS_T_RRSIG || t == DNS_T_NSEC || t == DNS_T_NSEC3 ||
	       (t == DNS_T_DS && r->qtype != DNS_T_DS);
}

/* Copy NS/AR of the last response into out. */
static int copy_tail(struct resolve_req *r, bool strip_sec, bool strip_glue, bool no_ar)
{
	const struct dns_msg *m = &r->resp;
	uint16_t i;
	int ret;

	for (i = 0; i < m->nrr; i++) {
		const struct dns_rr *rr = &m->rr[i];

		if (rr->section == DNS_S_AN || (no_ar && rr->section == DNS_S_AR))
			continue;
		if (strip_sec && strip_type(r, rr->type))
			continue;
		if (strip_glue && rr->section == DNS_S_AR &&
		    (rr->type == DNS_T_A || rr->type == DNS_T_AAAA))
			continue;
		ret = add_rr(&r->out, rr->section, rr);
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
		ret = add_rr(&r->out, DNS_S_AN, &r->prefix.rr[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static bool can_pass_through(const struct resolve_req *r)
{
	return r->nresp == 1 && !r->requeried && !r->synth && !r->latch.on && !r->nbinds;
}

static int pass_through(struct resolve_req *r)
{
	int rcode = r->resp.flags & DNS_F_RCODE, ret;

	ret = dns_msg_copy(&r->out, &r->resp);
	if (ret)
		return ret;
	memset(&r->out.edns, 0, sizeof(r->out.edns));
	r->out.id = 0;
	ret = dns_msg_set_question(&r->out, r->qname.data, r->qname.len, r->qtype, r->qclass);
	r->out.flags = DNS_F_QR | DNS_F_RA | r->rd;
	dns_msg_set_rcode(&r->out, rcode);
	return ret;
}

/* Answer = prefix + negative response (its SOA kept). */
static void finish_negative(struct resolve_req *r)
{
	int rcode = r->resp.flags & DNS_F_RCODE, ret;

	if (can_pass_through(r)) {
		ret = pass_through(r);
	} else {
		out_init(r, rcode);
		ret = copy_prefix(r);
		if (!ret)
			ret = copy_tail(r, false, r->latch.on, false);
	}
	if (ret) {
		servfail(r);
		return;
	}
	r->lifetime = lifetime_of(r->o->cfg, &r->out, LIFE_NEG);
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
			r->nw.cb = nft_done;
			nft_wait(o->nft, &r->nw, b->ticket);
			return;
		}
	}
	/* a failed batch drops its bindings from the DB */
	for (i = 0; i < r->nbinds; i++)
		if (fakeip_lookup(o->fdb, r->binds[i]->family, r->binds[i]->fake) != r->binds[i]) {
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

static struct binding *do_bind(struct resolve_req *r, const char *rule_id, uint32_t mark,
			       const uint8_t *ep, uint8_t eplen, int fam,
			       const uint8_t *real, uint32_t ttl, int *err)
{
	struct binding *b;

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
		return err;
	memcpy(out, b->fake, family == 4 ? 4 : 16);
	return 0;
}

static int emit_hints(struct resolve_req *r, const struct dns_rr *rr,
		      const struct plan *p, bool *changed)
{
	struct hint_ctx h = { .r = r, .rule_id = p->rule_id, .mark = p->mark, .ttl = rr->ttl };
	struct svcb_view v;
	uint8_t *buf;
	uint16_t len;
	int ret;

	ret = svcb_parse(rr->rdata, rr->rdlen, &v);
	if (ret)
		return ret;
	if (svcb_target_is_root(&v)) {
		h.endpoint = r->name.data;
		h.endpoint_len = r->name.len;
	} else {
		h.endpoint = v.target;
		h.endpoint_len = v.target_len;
	}
	/* fakes have the size of the addresses they replace */
	buf = malloc(rr->rdlen);
	if (!buf)
		return -ENOMEM;
	ret = svcb_rewrite_hints(rr->rdata, rr->rdlen, hint_fn, &h,
				 !fakeip_has_pool(r->o->fdb, 6), buf, rr->rdlen, &len);
	if (!ret) {
		if (len != rr->rdlen || memcmp(buf, rr->rdata, len))
			*changed = true;
		ret = dns_msg_add_rr(&r->out, DNS_S_AN, rr->owner, rr->owner_len,
				     rr->type, rr->cls, rr->ttl, buf, len);
	}
	free(buf);
	return ret;
}

static int emit_addr(struct resolve_req *r, const struct dns_rr *rr, const struct plan *p)
{
	int fam = afamily(rr->type), err;
	struct binding *b;

	b = do_bind(r, p->rule_id, p->mark, r->name.data, r->name.len, fam,
		    rr->rdata, rr->ttl, &err);
	if (!b)
		return err;
	return dns_msg_add_rr(&r->out, DNS_S_AN, rr->owner, rr->owner_len, rr->type,
			      rr->cls, rr->ttl, b->fake, rr->rdlen);
}

/* Decide one ServiceMode RR (match its effective target). */
static int plan_svcb(struct resolve_req *r, const struct dns_rr *rr, struct plan *p)
{
	const struct config *cfg = r->o->cfg;
	const struct rule *rule;
	const uint8_t *t;
	struct svcb_view v;
	uint16_t idx;
	uint8_t tlen;
	int ret;

	if (svcb_parse(rr->rdata, rr->rdlen, &v)) {
		p->act = ACT_DROP;
		return 0;
	}
	p->act = ACT_KEEP;
	if (!v.priority)
		return 0;
	t = svcb_target_is_root(&v) ? r->name.data : v.target;
	tlen = svcb_target_is_root(&v) ? r->name.len : v.target_len;
	idx = match_lookup_wire(cfg->idx, t, tlen);
	if (idx == MATCH_NONE || idx >= cfg->nrules)
		return -ENOENT;
	rule = &cfg->rules[idx];
	ret = dep_add(r, t, tlen, rule->fingerprint);
	if (ret)
		return ret;
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

	out_init(r, DNS_R_NOERROR);
	ret = copy_prefix(r);
	if (ret)
		return ret;
	if (soa)
		return add_rr(&r->out, DNS_S_NS, soa);
	return add_synth_soa(r, r->o->cfg->block_ttl);
}

static int plan_terminal(struct resolve_req *r, struct plan *plan, uint16_t *nkept,
			 bool *dropped)
{
	const struct dns_msg *m = &r->resp;
	int fam = afamily(r->qtype), ret;
	uint16_t i;

	for (i = 0; i < m->nrr && m->rr[i].section == DNS_S_AN; i++) {
		const struct dns_rr *rr = &m->rr[i];
		struct plan *p = &plan[i];

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
			ret = plan_svcb(r, rr, p);
			if (ret)
				return ret;
		} else {
			p->act = ACT_KEEP;
		}
		if (p->act == ACT_DROP)
			*dropped = true;
		else
			(*nkept)++;
	}
	return 0;
}

static int build_terminal(struct resolve_req *r, const struct plan *plan, bool *rewritten)
{
	const struct dns_msg *m = &r->resp;
	uint16_t i;
	int ret;

	out_init(r, m->flags & DNS_F_RCODE);
	ret = copy_prefix(r);
	for (i = 0; !ret && i < m->nrr && m->rr[i].section == DNS_S_AN; i++) {
		switch (plan[i].act) {
		case ACT_KEEP:
			ret = add_rr(&r->out, DNS_S_AN, &m->rr[i]);
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
	if (!*rewritten && can_pass_through(r))
		return pass_through(r);
	return copy_tail(r, *rewritten, r->latch.on || r->nbinds, false);
}

static void terminal(struct resolve_req *r)
{
	bool dropped = false, rewritten;
	struct plan *plan;
	uint16_t nkept = 0;
	int ret, kind = LIFE_POS;

	plan = calloc(r->resp.nrr ? r->resp.nrr : 1, sizeof(*plan));
	if (!plan) {
		servfail(r);
		return;
	}
	ret = plan_terminal(r, plan, &nkept, &dropped);
	rewritten = dropped;
	if (!ret && !nkept) {
		ret = build_nodata(r);
		kind = LIFE_NEG;
	} else if (!ret) {
		ret = build_terminal(r, plan, &rewritten);
	}
	free(plan);
	if (ret) {
		servfail(r);
		return;
	}
	r->lifetime = lifetime_of(r->o->cfg, &r->out, kind);
	r->wait_i = 0;
	commit_wait(r);
}

/* ---- the walk ---- */

static void walk(struct resolve_req *r, bool scan);

static void upstream_done(void *ctx, int err, const struct dns_msg *resp)
{
	struct resolve_req *r = ctx;

	r->uq = NULL;
	if (err || !resp || dns_msg_copy(&r->resp, resp)) {
		servfail(r);
		return;
	}
	r->have_resp = true;
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
	r->latch.rule_id = strdup(rule->id);
	if (!r->latch.rule_id)
		return -ENOMEM;
	r->latch.on = true;
	r->latch.mark = rule->mark;
	set_up(&r->latch.up, rule->up);
	return 0;
}

/* Steps 1-4. Returns true when the walk continues asynchronously or ended. */
static bool policy_step(struct resolve_req *r)
{
	const struct config *cfg = r->o->cfg;
	const struct rule *rule;
	struct upstream_set *want;
	uint16_t idx;

	idx = match_lookup_wire(cfg->idx, r->name.data, r->name.len);
	if (idx == MATCH_NONE || idx >= cfg->nrules)
		return servfail(r), true;
	rule = &cfg->rules[idx];
	if (dep_add(r, r->name.data, r->name.len, rule->fingerprint))
		return servfail(r), true;
	if (rule->action == RULE_BLOCK)
		return finish_block(r), true;
	if (!r->latch.on && rule->action == RULE_FAKEIP && latch_set(r, rule))
		return servfail(r), true;
	want = r->latch.on ? r->latch.up : rule->up;
	if (!want)
		return servfail(r), true;
	if (r->have_resp && want->id == r->cur_up->id)
		return false;
	if (r->have_resp) {
		stats.requeries++;
		r->requeried = true;
	}
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
			out_init(r, DNS_R_YXDOMAIN);
			if (copy_prefix(r))
				servfail(r);
			else
				deliver(r);
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

static const struct dns_rr *find_svcb_alias(const struct resolve_req *r)
{
	const struct dns_msg *m = &r->resp;
	struct svcb_view v;
	uint16_t i;

	for (i = 0; i < m->nrr && m->rr[i].section == DNS_S_AN; i++) {
		const struct dns_rr *rr = &m->rr[i];

		if (rr->type != r->qtype || !owned(rr, &r->name) ||
		    svcb_parse(rr->rdata, rr->rdlen, &v))
			continue;
		if (!v.priority && !svcb_target_is_root(&v))
			return rr;
	}
	return NULL;
}

static int scan_svcb_alias(struct resolve_req *r, const struct dns_rr *rr)
{
	struct dns_name target;
	struct svcb_view v;

	svcb_parse(rr->rdata, rr->rdlen, &v);
	memcpy(target.data, v.target, v.target_len);
	target.len = v.target_len;
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
	int rcode = m->flags & DNS_F_RCODE;
	bool asked;

	if (r->qtype != DNS_T_DNAME && r->qtype != DNS_T_CNAME &&
	    (rr = find_dname(m, &r->name)))
		return scan_dname(r, rr);
	if (r->qtype != DNS_T_CNAME && (rr = find_rr(m, &r->name, DNS_T_CNAME)))
		return scan_alias(r, rr);
	if (is_svcb(r->qtype) && (rr = find_svcb_alias(r)))
		return scan_svcb_alias(r, rr);
	if (find_rr(m, &r->name, r->qtype)) {
		terminal(r);
		return SCAN_DONE;
	}
	asked = m->has_q && dns_name_eq(m->qname.data, m->qname.len, r->name.data, r->name.len);
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

static bool try_cache(struct resolve_req *r)
{
	struct omni *o = r->o;
	int rcode;

	if (!o->cache || cache_lookup(o->cache, o->cfg, r->qname.data, r->qname.len,
				      r->qtype, r->qclass, &r->out))
		return false;
	stats.cache_hits++;
	rcode = r->out.flags & DNS_F_RCODE;
	r->out.flags = DNS_F_QR | DNS_F_RA | r->rd;
	dns_msg_set_rcode(&r->out, rcode);
	dns_msg_set_question(&r->out, r->qname.data, r->qname.len, r->qtype, r->qclass);
	deliver(r);
	return true;
}

struct resolve_req *resolve_start(struct omni *o, const struct dns_msg *query,
				  resolve_cb cb, void *ctx)
{
	struct resolve_req *r;

	if (!query->has_q)
		return NULL;
	r = calloc(1, sizeof(*r));
	if (!r)
		return NULL;
	stats.requests++;
	r->o = o;
	r->cb = cb;
	r->ctx = ctx;
	r->defer.cb = defer_cb;
	r->starting = true;
	r->gen0 = o->cfg->gen;
	r->qname = query->qname;
	r->qtype = query->qtype;
	r->qclass = query->qclass;
	r->rd = query->flags & DNS_F_RD;
	r->name = query->qname;
	dns_msg_init(&r->resp);
	dns_msg_init(&r->prefix);
	dns_msg_init(&r->out);

	if (r->qtype == DNS_T_ANY)
		finish_rcode(r, DNS_R_NOTIMP);
	else if (!try_ptr(r) && !try_cache(r))
		walk(r, false);
	r->starting = false;
	return r;
}

void resolve_cancel(struct resolve_req *r)
{
	if (r)
		req_free(r);
}
