// SPDX-License-Identifier: GPL-2.0-only
/*
 * resolve.c walk tests: scripted upstream stub, real config/match/fakeip/
 * cache and real nftables (inside an unprivileged netns).
 */
#include <arpa/inet.h>
#include <ftw.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <libubox/uloop.h>

#include "test.h"
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
#include "util/hash.h"
#include "util/time.h"

#define TABLE "omnitest_resolve"
#define HOLD 1		/* script err: never answer */

/* ---- scripted upstream stub ---- */

struct script {
	char srv[64];
	char qname[256];
	uint16_t qtype;
	int rcode, err;
	const char *rrs;
};

static struct script scripts[64];
static int nscripts;
static char qlog[4096];
static int nqueries, live_handles;
static void (*after_cb)(void);

struct upstream_query {
	struct uloop_timeout t;
	upstream_cb cb;
	void *ctx;
	const struct script *s;
	struct dns_name qname;
	uint16_t qtype;
};

static void S(const char *srv, const char *qname, uint16_t qtype, int rcode, const char *rrs)
{
	struct script *s = &scripts[nscripts++];

	snprintf(s->srv, sizeof(s->srv), "%s", srv);
	snprintf(s->qname, sizeof(s->qname), "%s", qname);
	s->qtype = qtype;
	s->rcode = rcode;
	s->err = 0;
	s->rrs = rrs;
}

static void S_err(const char *srv, const char *qname, uint16_t qtype, int err)
{
	S(srv, qname, qtype, 0, "");
	scripts[nscripts - 1].err = err;
}

static struct dns_name N(const char *text)
{
	struct dns_name n;

	if (dns_name_from_text(&n, text)) {
		fprintf(stderr, "bad name %s\n", text);
		abort();
	}
	return n;
}

static const char *ntext(const uint8_t *w, uint8_t len)
{
	static char buf[4][DNS_NAME_TEXT_MAX];
	static int i;

	i = (i + 1) % 4;
	dns_name_to_text(w, len, buf[i], sizeof(buf[i]));
	return buf[i];
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v;
}

/* "prio target [alpn=h2,h3] [ipv4hint=a,b] [ech=hex] [ipv6hint=a,b]" */
static uint16_t build_svcb(const char *prio, char **save, uint8_t *rd)
{
	struct dns_name t;
	char *kv;
	uint16_t n;

	put16(rd, (uint16_t)atoi(prio));
	t = N(strtok_r(NULL, " ", save));
	memcpy(rd + 2, t.data, t.len);
	n = 2 + t.len;
	while ((kv = strtok_r(NULL, " ", save))) {
		char *v = strchr(kv, '='), *item, *s2;
		uint16_t key, vl = 0;
		uint8_t *val = rd + n + 4;

		*v++ = 0;
		if (!strcmp(kv, "alpn")) {
			key = SVCB_KEY_ALPN;
			for (item = strtok_r(v, ",", &s2); item; item = strtok_r(NULL, ",", &s2)) {
				val[vl] = (uint8_t)strlen(item);
				memcpy(val + vl + 1, item, strlen(item));
				vl += 1 + strlen(item);
			}
		} else if (!strcmp(kv, "ech")) {
			key = SVCB_KEY_ECH;
			for (; v[0] && v[1]; v += 2) {
				unsigned b;

				sscanf(v, "%2x", &b);
				val[vl++] = (uint8_t)b;
			}
		} else {
			int fam = !strcmp(kv, "ipv4hint") ? AF_INET : AF_INET6;

			key = fam == AF_INET ? SVCB_KEY_IPV4HINT : SVCB_KEY_IPV6HINT;
			for (item = strtok_r(v, ",", &s2); item; item = strtok_r(NULL, ",", &s2)) {
				inet_pton(fam, item, val + vl);
				vl += fam == AF_INET ? 4 : 16;
			}
		}
		put16(rd + n, key);
		put16(rd + n + 2, vl);
		n += 4 + vl;
	}
	return n;
}

/* "sec owner ttl TYPE args" lines separated by ';' */
static void build_rrs(struct dns_msg *m, const char *text)
{
	char *copy = strdup(text), *line, *s1;

	for (line = strtok_r(copy, ";", &s1); line; line = strtok_r(NULL, ";", &s1)) {
		char *s2, *sec = strtok_r(line, " ", &s2), *owner, *type, *a;
		uint8_t rd[2048];
		uint16_t n = 0, t;
		struct dns_name on, x;
		uint32_t ttl;
		int secn;

		if (!sec)
			continue;
		secn = !strcmp(sec, "an") ? DNS_S_AN : !strcmp(sec, "ns") ? DNS_S_NS : DNS_S_AR;
		owner = strtok_r(NULL, " ", &s2);
		ttl = (uint32_t)atoi(strtok_r(NULL, " ", &s2));
		type = strtok_r(NULL, " ", &s2);
		a = strtok_r(NULL, " ", &s2);
		on = N(owner);
		if (!strcmp(type, "A")) {
			t = DNS_T_A;
			inet_pton(AF_INET, a, rd);
			n = 4;
		} else if (!strcmp(type, "AAAA")) {
			t = DNS_T_AAAA;
			inet_pton(AF_INET6, a, rd);
			n = 16;
		} else if (!strcmp(type, "CNAME") || !strcmp(type, "DNAME") || !strcmp(type, "PTR")) {
			t = type[0] == 'C' ? DNS_T_CNAME : type[0] == 'D' ? DNS_T_DNAME : DNS_T_PTR;
			x = N(a);
			memcpy(rd, x.data, x.len);
			n = x.len;
		} else if (!strcmp(type, "SOA")) {
			static const uint8_t fixed[16] = { 0, 0, 0, 1 };
			struct dns_name ns = N("ns.example"), hm = N("hm.example");
			uint32_t min = (uint32_t)atoi(a);

			t = DNS_T_SOA;
			memcpy(rd, ns.data, ns.len);
			n = ns.len;
			memcpy(rd + n, hm.data, hm.len);
			n += hm.len;
			memcpy(rd + n, fixed, 16);
			n += 16;
			rd[n++] = min >> 24;
			rd[n++] = min >> 16;
			rd[n++] = min >> 8;
			rd[n++] = min;
		} else if (!strcmp(type, "HTTPS") || !strcmp(type, "SVCB")) {
			t = type[0] == 'H' ? DNS_T_HTTPS : DNS_T_SVCB;
			n = build_svcb(a, &s2, rd);
		} else if (!strcmp(type, "MX")) {
			t = DNS_T_MX;
			put16(rd, (uint16_t)atoi(a));
			x = N(strtok_r(NULL, " ", &s2));
			memcpy(rd + 2, x.data, x.len);
			n = 2 + x.len;
		} else if (!strcmp(type, "RRSIG")) {
			t = DNS_T_RRSIG;
			memset(rd, 0, 24);
			n = 24;
		} else {
			fprintf(stderr, "bad type %s\n", type);
			abort();
		}
		if (dns_msg_add_rr(m, secn, on.data, on.len, t, DNS_C_IN, ttl, rd, n)) {
			fprintf(stderr, "add_rr failed: %s\n", line);
			abort();
		}
	}
	free(copy);
}

static void stub_fire(struct uloop_timeout *t)
{
	struct upstream_query *q = container_of(t, struct upstream_query, t);
	struct dns_msg m;
	upstream_cb cb = q->cb;
	void *ctx = q->ctx;

	live_handles--;
	if (!q->s || q->s->err) {
		int err = q->s ? q->s->err : -ETIMEDOUT;

		free(q);
		cb(ctx, err, NULL);
	} else {
		dns_msg_init(&m);
		dns_name_lower(q->qname.data, q->qname.len);
		dns_msg_set_question(&m, q->qname.data, q->qname.len, q->qtype, DNS_C_IN);
		m.flags = DNS_F_QR | DNS_F_RD | DNS_F_RA | DNS_F_AA;
		dns_msg_set_rcode(&m, q->s->rcode);
		build_rrs(&m, q->s->rrs);
		free(q);
		cb(ctx, 0, &m);
		dns_msg_free(&m);
	}
	if (after_cb)
		after_cb();
}

static void srv_text(const struct upstream_set *u, char *buf, size_t cap)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)&u->srv[0].sa;

	inet_ntop(AF_INET, &sin->sin_addr, buf, (socklen_t)cap);
}

struct upstream_query *upstream_query(struct upstream_set *u,
				      const uint8_t *qname, uint8_t qlen, uint16_t qtype,
				      upstream_cb cb, void *ctx)
{
	struct upstream_query *q = calloc(1, sizeof(*q));
	char srv[64], tb[16];
	const char *name = ntext(qname, qlen);
	int i;

	srv_text(u, srv, sizeof(srv));
	nqueries++;
	snprintf(qlog + strlen(qlog), sizeof(qlog) - strlen(qlog), "%s%s %s %s",
		 qlog[0] ? "|" : "", srv, name, dns_type_str(qtype, tb));
	q->cb = cb;
	q->ctx = ctx;
	q->t.cb = stub_fire;
	memcpy(q->qname.data, qname, qlen);
	q->qname.len = qlen;
	q->qtype = qtype;
	for (i = 0; i < nscripts; i++)
		if (!strcmp(scripts[i].srv, srv) && !strcmp(scripts[i].qname, name) &&
		    scripts[i].qtype == qtype)
			q->s = &scripts[i];
	live_handles++;
	if (!q->s || q->s->err != HOLD)
		uloop_timeout_set(&q->t, 0);
	return q;
}

void upstream_cancel(struct upstream_query *q)
{
	uloop_timeout_cancel(&q->t);
	live_handles--;
	free(q);
}

void upstream_init(uint32_t try_timeout_ms, uint32_t total_timeout_ms) {}
void upstream_set_timeouts(uint32_t try_timeout_ms, uint32_t total_timeout_ms) {}
void upstream_shutdown(void) {}

static struct upstream_stats ustats;
const struct upstream_stats *upstream_get_stats(void)
{
	return &ustats;
}

/* ---- environment ---- */

static char dir[64];
static struct omni o;
static struct nft_ctx *nft;
static const uint8_t SECRET[16] = { 42 };

static void wfile(const char *name, const char *text)
{
	char path[256];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f)
		abort();
	fputs(text, f);
	fclose(f);
}

/* '@' in text stands for the temp dir */
static struct config *load(const char *fmt)
{
	char text[8192], *p = text, err[512], path[256];
	struct config *c;

	for (; *fmt; fmt++)
		p += *fmt == '@' ? sprintf(p, "%s", dir) : sprintf(p, "%c", *fmt);
	*p = 0;
	wfile("omnitest", text);
	snprintf(path, sizeof(path), "%s/omnitest", dir);
	c = config_load(path, &o.nsc, err, sizeof(err));
	if (!c) {
		fprintf(stderr, "config_load: %s\n", err);
		abort();
	}
	c->gen = ++o.next_gen;
	return c;
}

#define GLOBAL_HDR "config omnidns 'main'\n\tlist listen_addr '127.0.0.1'\n" \
	"\toption fakeip_v4 '198.18.0.0/15'\n"
#define RULES \
	"config rule 'ads'\n\toption action 'block'\n\tlist nameset '@/ads.txt'\n" \
	"config rule 'vpn'\n\toption action 'fakeip'\n\toption upstream '@/up2.conf'\n" \
	"\toption fwmark '0x1'\n\tlist nameset '@/vpn.txt'\n" \
	"config rule 'alt'\n\toption action 'fakeip'\n\toption upstream '@/up3.conf'\n" \
	"\toption fwmark '0x2'\n\tlist nameset '@/alt.txt'\n" \
	"config rule 'fwd2'\n\toption action 'forward'\n\toption upstream '@/up2.conf'\n" \
	"\tlist nameset '@/fwd2.txt'\n" \
	"config rule 'fwd3'\n\toption action 'forward'\n\toption upstream '@/up3.conf'\n" \
	"\tlist nameset '@/fwd3.txt'\n" \
	"config rule 'all'\n\toption action 'forward'\n\toption upstream '@/up1.conf'\n"
#define CFG_DEFAULT GLOBAL_HDR RULES
#define CFG_V6 GLOBAL_HDR "\toption fakeip_v6 'fc00:18::/64'\n" RULES

#define MARK1 0x01000000u
#define MARK2 0x02000000u

static void teardown(void)
{
	if (o.cache)
		cache_free(o.cache);
	o.cache = NULL;
	nft_flush(nft);
	nft_drain(nft);
	fakeip_free(o.fdb);
	o.fdb = NULL;
	config_free(o.cfg);
	o.cfg = NULL;
}

static void setup(const char *cfgtext)
{
	uint32_t marks[16], n = 0;
	struct nft_desired d = { 0 };
	int i;

	teardown();
	o.cfg = load(cfgtext);
	for (i = 0; i < o.cfg->nrules; i++)
		if (o.cfg->rules[i].action == RULE_FAKEIP)
			marks[n++] = o.cfg->rules[i].mark;
	d.fwmask = o.cfg->fwmask;
	d.has_pool4 = o.cfg->has_pool4;
	d.has_pool6 = o.cfg->has_pool6;
	d.pool4 = o.cfg->pool4;
	d.pool6 = o.cfg->pool6;
	d.marks = marks;
	d.nmarks = n;
	if (nft_bootstrap(nft, &d)) {
		fprintf(stderr, "nft_bootstrap failed\n");
		abort();
	}
	o.fdb = fakeip_new(o.cfg->has_pool4 ? &o.cfg->pool4 : NULL,
			   o.cfg->has_pool6 ? &o.cfg->pool6 : NULL,
			   o.cfg->fakeip_max_bindings, o.cfg->fakeip_grace, SECRET, nft);
	o.cache = cache_new(1000, 1 << 20, o.fdb);
	nscripts = 0;
	qlog[0] = 0;
	nqueries = 0;
	after_cb = NULL;
}

/* ---- running queries ---- */

static struct dns_msg res;
static int ncb;
static struct resolve_req *cur;

static void res_cb(void *ctx, const struct dns_msg *m)
{
	ncb++;
	cur = NULL;
	dns_msg_copy(&res, m);
	uloop_end();
}

static void guard_cb(struct uloop_timeout *t)
{
	uloop_end();
}

static void run_loop(int ms)
{
	struct uloop_timeout guard = { .cb = guard_cb };

	uloop_timeout_set(&guard, ms);
	uloop_run();
	uloop_timeout_cancel(&guard);
}

static struct resolve_req *start(const char *qname, uint16_t qtype)
{
	struct dns_name n = N(qname);
	struct dns_msg q;

	dns_msg_init(&q);
	dns_msg_set_question(&q, n.data, n.len, qtype, DNS_C_IN);
	q.flags = DNS_F_RD;
	q.id = 1234;
	ncb = 0;
	qlog[0] = 0;
	nqueries = 0;
	dns_msg_free(&res);
	cur = resolve_start(&o, &q, res_cb, NULL);
	dns_msg_free(&q);
	return cur;
}

/* Resolve and wait; returns true when the callback fired exactly once. */
static bool run(const char *qname, uint16_t qtype)
{
	if (!start(qname, qtype) || ncb)
		return false;
	run_loop(3000);
	return ncb == 1;
}

static int rcode(void)
{
	return dns_msg_rcode(&res);
}

static int count(enum dns_section s)
{
	return dns_msg_count(&res, s);
}

/* "owner ttl TYPE rdata" (rdata decoded for common types) */
static const char *rrs(const struct dns_rr *rr)
{
	static char buf[4][512];
	static int i;
	char tb[16], rd[300] = "";
	struct dns_name t;
	uint32_t min;

	i = (i + 1) % 4;
	switch (rr->type) {
	case DNS_T_A:
		inet_ntop(AF_INET, rr->rdata, rd, sizeof(rd));
		break;
	case DNS_T_AAAA:
		inet_ntop(AF_INET6, rr->rdata, rd, sizeof(rd));
		break;
	case DNS_T_CNAME: case DNS_T_DNAME: case DNS_T_PTR:
		dns_rr_target(rr, &t);
		snprintf(rd, sizeof(rd), "%s", ntext(t.data, t.len));
		break;
	case DNS_T_SOA:
		dns_soa_minimum(rr, &min);
		snprintf(rd, sizeof(rd), "%s %u", ntext(rr->rdata, (uint8_t)dns_name_check(rr->rdata, rr->rdlen)), min);
		break;
	}
	snprintf(buf[i], sizeof(buf[i]), "%s %u %s%s%s", ntext(rr->owner, rr->owner_len),
		 rr->ttl, dns_type_str(rr->type, tb), rd[0] ? " " : "", rd);
	return buf[i];
}

static const char *R(int i)
{
	return i < res.nrr ? rrs(&res.rr[i]) : "(none)";
}

static char *sh(const char *cmd)
{
	FILE *f = popen(cmd, "r");
	size_t len = 0, cap = 1 << 16, r;
	char *buf = malloc(cap);

	while (f && (r = fread(buf + len, 1, cap - len - 1, f)) > 0)
		len += r;
	buf[len] = 0;
	if (f)
		pclose(f);
	return buf;
}

/* fake -> (real, mark) present in the kernel maps */
static bool in_kernel(int fam, const uint8_t *fake, const char *real, uint32_t mark)
{
	char cmd[256], f[64], n1[128], n2[128];
	char *o1;
	bool ok;

	inet_ntop(fam == 4 ? AF_INET : AF_INET6, fake, f, sizeof(f));
	snprintf(cmd, sizeof(cmd), "nft list map inet " TABLE " fake2real_v%d; "
		 "nft list map inet " TABLE " fake2mark_v%d", fam, fam);
	o1 = sh(cmd);
	snprintf(n1, sizeof(n1), "%s : %s", f, real);
	snprintf(n2, sizeof(n2), "%s : jump mark_%08x", f, mark);
	ok = strstr(o1, n1) && strstr(o1, n2);
	if (!ok)
		fprintf(stderr, "    kernel lacks %s / %s:\n%s", n1, n2, o1);
	free(o1);
	return ok;
}

static int kernel_elems(int fam)
{
	char cmd[256], *out;
	int n;

	snprintf(cmd, sizeof(cmd), "nft list map inet " TABLE " fake2real_v%d | "
		 "grep -oE ' : [0-9a-f]' | wc -l", fam);
	out = sh(cmd);
	n = atoi(out);
	free(out);
	return n;
}

/* rdata at `addr` is a fake of family fam for (real, mark, endpoint), in the kernel */
static bool is_fake(int fam, const uint8_t *addr, const char *real, uint32_t mark,
		    const char *endpoint)
{
	struct binding *b = fakeip_lookup(o.fdb, fam, addr);
	uint8_t r[16];

	inet_pton(fam == 4 ? AF_INET : AF_INET6, real, r);
	if (!b || memcmp(b->real, r, fam == 4 ? 4 : 16) || b->mark != mark ||
	    strcmp(ntext(b->endpoint, b->endpoint_len), endpoint)) {
		fprintf(stderr, "    not a fake of %s/%x/%s\n", real, mark, endpoint);
		return false;
	}
	return in_kernel(fam, addr, real, mark);
}

static bool no_queries(void)
{
	return nqueries == 0;
}

/* ---- tests ---- */

TEST(a_plain_forward)
{
	setup(CFG_DEFAULT);
	S("10.0.0.1", "www.plain.example", DNS_T_A, 0,
	  "an www.plain.example 300 A 1.2.3.4;an www.plain.example 300 RRSIG;"
	  "ns plain.example 300 SOA 60;ar ns.plain.example 300 A 5.5.5.5");
	REQUIRE(run("www.Plain.example", DNS_T_A));
	CHECK_EQ(rcode(), 0);
	CHECK_STR(qlog, "10.0.0.1 www.plain.example A");
	CHECK_EQ(count(DNS_S_AN), 2);	/* pass-through keeps RRSIG */
	CHECK_STR(R(0), "www.plain.example 300 A 1.2.3.4");
	CHECK_EQ(res.rr[1].type, DNS_T_RRSIG);
	CHECK_EQ(count(DNS_S_NS), 1);
	CHECK_EQ(count(DNS_S_AR), 1);
	CHECK(!(res.flags & DNS_F_AA));
	CHECK(res.flags & DNS_F_QR);
	CHECK(res.flags & DNS_F_RA);
	CHECK(!res.edns.present);
	CHECK(!memcmp(res.qname.data, "\x03www\x05Plain", 9));

	/* cached */
	time_override_advance(10);
	REQUIRE(run("www.plain.example", DNS_T_A));
	CHECK(no_queries());
	CHECK_STR(R(0), "www.plain.example 290 A 1.2.3.4");
	CHECK(resolve_get_stats()->cache_hits > 0);
}

static void block_case(const char *mode, int want_rcode, bool null)
{
	char cfg[4096];

	snprintf(cfg, sizeof(cfg), GLOBAL_HDR "\toption block_mode '%s'\n\toption block_ttl '120'\n"
		 RULES, mode);
	setup(cfg);
	REQUIRE(run("x.ads.example", DNS_T_A));
	CHECK(no_queries());
	CHECK_EQ(rcode(), want_rcode);
	if (null) {
		CHECK_EQ(res.nrr, 1);
		CHECK_STR(R(0), "x.ads.example 120 A 0.0.0.0");
		REQUIRE(run("x.ads.example", DNS_T_AAAA));
		CHECK_STR(R(0), "x.ads.example 120 AAAA ::");
		REQUIRE(run("x.ads.example", DNS_T_MX));
		CHECK_EQ(rcode(), 0);
	}
	if (!null || res.rr[0].type == DNS_T_SOA) {
		CHECK_EQ(count(DNS_S_AN), 0);
		CHECK_EQ(count(DNS_S_NS), 1);
		CHECK_STR(R(0), "x.ads.example 120 SOA omnidns.invalid 120");
	}
	CHECK(no_queries());
	/* blocked answers are cached too */
	REQUIRE(run("x.ads.example", DNS_T_TXT));
	REQUIRE(run("x.ads.example", DNS_T_TXT));
	CHECK(no_queries());
}

TEST(b_block_direct)
{
	uint64_t before = resolve_get_stats()->blocked;

	block_case("nodata", 0, false);
	block_case("nxdomain", 3, false);
	block_case("null", 0, true);
	CHECK(resolve_get_stats()->blocked > before);
}

TEST(c_cname_cloaking)
{
	setup(CFG_DEFAULT);
	S("10.0.0.1", "cdn.plain.example", DNS_T_A, 0,
	  "an cdn.plain.example 300 CNAME x.tracker.example;an x.tracker.example 300 A 5.6.7.8");
	REQUIRE(run("cdn.plain.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.1 cdn.plain.example A");
	CHECK_EQ(rcode(), 0);
	CHECK_EQ(count(DNS_S_AN), 0);
	CHECK_STR(R(0), "cdn.plain.example 300 SOA omnidns.invalid 300");
}

TEST(d_fakeip_latch)
{
	uint8_t f1[4], f2[4];
	struct binding *b;

	setup(CFG_DEFAULT);
	S("10.0.0.2", "www.vpn.example", DNS_T_A, 0,
	  "an www.vpn.example 300 A 1.2.3.4;an www.vpn.example 200 A 1.2.3.5;"
	  "an www.vpn.example 300 RRSIG;ar x.vpn.example 300 A 9.9.9.9");
	REQUIRE(run("www.vpn.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.2 www.vpn.example A");
	REQUIRE(count(DNS_S_AN) == 2);
	CHECK_EQ(count(DNS_S_AR), 0);	/* glue stripped under a latch */
	memcpy(f1, res.rr[0].rdata, 4);
	memcpy(f2, res.rr[1].rdata, 4);
	CHECK(memcmp(f1, f2, 4));
	CHECK(is_fake(4, f1, "1.2.3.4", MARK1, "www.vpn.example"));
	CHECK(is_fake(4, f2, "1.2.3.5", MARK1, "www.vpn.example"));
	CHECK_EQ(res.rr[0].ttl, 300);
	CHECK_EQ(res.rr[1].ttl, 200);
	CHECK_EQ(kernel_elems(4), 2);
	b = fakeip_lookup(o.fdb, 4, f1);
	CHECK(b && b->refcnt == 1);	/* held by the cache only */

	REQUIRE(run("WWW.vpn.example", DNS_T_A));
	CHECK(no_queries());
	CHECK(!memcmp(res.rr[0].rdata, f1, 4));
	CHECK(!memcmp(res.rr[1].rdata, f2, 4));

	/* after expiry: renewed binding, same fakes, fresh query */
	time_override_advance(301);
	REQUIRE(run("www.vpn.example", DNS_T_A));
	CHECK_EQ(nqueries, 1);
	REQUIRE(count(DNS_S_AN) == 2);
	CHECK(!memcmp(res.rr[0].rdata, f1, 4));
	CHECK(!memcmp(res.rr[1].rdata, f2, 4));
	CHECK_EQ(kernel_elems(4), 2);
}

TEST(e_latch_pins_upstream)
{
	setup(CFG_DEFAULT);
	S("10.0.0.2", "a.vpn.example", DNS_T_A, 0,
	  "an a.vpn.example 300 CNAME b.fwd3.example;an b.fwd3.example 100 A 9.9.9.9");
	REQUIRE(run("a.vpn.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.2 a.vpn.example A");
	REQUIRE(count(DNS_S_AN) == 2);
	CHECK_STR(R(0), "a.vpn.example 300 CNAME b.fwd3.example");
	CHECK(is_fake(4, res.rr[1].rdata, "9.9.9.9", MARK1, "b.fwd3.example"));
	CHECK_STR(ntext(res.rr[1].owner, res.rr[1].owner_len), "b.fwd3.example");
}

TEST(f_forward_then_fakeip)
{
	uint64_t rq = resolve_get_stats()->requeries;

	setup(CFG_DEFAULT);
	S("10.0.0.1", "a.plain.example", DNS_T_A, 0,
	  "an a.plain.example 300 CNAME b.vpn.example;an b.vpn.example 300 A 7.7.7.7");
	S("10.0.0.2", "b.vpn.example", DNS_T_A, 0, "an b.vpn.example 60 A 8.8.8.8");
	REQUIRE(run("a.plain.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.1 a.plain.example A|10.0.0.2 b.vpn.example A");
	CHECK_EQ(resolve_get_stats()->requeries, rq + 1);
	REQUIRE(count(DNS_S_AN) == 2);
	CHECK_STR(R(0), "a.plain.example 300 CNAME b.vpn.example");
	CHECK(is_fake(4, res.rr[1].rdata, "8.8.8.8", MARK1, "b.vpn.example"));
	CHECK_EQ(res.rr[1].ttl, 60);
	CHECK_EQ(kernel_elems(4), 1);
}

TEST(g_forward_requery)
{
	setup(CFG_DEFAULT);
	S("10.0.0.1", "a.plain.example", DNS_T_A, 0,
	  "an a.plain.example 300 CNAME b.fwd2.example;an b.fwd2.example 300 A 1.1.1.1");
	S("10.0.0.2", "b.fwd2.example", DNS_T_A, 0, "an b.fwd2.example 30 A 2.2.2.2");
	REQUIRE(run("a.plain.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.1 a.plain.example A|10.0.0.2 b.fwd2.example A");
	REQUIRE(count(DNS_S_AN) == 2);
	CHECK_STR(R(0), "a.plain.example 300 CNAME b.fwd2.example");
	CHECK_STR(R(1), "b.fwd2.example 30 A 2.2.2.2");

	/* forward -> forward on the same upstream identity: no re-query */
	S("10.0.0.1", "c.plain.example", DNS_T_A, 0,
	  "an c.plain.example 300 CNAME d.other.example;an d.other.example 300 A 1.1.1.1");
	REQUIRE(run("c.plain.example", DNS_T_A));
	CHECK_EQ(nqueries, 1);
	CHECK_STR(R(1), "d.other.example 300 A 1.1.1.1");
}

TEST(h_dname)
{
	setup(CFG_DEFAULT);
	S("10.0.0.1", "www.d.plain.example", DNS_T_A, 0,
	  "an d.plain.example 900 DNAME e.plain.example;"
	  "an www.d.plain.example 900 CNAME www.e.plain.example;"
	  "an www.e.plain.example 300 A 3.3.3.3");
	REQUIRE(run("www.d.plain.example", DNS_T_A));
	CHECK_EQ(nqueries, 1);
	REQUIRE(count(DNS_S_AN) == 3);
	CHECK_STR(R(0), "d.plain.example 900 DNAME e.plain.example");
	CHECK_STR(R(1), "www.d.plain.example 900 CNAME www.e.plain.example");
	CHECK_STR(R(2), "www.e.plain.example 300 A 3.3.3.3");

	/* no synthesized CNAME: we substitute; the target is a fakeip name */
	S("10.0.0.1", "www.x.plain.example", DNS_T_A, 0,
	  "an x.plain.example 600 DNAME y.vpn.example");
	S("10.0.0.2", "www.y.vpn.example", DNS_T_A, 0, "an www.y.vpn.example 300 A 4.4.4.4");
	REQUIRE(run("www.x.plain.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.1 www.x.plain.example A|10.0.0.2 www.y.vpn.example A");
	REQUIRE(count(DNS_S_AN) == 3);
	CHECK_STR(R(0), "x.plain.example 600 DNAME y.vpn.example");
	CHECK_STR(R(1), "www.x.plain.example 600 CNAME www.y.vpn.example");
	CHECK(is_fake(4, res.rr[2].rdata, "4.4.4.4", MARK1, "www.y.vpn.example"));

	/* substitution overflow -> YXDOMAIN */
	{
		char q[300] = "", owner[300];
		char rr[1024];

		strcpy(q, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
		       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
		       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.z.plain.example");
		strcpy(owner, "z.plain.example");
		snprintf(rr, sizeof(rr), "an %s 60 DNAME "
			 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
			 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", owner);
		S("10.0.0.1", q, DNS_T_A, 0, rr);
		REQUIRE(run(q, DNS_T_A));
		CHECK_EQ(rcode(), 6);
		CHECK_EQ(res.nrr, 1);
	}
}

TEST(i_dangling)
{
	setup(CFG_DEFAULT);
	S("10.0.0.1", "a.plain.example", DNS_T_A, 0, "an a.plain.example 300 CNAME b.plain.example");
	S("10.0.0.1", "b.plain.example", DNS_T_A, 0, "an b.plain.example 300 A 4.4.4.4");
	REQUIRE(run("a.plain.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.1 a.plain.example A|10.0.0.1 b.plain.example A");
	REQUIRE(count(DNS_S_AN) == 2);
	CHECK_STR(R(0), "a.plain.example 300 CNAME b.plain.example");
	CHECK_STR(R(1), "b.plain.example 300 A 4.4.4.4");

	/* the chased name has no data either -> NODATA, no further query */
	S("10.0.0.1", "c.plain.example", DNS_T_A, 0, "an c.plain.example 300 CNAME d.plain.example");
	S("10.0.0.1", "d.plain.example", DNS_T_A, 0, "");
	REQUIRE(run("c.plain.example", DNS_T_A));
	CHECK_EQ(nqueries, 2);
	CHECK_EQ(rcode(), 0);
	CHECK_EQ(res.nrr, 1);
}

static void chain(char *buf, size_t cap, int n)
{
	int i;

	buf[0] = 0;
	for (i = 0; i < n; i++)
		snprintf(buf + strlen(buf), cap - strlen(buf),
			 "an c%d.plain.example 300 CNAME c%d.plain.example;", i, i + 1);
	snprintf(buf + strlen(buf), cap - strlen(buf), "an c%d.plain.example 300 A 1.1.1.1", n);
}

TEST(j_loops_and_limits)
{
	static char ok[4096], bad[4096];
	uint64_t sf = resolve_get_stats()->servfail;

	setup(CFG_DEFAULT);
	S("10.0.0.1", "a.plain.example", DNS_T_A, 0,
	  "an a.plain.example 300 CNAME b.plain.example;an b.plain.example 300 CNAME A.plain.example");
	REQUIRE(run("a.plain.example", DNS_T_A));
	CHECK_EQ(rcode(), DNS_R_SERVFAIL);
	CHECK_EQ(res.nrr, 0);
	CHECK_EQ(resolve_get_stats()->servfail, sf + 1);

	chain(ok, sizeof(ok), RESOLVE_MAX_STEPS);
	S("10.0.0.1", "c0.plain.example", DNS_T_A, 0, ok);
	REQUIRE(run("c0.plain.example", DNS_T_A));
	CHECK_EQ(rcode(), 0);
	CHECK_EQ(count(DNS_S_AN), RESOLVE_MAX_STEPS + 1);

	chain(bad, sizeof(bad), RESOLVE_MAX_STEPS + 1);
	scripts[nscripts - 1].rrs = bad;
	cache_flush(o.cache);
	REQUIRE(run("c0.plain.example", DNS_T_A));
	CHECK_EQ(rcode(), DNS_R_SERVFAIL);
	/* SERVFAIL is not cached */
	REQUIRE(run("c0.plain.example", DNS_T_A));
	CHECK_EQ(nqueries, 1);
}

TEST(k_aaaa)
{
	setup(CFG_DEFAULT);
	S("10.0.0.2", "www.vpn.example", DNS_T_AAAA, 0,
	  "an www.vpn.example 300 AAAA 2001:db8::1");
	REQUIRE(run("www.vpn.example", DNS_T_AAAA));
	CHECK_EQ(rcode(), 0);
	CHECK_EQ(count(DNS_S_AN), 0);
	CHECK_STR(R(0), "www.vpn.example 300 SOA omnidns.invalid 300");
	CHECK_EQ(kernel_elems(6), 0);

	/* upstream SOA preferred; prefix kept */
	S("10.0.0.2", "c.vpn.example", DNS_T_AAAA, 0,
	  "an c.vpn.example 300 CNAME d.vpn.example;an d.vpn.example 300 AAAA 2001:db8::2;"
	  "ns vpn.example 50 SOA 40");
	REQUIRE(run("c.vpn.example", DNS_T_AAAA));
	CHECK_EQ(res.nrr, 2);
	CHECK_STR(R(0), "c.vpn.example 300 CNAME d.vpn.example");
	CHECK_STR(R(1), "vpn.example 50 SOA ns.example 40");

	setup(CFG_V6);
	S("10.0.0.2", "www.vpn.example", DNS_T_AAAA, 0,
	  "an www.vpn.example 300 AAAA 2001:db8::1");
	REQUIRE(run("www.vpn.example", DNS_T_AAAA));
	REQUIRE(count(DNS_S_AN) == 1);
	CHECK(fakeip_in_pool(o.fdb, 6, res.rr[0].rdata));
	CHECK(is_fake(6, res.rr[0].rdata, "2001:db8::1", MARK1, "www.vpn.example"));
	CHECK_EQ(kernel_elems(6), 1);
}

static bool svcb_param(const struct dns_rr *rr, uint16_t key, const uint8_t **val, uint16_t *len)
{
	struct svcb_view v;
	uint16_t off = 0;

	if (svcb_parse(rr->rdata, rr->rdlen, &v))
		return false;
	while (off < v.params_len) {
		uint16_t k = (uint16_t)(v.params[off] << 8 | v.params[off + 1]);
		uint16_t l = (uint16_t)(v.params[off + 2] << 8 | v.params[off + 3]);

		if (k == key) {
			*val = v.params + off + 4;
			*len = l;
			return true;
		}
		off += 4 + l;
	}
	return false;
}

TEST(l_https_service_mode)
{
	const uint8_t *val;
	uint16_t len;

	setup(CFG_DEFAULT);
	S("10.0.0.1", "svc.plain.example", DNS_T_HTTPS, 0,
	  "an svc.plain.example 300 HTTPS 1 a.vpn.example alpn=h2 ipv4hint=1.1.1.1 ech=0102 "
	  "ipv6hint=2001:db8::1;"
	  "an svc.plain.example 200 HTTPS 2 b.alt.example alpn=h3 ipv4hint=2.2.2.2,2.2.2.3;"
	  "an svc.plain.example 300 HTTPS 3 c.ads.example ipv4hint=3.3.3.3;"
	  "an svc.plain.example 300 RRSIG");
	REQUIRE(run("svc.plain.example", DNS_T_HTTPS));
	CHECK_STR(qlog, "10.0.0.1 svc.plain.example HTTPS");	/* targets never resolved */
	REQUIRE(count(DNS_S_AN) == 2);

	REQUIRE(svcb_param(&res.rr[0], SVCB_KEY_ALPN, &val, &len));
	CHECK(len == 3 && !memcmp(val, "\x02h2", 3));
	REQUIRE(svcb_param(&res.rr[0], SVCB_KEY_ECH, &val, &len));
	CHECK(len == 2 && val[0] == 1 && val[1] == 2);
	CHECK(!svcb_param(&res.rr[0], SVCB_KEY_IPV6HINT, &val, &len));
	REQUIRE(svcb_param(&res.rr[0], SVCB_KEY_IPV4HINT, &val, &len));
	REQUIRE(len == 4);
	CHECK(is_fake(4, val, "1.1.1.1", MARK1, "a.vpn.example"));

	REQUIRE(svcb_param(&res.rr[1], SVCB_KEY_ALPN, &val, &len));
	CHECK(len == 3 && !memcmp(val, "\x02h3", 3));
	REQUIRE(svcb_param(&res.rr[1], SVCB_KEY_IPV4HINT, &val, &len));
	REQUIRE(len == 8);
	CHECK(is_fake(4, val, "2.2.2.2", MARK2, "b.alt.example"));
	CHECK(is_fake(4, val + 4, "2.2.2.3", MARK2, "b.alt.example"));
	CHECK_EQ(res.rr[1].ttl, 200);
	CHECK_EQ(kernel_elems(4), 3);

	/* every ServiceMode RR blocked -> NODATA */
	S("10.0.0.1", "svc2.plain.example", DNS_T_HTTPS, 0,
	  "an svc2.plain.example 300 HTTPS 1 c.ads.example ipv4hint=3.3.3.3");
	REQUIRE(run("svc2.plain.example", DNS_T_HTTPS));
	CHECK_EQ(rcode(), 0);
	CHECK_EQ(count(DNS_S_AN), 0);
	CHECK_EQ(count(DNS_S_NS), 1);

	/* root target = owner; forward target untouched (pass-through) */
	S("10.0.0.1", "svc3.plain.example", DNS_T_HTTPS, 0,
	  "an svc3.plain.example 300 HTTPS 1 . ipv4hint=4.4.4.4");
	REQUIRE(run("svc3.plain.example", DNS_T_HTTPS));
	REQUIRE(svcb_param(&res.rr[0], SVCB_KEY_IPV4HINT, &val, &len));
	CHECK(len == 4 && !memcmp(val, "\x04\x04\x04\x04", 4));

	/* root target under a walk latch: endpoint = owner */
	S("10.0.0.2", "svc.vpn.example", DNS_T_HTTPS, 0,
	  "an svc.vpn.example 300 HTTPS 1 . ipv4hint=5.5.5.5");
	REQUIRE(run("svc.vpn.example", DNS_T_HTTPS));
	REQUIRE(svcb_param(&res.rr[0], SVCB_KEY_IPV4HINT, &val, &len));
	CHECK(is_fake(4, val, "5.5.5.5", MARK1, "svc.vpn.example"));
}

TEST(m_https_alias_mode)
{
	setup(CFG_DEFAULT);
	S("10.0.0.1", "www.plain.example", DNS_T_HTTPS, 0,
	  "an www.plain.example 300 HTTPS 0 svc.vpn.example");
	S("10.0.0.2", "svc.vpn.example", DNS_T_HTTPS, 0,
	  "an svc.vpn.example 100 HTTPS 1 . alpn=h2 ipv4hint=6.6.6.6");
	REQUIRE(run("www.plain.example", DNS_T_HTTPS));
	CHECK_STR(qlog, "10.0.0.1 www.plain.example HTTPS|10.0.0.2 svc.vpn.example HTTPS");
	REQUIRE(count(DNS_S_AN) == 2);
	CHECK_STR(ntext(res.rr[0].owner, res.rr[0].owner_len), "www.plain.example");
	CHECK_STR(ntext(res.rr[1].owner, res.rr[1].owner_len), "svc.vpn.example");
	{
		const uint8_t *val;
		uint16_t len;

		REQUIRE(svcb_param(&res.rr[1], SVCB_KEY_IPV4HINT, &val, &len));
		CHECK(is_fake(4, val, "6.6.6.6", MARK1, "svc.vpn.example"));
	}

	/* AliasMode to "." is terminal */
	S("10.0.0.1", "none.plain.example", DNS_T_HTTPS, 0,
	  "an none.plain.example 300 HTTPS 0 .");
	REQUIRE(run("none.plain.example", DNS_T_HTTPS));
	CHECK_EQ(nqueries, 1);
	CHECK_EQ(count(DNS_S_AN), 1);
}

static void rev4(char *buf, const uint8_t *a)
{
	sprintf(buf, "%u.%u.%u.%u.in-addr.arpa", a[3], a[2], a[1], a[0]);
}

static void rev6(char *buf, const uint8_t *a)
{
	int i;

	buf[0] = 0;
	for (i = 15; i >= 0; i--)
		sprintf(buf + strlen(buf), "%x.%x.", a[i] & 0xf, a[i] >> 4);
	strcat(buf, "ip6.arpa");
}

TEST(n_ptr)
{
	uint8_t fake[16], other[16];
	char rev[128];

	setup(CFG_V6);
	S("10.0.0.2", "www.vpn.example", DNS_T_A, 0, "an www.vpn.example 300 A 1.2.3.4");
	S("10.0.0.2", "www.vpn.example", DNS_T_AAAA, 0, "an www.vpn.example 300 AAAA 2001:db8::5");
	REQUIRE(run("www.vpn.example", DNS_T_A));
	memcpy(fake, res.rr[0].rdata, 4);
	rev4(rev, fake);
	REQUIRE(run(rev, DNS_T_PTR));
	CHECK(no_queries());
	CHECK_EQ(rcode(), 0);
	CHECK_EQ(res.rr[0].ttl, 60);
	CHECK_EQ(res.rr[0].type, DNS_T_PTR);
	{
		struct dns_name t;

		dns_rr_target(&res.rr[0], &t);
		CHECK_STR(ntext(t.data, t.len), "www.vpn.example");
	}

	inet_pton(AF_INET, "198.19.255.254", other);
	rev4(rev, other);
	REQUIRE(run(rev, DNS_T_PTR));
	CHECK(no_queries());
	CHECK_EQ(rcode(), DNS_R_NXDOMAIN);
	CHECK_EQ(count(DNS_S_NS), 1);

	REQUIRE(run("www.vpn.example", DNS_T_AAAA));
	memcpy(fake, res.rr[0].rdata, 16);
	rev6(rev, fake);
	REQUIRE(run(rev, DNS_T_PTR));
	CHECK(no_queries());
	CHECK_EQ(rcode(), 0);
	CHECK_EQ(res.nrr, 1);

	/* outside the pools: forwarded */
	S("10.0.0.1", "4.3.2.1.in-addr.arpa", DNS_T_PTR, 0, "an 4.3.2.1.in-addr.arpa 300 PTR x.example");
	REQUIRE(run("4.3.2.1.in-addr.arpa", DNS_T_PTR));
	CHECK_EQ(nqueries, 1);
	CHECK_STR(R(0), "4.3.2.1.in-addr.arpa 300 PTR x.example");
}

TEST(o_any)
{
	setup(CFG_DEFAULT);
	REQUIRE(run("www.plain.example", DNS_T_ANY));
	CHECK(no_queries());
	CHECK_EQ(rcode(), DNS_R_NOTIMP);
	CHECK_EQ(res.nrr, 0);
}

TEST(p_nxdomain_second_step)
{
	setup(CFG_DEFAULT);
	S("10.0.0.1", "a.plain.example", DNS_T_A, 0,
	  "an a.plain.example 300 CNAME b.fwd2.example;ns plain.example 300 SOA 60");
	S("10.0.0.2", "b.fwd2.example", DNS_T_A, DNS_R_NXDOMAIN,
	  "ns fwd2.example 900 SOA 100;ns fwd2.example 900 RRSIG");
	REQUIRE(run("a.plain.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.1 a.plain.example A|10.0.0.2 b.fwd2.example A");
	CHECK_EQ(rcode(), DNS_R_NXDOMAIN);
	REQUIRE(res.nrr == 3);
	CHECK_STR(R(0), "a.plain.example 300 CNAME b.fwd2.example");
	CHECK_STR(R(1), "fwd2.example 900 SOA ns.example 100");
	/* negative lifetime = min(SOA ttl, minimum) = 100 */
	time_override_advance(99);
	REQUIRE(run("a.plain.example", DNS_T_A));
	CHECK(no_queries());
	CHECK_STR(R(1), "fwd2.example 801 SOA ns.example 100");
	time_override_advance(1);
	REQUIRE(run("a.plain.example", DNS_T_A));
	CHECK_EQ(nqueries, 2);
}

static void cancel_hook(void)
{
	struct binding *b;
	uint32_t it = 0;
	bool waiting = false;

	if (!cur)
		return;
	while ((b = fakeip_next(o.fdb, &it)))
		waiting |= !nft_ticket_done(nft, b->ticket);
	CHECK(waiting);
	CHECK_EQ(ncb, 0);
	resolve_cancel(cur);
	cur = NULL;
	after_cb = NULL;
}

TEST(q_cancel)
{
	struct binding *b;
	uint32_t it = 0;

	setup(CFG_DEFAULT);
	S_err("10.0.0.2", "hold.vpn.example", DNS_T_A, HOLD);
	REQUIRE(start("hold.vpn.example", DNS_T_A));
	run_loop(50);
	CHECK_EQ(ncb, 0);
	CHECK_EQ(live_handles, 1);
	resolve_cancel(cur);
	cur = NULL;
	CHECK_EQ(live_handles, 0);
	run_loop(20);
	CHECK_EQ(ncb, 0);

	/* cancel during the nft wait */
	S("10.0.0.2", "w.vpn.example", DNS_T_A, 0, "an w.vpn.example 300 A 1.2.3.4");
	after_cb = cancel_hook;
	REQUIRE(start("w.vpn.example", DNS_T_A));
	run_loop(300);
	CHECK_EQ(ncb, 0);
	CHECK(!cur);
	b = fakeip_next(o.fdb, &it);
	REQUIRE(b);
	CHECK_EQ(b->refcnt, 0);
	CHECK_EQ(cache_count(o.cache), 0);

	/* cancel of a deferred cache/block answer before it fires */
	REQUIRE(start("x.ads.example", DNS_T_A));
	resolve_cancel(cur);
	cur = NULL;
	run_loop(20);
	CHECK_EQ(ncb, 0);
}

TEST(r_reload_revalidation)
{
	struct config *ncfg;
	const char *reordered = GLOBAL_HDR
		"config rule 'ads'\n\toption action 'block'\n\tlist nameset '@/ads.txt'\n"
		"config rule 'fwd2'\n\toption action 'forward'\n\toption upstream '@/up2.conf'\n"
		"\tlist nameset '@/fwd2.txt'\n\tlist nameset '@/vpn.txt'\n"
		"config rule 'vpn'\n\toption action 'fakeip'\n\toption upstream '@/up2.conf'\n"
		"\toption fwmark '0x1'\n\tlist nameset '@/vpn.txt'\n"
		"config rule 'alt'\n\toption action 'fakeip'\n\toption upstream '@/up3.conf'\n"
		"\toption fwmark '0x2'\n\tlist nameset '@/alt.txt'\n"
		"config rule 'fwd3'\n\toption action 'forward'\n\toption upstream '@/up3.conf'\n"
		"\tlist nameset '@/fwd3.txt'\n"
		"config rule 'all'\n\toption action 'forward'\n\toption upstream '@/up1.conf'\n";

	setup(CFG_DEFAULT);
	S("10.0.0.2", "www.vpn.example", DNS_T_A, 0, "an www.vpn.example 300 A 1.2.3.4");
	REQUIRE(run("www.vpn.example", DNS_T_A));
	CHECK(fakeip_in_pool(o.fdb, 4, res.rr[0].rdata));
	S("10.0.0.1", "www.plain.example", DNS_T_A, 0, "an www.plain.example 300 A 1.1.1.1");
	REQUIRE(run("www.plain.example", DNS_T_A));

	/* reload with the same rules: still hits */
	ncfg = load(CFG_DEFAULT);
	config_free(o.cfg);
	o.cfg = ncfg;
	REQUIRE(run("www.vpn.example", DNS_T_A));
	CHECK(no_queries());

	/* reorder: fwd2 now wins for *.vpn.example */
	ncfg = load(reordered);
	config_free(o.cfg);
	o.cfg = ncfg;
	REQUIRE(run("www.vpn.example", DNS_T_A));
	CHECK_STR(qlog, "10.0.0.2 www.vpn.example A");
	CHECK_STR(R(0), "www.vpn.example 300 A 1.2.3.4");
	REQUIRE(run("www.plain.example", DNS_T_A));
	CHECK(no_queries());
}

TEST(s_upstream_error)
{
	setup(CFG_DEFAULT);
	S_err("10.0.0.1", "fail.plain.example", DNS_T_A, -ETIMEDOUT);
	REQUIRE(run("fail.plain.example", DNS_T_A));
	CHECK_EQ(rcode(), DNS_R_SERVFAIL);
	REQUIRE(run("fail.plain.example", DNS_T_A));
	CHECK_EQ(rcode(), DNS_R_SERVFAIL);
	CHECK_EQ(nqueries, 1);

	/* error at the second step */
	S("10.0.0.1", "a.plain.example", DNS_T_A, 0, "an a.plain.example 300 CNAME b.fwd2.example");
	S_err("10.0.0.2", "b.fwd2.example", DNS_T_A, -EIO);
	REQUIRE(run("a.plain.example", DNS_T_A));
	CHECK_EQ(rcode(), DNS_R_SERVFAIL);
	CHECK_EQ(res.nrr, 0);
	CHECK_EQ(cache_count(o.cache), 0);
}

TEST(t_other_qtypes_steered)
{
	setup(CFG_DEFAULT);
	/* MX under a latch: no rewriting, but AR glue is stripped */
	S("10.0.0.2", "m.vpn.example", DNS_T_MX, 0,
	  "an m.vpn.example 300 MX 10 mx.vpn.example;ar mx.vpn.example 300 A 1.2.3.4");
	REQUIRE(run("m.vpn.example", DNS_T_MX));
	CHECK_STR(qlog, "10.0.0.2 m.vpn.example MX");
	CHECK_EQ(count(DNS_S_AN), 1);
	CHECK_EQ(count(DNS_S_AR), 0);
}

static int rm_cb(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	return remove(p);
}

int main(int argc, char **argv)
{
	test_require_netns(argv);
	hash_init();
	log_init("test_resolve", true, getenv("TEST_VERBOSE") ? LOG_DEBUG : LOG_CRIT);
	uloop_init();
	time_override_set(5000);
	strcpy(dir, "/tmp/omniresolve.XXXXXX");
	if (!mkdtemp(dir))
		return 1;
	nsc_init(&o.nsc);
	wfile("up1.conf", "nameserver 10.0.0.1\n");
	wfile("up2.conf", "nameserver 10.0.0.2\n");
	wfile("up3.conf", "nameserver 10.0.0.3\n");
	wfile("ads.txt", "*.ads.example\n*.tracker.example\n");
	wfile("vpn.txt", "*.vpn.example\n");
	wfile("alt.txt", "*.alt.example\n");
	wfile("fwd2.txt", "*.fwd2.example\n");
	wfile("fwd3.txt", "*.fwd3.example\n");
	nft = nft_open(TABLE);
	if (!nft) {
		fprintf(stderr, "nft_open failed\n");
		return 1;
	}
	o.nft = nft;
	dns_msg_init(&res);

	RUN(a_plain_forward);
	RUN(b_block_direct);
	RUN(c_cname_cloaking);
	RUN(d_fakeip_latch);
	RUN(e_latch_pins_upstream);
	RUN(f_forward_then_fakeip);
	RUN(g_forward_requery);
	RUN(h_dname);
	RUN(i_dangling);
	RUN(j_loops_and_limits);
	RUN(k_aaaa);
	RUN(l_https_service_mode);
	RUN(m_https_alias_mode);
	RUN(n_ptr);
	RUN(o_any);
	RUN(p_nxdomain_second_step);
	RUN(q_cancel);
	RUN(r_reload_revalidation);
	RUN(s_upstream_error);
	RUN(t_other_qtypes_steered);

	teardown();
	CHECK_EQ(live_handles, 0);
	dns_msg_free(&res);
	nft_destroy_table(nft);
	nft_close(nft);
	uloop_done();
	nsc_destroy(&o.nsc);
	nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
	return test_summary();
}
