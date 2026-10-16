// SPDX-License-Identifier: MIT
#include <arpa/inet.h>
#include <ftw.h>
#include <stdarg.h>
#include <sys/stat.h>

#include "test.h"
#include "cache.h"
#include "config.h"
#include "fakeip.h"
#include "log.h"
#include "match.h"
#include "nft.h"
#include "util/hash.h"
#include "util/time.h"

/* ---- nft stubs (fakeip needs them; tickets complete immediately) ---- */

uint64_t nft_elem_add(struct nft_ctx *n, int family, const uint8_t *fake,
                      const uint8_t *real, uint32_t mark, bool replace)
{
	return 1;
}

uint64_t nft_elem_del(struct nft_ctx *n, int family, const uint8_t *fake)
{
	return 1;
}

void nft_set_fail_hook(struct nft_ctx *n, void (*fn)(void *priv, uint64_t ticket, int err),
                       void *priv)
{
}

/* ---- config files ---- */

static char dir[64];
static struct nameset_cache nsc;
static uint64_t gen;

static void wfile(const char *name, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void wfile(const char *name, const char *fmt, ...)
{
	char path[256];
	va_list ap;
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f)
		abort();
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fclose(f);
}

#define HDR "config omnidns 'main'\n\tlist listen_addr '127.0.0.1'\n" \
	"\toption fakeip_v4 '198.18.0.0/15'\n"
#define RULE_FA "config rule 'fa'\n\toption action 'forward'\n" \
	"\toption upstream '@/up1.conf'\n\tlist nameset '@/a.txt'\n"
#define RULE_BLK "config rule 'blk'\n\toption action 'block'\n" \
	"\tlist nameset '@/a.txt'\n"
#define RULE_ALL "config rule 'all'\n\toption action 'forward'\n" \
	"\toption upstream '@/up2.conf'\n"

static struct config *load(const char *fmt)
{
	char err[512], path[256];
	struct config *c;

	char text[4096], *o = text;

	for (; *fmt; fmt++)
		o += *fmt == '@' ? sprintf(o, "%s", dir) : sprintf(o, "%c", *fmt);
	wfile("omnitest", "%s", text);
	snprintf(path, sizeof(path), "%s/omnitest", dir);
	c = config_load(path, &nsc, err, sizeof(err));
	if (!c) {
		fprintf(stderr, "config_load: %s\n", err);
		abort();
	}
	c->gen = ++gen;
	return c;
}

/* ---- helpers ---- */

static struct dns_name N(const char *text)
{
	struct dns_name n;

	if (dns_name_from_text(&n, text))
		abort();
	return n;
}

static void mkresp(struct dns_msg *m, const char *qname, const char *addr, uint32_t ttl)
{
	struct dns_name n = N(qname);
	uint8_t a[4];

	dns_msg_init(m);
	inet_pton(AF_INET, addr, a);
	dns_msg_set_question(m, n.data, n.len, DNS_T_A, DNS_C_IN);
	m->flags = DNS_F_QR | DNS_F_RA;
	dns_msg_add_rr(m, DNS_S_AN, n.data, n.len, DNS_T_A, DNS_C_IN, ttl, a, 4);
}

static struct cache_dep dep(const struct config *cfg, const char *name)
{
	struct cache_dep d = { .name = N(name) };
	uint16_t idx = match_lookup_wire(cfg->idx, d.name.data, d.name.len);

	d.fingerprint = cfg->rules[idx].fingerprint;
	return d;
}

static int ins(struct cache *c, const struct config *cfg, const char *qname, uint32_t life,
               struct binding *const *b, uint16_t nb)
{
	struct cache_dep d = dep(cfg, qname);
	struct dns_name n = N(qname);
	struct dns_msg m;
	int r;

	mkresp(&m, qname, "1.2.3.4", life);
	r = cache_insert(c, cfg, n.data, n.len, DNS_T_A, DNS_C_IN, &m, life, &d, 1, b, nb);
	dns_msg_free(&m);
	return r;
}

static int look(struct cache *c, const struct config *cfg, const char *qname,
		uint16_t qtype, struct dns_msg *out)
{
	struct dns_name n = N(qname);

	return cache_lookup(c, cfg, n.data, n.len, qtype, DNS_C_IN, out);
}

static const uint8_t SECRET[16] = { 7 };

static struct binding *mkbind(struct fakeip_db *db, const char *ep, const char *real)
{
	struct dns_name n = N(ep);
	uint8_t a[4];
	int err;

	inet_pton(AF_INET, real, a);
	return fakeip_bind(db, "r", 0x01000000, n.data, n.len, 4, a, 60, &err);
}

/* ---- tests ---- */

TEST(basic)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100, 1 << 20, NULL);
	struct dns_msg out;

	dns_msg_init(&out);
	time_override_set(1000);
	CHECK_EQ(look(c, cfg, "x.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(ins(c, cfg, "X.Foo.Example", 300, NULL, 0), 0);
	CHECK_EQ(cache_count(c), 1);
	CHECK(cache_bytes(c) > 0);
	REQUIRE(look(c, cfg, "x.FOO.example", DNS_T_A, &out) == 0);
	CHECK_EQ(out.nrr, 1);
	CHECK_EQ(out.rr[0].ttl, 300);
	CHECK_EQ(out.rr[0].type, DNS_T_A);
	CHECK(!memcmp(out.qname.data, "\x01" "X" "\x03" "Foo", 5));	/* case as stored */
	CHECK_EQ(look(c, cfg, "x.foo.example", DNS_T_AAAA, &out), -ENOENT);

	time_override_advance(100);
	REQUIRE(look(c, cfg, "x.foo.example", DNS_T_A, &out) == 0);
	CHECK_EQ(out.rr[0].ttl, 200);
	time_override_advance(199);
	REQUIRE(look(c, cfg, "x.foo.example", DNS_T_A, &out) == 0);
	CHECK_EQ(out.rr[0].ttl, 1);
	time_override_advance(1);
	CHECK_EQ(look(c, cfg, "x.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(cache_count(c), 0);
	CHECK_EQ(cache_bytes(c), 0);

	/* lifetime shorter than the TTLs; replacement */
	CHECK_EQ(ins(c, cfg, "y.foo.example", 0, NULL, 0), 0);
	CHECK_EQ(cache_count(c), 0);
	CHECK_EQ(ins(c, cfg, "y.foo.example", 10, NULL, 0), 0);
	CHECK_EQ(ins(c, cfg, "Y.foo.example", 20, NULL, 0), 0);
	CHECK_EQ(cache_count(c), 1);
	time_override_advance(15);
	CHECK_EQ(look(c, cfg, "y.foo.example", DNS_T_A, &out), 0);

	dns_msg_free(&out);
	cache_free(c);
	config_free(cfg);
}

TEST(limits_e2big)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100, 1 << 20, NULL);
	struct cache_dep deps[CACHE_MAX_DEPS + 1];
	struct dns_name n = N("a.example");
	struct dns_msg m;
	int i;

	for (i = 0; i <= CACHE_MAX_DEPS; i++)
		deps[i] = dep(cfg, "a.example");
	mkresp(&m, "a.example", "1.1.1.1", 60);
	CHECK_EQ(cache_insert(c, cfg, n.data, n.len, DNS_T_A, DNS_C_IN, &m, 60,
	                      deps, CACHE_MAX_DEPS + 1, NULL, 0), -E2BIG);
	CHECK_EQ(cache_insert(c, cfg, n.data, n.len, DNS_T_A, DNS_C_IN, &m, 60,
	                      deps, CACHE_MAX_DEPS, NULL, 0), 0);
	CHECK_EQ(cache_count(c), 1);
	dns_msg_free(&m);
	cache_free(c);
	config_free(cfg);
}

TEST(revalidation)
{
	struct config *c1 = load(HDR RULE_FA RULE_ALL), *c2, *c3, *c4, *c5;
	struct cache *c = cache_new(100, 1 << 20, NULL);
	struct dns_msg out;

	dns_msg_init(&out);
	time_override_set(1000);
	CHECK_EQ(ins(c, c1, "x.foo.example", 300, NULL, 0), 0);
	CHECK_EQ(ins(c, c1, "other.example", 300, NULL, 0), 0);

	/* the dep now matches a block rule inserted in front */
	c2 = load(HDR RULE_BLK RULE_FA RULE_ALL);
	CHECK_EQ(look(c, c2, "x.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(cache_count(c), 1);
	/* other.example still matches 'all' with the same fingerprint */
	CHECK_EQ(look(c, c2, "other.example", DNS_T_A, &out), 0);

	/* same rules reloaded: hit, gen re-stamped */
	CHECK_EQ(ins(c, c1, "x.foo.example", 300, NULL, 0), 0);
	c3 = load(HDR RULE_FA RULE_ALL);
	CHECK_EQ(look(c, c3, "x.foo.example", DNS_T_A, &out), 0);
	/* re-stamped: a config sharing c3's gen is not re-checked */
	c4 = load(HDR RULE_BLK RULE_FA RULE_ALL);
	c4->gen = c3->gen;
	CHECK_EQ(look(c, c4, "x.foo.example", DNS_T_A, &out), 0);

	/* upstream content change alters fa's fingerprint */
	wfile("up1.conf", "nameserver 8.8.8.8\n");
	c5 = load(HDR RULE_FA RULE_ALL);
	CHECK(c5->rules[0].fingerprint != c3->rules[0].fingerprint);
	CHECK_EQ(look(c, c5, "x.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(look(c, c5, "other.example", DNS_T_A, &out), 0);
	wfile("up1.conf", "nameserver 1.1.1.1\n");

	dns_msg_free(&out);
	cache_free(c);
	config_free(c1);
	config_free(c2);
	config_free(c3);
	config_free(c4);
	config_free(c5);
}

static uint32_t nfdb(struct fakeip_db *db)
{
	return fakeip_count(db);
}

TEST(binding_refs)
{
	struct ip_prefix p4;
	struct fakeip_db *db;
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c;
	struct binding *b[2];
	struct dns_msg out;
	char name[64];
	int i;

	dns_msg_init(&out);
	time_override_set(1000);
	ip_prefix_parse("198.18.0.0/15", &p4);
	db = fakeip_new(&p4, NULL, 1000, 0, SECRET, NULL);
	c = cache_new(8, 1 << 20, db);
	b[0] = mkbind(db, "a.example", "1.1.1.1");
	b[1] = mkbind(db, "b.example", "1.1.1.2");
	REQUIRE(b[0] && b[1]);
	CHECK_EQ(ins(c, cfg, "a.example", 30, b, 2), 0);
	CHECK_EQ(b[0]->refcnt, 1);
	CHECK_EQ(ins(c, cfg, "b.example", 30, b + 1, 1), 0);
	CHECK_EQ(b[1]->refcnt, 2);

	/* replace drops the old entry's refs */
	CHECK_EQ(ins(c, cfg, "a.example", 30, b, 1), 0);
	CHECK_EQ(b[0]->refcnt, 1);
	CHECK_EQ(b[1]->refcnt, 1);

	/* expiry drop */
	time_override_advance(31);
	CHECK_EQ(look(c, cfg, "a.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(b[0]->refcnt, 0);
	CHECK_EQ(look(c, cfg, "b.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(b[1]->refcnt, 0);

	/* eviction drop: 8 entries max, each pins b[0] */
	for (i = 0; i < 40; i++) {
		snprintf(name, sizeof(name), "n%d.example", i);
		CHECK_EQ(ins(c, cfg, name, 300, b, 1), 0);
		CHECK(cache_count(c) <= 8);
	}
	CHECK_EQ(b[0]->refcnt, cache_count(c));

	/* invalidation drop */
	{
		struct config *c2 = load(HDR "config rule 'n'\n\toption action 'block'\n"
		                         "\tlist nameset '@/n.txt'\n" RULE_FA RULE_ALL);
		uint32_t before = cache_count(c);

		snprintf(name, sizeof(name), "n39.example");
		CHECK_EQ(look(c, c2, name, DNS_T_A, &out), -ENOENT);
		CHECK_EQ(cache_count(c), before - 1);
		CHECK_EQ(b[0]->refcnt, before - 1);
		config_free(c2);
	}

	cache_flush(c);
	CHECK_EQ(cache_count(c), 0);
	CHECK_EQ(cache_bytes(c), 0);
	CHECK_EQ(b[0]->refcnt, 0);

	/* refs released on free; the bindings then expire and get evicted */
	CHECK_EQ(ins(c, cfg, "a.example", 30, b, 2), 0);
	cache_free(c);
	CHECK_EQ(b[0]->refcnt, 0);
	CHECK_EQ(b[1]->refcnt, 0);
	CHECK_EQ(nfdb(db), 2);
	dns_msg_free(&out);
	fakeip_free(db);
	config_free(cfg);
}

TEST(byte_limit)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100000, 8192, NULL);
	struct dns_msg out;
	char name[64];
	size_t one;
	int i;

	dns_msg_init(&out);
	time_override_set(1000);
	CHECK_EQ(ins(c, cfg, "first.example", 300, NULL, 0), 0);
	one = cache_bytes(c);
	CHECK(one > 0 && one < 8192 / 4);
	for (i = 0; i < 500; i++) {
		snprintf(name, sizeof(name), "host%d.example", i);
		CHECK_EQ(ins(c, cfg, name, 300, NULL, 0), 0);
		CHECK(cache_bytes(c) <= 8192);
	}
	CHECK(cache_count(c) < 8192 / one + 1);
	CHECK(cache_count(c) > 8192 / one / 2);
	/* the most recent one survives */
	CHECK_EQ(look(c, cfg, "host499.example", DNS_T_A, &out), 0);

	/* entry limit change evicts in a batch */
	cache_set_limits(c, 4, 8192);
	CHECK(cache_count(c) <= 4);
	cache_set_limits(c, 4, 0);
	CHECK_EQ(cache_count(c), 0);
	CHECK_EQ(cache_bytes(c), 0);
	CHECK_EQ(ins(c, cfg, "big.example", 300, NULL, 0), -E2BIG);
	dns_msg_free(&out);
	cache_free(c);
	config_free(cfg);
}

/* ---- message round trips ---- */

static void add(struct dns_msg *m, enum dns_section sec, const char *owner, uint16_t type,
                uint32_t ttl, const void *rd, uint16_t rdlen)
{
	struct dns_name o = N(owner);

	if (dns_msg_add_rr(m, sec, o.data, o.len, type, DNS_C_IN, ttl, rd, rdlen))
		abort();
}

static void add_name(struct dns_msg *m, enum dns_section sec, const char *owner,
                     uint16_t type, uint32_t ttl, const char *target)
{
	struct dns_name t = N(target);

	add(m, sec, owner, type, ttl, t.data, t.len);
}

static void add_a(struct dns_msg *m, enum dns_section sec, const char *owner,
                  uint32_t ttl, const char *addr)
{
	uint8_t a[16];
	int v6 = strchr(addr, ':') != NULL;

	inet_pton(v6 ? AF_INET6 : AF_INET, addr, a);
	add(m, sec, owner, v6 ? DNS_T_AAAA : DNS_T_A, ttl, a, v6 ? 16 : 4);
}

static void qinit(struct dns_msg *m, const char *qname, uint16_t qtype, uint16_t flags)
{
	struct dns_name n = N(qname);

	dns_msg_init(m);
	dns_msg_set_question(m, n.data, n.len, qtype, DNS_C_IN);
	m->id = 0x1234;
	m->flags = flags;
	m->edns.present = true;		/* never cached */
	m->edns.udp_size = 1232;
}

/* A CNAME chain with mixed-case owners, NS and AR sections. */
static void msg_chain(struct dns_msg *m)
{
	qinit(m, "Www.Foo.Example", DNS_T_A, DNS_F_QR | DNS_F_AA | DNS_F_RD | DNS_F_RA);
	add_name(m, DNS_S_AN, "Www.Foo.Example", DNS_T_CNAME, 300, "Edge.CDN.example");
	add_name(m, DNS_S_AN, "edge.cdn.example", DNS_T_CNAME, 120, "a1.cdn.example");
	add_a(m, DNS_S_AN, "a1.cdn.example", 60, "192.0.2.1");
	add_a(m, DNS_S_AN, "A1.cdn.example", 30, "192.0.2.2");
	add_name(m, DNS_S_NS, "cdn.example", DNS_T_NS, 3600, "ns1.cdn.example");
	add_a(m, DNS_S_AR, "ns1.cdn.example", 3600, "192.0.2.53");
	add_a(m, DNS_S_AR, "ns1.cdn.example", 3600, "2001:db8::53");
}

/* NXDOMAIN with the zone SOA in the authority section. */
static void msg_nx(struct dns_msg *m)
{
	struct dns_name mn = N("ns.foo.example"), rn = N("Host.foo.example");
	static const uint8_t fixed[20] = { 0, 0, 0, 7, 0, 0, 0x0e, 0x10, 0, 0, 0x03, 0x84,
	                                   0, 0x09, 0x3a, 0x80, 0, 0, 0x01, 0x2c };
	uint8_t rd[300], *p = rd;

	qinit(m, "nx.foo.example", DNS_T_AAAA, DNS_F_QR | DNS_F_RA | DNS_R_NXDOMAIN);
	memcpy(p, mn.data, mn.len);
	p += mn.len;
	memcpy(p, rn.data, rn.len);
	p += rn.len;
	memcpy(p, fixed, 20);
	p += 20;
	add(m, DNS_S_NS, "foo.example", DNS_T_SOA, 900, rd, (uint16_t)(p - rd));
}

/* HTTPS with alpn and ipv4hint, plus a glue A. */
static void msg_https(struct dns_msg *m)
{
	static const uint8_t rd[] = {
		0, 1, 0,				/* priority 1, target "." */
		0, 1, 0, 3, 2, 'h', '2',		/* alpn=h2 */
		0, 4, 0, 4, 192, 0, 2, 7,		/* ipv4hint */
	};

	qinit(m, "svc.example", DNS_T_HTTPS, DNS_F_QR | DNS_F_RA);
	add(m, DNS_S_AN, "svc.example", DNS_T_HTTPS, 100, rd, sizeof(rd));
	add_a(m, DNS_S_AR, "svc.example", 100, "192.0.2.7");
}

static int ins_msg(struct cache *c, const struct config *cfg, const struct dns_msg *m,
                   uint32_t life)
{
	struct cache_dep d = dep(cfg, "x.example");

	return cache_insert(c, cfg, m->qname.data, m->qname.len, m->qtype, DNS_C_IN, m,
	                    life, &d, 1, NULL, 0);
}

/*
 * Compare a cache hit with what a deep copy of the inserted message aged by
 * `age` looks like (the original cache semantics): same flags, question,
 * RR order and bytes, TTLs reduced and floored at 0, id and EDNS zero.
 */
static void check_hit(const struct dns_msg *got, const struct dns_msg *resp, uint32_t age)
{
	uint8_t w1[4096], w2[4096];
	struct dns_msg exp;
	int n1, n2;
	uint16_t i;

	CHECK_EQ(got->id, 0);
	CHECK(!got->edns.present && !got->edns.ext_rcode && !got->edns.udp_size);
	CHECK_EQ(got->flags, resp->flags);
	CHECK_EQ(got->has_q, resp->has_q);
	CHECK_EQ(got->qname.len, resp->qname.len);
	CHECK(!memcmp(got->qname.data, resp->qname.data, resp->qname.len));
	CHECK_EQ(got->qtype, resp->qtype);
	CHECK_EQ(got->qclass, resp->qclass);
	REQUIRE(got->nrr == resp->nrr);
	for (i = 0; i < got->nrr; i++) {
		const struct dns_rr *g = &got->rr[i], *r = &resp->rr[i];

		CHECK_EQ(g->section, r->section);
		CHECK_EQ(g->type, r->type);
		CHECK_EQ(g->cls, r->cls);
		CHECK_EQ(g->ttl, r->ttl > age ? r->ttl - age : 0);
		CHECK_EQ(g->owner_len, r->owner_len);
		CHECK(!memcmp(g->owner, r->owner, r->owner_len));
		CHECK_EQ(g->rdlen, r->rdlen);
		CHECK(!r->rdlen || !memcmp(g->rdata, r->rdata, r->rdlen));
		CHECK(g->owner >= got->buf && g->rdata + g->rdlen <= got->buf + got->buf_len);
	}

	/* and the wire form is byte-identical */
	dns_msg_init(&exp);
	REQUIRE(dns_msg_copy(&exp, resp) == 0);
	exp.id = 0;
	memset(&exp.edns, 0, sizeof(exp.edns));
	for (i = 0; i < exp.nrr; i++)
		exp.rr[i].ttl = exp.rr[i].ttl > age ? exp.rr[i].ttl - age : 0;
	n1 = dns_build(&exp, w1, sizeof(w1));
	n2 = dns_build(got, w2, sizeof(w2));
	CHECK(n1 > 12);
	CHECK_EQ(n1, n2);
	CHECK(n1 == n2 && !memcmp(w1, w2, (size_t)n1));
	dns_msg_free(&exp);
}

TEST(round_trip)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100, 1 << 20, NULL);
	struct dns_msg m[4], out;
	uint32_t age;
	int i;

	dns_msg_init(&out);
	time_override_set(5000);
	msg_chain(&m[0]);
	msg_nx(&m[1]);
	msg_https(&m[2]);
	qinit(&m[3], "empty.example", DNS_T_TXT, DNS_F_QR | DNS_F_RA);	/* NODATA, no RRs */
	for (i = 0; i < 4; i++)
		CHECK_EQ(ins_msg(c, cfg, &m[i], 1000), 0);
	CHECK_EQ(cache_count(c), 4);

	/* `out` is reused across hits of different sizes */
	for (age = 0; age <= 45; age += 45) {
		for (i = 0; i < 4; i++) {
			REQUIRE(cache_lookup(c, cfg, m[i].qname.data, m[i].qname.len, m[i].qtype,
			                     DNS_C_IN, &out) == 0);
			check_hit(&out, &m[i], age);
		}
		REQUIRE(cache_lookup(c, cfg, m[0].qname.data, m[0].qname.len, m[0].qtype,
		                     DNS_C_IN, &out) == 0);
		check_hit(&out, &m[0], age);
		time_override_advance(45);
	}
	/* lookups are case-insensitive; the question keeps the stored case */
	{
		struct dns_name q = N("www.FOO.example");

		REQUIRE(cache_lookup(c, cfg, q.data, q.len, DNS_T_A, DNS_C_IN, &out) == 0);
		check_hit(&out, &m[0], 90);
	}

	for (i = 0; i < 4; i++)
		dns_msg_free(&m[i]);
	dns_msg_free(&out);
	cache_free(c);
	config_free(cfg);
}

/* Answers whose owners and rdata expand past 64 KiB. */
TEST(huge_answer)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100, 1 << 20, NULL);
	struct dns_msg m, out;
	uint8_t rd[255];
	int i;

	dns_msg_init(&out);
	time_override_set(1000);
	/* 300 distinct 255-byte TXT rdata: ~76 KiB, not addressable */
	qinit(&m, "big.example", DNS_T_TXT, DNS_F_QR | DNS_F_RA);
	rd[0] = 254;
	for (i = 0; i < 300; i++) {
		memset(rd + 1, 'a' + i % 26, 254);
		rd[1] = (uint8_t)i;
		rd[2] = (uint8_t)(i >> 8);
		add(&m, DNS_S_AN, "big.example", DNS_T_TXT, 60, rd, sizeof(rd));
	}
	CHECK_EQ(ins_msg(c, cfg, &m, 60), -E2BIG);
	CHECK_EQ(cache_count(c), 0);
	CHECK_EQ(cache_bytes(c), 0);
	dns_msg_free(&m);

	/* the same size, repetitive: interned, cached and served intact */
	qinit(&m, "big.example", DNS_T_TXT, DNS_F_QR | DNS_F_RA);
	for (i = 0; i < 300; i++) {
		memset(rd + 1, 'a' + i % 4, 254);
		add(&m, DNS_S_AN, "big.example", DNS_T_TXT, 60, rd, sizeof(rd));
	}
	CHECK_EQ(ins_msg(c, cfg, &m, 60), 0);
	CHECK_EQ(cache_count(c), 1);
	REQUIRE(cache_lookup(c, cfg, m.qname.data, m.qname.len, DNS_T_TXT, DNS_C_IN, &out) == 0);
	check_hit(&out, &m, 0);
	dns_msg_free(&m);

	dns_msg_free(&out);
	cache_free(c);
	config_free(cfg);
}

/* ---- dependencies ---- */

static int ins_deps(struct cache *c, const struct config *cfg, const char *qname,
                    const char *d0, const char *d1)
{
	struct cache_dep d[2];
	struct dns_name n = N(qname);
	struct dns_msg m;
	uint16_t nd = 0;
	int r;

	if (d0)
		d[nd++] = dep(cfg, d0);
	if (d1)
		d[nd++] = dep(cfg, d1);
	mkresp(&m, qname, "192.0.2.9", 300);
	r = cache_insert(c, cfg, n.data, n.len, DNS_T_A, DNS_C_IN, &m, 300, d, nd, NULL, 0);
	dns_msg_free(&m);
	return r;
}

TEST(deps_revalidation)
{
	struct config *c1 = load(HDR RULE_FA RULE_ALL), *c2, *c3, *c4;
	struct cache *c = cache_new(100, 1 << 20, NULL);
	struct dns_msg out;

	dns_msg_init(&out);
	time_override_set(1000);
	/* qname first (as policy_step records it), qname absent, qname in another case */
	CHECK_EQ(ins_deps(c, c1, "Www.Foo.Example", "www.foo.example", "cdn.other.example"), 0);
	CHECK_EQ(ins_deps(c, c1, "x.foo.example", "cdn.other.example", NULL), 0);
	CHECK_EQ(ins_deps(c, c1, "Y.Foo.Example", "y.FOO.example", "z.foo.example"), 0);
	CHECK_EQ(ins_deps(c, c1, "q.example", "q.example", NULL), 0);
	CHECK_EQ(cache_count(c), 4);

	/* same generation: no re-check */
	CHECK_EQ(look(c, c1, "www.foo.example", DNS_T_A, &out), 0);

	/* cdn.other.example now hits a new rule in front: entries depending on it go */
	c2 = load(HDR "config rule 'cdn'\n\toption action 'block'\n"
	          "\tlist nameset '@/cdn.txt'\n" RULE_FA RULE_ALL);
	CHECK_EQ(look(c, c2, "www.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(look(c, c2, "x.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(look(c, c2, "y.foo.example", DNS_T_A, &out), 0);
	CHECK_EQ(look(c, c2, "q.example", DNS_T_A, &out), 0);
	CHECK_EQ(cache_count(c), 2);

	/* the qname dep itself changes: the qname-first entries go */
	CHECK_EQ(ins_deps(c, c2, "Www.Foo.Example", "www.foo.example", "other.example"), 0);
	CHECK_EQ(ins_deps(c, c2, "x.foo.example", "other.example", NULL), 0);
	c3 = load(HDR RULE_BLK RULE_FA RULE_ALL);
	CHECK_EQ(look(c, c3, "www.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(look(c, c3, "x.foo.example", DNS_T_A, &out), 0);
	CHECK_EQ(look(c, c3, "Y.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(look(c, c3, "q.example", DNS_T_A, &out), 0);
	CHECK_EQ(cache_count(c), 2);

	/* q.example (qname-only dep) changes when 'all' changes */
	wfile("up2.conf", "nameserver 9.9.9.10\n");
	c4 = load(HDR RULE_BLK RULE_FA RULE_ALL);
	CHECK_EQ(look(c, c4, "q.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(look(c, c4, "x.foo.example", DNS_T_A, &out), -ENOENT);
	CHECK_EQ(cache_count(c), 0);
	wfile("up2.conf", "nameserver 9.9.9.9\n");

	/* a dep naming the qname costs only its fingerprint and length byte */
	{
		size_t b1, b2, b3;

		CHECK_EQ(ins_deps(c, c4, "b.foo.example", "cdn.other.example", NULL), 0);
		b1 = cache_bytes(c);
		CHECK_EQ(ins_deps(c, c4, "b.foo.example", "B.Foo.Example", "cdn.other.example"), 0);
		b2 = cache_bytes(c);
		CHECK_EQ(ins_deps(c, c4, "b.foo.example", "c.foo.example", "cdn.other.example"), 0);
		b3 = cache_bytes(c);
		CHECK_EQ(b2 - b1, 9);
		CHECK_EQ(b3 - b1, 9 + 15);
		CHECK_EQ(look(c, c4, "b.foo.example", DNS_T_A, &out), 0);
	}

	dns_msg_free(&out);
	cache_free(c);
	config_free(c1);
	config_free(c2);
	config_free(c3);
	config_free(c4);
}

/* ---- byte accounting ---- */

#ifdef __SANITIZE_ADDRESS__
/* <sanitizer/allocator_interface.h> is not always installed */
size_t __sanitizer_get_current_allocated_bytes(void);
#define HEAP_NOW() __sanitizer_get_current_allocated_bytes()
#endif

TEST(byte_accounting)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(1000, 1 << 20, NULL);
	struct dns_msg m[3], out;
	char name[64];
	int i;

	dns_msg_init(&out);
	time_override_set(1000);
	msg_chain(&m[0]);
	msg_nx(&m[1]);
	msg_https(&m[2]);
	for (i = 0; i < 3; i++)
		CHECK_EQ(ins_msg(c, cfg, &m[i], 300), 0);
	CHECK_EQ(ins_deps(c, cfg, "Www.Foo.Example", "www.foo.example", "cdn.other.example"), 0);
	CHECK_EQ(ins_deps(c, cfg, "a.foo.example", "cdn.other.example", NULL), 0);
	for (i = 0; i < 20; i++) {
		snprintf(name, sizeof(name), "h%d.example", i);
		CHECK_EQ(ins(c, cfg, name, 300, NULL, 0), 0);
	}
#ifdef HEAP_NOW
	{
		size_t h0, h1, b0, b1;
		uint32_t n;

		/* replacing an entry changes the heap by exactly its accounted delta
		 * (once the hash table has settled at its size) */
		for (i = 0; i < 4; i++)
			CHECK_EQ(ins_deps(c, cfg, "a.foo.example", "cdn.other.example", NULL), 0);
		h0 = HEAP_NOW();
		b0 = cache_bytes(c);
		CHECK_EQ(ins_deps(c, cfg, "a.foo.example", "a.foo.example", "cdn.other.example"), 0);
		CHECK_EQ(HEAP_NOW() - h0, cache_bytes(c) - b0);
		h0 = HEAP_NOW();
		b0 = cache_bytes(c);
		CHECK_EQ(ins_deps(c, cfg, "a.foo.example", NULL, NULL), 0);
		CHECK_EQ(h0 - HEAP_NOW(), b0 - cache_bytes(c));

		/* the hmap never shrinks, so a flush frees exactly the entries */
		n = cache_count(c);
		b0 = cache_bytes(c);
		h0 = HEAP_NOW();
		cache_flush(c);
		h1 = HEAP_NOW();
		b1 = cache_bytes(c);
		CHECK_EQ(b1, 0);
		CHECK_EQ(b0, (h0 - h1) + (size_t)n * CACHE_ENTRY_OVERHEAD);
	}
#else
	fprintf(stderr, "  (heap checks need ASan)\n");
#endif

	/* eviction by bytes with multi-RR entries */
	cache_flush(c);
	cache_set_limits(c, 100000, 4096);
	for (i = 0; i < 100; i++) {
		struct dns_name q;

		snprintf(name, sizeof(name), "c%d.example", i);
		q = N(name);
		dns_msg_set_question(&m[0], q.data, q.len, DNS_T_A, DNS_C_IN);
		CHECK_EQ(ins_msg(c, cfg, &m[0], 300), 0);
		CHECK(cache_bytes(c) <= 4096);
	}
	CHECK(cache_count(c) > 2 && cache_count(c) < 100);
	{
		struct dns_name q = N("c99.example");

		CHECK_EQ(cache_lookup(c, cfg, q.data, q.len, DNS_T_A, DNS_C_IN, &out), 0);
	}

	for (i = 0; i < 3; i++)
		dns_msg_free(&m[i]);
	dns_msg_free(&out);
	cache_free(c);
	config_free(cfg);
}

static int rm_cb(const char *p, const struct stat *st, int flag, struct FTW *f)
{
	return remove(p);
}

int main(void)
{
	hash_init();
	log_init("test_cache", true, getenv("TEST_VERBOSE") ? LOG_DEBUG : LOG_CRIT);
	strcpy(dir, "/tmp/omnicache.XXXXXX");
	if (!mkdtemp(dir))
		return 1;
	nsc_init(&nsc);
	wfile("up1.conf", "nameserver 1.1.1.1\n");
	wfile("up2.conf", "nameserver 9.9.9.9\n");
	wfile("a.txt", "*.foo.example\n");
	wfile("n.txt", "n39.example\n");
	wfile("cdn.txt", "cdn.other.example\n");
	RUN(basic);
	RUN(limits_e2big);
	RUN(revalidation);
	RUN(binding_refs);
	RUN(byte_limit);
	RUN(round_trip);
	RUN(huge_answer);
	RUN(deps_revalidation);
	RUN(byte_accounting);
	nsc_destroy(&nsc);
	nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
	return test_summary();
}
