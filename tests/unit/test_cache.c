// SPDX-License-Identifier: MIT
#include <arpa/inet.h>
#include <ftw.h>
#include <stdarg.h>
#include <sys/stat.h>

#include "test.h"
#include "reply_corpus.h"
#include "cache.h"
#include "config.h"
#include "fakeip.h"
#include "log.h"
#include "match.h"
#include "nft.h"
#include "util/hash.h"
#include "util/time.h"

/* A copy of a message's question name. */
static inline struct dns_name qname_of(const struct dns_msg *m)
{
	struct dns_name n = { .len = m->qlen };

	memcpy(n.data, dns_msg_qname(m), m->qlen);
	return n;
}

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

bool nft_mark_known(const struct nft_ctx *n, uint32_t mark)
{
	return true;
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

/* Append the packed dependency (name -> its rule under cfg) of an entry for qname. */
static size_t dep(uint8_t *p, const struct config *cfg, const char *qname, const char *name)
{
	struct dns_name d = N(name), q = N(qname);
	uint16_t idx = match_lookup_wire(cfg->idx, d.data, d.len);

	return cache_dep_put(p, cfg->rules[idx].fingerprint, d.data, d.len, q.data, q.len);
}

static uint8_t wbuf[DNS_MAX_MSG], rbuf[DNS_MAX_MSG], refbuf[DNS_MAX_MSG + 1];

/* resp as resolve hands it to the cache: built once, id 0, no OPT */
static int wire_of(const struct dns_msg *resp, uint8_t *buf)
{
	struct dns_msg m = *resp;

	m.id = 0;
	memset(&m.edns, 0, sizeof(m.edns));
	return dns_build(&m, buf, DNS_MAX_MSG);
}

static int ins_resp(struct cache *c, const struct config *cfg, const struct dns_msg *resp,
                    uint32_t life, const uint8_t *deps, size_t dsz, uint16_t nd,
                    struct binding *const *b, uint16_t nb)
{
	int n = wire_of(resp, wbuf);

	if (n < 0)
		return n;
	return cache_insert(c, cfg, dns_msg_qname(resp), resp->qlen, resp->qtype, DNS_C_IN,
	                    cache_hash(dns_msg_qname(resp), resp->qlen, resp->qtype, DNS_C_IN),
	                    wbuf, (size_t)n, life, deps, dsz, nd, b, nb);
}

static int ins(struct cache *c, const struct config *cfg, const char *qname, uint32_t life,
               struct binding *const *b, uint16_t nb)
{
	uint8_t d[CACHE_DEP_HDR + DNS_MAX_NAME];
	size_t dsz = dep(d, cfg, qname, qname);
	struct dns_msg m;
	int r;

	mkresp(&m, qname, "1.2.3.4", life);
	r = ins_resp(c, cfg, &m, life, d, dsz, 1, b, nb);
	dns_msg_free(&m);
	return r;
}

/* Look a name up and render the hit for a client asking with that exact
 * name, id 0, no RD/CD and no EDNS, over TCP: rbuf, returns its length. */
static int look_raw(struct cache *c, const struct config *cfg, const struct dns_name *n,
                    uint16_t qtype, uint32_t *age)
{
	struct dns_reply rp = { .qname = n->data, .qlen = n->len };
	struct cache_hit h;
	int r;

	r = cache_lookup(c, cfg, n->data, n->len, qtype, DNS_C_IN,
	                 cache_hash(n->data, n->len, qtype, DNS_C_IN), &h);
	if (r)
		return r;
	rp.age = h.age;
	if (age)
		*age = h.age;
	r = dns_reply_render(h.msg, h.len, &rp, rbuf, sizeof(rbuf));
	CHECK(r > 0);
	return r;
}

/* ... and parse it into out */
static int look(struct cache *c, const struct config *cfg, const char *qname,
		uint16_t qtype, struct dns_msg *out)
{
	struct dns_name n = N(qname);
	int r = look_raw(c, cfg, &n, qtype, NULL);

	if (r < 0)
		return r;
	r = dns_parse(out, rbuf, (size_t)r);
	CHECK_EQ(r, 0);
	return r ? -EBADMSG : 0;
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
	CHECK(!memcmp(dns_msg_qname(&out), "\x01" "x" "\x03" "FOO", 5));	/* the client's case */
	CHECK_EQ(out.flags, DNS_F_QR | DNS_F_RA);
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
	uint8_t deps[(CACHE_MAX_DEPS + 1) * (CACHE_DEP_HDR + 16)];
	struct dns_name n = N("a.example");
	size_t dsz = 0, sz32 = 0;
	struct dns_msg m;
	int i;

	for (i = 0; i <= CACHE_MAX_DEPS; i++) {
		char name[32];

		snprintf(name, sizeof(name), "d%d.example", i);
		sz32 = dsz;
		dsz += dep(deps + dsz, cfg, "a.example", name);
	}
	mkresp(&m, "a.example", "1.1.1.1", 60);
	CHECK_EQ(ins_resp(c, cfg, &m, 60, deps, dsz, CACHE_MAX_DEPS + 1, NULL, 0), -E2BIG);
	CHECK_EQ(ins_resp(c, cfg, &m, 60, deps, sz32, CACHE_MAX_DEPS, NULL, 0), 0);
	CHECK_EQ(cache_count(c), 1);
	/* the stored question must be the key */
	{
		struct dns_name other = N("b.example");
		int len = wire_of(&m, wbuf);

		CHECK_EQ(cache_insert(c, cfg, other.data, other.len, DNS_T_A, DNS_C_IN,
		                      cache_hash(other.data, other.len, DNS_T_A, DNS_C_IN),
		                      wbuf, (size_t)len, 60, NULL, 0, 0, NULL, 0), -EINVAL);
		CHECK_EQ(cache_insert(c, cfg, n.data, n.len, DNS_T_A, DNS_C_IN,
		                      cache_hash(n.data, n.len, DNS_T_A, DNS_C_IN),
		                      wbuf, 20, 60, NULL, 0, 0, NULL, 0), -EINVAL);
		CHECK_EQ(cache_insert(c, cfg, n.data, n.len, DNS_T_AAAA, DNS_C_IN,
		                      cache_hash(n.data, n.len, DNS_T_AAAA, DNS_C_IN),
		                      wbuf, (size_t)len, 60, NULL, 0, 0, NULL, 0), -EINVAL);
	}
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
	uint8_t d[CACHE_DEP_HDR + DNS_MAX_NAME];
	size_t dsz = dep(d, cfg, "invalid", "x.example");

	return ins_resp(c, cfg, m, life, d, dsz, 1, NULL, 0);
}

/*
 * A hit for client name q (rendered by look_raw) must be byte for byte what
 * the pre-wire-cache path made of the inserted message aged by `age`.
 */
static void check_hit(int got, const struct dns_msg *resp, const struct dns_name *q,
                      uint32_t age)
{
	int n = ref_reply(resp, q->data, q->len, 0, 0, false, 65536, age, refbuf);

	CHECK(n > 12);
	CHECK_EQ(got, n);
	CHECK(got == n && !memcmp(rbuf, refbuf, (size_t)n));
}

TEST(round_trip)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100, 1 << 20, NULL);
	struct dns_msg m[4];
	uint32_t age, a;
	int i;

	time_override_set(5000);
	msg_chain(&m[0]);
	msg_nx(&m[1]);
	msg_https(&m[2]);
	qinit(&m[3], "empty.example", DNS_T_TXT, DNS_F_QR | DNS_F_RA);	/* NODATA, no RRs */
	for (i = 0; i < 4; i++)
		CHECK_EQ(ins_msg(c, cfg, &m[i], 1000), 0);
	CHECK_EQ(cache_count(c), 4);

	for (age = 0; age <= 45; age += 45) {
		for (i = 0; i < 4; i++) {
			struct dns_name q = qname_of(&m[i]);
			int n = look_raw(c, cfg, &q, m[i].qtype, &a);

			REQUIRE(n > 0);
			CHECK_EQ(a, age);
			check_hit(n, &m[i], &q, age);
		}
		time_override_advance(45);
	}
	/* lookups are case-insensitive; the question takes the client's case */
	{
		struct dns_name q = N("www.FOO.example");
		int n = look_raw(c, cfg, &q, DNS_T_A, NULL);

		REQUIRE(n > 0);
		CHECK(!memcmp(rbuf + 12, q.data, q.len));
		check_hit(n, &m[0], &q, 90);
	}

	for (i = 0; i < 4; i++)
		dns_msg_free(&m[i]);
	cache_free(c);
	config_free(cfg);
}

/* An answer too large for a TCP message is stored, and served, truncated. */
TEST(huge_answer)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100, 1 << 20, NULL);
	struct dns_msg m, out;
	struct dns_name q;
	uint8_t rd[255];
	size_t b0;
	int i, n;

	dns_msg_init(&out);
	time_override_set(1000);
	/* 300 distinct 255-byte TXT rdata: ~76 KiB */
	qinit(&m, "big.example", DNS_T_TXT, DNS_F_QR | DNS_F_RA);
	rd[0] = 254;
	for (i = 0; i < 300; i++) {
		memset(rd + 1, 'a' + i % 26, 254);
		rd[1] = (uint8_t)i;
		rd[2] = (uint8_t)(i >> 8);
		add(&m, DNS_S_AN, "big.example", DNS_T_TXT, 60, rd, sizeof(rd));
	}
	CHECK_EQ(ins_msg(c, cfg, &m, 60), 0);
	CHECK_EQ(cache_count(c), 1);
	b0 = cache_bytes(c);
	CHECK(b0 < 200 + CACHE_ENTRY_OVERHEAD);
	q = qname_of(&m);
	n = look_raw(c, cfg, &q, DNS_T_TXT, NULL);
	check_hit(n, &m, &q, 0);
	REQUIRE(look(c, cfg, "big.example", DNS_T_TXT, &out) == 0);
	CHECK(out.flags & DNS_F_TC);
	CHECK_EQ(out.nrr, 0);
	dns_msg_free(&m);

	/* 240 of them fit and are stored whole */
	qinit(&m, "big.example", DNS_T_TXT, DNS_F_QR | DNS_F_RA);
	for (i = 0; i < 240; i++) {
		memset(rd + 1, 'a' + i % 4, 254);
		add(&m, DNS_S_AN, "big.example", DNS_T_TXT, 60, rd, sizeof(rd));
	}
	CHECK_EQ(ins_msg(c, cfg, &m, 60), 0);
	CHECK_EQ(cache_count(c), 1);
	CHECK(cache_bytes(c) > 240 * 267);
	q = qname_of(&m);
	n = look_raw(c, cfg, &q, DNS_T_TXT, NULL);
	check_hit(n, &m, &q, 0);
	dns_msg_free(&m);

	dns_msg_free(&out);
	cache_free(c);
	config_free(cfg);
}

/* ---- delivery from the stored bytes vs the old path ---- */

struct golden {
	const char *name;
	int len;
	uint64_t fnv;
	const char *hex;
};

static const struct golden golden[] = {
#include "reply_golden.inc"
};

/*
 * Cases whose recorded bytes changed on purpose: they have names equal but
 * for case (a 0x20 client, or an upstream echoing one), which dns_build()
 * now compresses case-insensitively. They are compared with the reference
 * path run on today's dns_build(), and must still parse to the same
 * records as the recording, apart from the case of compressed names.
 */
static const char *const ci_changed[] = {
	"chain_0x20", "mixed", "mixed_other", "https_edns", "glue_edns900",
};

static uint64_t fnv64(const uint8_t *p, size_t n)
{
	uint64_t h = 1469598103934665603ull;

	while (n--)
		h = (h ^ *p++) * 1099511628211ull;
	return h;
}

static bool is_ci_changed(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof(ci_changed) / sizeof(ci_changed[0]); i++)
		if (!strcmp(name, ci_changed[i]))
			return true;
	return false;
}

/* The same messages, compared without case and the id. */
static bool same_msg_nocase(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	struct dns_msg x, y;
	bool ok;
	uint16_t i;

	dns_msg_init(&x);
	dns_msg_init(&y);
	ok = !dns_parse(&x, a, alen) && !dns_parse(&y, b, blen) && x.flags == y.flags &&
	     x.nrr == y.nrr && x.edns.present == y.edns.present &&
	     dns_name_eq(dns_msg_qname(&x), x.qlen, dns_msg_qname(&y), y.qlen);
	for (i = 0; ok && i < x.nrr; i++) {
		const struct dns_rr *r = &x.rr[i], *t = &y.rr[i];
		uint16_t k;

		ok = r->section == t->section && r->type == t->type && r->ttl == t->ttl &&
		     dns_name_eq(r->owner, r->owner_len, t->owner, t->owner_len) &&
		     r->rdlen == t->rdlen;
		for (k = 0; ok && k < r->rdlen; k++)
			ok = (r->rdata[k] | 0x20) == (t->rdata[k] | 0x20);
	}
	dns_msg_free(&x);
	dns_msg_free(&y);
	return ok;
}

static int hexval(char ch)
{
	return ch <= '9' ? ch - '0' : ch - 'a' + 10;
}

/* Insert a case's answer, age it, and render the hit for the case's client. */
static int deliver_case(struct cache *c, const struct config *cfg, const struct rcase *rc,
                        const struct dns_msg *m)
{
	struct dns_name q = rc_N(rc->client);
	struct dns_reply rp = {
		.id = rc->id, .rdcd = rc->rdcd, .qname = q.data, .qlen = q.len,
		.edns = rc->edns, .edns_udp = REF_EDNS_MAX_UDP,
	};
	struct cache_hit h;

	cache_flush(c);
	time_override_set(100000);
	if (ins_resp(c, cfg, m, 1000000, NULL, 0, 0, NULL, 0))
		return -1;
	time_override_advance(rc->age);
	if (cache_lookup(c, cfg, q.data, q.len, m->qtype, DNS_C_IN,
	                 cache_hash(q.data, q.len, m->qtype, DNS_C_IN), &h))
		return -1;
	CHECK_EQ(h.age, rc->age);
	rp.age = h.age;
	return dns_reply_render(h.msg, h.len, &rp, rbuf,
	                        ref_limit(rc->edns, rc->tcp, rc->udp_size));
}

TEST(golden_replies)
{
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100, 1 << 20, NULL);
	size_t i;

	REQUIRE(NRCASES == sizeof(golden) / sizeof(golden[0]));
	for (i = 0; i < NRCASES; i++) {
		const struct rcase *rc = &rcases[i];
		const struct golden *g = &golden[i];
		struct dns_msg m;
		int n, nref, k;

		if (strcmp(rc->name, g->name)) {
			CHECK(!strcmp(rc->name, g->name));
			break;
		}
		rc->mk(&m);
		n = deliver_case(c, cfg, rc, &m);
		nref = ref_case(rc, &m, refbuf);
		dns_msg_free(&m);
		if (n != nref || memcmp(rbuf, refbuf, (size_t)(n > 0 ? n : 0))) {
			fprintf(stderr, "  case %s: differs from the reference (%d vs %d)\n",
			        rc->name, n, nref);
			CHECK(0);
			continue;
		}
		if (is_ci_changed(rc->name)) {
			uint8_t old[1400];

			if (!g->hex || strlen(g->hex) / 2 > sizeof(old)) {
				CHECK(0);
				continue;
			}
			for (k = 0; k < g->len; k++)
				old[k] = (uint8_t)(hexval(g->hex[2 * k]) << 4 | hexval(g->hex[2 * k + 1]));
			CHECK(n != g->len || memcmp(rbuf, old, (size_t)n));	/* still listed? */
			if (!same_msg_nocase(rbuf, (size_t)n, old, (size_t)g->len)) {
				fprintf(stderr, "  case %s: not the recorded message\n", rc->name);
				CHECK(0);
			}
			continue;
		}
		if (n != g->len || fnv64(rbuf, (size_t)n) != g->fnv) {
			fprintf(stderr, "  case %s: %d bytes, recorded %d\n", rc->name, n, g->len);
			CHECK(0);
		}
	}
	cache_free(c);
	config_free(cfg);
}

/* ---- randomized: insert -> deliver vs the reference ---- */

static uint32_t rnd_state = 12345;

static uint32_t rnd(void)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 17;
	rnd_state ^= rnd_state << 5;
	return rnd_state;
}

static const char *const rnd_names[] = {
	"example", "a.example", "b.a.example", "www.example", "cdn.www.example",
	"x.y.z.example", "mail.example", "ns1.example", "ns2.example", "zz.test",
};

static struct dns_name rnd_name(void)
{
	struct dns_name n = rc_N(rnd_names[rnd() % (sizeof(rnd_names) / sizeof(rnd_names[0]))]);
	uint8_t i;

	for (i = 0; i < n.len; i++)
		if (n.data[i] >= 'a' && n.data[i] <= 'z' && rnd() % 3 == 0)
			n.data[i] -= 32;
	return n;
}

static void rnd_rr(struct dns_msg *m, enum dns_section sec)
{
	static const uint16_t types[] = { DNS_T_A, DNS_T_AAAA, DNS_T_CNAME, DNS_T_NS, DNS_T_PTR,
	                                  DNS_T_MX, DNS_T_SOA, DNS_T_TXT, DNS_T_SRV, DNS_T_HTTPS };
	struct dns_name o = rnd_name(), t = rnd_name(), t2 = rnd_name();
	uint16_t type = types[rnd() % (sizeof(types) / sizeof(types[0]))], len = 0, i;
	uint32_t ttl = rnd() % 4 == 0 ? rnd() % 0x80000000u : rnd() % 400;
	uint8_t rd[700];

	switch (type) {
	case DNS_T_A:
	case DNS_T_AAAA:
		len = type == DNS_T_A ? 4 : 16;
		for (i = 0; i < len; i++)
			rd[i] = (uint8_t)rnd();
		break;
	case DNS_T_CNAME: case DNS_T_NS: case DNS_T_PTR:
		memcpy(rd, t.data, t.len);
		len = t.len;
		break;
	case DNS_T_MX:
		rd[0] = 0;
		rd[1] = (uint8_t)rnd();
		memcpy(rd + 2, t.data, t.len);
		len = 2 + t.len;
		break;
	case DNS_T_SOA:
		memcpy(rd, t.data, t.len);
		memcpy(rd + t.len, t2.data, t2.len);
		len = t.len + t2.len;
		for (i = 0; i < 20; i++)
			rd[len++] = (uint8_t)rnd();
		break;
	default:
		len = (uint16_t)(rnd() % 600);
		for (i = 0; i < len; i++)
			rd[i] = (uint8_t)rnd();
		break;
	}
	if (dns_msg_add_rr(m, sec, o.data, o.len, type, DNS_C_IN, ttl, rd, len))
		abort();
}

TEST(randomized_replies)
{
	static const uint16_t sizes[] = { 0, 100, 512, 513, 700, 1232, 1400, 4096 };
	struct config *cfg = load(HDR RULE_FA RULE_ALL);
	struct cache *c = cache_new(100, 64 << 20, NULL);
	int iter, fails = 0;

	for (iter = 0; iter < 3000 && fails < 5; iter++) {
		struct dns_name q = rnd_name();
		struct rcase rc = { 0 };
		struct dns_msg m;
		int sec, k, n, nref, nrr = (int)(rnd() % (rnd() % 8 == 0 ? 170 : 40));

		dns_msg_init(&m);
		dns_msg_set_question(&m, q.data, q.len, (uint16_t)(1 + rnd() % 70), DNS_C_IN);
		m.flags = (uint16_t)(rnd() & ~DNS_F_QR);
		for (sec = DNS_S_AN; sec <= DNS_S_AR; sec++)
			for (k = rnd() % 3 ? (int)(rnd() % (nrr + 1)) : 0; k > 0; k--)
				rnd_rr(&m, (enum dns_section)sec);
		/* the client asks with the same name in its own case */
		q = qname_of(&m);
		for (k = 0; k < q.len; k++)
			if (((q.data[k] | 0x20) >= 'a' && (q.data[k] | 0x20) <= 'z') && rnd() % 2)
				q.data[k] ^= 0x20;
		rc.id = (uint16_t)rnd();
		rc.rdcd = (uint16_t)(rnd() & (DNS_F_RD | DNS_F_CD));
		rc.edns = rnd() % 2;
		rc.tcp = rnd() % 4 == 0;
		rc.udp_size = sizes[rnd() % (sizeof(sizes) / sizeof(sizes[0]))];
		rc.age = rnd() % 3 ? rnd() % 500 : 0;
		{
			struct dns_reply rp = {
				.id = rc.id, .rdcd = rc.rdcd, .qname = q.data, .qlen = q.len,
				.edns = rc.edns, .edns_udp = REF_EDNS_MAX_UDP,
			};
			struct cache_hit h;

			cache_flush(c);
			time_override_set(100000);
			n = ins_resp(c, cfg, &m, 1000000, NULL, 0, 0, NULL, 0);
			CHECK_EQ(n, 0);
			time_override_advance(rc.age);
			n = cache_lookup(c, cfg, q.data, q.len, m.qtype, DNS_C_IN,
			                 cache_hash(q.data, q.len, m.qtype, DNS_C_IN), &h);
			CHECK_EQ(n, 0);
			if (!n) {
				rp.age = h.age;
				n = dns_reply_render(h.msg, h.len, &rp, rbuf,
				                     ref_limit(rc.edns, rc.tcp, rc.udp_size));
			}
		}
		nref = ref_reply(&m, q.data, q.len, rc.id, rc.rdcd, rc.edns,
		                 ref_limit(rc.edns, rc.tcp, rc.udp_size), rc.age, refbuf);
		if (n != nref || n <= 0 || memcmp(rbuf, refbuf, (size_t)n)) {
			fprintf(stderr, "  iteration %d (%d RRs, edns %d tcp %d size %u age %u):"
			        " %d vs reference %d\n", iter, m.nrr, rc.edns, rc.tcp,
			        rc.udp_size, rc.age, n, nref);
			CHECK(0);
			fails++;
		}
		dns_msg_free(&m);
	}
	cache_free(c);
	config_free(cfg);
}

/* ---- dependencies ---- */

static int ins_deps(struct cache *c, const struct config *cfg, const char *qname,
                    const char *d0, const char *d1)
{
	uint8_t d[2 * (CACHE_DEP_HDR + DNS_MAX_NAME)];
	struct dns_msg m;
	uint16_t nd = 0;
	size_t dsz = 0;
	int r;

	if (d0)
		dsz += dep(d + dsz, cfg, qname, d0), nd++;
	if (d1)
		dsz += dep(d + dsz, cfg, qname, d1), nd++;
	mkresp(&m, qname, "192.0.2.9", 300);
	r = ins_resp(c, cfg, &m, 300, d, dsz, nd, NULL, 0);
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

	/* a typical entry: CNAME + 3 A, deps on the qname and the target */
	{
		uint8_t d[2 * (CACHE_DEP_HDR + DNS_MAX_NAME)];
		size_t dsz = dep(d, cfg, "www.example.com", "www.example.com");
		struct dns_msg t;

		dsz += dep(d + dsz, cfg, "www.example.com", "cdn.example.net");
		qinit(&t, "www.example.com", DNS_T_A, DNS_F_QR | DNS_F_RA);
		add_name(&t, DNS_S_AN, "www.example.com", DNS_T_CNAME, 300, "cdn.example.net");
		add_a(&t, DNS_S_AN, "cdn.example.net", 60, "192.0.2.1");
		add_a(&t, DNS_S_AN, "cdn.example.net", 60, "192.0.2.2");
		add_a(&t, DNS_S_AN, "cdn.example.net", 60, "192.0.2.3");
		cache_flush(c);
		CHECK_EQ(ins_resp(c, cfg, &t, 60, d, dsz, 2, NULL, 0), 0);
		/* message 110 (header 12, question 21, CNAME 29, A 3 x 16), deps 35 */
		if (sizeof(void *) == 8)
			CHECK_EQ(cache_bytes(c), 48 + 110 + 35 + CACHE_ENTRY_OVERHEAD);
		dns_msg_free(&t);
	}

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
	CHECK_EQ(look(c, cfg, "c99.example", DNS_T_A, &out), 0);

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
	RUN(golden_replies);
	RUN(randomized_replies);
	RUN(deps_revalidation);
	RUN(byte_accounting);
	nsc_destroy(&nsc);
	nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
	return test_summary();
}
