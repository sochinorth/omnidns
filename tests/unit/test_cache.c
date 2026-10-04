// SPDX-License-Identifier: GPL-2.0-only
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
	RUN(basic);
	RUN(limits_e2big);
	RUN(revalidation);
	RUN(binding_refs);
	RUN(byte_limit);
	nsc_destroy(&nsc);
	nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
	return test_summary();
}
