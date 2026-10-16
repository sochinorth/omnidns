// SPDX-License-Identifier: MIT
#include <arpa/inet.h>
#include <fcntl.h>
#include <ftw.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/stat.h>

#include "test.h"
#include "config.h"
#include "log.h"
#include "match.h"
#include "util/hash.h"

static char dir[64];
static struct nameset_cache nsc;

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

static const char *P(const char *name)
{
	static char buf[8][256];
	static int i;

	i = (i + 1) % 8;
	snprintf(buf[i], sizeof(buf[i]), "%s/%s", dir, name);
	return buf[i];
}

#define GLOBAL "config omnidns 'main'\n\tlist listen_addr '127.0.0.1'\n" \
	"\toption fakeip_v4 '198.18.0.0/15'\n"
#define CATCHALL "config rule 'all'\n\toption action 'forward'\n" \
	"\toption upstream '%s/up1.conf'\n"

static char err[512];

static struct config *load_text(const char *text)
{
	FILE *f = fopen(P("omnitest"), "w");

	if (!f)
		abort();
	fputs(text, f);
	fclose(f);
	err[0] = 0;
	return config_load(P("omnitest"), &nsc, err, sizeof(err));
}

static struct config *loadf(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static struct config *loadf(const char *fmt, ...)
{
	char text[8192];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(text, sizeof(text), fmt, ap);
	va_end(ap);
	return load_text(text);
}

/* Expect failure with `needle` in the message. */
#define EXPECT_ERR(needle, ...) do {					\
	struct config *_c = loadf(__VA_ARGS__);				\
	CHECK(!_c);							\
	if (!strstr(err, needle)) {					\
		fprintf(stderr, "  FAIL %s:%d: error '%s' lacks '%s'\n",	\
			__FILE__, __LINE__, err, needle);		\
		test_cur_failed = 1;					\
	}								\
	config_free(_c);						\
} while (0)

static void setup_files(void)
{
	wfile("up1.conf", "# comment\nnameserver 1.1.1.1\nnameserver 2606:4700::1111\n");
	wfile("up2.conf", "nameserver 9.9.9.9#5353\n");
	wfile("up1copy.conf", "search lan\nnameserver 1.1.1.1\noptions ndots:1\n"
	      "nameserver 2606:4700::1111\n");
	wfile("empty.conf", "search lan\n");
	mkdir(P("ns"), 0755);
	mkdir(P("ns/sub.txt"), 0755);
	wfile("ns/ads1.txt", "ads.example\n*.tracker.example\n");
	wfile("ns/ads2.txt", "# list 2\nbanner.example\n");
	wfile("ns/vpn.txt", "*.netflix.com\n");
	symlink(P("ns/vpn.txt"), P("ns/vpnlink.txt"));
}

TEST(valid_roundtrip)
{
	struct config *c = loadf(
		"config omnidns 'main'\n"
		"\toption port '5300'\n"
		"\tlist listen_addr '127.0.0.1'\n"
		"\tlist listen_addr '::1'\n"
		"\toption fwmask '0x00ff0000'\n"
		"\toption fakeip_v4 '198.18.0.0/15'\n"
		"\toption fakeip_v6 '64:ff9b:1::/48'\n"
		"\toption fakeip_grace '120'\n"
		"\toption cache_size '500'\n"
		"\toption block_mode 'nxdomain'\n"
		"\toption block_ttl '60'\n"
		"\toption upstream_timeout '1000'\n"
		"\toption log_level 'debug'\n"
		"config rule 'ads'\n"
		"\toption action 'block'\n"
		"\tlist nameset '%s/ns/ads*.txt'\n"
		"\tlist nameset '%s/ns/ads1.txt'\n"
		"\tlist nameset '%s/ns/sub*'\n"
		"config rule 'vpn'\n"
		"\toption action 'fakeip'\n"
		"\toption upstream '%s/up2.conf'\n"
		"\toption fwmark '0x2'\n"
		"\tlist nameset '%s/ns/vpn.txt'\n"
		"\tlist nameset '%s/ns/vpnlink.txt'\n"
		"config rule 'nothing'\n"
		"\toption action 'forward'\n"
		"\toption upstream '%s/up1.conf'\n"
		"\tlist nameset '%s/ns/none-*.txt'\n"
		CATCHALL, dir, dir, dir, dir, dir, dir, dir, dir, dir);

	if (!c)
		fprintf(stderr, "  err: %s\n", err);
	REQUIRE(c);
	CHECK_EQ(c->port, 5300);
	CHECK_EQ(c->nlisten, 2);
	CHECK_EQ(c->listen[0].ss_family, AF_INET);
	CHECK_EQ(ntohs(((struct sockaddr_in *)&c->listen[0])->sin_port), 5300);
	CHECK_EQ(c->listen[1].ss_family, AF_INET6);
	CHECK_EQ(c->fwmask, 0x00ff0000);
	CHECK(c->has_pool4 && c->has_pool6);
	CHECK_EQ(c->pool4.plen, 15);
	CHECK_EQ(c->pool6.plen, 48);
	CHECK_EQ(c->fakeip_grace, 120);
	CHECK_EQ(c->fakeip_max_bindings, 65536);
	CHECK_EQ(c->cache_size, 500);
	CHECK_EQ(c->cache_max_bytes, 16u << 20);
	CHECK_EQ(c->neg_ttl_max, 3600);
	CHECK_EQ(c->block_mode, BLOCK_NXDOMAIN);
	CHECK_EQ(c->block_ttl, 60);
	CHECK_EQ(c->upstream_timeout_ms, 1000);
	CHECK_EQ(c->upstream_total_timeout_ms, 5000);
	CHECK_EQ(c->max_pending, 1024);
	CHECK_EQ(c->log_level, LOG_DEBUG);
	REQUIRE(c->nrules == 4);
	CHECK_STR(c->rules[0].id, "ads");
	CHECK_EQ(c->rules[0].action, RULE_BLOCK);
	CHECK(!c->rules[0].up);
	CHECK_EQ(c->rules[0].nfiles, 2);	/* ads1 de-duplicated, dir skipped */
	CHECK_STR(c->rules[1].id, "vpn");
	CHECK_EQ(c->rules[1].ord, 1);
	CHECK_EQ(c->rules[1].action, RULE_FAKEIP);
	CHECK_EQ(c->rules[1].mark, 0x00020000);
	CHECK_EQ(c->rules[1].nfiles, 1);	/* symlink de-duplicated */
	REQUIRE(c->rules[1].up);
	CHECK_EQ(c->rules[1].up->n, 1);
	CHECK_EQ(ntohs(((struct sockaddr_in *)&c->rules[1].up->srv[0].sa)->sin_port), 5353);
	CHECK_EQ(c->rules[2].nfiles, 0);
	CHECK(!c->rules[2].catchall);
	CHECK(c->rules[3].catchall);
	CHECK_EQ(c->rules[3].up->n, 2);
	CHECK(c->rules[3].up == c->rules[2].up);	/* shared by path */
	CHECK(c->rules[0].fingerprint != c->rules[1].fingerprint);
	REQUIRE(c->idx);
	CHECK_EQ(match_lookup(c->idx, "ads.example", 11), 0);
	CHECK_EQ(match_lookup(c->idx, "x.tracker.example", 17), 0);
	CHECK_EQ(match_lookup(c->idx, "www.netflix.com", 15), 1);
	CHECK_EQ(match_lookup(c->idx, "x.ads.example", 13), 3);
	config_free(c);
}

TEST(validation_errors)
{
	EXPECT_ERR("cannot load", "x");
	EXPECT_ERR("missing 'config omnidns'", CATCHALL, dir);
	EXPECT_ERR("multiple 'omnidns'", GLOBAL "config omnidns 'other'\n" CATCHALL, dir);
	EXPECT_ERR("listen_addr is required", "config omnidns 'm'\n" CATCHALL, dir);
	EXPECT_ERR("invalid listen_addr 'lan'",
	           "config omnidns 'm'\n\tlist listen_addr 'lan'\n" CATCHALL, dir);
	EXPECT_ERR("duplicate listen_addr", "config omnidns 'm'\n\tlist listen_addr '::1'\n"
	           "\tlist listen_addr '::1'\n" CATCHALL, dir);
	EXPECT_ERR("invalid port", GLOBAL "\toption port '70000'\n" CATCHALL, dir);
	EXPECT_ERR("invalid port", GLOBAL "\toption port '0'\n" CATCHALL, dir);
	EXPECT_ERR("'fwmask'", GLOBAL "\toption fwmask '0'\n" CATCHALL, dir);
	EXPECT_ERR("'cache_size'", GLOBAL "\toption cache_size 'lots'\n" CATCHALL, dir);
	EXPECT_ERR("'block_ttl'", GLOBAL "\toption block_ttl '-1'\n" CATCHALL, dir);
	EXPECT_ERR("must not be a list", GLOBAL "\tlist cache_size '1'\n" CATCHALL, dir);
	EXPECT_ERR("block_mode", GLOBAL "\toption block_mode 'drop'\n" CATCHALL, dir);
	EXPECT_ERR("log_level", GLOBAL "\toption log_level 'loud'\n" CATCHALL, dir);
	EXPECT_ERR("upstream_total_timeout", GLOBAL "\toption upstream_timeout '6000'\n"
	           CATCHALL, dir);
	EXPECT_ERR("max_pending_per_client", GLOBAL "\toption max_pending '10'\n"
	           CATCHALL, dir);
	/* pools */
	EXPECT_ERR("prefix length", GLOBAL "\toption fakeip_v4 '198.18.0.0/31'\n" CATCHALL, dir);
	EXPECT_ERR("prefix length", GLOBAL "\toption fakeip_v4 '10.0.0.0/7'\n" CATCHALL, dir);
	EXPECT_ERR("prefix length", GLOBAL "\toption fakeip_v6 'fd00::/121'\n" CATCHALL, dir);
	EXPECT_ERR("prefix length", GLOBAL "\toption fakeip_v6 'fd00::/31'\n" CATCHALL, dir);
	EXPECT_ERR("invalid prefix", GLOBAL "\toption fakeip_v4 '198.18.0.1/15'\n" CATCHALL, dir);
	EXPECT_ERR("invalid prefix", GLOBAL "\toption fakeip_v4 'fd00::/48'\n" CATCHALL, dir);
	EXPECT_ERR("invalid prefix", GLOBAL "\toption fakeip_v6 '10.0.0.0/8'\n" CATCHALL, dir);
	EXPECT_ERR("invalid prefix", GLOBAL "\toption fakeip_v6 'fd00::'\n" CATCHALL, dir);
	EXPECT_ERR("reserved 127.0.0.0/8", GLOBAL "\toption fakeip_v4 '127.16.0.0/12'\n"
	           CATCHALL, dir);
	EXPECT_ERR("reserved 0.0.0.0/8", GLOBAL "\toption fakeip_v4 '0.0.0.0/16'\n" CATCHALL, dir);
	EXPECT_ERR("reserved 224.0.0.0/3", GLOBAL "\toption fakeip_v4 '240.0.0.0/8'\n"
	           CATCHALL, dir);
	EXPECT_ERR("reserved ::ffff:0:0/96", GLOBAL "\toption fakeip_v6 '::ffff:0:0/96'\n"
	           CATCHALL, dir);
	EXPECT_ERR("reserved ff00::/8", GLOBAL "\toption fakeip_v6 'ff02::/32'\n" CATCHALL, dir);
	EXPECT_ERR("reserved ::/128", GLOBAL "\toption fakeip_v6 '::/32'\n" CATCHALL, dir);
	/* rules */
	EXPECT_ERR("anonymous", GLOBAL "config rule\n\toption action 'block'\n" CATCHALL, dir);
	EXPECT_ERR("rule 'r': missing option 'action'",
	           GLOBAL "config rule 'r'\n\tlist nameset '/x'\n" CATCHALL, dir);
	EXPECT_ERR("rule 'r': invalid action 'drop'",
	           GLOBAL "config rule 'r'\n\toption action 'drop'\n" CATCHALL, dir);
	EXPECT_ERR("rule 'r': missing option 'upstream'",
	           GLOBAL "config rule 'r'\n\toption action 'forward'\n\tlist nameset '/x'\n"
	           CATCHALL, dir);
	EXPECT_ERR("rule 'r': upstream file",
	           GLOBAL "config rule 'r'\n\toption action 'forward'\n"
	           "\toption upstream '%s/nope.conf'\n\tlist nameset '/x'\n" CATCHALL, dir, dir);
	EXPECT_ERR("no usable nameserver",
	           GLOBAL "config rule 'r'\n\toption action 'forward'\n"
	           "\toption upstream '%s/empty.conf'\n\tlist nameset '/x'\n" CATCHALL, dir, dir);
	EXPECT_ERR("rule 'r': fakeip requires fakeip_v4",
	           "config omnidns 'm'\n\tlist listen_addr '127.0.0.1'\n"
	           "config rule 'r'\n\toption action 'fakeip'\n\toption fwmark '1'\n"
	           "\toption upstream '%s/up1.conf'\n\tlist nameset '/x'\n" CATCHALL, dir, dir);
	EXPECT_ERR("rule 'r': fakeip requires option 'fwmark'",
	           GLOBAL "config rule 'r'\n\toption action 'fakeip'\n"
	           "\toption upstream '%s/up1.conf'\n\tlist nameset '/x'\n" CATCHALL, dir, dir);
	EXPECT_ERR("rule 'r': fwmark '0' must be non-zero",
	           GLOBAL "config rule 'r'\n\toption action 'fakeip'\n\toption fwmark '0'\n"
	           "\toption upstream '%s/up1.conf'\n\tlist nameset '/x'\n" CATCHALL, dir, dir);
	EXPECT_ERR("rule 'r': fwmark '0x100'",
	           GLOBAL "config rule 'r'\n\toption action 'fakeip'\n\toption fwmark '0x100'\n"
	           "\toption upstream '%s/up1.conf'\n\tlist nameset '/x'\n" CATCHALL, dir, dir);
	EXPECT_ERR("rule 'r': invalid fwmark",
	           GLOBAL "config rule 'r'\n\toption action 'fakeip'\n\toption fwmark 'red'\n"
	           "\toption upstream '%s/up1.conf'\n\tlist nameset '/x'\n" CATCHALL, dir, dir);
	EXPECT_ERR("no catchall", GLOBAL);
	EXPECT_ERR("no catchall", GLOBAL "config rule 'r'\n\toption action 'block'\n"
	           "\tlist nameset '/x'\n");
	EXPECT_ERR("catchall rule 'all' (no nameset) must be the last rule",
	           GLOBAL CATCHALL "config rule 'r'\n\toption action 'block'\n"
	           "\tlist nameset '/x'\n", dir);
	EXPECT_ERR("must be the last rule", GLOBAL CATCHALL
	           "config rule 'b'\n\toption action 'block'\n", dir);
}

TEST(too_many_rules)
{
	size_t cap = 200000, o = 0;
	char *t = malloc(cap);
	struct config *c;

	o += (size_t)snprintf(t + o, cap - o, GLOBAL);
	for (int i = 0; i < CONFIG_MAX_RULES; i++)
		o += (size_t)snprintf(t + o, cap - o, "config rule 'r%d'\n"
		                      "\toption action 'block'\n\tlist nameset '/x'\n", i);
	o += (size_t)snprintf(t + o, cap - o, CATCHALL, dir);
	c = load_text(t);
	CHECK(!c);
	CHECK(strstr(err, "too many rules") != NULL);
	free(t);
}

TEST(nsc_reuse)
{
	struct nameset_file *a, *b, *c2;
	struct timespec ts[2];
	struct config *c1, *c3;
	int e = 0;

	wfile("ns/r.txt", "a.example\n");
	a = nsc_get(&nsc, P("ns/r.txt"), &e);
	REQUIRE(a);
	CHECK_EQ(a->npat, 1);
	b = nsc_get(&nsc, P("ns/r.txt"), &e);
	CHECK(a == b);
	CHECK_EQ(a->refcnt, 2);
	nsc_put(b);

	/* same size, different content, bump mtime */
	wfile("ns/r.txt", "b.example\n");
	clock_gettime(CLOCK_REALTIME, &ts[0]);
	ts[0].tv_sec += 10;
	ts[1] = ts[0];
	CHECK(!utimensat(AT_FDCWD, P("ns/r.txt"), ts, 0));
	c2 = nsc_get(&nsc, P("ns/r.txt"), &e);
	REQUIRE(c2);
	CHECK(c2 != a);
	REQUIRE(c2->blob && a->blob);
	CHECK_STR(c2->blob, "b.example");
	CHECK_EQ(c2->blob_len, 10);
	CHECK_STR(a->blob, "a.example");	/* old still alive and intact */
	CHECK_EQ(a->blob_len, 10);
	b = nsc_get(&nsc, P("ns/r.txt"), &e);
	CHECK(b == c2);
	nsc_put(b);
	nsc_put(a);
	nsc_sweep(&nsc);			/* frees stale a */
	nsc_put(c2);

	CHECK(!nsc_get(&nsc, P("ns/missing.txt"), &e));
	CHECK_EQ(e, -ENOENT);

	/* through config_load: unchanged files are shared between configs */
	c1 = loadf(GLOBAL "config rule 'r'\n\toption action 'block'\n"
	           "\tlist nameset '%s/ns/r.txt'\n" CATCHALL, dir, dir);
	REQUIRE(c1);
	c3 = loadf(GLOBAL "config rule 'r'\n\toption action 'block'\n"
	           "\tlist nameset '%s/ns/r.txt'\n" CATCHALL, dir, dir);
	REQUIRE(c3);
	CHECK(c1->rules[0].files[0] == c3->rules[0].files[0]);
	CHECK_EQ(c1->rules[0].fingerprint, c3->rules[0].fingerprint);
	config_free(c1);
	config_free(c3);
	nsc_sweep(&nsc);
	CHECK_EQ(hmap_len(&nsc.by_path), 0);
}

TEST(unreadable_nameset)
{
	struct config *c;

	if (!geteuid()) {
		fprintf(stderr, "  (root: skipping)\n");
		return;
	}
	wfile("ns/secret.txt", "s.example\n");
	chmod(P("ns/secret.txt"), 0);
	c = loadf(GLOBAL "config rule 'r'\n\toption action 'block'\n"
	          "\tlist nameset '%s/ns/secret.txt'\n\tlist nameset '%s/ns/ads2.txt'\n"
	          CATCHALL, dir, dir, dir);
	REQUIRE(c);
	CHECK_EQ(c->rules[0].nfiles, 1);
	config_free(c);
	chmod(P("ns/secret.txt"), 0644);
}

TEST(fingerprints)
{
	struct config *a, *b, *c, *d;
#define fmt GLOBAL "config rule 'r'\n\toption action 'fakeip'\n"		\
	"\toption fwmark '1'\n\toption upstream '%s/%s'\n\tlist nameset '/x'\n" \
	"config rule 'b'\n\toption action 'block'\n\tlist nameset '/x'\n" CATCHALL

	a = loadf(fmt, dir, "up1.conf", dir);
	b = loadf(fmt, dir, "up1copy.conf", dir);
	wfile("up3.conf", "nameserver 1.1.1.1\nnameserver 2606:4700::1111#54\n");
	c = loadf(fmt, dir, "up3.conf", dir);
	REQUIRE(a && b && c);
	CHECK_EQ(a->rules[0].up->id, b->rules[0].up->id);
	CHECK_EQ(a->rules[0].fingerprint, b->rules[0].fingerprint);
	CHECK(a->rules[0].fingerprint != c->rules[0].fingerprint);
	CHECK_EQ(a->rules[1].fingerprint, c->rules[1].fingerprint);
	CHECK_EQ(a->rules[2].fingerprint, b->rules[2].fingerprint);

	/* block_mode affects block rules only */
	d = loadf(GLOBAL "\toption block_mode 'null'\n"
	          "config rule 'r'\n\toption action 'fakeip'\n"
	          "\toption fwmark '1'\n\toption upstream '%s/%s'\n\tlist nameset '/x'\n"
	          "config rule 'b'\n\toption action 'block'\n\tlist nameset '/x'\n" CATCHALL,
	          dir, "up1.conf", dir);
	REQUIRE(d);
	CHECK_EQ(a->rules[0].fingerprint, d->rules[0].fingerprint);
	CHECK(a->rules[1].fingerprint != d->rules[1].fingerprint);
	config_free(d);

	/* two fakeip rules may share a mark */
	d = loadf(GLOBAL "config rule 'r'\n\toption action 'fakeip'\n"
	          "\toption fwmark '1'\n\toption upstream '%s/up1.conf'\n\tlist nameset '/x'\n"
	          "config rule 's'\n\toption action 'fakeip'\n"
	          "\toption fwmark '1'\n\toption upstream '%s/up2.conf'\n\tlist nameset '/y'\n"
	          CATCHALL, dir, dir, dir);
	REQUIRE(d);
	CHECK_EQ(d->rules[0].mark, d->rules[1].mark);
	CHECK(d->rules[0].fingerprint != d->rules[1].fingerprint);
	config_free(d);

	/* upstream content change under the same path */
	wfile("up3.conf", "nameserver 1.1.1.2\n");
	d = loadf(fmt, dir, "up3.conf", dir);
	REQUIRE(d);
	CHECK(c->rules[0].fingerprint != d->rules[0].fingerprint);
	config_free(a);
	config_free(b);
	config_free(c);
	config_free(d);
#undef fmt
}

static int rc(const char *text, struct upstream_server *out, int max, int *skipped)
{
	return resolvconf_parse(text, strlen(text), out, max, skipped);
}

TEST(resolvconf)
{
	struct upstream_server s[UPSTREAM_MAX_SERVERS + 4];
	struct sockaddr_in6 *s6;
	char text[2048];
	int sk, n, o = 0;

	n = rc("nameserver 1.2.3.4\r\n  nameserver\t127.0.0.1#5335  # dnsmasq\n"
	       "; nameserver 5.5.5.5\n# nameserver 6.6.6.6\nsearch lan\n"
	       "nameserver fe80::1%lo\nnameserver fe80::2%7#1053\n"
	       "nameserver 1.2.3.4#53\nnameserver ::1\n", s, 8, &sk);
	CHECK_EQ(n, 5);
	CHECK_EQ(sk, 0);
	CHECK_EQ(ntohs(((struct sockaddr_in *)&s[0].sa)->sin_port), 53);
	CHECK_EQ(ntohs(((struct sockaddr_in *)&s[1].sa)->sin_port), 5335);
	CHECK_EQ(s[1].salen, sizeof(struct sockaddr_in));
	s6 = (struct sockaddr_in6 *)&s[2].sa;
	CHECK_EQ(s6->sin6_family, AF_INET6);
	CHECK_EQ(s6->sin6_scope_id, if_nametoindex("lo"));
	CHECK(s6->sin6_scope_id != 0);
	s6 = (struct sockaddr_in6 *)&s[3].sa;
	CHECK_EQ(s6->sin6_scope_id, 7);
	CHECK_EQ(ntohs(s6->sin6_port), 1053);
	CHECK_EQ(s[4].salen, sizeof(struct sockaddr_in6));

	n = rc("nameserver example.com\nnameserver 1.2.3.4#\nnameserver 1.2.3.4#0\n"
	       "nameserver 1.2.3.4#65536\nnameserver 1.2.3.4%lo\nnameserver fe80::1%nosuchif0\n"
	       "nameserver 1.2.3\nnameserver ::1#x\nnameservers 1.1.1.1\nnameserver\n"
	       "nameserver 1.2.3.4#-1\n", s, 8, &sk);
	CHECK_EQ(n, 0);
	CHECK_EQ(sk, 9);

	for (int i = 0; i < 12; i++)
		o += sprintf(text + o, "nameserver 10.0.0.%d\n", i + 1);
	n = rc(text, s, UPSTREAM_MAX_SERVERS + 4, &sk);
	CHECK_EQ(n, UPSTREAM_MAX_SERVERS);
	CHECK_EQ(((uint8_t *)&((struct sockaddr_in *)&s[7].sa)->sin_addr)[3], 8);
	n = rc(text, s, 3, NULL);
	CHECK_EQ(n, 3);
	CHECK_EQ(rc("", s, 8, &sk), 0);
}

/* Parsed blob of one nameset text: owns the result between calls. */
static struct nameset_file nsr;

static uint32_t ns_win(const char *text, size_t len, size_t window, uint32_t *inval)
{
	free(nsr.blob);
	memset(&nsr, 0, sizeof(nsr));
	nsr.npat = 99;
	CHECK_EQ(nameset_parse(text, len, window, &nsr, inval, "test"), 0);
	return nsr.npat;
}

static uint32_t ns(const char *text, uint32_t *inval)
{
	return ns_win(text, strlen(text), 0, inval);
}

/* i-th entry of nsr.blob */
static const char *ent(uint32_t i)
{
	const char *e = nsr.blob;

	while (i--)
		e = ns_next(e);
	return e;
}

TEST(nameset_edge)
{
	uint32_t n, inval;
	char l63[128], l64[128], big[600];

	n = ns("# header\r\n\r\n  Example.COM \r\n*.Ads.Net\t# trailing\n"
	       "foo.bar#baz\n*.\n*\n*.*.x\ntrailing.dot.\n.leading\na..b\n"
	       "a b\nunder_score-ok.x\n#comment\n   # indented comment\n1.2.3.4\n"
	       "last.line", &inval);
	REQUIRE(n == 5);
	CHECK_EQ(inval, 8);
	CHECK_STR(ent(0), "example.com");
	CHECK(!ns_is_suffix(ent(0)));
	CHECK_STR(ent(1), "*.ads.net");
	CHECK(ns_is_suffix(ent(1)));
	CHECK_STR(ns_name(ent(1)), "ads.net");
	CHECK_STR(ent(2), "under_score-ok.x");
	CHECK_STR(ent(3), "1.2.3.4");
	CHECK_STR(ent(4), "last.line");	/* no trailing newline */
	CHECK_EQ(nsr.blob_len, 12 + 10 + 17 + 8 + 10);	/* exact size */
	CHECK(ns_next(ent(4)) == nsr.blob + nsr.blob_len);

	memset(l63, 'a', 63);
	strcpy(l63 + 63, ".com\n");
	memset(l64, 'a', 64);
	strcpy(l64 + 64, ".com\n");
	n = ns(l63, &inval);
	CHECK_EQ(n, 1);
	n = ns(l64, &inval);
	CHECK_EQ(n, 0);
	CHECK_EQ(inval, 1);

	/* 253 chars ok, 255 not; 127 labels ok */
	for (int i = 0; i < 4; i++) {
		memset(big + i * 64, 'b', 63);
		big[i * 64 + 63] = '.';
	}
	big[253] = 0;
	CHECK_EQ(ns(big, &inval), 1);
	CHECK_EQ(strlen(ent(0)), 253);
	big[253] = 'b';
	big[254] = 'b';
	big[255] = 0;
	CHECK_EQ(ns(big, &inval), 0);
	for (int i = 0; i < 127; i++) {
		big[i * 2] = 'x';
		big[i * 2 + 1] = '.';
	}
	big[253] = 0;
	CHECK_EQ(ns(big, &inval), 1);
	/* "*." + 253 chars ok */
	memmove(big + 2, big, 254);
	big[0] = '*';
	big[1] = '.';
	CHECK_EQ(ns(big, &inval), 1);
	CHECK(ns_is_suffix(ent(0)));
	CHECK_EQ(nsr.blob_len, 256);

	CHECK_EQ(ns("", &inval), 0);
	CHECK(nsr.blob == NULL);
	CHECK_EQ(nsr.blob_len, 0);
	CHECK_EQ(ns("# only\n  # comments\n\n\r\n", &inval), 0);
	CHECK_EQ(inval, 0);
	CHECK(nsr.blob == NULL);
	CHECK_EQ(ns("*.x\n*.x\n", &inval), 2);	/* dups are kept */
	CHECK_EQ(ns("A.B\r\n*.C.D\r\nE\r", &inval), 3);	/* CRLF, lowercased */
	CHECK_STR(ent(0), "a.b");
	CHECK_STR(ent(1), "*.c.d");
	CHECK_STR(ent(2), "e");
	CHECK_EQ(nsr.blob_len, 4 + 6 + 2);
	/* order kept around invalid / comment / blank lines */
	CHECK_EQ(ns("bad!\none\n\n#c\ntwo  # c\n-x-..\n*.three\nb@d\nfour", &inval), 4);
	CHECK_EQ(inval, 3);
	CHECK_STR(ent(0), "one");
	CHECK_STR(ent(1), "two");
	CHECK_STR(ent(2), "*.three");
	CHECK_STR(ent(3), "four");
}

/* Lines longer than the window are invalid (comments: ignored) and skipped
 * without disturbing the following lines or their numbering. */
TEST(nameset_long_lines)
{
	size_t cap = 3 * NAMESET_WINDOW, o = 0;
	char *t = malloc(cap);
	uint32_t inval;

	REQUIRE(t);
	o += (size_t)sprintf(t + o, "first.x\n");
	memset(t + o, 'a', NAMESET_WINDOW + 100);	/* spans two windows */
	o += NAMESET_WINDOW + 100;
	o += (size_t)sprintf(t + o, "\nsecond.x\n# ");
	memset(t + o, 'c', 200);
	o += 200;
	o += (size_t)sprintf(t + o, "\nthird.x");
	CHECK_EQ(ns_win(t, o, 0, &inval), 3);
	CHECK_EQ(inval, 1);
	CHECK_STR(ent(1), "second.x");
	CHECK_STR(ent(2), "third.x");
	/* small window: the comment line is ignored, the name lines fit */
	CHECK_EQ(ns_win(t, o, 128, &inval), 3);
	CHECK_EQ(inval, 1);
	CHECK_STR(ent(2), "third.x");
	/* long line running into EOF, and one exactly filling the last window */
	CHECK_EQ(ns_win("ok\nxxxxxxxxxxxxxxxxxxxx", 23, 8, &inval), 1);
	CHECK_EQ(inval, 1);
	CHECK_EQ(ns_win("ok\nabc.def", 10, 7, &inval), 2);
	CHECK_EQ(inval, 0);
	CHECK_STR(ent(1), "abc.def");
	CHECK_EQ(ns_win("abc.def", 7, 7, &inval), 1);
	/* a blank (whitespace-only) line filling the window is just blank */
	CHECK_EQ(ns_win("        \nfoo.com\n", 17, 8, &inval), 1);
	CHECK_EQ(inval, 0);
	CHECK_STR(ent(0), "foo.com");
	CHECK_EQ(ns_win(" \t\r     \r\nfoo.com", 17, 8, &inval), 1);
	CHECK_EQ(inval, 0);
	free(t);
}

/* Window boundaries anywhere must not change the result for lines that fit
 * in a window. */
static void check_windows(const char *text, size_t minwin)
{
	size_t len = strlen(text);
	uint32_t n0, inval0, inval;
	char *blob0;
	uint32_t len0;
	int bad = 0;

	n0 = ns_win(text, len, len + 1, &inval0);	/* single pass */
	blob0 = nsr.blob;
	len0 = nsr.blob_len;
	nsr.blob = NULL;
	for (size_t w = minwin; w <= len + 2; w++) {
		bool same = ns_win(text, len, w, &inval) == n0 && inval == inval0 &&
		            nsr.blob_len == len0 &&
		            (!len0 || !memcmp(nsr.blob, blob0, len0));

		if (!same && bad++ < 3)
			fprintf(stderr, "  window %zu differs\n", w);
	}
	CHECK_EQ(ns_win(text, len, 0, &inval), n0);
	CHECK_EQ(inval, inval0);
	CHECK_EQ(nsr.blob_len, len0);
	CHECK(!len0 || !memcmp(nsr.blob, blob0, len0));
	CHECK_EQ(bad, 0);
	free(blob0);
}

TEST(nameset_windows)
{
	/* every line (with its newline) fits in 7 bytes */
	check_windows("a.b\n*.cd\n#x\n\nA.B\r\nbad!\n x \n*.\n-\nq.r#\nz", 7);
	/* realistic lines up to 80 bytes */
	check_windows("# Header comment line for a block list, 2026\r\n"
	              "\n"
	              "ads.example.com\n"
	              "*.Tracker.Example.NET   # trailing comment here\n"
	              "  indented.example.org\t\n"
	              "not valid.example\n"
	              "*.cdn-1.example_2.io\r\n"
	              "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com\n"
	              "trailing.dot.\n"
	              "#*.commented.out\n"
	              "x\n"
	              "1.2.3.4\n"
	              "*.last.example", 81);
}

TEST(prefix_mark)
{
	struct ip_prefix p;
	uint8_t a4[4] = { 198, 19, 255, 1 }, b4[4] = { 198, 20, 0, 0 }, a6[16] = { 0 };

	CHECK_EQ(config_mark_shift(1, 0xff000000), 0x01000000);
	CHECK_EQ(config_mark_shift(0xff, 0xff000000), 0xff000000);
	CHECK_EQ(config_mark_shift(0x100, 0xff000000), 0);
	CHECK_EQ(config_mark_shift(0, 0xff000000), 0);
	CHECK_EQ(config_mark_shift(1, 0), 0);
	CHECK_EQ(config_mark_shift(3, 0x1), 0);
	CHECK_EQ(config_mark_shift(5, 0x0000ff00), 0x500);

	CHECK_EQ(ip_prefix_parse("198.18.0.0/15", &p), 0);
	CHECK_EQ(p.family, AF_INET);
	CHECK(ip_prefix_contains(&p, AF_INET, a4));
	CHECK(!ip_prefix_contains(&p, AF_INET, b4));
	CHECK(!ip_prefix_contains(&p, AF_INET6, a4));
	CHECK_EQ(ip_prefix_parse("0.0.0.0/0", &p), 0);
	CHECK(ip_prefix_contains(&p, AF_INET, b4));
	CHECK_EQ(ip_prefix_parse("64:ff9b:1::/48", &p), 0);
	CHECK_EQ(p.family, AF_INET6);
	a6[0] = 0; a6[1] = 0x64; a6[2] = 0xff; a6[3] = 0x9b; a6[5] = 1; a6[15] = 7;
	CHECK(ip_prefix_contains(&p, AF_INET6, a6));
	a6[5] = 2;
	CHECK(!ip_prefix_contains(&p, AF_INET6, a6));
	CHECK_EQ(ip_prefix_parse("10.0.0.0/33", &p), -EINVAL);
	CHECK_EQ(ip_prefix_parse("10.0.0.0", &p), -EINVAL);
	CHECK_EQ(ip_prefix_parse("10.0.0.0/", &p), -EINVAL);
	CHECK_EQ(ip_prefix_parse("10.0.0.0/+8", &p), -EINVAL);
	CHECK_EQ(ip_prefix_parse("10.0.0.1/8", &p), -EINVAL);
	CHECK_EQ(ip_prefix_parse("::/129", &p), -EINVAL);
}

TEST(upstream_load)
{
	struct upstream_set *u, *v;
	char e[256];

	u = upstream_set_load(P("up1.conf"), e, sizeof(e));
	REQUIRE(u);
	CHECK_EQ(u->n, 2);
	CHECK_EQ(u->refcnt, 1);
	v = upstream_set_load(P("up1copy.conf"), e, sizeof(e));
	REQUIRE(v);
	CHECK_EQ(u->id, v->id);
	CHECK(upstream_set_get(u) == u);
	CHECK_EQ(u->refcnt, 2);
	upstream_set_put(u);
	upstream_set_put(u);
	upstream_set_put(v);
	CHECK(!upstream_set_load(P("nope.conf"), e, sizeof(e)));
	CHECK(strstr(e, "nope.conf") != NULL);
	CHECK(!upstream_set_load(P("empty.conf"), e, sizeof(e)));
	CHECK(!upstream_set_load(dir, e, sizeof(e)));
}

static int rm_cb(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
	return remove(path);
}

int main(void)
{
	hash_init();
	log_init("test", true, getenv("TEST_VERBOSE") ? LOG_DEBUG : LOG_CRIT);
	strcpy(dir, "/tmp/omnicfg.XXXXXX");
	if (!mkdtemp(dir))
		return 1;
	nsc_init(&nsc);
	setup_files();
	RUN(valid_roundtrip);
	RUN(validation_errors);
	RUN(too_many_rules);
	RUN(nsc_reuse);
	RUN(unreadable_nameset);
	RUN(fingerprints);
	RUN(resolvconf);
	RUN(nameset_edge);
	RUN(nameset_long_lines);
	RUN(nameset_windows);
	RUN(prefix_mark);
	RUN(upstream_load);
	free(nsr.blob);
	nsc_sweep(&nsc);
	CHECK_EQ(hmap_len(&nsc.by_path), 0);
	nsc_destroy(&nsc);
	nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
	return test_summary();
}
