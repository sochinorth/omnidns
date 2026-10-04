// SPDX-License-Identifier: MIT
#include <time.h>

#include "test.h"
#include "config.h"
#include "dns/wire.h"
#include "log.h"
#include "match.h"
#include "util/hash.h"

static struct nameset_file *mkfile(const char *text)
{
	struct nameset_file *f = calloc(1, sizeof(*f));
	uint32_t inval;

	arena_init(&f->arena, 0);
	if (nameset_parse(text, strlen(text), &f->arena, &f->pat, &f->npat, &inval, "mem"))
		abort();
	f->refcnt = 1;
	return f;
}

static void freefile(struct nameset_file *f)
{
	arena_free(&f->arena);
	free(f);
}

struct ruleset {
	struct rule r[64];
	struct nameset_file *f[64];
	uint16_t n;
};

/* text == NULL: catchall */
static void add_rule(struct ruleset *rs, const char *text)
{
	struct rule *r = &rs->r[rs->n];

	memset(r, 0, sizeof(*r));
	r->ord = rs->n;
	if (text) {
		rs->f[rs->n] = mkfile(text);
		r->files = &rs->f[rs->n];
		r->nfiles = 1;
	} else {
		rs->f[rs->n] = NULL;
		r->catchall = true;
	}
	rs->n++;
}

static void free_rules(struct ruleset *rs)
{
	for (uint16_t i = 0; i < rs->n; i++)
		if (rs->f[i])
			freefile(rs->f[i]);
	rs->n = 0;
}

static uint16_t look(const struct match_index *idx, const char *name)
{
	return match_lookup(idx, name, strlen(name));
}

TEST(ordinals)
{
	struct ruleset rs = { .n = 0 };
	struct match_index *idx;

	add_rule(&rs, "*.com\n");			/* 0 */
	add_rule(&rs, "www.google.com\n*.ads.net\n");	/* 1 */
	add_rule(&rs, "ads.net\nx.ads.net\n*.y.ads.net\n");	/* 2 */
	add_rule(&rs, "foo.org\n*.bar.org\n");		/* 3 */
	add_rule(&rs, "*.foo.org\nbar.org\n");		/* 4 */
	add_rule(&rs, NULL);				/* 5 */
	idx = match_build(rs.r, rs.n);
	REQUIRE(idx);

	/* earlier rule wins regardless of specificity */
	CHECK_EQ(look(idx, "www.google.com"), 0);
	CHECK_EQ(look(idx, "com"), 0);
	/* apex inclusion of *.x */
	CHECK_EQ(look(idx, "ads.net"), 1);
	CHECK_EQ(look(idx, "x.ads.net"), 1);
	CHECK_EQ(look(idx, "a.y.ads.net"), 1);
	/* exact at full name only; suffix at ancestors */
	CHECK_EQ(look(idx, "foo.org"), 3);
	CHECK_EQ(look(idx, "a.foo.org"), 4);
	CHECK_EQ(look(idx, "bar.org"), 3);
	CHECK_EQ(look(idx, "z.bar.org"), 3);
	/* catchall fallback, root */
	CHECK_EQ(look(idx, "org"), 5);
	CHECK_EQ(look(idx, "example.net"), 5);
	CHECK_EQ(look(idx, ""), 5);
	CHECK_EQ(look(idx, "oogle.com.x"), 5);
	/* escaped bytes still match by ancestor suffix */
	CHECK_EQ(look(idx, "a\\046b.bar.org"), 3);
	CHECK_EQ(match_nodes(idx), 7);
	match_free(idx);
	free_rules(&rs);
}

TEST(exact_vs_suffix_same_node)
{
	struct ruleset rs = { .n = 0 };
	struct match_index *idx;

	add_rule(&rs, "a.example\n");
	add_rule(&rs, "*.a.example\n");
	add_rule(&rs, "*.example\n");
	idx = match_build(rs.r, rs.n);
	REQUIRE(idx);
	CHECK_EQ(look(idx, "a.example"), 0);
	CHECK_EQ(look(idx, "b.a.example"), 1);
	CHECK_EQ(look(idx, "example"), 2);
	CHECK_EQ(look(idx, "c.example"), 2);
	CHECK_EQ(look(idx, "net"), MATCH_NONE);		/* no catchall */
	CHECK_EQ(look(idx, ""), MATCH_NONE);
	match_free(idx);
	free_rules(&rs);
}

TEST(wire_lookup)
{
	struct ruleset rs = { .n = 0 };
	struct match_index *idx;
	struct dns_name n;

	add_rule(&rs, "*.Example.COM\n");
	add_rule(&rs, NULL);
	idx = match_build(rs.r, rs.n);
	REQUIRE(idx);
	REQUIRE(!dns_name_from_text(&n, "WWW.example.Com."));
	CHECK_EQ(match_lookup_wire(idx, n.data, n.len), 0);
	REQUIRE(!dns_name_from_text(&n, "a\\.b.example.com"));
	CHECK_EQ(match_lookup_wire(idx, n.data, n.len), 0);
	REQUIRE(!dns_name_from_text(&n, "example\\.com"));
	CHECK_EQ(match_lookup_wire(idx, n.data, n.len), 1);
	REQUIRE(!dns_name_from_text(&n, "."));
	CHECK_EQ(match_lookup_wire(idx, n.data, n.len), 1);
	match_free(idx);
	free_rules(&rs);
}

TEST(name_text)
{
	struct dns_name n;
	char buf[DNS_NAME_TEXT_MAX];
	char big[600];

	REQUIRE(!dns_name_from_text(&n, "Www.Ex-am_ple.COM"));
	CHECK_EQ(n.len, 19);
	CHECK_EQ(n.data[1], 'W');
	CHECK_EQ(dns_name_to_text(n.data, n.len, buf, sizeof(buf)), 17);
	CHECK_STR(buf, "www.ex-am_ple.com");
	REQUIRE(!dns_name_from_text(&n, "a\\.b\\032\\255*.c."));
	CHECK_EQ(n.data[0], 6);
	CHECK_EQ(dns_name_to_text(n.data, n.len, buf, sizeof(buf)), 17);
	CHECK_STR(buf, "a\\046b\\032\\255*.c");
	REQUIRE(!dns_name_from_text(&n, "."));
	CHECK_EQ(n.len, 1);
	CHECK_EQ(dns_name_to_text(n.data, n.len, buf, sizeof(buf)), 0);
	CHECK_STR(buf, "");
	CHECK_EQ(dns_name_from_text(&n, "a..b"), -EINVAL);
	CHECK_EQ(dns_name_from_text(&n, ".a"), -EINVAL);
	CHECK_EQ(dns_name_from_text(&n, "a\\25"), -EINVAL);
	CHECK_EQ(dns_name_from_text(&n, "a\\256"), -EINVAL);
	CHECK_EQ(dns_name_from_text(&n, "a\\"), -EINVAL);
	/* 63-char label ok, 64 not */
	memset(big, 'a', 64);
	big[63] = 0;
	CHECK_EQ(dns_name_from_text(&n, big), 0);
	big[63] = 'a';
	big[64] = 0;
	CHECK_EQ(dns_name_from_text(&n, big), -EINVAL);
	/* total length: 4 x 63 labels = 256 wire bytes: too long; 253 text ok */
	for (int i = 0; i < 4; i++) {
		memset(big + i * 64, 'b', 63);
		big[i * 64 + 63] = '.';
	}
	big[4 * 64 - 1] = 0;
	CHECK_EQ(dns_name_from_text(&n, big), -EINVAL);
	big[4 * 64 - 3] = 0;		/* last label 61 -> 253 chars, 255 wire */
	CHECK_EQ(dns_name_from_text(&n, big), 0);
	CHECK_EQ(n.len, 255);
	CHECK_EQ(dns_name_to_text(n.data, n.len, buf, sizeof(buf)), 253);
	CHECK_EQ(dns_name_to_text(n.data, n.len, buf, 253), -ENOSPC);
	CHECK_EQ(dns_name_to_text(n.data, n.len, buf, 254), 253);
	/* worst case escaping */
	{
		uint8_t w[255];
		int o = 0;

		for (int l = 0; l < 4; l++) {
			int ll = l < 3 ? 63 : 61;

			w[o++] = (uint8_t)ll;
			memset(w + o, '.', (size_t)ll);
			o += ll;
		}
		w[o++] = 0;
		CHECK_EQ(o, 255);
		CHECK_EQ(dns_name_to_text(w, (uint8_t)o, buf, sizeof(buf)), 250 * 4 + 3);
		CHECK_EQ(dns_name_to_text(w, 10, buf, sizeof(buf)), -EINVAL);
	}
}

/* ---- naive matcher for differential testing ---- */

static bool pat_hit(const struct ns_pattern *p, const char *name, size_t len)
{
	if (len == p->len && !memcmp(name, p->name, len))
		return true;
	if (!p->suffix || len <= p->len)
		return false;
	return name[len - p->len - 1] == '.' && !memcmp(name + len - p->len, p->name, p->len);
}

static uint16_t naive(const struct ruleset *rs, const char *name)
{
	size_t len = strlen(name);

	for (uint16_t i = 0; i < rs->n; i++) {
		const struct rule *r = &rs->r[i];

		if (r->catchall)
			return r->ord;
		if (!len)
			continue;
		for (uint32_t k = 0; k < r->files[0]->npat; k++)
			if (pat_hit(&r->files[0]->pat[k], name, len))
				return r->ord;
	}
	return MATCH_NONE;
}

static void rand_name(char *buf, int maxlabels)
{
	static const char *const labs[] = { "a", "b", "c", "ab", "ba", "x-y", "q_1" };
	int n = 1 + rand() % maxlabels, o = 0;

	for (int i = 0; i < n; i++) {
		o += sprintf(buf + o, "%s%s", i ? "." : "", labs[rand() % 7]);
	}
}

TEST(differential)
{
	struct ruleset rs = { .n = 0 };
	char text[4096], name[64];
	int mism = 0;

	srand(12345);
	for (int round = 0; round < 20; round++) {
		struct match_index *idx;
		int nrules = 1 + rand() % 30;

		for (int i = 0; i < nrules; i++) {
			int np = rand() % 8, o = 0;

			if (i == nrules - 1 && rand() % 2) {
				add_rule(&rs, NULL);
				break;
			}
			for (int k = 0; k < np; k++) {
				rand_name(name, 3);
				o += sprintf(text + o, "%s%s\n", rand() % 2 ? "*." : "", name);
			}
			text[o] = 0;
			add_rule(&rs, text);
		}
		idx = match_build(rs.r, rs.n);
		REQUIRE(idx);
		for (int q = 0; q < 2000; q++) {
			if (q == 0)
				name[0] = 0;
			else
				rand_name(name, 5);
			if (match_lookup(idx, name, strlen(name)) != naive(&rs, name))
				mism++;
		}
		match_free(idx);
		free_rules(&rs);
	}
	CHECK_EQ(mism, 0);
}

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

TEST(bulk_100k)
{
	enum { NR = 10, PER = 10000, NQ = 2000000 };
	struct ruleset rs = { .n = 0 };
	struct match_index *idx;
	size_t cap = (size_t)PER * 40;
	char *text = malloc(cap), (*names)[64];
	double t0, t1;
	uint64_t sum = 0;
	int hits = 0;

	for (int r = 0; r < NR; r++) {
		size_t o = 0;

		for (int i = 0; i < PER; i++)
			o += (size_t)snprintf(text + o, cap - o, "%sd%d.zone%d.com\n",
					      i % 2 ? "*." : "", i, r);
		add_rule(&rs, text);
	}
	add_rule(&rs, NULL);
	free(text);

	t0 = now_s();
	idx = match_build(rs.r, rs.n);
	t1 = now_s();
	REQUIRE(idx);
	CHECK_EQ(match_nodes(idx), NR * PER);
	fprintf(stderr, "  build: %u nodes in %.1f ms, footprint %zu bytes (%.1f B/pattern)\n",
		match_nodes(idx), (t1 - t0) * 1e3, match_footprint(idx),
		(double)match_footprint(idx) / (NR * PER));

	names = malloc(4096 * sizeof(*names));
	for (int i = 0; i < 4096; i++) {
		int d = rand() % (PER * 2), r = rand() % NR;

		snprintf(names[i], sizeof(names[i]), "%s.d%d.zone%d.com",
			 i % 3 ? "www.cdn" : "img", d, r);
	}
	t0 = now_s();
	for (int q = 0; q < NQ; q++) {
		const char *n = names[q & 4095];
		uint16_t o = match_lookup(idx, n, strlen(n));

		sum += o;
		hits += o != NR;
	}
	t1 = now_s();
	fprintf(stderr, "  lookup: %d lookups (4-5 labels) in %.1f ms = %.2f M/s (hits %d, sum %llu)\n",
		NQ, (t1 - t0) * 1e3, NQ / (t1 - t0) / 1e6, hits, (unsigned long long)sum);
	CHECK(hits > 0);
	CHECK(NQ / (t1 - t0) > 200000);

	/* spot-check semantics */
	CHECK_EQ(look(idx, "d1.zone3.com"), 3);
	CHECK_EQ(look(idx, "x.d1.zone3.com"), 3);
	CHECK_EQ(look(idx, "d2.zone3.com"), 3);
	CHECK_EQ(look(idx, "x.d2.zone3.com"), NR);
	free(names);
	match_free(idx);
	free_rules(&rs);
}

int main(void)
{
	hash_init();
	log_init("test", true, LOG_ERR);
	RUN(name_text);
	RUN(ordinals);
	RUN(exact_vs_suffix_same_node);
	RUN(wire_lookup);
	RUN(differential);
	RUN(bulk_100k);
	return test_summary();
}
