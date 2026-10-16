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

	if (nameset_parse(text, strlen(text), 0, f, &inval, "mem"))
		abort();
	f->refcnt = 1;
	return f;
}

static void freefile(struct nameset_file *f)
{
	free(f->blob);
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

TEST(refcount)
{
	struct ruleset rs = { .n = 0 };
	struct match_index *idx;

	add_rule(&rs, "a.example\n");
	add_rule(&rs, NULL);
	idx = match_build(rs.r, rs.n);
	REQUIRE(idx);
	CHECK(match_get(idx) == idx);
	CHECK(match_get(idx) == idx);
	match_free(idx);
	match_free(idx);
	CHECK_EQ(look(idx, "a.example"), 0);	/* one reference left */
	CHECK_EQ(look(idx, "b.example"), 1);
	match_free(idx);
	match_free(NULL);
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

static bool pat_hit(const char *e, const char *name, size_t len)
{
	const char *p = ns_name(e);
	size_t plen = strlen(p);

	if (len == plen && !memcmp(name, p, len))
		return true;
	if (!ns_is_suffix(e) || len <= plen)
		return false;
	return name[len - plen - 1] == '.' && !memcmp(name + len - plen, p, plen);
}

static uint16_t naive(const struct rule *rules, uint16_t nrules, const char *name)
{
	size_t len = strlen(name);

	for (uint16_t i = 0; i < nrules; i++) {
		const struct rule *r = &rules[i];

		if (r->catchall)
			return r->ord;
		if (!len)
			continue;
		for (uint16_t j = 0; j < r->nfiles; j++) {
			const struct nameset_file *f = r->files[j];

			for (const char *e = f->blob; e < f->blob + f->blob_len; e = ns_next(e))
				if (pat_hit(e, name, len))
					return r->ord;
		}
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

/* Labels that are prefixes/suffixes of each other. */
static void rand_name_near(char *buf, int maxlabels)
{
	static const char *const labs[] = {
		"example", "ample", "exampl", "co", "com", "c", "e", "m",
	};
	int n = 1 + rand() % maxlabels, o = 0;

	for (int i = 0; i < n; i++)
		o += sprintf(buf + o, "%s%s", i ? "." : "", labs[rand() % 8]);
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
			if (match_lookup(idx, name, strlen(name)) != naive(rs.r, rs.n, name))
				mism++;
		}
		match_free(idx);
		free_rules(&rs);
	}
	CHECK_EQ(mism, 0);
}

/* Rules with several files each, files shared between rules. */
TEST(differential_shared_files)
{
	enum { NPOOL = 12, MAXR = 24 };
	struct nameset_file *pool[NPOOL], *lists[MAXR][3];
	struct rule r[MAXR];
	char text[4096], name[64];
	int mism = 0;

	srand(777);
	for (int round = 0; round < 30; round++) {
		struct match_index *idx;
		uint16_t nr = (uint16_t)(1 + rand() % MAXR);
		uint32_t npat = 0;

		for (int i = 0; i < NPOOL; i++) {
			int np = rand() % 10, o = 0;

			for (int k = 0; k < np; k++) {
				rand_name_near(name, 3);
				o += sprintf(text + o, "%s%s\n", rand() % 2 ? "*." : "", name);
			}
			text[o] = 0;
			pool[i] = mkfile(text);
			npat += pool[i]->npat;
		}
		memset(r, 0, sizeof(r));
		for (uint16_t i = 0; i < nr; i++) {
			r[i].ord = i;
			if (i == nr - 1 && rand() % 2) {
				r[i].catchall = true;
				break;
			}
			r[i].files = lists[i];
			r[i].nfiles = (uint16_t)(1 + rand() % 3);
			for (int j = 0; j < r[i].nfiles; j++)
				lists[i][j] = pool[rand() % NPOOL];
		}
		idx = match_build(r, nr);
		REQUIRE(idx);
		CHECK(match_nodes(idx) <= npat);
		for (int q = 0; q < 3000; q++) {
			if (q == 0)
				name[0] = 0;
			else
				rand_name_near(name, 4);
			if (match_lookup(idx, name, strlen(name)) != naive(r, nr, name))
				mism++;
		}
		match_free(idx);
		for (int i = 0; i < NPOOL; i++)
			freefile(pool[i]);
	}
	CHECK_EQ(mism, 0);
}

TEST(multi_file_ords)
{
	struct nameset_file *a = mkfile("x.test\n*.shared.test\n");
	struct nameset_file *b = mkfile("*.x.test\nshared.test\n");
	struct nameset_file *c = mkfile("other.test\n");
	struct nameset_file *e = mkfile("# no patterns\n");
	struct nameset_file *f0[] = { e, a }, *f1[] = { b, c }, *f2[] = { c, a };
	struct rule r[4] = {
		{ .ord = 0, .files = f0, .nfiles = 2 },
		{ .ord = 1, .files = f1, .nfiles = 2 },
		{ .ord = 2, .files = f2, .nfiles = 2 },	/* reuses a and c */
		{ .ord = 3, .catchall = true },
	};
	struct match_index *idx = match_build(r, 4), *one;

	REQUIRE(idx);
	CHECK_EQ(look(idx, "x.test"), 0);	/* exact in rule 0, suffix in 1 */
	CHECK_EQ(look(idx, "y.x.test"), 1);
	CHECK_EQ(look(idx, "shared.test"), 0);	/* suffix in 0, exact in 1 */
	CHECK_EQ(look(idx, "z.shared.test"), 0);
	CHECK_EQ(look(idx, "other.test"), 1);
	CHECK_EQ(look(idx, "y.other.test"), 3);
	CHECK_EQ(look(idx, "test"), 3);
	CHECK_EQ(match_nodes(idx), 3);
	/* bases a, b, c (deduplicated; e has none): two more than a alone,
	 * same 16-slot table */
	one = match_build(r, 1);
	REQUIRE(one);
	CHECK_EQ(match_footprint(idx) - match_footprint(one), 2 * sizeof(char *));
	match_free(one);
	match_free(idx);
	freefile(a);
	freefile(b);
	freefile(c);
	freefile(e);
}

/* A file shared by several rules sizes the table once, not once per rule. */
TEST(shared_file_sizing)
{
	struct nameset_file *a = mkfile("a.t\nb.t\nc.t\nd.t\ne.t\nf.t\ng.t\nh.t\n"
	                                "i.t\nj.t\nk.t\nl.t\nm.t\n");
	struct nameset_file *fs[] = { a };
	struct rule r[9];
	struct match_index *idx, *one;

	memset(r, 0, sizeof(r));
	for (int i = 0; i < 8; i++) {
		r[i].ord = (uint16_t)i;
		r[i].files = fs;
		r[i].nfiles = 1;
	}
	r[8].ord = 8;
	r[8].catchall = true;
	idx = match_build(r, 9);
	one = match_build(r, 1);
	REQUIRE(idx && one);
	CHECK_EQ(match_nodes(idx), 13);
	CHECK_EQ(look(idx, "m.t"), 0);
	CHECK_EQ(look(idx, "n.t"), 8);
	/* 13 patterns -> 32 slots either way (104 counted per rule -> 256) */
	CHECK_EQ(match_footprint(idx), match_footprint(one));
	match_free(one);
	match_free(idx);
	freefile(a);
}

/*
 * Stored names are compared up to their NUL: a pattern must not match a
 * query that is a prefix of it, or one it is a prefix of. Find a name that
 * shares hash tag and home slot with "example.co" so that the names
 * really get compared.
 */
TEST(no_prefix_matches)
{
	struct ruleset rs = { .n = 0 };
	struct match_index *idx;
	uint64_t h0 = omni_hash("example.co", 10), h;
	char longer[32], text[64];
	uint32_t i;

	for (i = 0; i < (1u << 28); i++) {
		snprintf(longer, sizeof(longer), "example.co%x", i);
		h = omni_hash(longer, strlen(longer));
		if ((h >> 48) == (h0 >> 48) && (h & 15) == (h0 & 15))
			break;
	}
	REQUIRE(i < (1u << 28));
	snprintf(text, sizeof(text), "%s\n", longer);
	add_rule(&rs, text);			/* 0 */
	add_rule(&rs, "example.co\n");		/* 1 */
	add_rule(&rs, "*.ample.com\n");		/* 2 */
	add_rule(&rs, NULL);			/* 3 */
	idx = match_build(rs.r, rs.n);
	REQUIRE(idx);
	CHECK_EQ(match_nodes(idx), 3);
	CHECK_EQ(look(idx, longer), 0);
	CHECK_EQ(look(idx, "example.co"), 1);
	CHECK_EQ(look(idx, "example.com"), 3);
	CHECK_EQ(look(idx, "example.c"), 3);
	CHECK_EQ(look(idx, "xample.co"), 3);
	CHECK_EQ(look(idx, "ample.com"), 2);
	CHECK_EQ(look(idx, "x.ample.com"), 2);
	CHECK_EQ(look(idx, "ample.co"), 3);
	match_free(idx);
	free_rules(&rs);
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
	RUN(refcount);
	RUN(wire_lookup);
	RUN(differential);
	RUN(differential_shared_files);
	RUN(multi_file_ords);
	RUN(shared_file_sizing);
	RUN(no_prefix_matches);
	RUN(bulk_100k);
	return test_summary();
}
