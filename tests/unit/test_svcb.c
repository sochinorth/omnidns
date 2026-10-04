// SPDX-License-Identifier: MIT
#include "test.h"
#include "dns/svcb.h"

struct rd {
	uint8_t b[1024];
	uint16_t n;
};

static void r_bytes(struct rd *r, const void *d, size_t n)
{
	memcpy(r->b + r->n, d, n);
	r->n += n;
}

static void r_u16(struct rd *r, uint16_t v)
{
	uint8_t t[2] = { v >> 8, v & 0xff };

	r_bytes(r, t, 2);
}

static void r_param(struct rd *r, uint16_t key, const void *v, uint16_t len)
{
	r_u16(r, key);
	r_u16(r, len);
	r_bytes(r, v, len);
}

static const uint8_t v4[] = { 192, 0, 2, 1, 192, 0, 2, 2, 198, 51, 100, 7 };
static const uint8_t v6[32] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1,
				0x20, 0x01, 0x0d, 0xb8, [31] = 2 };
static const uint8_t alpn[] = { 2, 'h', '2', 2, 'h', '3' };
static const uint8_t ech[] = { 0xfe, 0x0d, 0x00, 0x01, 0xaa };

/* ServiceMode, target "svc.example.", alpn, ipv4hint, ech, ipv6hint, key 99 */
static void full_rdata(struct rd *r)
{
	r->n = 0;
	r_u16(r, 1);
	r_bytes(r, "\3svc\7example\0", 13);
	r_param(r, SVCB_KEY_ALPN, alpn, sizeof(alpn));
	r_param(r, SVCB_KEY_IPV4HINT, v4, sizeof(v4));
	r_param(r, SVCB_KEY_ECH, ech, sizeof(ech));
	r_param(r, SVCB_KEY_IPV6HINT, v6, sizeof(v6));
	r_param(r, 99, "xyz", 3);
}

/* map: 192.0.2.x -> 10.0.0.x, drop 198.51.100.0/24; v6: drop ::2, map last byte */
static int map_fn(void *ctx, int family, const uint8_t *in, uint8_t *out)
{
	int *calls = ctx;

	(*calls)++;
	if (family == 4) {
		if (in[0] == 198)
			return 1;
		out[0] = 10;
		out[1] = 0;
		out[2] = 0;
		out[3] = in[3];
		return 0;
	}
	if (in[15] == 2)
		return 1;
	memcpy(out, in, 16);
	out[0] = 0xfd;
	return 0;
}

static int drop_all(void *ctx, int family, const uint8_t *in, uint8_t *out)
{
	return 1;
}

static int fail_fn(void *ctx, int family, const uint8_t *in, uint8_t *out)
{
	return -ENOMEM;
}

/* Find a param value in rdata, return its length or -1. */
static int find_param(const uint8_t *rd, uint16_t len, uint16_t key, const uint8_t **val)
{
	struct svcb_view v;
	const uint8_t *p;
	size_t off = 0;

	if (svcb_parse(rd, len, &v))
		return -2;
	p = v.params;
	while (off + 4 <= v.params_len) {
		uint16_t k = p[off] << 8 | p[off + 1];
		uint16_t l = p[off + 2] << 8 | p[off + 3];

		if (k == key) {
			*val = p + off + 4;
			return l;
		}
		off += 4 + l;
	}
	return -1;
}

TEST(parse_modes)
{
	struct svcb_view v;
	struct rd r;

	r.n = 0;
	r_u16(&r, 0);
	r_bytes(&r, "\3foo\3com\0", 9);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), 0);
	CHECK_EQ(v.priority, 0);
	CHECK_EQ(v.target_len, 9);
	CHECK(!svcb_target_is_root(&v));
	CHECK_EQ(v.params_len, 0);

	full_rdata(&r);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), 0);
	CHECK_EQ(v.priority, 1);
	CHECK_EQ(v.target_len, 13);
	CHECK(v.target == r.b + 2);
	CHECK(v.params == r.b + 15);
	CHECK_EQ(v.params_len, r.n - 15);

	r.n = 0;
	r_u16(&r, 1);
	r_bytes(&r, "", 1);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), 0);
	CHECK(svcb_target_is_root(&v));
}

TEST(parse_malformed)
{
	struct svcb_view v;
	struct rd r;
	uint16_t i;

	/* truncated at every length */
	full_rdata(&r);
	for (i = 0; i < r.n; i++) {
		int e = svcb_parse(r.b, i, &v);

		/* only cuts at param boundaries are valid */
		if (i == 15 || i == 15 + 4 + 6 || i == 15 + 10 + 16 ||
		    i == 15 + 26 + 9 || i == 15 + 35 + 36)
			CHECK_EQ(e, 0);
		else
			CHECK_EQ(e, -EBADMSG);
	}
	/* non-increasing keys */
	r.n = 0;
	r_u16(&r, 1);
	r_bytes(&r, "", 1);
	r_param(&r, 4, v4, 4);
	r_param(&r, 1, alpn, sizeof(alpn));
	CHECK_EQ(svcb_parse(r.b, r.n, &v), -EBADMSG);
	/* duplicate keys */
	r.n = 0;
	r_u16(&r, 1);
	r_bytes(&r, "", 1);
	r_param(&r, 1, alpn, sizeof(alpn));
	r_param(&r, 1, alpn, sizeof(alpn));
	CHECK_EQ(svcb_parse(r.b, r.n, &v), -EBADMSG);
	/* bad hint lengths */
	r.n = 0;
	r_u16(&r, 1);
	r_bytes(&r, "", 1);
	r_param(&r, 4, v4, 5);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), -EBADMSG);
	r.n = 3;
	r_param(&r, 4, v4, 0);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), -EBADMSG);
	r.n = 3;
	r_param(&r, 6, v6, 20);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), -EBADMSG);
	r.n = 3;
	r_param(&r, 6, v6, 16);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), 0);
	/* value length beyond rdata */
	r.n = 3;
	r_u16(&r, 1);
	r_u16(&r, 50);
	r_bytes(&r, "ab", 2);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), -EBADMSG);
	/* bad target name: compression pointer / bad label */
	r.n = 0;
	r_u16(&r, 1);
	r_bytes(&r, "\xc0\x0c", 2);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), -EBADMSG);
	r.n = 0;
	r_u16(&r, 1);
	r_bytes(&r, "\x05" "ab", 3);
	CHECK_EQ(svcb_parse(r.b, r.n, &v), -EBADMSG);
	CHECK_EQ(svcb_parse(r.b, 2, &v), -EBADMSG);
}

TEST(rewrite_map)
{
	struct rd r;
	uint8_t out[1024];
	uint16_t olen = 0;
	const uint8_t *val;
	int calls = 0, l;

	full_rdata(&r);
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, map_fn, &calls, false, out, sizeof(out), &olen), 0);
	CHECK_EQ(calls, 5);
	CHECK_EQ(olen, r.n - 4 - 16);
	/* priority + target preserved */
	CHECK(!memcmp(out, r.b, 15));
	l = find_param(out, olen, SVCB_KEY_IPV4HINT, &val);
	CHECK_EQ(l, 8);
	if (l == 8)
		CHECK(!memcmp(val, "\x0a\0\0\x01\x0a\0\0\x02", 8));
	l = find_param(out, olen, SVCB_KEY_IPV6HINT, &val);
	CHECK_EQ(l, 16);
	if (l == 16)
		CHECK(val[0] == 0xfd && val[15] == 1);
	l = find_param(out, olen, SVCB_KEY_ALPN, &val);
	CHECK(l == sizeof(alpn) && !memcmp(val, alpn, l));
	l = find_param(out, olen, SVCB_KEY_ECH, &val);
	CHECK(l == sizeof(ech) && !memcmp(val, ech, l));
	l = find_param(out, olen, 99, &val);
	CHECK(l == 3 && !memcmp(val, "xyz", 3));
	/* alpn bytes are byte-identical in place */
	CHECK(!memcmp(out + 15, r.b + 15, 4 + sizeof(alpn)));
	/* trailing key 99 is byte-identical at the end */
	CHECK(!memcmp(out + olen - 7, r.b + r.n - 7, 7));
}

TEST(rewrite_drop)
{
	struct rd r;
	uint8_t out[1024];
	uint16_t olen = 0;
	const uint8_t *val;
	int calls = 0;

	full_rdata(&r);
	/* drop all -> both hint params removed, rest identical */
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, drop_all, NULL, false, out, sizeof(out), &olen), 0);
	CHECK_EQ(olen, r.n - (4 + sizeof(v4)) - (4 + sizeof(v6)));
	CHECK_EQ(find_param(out, olen, SVCB_KEY_IPV4HINT, &val), -1);
	CHECK_EQ(find_param(out, olen, SVCB_KEY_IPV6HINT, &val), -1);
	CHECK_EQ(find_param(out, olen, SVCB_KEY_ECH, &val), (int)sizeof(ech));
	{
		uint16_t need = olen;

		/* exact-size output is enough even with dropped hints */
		CHECK_EQ(svcb_rewrite_hints(r.b, r.n, drop_all, NULL, false, out, need, &olen), 0);
		CHECK_EQ(olen, need);
		CHECK_EQ(svcb_rewrite_hints(r.b, r.n, drop_all, NULL, false, out, need - 1, &olen), -ENOSPC);
	}
	/* drop_v6: no callback for v6, param removed */
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, map_fn, &calls, true, out, sizeof(out), &olen), 0);
	CHECK_EQ(calls, 3);
	CHECK_EQ(find_param(out, olen, SVCB_KEY_IPV6HINT, &val), -1);
	CHECK_EQ(find_param(out, olen, SVCB_KEY_IPV4HINT, &val), 8);
	CHECK_EQ(find_param(out, olen, 99, &val), 3);
	/* callback error propagates */
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, fail_fn, NULL, false, out, sizeof(out), &olen), -ENOMEM);
	/* NOSPC */
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, map_fn, &calls, false, out, 20, &olen), -ENOSPC);
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, map_fn, &calls, false, out, 10, &olen), -ENOSPC);
	/* malformed input */
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n - 1, map_fn, &calls, false, out, sizeof(out), &olen), -EBADMSG);
}

TEST(rewrite_mandatory)
{
	static const uint8_t mand[] = { 0, SVCB_KEY_ALPN, 0, SVCB_KEY_IPV4HINT,
					0, SVCB_KEY_IPV6HINT };
	struct svcb_view v;
	struct rd r = { .n = 0 };
	uint8_t out[1024];
	uint16_t olen;
	const uint8_t *val;

	r_u16(&r, 1);
	r_bytes(&r, "\0", 1);
	r_param(&r, 0, mand, sizeof(mand));
	r_param(&r, SVCB_KEY_ALPN, alpn, sizeof(alpn));
	r_param(&r, SVCB_KEY_IPV4HINT, v4, sizeof(v4));
	r_param(&r, SVCB_KEY_IPV6HINT, v6, sizeof(v6));
	REQUIRE(svcb_parse(r.b, r.n, &v) == 0);

	/* ipv6hint dropped -> removed from mandatory as well */
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, NULL, NULL, true, out, sizeof(out), &olen), 0);
	CHECK_EQ(svcb_parse(out, olen, &v), 0);
	CHECK_EQ(find_param(out, olen, 0, &val), 4);
	CHECK(val[1] == SVCB_KEY_ALPN && val[3] == SVCB_KEY_IPV4HINT);
	CHECK_EQ(find_param(out, olen, SVCB_KEY_IPV6HINT, &val), -1);

	/* both hints dropped -> only alpn stays mandatory */
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, drop_all, NULL, false, out, sizeof(out), &olen), 0);
	CHECK_EQ(find_param(out, olen, 0, &val), 2);
	CHECK(val[1] == SVCB_KEY_ALPN);
	CHECK_EQ(olen, r.n - 4 - (4 + sizeof(v4)) - (4 + sizeof(v6)));

	/* mandatory listing only hints -> param removed entirely */
	r.n = 0;
	r_u16(&r, 1);
	r_bytes(&r, "\0", 1);
	r_param(&r, 0, mand + 4, 2);
	r_param(&r, SVCB_KEY_IPV6HINT, v6, sizeof(v6));
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, NULL, NULL, true, out, sizeof(out), &olen), 0);
	CHECK_EQ(olen, 3);
	CHECK_EQ(find_param(out, olen, 0, &val), -1);
}

TEST(rewrite_alias)
{
	struct rd r;
	uint8_t out[64];
	uint16_t olen = 0;
	int calls = 0;

	r.n = 0;
	r_u16(&r, 0);
	r_bytes(&r, "\3foo\3com\0", 9);
	CHECK_EQ(svcb_rewrite_hints(r.b, r.n, map_fn, &calls, true, out, sizeof(out), &olen), 0);
	CHECK_EQ(olen, r.n);
	CHECK(!memcmp(out, r.b, r.n));
	CHECK_EQ(calls, 0);
}

int main(void)
{
	RUN(parse_modes);
	RUN(parse_malformed);
	RUN(rewrite_map);
	RUN(rewrite_drop);
	RUN(rewrite_mandatory);
	RUN(rewrite_alias);
	return test_summary();
}
