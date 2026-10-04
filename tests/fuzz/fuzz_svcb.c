// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns/svcb.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define ASSERT(c) do {						\
	if (!(c)) {						\
		fprintf(stderr, "assert %s:%d: %s\n", __FILE__, __LINE__, #c); \
		abort();					\
	}							\
} while (0)

/* Deterministic mapping driven by the address bytes. */
static int map_fn(void *ctx, int family, const uint8_t *in, uint8_t *out)
{
	int alen = family == 4 ? 4 : 16;

	ASSERT(family == 4 || family == 6);
	if (in[alen - 1] & 1)
		return 1;
	memcpy(out, in, alen);
	out[0] ^= 0x5a;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static uint8_t out[65535], out2[65535];
	struct svcb_view v, v2;
	uint16_t len, olen = 0, olen2 = 0;
	bool drop_v6;
	int r, r2;

	if (size < 1 || size > 65536)
		return 0;
	drop_v6 = data[0] & 1;
	data++;
	len = (uint16_t)(size - 1);

	r = svcb_parse(data, len, &v);
	ASSERT(r == 0 || r == -EBADMSG);
	r2 = svcb_rewrite_hints(data, len, map_fn, NULL, drop_v6, out, sizeof(out), &olen);
	ASSERT(r2 == r);
	if (r)
		return 0;
	ASSERT(v.target == data + 2);
	ASSERT(2 + v.target_len + v.params_len == len);
	ASSERT(olen <= len);
	ASSERT(svcb_parse(out, olen, &v2) == 0);
	ASSERT(v2.priority == v.priority && v2.target_len == v.target_len &&
	       !memcmp(v2.target, v.target, v.target_len));
	/* no callback and no drop: byte-exact copy */
	ASSERT(svcb_rewrite_hints(data, len, NULL, NULL, false, out2, sizeof(out2), &olen2) == 0);
	ASSERT(olen2 == len && !memcmp(out2, data, len));
	/* exact-size output works; one byte less fails */
	ASSERT(svcb_rewrite_hints(data, len, map_fn, NULL, drop_v6, out2, olen, &olen2) == 0);
	ASSERT(olen2 == olen && !memcmp(out, out2, olen));
	ASSERT(svcb_rewrite_hints(data, len, map_fn, NULL, drop_v6, out2,
				  olen - 1, &olen2) == -ENOSPC);
	return 0;
}
