// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <string.h>

#include "svcb.h"

static inline uint16_t get16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static inline void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

static int hint_alen(uint16_t key)
{
	if (key == SVCB_KEY_IPV4HINT)
		return 4;
	if (key == SVCB_KEY_IPV6HINT)
		return 16;
	return 0;
}

int svcb_parse(const uint8_t *rdata, uint16_t len, struct svcb_view *out)
{
	size_t off;
	int32_t prev = -1;
	int tl;

	if (len < 3)
		return -EBADMSG;
	tl = dns_name_check(rdata + 2, len - 2);
	if (tl < 0)
		return -EBADMSG;
	off = 2 + (size_t)tl;
	out->priority = get16(rdata);
	out->target = rdata + 2;
	out->target_len = (uint8_t)tl;
	out->params = rdata + off;
	out->params_len = (uint16_t)(len - off);
	while (off < len) {
		uint16_t key, vlen;
		int alen;

		if (len - off < 4)
			return -EBADMSG;
		key = get16(rdata + off);
		vlen = get16(rdata + off + 2);
		off += 4;
		if ((int32_t)key <= prev || vlen > len - off)
			return -EBADMSG;
		alen = hint_alen(key);
		if (alen && (!vlen || vlen % alen))
			return -EBADMSG;
		prev = key;
		off += vlen;
	}
	return 0;
}

/* Rewrite one hint param; *n is set to the bytes written (0 = removed). */
static int rewrite_hint(int family, const uint8_t *val, uint16_t vlen,
			svcb_addr_fn fn, void *ctx, uint8_t *out, size_t cap,
			size_t *n)
{
	int alen = family == 4 ? 4 : 16;
	uint8_t addr[16];
	size_t o = 0, i;
	int r;

	for (i = 0; i < vlen; i += alen) {
		r = fn(ctx, family, val + i, addr);
		if (r < 0)
			return r;
		if (r > 0)
			continue;
		if (cap - o < (size_t)alen)
			return -ENOSPC;
		memcpy(out + o, addr, alen);
		o += alen;
	}
	*n = o;
	return 0;
}

int svcb_rewrite_hints(const uint8_t *rdata, uint16_t len,
		       svcb_addr_fn fn, void *ctx, bool drop_v6,
		       uint8_t *out, size_t cap, uint16_t *outlen)
{
	struct svcb_view v;
	size_t off, o, room;
	int r;

	r = svcb_parse(rdata, len, &v);
	if (r)
		return r;
	off = 2 + (size_t)v.target_len;
	if (cap < off)
		return -ENOSPC;
	memcpy(out, rdata, off);
	o = off;
	while (off < len) {
		uint16_t key = get16(rdata + off), vlen = get16(rdata + off + 2);
		const uint8_t *val = rdata + off + 4;
		size_t n;

		off += 4 + (size_t)vlen;
		if (key == SVCB_KEY_IPV6HINT && drop_v6)
			continue;
		if (!hint_alen(key) || !fn) {
			if (cap - o < 4 + (size_t)vlen)
				return -ENOSPC;
			memcpy(out + o, val - 4, 4 + (size_t)vlen);
			o += 4 + (size_t)vlen;
			continue;
		}
		/* a fully dropped hint needs no room at all */
		room = cap - o >= 4 ? cap - o - 4 : 0;
		r = rewrite_hint(key == SVCB_KEY_IPV4HINT ? 4 : 6, val, vlen,
				 fn, ctx, room ? out + o + 4 : NULL, room, &n);
		if (r)
			return r;
		if (!n)
			continue;
		put16(out + o, key);
		put16(out + o + 2, (uint16_t)n);
		o += 4 + n;
	}
	*outlen = (uint16_t)o;
	return 0;
}
