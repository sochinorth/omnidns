// SPDX-License-Identifier: GPL-2.0-only
#include <string.h>
#include <sys/random.h>

#include "hash.h"

uint8_t omni_hash_key[16];

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND do {							\
	v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);	\
	v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;				\
	v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;				\
	v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);	\
} while (0)

static inline uint64_t load64le(const uint8_t *p)
{
	return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16 |
	       (uint64_t)p[3] << 24 | (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 |
	       (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
}

static inline uint8_t lower(uint8_t c)
{
	return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

struct sip {
	uint64_t v0, v1, v2, v3;
};

static void sip_init(struct sip *s, const uint8_t key[16])
{
	uint64_t k0 = load64le(key), k1 = load64le(key + 8);

	s->v0 = 0x736f6d6570736575ULL ^ k0;
	s->v1 = 0x646f72616e646f6dULL ^ k1;
	s->v2 = 0x6c7967656e657261ULL ^ k0;
	s->v3 = 0x7465646279746573ULL ^ k1;
}

static void sip_block(struct sip *s, uint64_t m)
{
	uint64_t v0 = s->v0, v1 = s->v1, v2 = s->v2, v3 = s->v3;

	v3 ^= m;
	SIPROUND;
	SIPROUND;
	v0 ^= m;
	s->v0 = v0; s->v1 = v1; s->v2 = v2; s->v3 = v3;
}

static uint64_t sip_final(struct sip *s, uint64_t b)
{
	uint64_t v0, v1, v2, v3;

	sip_block(s, b);
	v0 = s->v0; v1 = s->v1; v2 = s->v2; v3 = s->v3;
	v2 ^= 0xff;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t siphash_impl(const uint8_t key[16], const uint8_t *in, size_t len, int fold)
{
	struct sip s;
	uint8_t tmp[8];
	size_t i, j, full = len & ~(size_t)7;
	uint64_t b = (uint64_t)len << 56;

	sip_init(&s, key);
	for (i = 0; i < full; i += 8) {
		if (fold) {
			for (j = 0; j < 8; j++)
				tmp[j] = lower(in[i + j]);
			sip_block(&s, load64le(tmp));
		} else {
			sip_block(&s, load64le(in + i));
		}
	}
	for (j = 0; i + j < len; j++) {
		uint8_t c = in[i + j];
		b |= (uint64_t)(fold ? lower(c) : c) << (8 * j);
	}
	return sip_final(&s, b);
}

uint64_t siphash24(const uint8_t key[16], const void *data, size_t len)
{
	return siphash_impl(key, data, len, 0);
}

uint64_t omni_hash_ci(const void *data, size_t len)
{
	return siphash_impl(omni_hash_key, data, len, 1);
}

void hash_init(void)
{
	if (getrandom(omni_hash_key, sizeof(omni_hash_key), 0) != sizeof(omni_hash_key)) {
		/* extremely unlikely; fall back to something non-constant */
		uint64_t t = (uint64_t)(uintptr_t)&t ^ (uint64_t)(uintptr_t)hash_init;
		memcpy(omni_hash_key, &t, sizeof(t));
	}
}

void hash_init_fixed(const uint8_t key[16])
{
	memcpy(omni_hash_key, key, 16);
}
