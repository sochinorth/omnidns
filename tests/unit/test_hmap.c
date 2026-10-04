// SPDX-License-Identifier: MIT
#include <stdint.h>

#include "test.h"
#include "util/arena.h"
#include "util/hash.h"
#include "util/hmap.h"

struct item {
	uint64_t key;
	int seen;
};

static bool item_eq(const void *val, const void *key, void *ctx)
{
	return ((const struct item *)val)->key == *(const uint64_t *)key;
}

static uint64_t key_hash(uint64_t k)
{
	return omni_hash(&k, sizeof(k));
}

static struct item *get(struct hmap *m, uint64_t h, uint64_t k)
{
	return hmap_get(m, h, &k, item_eq, NULL);
}

static struct item *del(struct hmap *m, uint64_t h, uint64_t k)
{
	return hmap_del(m, h, &k, item_eq, NULL);
}

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t rng(void)
{
	uint64_t x = rng_state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	return rng_state = x;
}

TEST(siphash_vector)
{
	uint8_t key[16], msg[64];
	int i;

	for (i = 0; i < 16; i++)
		key[i] = i;
	for (i = 0; i < 64; i++)
		msg[i] = i;
	CHECK(siphash24(key, msg, 15) == 0xa129ca6149be45e5ULL);
	/* more reference vectors from the SipHash paper's vectors.h */
	CHECK(siphash24(key, msg, 0) == 0x726fdb47dd0e0e31ULL);
	CHECK(siphash24(key, msg, 8) == 0x93f5f5799a932462ULL);
	CHECK(siphash24(key, msg, 63) == 0x958a324ceb064572ULL);
}

TEST(hash_ci)
{
	const char *a = "WwW.ExAmPlE.CoM.with-a-long-tail", *b = "www.example.com.WITH-A-LONG-TAIL";
	uint8_t key[16] = { 1, 2, 3 };
	size_t n = strlen(a), i;

	hash_init_fixed(key);
	for (i = 0; i <= n; i++)
		CHECK(omni_hash_ci(a, i) == omni_hash_ci(b, i));
	/* the ci hash equals the plain hash of the lowercased input */
	CHECK(omni_hash_ci("example", 7) == omni_hash("example", 7));
	CHECK(omni_hash_ci("EXAMPLE", 7) == omni_hash("example", 7));
	CHECK(omni_hash_ci("example", 7) != omni_hash_ci("exampld", 7));
	/* non-ASCII bytes are not folded */
	CHECK(omni_hash_ci("\xc4", 1) != omni_hash_ci("\xe4", 1));
	/* only letters fold: '@' (0x40) and '`' (0x60) stay distinct */
	CHECK(omni_hash_ci("@", 1) != omni_hash_ci("`", 1));
	CHECK(omni_hash_ci("[", 1) != omni_hash_ci("{", 1));
}

TEST(hmap_basic)
{
	struct hmap m = HMAP_INIT;
	struct item it[1000];
	uint32_t i;

	CHECK(get(&m, 1, 1) == NULL);
	CHECK(del(&m, 1, 1) == NULL);
	CHECK(!hmap_del_ptr(&m, 1, &it[0]));
	CHECK_EQ(hmap_len(&m), 0);
	for (i = 0; i < 1000; i++) {
		it[i].key = i;
		REQUIRE(hmap_put(&m, key_hash(i), &it[i]) == 0);
	}
	CHECK_EQ(hmap_len(&m), 1000);
	for (i = 0; i < 1000; i++)
		CHECK(get(&m, key_hash(i), i) == &it[i]);
	CHECK(get(&m, key_hash(1000), 1000) == NULL);
	for (i = 0; i < 1000; i += 2)
		CHECK(del(&m, key_hash(i), i) == &it[i]);
	CHECK_EQ(hmap_len(&m), 500);
	for (i = 0; i < 1000; i++)
		CHECK(get(&m, key_hash(i), i) == (i & 1 ? &it[i] : NULL));
	CHECK(del(&m, key_hash(0), 0) == NULL);
	for (i = 1; i < 1000; i += 2)
		CHECK(hmap_del_ptr(&m, key_hash(i), &it[i]));
	CHECK(!hmap_del_ptr(&m, key_hash(1), &it[1]));
	CHECK_EQ(hmap_len(&m), 0);
	hmap_free(&m);
	CHECK(m.slots == NULL);
	CHECK(get(&m, 1, 1) == NULL);
	/* reusable after free */
	CHECK(hmap_put(&m, 5, &it[5]) == 0);
	CHECK(get(&m, 5, 5) == &it[5]);
	hmap_free(&m);
}

/* Equal hashes, distinct keys; duplicates allowed; del_ptr by identity. */
TEST(hmap_collisions)
{
	struct hmap m = HMAP_INIT;
	struct item it[64], dup = { .key = 3 };
	uint32_t i;

	for (i = 0; i < 64; i++) {
		it[i].key = i;
		REQUIRE(hmap_put(&m, i & 3, &it[i]) == 0);
	}
	for (i = 0; i < 64; i++)
		CHECK(get(&m, i & 3, i) == &it[i]);
	/* wrong hash never matches even if key equal */
	CHECK(get(&m, 7, 1) == NULL);

	REQUIRE(hmap_put(&m, 3, &dup) == 0);
	CHECK_EQ(hmap_len(&m), 65);
	CHECK(hmap_del_ptr(&m, 3, &dup));
	CHECK(get(&m, 3, 3) == &it[3]);
	REQUIRE(hmap_put(&m, 3, &dup) == 0);
	CHECK(hmap_del_ptr(&m, 3, &it[3]));
	CHECK(get(&m, 3, 3) == &dup);
	CHECK(del(&m, 3, 3) == &dup);
	CHECK(get(&m, 3, 3) == NULL);

	/* delete from the middle of chains, the rest stays reachable */
	for (i = 0; i < 64; i += 3)
		if (i != 3)
			CHECK(del(&m, i & 3, i) == &it[i]);
	for (i = 0; i < 64; i++)
		CHECK(get(&m, i & 3, i) == (i % 3 && i != 3 ? &it[i] : NULL));
	hmap_free(&m);
}

/* High hash bits set, probing wraps around the end of the table. */
TEST(hmap_wrap)
{
	struct hmap m = HMAP_INIT;
	struct item it[8];
	uint32_t i;

	REQUIRE(hmap_reserve(&m, 8) == 0);
	for (i = 0; i < 8; i++) {
		it[i].key = i;
		REQUIRE(hmap_put(&m, 0xffffffff00000000ULL | m.mask, &it[i]) == 0);
	}
	for (i = 0; i < 8; i++)
		CHECK(get(&m, 0xffffffff00000000ULL | m.mask, i) == &it[i]);
	for (i = 0; i < 8; i += 2)
		CHECK(del(&m, 0xffffffff00000000ULL | m.mask, i) == &it[i]);
	for (i = 0; i < 8; i++)
		CHECK(get(&m, 0xffffffff00000000ULL | m.mask, i) == (i & 1 ? &it[i] : NULL));
	hmap_free(&m);
}

TEST(hmap_reserve)
{
	struct hmap m = HMAP_INIT;
	struct item *it = calloc(10000, sizeof(*it));
	struct hmap_slot *slots;
	uint32_t i, cap;

	REQUIRE(it);
	REQUIRE(hmap_reserve(&m, 10000) == 0);
	cap = m.mask + 1;
	CHECK((cap & (cap - 1)) == 0);
	CHECK((uint64_t)cap * 3 > 10000ull * 4);
	slots = m.slots;
	for (i = 0; i < 10000; i++) {
		it[i].key = i;
		REQUIRE(hmap_put(&m, key_hash(i), &it[i]) == 0);
	}
	/* no rehash happened */
	CHECK(m.slots == slots);
	CHECK_EQ(m.mask + 1, cap);
	/* smaller reserve is a no-op */
	CHECK(hmap_reserve(&m, 10) == 0);
	CHECK(m.slots == slots);
	/* growing reserve keeps contents */
	REQUIRE(hmap_reserve(&m, 100000) == 0);
	CHECK(m.mask + 1 > cap);
	CHECK_EQ(hmap_len(&m), 10000);
	for (i = 0; i < 10000; i++)
		CHECK(get(&m, key_hash(i), i) == &it[i]);
	hmap_free(&m);
	free(it);
}

TEST(hmap_iter_delete)
{
	struct hmap m = HMAP_INIT;
	struct item *it = calloc(5000, sizeof(*it)), *v;
	uint32_t i, iter, n = 0;

	REQUIRE(it);
	for (i = 0; i < 5000; i++) {
		it[i].key = i;
		REQUIRE(hmap_put(&m, key_hash(i), &it[i]) == 0);
	}
	/* visit each exactly once, deleting odd keys on the way */
	for (iter = 0; (v = hmap_next(&m, &iter)); ) {
		v->seen++;
		n++;
		if (v->key & 1)
			CHECK(hmap_del_ptr(&m, key_hash(v->key), v));
	}
	CHECK_EQ(n, 5000);
	for (i = 0; i < 5000; i++)
		CHECK_EQ(it[i].seen, 1);
	CHECK_EQ(hmap_len(&m), 2500);
	/* second pass sees only even keys, delete all */
	n = 0;
	for (iter = 0; (v = hmap_next(&m, &iter)); ) {
		CHECK((v->key & 1) == 0);
		v->seen++;
		n++;
		CHECK(del(&m, key_hash(v->key), v->key) == v);
	}
	CHECK_EQ(n, 2500);
	CHECK_EQ(hmap_len(&m), 0);
	iter = 0;
	CHECK(hmap_next(&m, &iter) == NULL);
	hmap_free(&m);
	iter = 0;
	CHECK(hmap_next(&m, &iter) == NULL);
	free(it);
}

/* Millions of insert/delete cycles with a bounded live set: table must not grow. */
TEST(hmap_tombstone_churn)
{
	enum { LIVE = 1000, CYCLES = 3000000 };
	struct hmap m = HMAP_INIT;
	struct item *it = calloc(LIVE, sizeof(*it));
	uint64_t next = 0;
	uint32_t i, maxcap = 0;

	REQUIRE(it);
	for (i = 0; i < LIVE; i++) {
		it[i].key = next++;
		REQUIRE(hmap_put(&m, key_hash(it[i].key), &it[i]) == 0);
	}
	for (i = 0; i < CYCLES; i++) {
		struct item *x = &it[i % LIVE];

		if (del(&m, key_hash(x->key), x->key) != x) {
			CHECK(0);
			break;
		}
		x->key = next++;
		REQUIRE(hmap_put(&m, key_hash(x->key), x) == 0);
		if (m.mask + 1 > maxcap)
			maxcap = m.mask + 1;
		if (m.used * 4 > (m.mask + 1) * 3) {
			CHECK(0);
			break;
		}
	}
	CHECK_EQ(hmap_len(&m), LIVE);
	CHECK(maxcap <= 4096);
	for (i = 0; i < LIVE; i++)
		CHECK(get(&m, key_hash(it[i].key), it[i].key) == &it[i]);
	hmap_free(&m);
	free(it);
}

/* Random ops against a dense reference array. */
TEST(hmap_random_model)
{
	enum { N = 4096, OPS = 400000 };
	struct hmap m = HMAP_INIT;
	struct item *it = calloc(N, sizeof(*it));
	bool *in = calloc(N, sizeof(*in));
	uint32_t i, len = 0;

	REQUIRE(it && in);
	for (i = 0; i < N; i++)
		it[i].key = i;
	for (i = 0; i < OPS; i++) {
		uint32_t k = rng() % N;
		uint64_t h = key_hash(k) & 0xfff;	/* force some hash collisions */
		switch (rng() % 4) {
		case 0:
		case 1:
			if (!in[k]) {
				REQUIRE(hmap_put(&m, h, &it[k]) == 0);
				in[k] = true;
				len++;
			}
			break;
		case 2:
			CHECK(del(&m, h, k) == (in[k] ? &it[k] : NULL));
			len -= in[k];
			in[k] = false;
			break;
		case 3:
			CHECK(get(&m, h, k) == (in[k] ? &it[k] : NULL));
			break;
		}
		if (test_cur_failed)
			break;
	}
	CHECK_EQ(hmap_len(&m), len);
	for (i = 0; i < N; i++)
		CHECK(get(&m, key_hash(i) & 0xfff, i) == (in[i] ? &it[i] : NULL));
	hmap_free(&m);
	free(it);
	free(in);
}

TEST(arena_align)
{
	static const size_t aligns[] = { 1, 2, 4, 8, 16, 32, 64, 128, 4096 };
	struct arena a;
	size_t i, j;

	arena_init(&a, 0);
	CHECK_EQ(a.chunk, 64 * 1024);
	for (j = 0; j < 200; j++) {
		for (i = 0; i < sizeof(aligns) / sizeof(aligns[0]); i++) {
			uint8_t *p = arena_alloc(&a, 1 + j % 7, aligns[i]);

			REQUIRE(p);
			CHECK(((uintptr_t)p & (aligns[i] - 1)) == 0);
			memset(p, 0xa5, 1 + j % 7);
		}
	}
	/* align 0 behaves like 1; non-power-of-two is rejected */
	CHECK(arena_alloc(&a, 3, 0) != NULL);
	CHECK(arena_alloc(&a, 3, 24) == NULL);
	arena_free(&a);
	CHECK(a.head == NULL);
	CHECK_EQ(a.total, 0);
}

TEST(arena_large)
{
	struct arena a;
	uint8_t *small1, *big, *small2, *huge;
	size_t total;

	arena_init(&a, 1024);
	small1 = arena_alloc(&a, 10, 1);
	REQUIRE(small1);
	total = a.total;
	/* oversized request gets its own chunk... */
	big = arena_alloc(&a, 100000, 8);
	REQUIRE(big);
	memset(big, 1, 100000);
	CHECK(((uintptr_t)big & 7) == 0);
	CHECK(a.total >= total + 100000);
	/* ...and small allocs keep packing into the current chunk */
	small2 = arena_alloc(&a, 10, 1);
	CHECK(small2 == small1 + 10);
	/* large and over-aligned */
	huge = arena_alloc(&a, 1 << 20, 4096);
	REQUIRE(huge);
	CHECK(((uintptr_t)huge & 4095) == 0);
	memset(huge, 2, 1 << 20);
	CHECK(big[99999] == 1);
	/* overflow is refused, not wrapped */
	CHECK(arena_alloc(&a, SIZE_MAX, 1) == NULL);
	CHECK(arena_alloc(&a, SIZE_MAX - 8, 64) == NULL);
	/* filling chunks exactly */
	for (int i = 0; i < 1000; i++) {
		uint8_t *p = arena_alloc(&a, 256, 1);

		REQUIRE(p);
		memset(p, i, 256);
	}
	arena_free(&a);
}

TEST(arena_dup)
{
	struct arena a;
	char *s;
	uint8_t *d;

	arena_init(&a, 64);
	s = arena_strndup(&a, "hello world", 5);
	CHECK_STR(s, "hello");
	s = arena_strndup(&a, "", 0);
	CHECK_STR(s, "");
	d = arena_memdup(&a, "\0\1\2\3", 4);
	REQUIRE(d);
	CHECK(memcmp(d, "\0\1\2\3", 4) == 0);
	CHECK(arena_memdup(&a, NULL, 0) != NULL);
	s = arena_strndup(&a, "a-string-longer-than-a-quarter-chunk", 36);
	CHECK_STR(s, "a-string-longer-than-a-quarter-chunk");
	arena_free(&a);
}

int main(void)
{
	uint8_t key[16] = { 0 };

	hash_init_fixed(key);
	RUN(siphash_vector);
	RUN(hash_ci);
	RUN(hmap_basic);
	RUN(hmap_collisions);
	RUN(hmap_wrap);
	RUN(hmap_reserve);
	RUN(hmap_iter_delete);
	RUN(hmap_tombstone_churn);
	RUN(hmap_random_model);
	RUN(arena_align);
	RUN(arena_large);
	RUN(arena_dup);
	return test_summary();
}
