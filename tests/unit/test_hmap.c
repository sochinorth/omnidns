// SPDX-License-Identifier: MIT
#include <stdint.h>

#include "test.h"
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
	CHECK(m.val == NULL && m.hash == NULL);
	CHECK_EQ(hmap_footprint(&m), 0);
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
	void **slots;
	uint32_t i, cap;

	REQUIRE(it);
	REQUIRE(hmap_reserve(&m, 10000) == 0);
	cap = m.mask + 1;
	CHECK((cap & (cap - 1)) == 0);
	CHECK((uint64_t)cap * 3 > 10000ull * 4);
	slots = m.val;
	CHECK_EQ(hmap_footprint(&m), (size_t)cap * (sizeof(void *) + sizeof(uint32_t)));
	for (i = 0; i < 10000; i++) {
		it[i].key = i;
		REQUIRE(hmap_put(&m, key_hash(i), &it[i]) == 0);
	}
	/* no rehash happened */
	CHECK(m.val == slots);
	CHECK_EQ(m.mask + 1, cap);
	/* smaller reserve is a no-op */
	CHECK(hmap_reserve(&m, 10) == 0);
	CHECK(m.val == slots);
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

/*
 * Hashes equal in the low 32 bits but distinct above: they collide in the
 * table (only 32 bits are stored) and eq alone must tell them apart.
 */
TEST(hmap_upper_bits)
{
	enum { N = 2000 };
	struct hmap m = HMAP_INIT;
	struct item *it = calloc(N, sizeof(*it)), *v;
	uint32_t i, iter, n = 0;

	REQUIRE(it);
	for (i = 0; i < N; i++) {
		it[i].key = i;
		REQUIRE(hmap_put(&m, (uint64_t)(i + 1) << 32 | 0x5a5a5a5a, &it[i]) == 0);
	}
	CHECK_EQ(hmap_len(&m), N);
	for (i = 0; i < N; i++)
		CHECK(get(&m, (uint64_t)(i + 1) << 32 | 0x5a5a5a5a, i) == &it[i]);
	/* absent key with the same low bits */
	CHECK(get(&m, (uint64_t)(N + 1) << 32 | 0x5a5a5a5a, N) == NULL);
	/* different low bits never match, even for a present key */
	CHECK(get(&m, 1ULL << 32 | 0x5a5a5a5b, 0) == NULL);
	for (i = 0; i < N; i += 2)
		CHECK(del(&m, (uint64_t)(i + 1) << 32 | 0x5a5a5a5a, i) == &it[i]);
	for (i = 0; i < N; i++)
		CHECK(get(&m, (uint64_t)(i + 1) << 32 | 0x5a5a5a5a, i) ==
		      (i & 1 ? &it[i] : NULL));
	for (iter = 0; (v = hmap_next(&m, &iter)); n++)
		CHECK(v->key & 1);
	CHECK_EQ(n, N / 2);
	for (i = 1; i < N; i += 2)
		CHECK(hmap_del_ptr(&m, (uint64_t)(i + 1) << 32 | 0x5a5a5a5a, &it[i]));
	CHECK_EQ(hmap_len(&m), 0);
	hmap_free(&m);
	free(it);
}

/* Growth well past 2^16 live entries with tombstone churn, checked against a model. */
TEST(hmap_growth_churn)
{
	enum { N = 150000 };
	struct hmap m = HMAP_INIT;
	struct item *it = calloc(N, sizeof(*it)), *v;
	bool *in = calloc(N, sizeof(*in));
	uint32_t i, iter, n, len = 0, round;

	REQUIRE(it && in);
	for (i = 0; i < N; i++) {
		it[i].key = i;
		REQUIRE(hmap_put(&m, key_hash(i), &it[i]) == 0);
		in[i] = true;
	}
	len = N;
	CHECK(m.mask + 1 > 1u << 17);
	for (round = 0; round < 3; round++) {
		/* delete a pseudo-random half, then reinsert some of them */
		for (i = 0; i < N; i++) {
			if (!in[i] || rng() & 1)
				continue;
			CHECK(del(&m, key_hash(i), i) == &it[i]);
			in[i] = false;
			len--;
		}
		CHECK_EQ(hmap_len(&m), len);
		for (i = 0; i < N; i++) {
			if (in[i] || rng() % 3 == 0)
				continue;
			REQUIRE(hmap_put(&m, key_hash(i), &it[i]) == 0);
			in[i] = true;
			len++;
		}
		CHECK_EQ(hmap_len(&m), len);
		CHECK(m.used * 4 <= (m.mask + 1) * 3);
		for (i = 0; i < N; i++)
			CHECK(get(&m, key_hash(i), i) == (in[i] ? &it[i] : NULL));
		for (i = 0; i < N; i++)
			it[i].seen = 0;
		n = 0;
		for (iter = 0; (v = hmap_next(&m, &iter)); n++) {
			CHECK(in[v->key]);
			v->seen++;
		}
		CHECK_EQ(n, len);
		for (i = 0; i < N; i++)
			CHECK_EQ(it[i].seen, in[i]);
		if (test_cur_failed)
			break;
	}
	hmap_free(&m);
	free(it);
	free(in);
}

int main(void)
{
	uint8_t key[16] = { 0 };

	hash_init_fixed(key);
	RUN(siphash_vector);
	RUN(hmap_basic);
	RUN(hmap_collisions);
	RUN(hmap_wrap);
	RUN(hmap_reserve);
	RUN(hmap_iter_delete);
	RUN(hmap_tombstone_churn);
	RUN(hmap_random_model);
	RUN(hmap_upper_bits);
	RUN(hmap_growth_churn);
	return test_summary();
}
