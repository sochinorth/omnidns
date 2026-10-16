// SPDX-License-Identifier: MIT
#include <stdbool.h>
#include <stdint.h>

#include "test.h"
#include "util/s3fifo.h"

struct obj {
	struct s3_node node;
	uint32_t id;
	bool in;	/* model: currently in the structure */
	bool pinned;
	uint32_t evictions;
};

static uint32_t n_evict_cb;
static bool bad_evict;

static bool obj_can_evict(struct s3fifo *s, struct s3_node *n)
{
	return !container_of(n, struct obj, node)->pinned;
}

static void obj_evict(struct s3fifo *s, struct s3_node *n)
{
	struct obj *o = container_of(n, struct obj, node);

	if (!o->in || o->pinned)
		bad_evict = true;
	o->in = false;
	o->evictions++;
	n_evict_cb++;
}

static const struct s3_ops ops = {
	.can_evict = obj_can_evict,
	.evict = obj_evict,
};

static const struct s3_ops ops_nopin = {
	.evict = obj_evict,
};

static void put(struct s3fifo *s, struct obj *o, uint64_t hash)
{
	o->in = true;
	s3_insert(s, &o->node, hash);
}

static bool on_list(struct list_head *head, struct obj *o)
{
	struct s3_node *n;

	list_for_each_entry(n, head, list)
		if (n == &o->node)
			return true;
	return false;
}

/* Does `hash` hit the ghost? Probes with a temporary node. */
static bool in_ghost(struct s3fifo *s, uint64_t hash)
{
	struct obj probe = { 0 };
	uint32_t before = s->n_main;
	bool hit;

	s3_insert(s, &probe.node, hash);
	hit = s->n_main == before + 1;
	s3_remove(s, &probe.node);
	return hit;
}

static void reset(struct obj *o, uint32_t n)
{
	memset(o, 0, n * sizeof(*o));
	for (uint32_t i = 0; i < n; i++)
		o[i].id = i;
	n_evict_cb = 0;
	bad_evict = false;
}

TEST(init_destroy)
{
	struct s3fifo s;

	REQUIRE(s3_init(&s, 0, &ops, NULL) == 0);
	CHECK_EQ(s.ghost_cap, 1);
	CHECK_EQ(s3_count(&s), 0);
	CHECK_EQ(s3_evict(&s, 0), 0);
	CHECK_EQ(s3_maybe_evict(&s), 0);
	s3_destroy(&s);

	REQUIRE(s3_init(&s, 1000, &ops, (void *)&s) == 0);
	CHECK_EQ(s.ghost_cap, 900);
	CHECK(!s.ghost_ring && !s.ghost_set);
	CHECK(s.ghost_set_mask + 1 >= 1800);
	CHECK(s.priv == &s);
	s3_destroy(&s);
}

TEST(one_hit_wonders)
{
	struct s3fifo s;
	struct obj o[20];
	uint32_t i;

	reset(o, 20);
	REQUIRE(s3_init(&s, 20, &ops, NULL) == 0);
	for (i = 0; i < 20; i++)
		put(&s, &o[i], 1000 + i);
	CHECK_EQ(s.n_small, 20);
	CHECK_EQ(s.n_main, 0);
	CHECK_EQ(s3_evict(&s, 10), 10);
	/* FIFO order: the oldest ten went, straight out of small */
	for (i = 0; i < 20; i++) {
		CHECK_EQ(o[i].evictions, i < 10);
		CHECK_EQ(on_list(&s.small, &o[i]), i >= 10);
	}
	CHECK_EQ(s.n_small, 10);
	CHECK_EQ(s.n_main, 0);
	CHECK_EQ(n_evict_cb, 10);
	CHECK(!bad_evict);
	s3_destroy(&s);
}

TEST(promote_to_main)
{
	struct s3fifo s;
	struct obj o[20];
	uint32_t i;

	reset(o, 20);
	REQUIRE(s3_init(&s, 10, &ops, NULL) == 0);	/* small target 1 */
	for (i = 0; i < 20; i++)
		put(&s, &o[i], 1000 + i);
	for (i = 0; i < 20; i += 2) {
		s3_touch(&o[i].node);
		s3_touch(&o[i].node);
	}
	CHECK_EQ(s3_evict(&s, 10), 10);
	for (i = 0; i < 20; i++) {
		CHECK_EQ(o[i].evictions, i & 1);
		CHECK_EQ(on_list(&s.main, &o[i]), !(i & 1));
		if (!(i & 1))
			CHECK_EQ(o[i].node.freq, 0);
	}
	CHECK_EQ(s.n_main, 10);
	CHECK_EQ(s.n_small, 0);

	/* main: touched nodes get a second chance, untouched go first */
	s3_touch(&o[0].node);
	s3_touch(&o[2].node);
	CHECK_EQ(s3_evict(&s, 7), 3);
	CHECK(o[0].in && o[2].in);
	CHECK(!o[4].in && !o[6].in && !o[8].in);
	CHECK(o[10].in);
	/* touched ones were reinserted at the tail with freq decremented */
	CHECK(list_last_entry(&s.main, struct s3_node, list) == &o[2].node);
	CHECK_EQ(o[0].node.freq, 0);
	CHECK(!bad_evict);
	s3_destroy(&s);
}

TEST(freq_saturates)
{
	struct obj o = { 0 };

	for (int i = 0; i < 10; i++)
		s3_touch(&o.node);
	CHECK_EQ(o.node.freq, 3);
}

TEST(ghost_hit)
{
	struct s3fifo s;
	struct obj o[12], again = { 0 }, fresh = { 0 }, zero = { 0 }, zero2 = { 0 };

	reset(o, 12);
	REQUIRE(s3_init(&s, 10, &ops, NULL) == 0);
	for (uint32_t i = 0; i < 4; i++)
		put(&s, &o[i], 500 + i);
	CHECK_EQ(s3_evict(&s, 2), 2);
	CHECK(!o[0].in && !o[1].in);

	put(&s, &again, 500);	/* o[0]'s hash */
	CHECK(on_list(&s.main, &again));
	CHECK_EQ(s.n_main, 1);
	put(&s, &fresh, 9999);
	CHECK(on_list(&s.small, &fresh));

	/* hash 0 is representable */
	put(&s, &zero, 0);
	CHECK(on_list(&s.small, &zero));
	s3_remove(&s, &zero.node);
	zero.in = false;
	CHECK(!in_ghost(&s, 0));
	put(&s, &zero, 0);
	/* drain small down so zero is evicted from it */
	while (zero.in && s3_evict(&s, s3_count(&s) - 1))
		;
	CHECK(!zero.in);
	put(&s, &zero2, 0);
	CHECK(on_list(&s.main, &zero2));
	CHECK(!bad_evict);
	s3_destroy(&s);
}

TEST(ghost_expiry)
{
	struct s3fifo s;
	struct obj o[30];
	uint32_t i;

	reset(o, 30);
	REQUIRE(s3_init(&s, 10, &ops, NULL) == 0);	/* ghost_cap = 9 */
	CHECK_EQ(s.ghost_cap, 9);
	for (i = 0; i < 30; i++) {
		put(&s, &o[i], 7000 + i * 64);	/* same low bits: collide in the set */
		s3_evict(&s, 0);
	}
	CHECK_EQ(n_evict_cb, 30);
	CHECK_EQ(s.ghost_len, 9);
	for (i = 0; i < 30; i++)
		CHECK_EQ(in_ghost(&s, 7000 + i * 64), i >= 21);
	/* duplicates of one hash (inserted before it was a ghost) */
	struct obj d[20] = { 0 };

	for (i = 0; i < 20; i++)
		put(&s, &d[i], 42);
	CHECK_EQ(s.n_small, 20);
	CHECK_EQ(s3_evict(&s, 0), 20);
	for (i = 0; i < 20; i++)
		CHECK(!d[i].in);
	CHECK(in_ghost(&s, 42));
	for (i = 0; i < 30; i++)
		CHECK(!in_ghost(&s, 7000 + i * 64));
	for (i = 0; i < 9; i++) {
		struct obj e = { .in = true };

		s3_insert(&s, &e.node, 100 + i);
		s3_evict(&s, 0);
	}
	CHECK(!in_ghost(&s, 42));
	s3_destroy(&s);
}

TEST(lazy_ghost)
{
	struct s3fifo s;
	struct obj o[4];

	reset(o, 4);
	REQUIRE(s3_init(&s, 10, &ops, NULL) == 0);
	CHECK(!s.ghost_ring && !s.ghost_set);
	CHECK_EQ(s.ghost_cap, 9);
	CHECK(!in_ghost(&s, 1));
	put(&s, &o[0], 1);
	put(&s, &o[1], 2);
	s3_touch(&o[0].node);
	s3_touch(&o[1].node);
	/* promotions small -> main and evictions from main record no ghost */
	CHECK_EQ(s3_evict(&s, 0), 2);
	CHECK(!o[0].in && !o[1].in);
	CHECK(!s.ghost_ring && !s.ghost_set);
	put(&s, &o[2], 3);
	s3_remove(&s, &o[2].node);
	o[2].in = false;
	CHECK(!s.ghost_ring);
	/* first eviction from small allocates */
	put(&s, &o[3], 4);
	CHECK_EQ(s3_evict(&s, 0), 1);
	CHECK(s.ghost_ring && s.ghost_set);
	CHECK_EQ(s.ghost_len, 1);
	CHECK(in_ghost(&s, 4));
	CHECK(!in_ghost(&s, 1));
	s3_destroy(&s);
	CHECK(!s.ghost_ring && !s.ghost_set);
}

/* Insert every absent o[i] (hash hbase + i), evicting at the watermark. */
static void churn(struct s3fifo *s, struct obj *o, uint32_t n, uint64_t hbase)
{
	for (uint32_t i = 0; i < n; i++) {
		if (o[i].in)
			continue;
		put(s, &o[i], hbase + i);
		s3_maybe_evict(s);
	}
}

TEST(set_cap)
{
	enum { N = 400 };
	static struct obj o[N];
	struct s3fifo s;
	uint32_t i, n;
	uint64_t g = 0;

	reset(o, N);
	REQUIRE(s3_init(&s, 100, &ops, NULL) == 0);
	churn(&s, o, 200, 10000);
	CHECK(s3_count(&s) <= 100);
	CHECK(s.ghost_ring);
	for (i = 0; i < 200 && !g; i++)
		if (in_ghost(&s, 10000 + i))
			g = 10000 + i;
	CHECK(g);

	/* same ghost size (99 - 9 == 100 - 10): history kept */
	s3_set_cap(&s, 99);
	CHECK_EQ(s.cap, 99);
	CHECK_EQ(s.ghost_cap, 90);
	s3_set_cap(&s, 100);
	CHECK_EQ(s.ghost_cap, 90);
	CHECK(s.ghost_ring);
	CHECK(in_ghost(&s, g));

	/* shrink: ghost dropped and resized, eviction honours the new cap */
	s3_set_cap(&s, 20);
	CHECK_EQ(s.cap, 20);
	CHECK_EQ(s.ghost_cap, 18);
	CHECK_EQ(s.ghost_set_mask + 1, 64);
	CHECK(!s.ghost_ring && !s.ghost_set);
	CHECK_EQ(s.ghost_len, 0);
	CHECK(!in_ghost(&s, g));
	s3_maybe_evict(&s);
	CHECK(s3_count(&s) <= 20);
	for (i = 0; i < N; i++)
		o[i].evictions = 0;
	churn(&s, o, N, 20000);
	CHECK(s3_count(&s) <= 20);
	CHECK(s.ghost_ring);
	CHECK_EQ(s.ghost_len, 18);
	/* ring wrap at the new size: only the last 18 small evictions remain */
	for (n = 0, i = 0; i < N; i++)
		n += in_ghost(&s, 20000 + i);
	CHECK(n <= 18 && n > 0);

	/* grow: ghost dropped, entries kept, fills up to the new cap */
	n = s3_count(&s);
	s3_set_cap(&s, 300);
	CHECK_EQ(s.ghost_cap, 270);
	CHECK_EQ(s.ghost_set_mask + 1, 1024);
	CHECK(!s.ghost_ring);
	CHECK_EQ(s3_count(&s), n);
	CHECK_EQ(s3_maybe_evict(&s), 0);
	churn(&s, o, N, 30000);
	CHECK(s3_count(&s) <= 300);
	CHECK(s3_count(&s) > 200);
	CHECK(s.ghost_ring);
	CHECK(s.ghost_len > 0 && s.ghost_len <= 270);

	CHECK(!bad_evict);
	CHECK(s3_evict(&s, 0) > 0);
	CHECK_EQ(s3_count(&s), 0);
	s3_destroy(&s);
}

TEST(ghost_hash_edges)
{
	struct s3fifo s;
	struct obj o[8];
	uint64_t hi = 1ULL << 40;

	reset(o, 8);
	REQUIRE(s3_init(&s, 100, &ops, NULL) == 0);
	/* 0 is stored as 1 in the ghost (0 marks an empty set slot) */
	put(&s, &o[0], 0);
	CHECK_EQ(s3_evict(&s, 0), 1);
	CHECK(in_ghost(&s, 0));
	CHECK(in_ghost(&s, 1));
	CHECK(!in_ghost(&s, 2));
	/* only the low 32 bits are kept: high bits alone do not distinguish */
	put(&s, &o[1], 5 | hi);
	CHECK_EQ(s3_evict(&s, 0), 1);
	CHECK(in_ghost(&s, 5 | hi));
	CHECK(in_ghost(&s, 5));
	CHECK(!in_ghost(&s, 6));
	/* all share the home slot in the set (low bits equal) */
	for (uint32_t i = 2; i < 8; i++)
		put(&s, &o[i], 7 + ((uint64_t)i << 24));
	CHECK_EQ(s3_evict(&s, 0), 6);
	for (uint32_t i = 2; i < 8; i++)
		CHECK(in_ghost(&s, 7 + ((uint64_t)i << 24)));
	CHECK(!in_ghost(&s, 7));
	CHECK(!in_ghost(&s, 7 + (9ULL << 24)));
	CHECK_EQ(s.ghost_len, 8);
	CHECK(!bad_evict);
	s3_destroy(&s);
}

TEST(pinned)
{
	struct s3fifo s;
	struct obj o[100];
	uint32_t i;

	reset(o, 100);
	REQUIRE(s3_init(&s, 50, &ops, NULL) == 0);
	for (i = 0; i < 100; i++) {
		put(&s, &o[i], i + 1);
		o[i].pinned = i % 3 == 0;
		if (i % 5 == 0)
			s3_touch(&o[i].node);
	}
	/* 34 pinned: evicting to 0 stops at them */
	CHECK_EQ(s3_evict(&s, 0), 66);
	CHECK_EQ(s3_count(&s), 34);
	for (i = 0; i < 100; i++)
		CHECK_EQ(o[i].in, o[i].pinned);
	CHECK(!bad_evict);

	/* everything pinned: terminates without evicting */
	CHECK_EQ(s3_evict(&s, 0), 0);
	CHECK_EQ(s3_count(&s), 34);
	CHECK_EQ(s3_maybe_evict(&s), 0);

	/* unpin a few, they go next */
	o[0].pinned = o[3].pinned = false;
	CHECK_EQ(s3_evict(&s, 0), 2);
	CHECK(!o[0].in && !o[3].in);
	CHECK_EQ(s3_count(&s), 32);
	s3_destroy(&s);
}

/* Unpinned nodes stuck in an under-target small queue behind pinned main. */
TEST(pinned_main_small_leftover)
{
	struct s3fifo s;
	struct obj o[105];
	uint32_t i;

	reset(o, 105);
	REQUIRE(s3_init(&s, 100, &ops, NULL) == 0);
	for (i = 0; i < 100; i++) {
		put(&s, &o[i], i + 1);
		s3_touch(&o[i].node);
		o[i].pinned = true;
	}
	s3_evict(&s, 0);
	CHECK_EQ(s.n_main, 100);
	for (i = 100; i < 105; i++)
		put(&s, &o[i], i + 1);
	CHECK_EQ(s.n_small, 5);	/* below small target of 10 */
	CHECK_EQ(s3_evict(&s, 0), 5);
	for (i = 100; i < 105; i++)
		CHECK(!o[i].in);
	CHECK(!bad_evict);
	s3_destroy(&s);
}

/* Hot unpinned node among many pinned: freq decrements are progress. */
TEST(pinned_hot_unpinned)
{
	struct s3fifo s;
	static struct obj o[1001];
	uint32_t i;

	reset(o, 1001);
	REQUIRE(s3_init(&s, 1000, &ops, NULL) == 0);
	for (i = 0; i < 1001; i++) {
		put(&s, &o[i], i + 1);
		s3_touch(&o[i].node);
		o[i].pinned = true;
	}
	CHECK_EQ(s3_evict(&s, 1001), 0);	/* no-op */
	CHECK_EQ(s3_count(&s), 1001);
	/* all pinned: everything moves to main (freq reset), nothing evicted */
	CHECK_EQ(s3_evict(&s, 1000), 0);
	CHECK_EQ(s.n_main, 1001);
	/* one hot unpinned node needs three full passes before it goes */
	for (i = 0; i < 3; i++)
		s3_touch(&o[500].node);
	o[500].pinned = false;
	CHECK_EQ(s3_evict(&s, 1000), 1);
	CHECK(!o[500].in);
	s3_destroy(&s);
}

TEST(no_can_evict)
{
	struct s3fifo s;
	struct obj o[50];
	uint32_t i;

	reset(o, 50);
	REQUIRE(s3_init(&s, 40, &ops_nopin, NULL) == 0);
	for (i = 0; i < 50; i++) {
		put(&s, &o[i], i + 1);
		s3_touch(&o[i].node);
		s3_touch(&o[i].node);
		s3_touch(&o[i].node);
	}
	/* 50 > 40: down to 35 in one batch */
	CHECK_EQ(s3_maybe_evict(&s), 15);
	CHECK_EQ(s3_count(&s), 35);
	CHECK_EQ(s3_maybe_evict(&s), 0);
	CHECK_EQ(n_evict_cb, 15);
	s3_destroy(&s);
}

TEST(remove)
{
	struct s3fifo s;
	struct obj o[40];
	uint32_t i;

	reset(o, 40);
	REQUIRE(s3_init(&s, 40, &ops, NULL) == 0);
	for (i = 0; i < 40; i++)
		put(&s, &o[i], i + 1);
	for (i = 0; i < 40; i += 4)
		s3_touch(&o[i].node);
	CHECK_EQ(s3_evict(&s, 30), 10);	/* o[0],o[4],o[8],o[12] promoted */
	CHECK(on_list(&s.main, &o[0]));
	CHECK_EQ(s.n_main, 4);

	/* remove from main, from small head/middle/tail */
	s3_remove(&s, &o[4].node);
	o[4].in = false;
	CHECK_EQ(s.n_main, 3);
	CHECK(!on_list(&s.main, &o[4]));
	struct s3_node *head = list_first_entry(&s.small, struct s3_node, list);
	struct obj *h = container_of(head, struct obj, node);
	s3_remove(&s, head);
	h->in = false;
	s3_remove(&s, &o[20].node);
	o[20].in = false;
	s3_remove(&s, &o[39].node);
	o[39].in = false;
	/* removing twice is harmless */
	s3_remove(&s, &o[39].node);
	CHECK_EQ(s3_count(&s), 26);
	CHECK_EQ(n_evict_cb, 10);

	CHECK_EQ(s3_evict(&s, 0), 26);
	CHECK_EQ(n_evict_cb, 36);
	CHECK_EQ(o[4].evictions, 0);
	CHECK_EQ(o[20].evictions, 0);
	CHECK_EQ(o[39].evictions, 0);
	CHECK_EQ(h->evictions, 0);
	CHECK(!bad_evict);
	CHECK(list_empty(&s.small) && list_empty(&s.main));
	s3_destroy(&s);
}

static uint64_t rng_state = 0x2545f4914f6cdd1dULL;

static uint32_t rnd(uint32_t n)
{
	uint64_t x = rng_state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	rng_state = x;
	return (uint32_t)(x >> 32) % n;
}

/* Walk both lists: every node present exactly once, counts match model. */
static bool check_lists(struct s3fifo *s, struct obj *o, uint32_t n, uint32_t model_count)
{
	struct s3_node *x;
	uint32_t ns = 0, nm = 0, i, in = 0;
	bool ok = true;

	for (i = 0; i < n; i++)
		in += o[i].in;
	list_for_each_entry(x, &s->small, list) {
		struct obj *p = container_of(x, struct obj, node);

		ok &= p->in;
		ns++;
	}
	list_for_each_entry(x, &s->main, list) {
		struct obj *p = container_of(x, struct obj, node);

		ok &= p->in;
		nm++;
	}
	ok &= ns == s->n_small && nm == s->n_main;
	ok &= ns + nm == model_count && in == model_count;
	return ok;
}

TEST(random_model)
{
	enum { N = 600, OPS = 300000 };
	static struct obj o[N];
	static uint32_t prev_evictions[N];
	struct s3fifo s;
	uint32_t i, count = 0, op;

	reset(o, N);
	REQUIRE(s3_init(&s, 256, &ops, NULL) == 0);
	for (op = 0; op < OPS; op++) {
		struct obj *x = &o[rnd(N)];
		uint32_t before_cb = n_evict_cb, r, target, pinned = 0;

		switch (rnd(16)) {
		case 0 ... 5:
			if (!x->in) {
				/* small key space for hashes: ghost hits happen */
				put(&s, x, x->id % 300);
				count++;
				s3_maybe_evict(&s);
			}
			break;
		case 6 ... 9:
			if (x->in)
				s3_touch(&x->node);
			break;
		case 10:
		case 11:
			if (x->in) {
				s3_remove(&s, &x->node);
				x->in = false;
				count--;
			}
			break;
		case 12:
			x->pinned = rnd(8) == 0;
			break;
		case 13:
			target = rnd(300);
			r = s3_evict(&s, target);
			CHECK_EQ(r, n_evict_cb - before_cb);
			if (s3_count(&s) > target) {
				/* gave up: only pinned nodes may remain */
				for (i = 0; i < N; i++)
					if (o[i].in && !o[i].pinned)
						CHECK(0);
			}
			break;
		case 14:
			r = s3_maybe_evict(&s);
			CHECK_EQ(r, n_evict_cb - before_cb);
			break;
		case 15:
			for (i = 0; i < N; i++)
				pinned += o[i].in && o[i].pinned;
			CHECK(pinned <= count);
			break;
		}
		count -= n_evict_cb - before_cb;
		if (s3_count(&s) != count || bad_evict) {
			CHECK_EQ(s3_count(&s), count);
			CHECK(!bad_evict);
			break;
		}
		if (op % 997 == 0 && !check_lists(&s, o, N, count)) {
			CHECK(0);
			break;
		}
	}
	CHECK(check_lists(&s, o, N, count));
	/* drain: unpin all, evict everything; each in-node evicted exactly once */
	for (i = 0; i < N; i++) {
		o[i].pinned = false;
		prev_evictions[i] = o[i].evictions;
	}
	CHECK_EQ(s3_evict(&s, 0), count);
	for (i = 0; i < N; i++) {
		CHECK(!o[i].in);
		if (o[i].evictions - prev_evictions[i] > 1)
			CHECK(0);
	}
	CHECK_EQ(s3_count(&s), 0);
	CHECK(!bad_evict);
	s3_destroy(&s);
}

int main(void)
{
	RUN(init_destroy);
	RUN(one_hit_wonders);
	RUN(promote_to_main);
	RUN(freq_saturates);
	RUN(ghost_hit);
	RUN(ghost_expiry);
	RUN(lazy_ghost);
	RUN(set_cap);
	RUN(ghost_hash_edges);
	RUN(pinned);
	RUN(pinned_main_small_leftover);
	RUN(pinned_hot_unpinned);
	RUN(no_can_evict);
	RUN(remove);
	RUN(random_model);
	return test_summary();
}
