// SPDX-License-Identifier: MIT
#include "test.h"
#include "util/pool.h"

#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/asan_interface.h>
#endif

struct obj {
	void *link;			/* the pool's while kept */
	int payload;
	char *own;			/* storage kept across reuse */
};

static int released;

static void obj_release(void *p)
{
	struct obj *o = p;

	free(o->own);
	released++;
}

static struct pool mkpool(uint32_t cap, uint32_t floor)
{
	struct pool p = POOL_INIT(struct obj, cap, floor, obj_release);

	released = 0;
	return p;
}

/* A kept object comes back as it was left, apart from the link word. */
TEST(reuse)
{
	struct pool p = mkpool(8, 2);
	struct obj *a, *b;
	bool fresh;

	a = pool_get(&p, &fresh);
	REQUIRE(a);
	CHECK(fresh);
	CHECK(!a->payload && !a->own);		/* new ones are zeroed */
	a->payload = 42;
	a->own = malloc(16);
	pool_put(&p, a);
	CHECK_EQ(p.nfree, 1);
#if defined(__SANITIZE_ADDRESS__)
	/* kept objects are poisoned past the link word, like freed memory */
	CHECK(__asan_address_is_poisoned(&a->payload));
	CHECK(!__asan_address_is_poisoned(&a->link));
#endif
	b = pool_get(&p, &fresh);
	CHECK(b == a);
	CHECK(!fresh);
#if defined(__SANITIZE_ADDRESS__)
	CHECK(!__asan_address_is_poisoned(&b->payload));
#endif
	CHECK_EQ(b->payload, 42);
	CHECK(b->own != NULL);
	CHECK_EQ(p.nfree, 0);
	CHECK_EQ(released, 0);
	pool_put(&p, b);
	pool_put(&p, NULL);			/* ignored */
	pool_drain(&p);
	CHECK_EQ(released, 1);
	CHECK_EQ(p.nfree, 0);
	CHECK(!p.head);
}

/* At most cap are kept; the rest are freed (through release) on put. */
TEST(cap)
{
	struct pool p = mkpool(3, 1);
	struct obj *o[10];
	bool fresh;
	int i;

	for (i = 0; i < 10; i++) {
		o[i] = pool_get(&p, &fresh);
		REQUIRE(o[i]);
		o[i]->own = malloc(8);
	}
	for (i = 0; i < 10; i++)
		pool_put(&p, o[i]);
	CHECK_EQ(p.nfree, 3);
	CHECK_EQ(released, 7);
	/* the kept ones are reused before anything new is allocated */
	for (i = 0; i < 3; i++) {
		o[i] = pool_get(&p, &fresh);
		CHECK(!fresh);
	}
	o[3] = pool_get(&p, &fresh);
	CHECK(fresh);
	for (i = 0; i < 4; i++)
		pool_put(&p, o[i]);
	pool_drain(&p);
	CHECK_EQ(released, 11);
}

/*
 * Kept objects that stay unused through a trim interval are freed, down to
 * floor; while they are drawn on, only those never drawn on go.
 */
TEST(idle_release)
{
	struct pool p = mkpool(16, 2);
	struct obj *o[10];
	bool fresh;
	int i;

	for (i = 0; i < 10; i++)
		o[i] = pool_get(&p, &fresh);
	CHECK(!p.timer.pending);
	for (i = 0; i < 10; i++)
		pool_put(&p, o[i]);
	/* an interval started when more than floor were kept (3 of them) */
	CHECK(p.timer.pending);
	CHECK_EQ(p.nfree, 10);
	pool_trim(&p);
	/* only the 3 kept through the whole interval go */
	CHECK_EQ(p.nfree, 7);
	CHECK_EQ(released, 3);
	CHECK(p.timer.pending);
	/* busy interval: the kept count dips to 1, so at most 1 goes */
	for (i = 0; i < 6; i++)
		o[i] = pool_get(&p, &fresh);
	CHECK(!fresh);
	CHECK_EQ(p.low, 1);
	for (i = 0; i < 6; i++)
		pool_put(&p, o[i]);
	pool_trim(&p);
	CHECK_EQ(p.nfree, 6);
	CHECK_EQ(released, 4);
	/* idle: two intervals bring it down to floor, then no timer runs */
	pool_trim(&p);
	CHECK_EQ(p.nfree, 2);
	CHECK(!p.timer.pending);
	pool_trim(&p);
	CHECK_EQ(p.nfree, 2);
	CHECK_EQ(released, 8);
	/* at or below floor nothing is armed */
	o[0] = pool_get(&p, &fresh);
	pool_put(&p, o[0]);
	CHECK(!p.timer.pending);
	pool_drain(&p);
	CHECK_EQ(released, 10);
	CHECK(!p.timer.pending);
}

/* The timer runs the trim on its own. */
static void stop_cb(struct uloop_timeout *t)
{
	uloop_end();
}

TEST(timer)
{
	struct pool p = mkpool(8, 0);
	struct uloop_timeout stop = { .cb = stop_cb };
	struct obj *o;
	bool fresh;

	uloop_init();
	o = pool_get(&p, &fresh);
	pool_put(&p, o);
	CHECK(p.timer.pending);
	uloop_timeout_set(&stop, POOL_TRIM_MS + 500);
	uloop_run();
	CHECK_EQ(p.nfree, 0);
	CHECK_EQ(released, 1);
	CHECK(!p.timer.pending);
	uloop_done();
}

int main(void)
{
	RUN(reuse);
	RUN(cap);
	RUN(idle_release);
	RUN(timer);
	return test_summary();
}
