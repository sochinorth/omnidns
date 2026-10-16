/* SPDX-License-Identifier: MIT */
#ifndef OMNI_POOL_H
#define OMNI_POOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <libubox/uloop.h>

/*
 * Free list of fixed-size objects, for per-request state that would
 * otherwise be allocated and freed for every query (single-threaded, on
 * uloop).
 *
 * pool_put() keeps an object for reuse while fewer than `cap` are kept,
 * and frees it past that. Objects in use are bounded by their callers
 * (pending-request limits), kept ones by cap.
 *
 * Kept objects that go unused are given back: every POOL_TRIM_MS while more
 * than `floor` are kept, pool_trim() frees those that stayed in the pool
 * through the whole interval (the low-water mark of the kept count), down
 * to floor. Under steady load that is next to nothing; after a burst, or
 * when idle, memory returns to floor within two intervals.
 *
 * `release`, if set, runs on an object just before the pool frees it: an
 * object may keep storage of its own across reuse (e.g. message buffers),
 * which the pool cannot know about. While an object is kept, the pool uses
 * its first pointer-sized word (so that word is not part of what a kept
 * object keeps). Objects are at least a pointer in size.
 */
#define POOL_TRIM_MS	5000

struct pool {
	void *head;			/* kept objects, linked through their first word */
	uint32_t nfree;
	uint32_t low;			/* fewest kept since the last trim */
	uint32_t cap, floor;
	size_t size;
	void (*release)(void *obj);
	struct uloop_timeout timer;
};

/* head + 4 counters, no hole before size: 24 B on LP64, 20 B on ILP32 */
_Static_assert(offsetof(struct pool, size) == sizeof(void *) + 16, "pool layout");

#define POOL_INIT(type, cap_, floor_, release_) \
	{ .size = sizeof(type), .cap = (cap_), .floor = (floor_), .release = (release_) }

/*
 * A kept object as its last user left it (it is up to the caller to know
 * what that is and reinitialize it), or a new zeroed one. *fresh tells
 * which. NULL when out of memory.
 */
void *pool_get(struct pool *p, bool *fresh);
void pool_put(struct pool *p, void *obj);
/* What the timer runs: free the objects kept through the last interval. */
void pool_trim(struct pool *p);
/* Free every kept object (shutdown, tests); objects in use are unaffected. */
void pool_drain(struct pool *p);

#endif
