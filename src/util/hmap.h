/* SPDX-License-Identifier: MIT */
#ifndef OMNI_HMAP_H
#define OMNI_HMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Generic open-addressing hash map of opaque value pointers.
 *
 * The map stores (hash, val) pairs; it never owns or inspects values except
 * through the caller-supplied eq callback. Keys live inside the values.
 * Callers pass 64-bit hashes; only the low 31 bits are kept (the probe
 * index never uses more, and eq confirms every candidate anyway).
 * Linear probing with tombstones, capacity a power of two. NULL is not a
 * valid value.
 *
 * Sizing, all on hmap_put():
 *  - live + tombstones may fill 75% of the slots. Past that, tombstones
 *    are purged in place (no allocation) when live entries fill at most
 *    11/16, so a purge frees at least 1/16 of the table; otherwise the
 *    table doubles.
 *  - when live entries fall below 1/8 of the slots, the table shrinks to
 *    a quarter to three eighths full (never below what hmap_reserve()
 *    asked for). Growing again takes 75%, so it does not thrash.
 *
 * Duplicates: hmap_put() does not check for an existing equal key; callers
 * do hmap_get() first when uniqueness matters.
 */

typedef bool (*hmap_eq_fn)(const void *val, const void *key, void *ctx);

struct hmap {
	/*
	 * Parallel slot arrays in one allocation (val first, then hash).
	 * hash holds the low 31 bits; the top bit is scratch for the
	 * in-place purge.
	 */
	void **val;		/* NULL = empty, HMAP_TOMB = deleted */
	uint32_t *hash;
	uint32_t mask;		/* capacity - 1, 0 when unallocated */
	uint32_t len;		/* live entries */
	uint32_t used;		/* live + tombstones */
	uint32_t min_cap;	/* hmap_reserve(): never shrink below */
};

/* 32 B on LP64 (as before: min_cap fills the padding), 24 B on ILP32 */
_Static_assert(sizeof(struct hmap) == 2 * sizeof(void *) + 16, "hmap layout");

#define HMAP_INIT { 0 }

/* Pre-size for `n` entries (optional; the table then never shrinks below
 * that). Returns 0 or -ENOMEM. */
int hmap_reserve(struct hmap *m, uint32_t n);
void hmap_free(struct hmap *m);	/* frees the table only, not the values */

void *hmap_get(const struct hmap *m, uint64_t hash, const void *key,
               hmap_eq_fn eq, void *ctx);
int hmap_put(struct hmap *m, uint64_t hash, void *val);		/* 0 / -ENOMEM */
void *hmap_del(struct hmap *m, uint64_t hash, const void *key,
               hmap_eq_fn eq, void *ctx);			/* removed val or NULL */
/* Remove exactly this value pointer (identity compare). Returns true if found. */
bool hmap_del_ptr(struct hmap *m, uint64_t hash, const void *val);

/* Bytes of slot storage currently allocated (excludes struct hmap and values). */
size_t hmap_footprint(const struct hmap *m);

static inline uint32_t hmap_len(const struct hmap *m) { return m->len; }

/* Iteration: for (uint32_t it = 0; (v = hmap_next(m, &it)); ) ...
 * Deleting during iteration is allowed (the current element or any other):
 * deletes never move entries. hmap_put() during iteration is NOT allowed:
 * it may grow the table, purge tombstones in place or shrink it, any of
 * which moves entries so the walk skips or repeats them. */
void *hmap_next(const struct hmap *m, uint32_t *it);

#endif
