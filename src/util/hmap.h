/* SPDX-License-Identifier: MIT */
#ifndef OMNI_HMAP_H
#define OMNI_HMAP_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Generic open-addressing hash map of opaque value pointers.
 *
 * The map stores (hash, val) pairs; it never owns or inspects values except
 * through the caller-supplied eq callback. Keys live inside the values.
 * Linear probing with tombstones; grows at 75% load (counting tombstones),
 * rehashes in place-of-tombstones when tombstones dominate. Capacity is a
 * power of two. NULL is not a valid value.
 *
 * Duplicates: hmap_put() does not check for an existing equal key; callers
 * do hmap_get() first when uniqueness matters.
 */

typedef bool (*hmap_eq_fn)(const void *val, const void *key, void *ctx);

struct hmap_slot {
	uint64_t hash;
	void *val;		/* NULL = empty, HMAP_TOMB = deleted */
};

struct hmap {
	struct hmap_slot *slots;
	uint32_t mask;		/* capacity - 1, 0 when unallocated */
	uint32_t len;		/* live entries */
	uint32_t used;		/* live + tombstones */
};

#define HMAP_INIT { 0 }

/* Pre-size for `n` entries (optional). Returns 0 or -ENOMEM. */
int hmap_reserve(struct hmap *m, uint32_t n);
void hmap_free(struct hmap *m);	/* frees the table only, not the values */

void *hmap_get(const struct hmap *m, uint64_t hash, const void *key,
	       hmap_eq_fn eq, void *ctx);
int hmap_put(struct hmap *m, uint64_t hash, void *val);		/* 0 / -ENOMEM */
void *hmap_del(struct hmap *m, uint64_t hash, const void *key,
	       hmap_eq_fn eq, void *ctx);			/* removed val or NULL */
/* Remove exactly this value pointer (identity compare). Returns true if found. */
bool hmap_del_ptr(struct hmap *m, uint64_t hash, const void *val);

static inline uint32_t hmap_len(const struct hmap *m) { return m->len; }

/* Iteration: for (uint32_t it = 0; (v = hmap_next(m, &it)); ) ...
 * Deleting the current element during iteration is allowed. */
void *hmap_next(const struct hmap *m, uint32_t *it);

#endif
