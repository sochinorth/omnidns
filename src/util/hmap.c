// SPDX-License-Identifier: MIT
#include <errno.h>
#include <stdlib.h>

#include "hmap.h"

#define HMAP_TOMB ((void *)(uintptr_t)1)
#define HMAP_MIN_CAP 16
#define HMAP_MAX_CAP 0x80000000u
#define HMAP_SLOT_BYTES (sizeof(void *) + sizeof(uint32_t))
#define HASH_BITS 0x7fffffffu	/* stored hash bits; the top one marks a pending slot */
#define PENDING 0x80000000u

/* 12 B/slot on LP64, 8 B on ILP32 (was 16 B on both with a u64 hash). */
_Static_assert(HMAP_SLOT_BYTES == 12 || HMAP_SLOT_BYTES == 8,
               "hmap slot = 32-bit hash + value pointer");
/* the hash array sits right after the val array in the same allocation */
_Static_assert(_Alignof(uint32_t) <= _Alignof(void *), "hash array alignment");
/* the probe index never needs the PENDING bit */
_Static_assert(HMAP_MAX_CAP - 1 == HASH_BITS, "index bits within stored hash bits");

static inline uint32_t slot_hash(uint64_t hash)
{
	return (uint32_t)hash & HASH_BITS;
}

static int hmap_rehash(struct hmap *m, uint32_t cap)
{
	void **oldval = m->val, **val;
	uint32_t *oldhash = m->hash, *hash;
	uint32_t oldcap = m->mask ? m->mask + 1 : 0, i;

	/* calloc checks cap * HMAP_SLOT_BYTES for overflow (matters on ILP32) */
	val = calloc(cap, HMAP_SLOT_BYTES);
	if (!val)
		return -ENOMEM;
	hash = (uint32_t *)(val + cap);
	m->val = val;
	m->hash = hash;
	m->mask = cap - 1;
	m->used = m->len;
	for (i = 0; i < oldcap; i++) {
		void *v = oldval[i];
		uint32_t j;

		if (!v || v == HMAP_TOMB)
			continue;
		for (j = oldhash[i] & m->mask; val[j]; j = (j + 1) & m->mask)
			;
		val[j] = v;
		hash[j] = oldhash[i];
	}
	free(oldval);
	return 0;
}

/*
 * Drop every tombstone without allocating. Tombstones become empty, which
 * can cut a live entry off from its home slot, so every live entry is
 * marked pending and placed again: at the first slot from its home that is
 * empty or still pending. If that slot is its own, it stays; if empty, it
 * moves there; if pending, the two swap and the entry swapped in is placed
 * next. A placed slot never changes again, and everything between an
 * entry's home and its slot is placed, so every probe chain ends up intact.
 * Each step places one entry for good: O(capacity).
 */
static void hmap_purge(struct hmap *m)
{
	uint32_t mask = m->mask, i, j;

	for (i = 0; i <= mask; i++) {
		if (m->val[i] == HMAP_TOMB)
			m->val[i] = NULL;
		else if (m->val[i])
			m->hash[i] |= PENDING;
	}
	for (i = 0; i <= mask; i++) {
		while (m->val[i] && (m->hash[i] & PENDING)) {
			uint32_t h = m->hash[i] & HASH_BITS;
			void *v = m->val[i];

			for (j = h & mask; m->val[j] && !(m->hash[j] & PENDING); j = (j + 1) & mask)
				;
			if (j == i) {
				m->hash[i] = h;
				break;
			}
			/* j is empty (i becomes empty) or pending (swap) */
			m->val[i] = m->val[j];
			m->hash[i] = m->hash[j];
			m->val[j] = v;
			m->hash[j] = h;
		}
	}
	m->used = m->len;
}

static uint32_t cap_for(uint32_t n)
{
	uint32_t cap = HMAP_MIN_CAP;

	while (cap < HMAP_MAX_CAP && (uint64_t)n * 4 >= (uint64_t)cap * 3)
		cap <<= 1;
	return cap;
}

int hmap_reserve(struct hmap *m, uint32_t n)
{
	uint32_t cap = cap_for(n);

	if (cap > m->min_cap)
		m->min_cap = cap;
	if (m->mask && cap <= m->mask + 1)
		return 0;
	return hmap_rehash(m, cap);
}

void hmap_free(struct hmap *m)
{
	free(m->val);
	m->val = NULL;
	m->hash = NULL;
	m->mask = m->len = m->used = m->min_cap = 0;
}

size_t hmap_footprint(const struct hmap *m)
{
	return m->mask ? ((size_t)m->mask + 1) * HMAP_SLOT_BYTES : 0;
}

void *hmap_get(const struct hmap *m, uint64_t hash, const void *key,
               hmap_eq_fn eq, void *ctx)
{
	uint32_t h = slot_hash(hash), i;

	if (!m->mask)
		return NULL;
	for (i = h & m->mask; m->val[i]; i = (i + 1) & m->mask) {
		void *v = m->val[i];

		if (v != HMAP_TOMB && m->hash[i] == h && eq(v, key, ctx))
			return v;
	}
	return NULL;
}

/* Make room for one more entry (see hmap.h for the policy). */
static int hmap_room(struct hmap *m)
{
	uint64_t cap = m->mask ? (uint64_t)m->mask + 1 : 0;
	uint32_t want;

	/* mostly empty: shrink (best effort, the old table stays on failure) */
	if (cap > HMAP_MIN_CAP && cap > m->min_cap && (uint64_t)m->len * 8 < cap) {
		want = cap_for(2 * (m->len + 1));
		if (want < m->min_cap)
			want = m->min_cap;
		if (want < cap && !hmap_rehash(m, want))
			cap = want;
	}
	if (cap && (uint64_t)(m->used + 1) * 4 <= cap * 3)
		return 0;
	/* full of tombstones: purge them in place if that frees 1/16 */
	if (cap && (uint64_t)(m->len + 1) * 16 <= cap * 11) {
		hmap_purge(m);
		return 0;
	}
	want = cap_for(m->len + 1);
	if (want <= cap) {
		if (cap >= HMAP_MAX_CAP)
			return -ENOMEM;
		want = (uint32_t)cap * 2;
	}
	return hmap_rehash(m, want);
}

int hmap_put(struct hmap *m, uint64_t hash, void *val)
{
	uint32_t h = slot_hash(hash), i;

	if (hmap_room(m))
		return -ENOMEM;
	for (i = h & m->mask; m->val[i] && m->val[i] != HMAP_TOMB;
	     i = (i + 1) & m->mask)
		;
	if (!m->val[i])
		m->used++;
	m->hash[i] = h;
	m->val[i] = val;
	m->len++;
	return 0;
}

static void hmap_del_slot(struct hmap *m, uint32_t i)
{
	/* if the next slot is empty, this can become empty too (shortens chains) */
	if (!m->val[(i + 1) & m->mask]) {
		m->val[i] = NULL;
		m->used--;
	} else {
		m->val[i] = HMAP_TOMB;
	}
	m->len--;
}

void *hmap_del(struct hmap *m, uint64_t hash, const void *key,
               hmap_eq_fn eq, void *ctx)
{
	uint32_t h = slot_hash(hash), i;

	if (!m->mask)
		return NULL;
	for (i = h & m->mask; m->val[i]; i = (i + 1) & m->mask) {
		void *v = m->val[i];

		if (v != HMAP_TOMB && m->hash[i] == h && eq(v, key, ctx)) {
			hmap_del_slot(m, i);
			return v;
		}
	}
	return NULL;
}

bool hmap_del_ptr(struct hmap *m, uint64_t hash, const void *val)
{
	uint32_t i;

	if (!m->mask)
		return false;
	for (i = slot_hash(hash) & m->mask; m->val[i]; i = (i + 1) & m->mask) {
		if (m->val[i] == val) {
			hmap_del_slot(m, i);
			return true;
		}
	}
	return false;
}

void *hmap_next(const struct hmap *m, uint32_t *it)
{
	if (!m->mask)
		return NULL;
	while (*it <= m->mask) {
		void *v = m->val[(*it)++];

		if (v && v != HMAP_TOMB)
			return v;
	}
	return NULL;
}
