// SPDX-License-Identifier: MIT
#include <errno.h>
#include <stdlib.h>

#include "hmap.h"

#define HMAP_TOMB ((void *)(uintptr_t)1)
#define HMAP_MIN_CAP 16
#define HMAP_SLOT_BYTES (sizeof(void *) + sizeof(uint32_t))

/* 12 B/slot on LP64, 8 B on ILP32 (was 16 B on both with a u64 hash). */
_Static_assert(HMAP_SLOT_BYTES == 12 || HMAP_SLOT_BYTES == 8,
               "hmap slot = 32-bit hash + value pointer");
/* the hash array sits right after the val array in the same allocation */
_Static_assert(_Alignof(uint32_t) <= _Alignof(void *), "hash array alignment");

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

static uint32_t cap_for(uint32_t n)
{
	uint32_t cap = HMAP_MIN_CAP;

	while (cap < 0x80000000u && (uint64_t)n * 4 >= (uint64_t)cap * 3)
		cap <<= 1;
	return cap;
}

int hmap_reserve(struct hmap *m, uint32_t n)
{
	uint32_t cap = cap_for(n);

	if (m->mask && cap <= m->mask + 1)
		return 0;
	return hmap_rehash(m, cap);
}

void hmap_free(struct hmap *m)
{
	free(m->val);
	m->val = NULL;
	m->hash = NULL;
	m->mask = m->len = m->used = 0;
}

size_t hmap_footprint(const struct hmap *m)
{
	return m->mask ? ((size_t)m->mask + 1) * HMAP_SLOT_BYTES : 0;
}

void *hmap_get(const struct hmap *m, uint64_t hash, const void *key,
               hmap_eq_fn eq, void *ctx)
{
	uint32_t h = (uint32_t)hash, i;

	if (!m->mask)
		return NULL;
	for (i = h & m->mask; m->val[i]; i = (i + 1) & m->mask) {
		void *v = m->val[i];

		if (v != HMAP_TOMB && m->hash[i] == h && eq(v, key, ctx))
			return v;
	}
	return NULL;
}

int hmap_put(struct hmap *m, uint64_t hash, void *val)
{
	uint32_t h = (uint32_t)hash, i;

	if (!m->mask || (uint64_t)(m->used + 1) * 4 > (uint64_t)(m->mask + 1) * 3) {
		/* grow only if live entries need it; otherwise just purge tombstones */
		uint32_t cap = cap_for(m->len + 1);

		if (m->mask && cap < m->mask + 1)
			cap = m->mask + 1;
		if (hmap_rehash(m, cap))
			return -ENOMEM;
	}
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
	uint32_t h = (uint32_t)hash, i;

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
	for (i = (uint32_t)hash & m->mask; m->val[i]; i = (i + 1) & m->mask) {
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
