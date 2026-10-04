// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <stdlib.h>

#include "hmap.h"

#define HMAP_TOMB ((void *)(uintptr_t)1)
#define HMAP_MIN_CAP 16

static int hmap_rehash(struct hmap *m, uint32_t cap)
{
	struct hmap_slot *old = m->slots, *slots;
	uint32_t oldcap = m->mask ? m->mask + 1 : 0, i;

	slots = calloc(cap, sizeof(*slots));
	if (!slots)
		return -ENOMEM;
	m->slots = slots;
	m->mask = cap - 1;
	m->used = m->len;
	for (i = 0; i < oldcap; i++) {
		void *v = old[i].val;
		uint32_t j;

		if (!v || v == HMAP_TOMB)
			continue;
		for (j = old[i].hash & m->mask; slots[j].val; j = (j + 1) & m->mask)
			;
		slots[j] = old[i];
	}
	free(old);
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
	free(m->slots);
	m->slots = NULL;
	m->mask = m->len = m->used = 0;
}

void *hmap_get(const struct hmap *m, uint64_t hash, const void *key,
	       hmap_eq_fn eq, void *ctx)
{
	uint32_t i;

	if (!m->mask)
		return NULL;
	for (i = hash & m->mask; m->slots[i].val; i = (i + 1) & m->mask) {
		struct hmap_slot *s = &m->slots[i];

		if (s->val != HMAP_TOMB && s->hash == hash && eq(s->val, key, ctx))
			return s->val;
	}
	return NULL;
}

int hmap_put(struct hmap *m, uint64_t hash, void *val)
{
	uint32_t i;

	if (!m->mask || (uint64_t)(m->used + 1) * 4 > (uint64_t)(m->mask + 1) * 3) {
		/* grow only if live entries need it; otherwise just purge tombstones */
		uint32_t cap = cap_for(m->len + 1);

		if (m->mask && cap < m->mask + 1)
			cap = m->mask + 1;
		if (hmap_rehash(m, cap))
			return -ENOMEM;
	}
	for (i = hash & m->mask; m->slots[i].val && m->slots[i].val != HMAP_TOMB;
	     i = (i + 1) & m->mask)
		;
	if (!m->slots[i].val)
		m->used++;
	m->slots[i].hash = hash;
	m->slots[i].val = val;
	m->len++;
	return 0;
}

static void hmap_del_slot(struct hmap *m, uint32_t i)
{
	/* if the next slot is empty, this can become empty too (shortens chains) */
	if (!m->slots[(i + 1) & m->mask].val) {
		m->slots[i].val = NULL;
		m->used--;
	} else {
		m->slots[i].val = HMAP_TOMB;
	}
	m->len--;
}

void *hmap_del(struct hmap *m, uint64_t hash, const void *key,
	       hmap_eq_fn eq, void *ctx)
{
	uint32_t i;

	if (!m->mask)
		return NULL;
	for (i = hash & m->mask; m->slots[i].val; i = (i + 1) & m->mask) {
		struct hmap_slot *s = &m->slots[i];

		if (s->val != HMAP_TOMB && s->hash == hash && eq(s->val, key, ctx)) {
			void *v = s->val;

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
	for (i = hash & m->mask; m->slots[i].val; i = (i + 1) & m->mask) {
		if (m->slots[i].val == val) {
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
		void *v = m->slots[(*it)++].val;

		if (v && v != HMAP_TOMB)
			return v;
	}
	return NULL;
}
