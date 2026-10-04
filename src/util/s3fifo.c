// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <stdlib.h>

#include "s3fifo.h"

enum {
	S3_Q_NONE,
	S3_Q_SMALL,
	S3_Q_MAIN,
};

/* ghost set: linear probing with backward-shift deletion; may hold duplicates */

static inline uint64_t ghost_key(uint64_t hash)
{
	return hash ? hash : 1;
}

static bool ghost_has(const struct s3fifo *s, uint64_t h)
{
	uint32_t i;

	for (i = h & s->ghost_set_mask; s->ghost_set[i]; i = (i + 1) & s->ghost_set_mask)
		if (s->ghost_set[i] == h)
			return true;
	return false;
}

static void ghost_set_add(struct s3fifo *s, uint64_t h)
{
	uint32_t i;

	for (i = h & s->ghost_set_mask; s->ghost_set[i]; i = (i + 1) & s->ghost_set_mask)
		;
	s->ghost_set[i] = h;
}

static void ghost_set_del(struct s3fifo *s, uint64_t h)
{
	uint32_t mask = s->ghost_set_mask, i, j, k;

	for (i = h & mask; s->ghost_set[i] != h; i = (i + 1) & mask)
		if (!s->ghost_set[i])
			return;
	for (j = i;;) {
		j = (j + 1) & mask;
		if (!s->ghost_set[j])
			break;
		k = s->ghost_set[j] & mask;
		/* entry at j may stay if its home lies cyclically in (i, j] */
		if (i <= j ? (i < k && k <= j) : (i < k || k <= j))
			continue;
		s->ghost_set[i] = s->ghost_set[j];
		i = j;
	}
	s->ghost_set[i] = 0;
}

static void ghost_add(struct s3fifo *s, uint64_t hash)
{
	uint64_t h = ghost_key(hash);

	if (s->ghost_len == s->ghost_cap) {
		ghost_set_del(s, s->ghost_ring[s->ghost_head]);
		s->ghost_ring[s->ghost_head] = h;
		s->ghost_head = (s->ghost_head + 1) % s->ghost_cap;
	} else {
		s->ghost_ring[(s->ghost_head + s->ghost_len) % s->ghost_cap] = h;
		s->ghost_len++;
	}
	ghost_set_add(s, h);
}

int s3_init(struct s3fifo *s, uint32_t cap, const struct s3_ops *ops, void *priv)
{
	uint32_t gcap = cap - cap / 10, slots = 4;

	if (!gcap)
		gcap = 1;
	while (slots < 2 * (uint64_t)gcap)
		slots <<= 1;

	INIT_LIST_HEAD(&s->small);
	INIT_LIST_HEAD(&s->main);
	s->n_small = s->n_main = 0;
	s->cap = cap;
	s->ops = ops;
	s->priv = priv;
	s->ghost_cap = gcap;
	s->ghost_head = s->ghost_len = 0;
	s->ghost_set_mask = slots - 1;
	s->ghost_ring = calloc(gcap, sizeof(*s->ghost_ring));
	s->ghost_set = calloc(slots, sizeof(*s->ghost_set));
	if (!s->ghost_ring || !s->ghost_set) {
		s3_destroy(s);
		return -ENOMEM;
	}
	return 0;
}

void s3_destroy(struct s3fifo *s)
{
	free(s->ghost_ring);
	free(s->ghost_set);
	s->ghost_ring = NULL;
	s->ghost_set = NULL;
	s->ghost_cap = s->ghost_len = s->ghost_head = 0;
}

void s3_insert(struct s3fifo *s, struct s3_node *n, uint64_t hash)
{
	n->hash = hash;
	n->freq = 0;
	if (ghost_has(s, ghost_key(hash))) {
		n->queue = S3_Q_MAIN;
		list_add_tail(&n->list, &s->main);
		s->n_main++;
	} else {
		n->queue = S3_Q_SMALL;
		list_add_tail(&n->list, &s->small);
		s->n_small++;
	}
}

static void s3_unlink(struct s3fifo *s, struct s3_node *n)
{
	list_del(&n->list);
	if (n->queue == S3_Q_SMALL)
		s->n_small--;
	else if (n->queue == S3_Q_MAIN)
		s->n_main--;
	n->queue = S3_Q_NONE;
}

void s3_remove(struct s3fifo *s, struct s3_node *n)
{
	if (n->queue != S3_Q_NONE)
		s3_unlink(s, n);
}

static bool s3_pinned(struct s3fifo *s, struct s3_node *n)
{
	return s->ops->can_evict && !s->ops->can_evict(s, n);
}

static void s3_do_evict(struct s3fifo *s, struct s3_node *n)
{
	s3_unlink(s, n);
	s->ops->evict(s, n);
}

/*
 * One step at the head of small. Returns 1 if evicted, 0 if a node was
 * promoted on frequency, -1 if a pinned node blocked eviction (a stall).
 */
static int s3_step_small(struct s3fifo *s)
{
	struct s3_node *n = list_first_entry(&s->small, struct s3_node, list);
	int ret = 0;

	if (!n->freq) {
		if (!s3_pinned(s, n)) {
			ghost_add(s, n->hash);
			s3_do_evict(s, n);
			return 1;
		}
		ret = -1;
	}
	list_move_tail(&n->list, &s->main);
	n->queue = S3_Q_MAIN;
	n->freq = 0;
	s->n_small--;
	s->n_main++;
	return ret;
}

static int s3_step_main(struct s3fifo *s)
{
	struct s3_node *n = list_first_entry(&s->main, struct s3_node, list);

	if (n->freq) {
		n->freq--;
		list_move_tail(&n->list, &s->main);
		return 0;
	}
	if (s3_pinned(s, n)) {
		list_move_tail(&n->list, &s->main);
		return -1;
	}
	s3_do_evict(s, n);
	return 1;
}

uint32_t s3_evict(struct s3fifo *s, uint32_t target)
{
	uint32_t small_target = s->cap / 10 ? s->cap / 10 : 1;
	uint32_t evicted = 0;
	uint64_t stalls = 0;

	while (s3_count(s) > target) {
		int r;

		/* a full stalled pass over main also falls back to small */
		if (s->n_small && (s->n_small >= small_target || stalls >= s->n_main))
			r = s3_step_small(s);
		else
			r = s3_step_main(s);
		/* freq decrements and promotions are finite, so only stalls bound the scan */
		if (r > 0)
			evicted++;
		if (r >= 0)
			stalls = 0;
		else if (++stalls >= 2 * (uint64_t)s3_count(s) + 64)
			break;
	}
	return evicted;
}

uint32_t s3_maybe_evict(struct s3fifo *s)
{
	if (s3_count(s) <= s->cap)
		return 0;
	return s3_evict(s, (uint32_t)((uint64_t)s->cap * 7 / 8));
}
