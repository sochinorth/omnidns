/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OMNI_S3FIFO_H
#define OMNI_S3FIFO_H

#include <stdbool.h>
#include <stdint.h>
#include <libubox/list.h>

/*
 * Intrusive S3-FIFO (Yang et al., SOSP'23) with batched, pressure-only
 * eviction and pinning support.
 *
 *  - small FIFO (~10% of capacity), main FIFO, ghost FIFO of key hashes
 *    (same length as main).
 *  - insert: if key hash is in ghost -> main, else -> small.
 *  - hit: s3_touch() bumps freq (saturating at 3). No list movement.
 *  - eviction from small: freq>0 -> move to main (freq reset to 0),
 *    else evict and remember hash in ghost.
 *  - eviction from main: freq>0 -> freq--, reinsert at tail; else evict.
 *
 * Pinning: before evicting a node, ops->can_evict() is consulted. A pinned
 * node is treated as if it had freq>0 (it is moved/reinserted, never
 * evicted). To bound work, s3_evict() gives up after scanning
 * 2*(count) + 64 nodes without progress and returns what it achieved.
 *
 * The structure never frees nodes: ops->evict() is called after the node
 * has been unlinked, and the owner frees it.
 */

struct s3_node {
	struct list_head list;
	uint64_t hash;		/* key hash, for the ghost queue */
	uint8_t freq;
	uint8_t queue;		/* internal: S3_Q_* */
};

struct s3fifo;

struct s3_ops {
	bool (*can_evict)(struct s3fifo *s, struct s3_node *n);	/* may be NULL */
	void (*evict)(struct s3fifo *s, struct s3_node *n);
};

struct s3fifo {
	struct list_head small, main;
	uint32_t n_small, n_main;
	uint32_t cap;			/* target capacity in nodes */
	const struct s3_ops *ops;
	void *priv;
	/* ghost: ring of hashes + small open-addressed set over the ring */
	uint64_t *ghost_ring;
	uint32_t ghost_cap, ghost_head, ghost_len;
	uint64_t *ghost_set;		/* 2*ghost_cap slots, 0 = empty */
	uint32_t ghost_set_mask;
};

int s3_init(struct s3fifo *s, uint32_t cap, const struct s3_ops *ops, void *priv);
void s3_destroy(struct s3fifo *s);	/* does NOT call evict on remaining nodes */

static inline uint32_t s3_count(const struct s3fifo *s) { return s->n_small + s->n_main; }

void s3_insert(struct s3fifo *s, struct s3_node *n, uint64_t hash);
static inline void s3_touch(struct s3_node *n) { if (n->freq < 3) n->freq++; }
void s3_remove(struct s3fifo *s, struct s3_node *n);	/* external unlink, no evict cb */

/* Evict until s3_count() <= target. Returns number evicted. */
uint32_t s3_evict(struct s3fifo *s, uint32_t target);

/*
 * Watermark helper: if count > cap, evict down to cap * 7/8 in one batch.
 * Called by owners after inserts.
 */
uint32_t s3_maybe_evict(struct s3fifo *s);

#endif
