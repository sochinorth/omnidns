/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OMNI_FAKEIP_H
#define OMNI_FAKEIP_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "util/hmap.h"
#include "util/s3fifo.h"

/*
 * Fake IP binding database (RAM only).
 *
 * Binding key:   (rule_id, mark, endpoint name (case-insensitive), family, real IP)
 * Binding value: (fake IP, safe_until, nft ticket, refcount)
 *
 * Allocation is deterministic per process:
 *   candidate_0 = pool_first + siphash(secret, key) mod pool_usable
 *   candidate_i = next usable address (linear probing, wrapping)
 * Usable addresses exclude (v4) the network and broadcast address of the
 * pool, (v6) the all-zeros host (subnet-router anycast). Pool validity
 * (no 0/8, 127/8, 224/4+, ::, ::1, ff00::/8 overlap) is enforced in config.
 *
 * Probing at most FAKEIP_MAX_PROBE candidates:
 *   - free candidate                          -> take it
 *   - occupied by an evictable binding        -> reclaim: evict that binding
 *     (expired: safe_until < now and refcnt==0)  and reuse its fake; the nft
 *                                                 op uses replace=true
 *   - occupied by a live binding              -> continue
 * If no candidate is found, run an S3-FIFO eviction pass and retry once;
 * then fail with -ENOSPC.
 *
 * Capacity: max_bindings; S3-FIFO evicts only bindings that are expired and
 * unreferenced (pinned otherwise). Eviction deletes the nft elements.
 *
 * A binding is usable for answering only after its nft ticket is done;
 * callers wait with nft_wait(b->ticket) (fakeip_ticket()).
 */

#define FAKEIP_MAX_PROBE 64

struct nft_ctx;

struct binding {
	struct s3_node s3;
	uint64_t khash;		/* key hash */
	uint64_t fhash;		/* hash of (family, fake) */
	const char *rule_id;	/* interned (owned by db) */
	uint32_t mark;
	uint8_t family;		/* 4 or 6 */
	uint8_t fake[16];
	uint8_t real[16];
	uint32_t safe_until;	/* omni_now() seconds */
	uint64_t ticket;	/* nft batch that installed it */
	uint32_t refcnt;	/* cache entries referencing it */
	uint8_t endpoint_len;
	uint8_t endpoint[];	/* lowercased wire name */
};

struct fakeip_db;

/* p4/p6 may be NULL. secret: 16 random bytes (or fixed in tests). */
struct fakeip_db *fakeip_new(const struct ip_prefix *p4, const struct ip_prefix *p6,
			     uint32_t max_bindings, uint32_t grace,
			     const uint8_t secret[16], struct nft_ctx *nft);
void fakeip_free(struct fakeip_db *db);	/* frees memory only, no nft ops */

bool fakeip_has_pool(const struct fakeip_db *db, int family);

/*
 * Get or create the binding for the key and extend
 *   safe_until = max(safe_until, now + ttl + grace).
 * New/reclaimed bindings queue nft ops. Returns NULL with *err =
 * -EAFNOSUPPORT (no pool for family), -ENOSPC (exhausted), -ENOMEM.
 */
struct binding *fakeip_bind(struct fakeip_db *db, const char *rule_id, uint32_t mark,
			    const uint8_t *endpoint, uint8_t endpoint_len,
			    int family, const uint8_t *real, uint32_t ttl, int *err);

void fakeip_ref(struct binding *b);
void fakeip_unref(struct fakeip_db *db, struct binding *b);

/* Lookup by fake address (PTR answers, tests). NULL if unmapped. */
struct binding *fakeip_lookup(struct fakeip_db *db, int family, const uint8_t *fake);
bool fakeip_in_pool(const struct fakeip_db *db, int family, const uint8_t *addr);

/*
 * Reload support.
 * fakeip_set_config(): change pools / limits / grace. Returns -EBUSY if any
 * non-evictable binding's fake lies outside the corresponding new pool (or
 * the pool is removed while such bindings exist); evictable ones outside are
 * evicted. On success the new pools are used for future allocations
 * (existing in-pool bindings keep their fakes).
 */
int fakeip_set_config(struct fakeip_db *db, const struct ip_prefix *p4,
		      const struct ip_prefix *p6, uint32_t max_bindings, uint32_t grace);
/* Number of non-evictable bindings (used to reject fwmask changes). */
uint32_t fakeip_live_count(struct fakeip_db *db);

/* Distinct marks referenced by any binding (shifted values). Returns count
 * written (at most max). */
uint32_t fakeip_marks_in_use(struct fakeip_db *db, uint32_t *out, uint32_t max);

/* Evict ALL expired, unreferenced bindings now (e.g. before an fwmask
 * change, whose old marks they still carry). Returns the number evicted. */
uint32_t fakeip_evict_expired(struct fakeip_db *db);

/* Evict expired, unreferenced bindings while over the capacity watermark. */
void fakeip_maybe_evict(struct fakeip_db *db);

uint32_t fakeip_count(const struct fakeip_db *db);

/* Iterate all bindings (for dumps): returns next or NULL. */
struct binding *fakeip_next(struct fakeip_db *db, uint32_t *it);

#endif
