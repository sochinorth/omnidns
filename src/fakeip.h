/* SPDX-License-Identifier: MIT */
#ifndef OMNI_FAKEIP_H
#define OMNI_FAKEIP_H

#include <stdbool.h>
#include <stddef.h>
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
 * The (rule_id, mark) pair -- the binding's policy -- is stored as a 16-bit
 * index into a db-owned table of interned pairs, refcounted by bindings
 * (attached or detached-but-referenced); a pair's slot is freed and its
 * index reused when its last binding goes. At most FAKEIP_MAX_POLICIES
 * pairs exist at once; beyond that fakeip_bind() fails with -ENOSPC.
 *
 * Allocation is deterministic for a given secret, which a restarted
 * process takes over from the nft table (nft_adopt()):
 *   candidate_0 = pool_first + siphash(secret, key) mod pool_usable
 *   candidate_i = next usable address (linear probing, wrapping)
 * Usable addresses exclude (v4) the network and broadcast address of the
 * pool, (v6) the all-zeros host (subnet-router anycast). Pool validity
 * (no 0/8, 127/8, 224/4+, ::, ::1, ff00::/8 overlap) is enforced in config.
 *
 * Probing at most FAKEIP_MAX_PROBE candidates:
 *   - free candidate                          -> take it
 *   - occupied by an evictable binding        -> reclaim: evict that binding
 *     (expired: safe_until < now and refcnt==0)  and reuse its fake (the nft
 *                                                 add replaces its elements)
 *   - occupied by a live binding              -> continue
 *   - a placeholder with the key's (family, real, mark) -> claim it
 *     (searched over the whole window while placeholders exist)
 * If no candidate is found, run an S3-FIFO eviction pass and retry once;
 * then fail with -ENOSPC. (A pass is skipped while the last one stalled,
 * see fakeip_evict_scans().)
 *
 * Capacity: max_bindings; S3-FIFO evicts only bindings that are expired and
 * unreferenced (pinned otherwise). Eviction deletes the nft elements.
 *
 * A binding is usable for answering only after its nft ticket is done;
 * callers wait with nft_wait(b->ticket).
 */

#define FAKEIP_MAX_PROBE 64
#define FAKEIP_MAX_POLICIES 65535	/* policy ids 0..65534 */

struct nft_ctx;
struct nft_elem;

/*
 * Layout: no padding holes, the endpoint follows the fixed part directly
 * and bindings are allocated as offsetof(endpoint) + endpoint_len. The key
 * hash is not stored: by_key uses s3.hash (its low 32 bits; hmap keeps
 * only 31), and the 64-bit value is only needed when allocating. The
 * by_fake hash is recomputed from (family, fake) on removal.
 *
 * Rule id and mark live in the db's policy table: read them with
 * fakeip_rule_id() / fakeip_mark().
 */
struct binding {
	struct s3_node s3;	/* s3.hash: low 32 bits of the key hash (hmap keeps 31) */
	uint64_t ticket;	/* nft batch that installed it */
	uint32_t safe_until;	/* omni_now() seconds */
	uint32_t refcnt;	/* cache entries referencing it */
	uint16_t policy;	/* (rule_id, mark) index, owned by db */
	uint8_t family;		/* 4 or 6 */
	uint8_t endpoint_len;
	uint8_t fake[16];
	uint8_t real[16];
	uint8_t endpoint[];	/* lowercased wire name */
};

/* s3 (2 pointers + 8) + ticket + 2 * u32 + u16 + 2 + 2 * 16:
 * 76 bytes on LP64, 68 on ILP32. Endpoints that fit the smaller classes:
 * ILP32 musl 96 B slots up to 24 bytes; LP64 musl 112 B up to 32, glibc
 * 112 B chunks up to 28. */
_Static_assert(offsetof(struct binding, endpoint) == 2 * sizeof(void *) + 60,
               "binding layout");

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
 * -EAFNOSUPPORT (no pool for family), -ESTALE (no nft chain for `mark`:
 * a walk latched it before an fwmask change), -ENOSPC (exhausted), -ENOMEM.
 */
struct binding *fakeip_bind(struct fakeip_db *db, const char *rule_id, uint32_t mark,
                            const uint8_t *endpoint, uint8_t endpoint_len,
                            int family, const uint8_t *real, uint32_t ttl, int *err);

/* The binding's policy; valid as long as the binding (or a reference). */
const char *fakeip_rule_id(const struct fakeip_db *db, const struct binding *b);
uint32_t fakeip_mark(const struct fakeip_db *db, const struct binding *b);

/* Policy table introspection (tests, dumps): distinct live pairs, and the
 * number of bindings holding the pair (0 if not interned). */
uint32_t fakeip_policy_count(const struct fakeip_db *db);
uint32_t fakeip_policy_refs(const struct fakeip_db *db, const char *rule_id, uint32_t mark);

void fakeip_ref(struct binding *b);
void fakeip_unref(struct fakeip_db *db, struct binding *b);

/* Lookup by fake address (PTR answers, tests). NULL if unmapped or a
 * placeholder. */
struct binding *fakeip_lookup(struct fakeip_db *db, int family, const uint8_t *fake);

/*
 * Adoption at startup (main.c, after nft_adopt()): a map element the
 * kernel still holds from an earlier process becomes a placeholder
 * binding: fake -> (real, mark) under a reserved policy (rule id ""), no
 * endpoint, refcnt 0, its ticket done (0), safe_until = now + hold (hold:
 * fakeip_ttl_max + fakeip_grace, the longest a client may have been told
 * to keep it, or what the hold file says is left). Placeholders count against max_bindings and are evicted like any
 * expired binding (their elements destroyed). A bind whose key maps to the
 * same (family, real, mark) claims a placeholder it probes: the binding
 * takes over that fake with no nft op (the kernel has the mapping) and
 * keeps at least its safe_until; a placeholder with another mapping is a
 * live binding to every other bind until it expires.
 * Returns 0, -EINVAL (fake not allocatable in the current pools), -ESTALE
 * (no chain for `mark`), -EEXIST (fake taken), -ENOSPC (max_bindings
 * reached), -ENOMEM; the caller then destroys the element.
 */
int fakeip_adopt(struct fakeip_db *db, int family, const uint8_t *fake, const uint8_t *real,
                 uint32_t mark, uint32_t hold);
/*
 * Hold file: what a cleanly exiting process knows and its successor does
 * not, i.e. which map elements a client may still use and for how long.
 * Written at exit (main.c, after the last element batch is acked) and read
 * back at adoption; see docs/DESIGN.md (Restart) for the format.
 *
 * fakeip_hold_save(): one record (family, fake, remaining hold) per binding
 * that is not evictable now (placeholders included): hold = safe_until - now
 * (0 if past, for a referenced binding). `clock` is the CLOCK_BOOTTIME
 * second of the write, `secret` the table's (fingerprinted, never stored).
 * Written to a temporary file renamed over `path`. Returns 0 or -errno.
 */
int fakeip_hold_save(struct fakeip_db *db, const char *path, uint64_t clock);

struct fakeip_hold;

/*
 * Read the hold file at `path` and delete it (whatever it holds). Returns
 * it with every hold reduced by `clock` - its write time (clamped at 0), or
 * NULL with *err: -ENOENT (no file), -ESTALE (another table's secret or
 * another layout), -ERANGE (written in the future: another boot), -E2BIG
 * (more than max_records), -EINVAL (malformed: truncated, trailing bytes,
 * bad record, duplicate), -errno. NULL means "trust nothing".
 */
struct fakeip_hold *fakeip_hold_load(const char *path, const uint8_t secret[16],
                                     uint32_t max_records, uint64_t clock, int *err);
void fakeip_hold_free(struct fakeip_hold *h);
uint32_t fakeip_hold_count(const struct fakeip_hold *h);
/* true if listed, its adjusted hold in *hold */
bool fakeip_hold_find(const struct fakeip_hold *h, int family, const uint8_t *fake,
                      uint32_t *hold);

/*
 * Adoption of the elements nft_adopt() read: each consistent element (ok)
 * becomes a placeholder (fakeip_adopt()) held for `hold`, or, given a hold
 * file `h`, for the hold it lists; an element `h` does not list was
 * evictable when the earlier process exited. Every element not adopted is
 * destroyed (nft_elem_del(), queued). Returns the number adopted.
 */
uint32_t fakeip_adopt_elems(struct fakeip_db *db, const struct nft_elem *el, uint32_t nel,
                            uint32_t hold, const struct fakeip_hold *h);

/* true if `fake` holds a placeholder (its mark in *mark if non-NULL); tests */
bool fakeip_placeholder(struct fakeip_db *db, int family, const uint8_t *fake, uint32_t *mark);
uint32_t fakeip_placeholders(const struct fakeip_db *db);	/* unclaimed */
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
/* Number of non-evictable bindings now. */
uint32_t fakeip_live_count(struct fakeip_db *db);

/* Evict ALL expired, unreferenced bindings now (e.g. before an fwmask
 * change, whose old marks they still carry). Returns the number evicted. */
uint32_t fakeip_evict_expired(struct fakeip_db *db);

/*
 * Before an fwmask change: evict every expired, unreferenced binding and
 * return how many bindings are left. All of it is decided at one clock
 * reading, so each binding left was non-evictable at that instant (live);
 * the change is safe only when this returns 0 (the maps are then flushed,
 * and a binding left behind would be served without kernel elements).
 */
uint32_t fakeip_remask_blockers(struct fakeip_db *db);

/* Evict expired, unreferenced bindings while over the capacity watermark;
 * called periodically (also releases an idle S3-FIFO ghost). */
void fakeip_maybe_evict(struct fakeip_db *db);

/*
 * Eviction passes run so far (tests). A pass that finds every binding
 * pinned is not repeated until one of them can become evictable (time
 * reaches its safe_until, or its last reference goes) or the
 * configuration changes, so a full table makes a failing bind O(1).
 */
uint32_t fakeip_evict_scans(const struct fakeip_db *db);

uint32_t fakeip_count(const struct fakeip_db *db);

/* Iterate all bindings (for dumps): returns next or NULL. */
struct binding *fakeip_next(struct fakeip_db *db, uint32_t *it);

#endif
