/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OMNI_CACHE_H
#define OMNI_CACHE_H

#include <stdint.h>

#include "config.h"
#include "dns/wire.h"

/*
 * Cache of complete, policy-aware resolution results.
 *
 * Key: (lowercased qname, qtype, qclass).
 * Value: the final response message (sections + rcode/flags, no OPT),
 *        insert time, lifetime, dependency list, binding refs, config gen.
 *
 * Dependencies: every name whose rule match influenced the result (each
 * walk step, each ServiceMode TargetName) is recorded with the matched
 * rule's fingerprint. On lookup, if entry->gen != cfg->gen, each dep name is
 * re-matched against cfg; any fingerprint mismatch drops the entry (miss).
 * Otherwise entry->gen is updated to cfg->gen.
 *
 * TTLs: returned copies have every RR TTL reduced by the elapsed time
 * (floored at 0). An entry is served until insert + lifetime; then it is a
 * miss and dropped.
 *
 * Eviction: S3-FIFO bounded by max_entries and max_bytes, batched.
 * Dropping an entry releases its binding refs (fakeip_unref); it never
 * deletes bindings directly.
 */

#define CACHE_MAX_DEPS 32
#define CACHE_MAX_BINDS 64

struct cache;
struct fakeip_db;
struct binding;

struct cache_dep {
	struct dns_name name;		/* lowercased */
	uint64_t fingerprint;		/* of the rule the name matched */
};

struct cache *cache_new(uint32_t max_entries, size_t max_bytes, struct fakeip_db *fdb);
void cache_free(struct cache *c);
void cache_set_limits(struct cache *c, uint32_t max_entries, size_t max_bytes);

/* Returns 0 on hit (out filled, out->id/edns untouched, qname case as
 * stored) or -ENOENT. `out` must be initialized; it is reset first. */
int cache_lookup(struct cache *c, const struct config *cfg,
		 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
		 struct dns_msg *out);

/*
 * Insert/replace. `lifetime` seconds (0 => not cached). Takes a reference on
 * each binding. ndeps > CACHE_MAX_DEPS or nbinds > CACHE_MAX_BINDS => not
 * cached (returns -E2BIG).
 */
int cache_insert(struct cache *c, const struct config *cfg,
		 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
		 const struct dns_msg *resp, uint32_t lifetime,
		 const struct cache_dep *deps, uint16_t ndeps,
		 struct binding *const *binds, uint16_t nbinds);

void cache_flush(struct cache *c);
/*
 * Drop every expired entry (releasing its binding refs, so expired bindings
 * become reclaimable). Called periodically; returns entries dropped.
 */
uint32_t cache_sweep_expired(struct cache *c);
uint32_t cache_count(const struct cache *c);
size_t cache_bytes(const struct cache *c);

#endif
