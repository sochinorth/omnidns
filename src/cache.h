/* SPDX-License-Identifier: MIT */
#ifndef OMNI_CACHE_H
#define OMNI_CACHE_H

#include <stdint.h>
#include <string.h>

#include "config.h"
#include "dns/wire.h"

/*
 * Cache of complete, policy-aware resolution results.
 *
 * Key: (qname, qtype, qclass), the name compared case-insensitively.
 * Value: the final response in wire format as dns_build() wrote it (one
 *        question, no OPT), insert time, lifetime, dependency list, binding
 *        refs, config gen. A hit hands out those bytes and the entry's age;
 *        dns_reply_render() turns them into the client's reply.
 *
 * Dependencies: every name whose rule match influenced the result (each
 * walk step, each ServiceMode TargetName) is recorded with the matched
 * rule's fingerprint. On lookup, if entry->gen != cfg->gen, each dep name is
 * re-matched against cfg; any fingerprint mismatch drops the entry (miss).
 * Otherwise entry->gen is updated to cfg->gen.
 *
 * An entry is served until insert + lifetime; then it is a miss and dropped.
 *
 * Eviction: S3-FIFO bounded by max_entries and max_bytes, batched.
 * Dropping an entry releases its binding refs (fakeip_unref); it never
 * deletes bindings directly.
 */

#define CACHE_MAX_DEPS 32
#define CACHE_MAX_BINDS 64
/* Accounted per entry on top of its allocation: hmap slot, s3 ghost slot,
 * allocator slack. */
#define CACHE_ENTRY_OVERHEAD 64

struct cache;
struct fakeip_db;
struct binding;

/*
 * Dependencies are passed packed, in the form the entry stores them: per
 * dependency the matched rule's fingerprint (u64, host order), the name's
 * length (u8) and the lowercased name, where length 0 stands for the qname.
 */
#define CACHE_DEP_HDR 9

/* Append one dependency at p (at most CACHE_DEP_HDR + len bytes); returns
 * the bytes written. */
static inline size_t cache_dep_put(uint8_t *p, uint64_t fingerprint,
                                   const uint8_t *name, uint8_t len,
                                   const uint8_t *qname, uint8_t qlen)
{
	if (dns_name_eq(name, len, qname, qlen))
		len = 0;
	memcpy(p, &fingerprint, 8);
	p[8] = len;
	memcpy(p + CACHE_DEP_HDR, name, len);
	dns_name_lower(p + CACHE_DEP_HDR, len);
	return CACHE_DEP_HDR + len;
}

struct cache *cache_new(uint32_t max_entries, size_t max_bytes, struct fakeip_db *fdb);
void cache_free(struct cache *c);
void cache_set_limits(struct cache *c, uint32_t max_entries, size_t max_bytes);

/* The key's hash, as lookups and inserts take it (a miss and the insert
 * that follows it hash the key once). */
uint64_t cache_hash(const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass);

struct cache_hit {
	const uint8_t *msg;	/* the stored response (see above) */
	uint16_t len;
	uint32_t age;		/* seconds since insert: subtract from TTLs */
};

/* Returns 0 on hit, or -ENOENT. hit->msg points into the entry and stays
 * valid only until the next call into the cache. */
int cache_lookup(struct cache *c, const struct config *cfg,
                 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
                 uint64_t hash, struct cache_hit *hit);

/*
 * Insert/replace. msg: the response as dns_build() wrote it, with exactly
 * one question whose name is qname (any case; it is the key's stored
 * case), no OPT. `lifetime` seconds (0 => not cached). Takes a reference
 * on each binding. deps: ndeps packed dependencies, dsz bytes (see above).
 * ndeps > CACHE_MAX_DEPS or nbinds > CACHE_MAX_BINDS => not cached (returns
 * -E2BIG); a msg without that question => -EINVAL.
 */
int cache_insert(struct cache *c, const struct config *cfg,
                 const uint8_t *qname, uint8_t qlen, uint16_t qtype, uint16_t qclass,
                 uint64_t hash, const uint8_t *msg, size_t mlen, uint32_t lifetime,
                 const uint8_t *deps, size_t dsz, uint16_t ndeps,
                 struct binding *const *binds, uint16_t nbinds);

void cache_flush(struct cache *c);
/*
 * Drop every expired entry (releasing its binding refs, so expired bindings
 * become reclaimable). Called periodically; returns entries dropped. At
 * most one walk per second: a second call within the same omni_now()
 * second returns 0 at once (it would find nothing). Also releases the
 * eviction ghost once idle (s3_ghost_trim()).
 */
uint32_t cache_sweep_expired(struct cache *c);
uint32_t cache_count(const struct cache *c);
size_t cache_bytes(const struct cache *c);

#endif
