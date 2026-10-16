/* SPDX-License-Identifier: MIT */
#ifndef OMNI_RESOLVE_H
#define OMNI_RESOLVE_H

#include "dns/wire.h"

/*
 * Policy-aware resolution of one client question.
 *
 * Input: a validated query (opcode QUERY, exactly one question, class IN;
 * the server handles everything else). Output: the response in wire format
 * as dns_build() wrote it: id 0, flags QR|RA (+RD copied, AA clear), rcode,
 * the query's question, AN/NS/AR sections, no OPT. The server renders the
 * client's reply from it with dns_reply_render() (id, RD/CD, question case,
 * EDNS, size limit), the same way it renders cache hits.
 *
 * Special cases, in this order:
 *   qtype ANY             -> NOTIMP
 *   PTR for a fake pool address (in-addr.arpa / ip6.arpa under the pool)
 *                         -> answered from the binding DB, NXDOMAIN if none;
 *                            never sent upstream
 *   cache hit             -> resolve_lookup(), synchronously, before any
 *                            request is started
 *
 * The walk (see plan): state {name, upstream, latch, prefix RRs, deps}.
 *   step limit RESOLVE_MAX_STEPS (exceeded -> SERVFAIL), loop detection.
 *   block anywhere        -> block response per block_mode for the ORIGINAL
 *                            qname (NODATA: NOERROR + synthetic SOA in NS
 *                            with TTL=block_ttl; NXDOMAIN: same SOA;
 *                            NULL: A 0.0.0.0 / AAAA :: with TTL block_ttl,
 *                            NODATA for other qtypes). The alias prefix is
 *                            not included.
 *   latch                 -> pins fwmark AND upstream; later rules can only block.
 *   re-query              -> only when the effective upstream identity changes.
 *   rewrite               -> A/AAAA rdata, SVCB/HTTPS ipv4hint/ipv6hint;
 *                            when anything was rewritten, RRSIG/NSEC/NSEC3 are
 *                            removed from all sections and AD is cleared.
 *   AAAA with latch and no v6 pool -> NODATA (SOA from upstream if present).
 *
 * Synthetic SOA (block responses): owner = qname (presented as its own
 * zone apex), TTL = block_ttl, MNAME "omnidns.invalid.",
 * RNAME "hostmaster.omnidns.invalid.", serial 1, refresh/retry/expire
 * 3600/600/86400, minimum = block_ttl.
 */

#define RESOLVE_MAX_STEPS 12

struct omni;
struct resolve_req;

struct cache_hit;

/* msg (see above) is valid only during the callback; never NULL. */
typedef void (*resolve_cb)(void *ctx, const uint8_t *msg, size_t len);

/*
 * Answer from the cache, synchronously: 0 with *hit filled (the stored
 * response and its age, valid until the next cache call), or -ENOENT when
 * the query must go through resolve_start(): a miss, an entry that failed
 * revalidation, or a query that ANY/fake-PTR handling answers instead.
 * Counts as a request when it hits.
 */
int resolve_lookup(struct omni *o, const struct dns_msg *query, struct cache_hit *hit);

/* query: parsed client query (its id/edns are ignored); the cache is not
 * consulted (resolve_lookup() was). Callback is never invoked
 * synchronously. */
struct resolve_req *resolve_start(struct omni *o, const struct dns_msg *query,
                                  resolve_cb cb, void *ctx);
/* No callback after cancel. */
void resolve_cancel(struct resolve_req *r);

struct resolve_stats {
	uint64_t requests, cache_hits, blocked, fakeip_answers, servfail, requeries;
};
const struct resolve_stats *resolve_get_stats(void);

#endif
