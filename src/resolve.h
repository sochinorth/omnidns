/* SPDX-License-Identifier: MIT */
#ifndef OMNI_RESOLVE_H
#define OMNI_RESOLVE_H

#include "dns/wire.h"

/*
 * Policy-aware resolution of one client question.
 *
 * Input: a validated query (opcode QUERY, exactly one question, class IN;
 * the server handles everything else). Output: a response dns_msg whose
 * flags carry QR|RA (+RD copied, AA clear), rcode, and AN/NS/AR sections.
 * The server stamps id, question (client's original bytes/case) and EDNS.
 *
 * Special cases handled here:
 *   qtype ANY             -> NOTIMP
 *   PTR for a fake pool address (in-addr.arpa / ip6.arpa under the pool)
 *                         -> answered from the binding DB, NXDOMAIN if none;
 *                            never sent upstream
 *   cache hit             -> answered from cache
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

/* resp is valid only during the callback; never NULL. */
typedef void (*resolve_cb)(void *ctx, const struct dns_msg *resp);

/* query: parsed client query (its id/edns are ignored). Callback is never
 * invoked synchronously. */
struct resolve_req *resolve_start(struct omni *o, const struct dns_msg *query,
				  resolve_cb cb, void *ctx);
/* No callback after cancel. */
void resolve_cancel(struct resolve_req *r);

struct resolve_stats {
	uint64_t requests, cache_hits, blocked, fakeip_answers, servfail, requeries;
};
const struct resolve_stats *resolve_get_stats(void);

#endif
