/* SPDX-License-Identifier: MIT */
#ifndef OMNI_UPSTREAM_H
#define OMNI_UPSTREAM_H

#include <stdint.h>

#include "config.h"
#include "dns/wire.h"

/*
 * Asynchronous upstream DNS client on uloop.
 *
 * Query policy for an upstream_set: servers are tried in order. For each:
 *   - UDP from a fresh socket (kernel-random source port), random 16-bit ID,
 *     EDNS0 OPT with udp_size 1232, DO=0, RD=1, no other options.
 *     Responses are accepted only from the exact server address/port, with
 *     matching ID, QR=1, opcode 0, and a question equal (case-insensitive)
 *     to the one sent; anything else is ignored (keep waiting).
 *   - TC=1 -> retry the same server once over TCP (2-byte length framing).
 *   - rcode SERVFAIL/REFUSED/NOTIMP/FORMERR, unparsable response, socket
 *     error, or per-try timeout -> next server.
 *   - NOERROR / NXDOMAIN (and others) -> deliver.
 * An overall deadline (total timeout) bounds the whole query.
 * When all servers fail, cb gets err=-ETIMEDOUT or -EIO and resp=NULL.
 *
 * Coalescing: concurrent queries with equal (set id, qname (ci), qtype)
 * share one exchange; each caller gets its own callback and its own copy of
 * the parsed response (the last caller gets the parsed message itself, so
 * the common uncoalesced case copies nothing).
 *
 * Callbacks are never invoked synchronously from upstream_query().
 */

struct upstream_query;

/*
 * resp is valid only during the callback, but it belongs to this caller
 * alone: the callback may take it over, preferably by swapping it with an
 * empty message of its own (dns_msg_swap(), so that the storage of that one
 * is reused for a later response), or by moving it out (`*mine = *resp;
 * dns_msg_init(resp);`). Whatever is left in it is reset or freed after the
 * callback.
 */
typedef void (*upstream_cb)(void *ctx, int err, struct dns_msg *resp);

void upstream_init(uint32_t try_timeout_ms, uint32_t total_timeout_ms);
void upstream_set_timeouts(uint32_t try_timeout_ms, uint32_t total_timeout_ms);

struct upstream_query *upstream_query(struct upstream_set *u,
                                      const uint8_t *qname, uint8_t qlen, uint16_t qtype,
                                      upstream_cb cb, void *ctx);
/*
 * Callback will not be invoked after cancel. The handle is valid until its
 * callback returns or it is cancelled, whichever comes first: cancelling
 * from inside its own callback is a no-op, after it a use after free. NULL
 * from upstream_query() (out of memory) means no callback will come.
 */
void upstream_cancel(struct upstream_query *q);

/* Cancel everything (shutdown). */
void upstream_shutdown(void);

struct upstream_stats {
	uint64_t queries, coalesced, udp_sent, tcp_sent, timeouts, failures, spoofed;
};
const struct upstream_stats *upstream_get_stats(void);

/*
 * Write the upstream query for (name, qtype) into out: header with id 0 and
 * RD, the question with `name` copied verbatim at out + 12 (the caller
 * validates and lowercases it), and the OPT RR described above. Returns the
 * length or -ENOSPC. Exposed for tests.
 */
int upstream_build_query(uint8_t *out, size_t cap, const uint8_t *name,
                         uint8_t len, uint16_t qtype);

#endif
