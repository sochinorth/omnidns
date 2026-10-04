/* SPDX-License-Identifier: GPL-2.0-only */
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
 * share one exchange; each caller gets its own callback with the same
 * parsed response.
 *
 * Callbacks are never invoked synchronously from upstream_query().
 */

struct upstream_query;

/* resp is valid only during the callback. */
typedef void (*upstream_cb)(void *ctx, int err, const struct dns_msg *resp);

void upstream_init(uint32_t try_timeout_ms, uint32_t total_timeout_ms);
void upstream_set_timeouts(uint32_t try_timeout_ms, uint32_t total_timeout_ms);

struct upstream_query *upstream_query(struct upstream_set *u,
				      const uint8_t *qname, uint8_t qlen, uint16_t qtype,
				      upstream_cb cb, void *ctx);
/* Callback will not be invoked after cancel. */
void upstream_cancel(struct upstream_query *q);

/* Cancel everything (shutdown). */
void upstream_shutdown(void);

struct upstream_stats {
	uint64_t queries, coalesced, udp_sent, tcp_sent, timeouts, failures, spoofed;
};
const struct upstream_stats *upstream_get_stats(void);

#endif
