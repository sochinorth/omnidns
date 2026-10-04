/* SPDX-License-Identifier: MIT */
#ifndef OMNI_DNS_SVCB_H
#define OMNI_DNS_SVCB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wire.h"

/*
 * SVCB/HTTPS (RFC 9460) rdata handling. Input rdata is the verbatim wire
 * rdata (SVCB TargetName is never compressed).
 *
 * rdata = SvcPriority(16) TargetName(uncompressed) SvcParams*
 * SvcParam = key(16) len(16) value(len); keys must be strictly increasing.
 */

#define SVCB_KEY_ALPN		1
#define SVCB_KEY_IPV4HINT	4
#define SVCB_KEY_ECH		5
#define SVCB_KEY_IPV6HINT	6

struct svcb_view {
	uint16_t priority;		/* 0 = AliasMode */
	const uint8_t *target;		/* points into rdata */
	uint8_t target_len;
	const uint8_t *params;		/* points into rdata */
	uint16_t params_len;
};

/* Validates structure (name, param framing, increasing keys, hint lengths
 * multiple of 4/16 and non-zero). Returns 0 or -EBADMSG. */
int svcb_parse(const uint8_t *rdata, uint16_t len, struct svcb_view *out);

/* Is the target the root name "."?  (For ServiceMode it means "the owner".) */
static inline bool svcb_target_is_root(const struct svcb_view *v)
{
	return v->target_len == 1;
}

/*
 * Address mapping callback for hint rewriting.
 *  family: 4 or 6; in: 4/16 bytes; out: 4/16 bytes to write.
 * Return 0 to emit `out`, 1 to drop this address, negative errno to abort.
 */
typedef int (*svcb_addr_fn)(void *ctx, int family, const uint8_t *in, uint8_t *out);

/*
 * Rewrite ipv4hint/ipv6hint through `fn`, preserving every other param
 * byte-for-byte and key order. If all addresses of a hint are dropped the
 * whole param is removed. `drop_v6` removes ipv6hint unconditionally
 * (without calling fn).
 * Writes the new rdata to out (cap bytes) and its length to *outlen.
 * The output is never longer than the input, and cap >= len always
 * suffices (a smaller cap may fail with -ENOSPC even if the final result
 * would fit, since `mandatory` is fixed up after the hints are written).
 * Returns 0, -ENOSPC, -EBADMSG, or the callback's error.
 */
int svcb_rewrite_hints(const uint8_t *rdata, uint16_t len,
		       svcb_addr_fn fn, void *ctx, bool drop_v6,
		       uint8_t *out, size_t cap, uint16_t *outlen);

#endif
