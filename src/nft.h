/* SPDX-License-Identifier: MIT */
#ifndef OMNI_NFT_H
#define OMNI_NFT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <libubox/list.h>

#include "config.h"

/*
 * nftables dataplane, owned exclusively by omnidns: table `inet omnidns`
 * (name overridable for tests via nft_open()).
 *
 * Objects (M = fwmask, V = a shifted mark value):
 *
 *   map fake2real_v4 { type ipv4_addr : ipv4_addr }
 *   map fake2mark_v4 { type ipv4_addr : verdict }
 *   map fake2real_v6 { type ipv6_addr : ipv6_addr }
 *   map fake2mark_v6 { type ipv6_addr : verdict }
 *
 *   chain mark_%08x {            # one per V in use
 *     meta mark set meta mark & ~M | V
 *     ct mark set ct mark & ~M | V
 *   }
 *   chain restore_marks {        # regular chain, jumped to from hooks
 *     ct mark & M vmap { V1 : jump mark_V1, ... }     # omitted when no marks
 *   }
 *   chain prerouting_mangle  { type filter hook prerouting priority mangle; policy accept;
 *     jump restore_marks }
 *   chain output_mangle      { type route hook output priority mangle; policy accept;
 *     jump restore_marks }
 *   chain prerouting_dstnat  { type nat hook prerouting priority dstnat; policy accept;
 *     ip daddr POOL4 ip daddr vmap @fake2mark_v4      # jumps mark_V, which sets meta+ct mark
 *     ip daddr POOL4 dnat ip to ip daddr map @fake2real_v4
 *     (same for ip6 / POOL6) }
 *   chain output_dstnat      { type nat hook output priority -100; same rules }
 *   chain forward_reject     { type filter hook forward priority filter - 1; policy accept;
 *     ip daddr POOL4 reject                 # only unmapped fakes still have pool daddr
 *     ip6 daddr POOL6 reject }
 *   chain output_reject      { type filter hook output priority filter - 1; same }
 *
 * (vmap miss in prerouting_dstnat falls through; dnat map miss -> the
 * rule does not match and the packet keeps the fake daddr -> rejected.)
 *
 * Control-plane operations (bootstrap/reconcile) are synchronous netlink
 * transactions. Element updates are queued into an open batch which is
 * submitted asynchronously (from a uloop timeout of 0 ms, or immediately
 * when it reaches NFT_BATCH_MAX operations); completion is tracked by
 * "tickets" (monotonic batch sequence numbers). Elements are encoded
 * straight into persistent netlink buffers (see nft.c), which grow during
 * a burst and shrink back afterwards.
 */

#define NFT_BATCH_MAX 1024
#define NFT_SECRET_LEN 16
/* version of the table layout (table userdata, rule tags); nft_adopt()
 * takes over only a table of this version (2: every rule tagged; a table of
 * version 1 is bootstrapped) */
#define NFT_LAYOUT_VERSION 2

struct nft_ctx;

struct nft_desired {
	uint32_t fwmask;
	bool has_pool4, has_pool6;
	struct ip_prefix pool4, pool6;
	const uint32_t *marks;		/* shifted values, any order, may repeat */
	uint32_t nmarks;
};

/* `table` NULL means "omnidns". Opens/binds the netlink socket. */
struct nft_ctx *nft_open(const char *table);
void nft_close(struct nft_ctx *n);	/* does not delete the table */

/*
 * The fake IP allocation secret stored in the table's userdata (with a
 * layout version and the fwmask) whenever this context creates the table;
 * zero until set.
 */
void nft_set_secret(struct nft_ctx *n, const uint8_t secret[NFT_SECRET_LEN]);

/* Delete table if present, create everything per `d` (empty maps). Sync. */
int nft_bootstrap(struct nft_ctx *n, const struct nft_desired *d);

/* A map element of an existing table, paired per fake (see nft_adopt()). */
struct nft_elem {
	uint8_t family;		/* 4 or 6 */
	bool ok;		/* fake -> real and fake -> jump mark_<mark>, chain known */
	uint32_t mark;
	uint8_t fake[16];
	uint8_t real[16];
};

/*
 * Startup instead of nft_bootstrap(): take over the table an earlier
 * process left. Returns 1 if the table exists with this layout version and
 * d->fwmask (pools and marks of `d` are not compared), not dormant, with
 * every fixed chain of its type, hook and priority, regular mark chains and
 * the four maps of their types, and could be read: `secret` gets its secret
 * (also kept for re-creations), the shadow state is rebuilt from the kernel
 * (its mark chains, d's pools), and *elems (malloc'ed, sorted by family and
 * fake, *nelems of them) holds the map elements. Every rule records what it
 * was written for: a chain whose rules are not exactly those, or a base
 * chain whose policy is not accept, is rewritten by the next reconcile.
 * Nothing in the kernel is changed: the caller destroys the elements it
 * does not keep, then calls nft_reconcile(). Returns 0 otherwise (logged),
 * also for more than `max_elems` elements in the fake2real or the
 * fake2mark maps, a read error, or dumps interrupted by commits elsewhere
 * 16 times over; then bootstrap. Sync.
 */
int nft_adopt(struct nft_ctx *n, const struct nft_desired *d, uint32_t max_elems,
              uint8_t secret[NFT_SECRET_LEN], struct nft_elem **elems, uint32_t *nelems);

/*
 * Bring chains/rules to `d` in one atomic transaction without touching map
 * contents: add missing mark chains, rewrite restore/dstnat/reject rules,
 * delete mark chains no longer desired. Caller guarantees that no map
 * element references a chain being deleted. A new fwmask instead recreates
 * the whole table (empty maps, the same secret); it fails if the table is
 * gone. On failure nothing changes and the shadow state is kept. If `d`
 * equals the shadow state (the state of the last successful bootstrap,
 * reconcile or adoption whose chains were all current), no transaction is
 * sent: external edits to our chains are not repaired then. Sync.
 */
int nft_reconcile(struct nft_ctx *n, const struct nft_desired *d);

/* true if chain mark_<mark> exists (desired at the last successful
 * bootstrap/reconcile), i.e. nft_elem_add() with this mark can succeed. */
bool nft_mark_known(const struct nft_ctx *n, uint32_t mark);

/* Delete the whole table (shutdown with -x / tests). Sync. */
int nft_destroy_table(struct nft_ctx *n);

/* ---- async element batches ---- */

/*
 * Queue: add fake -> real into fake2real and fake -> jump mark_<mark> into
 * fake2mark. The mark chain must exist (desired at last reconcile). Any
 * existing element for `fake` is destroyed first in the same transaction,
 * so this also replaces (a reclaimed slot).
 * Returns the ticket of the batch carrying the op.
 */
uint64_t nft_elem_add(struct nft_ctx *n, int family, const uint8_t *fake,
                      const uint8_t *real, uint32_t mark);
uint64_t nft_elem_del(struct nft_ctx *n, int family, const uint8_t *fake);

/* true when the batch `ticket` has been acknowledged (successfully or not). */
bool nft_ticket_done(const struct nft_ctx *n, uint64_t ticket);

/* Called for each batch that failed, with its ticket (one-shot registrations
 * not needed: a single global hook, set by the fakeip DB). */
void nft_set_fail_hook(struct nft_ctx *n, void (*fn)(void *priv, uint64_t ticket, int err),
                       void *priv);

struct nft_waiter {
	struct list_head list;
	uint64_t ticket;
	void (*cb)(struct nft_waiter *w, int err);	/* err 0 or -errno */
};

/* Invoke w->cb once batch `ticket` completes. If already done, cb is
 * deferred to the next loop iteration (never called synchronously). */
void nft_wait(struct nft_ctx *n, struct nft_waiter *w, uint64_t ticket);
void nft_wait_cancel(struct nft_waiter *w);	/* safe if not waiting */

/* Submit the open batch now (does not wait). */
void nft_flush(struct nft_ctx *n);
/* Block until all submitted batches are acked (shutdown/tests). */
int nft_drain(struct nft_ctx *n);

/* Bytes currently held by the element batch buffers (tests/diagnostics). */
size_t nft_batch_mem(const struct nft_ctx *n);

#endif
