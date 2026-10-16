/* SPDX-License-Identifier: MIT */
#ifndef OMNI_CONFIG_H
#define OMNI_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "util/hmap.h"

/*
 * UCI configuration model.
 *
 *   config omnidns 'main'        (exactly one; section type "omnidns")
 *   config rule '<id>'           (ordered; id = UCI section name, must be named)
 *
 * Global options (defaults in parentheses):
 *   port (53), listen_addr (list, required, numeric v4/v6),
 *   fwmask (0xff000000, must be non-zero),
 *   fakeip_v4 (unset), fakeip_v6 (unset): CIDR,
 *     v4: plen 8..30; v6: plen 32..120; must not overlap loopback/multicast/0/::
 *   fakeip_grace (600 s), fakeip_max_bindings (65536),
 *   fakeip_ttl_max (3600 s): TTL cap of rewritten (fake) records, which
 *     also bounds binding lifetime against huge upstream TTLs,
 *   cache_size (10000 entries), cache_max_bytes (16 MiB), neg_ttl_max (3600),
 *   block_mode (nodata|nxdomain|null, default nodata), block_ttl (300),
 *   upstream_timeout (1500 ms), upstream_total_timeout (5000 ms),
 *   max_clients_tcp (64), max_pending (1024), max_pending_per_client (64),
 *   log_level (info; one of err|warn|info|debug)
 *
 * Rule options:
 *   action    block|forward|fakeip (required)
 *   upstream  path to resolv.conf-style file (required for forward/fakeip)
 *   fwmark    fakeip only, required: value in the field selected by fwmask,
 *             given unshifted (e.g. '0x01' with mask 0xff000000 -> 0x01000000);
 *             must be non-zero and fit.
 *   nameset   list of glob patterns of nameset files.
 *
 * A rule without any `nameset` option is a catchall: it must be the last
 * rule, and exactly one catchall must exist (otherwise load fails).
 * A rule with nameset options whose globs match no readable files matches
 * nothing (warning only).
 */

enum rule_action { RULE_BLOCK = 0, RULE_FORWARD, RULE_FAKEIP };
enum block_mode { BLOCK_NODATA = 0, BLOCK_NXDOMAIN, BLOCK_NULL };

struct ip_prefix {
	int family;			/* AF_INET / AF_INET6 */
	uint8_t addr[16];		/* network address (host bits zero) */
	uint8_t plen;
};

/* ---- upstreams (resolv.conf files) ---- */

struct upstream_server {
	struct sockaddr_storage sa;	/* port defaults to 53 */
	socklen_t salen;
};

/*
 * An ordered list of servers. Identity (`id`) is a hash of the ordered,
 * canonical server list (address+port+scope), NOT of the path: two files
 * with the same servers share identity, and an edited file with identical
 * servers keeps it. Refcounted: in-flight queries hold a reference.
 */
struct upstream_set {
	int refcnt;
	uint64_t id;
	uint16_t n;
	struct upstream_server srv[];
};

#define UPSTREAM_MAX_SERVERS 8

/*
 * Parse resolv.conf text. Recognized: "nameserver ADDR[#PORT]" where ADDR is
 * a numeric IPv4/IPv6 literal, IPv6 may carry %scope (interface name or
 * index); everything else (search, options, domain, comments '#' ';') is
 * ignored. Invalid nameserver lines are skipped (counted in *nskipped).
 * At most UPSTREAM_MAX_SERVERS are kept, in order, duplicates removed.
 * Returns number of servers parsed (>= 0) or -ENOMEM.
 */
int resolvconf_parse(const char *text, size_t len,
                     struct upstream_server *out, int max, int *nskipped);

/* Load a file; NULL with err message when unreadable or has zero servers. */
struct upstream_set *upstream_set_load(const char *path, char *err, size_t errlen);
struct upstream_set *upstream_set_get(struct upstream_set *u);
void upstream_set_put(struct upstream_set *u);

/* ---- namesets ---- */

/*
 * Parse nameset text: one pattern per line; blank lines and lines starting
 * with '#' are ignored; trailing "# comment" after whitespace is ignored;
 * surrounding whitespace trimmed; CRLF tolerated. Valid pattern:
 * optional "*." prefix + 1..127 labels of [a-z0-9_-] (1..63 chars each),
 * total <= 253 chars, no empty labels, no trailing dot. Uppercase is
 * lowercased (lenient). Invalid lines are skipped and counted in *ninvalid
 * (the first few are logged with `path` and line number).
 *
 * The text is consumed in windows of `window` bytes (0: NAMESET_WINDOW), as
 * files are. A line that does not fit in one window is invalid (or ignored
 * if it is a comment), so results only depend on the window size for lines
 * at least that long.
 *
 * Valid patterns are stored in f->blob as NUL-terminated names without
 * "*.", f->blob_len bytes in total (blob NULL when f->npat is 0): the
 * suffix patterns first (f->suffix_len bytes, in file order), then the exact
 * ones (in reverse file order). Identical text always gives an identical
 * blob. Returns 0 or -ENOMEM.
 */
#define NAMESET_WINDOW	(64u << 10)

struct nameset_file;

int nameset_parse(const char *text, size_t len, size_t window,
                  struct nameset_file *f, uint32_t *ninvalid, const char *path);
/* The same, sizing the output for size_hint bytes of text as a file is sized
 * by fstat(): size_hint < len acts like a file that grew while being read. */
int nameset_parse_hint(const char *text, size_t len, size_t size_hint, size_t window,
                       struct nameset_file *f, uint32_t *ninvalid, const char *path);

struct nameset_file {
	char *path;
	dev_t dev;
	ino_t ino;
	struct timespec mtime;
	off_t size;
	int refcnt;
	uint32_t blob_len;
	uint32_t suffix_len;	/* suffix region [0, suffix_len), exact the rest */
	uint32_t npat;
	char *blob;
};

/*
 * Walking one region of a blob:
 *   for (e = ns_begin(f, sfx); e < ns_end(f, sfx); e = ns_next(e))
 * visits the suffix (sfx) or exact (!sfx) pattern names. Empty for a file
 * without patterns.
 */
static inline const char *ns_begin(const struct nameset_file *f, bool suffix)
{
	return !f->blob ? NULL : suffix ? f->blob : f->blob + f->suffix_len;
}

static inline const char *ns_end(const struct nameset_file *f, bool suffix)
{
	return !f->blob ? NULL : f->blob + (suffix ? f->suffix_len : f->blob_len);
}

static inline const char *ns_next(const char *e)
{
	return e + strlen(e) + 1;
}

/*
 * Cache of parsed nameset files keyed by path. nsc_get() stats the file and
 * returns the cached parse if (dev, ino, mtime, size) are unchanged,
 * otherwise re-parses. A re-parse yielding the same patterns as the cached
 * entry returns that entry (with updated stat fields), so a touched or
 * atomically replaced but identical file keeps its identity. Returns a new
 * reference or NULL (*err = -errno; -EINVAL if not a regular file) if
 * unreadable. Files with refcnt 0 are dropped by nsc_sweep().
 */
struct nameset_cache {
	struct hmap by_path;
};

void nsc_init(struct nameset_cache *c);
struct nameset_file *nsc_get(struct nameset_cache *c, const char *path, int *err);
void nsc_put(struct nameset_file *f);
void nsc_sweep(struct nameset_cache *c);
void nsc_destroy(struct nameset_cache *c);

/* ---- rules / config ---- */

struct rule {
	char *id;			/* UCI section name (stable identity) */
	uint16_t ord;			/* position, 0-based */
	enum rule_action action;
	bool catchall;
	char *upstream_path;
	struct upstream_set *up;	/* NULL for block */
	uint32_t mark;			/* shifted into fwmask; fakeip only */
	uint16_t nfiles;
	struct nameset_file **files;
	/*
	 * Semantic fingerprint: hash of (id, action, up->id, mark, plus for
	 * block: block_mode, block_ttl; plus for fakeip: pool prefixes,
	 * fakeip_grace, fakeip_ttl_max). Two rules with equal fingerprint produce identical
	 * resolution behaviour for a name they match.
	 */
	uint64_t fingerprint;
};

#define CONFIG_MAX_RULES	1024
#define CONFIG_MAX_LISTEN	16

struct match_index;

struct config {
	uint64_t gen;			/* assigned by the caller on activation */

	uint16_t port;
	int nlisten;
	struct sockaddr_storage listen[CONFIG_MAX_LISTEN];

	uint32_t fwmask;
	bool has_pool4, has_pool6;
	struct ip_prefix pool4, pool6;
	uint32_t fakeip_grace;
	uint32_t fakeip_ttl_max;
	uint32_t fakeip_max_bindings;

	uint32_t cache_size;
	uint32_t cache_max_bytes;
	uint32_t neg_ttl_max;
	enum block_mode block_mode;
	uint32_t block_ttl;

	uint32_t upstream_timeout_ms;
	uint32_t upstream_total_timeout_ms;

	uint32_t max_clients_tcp;
	uint32_t max_pending;
	uint32_t max_pending_per_client;
	int log_level;			/* syslog prio */

	uint16_t nrules;
	struct rule *rules;
	struct match_index *idx;
};

/*
 * Load and fully validate the UCI file at `path` (e.g. /etc/config/omnidns).
 * Nameset files are resolved through `nsc` (glob(3), sorted, de-duplicated
 * per rule). Builds the match index. On failure returns NULL and a human
 * readable message in err.
 */
struct config *config_load(const char *path, struct nameset_cache *nsc,
                           char *err, size_t errlen);

/*
 * Like config_load(), as the successor of `prev` (NULL: plain load). If
 * config_same_namesets(prev, new), the new config shares prev's match index
 * instead of building one.
 */
struct config *config_reload(const char *path, struct nameset_cache *nsc,
                             const struct config *prev, char *err, size_t errlen);

/*
 * True if a and b have the same rule count and catchall, and each rule
 * (by ordinal) references the same nameset_file objects in the same order.
 * The match index depends on nothing else, so b can share a's index, and
 * the files it borrows are referenced by both configs.
 */
bool config_same_namesets(const struct config *a, const struct config *b);

/*
 * True if b resolves every name exactly like a: same match index, same
 * fwmask, and equal rule fingerprints by ordinal. Cached answers validated
 * against a are then valid against b, so b may keep a's generation.
 */
bool config_same_policy(const struct config *a, const struct config *b);

void config_free(struct config *cfg);

/* Shift an unshifted fwmark value into mask; returns 0 if it does not fit
 * or is zero. */
uint32_t config_mark_shift(uint32_t value, uint32_t mask);

int ip_prefix_parse(const char *s, struct ip_prefix *out);	/* "a.b.c.d/n", "x::/n" */
bool ip_prefix_contains(const struct ip_prefix *p, int family, const uint8_t *addr);

#endif
