/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OMNI_MATCH_H
#define OMNI_MATCH_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"

/*
 * Suffix index over all rules' nameset patterns.
 *
 * A hash map keyed by the dotted pattern name; each node stores
 * (min ordinal of rules with an exact pattern for the name,
 *  min ordinal of rules with a suffix pattern "*.name").
 *
 * Lookup of "a.b.google.com" (first match wins = minimum ordinal):
 *   full name   -> consider exact and suffix ordinals
 *   ancestors   -> "b.google.com", "google.com", "com": suffix only
 *   nothing     -> the catchall rule ordinal (or MATCH_NONE if none)
 *
 * Names given to lookup must be in dns_name_to_text() form (lowercase, no
 * trailing dot, escaped). The root name ("") matches only the catchall.
 */

#define MATCH_NONE 0xffff

struct match_index;

struct match_index *match_build(const struct rule *rules, uint16_t nrules);
void match_free(struct match_index *idx);

uint16_t match_lookup(const struct match_index *idx, const char *name, size_t len);
/* Convenience: converts the wire name to text first. */
uint16_t match_lookup_wire(const struct match_index *idx, const uint8_t *wire, uint8_t len);

size_t match_footprint(const struct match_index *idx);
uint32_t match_nodes(const struct match_index *idx);

#endif
