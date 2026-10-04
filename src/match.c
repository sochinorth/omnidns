// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>

#include "dns/wire.h"
#include "match.h"
#include "util/hash.h"

#define MATCH_MAX_PATTERN 253

struct mnode {
	uint16_t exact_ord;
	uint16_t suffix_ord;
	uint8_t len;
	char name[];
};

struct match_index {
	struct hmap map;
	struct arena arena;
	uint16_t catchall;
};

struct mkey {
	const char *name;
	size_t len;
};

static bool mnode_eq(const void *val, const void *key, void *ctx)
{
	const struct mnode *n = val;
	const struct mkey *k = key;

	return n->len == k->len && !memcmp(n->name, k->name, k->len);
}

static struct mnode *mnode_get(const struct match_index *idx, const char *name,
			       size_t len, uint64_t h)
{
	struct mkey k = { name, len };

	return hmap_get(&idx->map, h, &k, mnode_eq, NULL);
}

static int add_pattern(struct match_index *idx, const struct ns_pattern *p, uint16_t ord)
{
	uint64_t h = omni_hash(p->name, p->len);
	struct mnode *n = mnode_get(idx, p->name, p->len, h);

	if (!n) {
		n = arena_alloc(&idx->arena, sizeof(*n) + p->len, _Alignof(struct mnode));
		if (!n)
			return -1;
		n->exact_ord = n->suffix_ord = MATCH_NONE;
		n->len = p->len;
		memcpy(n->name, p->name, p->len);
		if (hmap_put(&idx->map, h, n))
			return -1;
	}
	if (p->suffix && ord < n->suffix_ord)
		n->suffix_ord = ord;
	else if (!p->suffix && ord < n->exact_ord)
		n->exact_ord = ord;
	return 0;
}

static uint32_t count_patterns(const struct rule *rules, uint16_t nrules)
{
	uint64_t n = 0;

	for (uint16_t i = 0; i < nrules; i++)
		for (uint16_t j = 0; j < rules[i].nfiles; j++)
			n += rules[i].files[j]->npat;
	return n > UINT32_MAX / 2 ? UINT32_MAX / 2 : (uint32_t)n;
}

struct match_index *match_build(const struct rule *rules, uint16_t nrules)
{
	struct match_index *idx = calloc(1, sizeof(*idx));

	if (!idx)
		return NULL;
	arena_init(&idx->arena, 256 * 1024);
	idx->catchall = MATCH_NONE;
	if (hmap_reserve(&idx->map, count_patterns(rules, nrules)))
		goto fail;
	for (uint16_t i = 0; i < nrules; i++) {
		const struct rule *r = &rules[i];

		if (r->catchall && idx->catchall == MATCH_NONE)
			idx->catchall = r->ord;
		for (uint16_t j = 0; j < r->nfiles; j++) {
			const struct nameset_file *f = r->files[j];

			for (uint32_t k = 0; k < f->npat; k++)
				if (add_pattern(idx, &f->pat[k], r->ord))
					goto fail;
		}
	}
	return idx;
fail:
	match_free(idx);
	return NULL;
}

void match_free(struct match_index *idx)
{
	if (!idx)
		return;
	hmap_free(&idx->map);
	arena_free(&idx->arena);
	free(idx);
}

static uint16_t probe(const struct match_index *idx, const char *s, size_t len,
		      bool full, uint16_t best)
{
	const struct mnode *n;

	if (len > MATCH_MAX_PATTERN)
		return best;
	n = mnode_get(idx, s, len, omni_hash(s, len));
	if (!n)
		return best;
	if (n->suffix_ord < best)
		best = n->suffix_ord;
	if (full && n->exact_ord < best)
		best = n->exact_ord;
	return best;
}

uint16_t match_lookup(const struct match_index *idx, const char *name, size_t len)
{
	uint16_t best;

	if (!len || !idx->map.len)
		return idx->catchall;
	best = probe(idx, name, len, true, MATCH_NONE);
	for (size_t i = 0; i < len; i++) {
		if (name[i] == '.')
			best = probe(idx, name + i + 1, len - i - 1, false, best);
	}
	return best != MATCH_NONE ? best : idx->catchall;
}

uint16_t match_lookup_wire(const struct match_index *idx, const uint8_t *wire, uint8_t len)
{
	char buf[DNS_NAME_TEXT_MAX];
	int n = dns_name_to_text(wire, len, buf, sizeof(buf));

	if (n < 0)
		return idx->catchall;
	return match_lookup(idx, buf, (size_t)n);
}

size_t match_footprint(const struct match_index *idx)
{
	size_t slots = idx->map.mask ? (size_t)idx->map.mask + 1 : 0;

	return sizeof(*idx) + idx->arena.total + slots * sizeof(struct hmap_slot);
}

uint32_t match_nodes(const struct match_index *idx)
{
	return idx->map.len;
}
