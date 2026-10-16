// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>

#include "dns/wire.h"
#include "log.h"
#include "match.h"
#include "util/hash.h"

#define MATCH_MAX_PATTERN 253
#define MSLOT_EMPTY 0xffff

/*
 * Open-addressing table, built once: sized for the total pattern count, no
 * growth, no deletes. A slot names its pattern by (file, off) into the
 * nameset blobs instead of holding a copy.
 */
struct mslot {
	uint32_t off;		/* entry name offset in bases[file] */
	uint16_t file;		/* index into idx->bases; MSLOT_EMPTY = empty */
	uint16_t tag;		/* hash >> 48 */
	uint16_t exact_ord, suffix_ord;
};

_Static_assert(sizeof(struct mslot) == 12, "struct mslot must stay 12 bytes");

struct match_index {
	struct mslot *slots;
	const char **bases;	/* distinct nameset blobs, sorted by address */
	uint32_t mask, len;
	uint16_t nbases, catchall;
	int refcnt;
};

/* The slot holding name, or the empty slot where it belongs. */
static struct mslot *find(const struct match_index *idx, const char *name,
                          size_t len, uint64_t h)
{
	uint16_t tag = (uint16_t)(h >> 48);

	for (uint32_t i = (uint32_t)h & idx->mask;; i = (i + 1) & idx->mask) {
		struct mslot *s = &idx->slots[i];
		const char *n;

		if (s->file == MSLOT_EMPTY)
			return s;
		if (s->tag != tag)
			continue;
		/* strnlen first: never read past the stored entry's NUL */
		n = idx->bases[s->file] + s->off;
		if (strnlen(n, len + 1) == len && !memcmp(n, name, len))
			return s;
	}
}

/* Same rule as util/hmap: power of two, at most 75% full, at least 16. */
static uint32_t cap_for(uint32_t n)
{
	uint32_t cap = 16;

	while (cap < 0x80000000u && (uint64_t)n * 4 >= (uint64_t)cap * 3)
		cap <<= 1;
	return cap;
}

static int ptr_cmp(const void *a, const void *b)
{
	uintptr_t x = (uintptr_t)*(const char *const *)a;
	uintptr_t y = (uintptr_t)*(const char *const *)b;

	return x < y ? -1 : x > y;
}

/* Collects the distinct non-empty blobs of all rules into idx->bases. */
static int collect_bases(struct match_index *idx, const struct rule *rules,
                         uint16_t nrules)
{
	size_t n = 0, u = 0;

	for (uint16_t i = 0; i < nrules; i++)
		n += rules[i].nfiles;
	if (!n)
		return 0;
	idx->bases = malloc(n * sizeof(*idx->bases));
	if (!idx->bases)
		return -1;
	n = 0;
	for (uint16_t i = 0; i < nrules; i++)
		for (uint16_t j = 0; j < rules[i].nfiles; j++)
			if (rules[i].files[j]->npat)
				idx->bases[n++] = rules[i].files[j]->blob;
	qsort(idx->bases, n, sizeof(*idx->bases), ptr_cmp);
	for (size_t i = 0; i < n; i++)
		if (!u || idx->bases[i] != idx->bases[u - 1])
			idx->bases[u++] = idx->bases[i];
	if (u >= MSLOT_EMPTY) {
		log_err("match: too many distinct nameset files (%zu)", u);
		return -1;
	}
	idx->nbases = (uint16_t)u;
	if (u) {
		const char **nb = realloc(idx->bases, u * sizeof(*nb));

		if (nb)
			idx->bases = nb;
	}
	return 0;
}

static uint16_t base_of(const struct match_index *idx, const char *blob)
{
	const char **b = bsearch(&blob, idx->bases, idx->nbases, sizeof(*idx->bases),
	                         ptr_cmp);

	return (uint16_t)(b - idx->bases);
}

/* Patterns in the distinct files (a file shared by several rules counts once). */
static uint32_t count_patterns(const struct match_index *idx, const struct rule *rules,
                               uint16_t nrules)
{
	bool *seen = calloc(idx->nbases ? idx->nbases : 1, sizeof(*seen));
	uint64_t n = 0;

	if (!seen)
		return UINT32_MAX;
	for (uint16_t i = 0; i < nrules; i++)
		for (uint16_t j = 0; j < rules[i].nfiles; j++) {
			const struct nameset_file *f = rules[i].files[j];
			uint16_t b;

			if (!f->npat || seen[b = base_of(idx, f->blob)])
				continue;
			seen[b] = true;
			n += f->npat;
		}
	free(seen);
	return n > UINT32_MAX / 2 ? UINT32_MAX / 2 : (uint32_t)n;
}

static void add_file(struct match_index *idx, const struct nameset_file *f,
                     uint16_t ord)
{
	uint16_t file = base_of(idx, f->blob);

	for (const char *e = f->blob; e < f->blob + f->blob_len; e = ns_next(e)) {
		const char *name = ns_name(e);
		size_t len = strlen(name);
		uint64_t h = omni_hash(name, len);
		struct mslot *s = find(idx, name, len, h);

		if (s->file == MSLOT_EMPTY) {
			s->off = (uint32_t)(name - f->blob);
			s->file = file;
			s->tag = (uint16_t)(h >> 48);
			s->exact_ord = s->suffix_ord = MATCH_NONE;
			idx->len++;
		}
		if (ns_is_suffix(e) && ord < s->suffix_ord)
			s->suffix_ord = ord;
		else if (!ns_is_suffix(e) && ord < s->exact_ord)
			s->exact_ord = ord;
	}
}

struct match_index *match_build(const struct rule *rules, uint16_t nrules)
{
	struct match_index *idx = calloc(1, sizeof(*idx));
	uint32_t n, cap;

	if (!idx)
		return NULL;
	idx->refcnt = 1;
	idx->catchall = MATCH_NONE;
	if (collect_bases(idx, rules, nrules))
		goto fail;
	n = count_patterns(idx, rules, nrules);
	if (n == UINT32_MAX)
		goto fail;
	cap = cap_for(n);
	idx->mask = cap - 1;
	idx->slots = malloc((size_t)cap * sizeof(*idx->slots));
	if (!idx->slots)
		goto fail;
	for (uint32_t i = 0; i < cap; i++)
		idx->slots[i].file = MSLOT_EMPTY;
	for (uint16_t i = 0; i < nrules; i++) {
		const struct rule *r = &rules[i];

		if (r->catchall && idx->catchall == MATCH_NONE)
			idx->catchall = r->ord;
		for (uint16_t j = 0; j < r->nfiles; j++)
			if (r->files[j]->npat)
				add_file(idx, r->files[j], r->ord);
	}
	return idx;
fail:
	match_free(idx);
	return NULL;
}

struct match_index *match_get(struct match_index *idx)
{
	idx->refcnt++;
	return idx;
}

void match_free(struct match_index *idx)
{
	if (!idx || --idx->refcnt > 0)
		return;
	free(idx->slots);
	free(idx->bases);
	free(idx);
}

static uint16_t probe(const struct match_index *idx, const char *s, size_t len,
                      bool full, uint16_t best)
{
	const struct mslot *n;

	if (len > MATCH_MAX_PATTERN)
		return best;
	n = find(idx, s, len, omni_hash(s, len));
	if (n->file == MSLOT_EMPTY)
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

	if (!len || !idx->len)
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

/* The pattern strings belong to the nameset files and are not counted. */
size_t match_footprint(const struct match_index *idx)
{
	return sizeof(*idx) + ((size_t)idx->mask + 1) * sizeof(struct mslot) +
	       (size_t)idx->nbases * sizeof(*idx->bases);
}

uint32_t match_nodes(const struct match_index *idx)
{
	return idx->len;
}
