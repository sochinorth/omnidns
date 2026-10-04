// SPDX-License-Identifier: GPL-2.0-only
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "arena.h"

struct arena_chunk {
	struct arena_chunk *next;
	size_t size, used;
	_Alignas(16) uint8_t data[];
};

void arena_init(struct arena *a, size_t chunk)
{
	a->head = NULL;
	a->chunk = chunk ? chunk : 64 * 1024;
	a->total = 0;
}

/* align is a power of two; alignment is absolute, not relative to the chunk */
static void *chunk_fit(struct arena_chunk *c, size_t len, size_t align)
{
	uintptr_t base = (uintptr_t)c->data;
	uintptr_t p = (base + c->used + align - 1) & ~(uintptr_t)(align - 1);
	size_t off = p - base;

	if (off > c->size || len > c->size - off)
		return NULL;
	c->used = off + len;
	return c->data + off;
}

void *arena_alloc(struct arena *a, size_t len, size_t align)
{
	struct arena_chunk *c = a->head;
	size_t need, size;
	void *p;

	if (!align)
		align = 1;
	if (align & (align - 1))
		return NULL;
	if (c && (p = chunk_fit(c, len, align)))
		return p;

	/* worst-case padding when malloc only guarantees 16-byte alignment */
	need = len + (align > 16 ? align - 1 : 0);
	if (need < len || need > SIZE_MAX - sizeof(*c))
		return NULL;
	size = need > a->chunk / 4 ? need : a->chunk;
	c = malloc(sizeof(*c) + size);
	if (!c)
		return NULL;
	c->size = size;
	c->used = 0;
	a->total += sizeof(*c) + size;
	if (size == need && a->head) {
		/* dedicated chunk: keep the current head for further small allocs */
		c->next = a->head->next;
		a->head->next = c;
	} else {
		c->next = a->head;
		a->head = c;
	}
	return chunk_fit(c, len, align);
}

void *arena_memdup(struct arena *a, const void *p, size_t len)
{
	void *d = arena_alloc(a, len, 1);

	if (d && len)
		memcpy(d, p, len);
	return d;
}

char *arena_strndup(struct arena *a, const char *s, size_t len)
{
	char *d = len < SIZE_MAX ? arena_alloc(a, len + 1, 1) : NULL;

	if (d) {
		memcpy(d, s, len);
		d[len] = 0;
	}
	return d;
}

void arena_free(struct arena *a)
{
	struct arena_chunk *c = a->head, *n;

	while (c) {
		n = c->next;
		free(c);
		c = n;
	}
	a->head = NULL;
	a->total = 0;
}
