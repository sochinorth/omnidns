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

void *arena_alloc(struct arena *a, size_t len, size_t align)
{
	struct arena_chunk *c = a->head;
	size_t off;

	if (!align)
		align = 1;
	if (c) {
		off = (c->used + align - 1) & ~(align - 1);
		if (off + len <= c->size) {
			c->used = off + len;
			return c->data + off;
		}
	}

	size_t size = len > a->chunk / 4 ? len : a->chunk;
	c = malloc(sizeof(*c) + size);
	if (!c)
		return NULL;
	c->size = size;
	c->used = len;
	a->total += sizeof(*c) + size;
	if (size == len && a->head) {
		/* dedicated chunk: keep the current head for further small allocs */
		c->next = a->head->next;
		a->head->next = c;
	} else {
		c->next = a->head;
		a->head = c;
	}
	return c->data;
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
	char *d = arena_alloc(a, len + 1, 1);

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
