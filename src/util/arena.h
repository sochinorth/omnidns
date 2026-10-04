/* SPDX-License-Identifier: MIT */
#ifndef OMNI_ARENA_H
#define OMNI_ARENA_H

#include <stddef.h>

/*
 * Chunked bump allocator. Allocations are never freed individually;
 * arena_free() releases everything. Chunks are `chunk` bytes (default 64KiB
 * when 0); oversized requests get a dedicated chunk.
 */
struct arena_chunk;

struct arena {
	struct arena_chunk *head;
	size_t chunk;
	size_t total;	/* bytes allocated from the system (for accounting) */
};

void arena_init(struct arena *a, size_t chunk);
void *arena_alloc(struct arena *a, size_t len, size_t align);	/* NULL on OOM */
void *arena_memdup(struct arena *a, const void *p, size_t len);
char *arena_strndup(struct arena *a, const char *s, size_t len);	/* NUL-terminated */
void arena_free(struct arena *a);

#endif
