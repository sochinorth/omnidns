// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>

#include "util/pool.h"

/*
 * Under ASan, a kept object is poisoned (all but the link word) so that a
 * use after pool_put() is reported as it would be after free().
 */
#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/asan_interface.h>
#define KEPT(p, obj)	ASAN_POISON_MEMORY_REGION((char *)(obj) + sizeof(void *), \
			                          (p)->size - sizeof(void *))
#define LIVE(p, obj)	ASAN_UNPOISON_MEMORY_REGION((obj), (p)->size)
#else
#define KEPT(p, obj)	((void)0)
#define LIVE(p, obj)	((void)0)
#endif

static void destroy(struct pool *p, void *obj)
{
	if (p->release)
		p->release(obj);
	free(obj);
}

static void free_some(struct pool *p, uint32_t n)
{
	while (n-- && p->head) {
		void *obj = p->head;

		memcpy(&p->head, obj, sizeof(void *));
		p->nfree--;
		LIVE(p, obj);
		destroy(p, obj);
	}
}

static void timer_cb(struct uloop_timeout *t)
{
	pool_trim(container_of(t, struct pool, timer));
}

/* Start an interval when more than floor are kept (and none is running). */
static void arm(struct pool *p)
{
	if (p->nfree <= p->floor || p->timer.pending)
		return;
	p->timer.cb = timer_cb;
	p->low = p->nfree;
	uloop_timeout_set(&p->timer, POOL_TRIM_MS);
}

void *pool_get(struct pool *p, bool *fresh)
{
	void *obj = p->head;

	if (obj) {
		memcpy(&p->head, obj, sizeof(void *));
		LIVE(p, obj);
		if (--p->nfree < p->low)
			p->low = p->nfree;
		*fresh = false;
	} else {
		obj = calloc(1, p->size);
		if (!obj)
			return NULL;
		*fresh = true;
	}
	p->used++;
	return obj;
}

void pool_put(struct pool *p, void *obj)
{
	if (!obj)
		return;
	p->used--;
	if (p->nfree >= p->cap) {
		destroy(p, obj);
		return;
	}
	memcpy(obj, &p->head, sizeof(void *));
	KEPT(p, obj);
	p->head = obj;
	p->nfree++;
	arm(p);
}

void pool_trim(struct pool *p)
{
	uint32_t excess = p->nfree > p->floor ? p->nfree - p->floor : 0;

	uloop_timeout_cancel(&p->timer);
	free_some(p, p->low < excess ? p->low : excess);
	arm(p);
}

void pool_drain(struct pool *p)
{
	uloop_timeout_cancel(&p->timer);
	free_some(p, p->nfree);
}
