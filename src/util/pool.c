// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>

#include "util/pool.h"

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
