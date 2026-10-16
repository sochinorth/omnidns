// SPDX-License-Identifier: MIT
#include <time.h>

#include "time.h"

static uint32_t override_now, tick_reads;

uint64_t omni_now_ms(void)
{
	struct timespec ts;

	if (override_now) {
		uint64_t ms = (uint64_t)override_now * 1000;

		if (tick_reads && !--tick_reads)
			override_now++;
		return ms;
	}
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 1000;
}

uint32_t omni_now(void)
{
	return omni_now_ms() / 1000;
}

void time_override_set(uint32_t now_s)
{
	override_now = now_s;
}

void time_override_advance(uint32_t delta_s)
{
	override_now += delta_s;
}

void time_override_tick_after(uint32_t nreads)
{
	tick_reads = nreads;
}
