/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OMNI_TIME_H
#define OMNI_TIME_H

#include <stdint.h>

/*
 * Monotonic clock in whole seconds (CLOCK_MONOTONIC based; never 0 so 0 can
 * mean "unset"). Tests can freeze/advance it with time_override_set().
 */
uint32_t omni_now(void);
uint64_t omni_now_ms(void);

void time_override_set(uint32_t now_s);	/* 0 disables the override */
void time_override_advance(uint32_t delta_s);

#endif
