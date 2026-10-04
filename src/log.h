/* SPDX-License-Identifier: MIT */
#ifndef OMNI_LOG_H
#define OMNI_LOG_H

#include <stdbool.h>
#include <syslog.h>

/*
 * Logging goes to syslog (or stderr when started with -f / in tests).
 * log_ratelimited() suppresses repeats of the same call site to at most one
 * message per `interval` seconds and reports the suppressed count.
 */

void log_init(const char *ident, bool to_stderr, int max_level);
void log_msg(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

struct log_rl {
	unsigned long last;	/* monotonic seconds of last emitted msg */
	unsigned suppressed;
};

void log_rl_msg(struct log_rl *rl, unsigned interval, int prio, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

#define log_err(...)    log_msg(LOG_ERR, __VA_ARGS__)
#define log_warn(...)   log_msg(LOG_WARNING, __VA_ARGS__)
#define log_info(...)   log_msg(LOG_INFO, __VA_ARGS__)
#define log_debug(...)  log_msg(LOG_DEBUG, __VA_ARGS__)

#define log_rl(prio, ...) do {						\
	static struct log_rl __rl;					\
	log_rl_msg(&__rl, 10, prio, __VA_ARGS__);			\
} while (0)

#endif
