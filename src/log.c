// SPDX-License-Identifier: GPL-2.0-only
#include <stdarg.h>
#include <stdio.h>

#include "log.h"
#include "util/time.h"

static bool log_stderr = true;
static int log_level = LOG_INFO;

void log_init(const char *ident, bool to_stderr, int max_level)
{
	log_stderr = to_stderr;
	log_level = max_level;
	if (!to_stderr)
		openlog(ident, LOG_PID, LOG_DAEMON);
}

static void __attribute__((format(printf, 2, 0))) log_vmsg(int prio, const char *fmt, va_list ap)
{
	if (prio > log_level)
		return;
	if (log_stderr) {
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	} else {
		vsyslog(prio, fmt, ap);
	}
}

void log_msg(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_vmsg(prio, fmt, ap);
	va_end(ap);
}

void log_rl_msg(struct log_rl *rl, unsigned interval, int prio, const char *fmt, ...)
{
	unsigned long now = omni_now();
	va_list ap;

	if (rl->last && now - rl->last < interval) {
		rl->suppressed++;
		return;
	}
	if (rl->suppressed)
		log_msg(prio, "(%u similar messages suppressed)", rl->suppressed);
	rl->last = now;
	rl->suppressed = 0;
	va_start(ap, fmt);
	log_vmsg(prio, fmt, ap);
	va_end(ap);
}
