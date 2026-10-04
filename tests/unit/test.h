/* SPDX-License-Identifier: MIT */
/* Minimal unit test harness: one executable per test file.
 *
 *   TEST(name) { CHECK(cond); CHECK_EQ(a, b); ... }
 *   int main(void) { RUN(name); ...; return test_summary(); }
 *
 * test_require_netns(argv): re-exec self under `unshare -rn` when not
 * already in a private netns (for nftables tests). Skips (exit 77) if
 * unshare is unavailable.
 */
#ifndef OMNI_TEST_H
#define OMNI_TEST_H

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_failures, test_checks, test_cur_failed;

#define TEST(name) static void test_##name(void)

#define CHECK(cond) do {						\
	test_checks++;							\
	if (!(cond)) {							\
		fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		test_cur_failed = 1;					\
	}								\
} while (0)

#define CHECK_EQ(a, b) do {						\
	long long _a = (long long)(a), _b = (long long)(b);		\
	test_checks++;							\
	if (_a != _b) {							\
		fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld != %lld)\n", \
			__FILE__, __LINE__, #a, #b, _a, _b);		\
		test_cur_failed = 1;					\
	}								\
} while (0)

#define CHECK_STR(a, b) do {						\
	const char *_a = (a), *_b = (b);				\
	test_checks++;							\
	if (!_a || !_b || strcmp(_a, _b)) {				\
		fprintf(stderr, "  FAIL %s:%d: %s == %s (\"%s\" != \"%s\")\n", \
			__FILE__, __LINE__, #a, #b, _a ? _a : "(null)", _b ? _b : "(null)"); \
		test_cur_failed = 1;					\
	}								\
} while (0)

#define REQUIRE(cond) do {						\
	CHECK(cond);							\
	if (test_cur_failed) return;					\
} while (0)

#define RUN(name) do {							\
	test_cur_failed = 0;						\
	fprintf(stderr, "- %s\n", #name);				\
	test_##name();							\
	if (test_cur_failed) test_failures++;				\
} while (0)

static inline int test_summary(void)
{
	fprintf(stderr, "%d checks, %d failed tests\n", test_checks, test_failures);
	return test_failures ? 1 : 0;
}

static inline void test_require_netns(char **argv)
{
	if (getenv("OMNI_IN_NETNS"))
		return;
	setenv("OMNI_IN_NETNS", "1", 1);
	char *args[64] = { "unshare", "-rn", "--" };
	int i = 3;
	for (char **a = argv; *a && i < 63; a++)
		args[i++] = *a;
	args[i] = NULL;
	execvp("unshare", args);
	fprintf(stderr, "unshare unavailable (%s), skipping\n", strerror(errno));
	exit(77);
}

#endif
