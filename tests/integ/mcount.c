// SPDX-License-Identifier: MIT
/*
 * LD_PRELOAD allocation counter used by tests/integ/test_perf.py.
 *
 *   cc -O2 -shared -fPIC -o mcount.so mcount.c -ldl
 *   MCOUNT_FILE=/tmp/x LD_PRELOAD=./mcount.so prog
 *
 * Counts calls and requested bytes of the malloc family. The counters live
 * in a MAP_SHARED mapping of $MCOUNT_FILE, so a reader can snapshot them at
 * any time by reading the file (MCOUNT_NFIELDS native-endian uint64s, in the
 * order of struct counters) -- no signals, nothing runs inside the process.
 * Without $MCOUNT_FILE (or if mapping fails) counting goes to a static block.
 * The constructor removes LD_PRELOAD and MCOUNT_FILE from the environment, so
 * children of the counted process do not add to (or reset) its counters.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

struct counters {
	uint64_t malloc, calloc, realloc, free, memalign, bytes;
};
#define MCOUNT_NFIELDS (sizeof(struct counters) / sizeof(uint64_t))

static struct counters fallback;
static struct counters *C = &fallback;

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static void (*real_free)(void *);
static int (*real_posix_memalign)(void **, size_t, size_t);
static void *(*real_aligned_alloc)(size_t, size_t);
static void *(*real_memalign)(size_t, size_t);

/* dlsym() may calloc before real_calloc is known: serve that from here */
static _Alignas(16) char boot[8192];
static size_t boot_off;
static int resolving;

#define ADD(f, n) __atomic_fetch_add(&C->f, (n), __ATOMIC_RELAXED)

static void resolve(void)
{
	if (real_malloc || resolving)
		return;
	resolving = 1;
	real_calloc = dlsym(RTLD_NEXT, "calloc");
	real_realloc = dlsym(RTLD_NEXT, "realloc");
	real_free = dlsym(RTLD_NEXT, "free");
	real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
	real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
	real_memalign = dlsym(RTLD_NEXT, "memalign");
	real_malloc = dlsym(RTLD_NEXT, "malloc");
	resolving = 0;
}

static void *boot_alloc(size_t n)
{
	size_t sz = (n + 15) & ~(size_t)15;
	if (sz > sizeof(boot) - boot_off)
		return NULL;
	void *p = boot + boot_off;
	boot_off += sz;
	return p; /* static storage: already zero */
}

static int is_boot(const void *p)
{
	return (const char *)p >= boot && (const char *)p < boot + sizeof(boot);
}

__attribute__((constructor)) static void mcount_init(void)
{
	resolve();
	const char *path = getenv("MCOUNT_FILE");
	unsetenv("LD_PRELOAD");
	if (!path)
		return;
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	unsetenv("MCOUNT_FILE");
	if (fd < 0)
		return;
	if (ftruncate(fd, sizeof(struct counters)) == 0) {
		void *m = mmap(NULL, sizeof(struct counters), PROT_READ | PROT_WRITE,
		               MAP_SHARED, fd, 0);
		if (m != MAP_FAILED) {
			struct counters *s = m;
			*s = fallback; /* carry over what the loader already did */
			C = s;
		}
	}
	close(fd);
}

void *malloc(size_t n)
{
	resolve();
	if (!real_malloc)
		return boot_alloc(n);
	ADD(malloc, 1);
	ADD(bytes, n);
	return real_malloc(n);
}

void *calloc(size_t a, size_t b)
{
	resolve();
	if (!real_calloc)
		return boot_alloc(a * b);
	ADD(calloc, 1);
	ADD(bytes, a * b);
	return real_calloc(a, b);
}

void *realloc(void *p, size_t n)
{
	resolve();
	ADD(realloc, 1);
	ADD(bytes, n);
	if (is_boot(p)) {
		void *q = real_malloc(n);
		if (q) {
			size_t avail = (size_t)(boot + sizeof(boot) - (char *)p);
			const char *s = p;
			char *d = q;
			for (size_t i = 0; i < n && i < avail; i++)
				d[i] = s[i];
		}
		return q;
	}
	return real_realloc(p, n);
}

void *reallocarray(void *p, size_t a, size_t b)
{
	size_t n;
	if (__builtin_mul_overflow(a, b, &n))
		return NULL;
	return realloc(p, n);
}

void free(void *p)
{
	if (!p || is_boot(p))
		return;
	resolve();
	ADD(free, 1);
	real_free(p);
}

int posix_memalign(void **out, size_t align, size_t n)
{
	resolve();
	ADD(memalign, 1);
	ADD(bytes, n);
	return real_posix_memalign(out, align, n);
}

void *aligned_alloc(size_t align, size_t n)
{
	resolve();
	ADD(memalign, 1);
	ADD(bytes, n);
	return real_aligned_alloc(align, n);
}

void *memalign(size_t align, size_t n)
{
	resolve();
	ADD(memalign, 1);
	ADD(bytes, n);
	return real_memalign(align, n);
}
