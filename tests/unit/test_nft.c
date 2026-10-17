// SPDX-License-Identifier: MIT
#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/set.h>
#include <libnftnl/table.h>
#include <libnftnl/rule.h>
#include <libnftnl/common.h>
#include <libubox/uloop.h>

#include "test.h"
#include "log.h"
#include "nft.h"
#include "fakeip.h"

#define TABLE "omnitest"

static char *sh(const char *cmd)
{
	FILE *f = popen(cmd, "r");
	size_t len = 0, cap = 4096;
	char *buf = malloc(cap);
	size_t r;

	if (!f) {
		buf[0] = 0;
		return buf;
	}
	while ((r = fread(buf + len, 1, cap - len - 1, f)) > 0) {
		len += r;
		if (cap - len < 2)
			buf = realloc(buf, cap *= 2);
	}
	buf[len] = 0;
	pclose(f);
	return buf;
}

static char *list_table(void)
{
	char *o = sh("nft list table inet " TABLE " 2>&1");
	if (getenv("NFT_DUMP"))
		fputs(o, stderr);
	return o;
}

static int has(const char *hay, const char *needle)
{
	if (strstr(hay, needle))
		return 1;
	fprintf(stderr, "    missing: \"%s\"\n", needle);
	return 0;
}

static int lacks(const char *hay, const char *needle)
{
	if (!strstr(hay, needle))
		return 1;
	fprintf(stderr, "    unexpected: \"%s\"\n", needle);
	return 0;
}

static long count_elems(const char *map)
{
	char cmd[256], *out;
	long n;

	snprintf(cmd, sizeof(cmd),
	         "nft list map inet " TABLE " %s | grep -oE ' : (jump|[0-9a-f])' | wc -l", map);
	out = sh(cmd);
	n = strtol(out, NULL, 10);
	free(out);
	return n;
}

static struct ip_prefix pfx(int family, const char *addr, int plen)
{
	struct ip_prefix p = { .family = family, .plen = (uint8_t)plen };

	inet_pton(family, addr, p.addr);
	return p;
}

static struct nft_desired desired(bool v4, bool v6, const uint32_t *marks, uint32_t n)
{
	struct nft_desired d = {
		.fwmask = 0xff000000,
		.has_pool4 = v4, .has_pool6 = v6,
		.pool4 = pfx(AF_INET, "198.18.0.0", 15),
		.pool6 = pfx(AF_INET6, "fc00::", 64),
		.marks = marks, .nmarks = n,
	};
	return d;
}

static struct nft_ctx *n;

TEST(bootstrap_v4)
{
	struct nft_desired d = desired(true, false, NULL, 0);
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	o = list_table();
	CHECK(has(o, "map fake2real_v4"));
	CHECK(has(o, "type ipv4_addr : ipv4_addr"));
	CHECK(has(o, "map fake2mark_v6"));
	CHECK(has(o, "type ipv6_addr : verdict"));
	CHECK(has(o, "type filter hook prerouting priority mangle; policy accept;"));
	CHECK(has(o, "type route hook output priority mangle; policy accept;"));
	CHECK(has(o, "type nat hook prerouting priority dstnat; policy accept;"));
	/* -100 at output is printed as "dstnat" */
	CHECK(has(o, "chain output_dstnat {\n\t\ttype nat hook output priority dstnat;"));
	CHECK(has(o, "type filter hook forward priority filter - 1; policy accept;"));
	CHECK(has(o, "type filter hook output priority filter - 1; policy accept;"));
	CHECK(has(o, "jump restore_marks"));
	CHECK(has(o, "ip daddr 198.18.0.0/15 ip daddr vmap @fake2mark_v4"));
	CHECK(has(o, "ip daddr 198.18.0.0/15 dnat ip to ip daddr map @fake2real_v4"));
	CHECK(has(o, "ip daddr 198.18.0.0/15 reject"));
	CHECK(lacks(o, "ip6 daddr"));
	CHECK(lacks(o, "vmap {"));
	CHECK(lacks(o, "chain mark_"));
	free(o);
	/* bootstrap again: deletes and recreates */
	CHECK(nft_bootstrap(n, &d) == 0);
}

TEST(bootstrap_v4v6_marks)
{
	static const uint32_t marks[] = { 0x02000000, 0x01000000, 0x02000000 };
	struct nft_desired d = desired(true, true, marks, 3);
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	o = list_table();
	CHECK(has(o, "chain mark_01000000"));
	CHECK(has(o, "chain mark_02000000"));
	CHECK(has(o, "meta mark set meta mark & 0x01ffffff | 0x01000000"));
	CHECK(has(o, "ct mark set ct mark & 0x02ffffff | 0x02000000"));
	CHECK(has(o, "ct mark & 0xff000000 vmap { 0x01000000 : jump mark_01000000, "
	          "0x02000000 : jump mark_02000000 }"));
	CHECK(has(o, "ip6 daddr fc00::/64 ip6 daddr vmap @fake2mark_v6"));
	CHECK(has(o, "ip6 daddr fc00::/64 dnat ip6 to ip6 daddr map @fake2real_v6"));
	CHECK(has(o, "ip6 daddr fc00::/64 reject"));
	free(o);
}

TEST(reconcile)
{
	static const uint32_t m1[] = { 0x01000000, 0x02000000 };
	static const uint32_t m2[] = { 0x03000000, 0x01000000 };
	static const uint32_t bad[] = { 0x00000001 };
	struct nft_desired d = desired(true, false, m1, 2);
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	d = desired(true, true, m2, 2);
	d.pool4 = pfx(AF_INET, "198.18.0.0", 16);
	d.pool6 = pfx(AF_INET6, "fd00::", 63);
	REQUIRE(nft_reconcile(n, &d) == 0);
	o = list_table();
	CHECK(has(o, "chain mark_01000000"));
	CHECK(has(o, "chain mark_03000000"));
	CHECK(lacks(o, "mark_02000000"));
	CHECK(has(o, "ct mark & 0xff000000 vmap { 0x01000000 : jump mark_01000000, "
	          "0x03000000 : jump mark_03000000 }"));
	CHECK(has(o, "ip daddr 198.18.0.0/16 dnat ip to ip daddr map @fake2real_v4"));
	CHECK(lacks(o, "198.18.0.0/15"));
	CHECK(has(o, "ip6 daddr fd00::/63 dnat ip6 to ip6 daddr map @fake2real_v6"));
	CHECK(has(o, "ip6 daddr fd00::/63 reject"));
	free(o);

	/* userspace validation failure keeps state */
	d.marks = bad;
	d.nmarks = 1;
	CHECK(nft_reconcile(n, &d) == -EINVAL);

	/* drop all marks and the v6 pool */
	d = desired(true, false, NULL, 0);
	REQUIRE(nft_reconcile(n, &d) == 0);
	o = list_table();
	CHECK(lacks(o, "chain mark_"));
	CHECK(lacks(o, "vmap {"));
	CHECK(lacks(o, "ip6 daddr"));
	CHECK(has(o, "ip daddr 198.18.0.0/15 reject"));
	free(o);

	/* idempotent */
	CHECK(nft_reconcile(n, &d) == 0);
}

TEST(reconcile_fwmask)
{
	static const uint32_t m1[] = { 0x01000000, 0x02000000 };
	static const uint32_t m2[] = { 0x01000000, 0x04000000 };
	struct nft_desired d = desired(true, false, m1, 2);
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	d.fwmask = 0x0f000000;
	d.marks = m2;
	CHECK(nft_mark_known(n, 0x02000000));
	REQUIRE(nft_reconcile(n, &d) == 0);
	CHECK(nft_mark_known(n, 0x01000000));
	CHECK(nft_mark_known(n, 0x04000000));
	CHECK(!nft_mark_known(n, 0x02000000));
	o = list_table();
	/* nft prints (x & m) ^ v as "x & (m | v) | v" */
	CHECK(has(o, "meta mark set meta mark & 0xf1ffffff | 0x01000000"));
	CHECK(has(o, "ct mark set ct mark & 0xf1ffffff | 0x01000000"));
	CHECK(has(o, "meta mark set meta mark & 0xf4ffffff | 0x04000000"));
	CHECK(lacks(o, "0x01ffffff"));
	CHECK(lacks(o, "mark_02000000"));
	CHECK(has(o, "ct mark & 0x0f000000 vmap"));
	free(o);
}

TEST(reconcile_noop)
{
	static const uint32_t m1[] = { 0x02000000, 0x01000000 };
	static const uint32_t m1b[] = { 0x01000000, 0x02000000, 0x01000000 };
	struct nft_desired d = desired(true, true, m1, 2);
	char *a, *b;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	/* "-a" prints rule handles: a rewritten chain gets new ones */
	a = sh("nft -a list table inet " TABLE);
	d.marks = m1b;		/* same set, other order, repeated */
	d.nmarks = 3;
	CHECK(nft_reconcile(n, &d) == 0);
	b = sh("nft -a list table inet " TABLE);
	CHECK_STR(a, b);
	free(b);
	/* a real change rewrites the policy chains */
	d.pool6 = pfx(AF_INET6, "fd00::", 64);
	CHECK(nft_reconcile(n, &d) == 0);
	b = sh("nft -a list table inet " TABLE);
	CHECK(strcmp(a, b) != 0);
	CHECK(has(b, "fd00::/64"));
	free(a);
	free(b);
	/* external edits survive a no-op reconcile (documented trade-off)... */
	free(sh("nft flush chain inet " TABLE " forward_reject"));
	CHECK(nft_reconcile(n, &d) == 0);
	a = list_table();
	CHECK(has(a, "chain forward_reject {\n\t\ttype filter hook forward priority "
	          "filter - 1; policy accept;\n\t}"));
	free(a);
	/* ...and are repaired by the next real change */
	d.pool6 = pfx(AF_INET6, "fc00::", 64);
	CHECK(nft_reconcile(n, &d) == 0);
	a = list_table();
	CHECK(has(a, "chain forward_reject {\n\t\ttype filter hook forward priority "
	          "filter - 1; policy accept;\n\t\tip daddr 198.18.0.0/15 reject"));
	free(a);
}

TEST(reconcile_kernel_failure)
{
	static const uint32_t m1[] = { 0x01000000 };
	static const uint32_t m2[] = { 0x02000000 };
	struct nft_desired d = desired(true, false, m1, 1);
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	/* someone deletes a chain we think exists: transaction aborts */
	free(sh("nft delete chain inet " TABLE " output_reject"));
	d.marks = m2;
	CHECK(nft_reconcile(n, &d) < 0);
	o = list_table();
	CHECK(has(o, "chain mark_01000000"));
	CHECK(lacks(o, "mark_02000000"));
	free(o);
	/* shadow unchanged: a new bootstrap restores order */
	CHECK(nft_bootstrap(n, &d) == 0);
}

/* ---- many mark chains ---- */

#define BIG_MASK	0x3fff0000u	/* 16383 marks */
#define BIG_N		4096

/* marks first+1 .. first+cnt, shifted into BIG_MASK, in reverse order */
static const uint32_t *big_marks(uint32_t first, uint32_t cnt)
{
	static uint32_t m[BIG_N];

	for (uint32_t i = 0; i < cnt; i++)
		m[i] = (first + cnt - i) << 16;
	return m;
}

static struct nft_desired big_desired(uint32_t first, uint32_t cnt)
{
	struct nft_desired d = desired(true, true, big_marks(first, cnt), cnt);

	d.fwmask = BIG_MASK;
	return d;
}

/*
 * Count "0xV : jump mark_V" (vmap) or "chain mark_V" (!vmap) in `o`; -1 if
 * any V is not a mark first+1 .. first+cnt or a key jumps to another chain.
 */
static long count_marks(const char *o, bool vmap, uint32_t first, uint32_t cnt)
{
	const char *lead = vmap ? "0x" : "chain mark_";
	long k = 0;

	for (const char *p = strstr(o, lead); p; p = strstr(p + 1, lead)) {
		unsigned a = 0, b = 0;
		int r = vmap ? sscanf(p, "0x%8x : jump mark_%8x", &a, &b) :
		               sscanf(p, "chain mark_%8x", &a);

		if (r < 1)
			continue;
		if (r == 1)
			b = a;
		if (a != b || a >> 16 <= first || a >> 16 > first + cnt || (a & 0xffff))
			return -1;
		k++;
	}
	return k;
}

/* restore_marks' vmap holds exactly marks first+1 .. first+cnt, each jumping
 * to its own chain, and exactly those mark chains exist */
static int big_check(uint32_t first, uint32_t cnt)
{
	char *o = sh("nft list chain inet " TABLE " restore_marks | "
	             "grep -oE '0x[0-9a-f]{8} : jump mark_[0-9a-f]{8}'");
	long got;
	int ok = 1;

	got = count_marks(o, true, first, cnt);
	if (got != (long)cnt) {
		fprintf(stderr, "    restore_marks: %ld elements, want %u\n", got, cnt);
		ok = 0;
	}
	free(o);
	o = sh("nft list chains inet " TABLE);
	got = count_marks(o, false, first, cnt);
	if (got != (long)cnt) {
		fprintf(stderr, "    mark chains: %ld, want %u\n", got, cnt);
		ok = 0;
	}
	free(o);
	return ok;
}

TEST(big_bootstrap)
{
	struct nft_desired d = big_desired(0, BIG_N);
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	CHECK(big_check(0, BIG_N));
	CHECK(nft_mark_known(n, 1u << 16));
	CHECK(nft_mark_known(n, (uint32_t)BIG_N << 16));
	o = sh("nft list chain inet " TABLE " mark_10000000");
	CHECK(has(o, "meta mark set meta mark & 0xd000ffff | 0x10000000"));
	free(o);
	/* again over the full table: delete and recreate */
	REQUIRE(nft_bootstrap(n, &d) == 0);
	CHECK(big_check(0, BIG_N));
}

/*
 * Growing 1 -> 4096 marks across reconciles: around the CHUNK_MAX element
 * message boundary, and past the counts where restore_marks' vmap, sent in
 * a single message, wrapped the 16-bit nest length (1260 x 52 bytes, ...).
 */
TEST(big_reconcile)
{
	static const uint32_t steps[] = { 1, 2, 255, 256, 257, 512, 1260, 1261, 2048,
	                                  2521, 3780, 3800, BIG_N };
	struct nft_desired d = big_desired(0, 1);
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	CHECK(big_check(0, 1));
	for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
		d = big_desired(0, steps[i]);
		REQUIRE(nft_reconcile(n, &d) == 0);
		CHECK(big_check(0, steps[i]));
	}
	/* replace all 4096 chains by 4096 others in one transaction */
	d = big_desired(BIG_N, BIG_N);
	REQUIRE(nft_reconcile(n, &d) == 0);
	CHECK(big_check(BIG_N, BIG_N));
	CHECK(!nft_mark_known(n, 1u << 16));
	CHECK(nft_mark_known(n, (uint32_t)(BIG_N + 1) << 16));
	/* a new fwmask rewrites every chain */
	d.fwmask = 0x7fff0000;	/* printed keep masks: 0xc000ffff | V -> 0x8000ffff | V */
	REQUIRE(nft_reconcile(n, &d) == 0);
	o = sh("nft list table inet " TABLE " | grep -c 'meta mark set meta mark & 0x[89ab]'");
	CHECK_EQ(strtol(o, NULL, 10), BIG_N);
	free(o);
	o = sh("nft list table inet " TABLE " | grep -c 'mark & 0x[c-f]'");
	CHECK_EQ(strtol(o, NULL, 10), 0);
	free(o);
	d = big_desired(0, 3);
	REQUIRE(nft_reconcile(n, &d) == 0);
	CHECK(big_check(0, 3));
}

/*
 * setsockopt() is interposed (like mnl_socket_sendto() below) so a context
 * can be opened with a small receive buffer: control-plane transactions must
 * not depend on its size.
 */
static int small_rcvbuf;

int setsockopt(int fd, int level, int opt, const void *val, socklen_t len)
{
	static int (*real_setsockopt)(int, int, int, const void *, socklen_t);

	if (!real_setsockopt)
		*(void **)&real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
	if (small_rcvbuf && level == SOL_SOCKET && (opt == SO_RCVBUF || opt == SO_RCVBUFFORCE))
		val = &small_rcvbuf;
	return real_setsockopt(fd, level, opt, val, len);
}

/* a failing message deep in a big transaction is reported, nothing changes */
TEST(big_reconcile_failure)
{
	struct nft_desired d = big_desired(0, BIG_N);
	struct nft_ctx *m;

	small_rcvbuf = 32 << 10;
	m = nft_open(TABLE);
	small_rcvbuf = 0;
	REQUIRE(m);
	REQUIRE(nft_bootstrap(m, &d) == 0);
	CHECK(big_check(0, BIG_N));
	free(sh("nft delete chain inet " TABLE " output_reject"));
	d = big_desired(BIG_N / 2, BIG_N);
	CHECK_EQ(nft_reconcile(m, &d), -ENOENT);
	CHECK(big_check(0, BIG_N));
	CHECK(nft_mark_known(m, 1u << 16));
	CHECK(!nft_mark_known(m, (uint32_t)(BIG_N + 1) << 16));
	/* the table gone: every message fails, with far more errors than the
	 * receive buffer holds; the first one is still reported */
	free(sh("nft delete table inet " TABLE));
	CHECK_EQ(nft_reconcile(m, &d), -ENOENT);
	/* the leftover errors are not taken for the next transaction's reply */
	d = big_desired(0, BIG_N);
	REQUIRE(nft_bootstrap(m, &d) == 0);
	CHECK(big_check(0, BIG_N));
	d = big_desired(1, 2);
	REQUIRE(nft_reconcile(m, &d) == 0);
	CHECK(big_check(1, 2));
	nft_close(m);
}

/* ---- async ---- */

struct twait {
	struct nft_waiter w;
	int fired, err;
};

static int pending_waiters;
static uint64_t failed_ticket;
static int failed_err, nfails;

static void wait_cb(struct nft_waiter *w, int err)
{
	struct twait *t = container_of(w, struct twait, w);

	t->fired++;
	t->err = err;
	if (--pending_waiters == 0)
		uloop_end();
}

static void fail_hook(void *priv, uint64_t ticket, int err)
{
	failed_ticket = ticket;
	failed_err = err;
	nfails++;
}

static void abort_cb(struct uloop_timeout *t)
{
	fprintf(stderr, "  uloop timeout\n");
	uloop_end();
}

static void run_loop(void)
{
	struct uloop_timeout guard = { .cb = abort_cb };

	uloop_timeout_set(&guard, 5000);
	uloop_run();
	uloop_timeout_cancel(&guard);
}

static void wait_on(struct twait *t, uint64_t ticket)
{
	memset(t, 0, sizeof(*t));
	t->w.cb = wait_cb;
	pending_waiters++;
	nft_wait(n, &t->w, ticket);
}

static void v4(uint8_t *a, const char *s)
{
	inet_pton(AF_INET, s, a);
}

static void bootstrap_marks(void)
{
	static const uint32_t marks[] = { 0x01000000, 0x02000000 };
	struct nft_desired d = desired(true, true, marks, 2);

	CHECK(nft_bootstrap(n, &d) == 0);
}

TEST(async_add_del)
{
	uint8_t f1[4], f2[4], r1[4], r2[4], f6[16], r6[16];
	struct twait a, b, c;
	uint64_t t1, t2, t3;
	char *o;

	bootstrap_marks();
	nfails = 0;
	v4(f1, "198.18.0.1"); v4(r1, "10.1.1.1");
	v4(f2, "198.18.0.2"); v4(r2, "10.2.2.2");
	inet_pton(AF_INET6, "fc00::1", f6);
	inet_pton(AF_INET6, "2001:db8::1", r6);

	t1 = nft_elem_add(n, AF_INET, f1, r1, 0x01000000);
	t2 = nft_elem_add(n, AF_INET, f2, r2, 0x02000000);
	CHECK_EQ(t1, t2);
	CHECK(nft_elem_add(n, AF_INET6, f6, r6, 0x02000000) == t1);
	CHECK(!nft_ticket_done(n, t1));
	wait_on(&a, t1);
	wait_on(&b, t1);
	run_loop();
	CHECK_EQ(a.fired, 1);
	CHECK_EQ(b.fired, 1);
	CHECK_EQ(a.err, 0);
	CHECK(nft_ticket_done(n, t1));
	o = list_table();
	CHECK(has(o, "198.18.0.1 : 10.1.1.1"));
	CHECK(has(o, "198.18.0.2 : 10.2.2.2"));
	CHECK(has(o, "198.18.0.1 : jump mark_01000000"));
	CHECK(has(o, "198.18.0.2 : jump mark_02000000"));
	CHECK(has(o, "fc00::1 : 2001:db8::1"));
	CHECK(has(o, "fc00::1 : jump mark_02000000"));
	free(o);

	/* waiting on a done ticket is deferred, never synchronous */
	wait_on(&c, t1);
	CHECK_EQ(c.fired, 0);
	run_loop();
	CHECK_EQ(c.fired, 1);
	CHECK_EQ(c.err, 0);

	/* re-adding identical element is fine; replace changes mapping */
	CHECK(nft_elem_add(n, AF_INET, f2, r2, 0x02000000) != 0);
	t2 = nft_elem_add(n, AF_INET, f1, r2, 0x02000000);
	t3 = nft_elem_del(n, AF_INET6, f6);
	CHECK(t2 > t1);
	CHECK_EQ(t3, t2);
	wait_on(&a, t3);
	run_loop();
	CHECK_EQ(a.err, 0);
	o = list_table();
	CHECK(has(o, "198.18.0.1 : 10.2.2.2"));
	CHECK(has(o, "198.18.0.1 : jump mark_02000000"));
	CHECK(lacks(o, "fc00::1 :"));
	free(o);

	/* adds are idempotent: remapping an existing key always succeeds,
	 * also with the 4/6 family shorthand used by the fakeip DB */
	t3 = nft_elem_add(n, 4, f1, r1, 0x01000000);
	wait_on(&a, t3);
	run_loop();
	CHECK_EQ(a.err, 0);
	o = list_table();
	CHECK(has(o, "198.18.0.1 : 10.1.1.1"));
	free(o);

	/* same key twice in one loop iteration: the second op must win */
	nft_elem_add(n, 4, f1, r2, 0x02000000);
	t3 = nft_elem_add(n, 4, f1, r1, 0x01000000);
	wait_on(&a, t3);
	run_loop();
	CHECK_EQ(a.err, 0);
	o = list_table();
	CHECK(has(o, "198.18.0.1 : 10.1.1.1"));
	CHECK(has(o, "198.18.0.1 : jump mark_01000000"));
	free(o);
	/* add then delete in one iteration: element must be gone */
	nft_elem_add(n, 4, f1, r2, 0x02000000);
	t3 = nft_elem_del(n, 4, f1);
	wait_on(&a, t3);
	run_loop();
	CHECK_EQ(a.err, 0);
	o = list_table();
	CHECK(lacks(o, "198.18.0.1 :"));
	free(o);
	t3 = nft_elem_add(n, 4, f1, r1, 0x01000000);
	wait_on(&a, t3);
	run_loop();

	/* cancel: never fires */
	t3 = nft_elem_del(n, AF_INET, f2);
	wait_on(&a, t3);
	nft_wait_cancel(&a.w);
	nft_wait_cancel(&a.w);
	pending_waiters--;
	CHECK_EQ(nft_drain(n), 0);
	CHECK_EQ(a.fired, 0);
	CHECK(nft_ticket_done(n, t3));
	CHECK_EQ(count_elems("fake2real_v4"), 1);
	CHECK_EQ(nfails, 0);
}

TEST(async_failure)
{
	uint8_t f1[4], r1[4], f2[4];
	struct twait a, b;
	uint64_t t1, t2;
	char *o;

	bootstrap_marks();
	nfails = 0;
	v4(f1, "198.18.0.9"); v4(r1, "10.9.9.9"); v4(f2, "198.18.0.10");
	/* no chain mark_05000000 */
	t1 = nft_elem_add(n, AF_INET, f1, r1, 0x05000000);
	wait_on(&a, t1);
	run_loop();
	CHECK_EQ(a.fired, 1);
	CHECK(a.err < 0);
	CHECK_EQ(nfails, 1);
	CHECK_EQ(failed_ticket, t1);
	CHECK_EQ(failed_err, a.err);
	/* the real-map add in the same batch was rolled back */
	o = list_table();
	CHECK(lacks(o, "198.18.0.9"));
	free(o);

	/* deferred wait on a failed ticket reports the error */
	wait_on(&a, t1);
	run_loop();
	CHECK_EQ(a.err, failed_err);

	/* replace or delete of a non-existent element is a no-op (DESTROY) */
	t2 = nft_elem_add(n, AF_INET, f2, r1, 0x01000000);
	nft_elem_del(n, 6, (const uint8_t *)"\xfc\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x77");
	wait_on(&b, t2);
	run_loop();
	CHECK_EQ(b.err, 0);
	CHECK_EQ(nfails, 1);

	/* the next batch is unaffected */
	t2 = nft_elem_add(n, AF_INET, f2, r1, 0x01000000);
	wait_on(&b, t2);
	run_loop();
	CHECK_EQ(b.err, 0);
}

/*
 * Only a batch's last message asks for an ack. An error in an earlier
 * message (here the v4 mark add, before the v6 adds) still fails exactly
 * its batch, and the next batch, in flight at the same time, succeeds.
 */
TEST(async_failure_not_last)
{
	uint8_t f1[4], r1[4], f2[4], f6[16], r6[16];
	struct twait a, b;
	uint64_t t1, t2;
	char *o;

	bootstrap_marks();
	nfails = 0;
	v4(f1, "198.18.0.11"); v4(r1, "10.11.11.11"); v4(f2, "198.18.0.12");
	inet_pton(AF_INET6, "fc00::11", f6);
	inet_pton(AF_INET6, "2001:db8::11", r6);
	t1 = nft_elem_add(n, AF_INET, f1, r1, 0x05000000);	/* no chain */
	CHECK(nft_elem_add(n, AF_INET6, f6, r6, 0x01000000) == t1);
	nft_flush(n);
	t2 = nft_elem_add(n, AF_INET, f2, r1, 0x01000000);
	CHECK(t2 == t1 + 1);
	nft_flush(n);
	wait_on(&a, t1);
	wait_on(&b, t2);
	run_loop();
	CHECK_EQ(a.fired, 1);
	CHECK(a.err < 0);
	CHECK_EQ(b.fired, 1);
	CHECK_EQ(b.err, 0);
	CHECK_EQ(nfails, 1);
	CHECK_EQ(failed_ticket, t1);
	o = list_table();
	CHECK(lacks(o, "198.18.0.11"));
	CHECK(lacks(o, "fc00::11"));
	CHECK(has(o, "198.18.0.12 : jump mark_01000000"));
	free(o);
	nft_elem_del(n, AF_INET, f2);
	CHECK_EQ(nft_drain(n), 0);
}

TEST(async_big_batch)
{
	enum { N = NFT_BATCH_MAX + 500 };
	uint64_t first = 0, last = 0;
	struct twait a, b;
	uint8_t f[4], r[4] = { 10, 0, 0, 1 };

	bootstrap_marks();
	nfails = 0;
	for (int i = 0; i < N; i++) {
		uint64_t t;

		f[0] = 198; f[1] = 18; f[2] = (uint8_t)(i >> 8); f[3] = (uint8_t)i;
		t = nft_elem_add(n, AF_INET, f, r, 0x01000000);
		if (!first)
			first = t;
		last = t;
	}
	CHECK_EQ(last, first + 1);
	wait_on(&a, first);
	wait_on(&b, last);
	run_loop();
	CHECK_EQ(a.err, 0);
	CHECK_EQ(b.err, 0);
	CHECK_EQ(count_elems("fake2real_v4"), N);
	CHECK_EQ(count_elems("fake2mark_v4"), N);

	/* delete them all again, in big batches drained synchronously */
	for (int i = 0; i < N; i++) {
		f[0] = 198; f[1] = 18; f[2] = (uint8_t)(i >> 8); f[3] = (uint8_t)i;
		nft_elem_del(n, AF_INET, f);
	}
	CHECK_EQ(nft_drain(n), 0);
	CHECK_EQ(count_elems("fake2real_v4"), 0);
	CHECK_EQ(nfails, 0);
}

/*
 * Several batches in flight at once (each flushed synchronously at
 * NFT_BATCH_MAX ops, so their encoded elements are already gone when the
 * acks arrive), one of them failing in the kernel.
 */
TEST(async_burst_inflight)
{
	enum { N = 3 * NFT_BATCH_MAX + 100, BAD = NFT_BATCH_MAX + 500, MAXB = 8 };
	static uint64_t tick[N];
	uint64_t tickets[MAXB], bad_ticket = 0;
	struct twait w[MAXB];
	uint32_t per[MAXB] = { 0 }, nb = 0;
	uint8_t f[4], r[4] = { 10, 0, 0, 2 };

	bootstrap_marks();
	nfails = 0;
	for (int i = 0; i < N; i++) {
		f[0] = 198; f[1] = 19; f[2] = (uint8_t)(i >> 8); f[3] = (uint8_t)i;
		if (i == BAD) {
			uint8_t bf[4] = { 198, 18, 250, 250 };

			/* no chain mark_07000000: fails its whole batch */
			bad_ticket = nft_elem_add(n, AF_INET, bf, r, 0x07000000);
		}
		tick[i] = nft_elem_add(n, AF_INET, f, r, 0x02000000);
		if (!nb || tickets[nb - 1] != tick[i]) {
			REQUIRE(nb < MAXB);
			tickets[nb++] = tick[i];
		}
		per[nb - 1]++;
	}
	CHECK(nb >= 4);
	CHECK(bad_ticket > tickets[0] && bad_ticket < tickets[nb - 1]);
	for (uint32_t i = 0; i < nb; i++) {
		CHECK(!nft_ticket_done(n, tickets[i]));
		wait_on(&w[i], tickets[i]);
	}
	run_loop();
	long expect = 0;

	for (uint32_t i = 0; i < nb; i++) {
		CHECK_EQ(w[i].fired, 1);
		if (tickets[i] == bad_ticket) {
			CHECK(w[i].err < 0);
		} else {
			CHECK_EQ(w[i].err, 0);
			expect += per[i];
		}
		CHECK(nft_ticket_done(n, tickets[i]));
	}
	CHECK_EQ(nfails, 1);
	CHECK_EQ(failed_ticket, bad_ticket);
	CHECK_EQ(count_elems("fake2real_v4"), expect);
	CHECK_EQ(count_elems("fake2mark_v4"), expect);

	/* a key re-added right after: its pending add forces a new batch,
	 * also across the many batches already sent */
	f[0] = 198; f[1] = 19; f[2] = 0; f[3] = 1;
	uint64_t t1 = nft_elem_add(n, AF_INET, f, r, 0x01000000);
	uint64_t t2 = nft_elem_add(n, AF_INET, f, r, 0x02000000);
	CHECK(t2 == t1 + 1);
	for (int i = 0; i < N; i++) {
		f[0] = 198; f[1] = 19; f[2] = (uint8_t)(i >> 8); f[3] = (uint8_t)i;
		nft_elem_del(n, AF_INET, f);
	}
	CHECK_EQ(nft_drain(n), 0);
	CHECK_EQ(count_elems("fake2real_v4"), 0);
	CHECK_EQ(count_elems("fake2mark_v4"), 0);
	CHECK_EQ(nfails, 1);
}

/* the fakeip DB on the real kernel: a failed batch drops its bindings */
TEST(fakeip_failed_batch)
{
	static const uint8_t secret[16] = { 1 };
	struct ip_prefix p4 = pfx(AF_INET, "198.18.0.0", 15);
	struct fakeip_db *db;
	struct binding *a, *b, *c;
	struct twait wa, wc;
	int err;
	uint8_t r[4] = { 10, 3, 3, 3 }, afake[4], bfake[4];
	char *o, buf[64];

	static const uint32_t marks[] = { 0x01000000, 0x02000000, 0x05000000 };
	struct nft_desired d = desired(true, false, marks, 3);

	REQUIRE(nft_bootstrap(n, &d) == 0);
	db = fakeip_new(&p4, NULL, 100, 0, secret, n);	/* takes the fail hook */
	REQUIRE(db);
	/* a mark without a chain is refused up front */
	CHECK(!fakeip_bind(db, "r", 0x06000000, (const uint8_t *)"\1x\0", 3, 4, r, 60, &err));
	CHECK_EQ(err, -ESTALE);
	/* a chain deleted behind our back: the batch fails in the kernel */
	free(sh("nft flush chain inet " TABLE " restore_marks; "
	        "nft delete chain inet " TABLE " mark_05000000"));
	a = fakeip_bind(db, "r", 0x01000000, (const uint8_t *)"\1a\0", 3, 4, r, 60, &err);
	b = fakeip_bind(db, "r", 0x05000000, (const uint8_t *)"\1b\0", 3, 4, r, 60, &err);
	REQUIRE(a && b);
	CHECK_EQ(a->ticket, b->ticket);
	memcpy(afake, a->fake, 4);
	memcpy(bfake, b->fake, 4);
	fakeip_ref(a);		/* a cache entry still holds it */
	nft_flush(n);		/* sent; encoded elements discarded */
	c = fakeip_bind(db, "r", 0x02000000, (const uint8_t *)"\1c\0", 3, 4, r, 60, &err);
	REQUIRE(c);
	CHECK(c->ticket > a->ticket);
	wait_on(&wa, a->ticket);
	wait_on(&wc, c->ticket);
	run_loop();
	CHECK_EQ(wa.fired, 1);
	CHECK(wa.err < 0);
	CHECK_EQ(wc.fired, 1);
	CHECK_EQ(wc.err, 0);
	CHECK(nft_ticket_done(n, a->ticket));
	CHECK_EQ(fakeip_count(db), 1);
	CHECK(!fakeip_lookup(db, 4, afake));
	CHECK(!fakeip_lookup(db, 4, bfake));
	CHECK(fakeip_lookup(db, 4, c->fake) == c);
	/* a later (deferred) wait on the failed ticket still reports it */
	wait_on(&wa, a->ticket);
	run_loop();
	CHECK_EQ(wa.fired, 1);
	CHECK(wa.err < 0);
	o = list_table();
	inet_ntop(AF_INET, afake, buf, sizeof(buf));
	CHECK(lacks(o, buf));
	inet_ntop(AF_INET, c->fake, buf, sizeof(buf));
	strcat(buf, " : 10.3.3.3");
	CHECK(has(o, buf));
	free(o);
	fakeip_unref(db, a);	/* detached: freed now */
	fakeip_free(db);
	nft_set_fail_hook(n, fail_hook, NULL);
}

/*
 * A failed batch rolls back the deletes it carried, so the kernel may keep
 * elements the binding table already forgot, jumping to old mark chains. An
 * fwmask change (accepted only with no live binding) must still be able to
 * delete those chains: it recreates the table, maps included. Any
 * other reconcile leaves the maps alone.
 */
TEST(reconcile_fwmask_stale_elems)
{
	static const uint32_t m1[] = { 0x01000000 };
	static const uint32_t m2[] = { 0x01000000, 0x02000000 };
	static const uint32_t m3[] = { 0x00010000 };
	struct nft_desired d = desired(true, true, m1, 1);
	uint8_t f1[4], r1[4], f2[4], f6[16], r6[16];
	struct twait a, b;
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	v4(f1, "198.18.0.21"); v4(r1, "10.2.1.1"); v4(f2, "198.18.0.22");
	inet_pton(AF_INET6, "fc00::21", f6);
	inet_pton(AF_INET6, "2001:db8::21", r6);
	nft_elem_add(n, AF_INET, f1, r1, 0x01000000);
	wait_on(&a, nft_elem_add(n, AF_INET6, f6, r6, 0x01000000));
	run_loop();
	CHECK_EQ(a.err, 0);
	/* the delete shares a batch with an add the kernel rejects (no chain) */
	nft_elem_del(n, AF_INET, f1);
	nft_elem_del(n, AF_INET6, f6);
	wait_on(&b, nft_elem_add(n, AF_INET, f2, r1, 0x05000000));
	run_loop();
	CHECK(b.err < 0);
	CHECK_EQ(count_elems("fake2mark_v4"), 1);
	CHECK_EQ(count_elems("fake2real_v6"), 1);

	/* a reload keeping the fwmask keeps the elements */
	d.marks = m2;
	d.nmarks = 2;
	CHECK_EQ(nft_reconcile(n, &d), 0);
	CHECK_EQ(count_elems("fake2real_v4"), 1);
	CHECK_EQ(count_elems("fake2mark_v6"), 1);

	/* an fwmask change drops them with the old chains */
	d.fwmask = 0x00ff0000;
	d.marks = m3;
	d.nmarks = 1;
	CHECK_EQ(nft_reconcile(n, &d), 0);
	CHECK(nft_mark_known(n, 0x00010000));
	CHECK(!nft_mark_known(n, 0x01000000));
	CHECK_EQ(count_elems("fake2real_v4"), 0);
	CHECK_EQ(count_elems("fake2mark_v4"), 0);
	CHECK_EQ(count_elems("fake2real_v6"), 0);
	CHECK_EQ(count_elems("fake2mark_v6"), 0);
	o = list_table();
	CHECK(lacks(o, "mark_01000000"));
	CHECK(has(o, "chain mark_00010000"));
	free(o);

	/* the maps still work */
	wait_on(&a, nft_elem_add(n, AF_INET, f1, r1, 0x00010000));
	run_loop();
	CHECK_EQ(a.err, 0);
	CHECK_EQ(count_elems("fake2mark_v4"), 1);
}

/* ---- adoption across a restart ---- */

static const uint8_t secret_a[NFT_SECRET_LEN] = { 0xa1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static const uint8_t secret_b[NFT_SECRET_LEN] = { 0xb2, 7 };

static void elem_sync(int family, const char *fake, const char *real, uint32_t mark)
{
	uint8_t f[16], r[16];

	inet_pton(family, fake, f);
	inet_pton(family, real, r);
	nft_elem_add(n, family, f, r, mark);
}

/* a second context on the same table, as a restarted daemon has */
static int adopt(const struct nft_desired *d, uint32_t max, uint8_t *secret,
                 struct nft_elem **el, uint32_t *nel, struct nft_ctx **out)
{
	struct nft_ctx *m = nft_open(TABLE);
	int r = m ? nft_adopt(m, d, max, secret, el, nel) : -1;

	if (out)
		*out = m;
	else
		nft_close(m);
	return r;
}

static bool elem_is(const struct nft_elem *e, int family, const char *fake, bool ok,
                    const char *real, uint32_t mark)
{
	uint8_t f[16] = { 0 }, r[16] = { 0 };

	inet_pton(family, fake, f);
	if (real)
		inet_pton(family, real, r);
	return e->family == (family == AF_INET ? 4 : 6) && !memcmp(e->fake, f, 16) &&
	       e->ok == ok && (!ok || (!memcmp(e->real, r, 16) && e->mark == mark));
}

TEST(adopt_userdata_secret)
{
	static const uint32_t m1[] = { 0x01000000 };
	struct nft_desired d = desired(true, false, m1, 1);
	uint8_t got[NFT_SECRET_LEN];
	struct nft_elem *el;
	uint32_t nel;
	char *o;

	nft_set_secret(n, secret_a);
	REQUIRE(nft_bootstrap(n, &d) == 0);
	memset(got, 0, sizeof(got));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 1);
	CHECK(!memcmp(got, secret_a, sizeof(got)));
	CHECK_EQ(nel, 0);
	free(el);
	/* nft still lists the table (it ignores our userdata types) */
	o = list_table();
	CHECK(has(o, "chain mark_01000000"));
	free(o);

	/* an fwmask change recreates the table: same secret, new fwmask */
	nft_set_secret(n, secret_b);	/* not used: the table already has one */
	{
		struct nft_ctx *m;

		REQUIRE(adopt(&d, 100, got, &el, &nel, &m) == 1);
		free(el);
		d.fwmask = 0x00ff0000;
		d.nmarks = 0;
		CHECK_EQ(nft_reconcile(m, &d), 0);
		nft_close(m);
	}
	memset(got, 0, sizeof(got));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 1);
	CHECK(!memcmp(got, secret_a, sizeof(got)));
	free(el);
	d.fwmask = 0xff000000;
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);	/* the old fwmask */

	/* an fwmask change never brings back a table deleted meanwhile (-F) */
	REQUIRE(nft_bootstrap(n, &d) == 0);
	free(sh("nft delete table inet " TABLE));
	d.fwmask = 0x00ff0000;
	CHECK(nft_reconcile(n, &d) < 0);
	o = list_table();
	CHECK(lacks(o, "table inet " TABLE " {"));
	free(o);
}

TEST(adopt_dump)
{
	static const uint32_t m1[] = { 0x01000000, 0x02000000 };
	struct nft_desired d = desired(true, true, m1, 2);
	uint8_t got[NFT_SECRET_LEN];
	struct nft_elem *el;
	uint32_t nel;

	nft_set_secret(n, secret_a);
	REQUIRE(nft_bootstrap(n, &d) == 0);
	elem_sync(AF_INET, "198.18.0.1", "10.1.1.1", 0x01000000);
	elem_sync(AF_INET6, "fc00::1", "2001:db8::1", 0x02000000);
	elem_sync(AF_INET, "198.18.0.3", "10.3.3.3", 0x02000000);
	REQUIRE(nft_drain(n) == 0);
	/* foreign state: a half element, a jump to a foreign chain, a mark
	 * chain we did not make (not valid for the fwmask) */
	free(sh("nft add chain inet " TABLE " foo; nft add chain inet " TABLE " mark_00000001; "
	        "nft add element inet " TABLE " fake2real_v4 '{ 198.18.0.9 : 10.9.9.9 }'; "
	        "nft add element inet " TABLE " fake2real_v4 '{ 198.18.0.10 : 10.9.9.9 }'; "
	        "nft add element inet " TABLE " fake2mark_v4 '{ 198.18.0.10 : jump foo }'; "
	        "nft add element inet " TABLE " fake2mark_v4 '{ 198.18.0.11 : jump mark_00000001 }'; "
	        "nft add element inet " TABLE " fake2mark_v6 '{ fc00::2 : jump mark_01000000 }'"));
	REQUIRE(adopt(&d, 100, got, &el, &nel, NULL) == 1);
	REQUIRE(nel == 7);
	CHECK(elem_is(&el[0], AF_INET, "198.18.0.1", true, "10.1.1.1", 0x01000000));
	CHECK(elem_is(&el[1], AF_INET, "198.18.0.3", true, "10.3.3.3", 0x02000000));
	CHECK(elem_is(&el[2], AF_INET, "198.18.0.9", false, NULL, 0));
	CHECK(elem_is(&el[3], AF_INET, "198.18.0.10", false, NULL, 0));
	CHECK(elem_is(&el[4], AF_INET, "198.18.0.11", false, NULL, 0));
	CHECK(elem_is(&el[5], AF_INET6, "fc00::1", true, "2001:db8::1", 0x02000000));
	CHECK(elem_is(&el[6], AF_INET6, "fc00::2", false, NULL, 0));
	free(el);
	/* bounded: more elements in the fake2mark (or fake2real) maps than
	 * allowed declines adoption; here 6 (and 5) */
	el = NULL;
	CHECK_EQ(adopt(&d, 5, got, &el, &nel, NULL), 0);
	CHECK(!el);
	CHECK_EQ(adopt(&d, 6, got, &el, &nel, NULL), 1);
	free(el);
	free(sh("nft flush map inet " TABLE " fake2mark_v4; nft flush map inet " TABLE " fake2real_v4; "
	        "nft flush map inet " TABLE " fake2mark_v6; nft flush map inet " TABLE " fake2real_v6; "
	        "nft delete chain inet " TABLE " mark_00000001; nft delete chain inet " TABLE " foo"));
}

/* a restarted daemon: adopt, destroy what it does not keep, reconcile */
TEST(adopt_reconcile_keeps_elements)
{
	static const uint32_t m1[] = { 0x01000000, 0x02000000 };
	static const uint32_t m2[] = { 0x01000000 };
	struct nft_desired d = desired(true, true, m1, 2);
	uint8_t got[NFT_SECRET_LEN], f[4];
	struct nft_elem *el;
	struct nft_ctx *m;
	uint32_t nel;
	char *a, *b;

	nft_set_secret(n, secret_a);
	REQUIRE(nft_bootstrap(n, &d) == 0);
	elem_sync(AF_INET, "198.18.0.1", "10.1.1.1", 0x01000000);
	elem_sync(AF_INET, "198.18.0.2", "10.2.2.2", 0x02000000);
	REQUIRE(nft_drain(n) == 0);
	a = sh("nft -a list table inet " TABLE);

	/* unchanged desired state: nothing is sent */
	REQUIRE(adopt(&d, 100, got, &el, &nel, &m) == 1);
	CHECK_EQ(nel, 2);
	free(el);
	CHECK(nft_mark_known(m, 0x02000000));
	CHECK_EQ(nft_reconcile(m, &d), 0);
	b = sh("nft -a list table inet " TABLE);
	CHECK_STR(a, b);
	free(b);

	/* the restarted daemon keeps only the first: mark_02000000 goes */
	v4(f, "198.18.0.2");
	nft_elem_del(m, AF_INET, f);
	CHECK_EQ(nft_drain(m), 0);
	d.marks = m2;
	d.nmarks = 1;
	CHECK_EQ(nft_reconcile(m, &d), 0);
	b = list_table();
	CHECK(has(b, "198.18.0.1 : 10.1.1.1"));
	CHECK(has(b, "198.18.0.1 : jump mark_01000000"));
	CHECK(lacks(b, "198.18.0.2"));
	CHECK(lacks(b, "mark_02000000"));
	free(b);
	nft_close(m);

	/* policy rules edited behind our back: the adopting reconcile rewrites them */
	free(sh("nft flush chain inet " TABLE " forward_reject"));
	REQUIRE(adopt(&d, 100, got, &el, &nel, &m) == 1);
	free(el);
	CHECK_EQ(nft_reconcile(m, &d), 0);
	b = list_table();
	CHECK(has(b, "chain forward_reject {\n\t\ttype filter hook forward priority "
	          "filter - 1; policy accept;\n\t\tip daddr 198.18.0.0/15 reject"));
	CHECK(has(b, "198.18.0.1 : 10.1.1.1"));
	free(b);
	/* ... and so is a pool change made while no daemon ran */
	d.pool4 = pfx(AF_INET, "198.18.0.0", 16);
	nft_close(m);
	REQUIRE(adopt(&d, 100, got, &el, &nel, &m) == 1);
	free(el);
	CHECK_EQ(nft_reconcile(m, &d), 0);
	b = list_table();
	CHECK(has(b, "ip daddr 198.18.0.0/16 dnat ip to ip daddr map @fake2real_v4"));
	free(b);
	nft_close(m);
	free(a);
}

TEST(adopt_mismatch_bootstraps)
{
	static const uint32_t m1[] = { 0x01000000 };
	struct nft_desired d = desired(true, false, m1, 1);
	uint8_t got[NFT_SECRET_LEN];
	struct nft_elem *el;
	uint32_t nel;

	nft_set_secret(n, secret_a);
	REQUIRE(nft_bootstrap(n, &d) == 0);
	elem_sync(AF_INET, "198.18.0.1", "10.1.1.1", 0x01000000);
	REQUIRE(nft_drain(n) == 0);
	/* another fwmask */
	d.fwmask = 0x0f000000;
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
	CHECK(!el && !nel);
	d.fwmask = 0xff000000;
	/* a chain missing */
	free(sh("nft delete chain inet " TABLE " output_reject"));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
	/* no table */
	free(sh("nft delete table inet " TABLE));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
	/* a table without our userdata (another layout version) */
	free(sh("nft add table inet " TABLE " '{ comment \"x\"; }'"));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
	/* the bootstrap that follows replaces it with a fresh secret */
	nft_set_secret(n, secret_b);
	REQUIRE(nft_bootstrap(n, &d) == 0);
	CHECK_EQ(count_elems("fake2real_v4"), 0);
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 1);
	CHECK(!memcmp(got, secret_b, sizeof(got)));
	free(el);
}

/* commit one table or rule message in a batch of its own; 0 or -errno */
static int raw_commit(uint16_t type, uint16_t flags, struct nftnl_table *t, struct nftnl_rule *r)
{
	struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
	char buf[8192];
	struct mnl_nlmsg_batch *b = mnl_nlmsg_batch_start(buf, sizeof(buf));
	struct nlmsghdr *nlh;
	int err = -errno;
	ssize_t len;

	if (!nl)
		return err;
	mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	nftnl_batch_begin(mnl_nlmsg_batch_current(b), 1);
	mnl_nlmsg_batch_next(b);
	nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(b), type, NFPROTO_INET,
	                            flags | NLM_F_ACK, 2);
	if (t)
		nftnl_table_nlmsg_build_payload(nlh, t);
	else
		nftnl_rule_nlmsg_build_payload(nlh, r);
	mnl_nlmsg_batch_next(b);
	nftnl_batch_end(mnl_nlmsg_batch_current(b), 3);
	mnl_nlmsg_batch_next(b);
	err = 0;
	if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(b), mnl_nlmsg_batch_size(b)) < 0 ||
	    (len = mnl_socket_recvfrom(nl, buf, sizeof(buf))) < 0 ||
	    mnl_cb_run(buf, (size_t)len, 0, 0, NULL, NULL) < 0)
		err = -errno;
	mnl_nlmsg_batch_stop(b);
	mnl_socket_close(nl);
	return err;
}

/* userdata TLVs (type, length, value) */
static size_t tlv(uint8_t *p, uint8_t type, uint8_t len, const void *v, size_t vlen)
{
	p[0] = type;
	p[1] = len;
	memcpy(p + 2, v, vlen);
	return 2 + vlen;
}

/*
 * A userdata TLV claiming more bytes than the attribute holds is ignored,
 * never read past (ASan): the table's (a secret cut short, a lone type
 * byte), a rule's (a tag cut short).
 */
TEST(adopt_crafted_userdata)
{
	static const uint32_t m1[] = { 0x01000000 };
	struct nft_desired d = desired(true, false, m1, 1);
	uint32_t ver = NFT_LAYOUT_VERSION, mask = d.fwmask;
	uint8_t got[NFT_SECRET_LEN], ud[64], *u;
	struct nftnl_table *t;
	struct nftnl_rule *r;
	struct nft_elem *el;
	uint32_t nel;
	size_t len;
	char *o;

	len = tlv(ud, 0x80, 4, &ver, 4);
	len += tlv(ud + len, 0x81, 4, &mask, 4);
	for (int lone = 0; lone < 2; lone++) {
		size_t l = len + (lone ? 0 : tlv(ud + len, 0x82, NFT_SECRET_LEN, secret_a, 3));

		if (lone)
			ud[l++] = 0x82;
		free(sh("nft delete table inet " TABLE " 2>/dev/null"));
		/* an exact-size copy, so that ASan sees a read past it */
		u = malloc(l);
		memcpy(u, ud, l);
		t = nftnl_table_alloc();
		nftnl_table_set_str(t, NFTNL_TABLE_NAME, TABLE);
		nftnl_table_set_data(t, NFTNL_TABLE_USERDATA, u, (uint32_t)l);
		REQUIRE(raw_commit(NFT_MSG_NEWTABLE, NLM_F_CREATE, t, NULL) == 0);
		nftnl_table_free(t);
		free(u);
		CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
	}

	nft_set_secret(n, secret_a);
	REQUIRE(nft_bootstrap(n, &d) == 0);
	r = nftnl_rule_alloc();
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, TABLE);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, "forward_reject");
	len = tlv(ud, 0x80, 8, &ver, 2);
	nftnl_rule_set_data(r, NFTNL_RULE_USERDATA, ud, (uint32_t)len);
	REQUIRE(raw_commit(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND, NULL, r) == 0);
	nftnl_rule_free(r);
	{
		struct nft_ctx *m;

		REQUIRE(adopt(&d, 100, got, &el, &nel, &m) == 1);
		free(el);
		CHECK_EQ(nft_reconcile(m, &d), 0);	/* the rule was not ours */
		nft_close(m);
	}
	o = list_table();
	CHECK(has(o, "chain forward_reject {\n\t\ttype filter hook forward priority filter - 1; "
	          "policy accept;\n\t\tip daddr 198.18.0.0/15 reject with icmp port-unreachable\n\t}"));
	free(o);
}

/* recv() is interposed too, to count what a context reads */
static bool count_recv;
static size_t recv_bytes;

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	static ssize_t (*real_recv)(int, void *, size_t, int);
	ssize_t r;

	if (!real_recv)
		*(void **)&real_recv = dlsym(RTLD_NEXT, "recv");
	r = real_recv(fd, buf, len, flags);
	if (count_recv && r > 0)
		recv_bytes += (size_t)r;
	return r;
}

/* fakes 198.18.0.1 ... (and fc00::1 ...) mapped to 10.0.0.0 ..., all with `mark` */
static void fill_maps(uint32_t cnt, bool v6, uint32_t mark)
{
	for (uint32_t i = 0; i < cnt; i++) {
		uint8_t f[16] = { 0 }, r[16] = { 0 };
		uint32_t a = htonl(0xc6120001 + i), b = htonl(0x0a000000 + i);

		if (v6) {
			inet_pton(AF_INET6, "fc00::", f);
			memcpy(f + 12, &a, 4);
			inet_pton(AF_INET6, "2001:db8::", r);
			memcpy(r + 12, &b, 4);
		} else {
			memcpy(f, &a, 4);
			memcpy(r, &b, 4);
		}
		nft_elem_add(n, v6 ? AF_INET6 : AF_INET, f, r, mark);
	}
	REQUIRE(nft_drain(n) == 0);
}

/*
 * Declining at the element cap ends the dump: the kernel does not go on
 * filling a socket that the next transaction then has to drain.
 */
TEST(adopt_cap_bounds_work)
{
	static const uint32_t m1[] = { 0x01000000 };
	struct nft_desired d = desired(true, false, m1, 1);
	uint8_t got[NFT_SECRET_LEN];
	struct nft_elem *el;
	struct nft_ctx *m;
	uint32_t nel;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	fill_maps(4000, false, 0x01000000);
	REQUIRE(adopt(&d, 5, got, &el, &nel, &m) == 0);
	recv_bytes = 0;
	count_recv = true;
	CHECK_EQ(nft_bootstrap(m, &d), 0);
	count_recv = false;
	CHECK_EQ(recv_bytes < 4096 ? 0 : recv_bytes, 0);
	nft_close(m);
}

/* commits in another table, as fw4 or mwan3 may make them any time (in
 * this netns, one every few ms) */
static pid_t churn_start(unsigned pause_us)
{
	pid_t pid = fork();

	if (pid)
		return pid;
	for (bool add = true;; add = !add) {
		struct nftnl_table *t = nftnl_table_alloc();

		nftnl_table_set_str(t, NFTNL_TABLE_NAME, "churn");
		raw_commit(add ? NFT_MSG_NEWTABLE : NFT_MSG_DELTABLE, add ? NLM_F_CREATE : 0, t,
		           NULL);
		nftnl_table_free(t);
		usleep(pause_us);
	}
}

static void churn_stop(pid_t pid)
{
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	free(sh("nft delete table inet churn 2>/dev/null"));
}

/*
 * A commit anywhere while a dump runs interrupts it (NLM_F_DUMP_INTR): the
 * readback starts over, and adoption still succeeds.
 */
TEST(adopt_under_churn)
{
	static const uint32_t m1[] = { 0x01000000 };
	struct nft_desired d = desired(true, true, m1, 1);
	uint8_t got[NFT_SECRET_LEN];
	struct nft_elem *el;
	uint32_t nel;
	int ok = 0;
	pid_t pid;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	fill_maps(2000, false, 0x01000000);
	fill_maps(2000, true, 0x01000000);
	/* a large foreign table: the chain dump, of all tables, takes a while */
	free(sh("{ echo 'add table inet foreign'; for i in $(seq 10000); do "
	        "echo \"add chain inet foreign c$i\"; done; } | nft -f -"));
	pid = churn_start(10000);
	for (int i = 0; i < 30; i++) {
		el = NULL;
		if (adopt(&d, 10000, got, &el, &nel, NULL) == 1 && nel == 4000)
			ok++;
		free(el);
	}
	churn_stop(pid);
	free(sh("nft delete table inet foreign"));
	CHECK_EQ(ok, 30);
}

/* ---- real packets in the netns ---- */

static int tcp_connect(const char *dst, int port)
{
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
	int fd = socket(AF_INET, SOCK_STREAM, 0), err = 0;

	inet_pton(AF_INET, dst, &sa.sin_addr);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		err = errno;
	close(fd);
	return err;
}

static long counter_packets(const char *chain_line)
{
	char cmd[256], *o, *p;
	long v = -1;

	snprintf(cmd, sizeof(cmd),
	         "nft list chain ip omnicnt out | grep '%s'", chain_line);
	o = sh(cmd);
	p = strstr(o, "packets ");
	if (p)
		v = strtol(p + 8, NULL, 10);
	free(o);
	return v;
}

TEST(packets)
{
	static const uint32_t marks[] = { 0x01000000 };
	struct nft_desired d = desired(true, false, marks, 1);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(5555) };
	uint8_t fake[4], real[4];
	int lfd, one = 1;
	char *o;

	free(sh("ip link set lo up; ip link add d0 type dummy; ip link set d0 up;"
		"ip addr add 10.99.0.1/24 dev d0; ip route add 198.18.0.0/15 dev d0"));
	free(sh("nft -f - <<'EOF'\n"
		"table ip omnicnt {\n"
		" chain out {\n"
		"  type filter hook output priority 10; policy accept;\n"
		"  ip daddr 127.0.0.1 tcp dport 5555 meta mark 0x01000000 counter\n"
		"  ip daddr 127.0.0.1 tcp dport 5555 ct mark 0x01000000 counter\n"
		" }\n"
		"}\nEOF"));
	REQUIRE(nft_bootstrap(n, &d) == 0);
	v4(fake, "198.18.0.5");
	v4(real, "127.0.0.1");
	nft_elem_add(n, AF_INET, fake, real, 0x01000000);
	REQUIRE(nft_drain(n) == 0);

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	REQUIRE(bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	REQUIRE(listen(lfd, 4) == 0);

	CHECK_EQ(tcp_connect("198.18.0.5", 5555), 0);
	CHECK_EQ(tcp_connect("198.18.0.6", 5555), ECONNREFUSED);
	close(lfd);

	CHECK(counter_packets("meta mark") > 0);
	CHECK(counter_packets("ct mark") > 0);
	o = sh("nft list table ip omnicnt");
	if (counter_packets("meta mark") <= 0)
		fprintf(stderr, "%s\n", o);
	free(o);
	free(sh("nft delete table ip omnicnt"));
}

TEST(destroy)
{
	char *o;

	CHECK_EQ(nft_destroy_table(n), 0);
	o = list_table();
	CHECK(lacks(o, "table inet " TABLE " {"));
	free(o);
	CHECK_EQ(nft_destroy_table(n), 0);
}

/*
 * ---- wire format of element batches ----
 *
 * mnl_socket_sendto() is interposed (this executable's definition wins over
 * libmnl's for the statically linked nft.o) to capture the async batches.
 * ref_batch() is a reference encoder built on libnftnl's set-element API,
 * grouping and chunking elements the way nft.c did before it encoded them
 * itself: the captured bytes must be identical.
 */
static struct {
	bool on;
	char *p;
	size_t len, cap;
	uint32_t nsend;
	size_t off[64];		/* start of each captured send */
} cap;

ssize_t mnl_socket_sendto(const struct mnl_socket *nl, const void *buf, size_t len)
{
	static ssize_t (*real_sendto)(const struct mnl_socket *, const void *, size_t);

	if (!real_sendto)
		*(void **)&real_sendto = dlsym(RTLD_NEXT, "mnl_socket_sendto");
	if (cap.on && cap.nsend < 64) {
		if (cap.len + len > cap.cap) {
			cap.cap = (cap.len + len) * 2;
			cap.p = realloc(cap.p, cap.cap);
		}
		cap.off[cap.nsend++] = cap.len;
		memcpy(cap.p + cap.len, buf, len);
		cap.len += len;
	}
	return real_sendto(nl, buf, len);
}

static void cap_start(void)
{
	cap.len = 0;
	cap.nsend = 0;
	cap.on = true;
}

static const char *cap_send(uint32_t i, size_t *len)
{
	*len = (i + 1 < cap.nsend ? cap.off[i + 1] : cap.len) - cap.off[i];
	return cap.p + cap.off[i];
}

struct rop {
	int fam;		/* 4 or 6 */
	bool add;
	uint32_t mark;
	uint8_t fake[16], real[16];
};

static const char *const ref_sets[4] = {
	"fake2real_v4", "fake2mark_v4", "fake2real_v6", "fake2mark_v6",
};

/*
 * one batch: BEGIN, per phase (destroys, adds) per set chunks of 256, END;
 * only the last message before END asks for an ack (nft.c set NLM_F_ACK on
 * every message until it adopted the control plane's single final ack)
 */
static size_t ref_batch(char *buf, uint32_t seq, const struct rop *ops, uint32_t nops)
{
	size_t len = 0;
	struct nlmsghdr *nlh, *last = NULL;

	nlh = nftnl_batch_begin(buf, seq++);
	len += MNL_ALIGN(nlh->nlmsg_len);
	for (int phase = 0; phase < 2; phase++) {
		for (int s = 0; s < 4; s++) {
			int fam = s < 2 ? 4 : 6, alen = fam == 4 ? 4 : 16;
			bool mark = s & 1;
			struct nftnl_set *set = NULL;
			uint32_t cnt = 0;

			for (uint32_t i = 0; i <= nops; i++) {
				const struct rop *o = &ops[i];
				struct nftnl_set_elem *e;
				char chain[32];

				if (set && (i == nops || cnt == 256)) {
					int type = phase ? NFT_MSG_NEWSETELEM : NFT_MSG_DESTROYSETELEM;

					nlh = nftnl_nlmsg_build_hdr(buf + len, type, NFPROTO_INET,
					        phase ? NLM_F_CREATE : 0, seq++);
					nftnl_set_elems_nlmsg_build_payload(nlh, set);
					last = nlh;
					len += MNL_ALIGN(nlh->nlmsg_len);
					nftnl_set_free(set);
					set = NULL;
					cnt = 0;
				}
				if (i == nops)
					break;
				if (o->fam != fam || (phase && !o->add))
					continue;
				if (!set) {
					set = nftnl_set_alloc();
					nftnl_set_set_str(set, NFTNL_SET_TABLE, TABLE);
					nftnl_set_set_str(set, NFTNL_SET_NAME, ref_sets[s]);
				}
				e = nftnl_set_elem_alloc();
				nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, o->fake, alen);
				if (phase && !mark) {
					nftnl_set_elem_set(e, NFTNL_SET_ELEM_DATA, o->real, alen);
				} else if (phase) {
					snprintf(chain, sizeof(chain), "mark_%08x", o->mark);
					nftnl_set_elem_set_u32(e, NFTNL_SET_ELEM_VERDICT, NFT_JUMP);
					nftnl_set_elem_set_str(e, NFTNL_SET_ELEM_CHAIN, chain);
				}
				nftnl_set_elem_add(set, e);
				cnt++;
			}
		}
	}
	if (last)
		last->nlmsg_flags |= NLM_F_ACK;
	nlh = nftnl_batch_end(buf + len, seq);
	len += MNL_ALIGN(nlh->nlmsg_len);
	return len;
}

static void hexdiff(const char *a, size_t alen, const char *b, size_t blen)
{
	size_t i = 0;

	while (i < alen && i < blen && a[i] == b[i])
		i++;
	fprintf(stderr, "    batch differs at byte %zu (got %zu bytes, want %zu)\n",
		i, alen, blen);
}

/* submit ops (which must fit in one batch), compare the wire bytes */
static int wire_check(const struct rop *ops, uint32_t nops, uint32_t send)
{
	static char want[1 << 20];
	const struct nlmsghdr *got;
	size_t glen, wlen;

	got = (const struct nlmsghdr *)cap_send(send, &glen);
	wlen = ref_batch(want, got->nlmsg_seq, ops, nops);
	if (glen == wlen && !memcmp(got, want, wlen))
		return 1;
	hexdiff((const char *)got, glen, want, wlen);
	return 0;
}

static void rop_queue(const struct rop *o)
{
	if (o->add)
		nft_elem_add(n, o->fam, o->fake, o->real, o->mark);
	else
		nft_elem_del(n, o->fam, o->fake);
}

static void rop_key(struct rop *o, int fam, uint32_t i)
{
	memset(o->fake, 0, sizeof(o->fake));
	o->fam = fam;
	if (fam == 4) {
		o->fake[0] = 198; o->fake[1] = 18;
		o->fake[2] = (uint8_t)(i >> 8); o->fake[3] = (uint8_t)i;
	} else {
		o->fake[0] = 0xfc;
		o->fake[14] = (uint8_t)(i >> 8); o->fake[15] = (uint8_t)i;
	}
}

static const uint32_t wire_marks[] = { 0x01000000, 0x02000000, 0xfe000000 };

TEST(wire_v4v6_all_marks)
{
	struct nft_desired d = desired(true, true, wire_marks, 3);
	struct rop ops[16];
	uint32_t k = 0;
	char *o;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	nfails = 0;
	for (int fam = 4; fam <= 6; fam += 2) {
		for (uint32_t m = 0; m < 3; m++) {
			struct rop *r = &ops[k++];

			rop_key(r, fam, m + 1);
			r->add = true;
			r->mark = wire_marks[m];
			memset(r->real, 0, sizeof(r->real));
			r->real[0] = 10; r->real[3] = (uint8_t)(m + 1);
		}
	}
	/* destroy + add of one key in the same batch, and a plain destroy */
	rop_key(&ops[k], 4, 77); ops[k++].add = false;
	ops[k] = ops[k - 1]; ops[k].add = true; ops[k].mark = 0xfe000000;
	memcpy(ops[k++].real, "\x0a\x4d\x4d\x4d", 4);
	rop_key(&ops[k], 6, 78); ops[k++].add = false;
	cap_start();
	for (uint32_t i = 0; i < k; i++)
		rop_queue(&ops[i]);
	nft_flush(n);
	cap.on = false;
	REQUIRE(cap.nsend == 1);
	CHECK(wire_check(ops, k, 0));
	CHECK_EQ(nft_drain(n), 0);
	CHECK_EQ(nfails, 0);
	o = list_table();
	CHECK(has(o, "198.18.0.1 : jump mark_01000000"));
	CHECK(has(o, "198.18.0.3 : jump mark_fe000000"));
	CHECK(has(o, "198.18.0.77 : jump mark_fe000000"));
	CHECK(has(o, "198.18.0.77 : 10.77.77.77"));
	CHECK(has(o, "fc00::2 : jump mark_02000000"));
	CHECK(has(o, "fc00::3 : a00:3::"));
	free(o);
}

/* exactly NFT_BATCH_MAX ops: one batch; one more: a second batch */
static void wire_burst(uint32_t nops)
{
	static struct rop ops[NFT_BATCH_MAX + 1];

	for (uint32_t i = 0; i < nops; i++) {
		struct rop *r = &ops[i];

		/* mixed families and kinds, > 256 elements in several lists */
		rop_key(r, i % 3 ? 4 : 6, i);
		r->add = i % 5 != 0;
		r->mark = wire_marks[i % 3];
		memset(r->real, 0, sizeof(r->real));
		r->real[0] = 10; r->real[2] = (uint8_t)(i >> 8); r->real[3] = (uint8_t)i;
	}
	cap_start();
	for (uint32_t i = 0; i < nops; i++)
		rop_queue(&ops[i]);
	nft_flush(n);
	cap.on = false;
	REQUIRE(cap.nsend == (nops > NFT_BATCH_MAX ? 2u : 1u));
	CHECK(wire_check(ops, nops > NFT_BATCH_MAX ? NFT_BATCH_MAX : nops, 0));
	if (nops > NFT_BATCH_MAX)
		CHECK(wire_check(ops + NFT_BATCH_MAX, nops - NFT_BATCH_MAX, 1));
	CHECK_EQ(nft_drain(n), 0);
	CHECK_EQ(nfails, 0);
}

TEST(wire_batch_max)
{
	struct nft_desired d = desired(true, true, wire_marks, 3);

	REQUIRE(nft_bootstrap(n, &d) == 0);
	nfails = 0;
	wire_burst(NFT_BATCH_MAX);
	/* adds: i % 5 != 0; v4: i % 3 != 0 */
	CHECK_EQ(count_elems("fake2real_v4"), 546);
	CHECK_EQ(count_elems("fake2mark_v6"), 273);
	REQUIRE(nft_bootstrap(n, &d) == 0);
	wire_burst(NFT_BATCH_MAX + 1);
	CHECK_EQ(count_elems("fake2real_v4"), 547);
}

/* batches of one shape reuse the buffers; a burst's growth decays again */
TEST(batch_buffers)
{
	struct nft_desired d = desired(true, true, wire_marks, 3);
	struct rop r = { .add = true, .mark = 0x02000000, .real = { 10, 0, 0, 9 } };
	size_t warm, peak;

	REQUIRE(nft_bootstrap(n, &d) == 0);
	nfails = 0;
	for (int round = 0; round < 6; round++) {
		for (uint32_t i = 0; i < 300; i++) {
			rop_key(&r, i & 1 ? 6 : 4, i);
			r.add = i % 7 != 0;
			rop_queue(&r);
		}
		CHECK_EQ(nft_drain(n), 0);
		if (round == 1)
			warm = nft_batch_mem(n);
		else if (round > 1)
			CHECK_EQ(nft_batch_mem(n), warm);
	}
	wire_burst(NFT_BATCH_MAX);
	peak = nft_batch_mem(n);
	CHECK(peak >= warm);
	CHECK(peak <= 1024 * 1024);
	/* single-op batches: each buffer halves after every 64 of them,
	 * down to its floor */
	for (int i = 0; i < 8 * 64; i++) {
		rop_key(&r, 4, 5000);
		r.add = true;
		rop_queue(&r);
		CHECK_EQ(nft_drain(n), 0);
	}
	CHECK(nft_batch_mem(n) <= 8 * 1024 + 4096);
	CHECK_EQ(nfails, 0);
}

/*
 * Every chain is checked: one edited behind our back is rewritten by the
 * reconcile after adoption, keeping the elements; one that cannot be
 * rewritten in place (another hook or priority, a map of another type)
 * declines adoption.
 */
TEST(adopt_repairs_chains)
{
	static const uint32_t m1[] = { 0x01000000, 0x02000000 };
	struct nft_desired d = desired(true, true, m1, 2);
	uint8_t got[NFT_SECRET_LEN];
	struct nft_elem *el;
	struct nft_ctx *m;
	uint32_t nel;
	char *a, *b;

	nft_set_secret(n, secret_a);
	REQUIRE(nft_bootstrap(n, &d) == 0);
	elem_sync(AF_INET, "198.18.0.1", "10.1.1.1", 0x02000000);
	REQUIRE(nft_drain(n) == 0);
	a = list_table();
	/* no ct mark restored; a mark chain doing something else; a foreign
	 * rule; a base chain dropping */
	free(sh("nft flush chain inet " TABLE " prerouting_mangle; "
	        "nft flush chain inet " TABLE " mark_02000000; "
	        "nft add rule inet " TABLE " mark_02000000 accept; "
	        "nft add rule inet " TABLE " output_mangle counter; "
	        "nft add chain inet " TABLE " output_reject '{ policy drop; }'"));
	REQUIRE(adopt(&d, 100, got, &el, &nel, &m) == 1);
	CHECK_EQ(nel, 1);
	free(el);
	CHECK_EQ(nft_reconcile(m, &d), 0);
	b = list_table();
	CHECK_STR(a, b);
	free(b);
	/* repaired, it is current again */
	CHECK_EQ(nft_reconcile(m, &d), 0);
	nft_close(m);
	REQUIRE(adopt(&d, 100, got, &el, &nel, &m) == 1);
	free(el);
	cap_start();
	CHECK_EQ(nft_reconcile(m, &d), 0);
	cap.on = false;
	CHECK_EQ(cap.nsend, 0);
	nft_close(m);
	free(a);

	/* another priority */
	free(sh("nft flush chain inet " TABLE " prerouting_dstnat; "
	        "nft delete chain inet " TABLE " prerouting_dstnat; "
	        "nft add chain inet " TABLE " prerouting_dstnat "
	        "'{ type nat hook prerouting priority -90; }'"));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
	/* a mark chain that is a base chain */
	REQUIRE(nft_bootstrap(n, &d) == 0);
	free(sh("nft flush chain inet " TABLE " restore_marks; "
	        "nft delete chain inet " TABLE " mark_02000000; "
	        "nft add chain inet " TABLE " mark_02000000 "
	        "'{ type filter hook input priority 0; }'"));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
	/* a map of another type */
	REQUIRE(nft_bootstrap(n, &d) == 0);
	free(sh("nft flush chain inet " TABLE " prerouting_dstnat; "
	        "nft flush chain inet " TABLE " output_dstnat; "
	        "nft delete map inet " TABLE " fake2real_v6; "
	        "nft add map inet " TABLE " fake2real_v6 '{ type ipv6_addr : ipv4_addr; }'"));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
	/* a dormant table */
	REQUIRE(nft_bootstrap(n, &d) == 0);
	free(sh("nft add table inet " TABLE " '{ flags dormant; }'"));
	CHECK_EQ(adopt(&d, 100, got, &el, &nel, NULL), 0);
}

int main(int argc, char **argv)
{
	test_require_netns(argv);
	log_init("test_nft", true, LOG_DEBUG);
	uloop_init();
	n = nft_open(TABLE);
	if (!n) {
		fprintf(stderr, "nft_open failed\n");
		return 1;
	}
	nft_set_fail_hook(n, fail_hook, NULL);
	RUN(bootstrap_v4);
	RUN(bootstrap_v4v6_marks);
	RUN(reconcile);
	RUN(reconcile_fwmask);
	RUN(reconcile_noop);
	RUN(reconcile_kernel_failure);
	RUN(big_bootstrap);
	RUN(big_reconcile);
	RUN(big_reconcile_failure);
	RUN(async_add_del);
	RUN(async_failure);
	RUN(async_failure_not_last);
	RUN(async_big_batch);
	RUN(async_burst_inflight);
	RUN(fakeip_failed_batch);
	RUN(reconcile_fwmask_stale_elems);
	RUN(adopt_userdata_secret);
	RUN(adopt_dump);
	RUN(adopt_reconcile_keeps_elements);
	RUN(adopt_mismatch_bootstraps);
	RUN(adopt_repairs_chains);
	RUN(adopt_crafted_userdata);
	RUN(adopt_cap_bounds_work);
	RUN(adopt_under_churn);
	RUN(wire_v4v6_all_marks);
	RUN(wire_batch_max);
	RUN(batch_buffers);
	RUN(packets);
	RUN(destroy);
	nft_close(n);
	uloop_done();
	return test_summary();
}
