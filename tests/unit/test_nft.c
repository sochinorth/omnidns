// SPDX-License-Identifier: GPL-2.0-only
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <libubox/uloop.h>

#include "test.h"
#include "log.h"
#include "nft.h"

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
	REQUIRE(nft_reconcile(n, &d) == 0);
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

	t1 = nft_elem_add(n, AF_INET, f1, r1, 0x01000000, false);
	t2 = nft_elem_add(n, AF_INET, f2, r2, 0x02000000, false);
	CHECK_EQ(t1, t2);
	CHECK(nft_elem_add(n, AF_INET6, f6, r6, 0x02000000, false) == t1);
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
	CHECK(nft_elem_add(n, AF_INET, f2, r2, 0x02000000, false) != 0);
	t2 = nft_elem_add(n, AF_INET, f1, r2, 0x02000000, true);
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

	/* add without replace to a different value fails */
	t3 = nft_elem_add(n, AF_INET, f1, r1, 0x01000000, false);
	wait_on(&a, t3);
	run_loop();
	CHECK(a.err != 0);

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
	CHECK_EQ(nfails, 1);
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
	t1 = nft_elem_add(n, AF_INET, f1, r1, 0x05000000, false);
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

	/* replace of a non-existent element fails (ENOENT) */
	t2 = nft_elem_add(n, AF_INET, f2, r1, 0x01000000, true);
	wait_on(&b, t2);
	run_loop();
	CHECK_EQ(b.err, -ENOENT);
	CHECK_EQ(nfails, 2);

	/* the next batch is unaffected */
	t2 = nft_elem_add(n, AF_INET, f2, r1, 0x01000000, false);
	wait_on(&b, t2);
	run_loop();
	CHECK_EQ(b.err, 0);
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
		t = nft_elem_add(n, AF_INET, f, r, 0x01000000, false);
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
	nft_elem_add(n, AF_INET, fake, real, 0x01000000, false);
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
	RUN(reconcile_kernel_failure);
	RUN(async_add_del);
	RUN(async_failure);
	RUN(async_big_batch);
	RUN(packets);
	RUN(destroy);
	nft_close(n);
	uloop_done();
	return test_summary();
}
