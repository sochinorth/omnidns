// SPDX-License-Identifier: GPL-2.0-only
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <libubox/uloop.h>

#include "test.h"
#include "upstream.h"
#include "util/hash.h"
#include "util/time.h"

/* ---- fake servers (tests/integ/dnsmini.py) ---- */

struct fake {
	pid_t pid;
	uint16_t port;
	char log[256];
};

static char tmpdir[128];
static struct fake srv_a, srv_b;
static uint16_t dead_port;

static uint16_t free_port(void)
{
	struct sockaddr_in sa = { .sin_family = AF_INET };
	socklen_t sl = sizeof(sa);
	int u = socket(AF_INET, SOCK_DGRAM, 0), t = socket(AF_INET, SOCK_STREAM, 0);
	uint16_t port = 0;

	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	for (int i = 0; i < 50 && !port; i++) {
		sa.sin_port = 0;
		if (bind(u, (void *)&sa, sizeof(sa)) || getsockname(u, (void *)&sa, &sl))
			break;
		if (!bind(t, (void *)&sa, sizeof(sa)))
			port = ntohs(sa.sin_port);
		close(u);
		u = socket(AF_INET, SOCK_DGRAM, 0);
	}
	close(u);
	close(t);
	return port;
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");

	fputs(text, f);
	fclose(f);
}

static bool fake_start(struct fake *f, const char *name, const char *zone)
{
	char zpath[256], port[16], line[64];
	int pfd[2];
	FILE *in;

	snprintf(zpath, sizeof(zpath), "%s/%s.json", tmpdir, name);
	snprintf(f->log, sizeof(f->log), "%s/%s.jsonl", tmpdir, name);
	write_file(zpath, zone);
	f->port = free_port();
	snprintf(port, sizeof(port), "%u", f->port);
	if (pipe(pfd))
		return false;
	f->pid = fork();
	if (!f->pid) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		dup2(pfd[1], 1);
		close(pfd[0]);
		close(pfd[1]);
		execlp("python3", "python3", "../integ/dnsmini.py", "serve",
		       "--addr", "127.0.0.1", "--port", port, "--zone", zpath,
		       "--log", f->log, (char *)NULL);
		_exit(127);
	}
	close(pfd[1]);
	in = fdopen(pfd[0], "r");
	if (!fgets(line, sizeof(line), in) || strncmp(line, "ready", 5)) {
		fclose(in);
		return false;
	}
	fclose(in);
	return true;
}

static void fake_stop(struct fake *f)
{
	if (f->pid > 0) {
		kill(f->pid, SIGKILL);
		waitpid(f->pid, NULL, 0);
	}
	unlink(f->log);
}

/* count log lines mentioning name (and proto, if given) */
static int log_count(const struct fake *f, const char *name, const char *proto)
{
	char line[512], pat[300], ppat[64];
	FILE *in = fopen(f->log, "r");
	int n = 0;

	if (!in)
		return 0;
	snprintf(pat, sizeof(pat), "\"name\": \"%s\"", name);
	snprintf(ppat, sizeof(ppat), "\"proto\": \"%s\"", proto ? proto : "");
	while (fgets(line, sizeof(line), in))
		if (strstr(line, pat) && (!proto || strstr(line, ppat)))
			n++;
	fclose(in);
	return n;
}

static void log_clear(const struct fake *f)
{
	unlink(f->log);
}

/* ---- upstream sets ---- */

static struct upstream_set *mkset(uint64_t id, int n, const uint16_t *ports)
{
	struct upstream_set *u = calloc(1, sizeof(*u) + n * sizeof(u->srv[0]));

	u->refcnt = 1;
	u->id = id;
	u->n = n;
	for (int i = 0; i < n; i++) {
		struct sockaddr_in *sa = (void *)&u->srv[i].sa;

		sa->sin_family = AF_INET;
		sa->sin_port = htons(ports[i]);
		sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		u->srv[i].salen = sizeof(*sa);
	}
	return u;
}

/* ---- loop helpers ---- */

struct res {
	int called;
	int err;
	int rcode;
	int nan;
	uint8_t a[4];
	uint64_t t_ms;
	struct upstream_query *cancel_other;	/* cancel this from the cb */
	struct upstream_query *started;		/* query started from the cb */
	struct res *child;
	struct upstream_set *set;
};

static int n_done, n_want;
static bool watchdog_fired;

static void watchdog_cb(struct uloop_timeout *t)
{
	watchdog_fired = true;
	uloop_end();
}

static void run_loop(int want, int timeout_ms)
{
	struct uloop_timeout wd = { .cb = watchdog_cb };

	n_done = 0;
	n_want = want;
	watchdog_fired = false;
	uloop_timeout_set(&wd, timeout_ms);
	uloop_run();
	uloop_timeout_cancel(&wd);
}

static void res_cb(void *ctx, int err, const struct dns_msg *m)
{
	struct res *r = ctx;

	r->called++;
	r->err = err;
	r->t_ms = omni_now_ms();
	if (m) {
		r->rcode = dns_msg_rcode(m);
		r->nan = dns_msg_count(m, DNS_S_AN);
		for (int i = 0; i < m->nrr; i++)
			if (m->rr[i].type == DNS_T_A && m->rr[i].rdlen == 4)
				memcpy(r->a, m->rr[i].rdata, 4);
	}
	if (r->cancel_other)
		upstream_cancel(r->cancel_other);
	if (r->child) {
		struct dns_name n;

		dns_name_from_text(&n, "b.example.com");
		r->started = upstream_query(r->set, n.data, n.len, DNS_T_A, res_cb, r->child);
		n_want++;
	}
	if (++n_done >= n_want)
		uloop_end();
}

static struct upstream_query *q(struct upstream_set *u, const char *name,
				uint16_t qtype, struct res *r)
{
	struct dns_name n;

	if (dns_name_from_text(&n, name))
		return NULL;
	return upstream_query(u, n.data, n.len, qtype, res_cb, r);
}

static const char zone_a[] =
	"{\"records\": ["
	"[\"a.example.com\", \"A\", 60, \"192.0.2.1\"],"
	"[\"b.example.com\", \"A\", 60, \"192.0.2.2\"],"
	"[\"co.example.com\", \"A\", 60, \"192.0.2.3\"],"
	"[\"tc.example.com\", \"A\", 60, \"192.0.2.4\"]],"
	"\"behaviors\": {\"tc.example.com\": \"tc\","
	" \"drop.example.com\": \"drop\", \"fail.example.com\": \"servfail\","
	" \"refuse.example.com\": \"refused\"}}";

static const char zone_b[] =
	"{\"records\": ["
	"[\"a.example.com\", \"A\", 60, \"198.51.100.1\"],"
	"[\"drop.example.com\", \"A\", 60, \"198.51.100.2\"],"
	"[\"fail.example.com\", \"A\", 60, \"198.51.100.3\"],"
	"[\"refuse.example.com\", \"A\", 60, \"198.51.100.4\"]]}";

static void ip_is(const struct res *r, const char *ip)
{
	struct in_addr a;

	inet_pton(AF_INET, ip, &a);
	CHECK(!memcmp(r->a, &a, 4));
}

/* ---- tests ---- */

TEST(normal)
{
	struct upstream_set *u = mkset(1, 1, &srv_a.port);
	struct res r = { 0 };

	REQUIRE(q(u, "A.Example.COM", DNS_T_A, &r));
	run_loop(1, 3000);
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, 0);
	CHECK_EQ(r.rcode, DNS_R_NOERROR);
	CHECK_EQ(r.nan, 1);
	ip_is(&r, "192.0.2.1");
	CHECK_EQ(log_count(&srv_a, "a.example.com", "udp"), 1);
	upstream_set_put(u);
}

TEST(nxdomain)
{
	struct upstream_set *u = mkset(1, 1, &srv_a.port);
	struct res r = { 0 };

	REQUIRE(q(u, "nx.example.com", DNS_T_A, &r));
	run_loop(1, 3000);
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, 0);
	CHECK_EQ(r.rcode, DNS_R_NXDOMAIN);
	upstream_set_put(u);
}

TEST(dead_first)
{
	uint16_t ports[2] = { dead_port, srv_b.port };
	struct upstream_set *u = mkset(2, 2, ports);
	struct res r = { 0 };
	uint64_t t0 = omni_now_ms();

	REQUIRE(q(u, "a.example.com", DNS_T_A, &r));
	run_loop(1, 3000);
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, 0);
	ip_is(&r, "198.51.100.1");
	CHECK(r.t_ms - t0 < 250);	/* ICMP refusal, no timeout */
	upstream_set_put(u);
}

TEST(drop_first)
{
	uint16_t ports[2] = { srv_a.port, srv_b.port };
	struct upstream_set *u = mkset(3, 2, ports);
	struct res r = { 0 };
	uint64_t t0 = omni_now_ms(), to = upstream_get_stats()->timeouts;

	REQUIRE(q(u, "drop.example.com", DNS_T_A, &r));
	run_loop(1, 3000);
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, 0);
	ip_is(&r, "198.51.100.2");
	CHECK(r.t_ms - t0 >= 280);
	CHECK(r.t_ms - t0 < 1000);
	CHECK_EQ(upstream_get_stats()->timeouts, to + 1);
	upstream_set_put(u);
}

TEST(servfail_next)
{
	uint16_t ports[2] = { srv_a.port, srv_b.port };
	struct upstream_set *u = mkset(3, 2, ports);
	struct res r = { 0 }, r2 = { 0 };

	REQUIRE(q(u, "fail.example.com", DNS_T_A, &r));
	REQUIRE(q(u, "refuse.example.com", DNS_T_A, &r2));
	run_loop(2, 3000);
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, 0);
	CHECK_EQ(r.rcode, 0);
	ip_is(&r, "198.51.100.3");
	CHECK_EQ(r2.called, 1);
	ip_is(&r2, "198.51.100.4");
	CHECK_EQ(log_count(&srv_a, "fail.example.com", NULL), 1);
	upstream_set_put(u);
}

TEST(all_fail)
{
	uint16_t ports[2] = { srv_a.port, dead_port };
	struct upstream_set *u = mkset(4, 2, ports);
	struct res r = { 0 };
	uint64_t f = upstream_get_stats()->failures;

	REQUIRE(q(u, "fail.example.com", DNS_T_A, &r));
	run_loop(1, 3000);
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, -EIO);
	CHECK_EQ(upstream_get_stats()->failures, f + 1);
	upstream_set_put(u);
}

TEST(tc_tcp)
{
	struct upstream_set *u = mkset(1, 1, &srv_a.port);
	struct res r = { 0 };
	uint64_t tcp = upstream_get_stats()->tcp_sent;
	char line[512];
	FILE *in;
	int i = 0, udp_at = -1, tcp_at = -1;

	log_clear(&srv_a);
	REQUIRE(q(u, "tc.example.com", DNS_T_A, &r));
	run_loop(1, 3000);
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, 0);
	CHECK_EQ(r.nan, 1);
	ip_is(&r, "192.0.2.4");
	CHECK_EQ(upstream_get_stats()->tcp_sent, tcp + 1);
	in = fopen(srv_a.log, "r");
	REQUIRE(in);
	while (fgets(line, sizeof(line), in)) {
		if (!strstr(line, "tc.example.com"))
			continue;
		if (strstr(line, "\"udp\""))
			udp_at = i;
		if (strstr(line, "\"tcp\""))
			tcp_at = i;
		i++;
	}
	fclose(in);
	CHECK_EQ(i, 2);
	CHECK_EQ(udp_at, 0);
	CHECK_EQ(tcp_at, 1);
	upstream_set_put(u);
}

TEST(coalesce)
{
	struct upstream_set *u = mkset(1, 1, &srv_a.port);
	struct res r[5] = { 0 };
	uint64_t co = upstream_get_stats()->coalesced;

	log_clear(&srv_a);
	for (int i = 0; i < 5; i++)
		REQUIRE(q(u, i & 1 ? "CO.example.com" : "co.example.com", DNS_T_A, &r[i]));
	run_loop(5, 3000);
	for (int i = 0; i < 5; i++) {
		CHECK_EQ(r[i].called, 1);
		CHECK_EQ(r[i].err, 0);
		ip_is(&r[i], "192.0.2.3");
	}
	CHECK_EQ(upstream_get_stats()->coalesced, co + 4);
	CHECK_EQ(log_count(&srv_a, "co.example.com", NULL), 1);
	upstream_set_put(u);
}

TEST(no_coalesce_qtype)
{
	struct upstream_set *u = mkset(1, 1, &srv_a.port);
	struct res r1 = { 0 }, r2 = { 0 };

	log_clear(&srv_a);
	REQUIRE(q(u, "co.example.com", DNS_T_A, &r1));
	REQUIRE(q(u, "co.example.com", DNS_T_AAAA, &r2));
	run_loop(2, 3000);
	CHECK_EQ(r1.called, 1);
	CHECK_EQ(r2.called, 1);
	CHECK_EQ(log_count(&srv_a, "co.example.com", NULL), 2);
	upstream_set_put(u);
}

TEST(cancel_one)
{
	struct upstream_set *u = mkset(1, 1, &srv_a.port);
	struct res r[3] = { 0 };
	struct upstream_query *h[3];

	for (int i = 0; i < 3; i++)
		REQUIRE((h[i] = q(u, "a.example.com", DNS_T_A, &r[i])));
	upstream_cancel(h[1]);
	run_loop(2, 3000);
	CHECK_EQ(r[0].called, 1);
	CHECK_EQ(r[1].called, 0);
	CHECK_EQ(r[2].called, 1);
	ip_is(&r[2], "192.0.2.1");
	upstream_set_put(u);
}

TEST(cancel_all)
{
	uint16_t ports[2] = { srv_a.port, srv_b.port };
	struct upstream_set *u = mkset(3, 2, ports);
	struct res r[4] = { 0 };
	struct upstream_query *h[4];

	REQUIRE((h[0] = q(u, "a.example.com", DNS_T_A, &r[0])));
	REQUIRE((h[1] = q(u, "a.example.com", DNS_T_A, &r[1])));
	REQUIRE((h[2] = q(NULL, "a.example.com", DNS_T_A, &r[2])));	/* deferred -EINVAL */
	REQUIRE((h[3] = q(u, "drop.example.com", DNS_T_A, &r[3])));
	for (int i = 0; i < 3; i++)
		upstream_cancel(h[i]);
	run_loop(1, 100);	/* the drop query is now in flight */
	CHECK(watchdog_fired);
	CHECK_EQ(u->refcnt, 2);
	upstream_cancel(h[3]);
	CHECK_EQ(u->refcnt, 1);
	run_loop(1, 500);
	CHECK(watchdog_fired);
	for (int i = 0; i < 4; i++)
		CHECK_EQ(r[i].called, 0);
	upstream_set_put(u);
}

TEST(deadline)
{
	uint16_t ports[3] = { srv_a.port, srv_a.port, srv_a.port };
	struct upstream_set *u = mkset(5, 3, ports);
	struct res r = { 0 };
	uint64_t t0 = omni_now_ms(), dt;

	upstream_set_timeouts(300, 500);
	REQUIRE(q(u, "drop.example.com", DNS_T_A, &r));
	run_loop(1, 3000);
	upstream_set_timeouts(300, 2000);
	dt = r.t_ms - t0;
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, -ETIMEDOUT);
	CHECK(dt >= 480);
	CHECK(dt < 800);
	upstream_set_put(u);
}

TEST(reentrant)
{
	struct upstream_set *u = mkset(1, 1, &srv_a.port);
	struct res r1 = { 0 }, r2 = { 0 }, r3 = { 0 }, child = { 0 };
	struct upstream_query *h2;

	r1.child = &child;
	r1.set = u;
	REQUIRE(q(u, "a.example.com", DNS_T_A, &r1));
	REQUIRE((h2 = q(u, "a.example.com", DNS_T_A, &r2)));
	REQUIRE(q(u, "a.example.com", DNS_T_A, &r3));
	r1.cancel_other = h2;
	/* r1 (+1 child), r3 */
	run_loop(2, 3000);
	if (n_done < n_want)
		run_loop(1, 3000);
	CHECK_EQ(r1.called, 1);
	CHECK_EQ(r2.called, 0);
	CHECK_EQ(r3.called, 1);
	CHECK(r1.started);
	CHECK_EQ(child.called, 1);
	CHECK_EQ(child.err, 0);
	ip_is(&child, "192.0.2.2");
	upstream_set_put(u);
}

/* ---- spoofing responder ---- */

static struct uloop_fd spoof_fd;
static int spoof_queries;

static int spoof_build(const struct dns_msg *qm, uint16_t id, const char *qn,
		       uint8_t *out)
{
	struct dns_msg m;
	struct dns_name n;
	uint8_t ip[4] = { 203, 0, 113, 7 };
	int len;

	if (qn)
		dns_name_from_text(&n, qn);
	else
		n = qm->qname;
	dns_msg_init(&m);
	m.id = id;
	m.flags = DNS_F_QR | DNS_F_RD | DNS_F_RA;
	dns_msg_set_question(&m, n.data, n.len, qm->qtype, DNS_C_IN);
	dns_msg_add_rr(&m, DNS_S_AN, n.data, n.len, DNS_T_A, DNS_C_IN, 60, ip, 4);
	len = dns_build(&m, out, 512);
	dns_msg_free(&m);
	return len;
}

static void spoof_cb(struct uloop_fd *fd, unsigned int events)
{
	uint8_t buf[512], out[512];
	struct sockaddr_storage from;
	socklen_t fl = sizeof(from);
	struct dns_msg qm;
	ssize_t n;
	int len;

	n = recvfrom(fd->fd, buf, sizeof(buf), 0, (void *)&from, &fl);
	if (n <= 0)
		return;
	spoof_queries++;
	dns_msg_init(&qm);
	if (dns_parse_query(&qm, buf, n)) {
		dns_msg_free(&qm);
		return;
	}
	len = spoof_build(&qm, qm.id ^ 0x5a5a, NULL, out);
	sendto(fd->fd, out, len, 0, (void *)&from, fl);
	len = spoof_build(&qm, qm.id, "evil.example.net", out);
	sendto(fd->fd, out, len, 0, (void *)&from, fl);
	len = spoof_build(&qm, qm.id, NULL, out);
	out[2] &= ~0x80;	/* QR=0 */
	sendto(fd->fd, out, len, 0, (void *)&from, fl);
	len = spoof_build(&qm, qm.id, NULL, out);
	sendto(fd->fd, out, len, 0, (void *)&from, fl);
	dns_msg_free(&qm);
}

TEST(spoof)
{
	struct sockaddr_in sa = { .sin_family = AF_INET };
	socklen_t sl = sizeof(sa);
	struct upstream_set *u;
	struct res r = { 0 };
	uint64_t sp = upstream_get_stats()->spoofed;
	uint16_t port;

	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	spoof_fd.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	REQUIRE(!bind(spoof_fd.fd, (void *)&sa, sizeof(sa)));
	getsockname(spoof_fd.fd, (void *)&sa, &sl);
	port = ntohs(sa.sin_port);
	spoof_fd.cb = spoof_cb;
	uloop_fd_add(&spoof_fd, ULOOP_READ);
	u = mkset(6, 1, &port);

	REQUIRE(q(u, "Spoof.Example.com", DNS_T_A, &r));
	run_loop(1, 3000);
	CHECK_EQ(r.called, 1);
	CHECK_EQ(r.err, 0);
	ip_is(&r, "203.0.113.7");
	CHECK_EQ(spoof_queries, 1);
	CHECK(upstream_get_stats()->spoofed >= sp + 3);
	uloop_fd_delete(&spoof_fd);
	close(spoof_fd.fd);
	upstream_set_put(u);
}

TEST(shutdown_inflight)
{
	uint16_t ports[1] = { srv_a.port };
	struct upstream_set *u = mkset(7, 1, ports);
	struct res r = { 0 };

	REQUIRE(q(u, "drop.example.com", DNS_T_A, &r));
	REQUIRE(q(u, "a.example.com", DNS_T_AAAA, &r));
	REQUIRE(q(NULL, "a.example.com", DNS_T_A, &r));
	run_loop(1, 50);
	upstream_shutdown();
	CHECK_EQ(u->refcnt, 1);
	run_loop(1, 100);
	CHECK(watchdog_fired);
	upstream_set_put(u);
}

int main(void)
{
	char tpl[] = "/tmp/omni-upstream-XXXXXX";

	signal(SIGPIPE, SIG_IGN);
	hash_init();
	if (!mkdtemp(tpl))
		return 1;
	snprintf(tmpdir, sizeof(tmpdir), "%s", tpl);
	uloop_init();
	upstream_init(300, 2000);
	dead_port = free_port();
	if (!fake_start(&srv_a, "a", zone_a) || !fake_start(&srv_b, "b", zone_b)) {
		fprintf(stderr, "cannot start dnsmini, skipping\n");
		fake_stop(&srv_a);
		fake_stop(&srv_b);
		return 77;
	}
	RUN(normal);
	RUN(nxdomain);
	RUN(dead_first);
	RUN(drop_first);
	RUN(servfail_next);
	RUN(all_fail);
	RUN(tc_tcp);
	RUN(coalesce);
	RUN(no_coalesce_qtype);
	RUN(cancel_one);
	RUN(cancel_all);
	RUN(deadline);
	RUN(reentrant);
	RUN(spoof);
	RUN(shutdown_inflight);
	upstream_shutdown();
	uloop_done();
	fake_stop(&srv_a);
	fake_stop(&srv_b);
	char path[256];
	snprintf(path, sizeof(path), "%s/a.json", tmpdir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/b.json", tmpdir);
	unlink(path);
	rmdir(tmpdir);
	return test_summary();
}
