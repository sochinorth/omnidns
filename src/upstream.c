// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libubox/list.h>
#include <libubox/uloop.h>

#include "log.h"
#include "upstream.h"
#include "util/hash.h"
#include "util/hmap.h"
#include "util/time.h"

#define UP_EDNS_SIZE		1232
#define UP_MAX_EXCHANGES	1024
#define UP_UDP_BUDGET		16	/* datagrams per wakeup */
#define UP_QBUF			512

struct exchange;

struct upstream_query {
	struct list_head list;		/* ex->waiters, deferred or delivering */
	struct exchange *ex;		/* NULL once detached */
	upstream_cb cb;
	void *ctx;
	int err;			/* for deferred failures */
	bool in_cb;
	struct uloop_timeout defer;
};

struct exchange {
	struct list_head list;		/* all_ex */
	uint64_t hash;
	struct upstream_set *set;
	struct dns_name qname;		/* lowercased */
	uint16_t qtype;
	struct list_head waiters;
	int nwait;

	bool started, tcp;
	uint16_t srv;			/* current server index */
	uint16_t id;
	int last_err;
	uint64_t deadline;
	struct uloop_fd ufd;
	struct uloop_timeout timer;

	uint8_t qbuf[UP_QBUF];
	int qlen;

	/* TCP state */
	size_t tsent;
	uint8_t thdr[2];
	size_t thdr_got;
	uint8_t *tbuf;
	size_t tlen, tgot;
};

static struct {
	uint32_t try_ms, total_ms;
	struct hmap map;
	struct list_head all_ex;
	struct list_head deferred;
	struct list_head delivering;
	uint32_t nex;
	struct upstream_stats st;
	uint16_t idpool[64];
	unsigned idleft;
} U = {
	.all_ex = LIST_HEAD_INIT(U.all_ex),
	.deferred = LIST_HEAD_INIT(U.deferred),
	.delivering = LIST_HEAD_INIT(U.delivering),
};

static uint8_t rbuf[DNS_MAX_MSG + 1];

static void ex_try(struct exchange *ex);
static void ex_next(struct exchange *ex, int err);

/* ---- helpers ---- */

static uint16_t rand_id(void)
{
	if (!U.idleft) {
		ssize_t r = getrandom(U.idpool, sizeof(U.idpool), GRND_NONBLOCK);

		if (r != sizeof(U.idpool)) {
			uint64_t t = omni_now_ms();
			size_t i;

			for (i = 0; i < 64; i++)
				U.idpool[i] = omni_hash(&t, sizeof(t)) >> (i % 48);
		}
		U.idleft = 64;
	}
	return U.idpool[--U.idleft];
}

static bool sa_eq(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;
	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *x = (const void *)a, *y = (const void *)b;

		return x->sin_port == y->sin_port &&
		       x->sin_addr.s_addr == y->sin_addr.s_addr;
	}
	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *x = (const void *)a, *y = (const void *)b;

		return x->sin6_port == y->sin6_port &&
		       !memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr));
	}
	return false;
}

static uint64_t key_hash(uint64_t set_id, const uint8_t *lname, uint8_t len, uint16_t qtype)
{
	uint8_t k[8 + 2 + DNS_MAX_NAME];

	memcpy(k, &set_id, 8);
	memcpy(k + 8, &qtype, 2);
	memcpy(k + 10, lname, len);
	return omni_hash(k, 10 + len);
}

struct ex_key {
	uint64_t set_id;
	const uint8_t *name;
	uint8_t len;
	uint16_t qtype;
};

static bool ex_eq(const void *val, const void *key, void *ctx)
{
	const struct exchange *ex = val;
	const struct ex_key *k = key;

	return ex->set->id == k->set_id && ex->qtype == k->qtype &&
	       ex->qname.len == k->len && !memcmp(ex->qname.data, k->name, k->len);
}

/* ---- callbacks ---- */

static void fire(struct upstream_query *q, int err, const struct dns_msg *m)
{
	q->in_cb = true;
	q->cb(q->ctx, err, m);
	free(q);
}

static void deliver_list(int err, const struct dns_msg *m)
{
	struct upstream_query *q;

	while (!list_empty(&U.delivering)) {
		q = list_first_entry(&U.delivering, struct upstream_query, list);
		list_del_init(&q->list);
		fire(q, err, m);
	}
}

static void defer_cb(struct uloop_timeout *t)
{
	struct upstream_query *q = container_of(t, struct upstream_query, defer);

	list_del_init(&q->list);
	fire(q, q->err, NULL);
}

static struct upstream_query *defer_err(upstream_cb cb, void *ctx, int err)
{
	struct upstream_query *q = calloc(1, sizeof(*q));

	if (!q)
		return NULL;
	q->cb = cb;
	q->ctx = ctx;
	q->err = err;
	q->defer.cb = defer_cb;
	list_add_tail(&q->list, &U.deferred);
	uloop_timeout_set(&q->defer, 0);
	return q;
}

/* ---- exchange lifecycle ---- */

static void ex_close(struct exchange *ex)
{
	if (ex->ufd.fd >= 0) {
		uloop_fd_delete(&ex->ufd);
		close(ex->ufd.fd);
		ex->ufd.fd = -1;
	}
	free(ex->tbuf);
	ex->tbuf = NULL;
	ex->tsent = ex->thdr_got = ex->tlen = ex->tgot = 0;
}

static void ex_free(struct exchange *ex)
{
	ex_close(ex);
	uloop_timeout_cancel(&ex->timer);
	hmap_del_ptr(&U.map, ex->hash, ex);
	list_del(&ex->list);
	upstream_set_put(ex->set);
	U.nex--;
	free(ex);
}

/* Detach all waiters, free the exchange, then run the callbacks. */
static void ex_finish(struct exchange *ex, int err, const struct dns_msg *m)
{
	struct upstream_query *q;

	list_for_each_entry(q, &ex->waiters, list)
		q->ex = NULL;
	list_splice_tail_init(&ex->waiters, &U.delivering);
	if (err)
		U.st.failures++;
	ex_free(ex);
	deliver_list(err, m);
}

static void ex_fail(struct exchange *ex, int err)
{
	ex_finish(ex, err == -ETIMEDOUT ? -ETIMEDOUT : -EIO, NULL);
}

static void ex_next(struct exchange *ex, int err)
{
	ex->last_err = err;
	ex_close(ex);
	ex->srv++;
	ex_try(ex);
}

/* ---- response validation ---- */

static bool hdr_ok(const struct exchange *ex, const uint8_t *b, size_t len)
{
	uint16_t flags;

	if (len < 12)
		return false;
	flags = b[2] << 8 | b[3];
	return (b[0] << 8 | b[1]) == ex->id && (flags & DNS_F_QR) &&
	       !(flags & DNS_F_OPCODE);
}

static bool q_ok(const struct exchange *ex, const struct dns_msg *m)
{
	return m->has_q && m->qtype == ex->qtype && m->qclass == DNS_C_IN &&
	       dns_name_eq(m->qname.data, m->qname.len, ex->qname.data, ex->qname.len);
}

static bool rcode_fail(int rc)
{
	return rc == DNS_R_SERVFAIL || rc == DNS_R_REFUSED ||
	       rc == DNS_R_NOTIMP || rc == DNS_R_FORMERR;
}

static void ex_start_tcp(struct exchange *ex);

/*
 * Returns true if the response was consumed (the exchange may be gone),
 * false if it was ignored as spoofed.
 */
static bool ex_on_resp(struct exchange *ex, const uint8_t *b, size_t len)
{
	struct dns_msg m;
	bool tcp = ex->tcp;

	if (!hdr_ok(ex, b, len))
		goto spoofed;
	dns_msg_init(&m);
	if (dns_parse_query(&m, b, len)) {
		dns_msg_free(&m);
		ex_next(ex, -EIO);
		return true;
	}
	if (!q_ok(ex, &m)) {
		dns_msg_free(&m);
		goto spoofed;
	}
	if (dns_parse(&m, b, len)) {
		dns_msg_free(&m);
		ex_next(ex, -EIO);
		return true;
	}
	if ((m.flags & DNS_F_TC) && !tcp) {
		dns_msg_free(&m);
		ex_start_tcp(ex);
	} else if (m.flags & DNS_F_TC) {
		/* truncated even over TCP: never deliver (or cache) a partial answer */
		dns_msg_free(&m);
		ex_next(ex, -EIO);
	} else if (rcode_fail(dns_msg_rcode(&m))) {
		dns_msg_free(&m);
		ex_next(ex, -EIO);
	} else {
		ex_finish(ex, 0, &m);
		dns_msg_free(&m);
	}
	return true;
spoofed:
	U.st.spoofed++;
	if (tcp) {
		ex_next(ex, -EIO);
		return true;
	}
	return false;
}

/* ---- UDP ---- */

static void udp_cb(struct exchange *ex)
{
	const struct upstream_server *s = &ex->set->srv[ex->srv];
	struct sockaddr_storage from;
	socklen_t flen;
	ssize_t n;
	int i;

	for (i = 0; i < UP_UDP_BUDGET; i++) {
		flen = sizeof(from);
		n = recvfrom(ex->ufd.fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&from, &flen);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return;
			ex_next(ex, -errno);
			return;
		}
		if (!sa_eq(&from, &s->sa)) {
			U.st.spoofed++;
			continue;
		}
		if (ex_on_resp(ex, rbuf, n))
			return;
	}
}

static int sock_open(struct exchange *ex, int type)
{
	const struct upstream_server *s = &ex->set->srv[ex->srv];
	int fd;

	fd = socket(s->sa.ss_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (const struct sockaddr *)&s->sa, s->salen) < 0 &&
	    errno != EINPROGRESS) {
		int err = -errno;

		close(fd);
		return err;
	}
	ex->ufd.fd = fd;
	return 0;
}

static void new_id(struct exchange *ex)
{
	ex->id = rand_id();
	ex->qbuf[0] = ex->id >> 8;
	ex->qbuf[1] = ex->id;
}

static int udp_start(struct exchange *ex)
{
	int err;

	ex->tcp = false;
	new_id(ex);
	err = sock_open(ex, SOCK_DGRAM);
	if (err)
		return err;
	if (send(ex->ufd.fd, ex->qbuf, ex->qlen, 0) != ex->qlen)
		return errno ? -errno : -EIO;
	U.st.udp_sent++;
	return uloop_fd_add(&ex->ufd, ULOOP_READ | ULOOP_ERROR_CB) ? -EIO : 0;
}

/* ---- TCP ---- */

static void tcp_fail(struct exchange *ex, int err)
{
	ex_next(ex, err ? err : -EIO);
}

static void tcp_write(struct exchange *ex)
{
	uint8_t frame[2 + UP_QBUF];
	size_t total = 2 + ex->qlen;
	int soerr = 0;
	socklen_t sl = sizeof(soerr);
	ssize_t n;

	if (!ex->tsent) {
		if (getsockopt(ex->ufd.fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0)
			soerr = errno;
		if (soerr)
			return tcp_fail(ex, -soerr);
	}
	frame[0] = ex->qlen >> 8;
	frame[1] = ex->qlen;
	memcpy(frame + 2, ex->qbuf, ex->qlen);
	n = send(ex->ufd.fd, frame + ex->tsent, total - ex->tsent, MSG_NOSIGNAL);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;
		return tcp_fail(ex, -errno);
	}
	if (!ex->tsent)
		U.st.tcp_sent++;
	ex->tsent += n;
	if (ex->tsent == total && uloop_fd_add(&ex->ufd, ULOOP_READ | ULOOP_ERROR_CB))
		tcp_fail(ex, -EIO);
}

/* Returns >0 bytes read, 0 would block, <0 error/EOF. */
static ssize_t tcp_recv(struct exchange *ex, void *p, size_t len)
{
	ssize_t n = recv(ex->ufd.fd, p, len, 0);

	if (n > 0)
		return n;
	if (n == 0)
		return -EIO;
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
		return 0;
	return -errno;
}

static void tcp_read(struct exchange *ex)
{
	ssize_t n = 0;

	while (ex->thdr_got < 2) {
		n = tcp_recv(ex, ex->thdr + ex->thdr_got, 2 - ex->thdr_got);
		if (n <= 0)
			goto out;
		ex->thdr_got += n;
		if (ex->thdr_got < 2)
			continue;
		ex->tlen = ex->thdr[0] << 8 | ex->thdr[1];
		if (!ex->tlen)
			return tcp_fail(ex, -EIO);
		ex->tbuf = malloc(ex->tlen);
		if (!ex->tbuf)
			return tcp_fail(ex, -ENOMEM);
	}
	while (ex->tgot < ex->tlen) {
		n = tcp_recv(ex, ex->tbuf + ex->tgot, ex->tlen - ex->tgot);
		if (n <= 0)
			goto out;
		ex->tgot += n;
	}
	ex_on_resp(ex, ex->tbuf, ex->tlen);
	return;
out:
	if (n < 0)
		tcp_fail(ex, n);
}

static void ex_start_tcp(struct exchange *ex)
{
	int err;

	ex_close(ex);
	ex->tcp = true;
	new_id(ex);
	err = sock_open(ex, SOCK_STREAM);
	if (!err && uloop_fd_add(&ex->ufd, ULOOP_WRITE | ULOOP_ERROR_CB))
		err = -EIO;
	if (err)
		ex_next(ex, err);
}

/* ---- driving ---- */

static void fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct exchange *ex = container_of(fd, struct exchange, ufd);

	if (!ex->tcp)
		udp_cb(ex);
	else if (ex->tsent < 2u + ex->qlen)
		tcp_write(ex);
	else
		tcp_read(ex);
}

static void ex_try(struct exchange *ex)
{
	uint64_t now = omni_now_ms(), left;
	int err;

	while (ex->srv < ex->set->n) {
		if (now >= ex->deadline) {
			ex_fail(ex, -ETIMEDOUT);
			return;
		}
		left = ex->deadline - now;
		err = udp_start(ex);
		if (!err) {
			uloop_timeout_set(&ex->timer, left < U.try_ms ? left : U.try_ms);
			return;
		}
		log_debug("upstream: send failed: %s", strerror(-err));
		ex->last_err = err;
		ex_close(ex);
		ex->srv++;
	}
	ex_fail(ex, ex->last_err);
}

static void timer_cb(struct uloop_timeout *t)
{
	struct exchange *ex = container_of(t, struct exchange, timer);

	if (!ex->started) {
		ex->started = true;
		ex->deadline = omni_now_ms() + U.total_ms;
		ex_try(ex);
		return;
	}
	U.st.timeouts++;
	if (omni_now_ms() >= ex->deadline) {
		ex_fail(ex, -ETIMEDOUT);
		return;
	}
	ex_next(ex, -ETIMEDOUT);
}

static int build_query(struct exchange *ex)
{
	struct dns_msg m;
	int n;

	dns_msg_init(&m);
	n = dns_msg_set_question(&m, ex->qname.data, ex->qname.len, ex->qtype, DNS_C_IN);
	if (!n) {
		m.flags = DNS_F_RD;
		m.edns.present = true;
		m.edns.udp_size = UP_EDNS_SIZE;
		n = dns_build(&m, ex->qbuf, sizeof(ex->qbuf));
	}
	dns_msg_free(&m);
	if (n < 0)
		return n;
	ex->qlen = n;
	return 0;
}

static struct exchange *ex_new(struct upstream_set *u, const uint8_t *lname,
			       uint8_t len, uint16_t qtype, uint64_t hash, int *err)
{
	struct exchange *ex = calloc(1, sizeof(*ex));

	*err = -ENOMEM;
	if (!ex)
		return NULL;
	memcpy(ex->qname.data, lname, len);
	ex->qname.len = len;
	ex->qtype = qtype;
	*err = build_query(ex);
	if (*err || (*err = hmap_put(&U.map, hash, ex))) {
		free(ex);
		return NULL;
	}
	ex->hash = hash;
	ex->set = upstream_set_get(u);
	INIT_LIST_HEAD(&ex->waiters);
	ex->ufd.fd = -1;
	ex->ufd.cb = fd_cb;
	ex->timer.cb = timer_cb;
	list_add_tail(&ex->list, &U.all_ex);
	U.nex++;
	uloop_timeout_set(&ex->timer, 0);
	return ex;
}

/* ---- API ---- */

void upstream_init(uint32_t try_timeout_ms, uint32_t total_timeout_ms)
{
	memset(&U.st, 0, sizeof(U.st));
	upstream_set_timeouts(try_timeout_ms, total_timeout_ms);
}

void upstream_set_timeouts(uint32_t try_timeout_ms, uint32_t total_timeout_ms)
{
	U.try_ms = try_timeout_ms ? try_timeout_ms : 1;
	U.total_ms = total_timeout_ms ? total_timeout_ms : 1;
}

struct upstream_query *upstream_query(struct upstream_set *u,
				      const uint8_t *qname, uint8_t qlen, uint16_t qtype,
				      upstream_cb cb, void *ctx)
{
	uint8_t lname[DNS_MAX_NAME];
	struct upstream_query *q;
	struct exchange *ex;
	struct ex_key k;
	uint64_t h;
	int err;

	U.st.queries++;
	if (!u || !qname || dns_name_check(qname, qlen) != qlen)
		return defer_err(cb, ctx, -EINVAL);
	memcpy(lname, qname, qlen);
	dns_name_lower(lname, qlen);
	k = (struct ex_key){ u->id, lname, qlen, qtype };
	h = key_hash(u->id, lname, qlen, qtype);
	ex = hmap_get(&U.map, h, &k, ex_eq, NULL);
	if (ex) {
		U.st.coalesced++;
	} else {
		if (U.nex >= UP_MAX_EXCHANGES)
			return defer_err(cb, ctx, -EBUSY);
		ex = ex_new(u, lname, qlen, qtype, h, &err);
		if (!ex)
			return defer_err(cb, ctx, err);
	}
	q = calloc(1, sizeof(*q));
	if (!q) {
		if (!ex->nwait)
			ex_free(ex);
		return NULL;
	}
	q->ex = ex;
	q->cb = cb;
	q->ctx = ctx;
	list_add_tail(&q->list, &ex->waiters);
	ex->nwait++;
	return q;
}

void upstream_cancel(struct upstream_query *q)
{
	struct exchange *ex;

	if (!q || q->in_cb)
		return;
	ex = q->ex;
	list_del(&q->list);
	uloop_timeout_cancel(&q->defer);
	free(q);
	if (ex && --ex->nwait == 0)
		ex_free(ex);
}

static void free_queries(struct list_head *h)
{
	struct upstream_query *q, *tmp;

	list_for_each_entry_safe(q, tmp, h, list) {
		list_del_init(&q->list);
		uloop_timeout_cancel(&q->defer);
		if (!q->in_cb)
			free(q);
	}
}

void upstream_shutdown(void)
{
	struct exchange *ex, *tmp;

	list_for_each_entry_safe(ex, tmp, &U.all_ex, list) {
		free_queries(&ex->waiters);
		ex_free(ex);
	}
	free_queries(&U.deferred);
	free_queries(&U.delivering);
	hmap_free(&U.map);
}

const struct upstream_stats *upstream_get_stats(void)
{
	return &U.st;
}
