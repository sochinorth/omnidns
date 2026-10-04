// SPDX-License-Identifier: GPL-2.0-only
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libubox/list.h>
#include <libubox/uloop.h>

#include "dns/wire.h"
#include "log.h"
#include "resolve.h"
#include "server.h"
#include "util/hash.h"
#include "util/hmap.h"

#define UDP_BUDGET		64	/* datagrams per wakeup */
#define TCP_IDLE_MS		10000
#define TCP_MAX_INFLIGHT	16
#define TCP_MAX_OUTQ		(256 * 1024)
#define EDNS_MAX_UDP		1232

struct listener {
	struct uloop_fd ufd;
	struct list_head list;
	int proto;			/* IPPROTO_UDP / IPPROTO_TCP */
	struct sockaddr_storage addr;
};

/* per client IP pending-query accounting */
struct client_cnt {
	uint8_t family;
	uint8_t ip[16];
	uint32_t n;
};

struct outbuf {
	struct list_head list;
	size_t len, off;
	uint8_t data[];
};

struct tcp_conn {
	struct uloop_fd ufd;
	struct uloop_timeout idle;
	struct list_head list;
	struct list_head reqs;
	struct list_head outq;
	size_t outq_bytes;
	struct sockaddr_storage peer;
	uint8_t hdr[2];
	size_t hdr_got;
	uint8_t *msg;
	size_t msg_len, msg_got;
	uint32_t inflight;
	bool read_closed;
};

struct creq {
	struct list_head list;		/* all_reqs or conn->reqs */
	struct omni *o;
	struct resolve_req *rr;
	struct client_cnt *cc;
	struct tcp_conn *conn;		/* NULL for UDP */
	int udp_fd;
	struct sockaddr_storage peer;
	socklen_t peerlen;
	int ifindex;
	struct sockaddr_storage local;	/* destination address of the query (UDP) */
	bool have_local;
	uint16_t id;
	uint16_t rdcd;			/* RD|CD bits copied from the query */
	struct dns_name qname;
	uint16_t qtype, qclass;
	bool edns;
	uint16_t udp_size;
};

static struct omni *srv_o;
static LIST_HEAD(listeners);
static LIST_HEAD(conns);
static LIST_HEAD(udp_reqs);
static struct hmap clients = HMAP_INIT;
static struct server_stats stats;
static uint16_t cur_port;
static uint32_t n_conns;
static uint8_t udp_buf[65536];
static uint8_t out_buf[65536];

const struct server_stats *server_get_stats(void)
{
	return &stats;
}

/* ---- per-client accounting ---- */

static void sa_ip(const struct sockaddr_storage *ss, uint8_t *family, uint8_t ip[16])
{
	memset(ip, 0, 16);
	if (ss->ss_family == AF_INET) {
		*family = 4;
		memcpy(ip, &((const struct sockaddr_in *)ss)->sin_addr, 4);
	} else {
		const struct in6_addr *a = &((const struct sockaddr_in6 *)ss)->sin6_addr;

		if (IN6_IS_ADDR_V4MAPPED(a)) {
			*family = 4;
			memcpy(ip, &a->s6_addr[12], 4);
		} else {
			*family = 6;
			memcpy(ip, a, 16);
		}
	}
}

static bool client_eq(const void *val, const void *key, void *ctx)
{
	const struct client_cnt *a = val, *b = key;

	return a->family == b->family && !memcmp(a->ip, b->ip, 16);
}

static struct client_cnt *client_acquire(const struct sockaddr_storage *peer)
{
	const struct config *cfg = srv_o->cfg;
	struct client_cnt key, *c;
	uint64_t h;

	if (stats.pending >= cfg->max_pending)
		return NULL;
	sa_ip(peer, &key.family, key.ip);
	h = omni_hash(&key.family, 1) ^ omni_hash(key.ip, 16);
	c = hmap_get(&clients, h, &key, client_eq, NULL);
	if (!c) {
		c = calloc(1, sizeof(*c));
		if (!c)
			return NULL;
		*c = key;
		c->n = 0;
		if (hmap_put(&clients, h, c)) {
			free(c);
			return NULL;
		}
	}
	if (c->n >= cfg->max_pending_per_client)
		return NULL;
	c->n++;
	stats.pending++;
	return c;
}

static void client_release(struct client_cnt *c)
{
	stats.pending--;
	if (--c->n)
		return;
	hmap_del_ptr(&clients, omni_hash(&c->family, 1) ^ omni_hash(c->ip, 16), c);
	free(c);
}

/* ---- response building ---- */

static int build_reply(const struct creq *q, const struct dns_msg *resp,
		       uint8_t *buf, size_t maxlen)
{
	struct dns_msg m;
	int ret;

	dns_msg_init(&m);
	if (resp) {
		ret = dns_msg_copy(&m, resp);
		if (ret)
			goto out;
	} else {
		m.flags = DNS_R_SERVFAIL;
	}
	m.id = q->id;
	m.flags = (m.flags & ~(DNS_F_RD | DNS_F_CD | DNS_F_OPCODE | DNS_F_AA)) |
		  DNS_F_QR | DNS_F_RA | q->rdcd;
	ret = dns_msg_set_question(&m, q->qname.data, q->qname.len, q->qtype, q->qclass);
	if (ret)
		goto out;
	{
		int rcode = dns_msg_rcode(&m);

		memset(&m.edns, 0, sizeof(m.edns));
		if (q->edns) {
			m.edns.present = true;
			m.edns.udp_size = EDNS_MAX_UDP;
		}
		dns_msg_set_rcode(&m, rcode);
	}
	ret = dns_build(&m, buf, maxlen);
out:
	dns_msg_free(&m);
	return ret;
}

/* Minimal error reply when only the raw header (and maybe question) is known. */
static int build_error(const uint8_t *query, size_t qlen, int rcode,
		       const struct dns_msg *parsed, bool edns, uint8_t *buf, size_t cap)
{
	struct dns_msg m;
	int ret;

	if (qlen < 12)
		return -EINVAL;
	dns_msg_init(&m);
	m.id = (query[0] << 8) | query[1];
	m.flags = DNS_F_QR | (((query[2] << 8) | query[3]) & (DNS_F_OPCODE | DNS_F_RD | DNS_F_CD));
	if (parsed && parsed->has_q)
		dns_msg_set_question(&m, parsed->qname.data, parsed->qname.len,
				     parsed->qtype, parsed->qclass);
	if (edns) {
		m.edns.present = true;
		m.edns.udp_size = EDNS_MAX_UDP;
	}
	dns_msg_set_rcode(&m, rcode);
	ret = dns_build(&m, buf, cap < 512 ? cap : 512);
	dns_msg_free(&m);
	return ret;
}

/* ---- UDP ---- */

static void udp_send(int fd, const struct sockaddr_storage *peer, socklen_t peerlen,
		     const struct sockaddr_storage *local, bool have_local, int ifindex,
		     const uint8_t *buf, size_t len)
{
	union {
		char v4[CMSG_SPACE(sizeof(struct in_pktinfo))];
		char v6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} cbuf;
	struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
	struct msghdr mh = {
		.msg_name = (void *)peer, .msg_namelen = peerlen,
		.msg_iov = &iov, .msg_iovlen = 1,
	};

	memset(&cbuf, 0, sizeof(cbuf));
	if (have_local && local->ss_family == AF_INET) {
		struct cmsghdr *c;
		struct in_pktinfo *pi;

		mh.msg_control = &cbuf;
		mh.msg_controllen = CMSG_SPACE(sizeof(*pi));
		c = CMSG_FIRSTHDR(&mh);
		c->cmsg_level = IPPROTO_IP;
		c->cmsg_type = IP_PKTINFO;
		c->cmsg_len = CMSG_LEN(sizeof(*pi));
		pi = (struct in_pktinfo *)CMSG_DATA(c);
		pi->ipi_spec_dst = ((const struct sockaddr_in *)local)->sin_addr;
	} else if (have_local && local->ss_family == AF_INET6) {
		struct cmsghdr *c;
		struct in6_pktinfo *pi;

		mh.msg_control = &cbuf;
		mh.msg_controllen = CMSG_SPACE(sizeof(*pi));
		c = CMSG_FIRSTHDR(&mh);
		c->cmsg_level = IPPROTO_IPV6;
		c->cmsg_type = IPV6_PKTINFO;
		c->cmsg_len = CMSG_LEN(sizeof(*pi));
		pi = (struct in6_pktinfo *)CMSG_DATA(c);
		pi->ipi6_addr = ((const struct sockaddr_in6 *)local)->sin6_addr;
		pi->ipi6_ifindex = ifindex;
	}
	if (sendmsg(fd, &mh, MSG_DONTWAIT) < 0)
		log_rl(LOG_DEBUG, "udp sendmsg: %s", strerror(errno));
}

static size_t udp_limit(const struct creq *q)
{
	if (!q->edns)
		return 512;
	if (q->udp_size < 512)
		return 512;
	return q->udp_size > EDNS_MAX_UDP ? EDNS_MAX_UDP : q->udp_size;
}

static void tcp_send(struct tcp_conn *c, const uint8_t *buf, size_t len);
static void tcp_close(struct tcp_conn *c);
static void tcp_update_events(struct tcp_conn *c);

static void creq_done(void *ctx, const struct dns_msg *resp)
{
	struct creq *q = ctx;
	int len;

	q->rr = NULL;
	if (q->conn) {
		q->conn->inflight--;
		len = build_reply(q, resp, out_buf, sizeof(out_buf));
		if (len > 0)
			tcp_send(q->conn, out_buf, len);
	} else {
		len = build_reply(q, resp, out_buf, udp_limit(q));
		if (len > 0)
			udp_send(q->udp_fd, &q->peer, q->peerlen, &q->local, q->have_local,
				 q->ifindex, out_buf, len);
	}
	list_del(&q->list);
	client_release(q->cc);
	if (q->conn) {
		struct tcp_conn *c = q->conn;

		free(q);
		if (c->read_closed && !c->inflight && list_empty(&c->outq))
			tcp_close(c);
		else
			tcp_update_events(c);
		return;
	}
	free(q);
}

static void creq_free(struct creq *q)
{
	if (q->rr)
		resolve_cancel(q->rr);
	list_del(&q->list);
	client_release(q->cc);
	free(q);
}

/*
 * Validate and dispatch one query. Returns length of an immediate reply
 * written to `reply` (0 if dispatched or dropped).
 */
static int handle_query(const uint8_t *buf, size_t len, struct creq *tmpl,
			struct list_head *reqs, uint8_t *reply, size_t reply_cap)
{
	struct dns_msg m;
	struct creq *q;
	struct client_cnt *cc;
	int ret, rcode = -1;

	if (len < 12 || (buf[2] & 0x80))
		return 0;			/* no header or a response: drop */

	dns_msg_init(&m);
	ret = dns_parse(&m, buf, len);
	if (ret == -ENOMEM) {
		ret = 0;
		goto out;
	}
	if (ret) {
		stats.formerr++;
		ret = build_error(buf, len, DNS_R_FORMERR, NULL, false, reply, reply_cap);
		goto out;
	}
	if ((m.flags & DNS_F_OPCODE) != 0)
		rcode = DNS_R_NOTIMP;
	else if (!m.has_q)
		rcode = DNS_R_FORMERR;
	else if (m.edns.present && m.edns.version > 0)
		rcode = DNS_R_BADVERS;
	else if (m.qclass != DNS_C_IN || m.qtype == DNS_T_AXFR || m.qtype == DNS_T_IXFR ||
		 m.qtype == DNS_T_OPT)
		rcode = DNS_R_REFUSED;
	if (rcode >= 0) {
		ret = build_error(buf, len, rcode, &m, m.edns.present, reply, reply_cap);
		goto out;
	}

	cc = client_acquire(&tmpl->peer);
	if (!cc) {
		stats.refused_limit++;
		if (tmpl->conn)
			ret = build_error(buf, len, DNS_R_REFUSED, &m, m.edns.present,
					  reply, reply_cap);
		else
			ret = 0;
		goto out;
	}
	q = malloc(sizeof(*q));
	if (!q) {
		client_release(cc);
		ret = 0;
		goto out;
	}
	*q = *tmpl;
	q->cc = cc;
	q->id = m.id;
	q->rdcd = m.flags & (DNS_F_RD | DNS_F_CD);
	q->qname = m.qname;
	q->qtype = m.qtype;
	q->qclass = m.qclass;
	q->edns = m.edns.present;
	q->udp_size = m.edns.udp_size;
	list_add_tail(&q->list, reqs);
	if (q->conn)
		q->conn->inflight++;
	q->rr = resolve_start(q->o, &m, creq_done, q);
	if (!q->rr) {
		/* could not start: answer SERVFAIL right away */
		if (q->conn)
			q->conn->inflight--;
		list_del(&q->list);
		client_release(cc);
		free(q);
		ret = build_error(buf, len, DNS_R_SERVFAIL, &m, m.edns.present, reply, reply_cap);
		goto out;
	}
	ret = 0;
out:
	dns_msg_free(&m);
	return ret > 0 ? ret : 0;
}

static void udp_read_cb(struct uloop_fd *ufd, unsigned events)
{
	int budget = UDP_BUDGET;

	while (budget--) {
		char cbuf[256];
		struct creq tmpl;
		struct iovec iov = { .iov_base = udp_buf, .iov_len = sizeof(udp_buf) };
		struct msghdr mh = {
			.msg_name = &tmpl.peer, .msg_namelen = sizeof(tmpl.peer),
			.msg_iov = &iov, .msg_iovlen = 1,
			.msg_control = cbuf, .msg_controllen = sizeof(cbuf),
		};
		struct cmsghdr *c;
		ssize_t n;
		int rlen;

		memset(&tmpl, 0, sizeof(tmpl));
		n = recvmsg(ufd->fd, &mh, MSG_DONTWAIT);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
				log_rl(LOG_WARNING, "udp recvmsg: %s", strerror(errno));
			return;
		}
		stats.udp_queries++;
		tmpl.o = srv_o;
		tmpl.udp_fd = ufd->fd;
		tmpl.peerlen = mh.msg_namelen;
		for (c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
			if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
				struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(c);
				struct sockaddr_in *l = (struct sockaddr_in *)&tmpl.local;

				l->sin_family = AF_INET;
				l->sin_addr = pi->ipi_addr;
				tmpl.have_local = true;
			} else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
				struct in6_pktinfo *pi = (struct in6_pktinfo *)CMSG_DATA(c);
				struct sockaddr_in6 *l = (struct sockaddr_in6 *)&tmpl.local;

				l->sin6_family = AF_INET6;
				l->sin6_addr = pi->ipi6_addr;
				tmpl.ifindex = pi->ipi6_ifindex;
				tmpl.have_local = true;
			}
		}
		rlen = handle_query(udp_buf, n, &tmpl, &udp_reqs, out_buf, 512);
		if (rlen > 0)
			udp_send(ufd->fd, &tmpl.peer, tmpl.peerlen, &tmpl.local, tmpl.have_local,
				 tmpl.ifindex, out_buf, rlen);
	}
}

/* ---- TCP ---- */

static void tcp_close(struct tcp_conn *c)
{
	struct creq *q, *tmp;
	struct outbuf *ob, *obt;

	list_for_each_entry_safe(q, tmp, &c->reqs, list)
		creq_free(q);
	list_for_each_entry_safe(ob, obt, &c->outq, list) {
		list_del(&ob->list);
		free(ob);
	}
	uloop_timeout_cancel(&c->idle);
	uloop_fd_delete(&c->ufd);
	close(c->ufd.fd);
	list_del(&c->list);
	free(c->msg);
	free(c);
	n_conns--;
}

static void tcp_update_events(struct tcp_conn *c)
{
	unsigned ev = 0;

	if (!c->read_closed && c->inflight < TCP_MAX_INFLIGHT && c->outq_bytes < TCP_MAX_OUTQ)
		ev |= ULOOP_READ;
	if (!list_empty(&c->outq))
		ev |= ULOOP_WRITE;
	if (ev)
		uloop_fd_add(&c->ufd, ev);
	else
		uloop_fd_delete(&c->ufd);
}

static bool tcp_flush(struct tcp_conn *c)
{
	struct outbuf *ob, *tmp;

	list_for_each_entry_safe(ob, tmp, &c->outq, list) {
		while (ob->off < ob->len) {
			ssize_t n = send(c->ufd.fd, ob->data + ob->off, ob->len - ob->off,
					 MSG_DONTWAIT | MSG_NOSIGNAL);

			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return true;
				if (errno == EINTR)
					continue;
				return false;
			}
			ob->off += n;
		}
		c->outq_bytes -= ob->len;
		list_del(&ob->list);
		free(ob);
	}
	return true;
}

static void tcp_send(struct tcp_conn *c, const uint8_t *buf, size_t len)
{
	struct outbuf *ob = malloc(sizeof(*ob) + len + 2);

	if (!ob)
		return;
	ob->len = len + 2;
	ob->off = 0;
	ob->data[0] = len >> 8;
	ob->data[1] = len & 0xff;
	memcpy(ob->data + 2, buf, len);
	list_add_tail(&ob->list, &c->outq);
	c->outq_bytes += ob->len;
	if (!tcp_flush(c)) {
		c->read_closed = true;
		/* drop everything queued; close once in-flight finish */
		struct outbuf *o2, *t2;

		list_for_each_entry_safe(o2, t2, &c->outq, list) {
			list_del(&o2->list);
			free(o2);
		}
		c->outq_bytes = 0;
	}
	uloop_timeout_set(&c->idle, TCP_IDLE_MS);
	tcp_update_events(c);
}

static void tcp_idle_cb(struct uloop_timeout *t)
{
	struct tcp_conn *c = container_of(t, struct tcp_conn, idle);

	tcp_close(c);
}

/* Returns false when the connection must be closed. */
static bool tcp_read(struct tcp_conn *c)
{
	for (;;) {
		ssize_t n;

		if (c->inflight >= TCP_MAX_INFLIGHT || c->outq_bytes >= TCP_MAX_OUTQ)
			return true;
		if (c->hdr_got < 2) {
			n = recv(c->ufd.fd, c->hdr + c->hdr_got, 2 - c->hdr_got, MSG_DONTWAIT);
		} else {
			n = recv(c->ufd.fd, c->msg + c->msg_got, c->msg_len - c->msg_got,
				 MSG_DONTWAIT);
		}
		if (n == 0) {
			c->read_closed = true;
			return true;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return true;
			if (errno == EINTR)
				continue;
			return false;
		}
		if (c->hdr_got < 2) {
			c->hdr_got += n;
			if (c->hdr_got < 2)
				continue;
			c->msg_len = (c->hdr[0] << 8) | c->hdr[1];
			if (c->msg_len < 12)
				return false;
			c->msg = malloc(c->msg_len);
			if (!c->msg)
				return false;
			c->msg_got = 0;
			continue;
		}
		c->msg_got += n;
		if (c->msg_got < c->msg_len)
			continue;

		{
			struct creq tmpl;
			int rlen;

			memset(&tmpl, 0, sizeof(tmpl));
			tmpl.o = srv_o;
			tmpl.conn = c;
			tmpl.udp_fd = -1;
			tmpl.peer = c->peer;
			stats.tcp_queries++;
			rlen = handle_query(c->msg, c->msg_len, &tmpl, &c->reqs,
					    out_buf, sizeof(out_buf));
			free(c->msg);
			c->msg = NULL;
			c->hdr_got = 0;
			if (rlen > 0)
				tcp_send(c, out_buf, rlen);
			uloop_timeout_set(&c->idle, TCP_IDLE_MS);
		}
	}
}

static void tcp_conn_cb(struct uloop_fd *ufd, unsigned events)
{
	struct tcp_conn *c = container_of(ufd, struct tcp_conn, ufd);

	if (ufd->error) {
		tcp_close(c);
		return;
	}
	if ((events & ULOOP_WRITE) && !tcp_flush(c)) {
		tcp_close(c);
		return;
	}
	if ((events & ULOOP_READ) && !c->read_closed && !tcp_read(c)) {
		tcp_close(c);
		return;
	}
	if (c->read_closed && !c->inflight && list_empty(&c->outq)) {
		tcp_close(c);
		return;
	}
	tcp_update_events(c);
}

static void tcp_accept_cb(struct uloop_fd *ufd, unsigned events)
{
	for (;;) {
		struct sockaddr_storage peer;
		socklen_t plen = sizeof(peer);
		struct tcp_conn *c;
		int fd;

		fd = accept4(ufd->fd, (struct sockaddr *)&peer, &plen, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
				log_rl(LOG_WARNING, "tcp accept: %s", strerror(errno));
			return;
		}
		if (n_conns >= srv_o->cfg->max_clients_tcp || !(c = calloc(1, sizeof(*c)))) {
			stats.dropped++;
			close(fd);
			continue;
		}
		stats.tcp_conns++;
		n_conns++;
		c->ufd.fd = fd;
		c->ufd.cb = tcp_conn_cb;
		c->idle.cb = tcp_idle_cb;
		c->peer = peer;
		INIT_LIST_HEAD(&c->reqs);
		INIT_LIST_HEAD(&c->outq);
		list_add(&c->list, &conns);
		uloop_fd_add(&c->ufd, ULOOP_READ);
		uloop_timeout_set(&c->idle, TCP_IDLE_MS);
	}
}

/* ---- listeners ---- */

static int open_listener(const struct sockaddr_storage *addr, uint16_t port, int proto)
{
	struct sockaddr_storage sa = *addr;
	socklen_t salen;
	int fd, on = 1, type = proto == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;

	if (sa.ss_family == AF_INET) {
		((struct sockaddr_in *)&sa)->sin_port = htons(port);
		salen = sizeof(struct sockaddr_in);
	} else {
		((struct sockaddr_in6 *)&sa)->sin6_port = htons(port);
		salen = sizeof(struct sockaddr_in6);
	}
	fd = socket(sa.ss_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, proto);
	if (fd < 0)
		return -errno;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	/* lets a reload bind the new sockets before closing the old ones */
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
	if (sa.ss_family == AF_INET6)
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
	if (proto == IPPROTO_UDP) {
		if (sa.ss_family == AF_INET)
			setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
		else
			setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
	} else {
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	}
	/* allow binding addresses that are not (yet) configured */
	if (sa.ss_family == AF_INET)
		setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &on, sizeof(on));
	else
		setsockopt(fd, IPPROTO_IPV6, IPV6_FREEBIND, &on, sizeof(on));
	if (bind(fd, (struct sockaddr *)&sa, salen) < 0 ||
	    (proto == IPPROTO_TCP && listen(fd, 64) < 0)) {
		int err = -errno;

		close(fd);
		return err;
	}
	return fd;
}

static void close_listeners(struct list_head *head)
{
	struct listener *l, *tmp;

	list_for_each_entry_safe(l, tmp, head, list) {
		uloop_fd_delete(&l->ufd);
		close(l->ufd.fd);
		list_del(&l->list);
		free(l);
	}
}

static int open_all(const struct config *cfg, struct list_head *out)
{
	static const int protos[] = { IPPROTO_UDP, IPPROTO_TCP };
	char abuf[INET6_ADDRSTRLEN];
	int i, p;

	for (i = 0; i < cfg->nlisten; i++) {
		for (p = 0; p < 2; p++) {
			struct listener *l;
			int fd = open_listener(&cfg->listen[i], cfg->port, protos[p]);

			if (fd < 0) {
				const void *a = cfg->listen[i].ss_family == AF_INET ?
					(const void *)&((const struct sockaddr_in *)&cfg->listen[i])->sin_addr :
					(const void *)&((const struct sockaddr_in6 *)&cfg->listen[i])->sin6_addr;

				inet_ntop(cfg->listen[i].ss_family, a, abuf, sizeof(abuf));
				log_err("cannot listen on %s port %u/%s: %s", abuf, cfg->port,
					protos[p] == IPPROTO_UDP ? "udp" : "tcp", strerror(-fd));
				close_listeners(out);
				return fd;
			}
			l = calloc(1, sizeof(*l));
			if (!l) {
				close(fd);
				close_listeners(out);
				return -ENOMEM;
			}
			l->proto = protos[p];
			l->addr = cfg->listen[i];
			l->ufd.fd = fd;
			l->ufd.cb = protos[p] == IPPROTO_UDP ? udp_read_cb : tcp_accept_cb;
			list_add_tail(&l->list, out);
		}
	}
	return 0;
}

static void activate(struct list_head *head)
{
	struct listener *l;

	list_for_each_entry(l, head, list)
		uloop_fd_add(&l->ufd, ULOOP_READ);
}

int server_start(struct omni *o)
{
	LIST_HEAD(tmp);
	int ret;

	srv_o = o;
	ret = open_all(o->cfg, &tmp);
	if (ret)
		return ret;
	cur_port = o->cfg->port;
	list_splice(&tmp, &listeners);
	activate(&listeners);
	return 0;
}

static bool same_listen(const struct config *cfg)
{
	struct listener *l;
	int n = 0;

	list_for_each_entry(l, &listeners, list) {
		bool found = false;
		int i;

		for (i = 0; i < cfg->nlisten; i++)
			if (!memcmp(&cfg->listen[i], &l->addr, sizeof(l->addr)))
				found = true;
		if (!found)
			return false;
		n++;
	}
	return n == cfg->nlisten * 2;
}

int server_reconfigure(struct omni *o)
{
	LIST_HEAD(tmp);
	LIST_HEAD(old);
	int ret;

	srv_o = o;
	if (cur_port == o->cfg->port && same_listen(o->cfg))
		return 0;
	ret = open_all(o->cfg, &tmp);
	if (ret)
		return ret;
	list_splice_init(&listeners, &old);
	close_listeners(&old);
	cur_port = o->cfg->port;
	list_splice(&tmp, &listeners);
	activate(&listeners);
	return 0;
}

void server_stop(void)
{
	struct tcp_conn *c, *ctmp;
	struct creq *q, *qtmp;
	uint32_t it = 0;
	void *v;

	close_listeners(&listeners);
	list_for_each_entry_safe(c, ctmp, &conns, list)
		tcp_close(c);
	list_for_each_entry_safe(q, qtmp, &udp_reqs, list)
		creq_free(q);
	while ((v = hmap_next(&clients, &it)))
		free(v);
	hmap_free(&clients);
}
