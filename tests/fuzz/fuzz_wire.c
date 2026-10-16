// SPDX-License-Identifier: MIT
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns/wire.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define ASSERT(c) do {						\
	if (!(c)) {						\
		fprintf(stderr, "assert %s:%d: %s\n", __FILE__, __LINE__, #c); \
		abort();					\
	}							\
} while (0)

static bool nocase_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (a[i] != b[i] && ((a[i] | 0x20) != (b[i] | 0x20) ||
		                     (a[i] | 0x20) < 'a' || (a[i] | 0x20) > 'z'))
			return false;
	return true;
}

/* rdata types whose names dns_build() compresses (and may recase) */
static bool compressible(uint16_t t)
{
	return (t >= DNS_T_NS && t <= 9) || t == DNS_T_PTR || t == 14 || t == DNS_T_MX;
}

/* Equal, except that names may take the case of a name they compress
 * against. */
static bool rr_eq(const struct dns_rr *x, const struct dns_rr *y)
{
	return x->section == y->section && x->type == y->type &&
	       x->cls == y->cls && x->ttl == y->ttl &&
	       x->owner_len == y->owner_len && x->rdlen == y->rdlen &&
	       nocase_eq(x->owner, y->owner, x->owner_len) &&
	       (compressible(x->type) ? nocase_eq(x->rdata, y->rdata, x->rdlen) :
	                                !memcmp(x->rdata, y->rdata, x->rdlen));
}

static void check_rr(const struct dns_msg *m, const struct dns_rr *rr)
{
	struct dns_name t, s;
	uint32_t min;
	int r;

	ASSERT(rr->owner >= m->buf && rr->owner + rr->owner_len <= m->buf + m->buf_len);
	ASSERT(rr->rdata >= m->buf && rr->rdata + rr->rdlen <= m->buf + m->buf_len);
	ASSERT(dns_name_check(rr->owner, rr->owner_len) == rr->owner_len);
	ASSERT(rr->type != DNS_T_OPT);
	if (rr->type == DNS_T_SOA)
		ASSERT(dns_soa_minimum(rr, &min) == 0);
	if (rr->type != DNS_T_CNAME && rr->type != DNS_T_DNAME &&
	    rr->type != DNS_T_PTR && rr->type != DNS_T_NS)
		return;
	ASSERT(dns_rr_target(rr, &t) == 0);
	if (rr->type != DNS_T_DNAME || !m->has_q)
		return;
	r = dns_name_dname_subst(dns_msg_qname(m), m->qlen, rr->owner,
	                         rr->owner_len, t.data, t.len, &s);
	ASSERT(r == 0 || r == -EINVAL || r == -EOVERFLOW);
	if (!r)
		ASSERT(dns_name_check(s.data, s.len) == s.len);
	if (r == -EINVAL)
		ASSERT(m->qlen <= rr->owner_len ||
		       !dns_name_is_under(dns_msg_qname(m), m->qlen,
		                          rr->owner, rr->owner_len));
}

static void check_msg(const struct dns_msg *m)
{
	uint8_t low[DNS_MAX_NAME];
	uint16_t i;

	for (i = 0; i < m->nrr; i++) {
		ASSERT(i == 0 || m->rr[i].section >= m->rr[i - 1].section);
		check_rr(m, &m->rr[i]);
	}
	if (!m->has_q)
		return;
	ASSERT(m->qoff + m->qlen <= m->buf_len);
	ASSERT(dns_name_check(dns_msg_qname(m), m->qlen) == m->qlen);
	memcpy(low, dns_msg_qname(m), m->qlen);
	dns_name_lower(low, m->qlen);
	ASSERT(dns_name_eq(low, m->qlen, dns_msg_qname(m), m->qlen));
	ASSERT(dns_name_hash(low, m->qlen) == dns_name_hash(dns_msg_qname(m), m->qlen));
}

/* b was built from a (possibly truncated) and re-parsed. */
static void check_rebuilt(const struct dns_msg *a, const struct dns_msg *b)
{
	uint16_t i, an = 0;

	ASSERT(a->id == b->id && a->has_q == b->has_q);
	ASSERT((a->flags | DNS_F_TC) == (b->flags | DNS_F_TC));
	ASSERT(a->edns.present == b->edns.present);
	if (a->edns.present)
		ASSERT(a->edns.udp_size == b->edns.udp_size &&
		       a->edns.version == b->edns.version &&
		       a->edns.ext_rcode == b->edns.ext_rcode &&
		       a->edns.do_bit == b->edns.do_bit);
	if (a->has_q)
		ASSERT(a->qtype == b->qtype && a->qclass == b->qclass &&
		       a->qlen == b->qlen &&
		       !memcmp(dns_msg_qname(a), dns_msg_qname(b), a->qlen));
	ASSERT(b->nrr <= a->nrr);
	for (i = 0; i < a->nrr; i++)
		if (a->rr[i].section != DNS_S_AR)
			an++;
	if (b->nrr < an) {
		/* AN/NS did not fit: header + question (+ OPT) with TC */
		ASSERT(b->nrr == 0 && (b->flags & DNS_F_TC));
		return;
	}
	ASSERT(b->flags == a->flags);
	for (i = 0; i < b->nrr; i++)
		ASSERT(rr_eq(&a->rr[i], &b->rr[i]));
}

static uint8_t out1[DNS_MAX_MSG], out2[DNS_MAX_MSG], out3[DNS_MAX_MSG];

/*
 * Rendering the message built once (id 0, no OPT) for a client must give
 * exactly what building it stamped for that client gives: the question in
 * another case, id, RD/CD, OPT, TTLs aged, every size limit's truncation.
 */
static void render_check(const struct dns_msg *a, uint32_t seed)
{
	static const size_t limits[] = { 512, 1232, DNS_MAX_MSG };
	struct dns_msg s;
	struct dns_reply rp;
	struct dns_name q;
	uint16_t i;
	size_t li;
	int n, r, w;

	if (!a->has_q)
		return;
	dns_msg_init(&s);
	ASSERT(dns_msg_copy(&s, a) == 0);
	s.id = 0;
	memset(&s.edns, 0, sizeof(s.edns));
	n = dns_build(&s, out1, DNS_MAX_MSG);
	ASSERT(n > 0);
	q.len = a->qlen;
	memcpy(q.data, dns_msg_qname(a), a->qlen);
	for (i = 0; i < q.len; i++)
		if ((q.data[i] | 0x20) >= 'a' && (q.data[i] | 0x20) <= 'z' && (seed >> (i % 32)) & 1)
			q.data[i] ^= 0x20;
	memset(&rp, 0, sizeof(rp));
	rp.id = (uint16_t)seed;
	rp.rdcd = (uint16_t)(seed >> 8) & (DNS_F_RD | DNS_F_CD);
	rp.qname = q.data;
	rp.qlen = q.len;
	rp.edns = seed & 1;
	rp.edns_udp = 1232;
	rp.age = seed % 7 == 0 ? 0 : seed % 1000;
	/* the stamped reference */
	for (i = 0; i < s.nrr; i++)
		s.rr[i].ttl = s.rr[i].ttl > rp.age ? s.rr[i].ttl - rp.age : 0;
	s.id = rp.id;
	s.flags = (s.flags & ~(DNS_F_RD | DNS_F_CD | DNS_F_OPCODE | DNS_F_AA)) |
	          DNS_F_QR | DNS_F_RA | rp.rdcd;
	ASSERT(dns_msg_set_question(&s, q.data, q.len, s.qtype, s.qclass) == 0);
	s.edns.present = rp.edns;
	s.edns.udp_size = rp.edns ? 1232 : 0;
	for (li = 0; li < sizeof(limits) / sizeof(limits[0]); li++) {
		r = dns_reply_render(out1, (size_t)n, &rp, out2, limits[li]);
		w = dns_build(&s, out3, limits[li]);
		ASSERT(r == w);
		ASSERT(r < 0 || !memcmp(out2, out3, (size_t)r));
	}
	dns_msg_free(&s);
}

static void build_check(const struct dns_msg *a, size_t maxlen)
{
	struct dns_msg b;
	int n, n2;

	dns_msg_init(&b);
	n = dns_build(a, out1, maxlen);
	ASSERT(n >= 12 && (size_t)n <= maxlen);
	ASSERT(dns_parse(&b, out1, n) == 0);
	check_msg(&b);
	check_rebuilt(a, &b);
	/* building the re-parsed message is a fixed point */
	n2 = dns_build(&b, out2, maxlen);
	ASSERT(n2 == n && !memcmp(out1, out2, n));
	dns_msg_free(&b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct dns_msg m, c;
	int r;

	dns_msg_init(&m);
	dns_msg_init(&c);
	r = dns_parse(&m, data, size);
	ASSERT(r == 0 || r == -EBADMSG || r == -E2BIG);
	if (r) {
		ASSERT(m.nrr == 0);
		goto out;
	}
	check_msg(&m);
	ASSERT(dns_msg_copy(&c, &m) == 0);
	ASSERT(c.buf_len == c.buf_cap && c.buf_len <= m.buf_len && c.rr_cap == c.nrr);
	ASSERT(c.nrr == m.nrr);
	check_rebuilt(&m, &c);
	build_check(&m, DNS_MAX_MSG);
	build_check(&m, 512);
	render_check(&m, size >= 4 ? (uint32_t)data[size - 1] << 24 | (uint32_t)data[size - 2] << 16 |
	                            (uint32_t)data[size - 3] << 8 | data[size - 4] : (uint32_t)size);
	ASSERT(dns_parse_query(&c, data, size) == 0);
	ASSERT(c.has_q == m.has_q && c.nrr == 0);
out:
	dns_msg_free(&m);
	dns_msg_free(&c);
	return 0;
}
