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

static bool rr_eq(const struct dns_rr *x, const struct dns_rr *y)
{
	return x->section == y->section && x->type == y->type &&
	       x->cls == y->cls && x->ttl == y->ttl &&
	       x->owner_len == y->owner_len && x->rdlen == y->rdlen &&
	       !memcmp(x->owner, y->owner, x->owner_len) &&
	       !memcmp(x->rdata, y->rdata, x->rdlen);
}

static void check_rr(const struct dns_msg *m, const struct dns_rr *rr)
{
	struct dns_name t, s;
	uint32_t min;
	int r;

	ASSERT(rr->owner >= m->buf && rr->owner + rr->owner_len <= m->buf + m->buf_len);
	ASSERT(rr->rdata >= m->buf && rr->rdata + rr->rdlen <= m->buf + m->buf_len);
	ASSERT(dns_name_check(rr->owner, rr->owner_len) == rr->owner_len);
	ASSERT(dns_name_labels(rr->owner, rr->owner_len) >= 0);
	ASSERT(rr->type != DNS_T_OPT);
	if (rr->type == DNS_T_SOA)
		ASSERT(dns_soa_minimum(rr, &min) == 0);
	if (rr->type != DNS_T_CNAME && rr->type != DNS_T_DNAME &&
	    rr->type != DNS_T_PTR && rr->type != DNS_T_NS)
		return;
	ASSERT(dns_rr_target(rr, &t) == 0);
	if (rr->type != DNS_T_DNAME || !m->has_q)
		return;
	r = dns_name_dname_subst(m->qname.data, m->qname.len, rr->owner,
				 rr->owner_len, t.data, t.len, &s);
	ASSERT(r == 0 || r == -EINVAL || r == -EOVERFLOW);
	if (!r)
		ASSERT(dns_name_check(s.data, s.len) == s.len);
	if (r == -EINVAL)
		ASSERT(m->qname.len <= rr->owner_len ||
		       !dns_name_is_under(m->qname.data, m->qname.len,
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
	ASSERT(dns_name_check(m->qname.data, m->qname.len) == m->qname.len);
	memcpy(low, m->qname.data, m->qname.len);
	dns_name_lower(low, m->qname.len);
	ASSERT(dns_name_eq(low, m->qname.len, m->qname.data, m->qname.len));
	ASSERT(dns_name_hash(low, m->qname.len) ==
	       dns_name_hash(m->qname.data, m->qname.len));
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
		       a->qname.len == b->qname.len &&
		       !memcmp(a->qname.data, b->qname.data, a->qname.len));
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

static uint8_t out1[DNS_MAX_MSG], out2[DNS_MAX_MSG];

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
	ASSERT(dns_msg_footprint(&c) <= dns_msg_footprint(&m));
	ASSERT(c.nrr == m.nrr);
	check_rebuilt(&m, &c);
	build_check(&m, DNS_MAX_MSG);
	build_check(&m, 512);
	ASSERT(dns_parse_query(&c, data, size) == 0);
	ASSERT(c.has_q == m.has_q && c.nrr == 0);
out:
	dns_msg_free(&m);
	dns_msg_free(&c);
	return 0;
}
