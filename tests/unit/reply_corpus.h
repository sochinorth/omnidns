/* SPDX-License-Identifier: MIT */
/*
 * Reply corpus for the cached-answer delivery tests (test_cache.c).
 *
 * Each case is a final answer as resolve assembles it (question in the case
 * it was inserted with, no OPT) plus how one client asked for it (its
 * question's case, id, RD/CD, EDNS, transport) and the entry's age.
 *
 * ref_reply() is the reference for what the client must receive: the
 * pre-wire-cache path, verbatim — the answer with every TTL aged (as the
 * cache's inflate() returned it), stamped by server.c's build_reply() and
 * serialized by dns_build(). reply_golden.inc holds its output recorded
 * from the code before the answer cache stored wire format.
 */
#ifndef OMNI_REPLY_CORPUS_H
#define OMNI_REPLY_CORPUS_H

#include <arpa/inet.h>

#include "dns/wire.h"

#define REF_EDNS_MAX_UDP 1232

struct rcase {
	const char *name;
	void (*mk)(struct dns_msg *m);
	const char *client;	/* client's qname (case as sent) */
	uint16_t id, rdcd;
	bool edns, tcp;
	uint16_t udp_size;
	uint32_t age;
};

static struct dns_name rc_N(const char *text)
{
	struct dns_name n;

	if (dns_name_from_text(&n, text))
		abort();
	return n;
}

static void rc_add(struct dns_msg *m, enum dns_section sec, const char *owner, uint16_t type,
                   uint32_t ttl, const void *rd, uint16_t rdlen)
{
	struct dns_name o = rc_N(owner);

	if (dns_msg_add_rr(m, sec, o.data, o.len, type, DNS_C_IN, ttl, rd, rdlen))
		abort();
}

static void rc_name(struct dns_msg *m, enum dns_section sec, const char *owner,
                    uint16_t type, uint32_t ttl, const char *target)
{
	struct dns_name t = rc_N(target);

	rc_add(m, sec, owner, type, ttl, t.data, t.len);
}

static void rc_a(struct dns_msg *m, enum dns_section sec, const char *owner,
                 uint32_t ttl, const char *addr)
{
	uint8_t a[16];
	int v6 = strchr(addr, ':') != NULL;

	inet_pton(v6 ? AF_INET6 : AF_INET, addr, a);
	rc_add(m, sec, owner, v6 ? DNS_T_AAAA : DNS_T_A, ttl, a, v6 ? 16 : 4);
}

static void rc_q(struct dns_msg *m, const char *qname, uint16_t qtype, uint16_t flags)
{
	struct dns_name n = rc_N(qname);

	dns_msg_init(m);
	dns_msg_set_question(m, n.data, n.len, qtype, DNS_C_IN);
	m->flags = flags;
}

#define QRRA (DNS_F_QR | DNS_F_RA)

static void rc_soa(struct dns_msg *m, const char *owner, uint32_t ttl, const char *mname,
                   const char *rname, uint32_t minimum)
{
	struct dns_name mn = rc_N(mname), rn = rc_N(rname);
	uint8_t rd[600], *p = rd;
	static const uint8_t fixed[16] = { 0, 0, 0, 7, 0, 0, 0x0e, 0x10, 0, 0, 0x03, 0x84,
	                                   0, 0x09, 0x3a, 0x80 };

	memcpy(p, mn.data, mn.len);
	p += mn.len;
	memcpy(p, rn.data, rn.len);
	p += rn.len;
	memcpy(p, fixed, 16);
	p += 16;
	*p++ = minimum >> 24;
	*p++ = minimum >> 16;
	*p++ = minimum >> 8;
	*p++ = minimum;
	rc_add(m, DNS_S_NS, owner, DNS_T_SOA, ttl, rd, (uint16_t)(p - rd));
}

/* CNAME chain, one consistent case, NS and AR. */
static void mk_chain(struct dns_msg *m)
{
	rc_q(m, "www.foo.example", DNS_T_A, QRRA | DNS_F_RD);
	rc_name(m, DNS_S_AN, "www.foo.example", DNS_T_CNAME, 300, "edge.cdn.example");
	rc_name(m, DNS_S_AN, "edge.cdn.example", DNS_T_CNAME, 120, "a1.cdn.example");
	rc_a(m, DNS_S_AN, "a1.cdn.example", 60, "192.0.2.1");
	rc_a(m, DNS_S_AN, "a1.cdn.example", 30, "192.0.2.2");
	rc_name(m, DNS_S_NS, "cdn.example", DNS_T_NS, 3600, "ns1.cdn.example");
	rc_a(m, DNS_S_AR, "ns1.cdn.example", 3600, "192.0.2.53");
	rc_a(m, DNS_S_AR, "ns1.cdn.example", 3600, "2001:db8::53");
}

/* The same chain as an upstream echoing a 0x20 query would give it. */
static void mk_chain_mixed(struct dns_msg *m)
{
	rc_q(m, "wWw.FoO.example", DNS_T_A, QRRA);
	rc_name(m, DNS_S_AN, "wWw.FoO.example", DNS_T_CNAME, 300, "Edge.CDN.example");
	rc_name(m, DNS_S_AN, "edge.cdn.example", DNS_T_CNAME, 120, "a1.cdn.example");
	rc_a(m, DNS_S_AN, "A1.cdn.example", 60, "192.0.2.1");
}

static void mk_nx(struct dns_msg *m)
{
	rc_q(m, "nx.foo.example", DNS_T_AAAA, QRRA | DNS_R_NXDOMAIN);
	rc_soa(m, "foo.example", 900, "ns.foo.example", "host.foo.example", 300);
}

static void mk_nodata(struct dns_msg *m)
{
	rc_q(m, "empty.example", DNS_T_TXT, QRRA);
}

static void mk_nodata_soa(struct dns_msg *m)
{
	rc_q(m, "v4only.example", DNS_T_AAAA, QRRA | DNS_F_RD);
	rc_soa(m, "v4only.example", 3600, "omnidns.invalid", "hostmaster.omnidns.invalid", 120);
}

/* HTTPS whose hints were rewritten to fakes, plus forward glue. */
static void mk_https(struct dns_msg *m)
{
	static const uint8_t rd[] = {
		0, 1, 0,				/* priority 1, target "." */
		0, 1, 0, 3, 2, 'h', '2',		/* alpn=h2 */
		0, 4, 0, 8, 198, 18, 0, 5, 198, 18, 0, 6,	/* ipv4hint */
		0, 6, 0, 16, 0xfd, 0, 1, 0x98, 0, 0x18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
	};
	static const uint8_t rd2[] = {
		0, 2, 3, 'a', 'l', 't', 3, 's', 'v', 'c', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,
		0, 1, 0, 3, 2, 'h', '3',
	};

	rc_q(m, "svc.example", DNS_T_HTTPS, QRRA | DNS_F_RD);
	rc_add(m, DNS_S_AN, "svc.example", DNS_T_HTTPS, 100, rd, sizeof(rd));
	rc_add(m, DNS_S_AN, "svc.example", DNS_T_HTTPS, 100, rd2, sizeof(rd2));
	rc_a(m, DNS_S_AR, "alt.svc.example", 100, "192.0.2.7");
}

static void mk_mx(struct dns_msg *m)
{
	uint8_t rd[300];
	struct dns_name t;

	rc_q(m, "mail.example", DNS_T_MX, QRRA | DNS_F_RD);
	t = rc_N("mx1.mail.example");
	rd[0] = 0;
	rd[1] = 10;
	memcpy(rd + 2, t.data, t.len);
	rc_add(m, DNS_S_AN, "mail.example", DNS_T_MX, 600, rd, (uint16_t)(2 + t.len));
	t = rc_N("mx2.other.example");
	rd[1] = 20;
	memcpy(rd + 2, t.data, t.len);
	rc_add(m, DNS_S_AN, "mail.example", DNS_T_MX, 600, rd, (uint16_t)(2 + t.len));
	rc_a(m, DNS_S_AR, "mx1.mail.example", 600, "192.0.2.25");
	rc_a(m, DNS_S_AR, "mx1.mail.example", 600, "2001:db8::25");
	rc_a(m, DNS_S_AR, "mx2.other.example", 600, "192.0.2.26");
}

/* n A records: 60 overflow 512, 100 overflow 1232. */
static void mk_many(struct dns_msg *m, int n)
{
	char a[32];
	int i;

	rc_q(m, "many.example", DNS_T_A, QRRA | DNS_F_RD);
	for (i = 0; i < n; i++) {
		snprintf(a, sizeof(a), "10.0.%d.%d", i / 256, i % 256);
		rc_a(m, DNS_S_AN, "many.example", 300, a);
	}
}

static void mk_many60(struct dns_msg *m) { mk_many(m, 60); }
static void mk_many100(struct dns_msg *m) { mk_many(m, 100); }

/* One answer, a lot of glue: only AR is cut. */
static void mk_glue(struct dns_msg *m)
{
	char a[32];
	int i;

	rc_q(m, "g.example", DNS_T_NS, QRRA);
	rc_name(m, DNS_S_AN, "g.example", DNS_T_NS, 300, "ns.g.example");
	rc_name(m, DNS_S_NS, "g.example", DNS_T_NS, 300, "ns.g.example");
	for (i = 0; i < 100; i++) {
		snprintf(a, sizeof(a), "10.1.%d.%d", i / 256, i % 256);
		rc_a(m, DNS_S_AR, "ns.g.example", 300, a);
	}
}

/* TXT records filling the message to exactly `total` bytes (no OPT). */
static void mk_txt_fill(struct dns_msg *m, size_t total, int nar)
{
	uint8_t rd[256];
	size_t len;
	int i;

	rc_q(m, "big.example", DNS_T_TXT, QRRA | DNS_F_RD);
	len = 12 + 13 + 4 + (size_t)nar * 16;	/* header, question, glue A (pointer owner) */
	memset(rd, 'x', sizeof(rd));
	for (i = 0; len + 12 + 256 <= total; i++, len += 12 + 256) {
		rd[0] = 255;
		rd[1] = (uint8_t)i;
		rd[2] = (uint8_t)(i >> 8);
		rc_add(m, DNS_S_AN, "big.example", DNS_T_TXT, 60, rd, 256);
	}
	if (total > len + 12) {
		rd[0] = (uint8_t)(total - len - 12 - 1);
		rc_add(m, DNS_S_AN, "big.example", DNS_T_TXT, 60, rd, (uint16_t)(total - len - 12));
	}
	for (i = 0; i < nar; i++) {
		uint8_t a[4] = { 10, 2, (uint8_t)(i >> 8), (uint8_t)i };

		rc_add(m, DNS_S_AR, "big.example", DNS_T_A, 60, a, 4);
	}
}

/* fits 65535 without OPT, not with it */
static void mk_tcp_an_edge(struct dns_msg *m) { mk_txt_fill(m, 65530, 0); }
/* AN fits with OPT, the last glue records do not */
static void mk_tcp_ar_edge(struct dns_msg *m) { mk_txt_fill(m, 65530, 3); }
/* does not fit a TCP message at all */
static void mk_over64k(struct dns_msg *m) { mk_txt_fill(m, 65600, 0); }

/* rcode 19 (an extended rcode) without OPT: only its low 4 bits survive */
static void mk_extrcode(struct dns_msg *m)
{
	rc_q(m, "ext.example", DNS_T_A, QRRA);
	dns_msg_set_rcode(m, 19);
}

/* flags resolve never sets, to pin the mask: AA, AD, TC, Z, opcode, RD, CD */
static void mk_flags(struct dns_msg *m)
{
	rc_q(m, "flags.example", DNS_T_A,
	     0x7fff & ~DNS_F_RCODE);
	dns_msg_set_rcode(m, DNS_R_REFUSED);
	rc_a(m, DNS_S_AN, "flags.example", 5, "192.0.2.99");
}

/* TTLs of 0, 1 and large, for the floor */
static void mk_ttls(struct dns_msg *m)
{
	rc_q(m, "ttl.example", DNS_T_A, QRRA);
	rc_a(m, DNS_S_AN, "ttl.example", 0, "192.0.2.1");
	rc_a(m, DNS_S_AN, "ttl.example", 1, "192.0.2.2");
	rc_a(m, DNS_S_AN, "ttl.example", 0x7fffffff, "192.0.2.3");
	rc_soa(m, "example", 50, "ns.example", "h.example", 50);
	rc_a(m, DNS_S_AR, "ns.example", 49, "192.0.2.4");
}

#define RC_RDCD (DNS_F_RD | DNS_F_CD)

static const struct rcase rcases[] = {
	{ "chain",          mk_chain,       "www.foo.example",  0x1234, DNS_F_RD, false, false, 0, 0 },
	{ "chain_aged",     mk_chain,       "www.foo.example",  0x0001, DNS_F_RD, false, false, 0, 45 },
	{ "chain_floor",    mk_chain,       "www.foo.example",  0xffff, 0,        false, false, 0, 100 },
	{ "chain_edns",     mk_chain,       "www.foo.example",  0xabcd, RC_RDCD,  true,  false, 4096, 7 },
	{ "chain_tcp",      mk_chain,       "www.foo.example",  0x4242, DNS_F_CD, true,  true,  1232, 0 },
	{ "chain_0x20",     mk_chain,       "WwW.fOo.ExAmPlE",  0x0020, DNS_F_RD, false, false, 0, 3 },
	{ "mixed",          mk_chain_mixed, "wWw.FoO.example",  0x0021, 0,        false, false, 0, 0 },
	{ "mixed_other",    mk_chain_mixed, "www.foo.example",  0x0022, 0,        true,  false, 1400, 0 },
	{ "nx",             mk_nx,          "nx.foo.example",   0x0100, DNS_F_RD, false, false, 0, 10 },
	{ "nx_edns",        mk_nx,          "NX.foo.example",   0x0101, DNS_F_RD, true,  false, 512, 0 },
	{ "nodata",         mk_nodata,      "empty.example",    0x0200, DNS_F_RD, false, false, 0, 0 },
	{ "nodata_soa",     mk_nodata_soa,  "v4only.example",   0x0201, DNS_F_RD, true,  false, 1232, 119 },
	{ "https",          mk_https,       "svc.example",      0x0300, DNS_F_RD, false, false, 0, 1 },
	{ "https_edns",     mk_https,       "SVC.example",      0x0301, RC_RDCD,  true,  false, 1232, 0 },
	{ "mx",             mk_mx,          "mail.example",     0x0400, DNS_F_RD, false, false, 0, 30 },
	{ "many60_udp",     mk_many60,      "many.example",     0x0500, DNS_F_RD, false, false, 0, 0 },
	{ "many60_edns",    mk_many60,      "many.example",     0x0501, DNS_F_RD, true,  false, 1232, 5 },
	{ "many60_small",   mk_many60,      "many.example",     0x0502, DNS_F_RD, true,  false, 100, 0 },
	{ "many100_edns",   mk_many100,     "many.example",     0x0503, DNS_F_RD, true,  false, 65535, 0 },
	{ "many100_tcp",    mk_many100,     "many.example",     0x0504, DNS_F_RD, false, true,  0, 299 },
	{ "glue_udp",       mk_glue,        "g.example",        0x0600, 0,        false, false, 0, 0 },
	{ "glue_edns",      mk_glue,        "g.example",        0x0601, 0,        true,  false, 1232, 2 },
	{ "glue_edns900",   mk_glue,        "G.Example",        0x0602, 0,        true,  false, 900, 0 },
	{ "glue_tcp",       mk_glue,        "g.example",        0x0603, 0,        true,  true,  0, 0 },
	{ "tcp_an_edge",    mk_tcp_an_edge, "big.example",      0x0700, DNS_F_RD, false, true,  0, 0 },
	{ "tcp_an_edge_o",  mk_tcp_an_edge, "big.example",      0x0701, DNS_F_RD, true,  true,  4096, 0 },
	{ "tcp_ar_edge",    mk_tcp_ar_edge, "big.example",      0x0702, DNS_F_RD, false, true,  0, 0 },
	{ "tcp_ar_edge_o",  mk_tcp_ar_edge, "big.example",      0x0703, DNS_F_RD, true,  true,  4096, 1 },
	{ "tcp_ar_edge_u",  mk_tcp_ar_edge, "big.example",      0x0704, DNS_F_RD, true,  false, 4096, 0 },
	{ "over64k_tcp",    mk_over64k,     "big.example",      0x0705, DNS_F_RD, true,  true,  4096, 0 },
	{ "over64k_udp",    mk_over64k,     "big.example",      0x0706, DNS_F_RD, false, false, 0, 0 },
	{ "extrcode",       mk_extrcode,    "ext.example",      0x0800, DNS_F_RD, false, false, 0, 0 },
	{ "extrcode_edns",  mk_extrcode,    "ext.example",      0x0801, DNS_F_RD, true,  false, 1232, 0 },
	{ "flags",          mk_flags,       "flags.example",    0x0900, 0,        false, false, 0, 0 },
	{ "flags_rdcd",     mk_flags,       "flags.example",    0x0901, RC_RDCD,  true,  false, 1232, 9 },
	{ "ttls",           mk_ttls,        "ttl.example",      0x0a00, 0,        false, false, 0, 49 },
	{ "ttls_floor",     mk_ttls,        "ttl.example",      0x0a01, 0,        true,  true,  0, 50 },
};

#define NRCASES (sizeof(rcases) / sizeof(rcases[0]))

static size_t ref_limit(bool edns, bool tcp, uint16_t udp_size)
{
	if (tcp)
		return 65536;		/* sizeof(out_buf) */
	if (!edns || udp_size < 512)
		return 512;
	return udp_size > REF_EDNS_MAX_UDP ? REF_EDNS_MAX_UDP : udp_size;
}

/*
 * The old path: resp aged by `age` (inflate), then build_reply().
 * qname: the client's question name (wire).
 */
static int ref_reply(const struct dns_msg *resp, const uint8_t *qname, uint8_t qlen,
                     uint16_t id, uint16_t rdcd, bool edns, size_t maxlen, uint32_t age,
                     uint8_t *buf)
{
	struct dns_msg aged, m;
	uint16_t i;
	int ret, rcode;

	dns_msg_init(&aged);
	if (dns_msg_copy(&aged, resp))
		abort();
	aged.id = 0;
	memset(&aged.edns, 0, sizeof(aged.edns));
	for (i = 0; i < aged.nrr; i++)
		aged.rr[i].ttl = aged.rr[i].ttl > age ? aged.rr[i].ttl - age : 0;
	/* build_reply(), verbatim */
	m = aged;
	m.id = id;
	m.flags = (m.flags & ~(DNS_F_RD | DNS_F_CD | DNS_F_OPCODE | DNS_F_AA)) |
	          DNS_F_QR | DNS_F_RA | rdcd;
	ret = dns_msg_set_question(&m, qname, qlen, resp->qtype, resp->qclass);
	if (ret)
		goto out;
	rcode = dns_msg_rcode(&m);
	memset(&m.edns, 0, sizeof(m.edns));
	if (edns) {
		m.edns.present = true;
		m.edns.udp_size = REF_EDNS_MAX_UDP;
	}
	dns_msg_set_rcode(&m, rcode);
	ret = dns_build(&m, buf, maxlen);
out:
	dns_msg_free(&aged);
	return ret;
}

static int ref_case(const struct rcase *c, const struct dns_msg *resp, uint8_t *buf)
{
	struct dns_name q = rc_N(c->client);

	return ref_reply(resp, q.data, q.len, c->id, c->rdcd, c->edns,
	                 ref_limit(c->edns, c->tcp, c->udp_size), c->age, buf);
}

#endif
