// SPDX-License-Identifier: MIT
#include "test.h"
#include "dns/wire.h"
#include "util/hash.h"

/* Build a wire name from dotted text (no escapes). */
static uint8_t wn(uint8_t *out, const char *s)
{
	uint8_t n = 0;

	while (*s) {
		const char *dot = strchr(s, '.');
		size_t l = dot ? (size_t)(dot - s) : strlen(s);

		out[n++] = (uint8_t)l;
		memcpy(out + n, s, l);
		n += l;
		s += l;
		if (*s)
			s++;
	}
	out[n++] = 0;
	return n;
}

/* Packet assembly helpers */
struct pkt {
	uint8_t b[70000];
	size_t n;
};

static void p_bytes(struct pkt *p, const void *d, size_t n)
{
	memcpy(p->b + p->n, d, n);
	p->n += n;
}

static void p_u8(struct pkt *p, uint8_t v)
{
	p->b[p->n++] = v;
}

static void p_u16(struct pkt *p, uint16_t v)
{
	p_u8(p, v >> 8);
	p_u8(p, v & 0xff);
}

static void p_u32(struct pkt *p, uint32_t v)
{
	p_u16(p, v >> 16);
	p_u16(p, v & 0xffff);
}

static void p_name(struct pkt *p, const char *s)
{
	uint8_t t[256];

	p_bytes(p, t, wn(t, s));
}

static void p_hdr(struct pkt *p, uint16_t flags, uint16_t qd, uint16_t an,
                  uint16_t ns, uint16_t ar)
{
	p->n = 0;
	p_u16(p, 0x1234);
	p_u16(p, flags);
	p_u16(p, qd);
	p_u16(p, an);
	p_u16(p, ns);
	p_u16(p, ar);
}

static void p_q(struct pkt *p, const char *name, uint16_t type)
{
	p_name(p, name);
	p_u16(p, type);
	p_u16(p, DNS_C_IN);
}

/* RR fixed part after owner */
static void p_rrfix(struct pkt *p, uint16_t type, uint32_t ttl, uint16_t rdlen)
{
	p_u16(p, type);
	p_u16(p, DNS_C_IN);
	p_u32(p, ttl);
	p_u16(p, rdlen);
}

static void p_a(struct pkt *p, uint8_t last)
{
	uint8_t a[4] = { 192, 0, 2, last };

	p_rrfix(p, DNS_T_A, 300, 4);
	p_bytes(p, a, 4);
}

static void p_opt(struct pkt *p)
{
	p_u8(p, 0);
	p_u16(p, DNS_T_OPT);
	p_u16(p, 1232);
	p_u32(p, 0x00008000);
	p_u16(p, 0);
}

static int parse(struct dns_msg *m, struct pkt *p)
{
	return dns_parse(m, p->b, p->n);
}

static bool msg_equal(const struct dns_msg *a, const struct dns_msg *b)
{
	uint16_t i;

	if (a->id != b->id || a->flags != b->flags || a->has_q != b->has_q ||
	    a->nrr != b->nrr || a->edns.present != b->edns.present)
		return false;
	if (a->has_q && (a->qtype != b->qtype || a->qclass != b->qclass ||
	                 a->qlen != b->qlen ||
	                 memcmp(dns_msg_qname(a), dns_msg_qname(b), a->qlen)))
		return false;
	if (a->edns.present && (a->edns.udp_size != b->edns.udp_size ||
				a->edns.do_bit != b->edns.do_bit ||
				a->edns.version != b->edns.version ||
				a->edns.ext_rcode != b->edns.ext_rcode))
		return false;
	for (i = 0; i < a->nrr; i++) {
		const struct dns_rr *x = &a->rr[i], *y = &b->rr[i];

		if (x->section != y->section || x->type != y->type ||
		    x->cls != y->cls || x->ttl != y->ttl ||
		    x->owner_len != y->owner_len || x->rdlen != y->rdlen ||
		    memcmp(x->owner, y->owner, x->owner_len) ||
		    memcmp(x->rdata, y->rdata, x->rdlen))
			return false;
	}
	return true;
}

/* A response for www.example.com with CNAME -> cdn.example.net (compressed). */
static void build_cname_resp(struct pkt *p)
{
	size_t rdpos;

	p_hdr(p, DNS_F_QR | DNS_F_RD | DNS_F_RA, 1, 2, 0, 1);
	p_q(p, "www.example.com", DNS_T_A);
	/* owner -> ptr to qname (12) */
	p_u16(p, 0xc00c);
	p_rrfix(p, DNS_T_CNAME, 60, 0);
	rdpos = p->n;
	/* "cdn" + ptr to "example" label... use "cdn.example" + ".net" */
	p_u8(p, 3);
	p_bytes(p, "cdn", 3);
	p_u8(p, 7);
	p_bytes(p, "example", 7);
	p_u8(p, 3);
	p_bytes(p, "net", 3);
	p_u8(p, 0);
	p->b[rdpos - 2] = 0;
	p->b[rdpos - 1] = (uint8_t)(p->n - rdpos);
	/* A owned by ptr to cdn.example.net */
	p_u16(p, 0xc000 | (uint16_t)rdpos);
	p_a(p, 1);
	p_opt(p);
}

TEST(basic_parse)
{
	struct dns_msg m;
	struct pkt p;
	struct dns_name t;
	uint8_t n[256];

	dns_msg_init(&m);
	build_cname_resp(&p);
	REQUIRE(parse(&m, &p) == 0);
	CHECK(m.has_q);
	CHECK_EQ(m.id, 0x1234);
	CHECK_EQ(m.qtype, DNS_T_A);
	CHECK_EQ(m.nrr, 2);
	CHECK(m.edns.present);
	CHECK_EQ(m.edns.udp_size, 1232);
	CHECK(m.edns.do_bit);
	CHECK_EQ(dns_msg_count(&m, DNS_S_AN), 2);
	CHECK_EQ(dns_msg_count(&m, DNS_S_AR), 0);
	CHECK(dns_name_eq(m.rr[0].owner, m.rr[0].owner_len, n, wn(n, "WWW.example.COM")));
	CHECK_EQ(dns_rr_target(&m.rr[0], &t), 0);
	CHECK(dns_name_eq(t.data, t.len, n, wn(n, "cdn.example.net")));
	CHECK(dns_name_eq(m.rr[1].owner, m.rr[1].owner_len, n, wn(n, "cdn.example.net")));
	CHECK_EQ(dns_rr_target(&m.rr[1], &t), -EINVAL);
	dns_msg_free(&m);
}

/* RFC 2181 sec. 8: TTLs with the MSB set are treated as zero */
TEST(ttl_msb_clamp)
{
	uint8_t a[4] = { 192, 0, 2, 1 };
	struct dns_msg m;
	struct pkt p;

	dns_msg_init(&m);
	p_hdr(&p, DNS_F_QR, 1, 2, 0, 0);
	p_q(&p, "x.test", DNS_T_A);
	p_name(&p, "x.test");
	p_rrfix(&p, DNS_T_A, 0x80000001u, 4);
	p_bytes(&p, a, 4);
	p_name(&p, "x.test");
	p_rrfix(&p, DNS_T_A, 0x7fffffffu, 4);
	p_bytes(&p, a, 4);
	REQUIRE(parse(&m, &p) == 0);
	CHECK_EQ(m.rr[0].ttl, 0);
	CHECK_EQ(m.rr[1].ttl, 0x7fffffff);
	dns_msg_free(&m);
}

/* CNAME rdata compressed against the question */
TEST(cname_compressed_rdata)
{
	struct dns_msg m;
	struct pkt p;
	struct dns_name t;
	uint8_t n[256];
	size_t rdpos;

	dns_msg_init(&m);
	p_hdr(&p, DNS_F_QR, 1, 1, 0, 0);
	p_q(&p, "www.example.com", DNS_T_A);
	p_u16(&p, 0xc00c);
	p_rrfix(&p, DNS_T_CNAME, 60, 6);
	rdpos = p.n;
	p_u8(&p, 3);
	p_bytes(&p, "web", 3);
	p_u16(&p, 0xc010);	/* -> example.com */
	CHECK_EQ(p.n - rdpos, 6);
	REQUIRE(parse(&m, &p) == 0);
	REQUIRE(dns_rr_target(&m.rr[0], &t) == 0);
	CHECK_EQ(t.len, wn(n, "web.example.com"));
	CHECK(!memcmp(t.data, n, t.len));
	CHECK_EQ(m.rr[0].rdlen, t.len);

	/* trailing garbage inside CNAME rdata -> rejected */
	p.b[rdpos - 1] = 7;
	p_u8(&p, 0);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	dns_msg_free(&m);
}

TEST(pointer_loops)
{
	struct dns_msg m;
	struct pkt p;

	dns_msg_init(&m);
	/* self pointer */
	p_hdr(&p, 0, 1, 0, 0, 0);
	p_u16(&p, 0xc00c);
	p_u16(&p, 1);
	p_u16(&p, 1);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* forward pointer */
	p_hdr(&p, 0, 1, 0, 0, 0);
	p_u16(&p, 0xc00e);
	p_name(&p, "a");
	p_u16(&p, 1);
	p_u16(&p, 1);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* mutual: label at 12 then pointer at 14 -> 12 (backward but loops) */
	p_hdr(&p, 0, 1, 0, 0, 0);
	p_u8(&p, 1);
	p_u8(&p, 'a');
	p_u16(&p, 0xc00c);
	p_u16(&p, 1);
	p_u16(&p, 1);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* mutual via two pointers: 12 -> 14 (fwd) and 14 -> 12 */
	p_hdr(&p, 0, 1, 0, 0, 0);
	p_u16(&p, 0xc00e);
	p_u16(&p, 0xc00c);
	p_u16(&p, 1);
	p_u16(&p, 1);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* pointer into header */
	p_hdr(&p, 0, 1, 0, 0, 0);
	p_u16(&p, 0xc004);
	p_u16(&p, 1);
	p_u16(&p, 1);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* truncated pointer */
	p_hdr(&p, 0, 1, 0, 0, 0);
	p_u8(&p, 0xc0);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	dns_msg_free(&m);
}

TEST(jump_limit)
{
	struct dns_msg m;
	struct pkt p;
	size_t prev;
	int i;

	dns_msg_init(&m);
	/* chain of pointers in AN owners: each RR owner points to previous */
	p_hdr(&p, DNS_F_QR, 1, 40, 0, 0);
	p_q(&p, "a", DNS_T_A);
	prev = 12;
	for (i = 0; i < 40; i++) {
		size_t here = p.n;

		p_u16(&p, 0xc000 | (uint16_t)prev);
		p_a(&p, 1);
		prev = here;
	}
	/* depth up to 40 jumps > DNS_MAX_PTR_JUMPS */
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	p.b[7] = DNS_MAX_PTR_JUMPS + 1;	/* last RR needs 33 jumps */
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	p.b[7] = DNS_MAX_PTR_JUMPS;	/* trailing bytes are ignored */
	CHECK_EQ(parse(&m, &p), 0);
	dns_msg_free(&m);
}

TEST(jump_limit_ok)
{
	struct dns_msg m;
	struct pkt p;
	size_t prev;
	int i;

	dns_msg_init(&m);
	p_hdr(&p, DNS_F_QR, 1, DNS_MAX_PTR_JUMPS, 0, 0);
	p_q(&p, "a", DNS_T_A);
	prev = 12;
	for (i = 0; i < DNS_MAX_PTR_JUMPS; i++) {
		size_t here = p.n;

		p_u16(&p, 0xc000 | (uint16_t)prev);
		p_a(&p, 1);
		prev = here;
	}
	CHECK_EQ(parse(&m, &p), 0);
	CHECK_EQ(m.nrr, DNS_MAX_PTR_JUMPS);
	dns_msg_free(&m);
}

TEST(oversize_names)
{
	struct dns_msg m;
	struct pkt p;
	uint8_t lab[64];
	int i;

	dns_msg_init(&m);
	memset(lab, 'x', sizeof(lab));
	/* 64-byte label (0x40 type bit) */
	p_hdr(&p, 0, 1, 0, 0, 0);
	p_u8(&p, 64);
	p_bytes(&p, lab, 64);
	p_u8(&p, 0);
	p_u16(&p, 1);
	p_u16(&p, 1);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* 0x80 label type */
	p.b[12] = 0x81;
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* name exactly 255 bytes: 4*63-label (256) too long; 3*64 + 62 + 1 = 255 */
	p_hdr(&p, 0, 1, 0, 0, 0);
	for (i = 0; i < 3; i++) {
		p_u8(&p, 63);
		p_bytes(&p, lab, 63);
	}
	p_u8(&p, 61);
	p_bytes(&p, lab, 61);
	p_u8(&p, 0);
	p_u16(&p, 1);
	p_u16(&p, 1);
	CHECK_EQ(parse(&m, &p), 0);
	CHECK_EQ(m.qlen, 255);
	/* 256 bytes */
	p_hdr(&p, 0, 1, 0, 0, 0);
	for (i = 0; i < 3; i++) {
		p_u8(&p, 63);
		p_bytes(&p, lab, 63);
	}
	p_u8(&p, 62);
	p_bytes(&p, lab, 62);
	p_u8(&p, 0);
	p_u16(&p, 1);
	p_u16(&p, 1);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* over 255 via compression: 200-byte name + pointer to 200-byte name */
	p_hdr(&p, 0, 1, 1, 0, 0);
	for (i = 0; i < 3; i++) {
		p_u8(&p, 63);
		p_bytes(&p, lab, 63);
	}
	p_u8(&p, 0);
	p_u16(&p, 1);
	p_u16(&p, 1);
	p_u8(&p, 63);
	p_bytes(&p, lab, 63);
	p_u16(&p, 0xc00c);
	p_a(&p, 1);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	CHECK(dns_name_check(p.b + 12, 300) == 193);
	dns_msg_free(&m);
}

TEST(truncation)
{
	struct dns_msg m;
	struct pkt p;
	size_t full;

	dns_msg_init(&m);
	build_cname_resp(&p);
	full = p.n;
	/* cut inside the A rdata: no TC -> error */
	p.n = full - 11 - 2;
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* with TC set -> keep complete RRs only */
	p.b[2] |= DNS_F_TC >> 8;
	CHECK_EQ(parse(&m, &p), 0);
	CHECK_EQ(m.nrr, 1);
	CHECK(m.flags & DNS_F_TC);
	CHECK(!m.edns.present);
	/* cut right after the question with TC */
	p.n = 12 + 17 + 4;
	CHECK_EQ(parse(&m, &p), 0);
	CHECK_EQ(m.nrr, 0);
	CHECK(m.has_q);
	/* cut inside the question with TC -> still malformed */
	p.n = 12 + 5;
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* short header */
	CHECK_EQ(dns_parse(&m, p.b, 11), -EBADMSG);
	dns_msg_free(&m);
}

TEST(rdlength_overrun)
{
	struct dns_msg m;
	struct pkt p;

	dns_msg_init(&m);
	p_hdr(&p, DNS_F_QR, 1, 1, 0, 0);
	p_q(&p, "a", DNS_T_A);
	p_u16(&p, 0xc00c);
	p_rrfix(&p, DNS_T_A, 1, 400);
	p_u32(&p, 0);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* name in MX rdata runs past rdlength (but not past message) */
	p_hdr(&p, DNS_F_QR, 1, 1, 0, 0);
	p_q(&p, "a", DNS_T_MX);
	p_u16(&p, 0xc00c);
	p_rrfix(&p, DNS_T_MX, 1, 4);
	p_u16(&p, 10);
	p_name(&p, "mail.a");
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* SOA with short fixed part */
	p_hdr(&p, DNS_F_QR, 1, 0, 1, 0);
	p_q(&p, "a", DNS_T_A);
	p_u16(&p, 0xc00c);
	p_rrfix(&p, DNS_T_SOA, 1, 2 + 2 + 19);
	p_u16(&p, 0xc00c);
	p_u16(&p, 0xc00c);
	p_bytes(&p, "0123456789012345678", 19);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* unknown type with garbage is kept verbatim */
	p_hdr(&p, DNS_F_QR, 1, 1, 0, 0);
	p_q(&p, "a", DNS_T_A);
	p_u16(&p, 0xc00c);
	p_rrfix(&p, 999, 1, 3);
	p_bytes(&p, "\xc0\x0c\xff", 3);
	CHECK_EQ(parse(&m, &p), 0);
	CHECK_EQ(m.rr[0].rdlen, 3);
	/* DNAME must be a single uncompressed name */
	p_hdr(&p, DNS_F_QR, 1, 1, 0, 0);
	p_q(&p, "a", DNS_T_A);
	p_u16(&p, 0xc00c);
	p_rrfix(&p, DNS_T_DNAME, 1, 2);
	p_u16(&p, 0xc00c);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* empty NS rdata */
	p_hdr(&p, DNS_F_QR, 1, 1, 0, 0);
	p_q(&p, "a", DNS_T_A);
	p_u16(&p, 0xc00c);
	p_rrfix(&p, DNS_T_NS, 1, 0);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	dns_msg_free(&m);
}

TEST(opt_rules)
{
	struct dns_msg m;
	struct pkt p;

	dns_msg_init(&m);
	/* two OPTs */
	p_hdr(&p, 0, 1, 0, 0, 2);
	p_q(&p, "a", DNS_T_A);
	p_opt(&p);
	p_opt(&p);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* OPT with non-root owner */
	p_hdr(&p, 0, 1, 0, 0, 1);
	p_q(&p, "a", DNS_T_A);
	p_u16(&p, 0xc00c);
	p_u16(&p, DNS_T_OPT);
	p_u16(&p, 1232);
	p_u32(&p, 0);
	p_u16(&p, 0);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* OPT in answer section */
	p_hdr(&p, 0, 1, 1, 0, 0);
	p_q(&p, "a", DNS_T_A);
	p_opt(&p);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* malformed option framing */
	p_hdr(&p, 0, 1, 0, 0, 1);
	p_q(&p, "a", DNS_T_A);
	p_u8(&p, 0);
	p_u16(&p, DNS_T_OPT);
	p_u16(&p, 4096);
	p_u32(&p, 0x01010000);
	p_u16(&p, 6);
	p_u16(&p, 10);
	p_u16(&p, 8);	/* says 8 bytes, has 2 */
	p_u16(&p, 0);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	/* well-formed option; ext_rcode/version extracted */
	p.b[p.n - 3] = 2;
	CHECK_EQ(parse(&m, &p), 0);
	CHECK(m.edns.present);
	CHECK_EQ(m.edns.udp_size, 4096);
	CHECK_EQ(m.edns.ext_rcode, 1);
	CHECK_EQ(m.edns.version, 1);
	CHECK(!m.edns.do_bit);
	CHECK_EQ(m.nrr, 0);
	CHECK_EQ(dns_msg_rcode(&m), 16);
	dns_msg_free(&m);
}

TEST(qdcount)
{
	struct dns_msg m;
	struct pkt p;

	dns_msg_init(&m);
	p_hdr(&p, 0, 2, 0, 0, 0);
	p_q(&p, "a", DNS_T_A);
	p_q(&p, "b", DNS_T_A);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	CHECK_EQ(dns_parse_query(&m, p.b, p.n), -EBADMSG);
	p_hdr(&p, 0, 0, 0, 0, 0);
	CHECK_EQ(parse(&m, &p), 0);
	CHECK(!m.has_q);
	/* parse_query ignores the rest */
	p_hdr(&p, 0, 1, 1, 0, 0);
	p_q(&p, "a", DNS_T_A);
	p_u8(&p, 0xff);
	CHECK_EQ(parse(&m, &p), -EBADMSG);
	CHECK_EQ(dns_parse_query(&m, p.b, p.n), 0);
	CHECK(m.has_q);
	CHECK_EQ(m.qtype, DNS_T_A);
	dns_msg_free(&m);
}

TEST(too_many_rrs)
{
	struct dns_msg m;
	static struct pkt p;
	int i;

	dns_msg_init(&m);
	p_hdr(&p, DNS_F_QR, 1, DNS_MAX_RRS + 1, 0, 0);
	p_q(&p, "a", DNS_T_A);
	for (i = 0; i < DNS_MAX_RRS + 1; i++) {
		p_u16(&p, 0xc00c);
		p_a(&p, (uint8_t)i);
	}
	CHECK_EQ(parse(&m, &p), -E2BIG);
	CHECK_EQ(m.nrr, 0);
	p.b[6] = DNS_MAX_RRS >> 8;
	p.b[7] = DNS_MAX_RRS & 0xff;
	CHECK_EQ(parse(&m, &p), 0);
	CHECK_EQ(m.nrr, DNS_MAX_RRS);
	dns_msg_free(&m);
}

static void roundtrip(struct pkt *p, size_t maxlen, int *outlen)
{
	struct dns_msg a, b;
	uint8_t out[65535];
	int n;

	dns_msg_init(&a);
	dns_msg_init(&b);
	CHECK_EQ(dns_parse(&a, p->b, p->n), 0);
	n = dns_build(&a, out, maxlen);
	CHECK(n > 0);
	if (n > 0) {
		CHECK_EQ(dns_parse(&b, out, n), 0);
		CHECK(msg_equal(&a, &b));
	}
	*outlen = n;
	dns_msg_free(&a);
	dns_msg_free(&b);
}

TEST(round_trip_compress)
{
	static struct pkt p;
	struct dns_msg m;
	uint8_t n1[256], n2[256], rd[600], out[65535];
	uint8_t l1, l2, o;
	size_t rl;
	int n, i, sum = 0;

	/* uncompressed message built programmatically */
	dns_msg_init(&m);
	m.id = 7;
	m.flags = DNS_F_QR | DNS_F_RD;
	l1 = wn(n1, "www.Example.com");
	REQUIRE(dns_msg_set_question(&m, n1, l1, DNS_T_A, DNS_C_IN) == 0);
	l2 = wn(n2, "cdn.Example.com");
	REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, n1, l1, DNS_T_CNAME, 1, 30, n2, l2) == 0);
	for (i = 0; i < 4; i++) {
		uint8_t a[4] = { 10, 0, 0, (uint8_t)i };

		REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, n2, l2, DNS_T_A, 1, 30, a, 4) == 0);
	}
	/* SOA in authority */
	rl = wn(rd, "ns1.Example.com");
	rl += wn(rd + rl, "hostmaster.Example.com");
	memset(rd + rl, 0, 20);
	rd[rl + 19] = 77;
	rl += 20;
	o = wn(n2, "Example.com");
	REQUIRE(dns_msg_add_rr(&m, DNS_S_NS, n2, o, DNS_T_SOA, 1, 30, rd, (uint16_t)rl) == 0);
	/* MX in additional */
	rd[0] = 0;
	rd[1] = 5;
	rl = 2 + wn(rd + 2, "mx.Example.com");
	REQUIRE(dns_msg_add_rr(&m, DNS_S_AR, n2, o, DNS_T_MX, 1, 30, rd, (uint16_t)rl) == 0);
	CHECK_EQ(dns_msg_add_rr(&m, DNS_S_AN, n2, o, DNS_T_A, 1, 30, rd, 4), -EINVAL);
	CHECK_EQ(dns_msg_add_rr(&m, DNS_S_AR, n2, o, DNS_T_MX, 1, 30, rd, 3), -EINVAL);
	CHECK_EQ(dns_msg_add_rr(&m, DNS_S_AR, n2, o, DNS_T_OPT, 1, 30, rd, 0), -EINVAL);
	m.edns.present = true;
	m.edns.udp_size = 1232;

	n = dns_build(&m, out, 65535);
	REQUIRE(n > 0);
	/* compression must beat the uncompressed size by a lot */
	sum = 12 + l1 + 4 + 11;
	for (i = 0; i < m.nrr; i++)
		sum += m.rr[i].owner_len + 10 + m.rr[i].rdlen;
	CHECK(n < sum - 80);
	memcpy(p.b, out, n);
	p.n = n;
	{
		int rn;

		roundtrip(&p, 65535, &rn);
		CHECK_EQ(rn, n);
	}
	{
		struct dns_msg b;
		uint32_t min = 0;

		dns_msg_init(&b);
		REQUIRE(dns_parse(&b, out, (size_t)n) == 0);
		CHECK(msg_equal(&m, &b));
		CHECK_EQ(dns_msg_count(&b, DNS_S_NS), 1);
		CHECK_EQ(dns_soa_minimum(&b.rr[5], &min), 0);
		CHECK_EQ(min, 77);
		CHECK_EQ(dns_soa_minimum(&b.rr[0], &min), -EINVAL);
		dns_msg_free(&b);
	}
	dns_msg_free(&m);
}

TEST(round_trip_parsed)
{
	struct pkt p;
	int n;

	build_cname_resp(&p);
	roundtrip(&p, 65535, &n);
	CHECK(n > 0 && (size_t)n <= p.n);
}

TEST(truncate_512)
{
	struct dns_msg m, b;
	uint8_t n1[256], out[65535];
	uint8_t l1;
	int n, i;

	dns_msg_init(&m);
	dns_msg_init(&b);
	l1 = wn(n1, "big.example.com");
	REQUIRE(dns_msg_set_question(&m, n1, l1, DNS_T_TXT, DNS_C_IN) == 0);
	m.flags = DNS_F_QR;
	m.edns.present = true;
	m.edns.udp_size = 512;
	/* AN: 2 small A; AR: 20 x 30-byte TXT */
	for (i = 0; i < 2; i++) {
		uint8_t a[4] = { 1, 2, 3, (uint8_t)i };

		REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, n1, l1, DNS_T_A, 1, 1, a, 4) == 0);
	}
	for (i = 0; i < 20; i++) {
		uint8_t t[31];

		memset(t, 'a' + i, sizeof(t));
		t[0] = 30;
		REQUIRE(dns_msg_add_rr(&m, DNS_S_AR, n1, l1, DNS_T_TXT, 1, 1, t, 31) == 0);
	}
	n = dns_build(&m, out, 512);
	REQUIRE(n > 0);
	CHECK(n <= 512);
	REQUIRE(dns_parse(&b, out, n) == 0);
	CHECK(!(b.flags & DNS_F_TC));
	CHECK_EQ(dns_msg_count(&b, DNS_S_AN), 2);
	CHECK(dns_msg_count(&b, DNS_S_AR) < 20);
	CHECK(dns_msg_count(&b, DNS_S_AR) > 5);
	CHECK(b.edns.present);
	/* AR kept is a prefix */
	for (i = 2; i < b.nrr; i++)
		CHECK(!memcmp(b.rr[i].rdata, m.rr[i].rdata, 31));
	/* make AN too big: 30 large TXT in AN */
	dns_msg_reset(&m);
	REQUIRE(dns_msg_set_question(&m, n1, l1, DNS_T_TXT, DNS_C_IN) == 0);
	m.flags = DNS_F_QR;
	m.edns.present = true;
	for (i = 0; i < 30; i++) {
		uint8_t t[31];

		memset(t, 'a', sizeof(t));
		t[0] = 30;
		REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, n1, l1, DNS_T_TXT, 1, 1, t, 31) == 0);
	}
	n = dns_build(&m, out, 512);
	REQUIRE(n > 0);
	CHECK_EQ(n, 12 + l1 + 4 + 11);
	REQUIRE(dns_parse(&b, out, n) == 0);
	CHECK(b.flags & DNS_F_TC);
	CHECK_EQ(b.nrr, 0);
	CHECK(b.has_q);
	CHECK(b.edns.present);
	/* bigger limit fits */
	n = dns_build(&m, out, 4096);
	REQUIRE(n > 512);
	REQUIRE(dns_parse(&b, out, n) == 0);
	CHECK(!(b.flags & DNS_F_TC));
	CHECK_EQ(b.nrr, 30);
	/* too small for header */
	CHECK_EQ(dns_build(&m, out, 20), -ENOSPC);
	dns_msg_free(&m);
	dns_msg_free(&b);
}

/* Names compress regardless of case and take the earlier name's case. */
TEST(compress_nocase)
{
	struct dns_msg m, b;
	uint8_t q[256], o[256], t[256], o2[256], out[1024];
	uint8_t ql, ol, tl, o2l;
	int n;

	dns_msg_init(&m);
	dns_msg_init(&b);
	ql = wn(q, "WwW.ExAmple.COM");
	ol = wn(o, "www.example.com");
	tl = wn(t, "CDN.example.com");
	o2l = wn(o2, "cdn.EXAMPLE.com");
	REQUIRE(dns_msg_set_question(&m, q, ql, DNS_T_A, DNS_C_IN) == 0);
	REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, o, ol, DNS_T_CNAME, 1, 30, t, tl) == 0);
	REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, o2, o2l, DNS_T_A, 1, 30,
	                       (const uint8_t *)"\x0a\0\0\x01", 4) == 0);
	n = dns_build(&m, out, sizeof(out));
	/* header, question, CNAME (c00c, rdata "CDN" + c010), A (pointer to CDN...) */
	CHECK_EQ(n, 12 + ql + 4 + (2 + 10 + 6) + (2 + 10 + 4));
	CHECK(out[12 + ql + 4] == 0xc0 && out[12 + ql + 5] == 12);
	REQUIRE(dns_parse(&b, out, (size_t)n) == 0);
	CHECK(!memcmp(b.rr[0].owner, q, ql));
	CHECK(!memcmp(b.rr[0].rdata, "\x03" "CDN" "\x07" "ExAmple" "\x03" "COM", tl));
	CHECK(!memcmp(b.rr[1].owner, b.rr[0].rdata, tl));
	dns_msg_free(&m);
	dns_msg_free(&b);
}

/* Build m with question name q, id and flags as a server stamps them. */
static int stamped_build(const struct dns_msg *src, const uint8_t *q, uint8_t ql, uint16_t id,
                         uint16_t rdcd, bool edns, uint32_t age, uint8_t *out, size_t maxlen)
{
	struct dns_msg m;
	uint16_t i;
	int n;

	dns_msg_init(&m);
	if (dns_msg_copy(&m, src))
		return -ENOMEM;
	for (i = 0; i < m.nrr; i++)
		m.rr[i].ttl = m.rr[i].ttl > age ? m.rr[i].ttl - age : 0;
	m.id = id;
	m.flags = (m.flags & ~(DNS_F_RD | DNS_F_CD | DNS_F_OPCODE | DNS_F_AA)) |
	          DNS_F_QR | DNS_F_RA | rdcd;
	dns_msg_set_question(&m, q, ql, src->qtype, src->qclass);
	memset(&m.edns, 0, sizeof(m.edns));
	m.edns.present = edns;
	m.edns.udp_size = edns ? 1232 : 0;
	n = dns_build(&m, out, maxlen);
	dns_msg_free(&m);
	return n;
}

TEST(reply_render)
{
	static uint8_t stored[65535], got[65535], want[65535];
	struct dns_msg m;
	uint8_t q[256], q2[256], o[256], t[256];
	uint8_t ql, ol, tl;
	struct dns_reply rp = { 0 };
	int n, len, w, i;
	size_t lim;

	dns_msg_init(&m);
	ql = wn(q, "a.b.example");
	wn(q2, "A.B.Example");
	ol = wn(o, "x.b.example");		/* "x" + pointer into the question */
	tl = wn(t, "deep.label.x.b.example");
	REQUIRE(dns_msg_set_question(&m, q, ql, DNS_T_MX, DNS_C_IN) == 0);
	m.flags = DNS_F_QR | DNS_F_AA | DNS_F_RD | DNS_F_AD | 0x0040 | DNS_R_NXDOMAIN;
	for (i = 0; i < 40; i++) {
		uint8_t rd[300] = { 0, (uint8_t)i };

		memcpy(rd + 2, t, tl);
		REQUIRE(dns_msg_add_rr(&m, i < 20 ? DNS_S_AN : DNS_S_AR, i % 2 ? o : q,
		                       i % 2 ? ol : ql, DNS_T_MX, 1, (uint32_t)(i * 7), rd,
		                       (uint16_t)(2 + tl)) == 0);
	}
	len = dns_build(&m, stored, sizeof(stored));
	REQUIRE(len > 512);

	rp.qname = q2;
	rp.qlen = ql;
	rp.edns_udp = 1232;
	/* every limit from "only the question fits" up, with and without OPT and age */
	for (lim = 12 + ql + 4; lim <= (size_t)len + 20; lim++) {
		for (i = 0; i < 4; i++) {
			rp.id = (uint16_t)lim;
			rp.rdcd = i & 1 ? DNS_F_CD : DNS_F_RD;
			rp.edns = i & 2;
			rp.age = i * 33;
			n = dns_reply_render(stored, (size_t)len, &rp, got, lim);
			w = stamped_build(&m, q2, ql, rp.id, rp.rdcd, rp.edns, rp.age, want, lim);
			CHECK_EQ(n, w);
			if (n != w || (n > 0 && memcmp(got, want, (size_t)n))) {
				fprintf(stderr, "  limit %zu variant %d\n", lim, i);
				CHECK(0);
				goto out;
			}
		}
	}
	/* maxlen above a message is clamped like dns_build() */
	rp.edns = true;
	CHECK_EQ(dns_reply_render(stored, (size_t)len, &rp, got, 100000), len + 11);

	/* not the stored question, not one question, malformed */
	rp.qname = (const uint8_t *)"\x01" "a" "\x01" "c" "\x07" "example";
	CHECK_EQ(dns_reply_render(stored, (size_t)len, &rp, got, 512), -EINVAL);
	rp.qname = q2;
	rp.qlen = ql - 2;
	CHECK_EQ(dns_reply_render(stored, (size_t)len, &rp, got, 512), -EINVAL);
	rp.qlen = ql;
	CHECK_EQ(dns_reply_render(stored, 11, &rp, got, 512), -EINVAL);
	rp.age = 1;
	CHECK_EQ(dns_reply_render(stored, (size_t)len - 1, &rp, got, 65535), -EINVAL);
	memcpy(want, stored, (size_t)len);
	want[5] = 2;
	CHECK_EQ(dns_reply_render(want, (size_t)len, &rp, got, 512), -EINVAL);
	want[5] = 1;
	want[7]++;			/* one AN record more than there is */
	CHECK_EQ(dns_reply_render(want, (size_t)len, &rp, got, 65535), -EINVAL);
	/* the question alone does not fit */
	rp.edns = true;
	CHECK_EQ(dns_reply_render(stored, (size_t)len, &rp, got, 12 + ql + 4 + 10), -ENOSPC);
out:
	dns_msg_free(&m);
}

TEST(names)
{
	uint8_t a[256], b[256], z[256], t[256];
	uint8_t al, bl, zl, tl;
	struct dns_name out;
	uint8_t big[256];
	int i;

	al = wn(a, "WwW.ExAmPlE.CoM");
	bl = wn(b, "www.example.com");
	CHECK(dns_name_eq(a, al, b, bl));
	CHECK_EQ(dns_name_hash(a, al), dns_name_hash(b, bl));
	bl = wn(b, "www.example.org");
	CHECK(!dns_name_eq(a, al, b, bl));
	CHECK(dns_name_hash(a, al) != dns_name_hash(b, bl));
	dns_name_lower(a, al);
	CHECK(!memcmp(a, "\3www\7example\3com", al));

	zl = wn(z, "example.com");
	CHECK(dns_name_is_under(a, al, z, zl));
	CHECK(dns_name_is_under(z, zl, z, zl));
	CHECK(dns_name_is_under(a, al, (const uint8_t *)"", 1));
	zl = wn(z, "ample.com");
	CHECK(!dns_name_is_under(a, al, z, zl));
	zl = wn(z, "EXAMPLE.com");
	CHECK(dns_name_is_under(a, al, z, zl));
	/* label boundary: "xexample.com" not under "example.com" with odd lens */
	bl = wn(b, "x.com");
	CHECK(!dns_name_is_under(z, zl, b, bl));

	/* DNAME */
	tl = wn(t, "example.net");
	CHECK_EQ(dns_name_dname_subst(a, al, z, zl, t, tl, &out), 0);
	bl = wn(b, "www.example.net");
	CHECK(out.len == bl && !memcmp(out.data, b, bl));
	CHECK_EQ(dns_name_dname_subst(z, zl, z, zl, t, tl, &out), -EINVAL);
	bl = wn(b, "foo.org");
	CHECK_EQ(dns_name_dname_subst(a, al, b, bl, t, tl, &out), -EINVAL);
	/* overflow: long qname prefix + long target */
	for (i = 0; i < 3; i++) {
		big[i * 64] = 63;
		memset(big + i * 64 + 1, 'q', 63);
	}
	memcpy(big + 192, z, zl);
	CHECK_EQ(dns_name_check(big, 256), 192 + zl);
	/* prefix = 192 bytes; target of 64+ bytes overflows */
	tl = 0;
	t[tl++] = 63;
	memset(t + tl, 't', 63);
	tl += 63;
	t[tl++] = 0;
	CHECK_EQ(dns_name_dname_subst(big, 192 + zl, z, zl, t, tl, &out), -EOVERFLOW);
	t[0] = 61;
	t[62] = 0;
	tl = 63;
	CHECK_EQ(dns_name_dname_subst(big, 192 + zl, z, zl, t, tl, &out), 0);
	CHECK_EQ(out.len, 255);

	/* name_check */
	CHECK_EQ(dns_name_check((const uint8_t *)"\1a", 2), -EBADMSG);
	CHECK_EQ(dns_name_check((const uint8_t *)"\1a\0", 3), 3);
	CHECK_EQ(dns_name_check((const uint8_t *)"\x40", 1), -EBADMSG);
}

TEST(copy_compact)
{
	struct dns_msg m, c;
	struct pkt p;

	dns_msg_init(&m);
	dns_msg_init(&c);
	build_cname_resp(&p);
	REQUIRE(parse(&m, &p) == 0);
	REQUIRE(dns_msg_copy(&c, &m) == 0);
	CHECK(msg_equal(&m, &c));
	CHECK(c.buf != m.buf);
	CHECK_EQ(c.buf_cap, c.buf_len);
	CHECK(c.buf_len <= m.buf_len);
	CHECK_EQ(c.rr_cap, c.nrr);
	CHECK_EQ(c.qoff, 0);
	/* source can go away */
	dns_msg_free(&m);
	CHECK(c.rr[1].rdata[3] == 1);
	CHECK(!memcmp(dns_msg_qname(&c), "\x03www\x07" "example\x03" "com", 17));
	/* copy into a non-empty destination */
	build_cname_resp(&p);
	REQUIRE(parse(&m, &p) == 0);
	REQUIRE(dns_msg_copy(&m, &c) == 0);
	CHECK(msg_equal(&m, &c));
	dns_msg_free(&m);
	dns_msg_free(&c);
	CHECK(!c.buf && !c.rr && !c.has_q);
	/* a question alone */
	dns_msg_set_question(&m, (const uint8_t *)"\1a", 3, DNS_T_A, DNS_C_IN);
	REQUIRE(dns_msg_copy(&c, &m) == 0);
	CHECK_EQ(c.buf_len, 3);
	CHECK(msg_equal(&m, &c));
	dns_msg_free(&m);
	dns_msg_free(&c);
}

/*
 * The question name lives in the message's storage, at an offset: it stays
 * valid when the struct is moved, when the storage grows, and when it is set
 * again (in place when it fits, else appended).
 */
TEST(question_storage)
{
	static const uint8_t q1[] = "\x03www\x07" "Example\x03" "com";
	static const uint8_t q2[] = "\x03WWW\x07" "example\x03" "COM";
	static const uint8_t lng[] = "\x0alonger-one\x07" "example\x03" "com";
	uint8_t rd[200];
	struct dns_msg m, moved;
	const uint8_t *b0;
	uint32_t used;
	int i;

	dns_msg_init(&m);
	CHECK(dns_msg_qname(&m) == NULL);
	REQUIRE(dns_msg_set_question(&m, q1, 17, DNS_T_A, DNS_C_IN) == 0);
	CHECK(m.has_q && m.qlen == 17 && m.qoff == 0 && m.buf_len == 17);
	/* RRs after it, enough to regrow the storage several times */
	memset(rd, 'x', sizeof(rd));
	b0 = m.buf;
	for (i = 0; i < 20; i++)
		REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, q1, 17, DNS_T_TXT, DNS_C_IN, 1, rd,
		                       sizeof(rd)) == 0);
	CHECK(m.buf != b0);
	CHECK(!memcmp(dns_msg_qname(&m), q1, 17));
	/* moved like r->out = r->resp */
	moved = m;
	dns_msg_init(&m);
	CHECK(!memcmp(dns_msg_qname(&moved), q1, 17));
	/* the same name in another case: in place */
	b0 = dns_msg_qname(&moved);
	used = moved.buf_len;
	REQUIRE(dns_msg_set_question(&moved, q2, 17, DNS_T_AAAA, DNS_C_IN) == 0);
	CHECK(dns_msg_qname(&moved) == b0 && moved.buf_len == used);
	CHECK(!memcmp(dns_msg_qname(&moved), q2, 17));
	CHECK_EQ(moved.qtype, DNS_T_AAAA);
	/* a longer one: appended, RRs untouched */
	REQUIRE(dns_msg_set_question(&moved, lng, 24, DNS_T_A, DNS_C_IN) == 0);
	CHECK_EQ(moved.qlen, 24);
	CHECK_EQ(moved.qoff, used);
	CHECK(!memcmp(dns_msg_qname(&moved), lng, 24));
	CHECK(!memcmp(moved.rr[19].owner, q1, 17) && moved.rr[19].rdata[0] == 'x');
	/* an invalid name changes nothing */
	CHECK_EQ(dns_msg_set_question(&moved, (const uint8_t *)"\5ab", 3, DNS_T_A, DNS_C_IN),
	         -EINVAL);
	CHECK(!memcmp(dns_msg_qname(&moved), lng, 24));
	/* from the message's own storage (an RR owner), growing it */
	REQUIRE(dns_msg_set_question(&moved, (const uint8_t *)"\1a", 3, DNS_T_A, DNS_C_IN) == 0);
	moved.buf_cap = moved.buf_len;	/* force the append to reallocate */
	REQUIRE(dns_msg_set_question(&moved, moved.rr[0].owner, 17, DNS_T_A, DNS_C_IN) == 0);
	CHECK(!memcmp(dns_msg_qname(&moved), q1, 17));
	CHECK(!memcmp(moved.rr[0].owner, q1, 17));
	/* a copy of a moved message, and a build of it, keep the question */
	REQUIRE(dns_msg_copy(&m, &moved) == 0);
	CHECK(msg_equal(&m, &moved));
	dns_msg_free(&m);
	/* reset drops it, keeping the storage */
	b0 = moved.buf;
	dns_msg_reset(&moved);
	CHECK(!moved.has_q && !moved.buf_len && moved.buf == b0);
	CHECK(dns_msg_qname(&moved) == NULL);
	dns_msg_free(&moved);
}

/* Recycling keeps small storage for reuse and frees large storage. */
TEST(recycle)
{
	static uint8_t rd[3000];
	struct dns_msg m, other;
	const uint8_t *b;
	struct pkt p;

	dns_msg_init(&m);
	build_cname_resp(&p);
	REQUIRE(parse(&m, &p) == 0);
	b = m.buf;
	dns_msg_recycle(&m);
	CHECK(m.buf == b && m.rr && !m.nrr && !m.buf_len && !m.has_q);
	/* reused by the next parse without moving */
	REQUIRE(parse(&m, &p) == 0);
	CHECK(m.buf == b);
	/* swapped away and back, storage and all */
	dns_msg_init(&other);
	dns_msg_swap(&m, &other);
	CHECK(!m.buf && other.buf == b && other.nrr == 2);
	CHECK(!memcmp(dns_msg_qname(&other), "\x03www", 4));
	dns_msg_swap(&m, &other);
	/* large storage is not kept */
	REQUIRE(dns_msg_add_rr(&m, DNS_S_AR, (const uint8_t *)"\1a", 3, DNS_T_TXT, DNS_C_IN, 1,
	                       rd, sizeof(rd)) == 0);
	dns_msg_recycle(&m);
	CHECK(!m.buf && !m.rr && !m.buf_cap);
	dns_msg_free(&m);
	dns_msg_free(&other);
}

/* Caller storage: a query parses without allocating; growth moves to the heap. */
TEST(caller_storage)
{
	uint8_t store[64], rd[100];
	struct dns_msg m;
	struct pkt p;

	build_cname_resp(&p);
	dns_msg_init_buf(&m, store, 20);
	REQUIRE(dns_parse_query(&m, p.b, p.n) == 0);
	CHECK(m.buf == store && m.buf_ext);
	CHECK(!memcmp(dns_msg_qname(&m), "\x03www\x07" "example\x03" "com", 17));
	/* a full parse needs more: the storage moves to the heap, rebased */
	REQUIRE(dns_parse(&m, p.b, p.n) == 0);
	CHECK(m.buf != store && !m.buf_ext);
	CHECK(!memcmp(dns_msg_qname(&m), "\x03www\x07" "example\x03" "com", 17));
	CHECK_EQ(m.nrr, 2);
	dns_msg_free(&m);
	/* growth while RRs point into the caller's storage */
	dns_msg_init_buf(&m, store, sizeof(store));
	memset(rd, 'y', sizeof(rd));
	REQUIRE(dns_msg_set_question(&m, (const uint8_t *)"\1a", 3, DNS_T_A, DNS_C_IN) == 0);
	REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, (const uint8_t *)"\1b", 3, DNS_T_TXT,
	                       DNS_C_IN, 1, rd, 40) == 0);
	CHECK(m.buf == store);
	REQUIRE(dns_msg_add_rr(&m, DNS_S_AN, (const uint8_t *)"\1c", 3, DNS_T_TXT,
	                       DNS_C_IN, 1, rd, sizeof(rd)) == 0);
	CHECK(m.buf != store);
	memset(store, 0, sizeof(store));	/* nothing refers to it any more */
	CHECK(!memcmp(dns_msg_qname(&m), "\1a", 3));
	CHECK(!memcmp(m.rr[0].owner, "\1b", 3) && m.rr[0].rdata[39] == 'y');
	dns_msg_free(&m);
}

TEST(growth_rebase)
{
	/* many RRs with long expanded names force buffer regrowth */
	static struct pkt p;
	struct dns_msg m, c;
	uint8_t lab[63];
	int i;

	memset(lab, 'z', sizeof(lab));
	dns_msg_init(&m);
	dns_msg_init(&c);
	p_hdr(&p, DNS_F_QR, 1, 300, 0, 0);
	p_u8(&p, 63);
	p_bytes(&p, lab, 63);
	p_u8(&p, 63);
	p_bytes(&p, lab, 63);
	p_u8(&p, 63);
	p_bytes(&p, lab, 63);
	p_u8(&p, 0);
	p_u16(&p, DNS_T_CNAME);
	p_u16(&p, 1);
	for (i = 0; i < 300; i++) {
		p_u16(&p, 0xc00c);
		p_rrfix(&p, DNS_T_CNAME, 1, 2);
		p_u16(&p, 0xc00c);
	}
	REQUIRE(parse(&m, &p) == 0);
	CHECK_EQ(m.nrr, 300);
	CHECK(m.buf_len == m.qlen + 300u * 2 * 193);
	for (i = 0; i < 300; i++) {
		CHECK(m.rr[i].owner >= m.buf && m.rr[i].owner < m.buf + m.buf_len);
		CHECK(!memcmp(m.rr[i].rdata, m.rr[i].owner, 193));
	}
	REQUIRE(dns_msg_copy(&c, &m) == 0);
	CHECK(msg_equal(&m, &c));
	{
		int n;

		roundtrip(&p, 65535, &n);
		CHECK(n > 0 && (size_t)n <= p.n);
	}
	dns_msg_free(&m);
	dns_msg_free(&c);
}

TEST(rcode_and_types)
{
	struct dns_msg m;
	char buf[16];

	dns_msg_init(&m);
	m.edns.present = true;
	dns_msg_set_rcode(&m, DNS_R_BADVERS);
	CHECK_EQ(m.flags & DNS_F_RCODE, 0);
	CHECK_EQ(m.edns.ext_rcode, 1);
	CHECK_EQ(dns_msg_rcode(&m), DNS_R_BADVERS);
	dns_msg_set_rcode(&m, DNS_R_NXDOMAIN);
	CHECK_EQ(dns_msg_rcode(&m), DNS_R_NXDOMAIN);
	CHECK_STR(dns_type_str(DNS_T_HTTPS, buf), "HTTPS");
	CHECK_STR(dns_type_str(1234, buf), "TYPE1234");
	dns_msg_free(&m);
}

/* dns_build() reuses one static context: stale state must never leak. */
static void small_msg(struct dns_msg *m, uint8_t *n1)
{
	uint8_t a[4] = { 192, 0, 2, 1 };
	uint8_t l1 = wn(n1, "www.example.org");

	dns_msg_init(m);
	m->id = 0x1234;
	m->flags = DNS_F_QR | DNS_F_RD | DNS_F_RA;
	dns_msg_set_question(m, n1, l1, DNS_T_A, DNS_C_IN);
	dns_msg_add_rr(m, DNS_S_AN, n1, l1, DNS_T_A, DNS_C_IN, 60, a, 4);
}

TEST(build_reuse)
{
	static const uint8_t expect[] = {
		0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0,
		0, 1, 0, 1,
		0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1,
	};
	struct dns_msg big, sm, bad;
	uint8_t n1[256], nb[256], nsm[256], out[65535], first[512];
	uint8_t lb;
	int n, n0, i;

	small_msg(&sm, nsm);
	n0 = dns_build(&sm, first, sizeof(first));
	REQUIRE(n0 == (int)sizeof(expect));
	CHECK(!memcmp(first, expect, sizeof(expect)));

	/* a big build fills the compression table with many suffixes ... */
	dns_msg_init(&big);
	lb = wn(nb, "www.example.org");
	REQUIRE(dns_msg_set_question(&big, nb, lb, DNS_T_A, DNS_C_IN) == 0);
	for (i = 0; i < 200; i++) {
		char name[64];
		uint8_t l;

		snprintf(name, sizeof(name), "h%d.www.example.org", i);
		l = wn(n1, name);
		REQUIRE(dns_msg_add_rr(&big, DNS_S_AN, n1, l, DNS_T_CNAME, 1, 30, nb, lb) == 0);
	}
	n = dns_build(&big, out, sizeof(out));
	REQUIRE(n > 0);
	/* ... and the next, smaller build must not see any of it */
	memset(out, 0xee, sizeof(out));
	CHECK_EQ(dns_build(&sm, out, 512), n0);
	CHECK(!memcmp(out, expect, sizeof(expect)));

	/* failing midway: the question name is hashed into the table, then
	 * does not fit; an RR with a bad section fails after the question */
	CHECK_EQ(dns_build(&big, out, 12 + 4), -ENOSPC);
	CHECK_EQ(dns_build(&sm, out, 512), n0);
	CHECK(!memcmp(out, expect, sizeof(expect)));
	small_msg(&bad, n1);
	bad.rr[0].section = DNS_S_AR + 1;
	CHECK_EQ(dns_build(&bad, out, 512), -EINVAL);
	memset(out, 0, sizeof(out));
	CHECK_EQ(dns_build(&sm, out, 512), n0);
	CHECK(!memcmp(out, expect, sizeof(expect)));

	/* a truncated (TC) build followed by a full one */
	n = dns_build(&big, out, 512);
	CHECK(n > 0 && (out[2] & 0x02));
	CHECK_EQ(dns_build(&sm, out, 512), n0);
	CHECK(!memcmp(out, expect, sizeof(expect)));

	dns_msg_free(&bad);
	dns_msg_free(&sm);
	dns_msg_free(&big);
}

/* ---- randomized messages ---- */

static uint32_t rnd_state;

static uint32_t rnd(uint32_t n)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 17;
	rnd_state ^= rnd_state << 5;
	return n ? rnd_state % n : rnd_state;
}

/* A name from a small vocabulary in mixed case, so that names share
 * suffixes (and differ only by case) often: compression gets exercised. */
static uint8_t rnd_name(uint8_t *out)
{
	static const char *const labs[] = {
		"www", "WWW", "example", "Example", "EXAMPLE", "cdn", "a", "mail", "svc",
		"com", "org", "Org", "x1", "ns", "edge",
		"a-long-label-to-fill-names-with-0123456789-abcdefghijklmnopqrst",
	};
	int nl = (int)rnd(5), i;
	uint8_t n = 0;

	if (rnd(4) == 0)
		nl += (int)rnd(4);
	for (i = 0; i < nl; i++) {
		const char *l = labs[rnd(sizeof(labs) / sizeof(labs[0]))];
		size_t len = strlen(l);

		if (n + 1 + len + 1 > DNS_MAX_NAME)
			break;
		out[n++] = (uint8_t)len;
		memcpy(out + n, l, len);
		n += (uint8_t)len;
	}
	out[n++] = 0;
	return n;
}

/* Fill m with a random message (records in section order, valid rdata). */
static void rnd_msg(struct dns_msg *m)
{
	static const uint16_t types[] = {
		DNS_T_A, DNS_T_AAAA, DNS_T_CNAME, DNS_T_NS, DNS_T_PTR, DNS_T_MX, DNS_T_SOA,
		DNS_T_TXT, DNS_T_DNAME, DNS_T_SRV, DNS_T_HTTPS, DNS_T_RRSIG, 3, 4, 7, 8, 9, 14,
	};
	uint8_t owner[DNS_MAX_NAME], rd[8192];
	int nrr = (int)rnd(12), i, sec = DNS_S_AN;

	dns_msg_init(m);
	m->id = (uint16_t)rnd(0);
	m->flags = (uint16_t)rnd(0);
	if (rnd(10)) {
		uint8_t q[DNS_MAX_NAME], ql = rnd_name(q);

		dns_msg_set_question(m, q, ql, (uint16_t)rnd(70), rnd(8) ? DNS_C_IN : (uint16_t)rnd(0));
	}
	if (rnd(3) == 0) {
		m->edns.present = true;
		m->edns.udp_size = (uint16_t)rnd(0);
		m->edns.ext_rcode = (uint8_t)rnd(0);
		m->edns.version = (uint8_t)rnd(2);
		m->edns.do_bit = rnd(2);
	}
	if (rnd(8) == 0)
		nrr += (int)rnd(400);
	for (i = 0; i < nrr; i++) {
		uint16_t type = types[rnd(sizeof(types) / sizeof(types[0]))], n = 0;
		uint8_t ol = rnd_name(owner);
		uint32_t k;

		if (rnd(6) == 0 && sec < DNS_S_AR)
			sec++;
		switch (type) {
		case DNS_T_A: case DNS_T_AAAA:
			n = type == DNS_T_A ? 4 : 16;
			for (k = 0; k < n; k++)
				rd[k] = (uint8_t)rnd(0);
			break;
		case DNS_T_MX:
			rd[0] = 0;
			rd[1] = (uint8_t)rnd(0);
			n = 2 + rnd_name(rd + 2);
			break;
		case DNS_T_SRV:
			memset(rd, 1, 6);
			n = 6 + rnd_name(rd + 6);
			break;
		case DNS_T_SOA: case 14:
			n = rnd_name(rd);
			n += rnd_name(rd + n);
			if (type == DNS_T_SOA) {
				for (k = 0; k < 20; k++)
					rd[n++] = (uint8_t)rnd(0);
			}
			break;
		case DNS_T_TXT: case DNS_T_HTTPS: case DNS_T_RRSIG:
			n = (uint16_t)rnd(rnd(10) ? 300 : sizeof(rd));
			for (k = 0; k < n; k++)
				rd[k] = (uint8_t)rnd(0);
			if (type == DNS_T_HTTPS && n >= 3) {
				uint8_t t[DNS_MAX_NAME], tl = rnd_name(t);

				if (2u + tl <= n)
					memcpy(rd + 2, t, tl);
			}
			break;
		default:	/* one name */
			n = rnd_name(rd);
			break;
		}
		if (dns_msg_add_rr(m, (enum dns_section)sec, owner, ol, type,
		                   rnd(10) ? DNS_C_IN : (uint16_t)rnd(0), rnd(0), rd, n))
			abort();
	}
}

static int rnd_tc, rnd_arcut, rnd_full;	/* outcomes of rnd_builds() */

/* Build m at sizes from too small for the question to 64 KiB; hash it all. */
static uint64_t rnd_builds(const struct dns_msg *m)
{
	static const size_t limits[] = { 12, 40, 100, 512, 1232, 4096, 20000, DNS_MAX_MSG };
	static uint8_t out[DNS_MAX_MSG];
	uint64_t h = 1469598103934665603ull;
	size_t li, k;

	for (li = 0; li < sizeof(limits) / sizeof(limits[0]); li++) {
		int n = dns_build(m, out, limits[li]);
		uint8_t rc[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };

		for (k = 0; k < 4; k++)
			h = (h ^ rc[k]) * 1099511628211ull;
		for (k = 0; n > 0 && k < (size_t)n; k++)
			h = (h ^ out[k]) * 1099511628211ull;
		if (n < 12 || (m->flags & DNS_F_TC))
			continue;
		if (out[2] & 0x02)
			rnd_tc++;
		else if ((out[10] << 8 | out[11]) < dns_msg_count(m, DNS_S_AR) + m->edns.present)
			rnd_arcut++;
		else if (m->nrr > 20)
			rnd_full++;
	}
	return h;
}

#define RND_MSGS 600

/*
 * dns_build() of random messages at every size limit, byte for byte as
 * recorded (build_golden.inc, FNV-1a 64 per message over the results of
 * all limits) from the build before the streaming builder replaced it.
 * WIRE_GOLDEN_RECORD=<file> writes the table anew instead.
 */
TEST(build_golden)
{
	static const uint64_t golden[] = {
#include "build_golden.inc"
	};
	FILE *rec = getenv("WIRE_GOLDEN_RECORD") ? fopen(getenv("WIRE_GOLDEN_RECORD"), "w") : NULL;
	struct dns_msg m;
	int i, bad = 0;

	if (!rec)
		REQUIRE(sizeof(golden) / sizeof(golden[0]) == RND_MSGS);
	rnd_state = 0x9e3779b9u;
	for (i = 0; i < RND_MSGS; i++) {
		uint64_t h;

		rnd_msg(&m);
		h = rnd_builds(&m);
		if (rec)
			fprintf(rec, "0x%016" PRIx64 "ull,\n", h);
		else if (h != golden[i] && bad++ < 5)
			fprintf(stderr, "  random message %d: built bytes differ\n", i);
		dns_msg_free(&m);
	}
	if (rec)
		fclose(rec);
	CHECK_EQ(bad, 0);
	/* each kind of cut, and large messages that fit, are well represented */
	CHECK(rnd_tc > 200 && rnd_arcut > 50 && rnd_full > 20);
}

/* Section order, the record cap, and records offered after a cut. */
TEST(stream_rules)
{
	static struct dns_builder b;
	uint8_t q[64], out[512], a[4] = { 192, 0, 2, 1 };
	uint8_t ql = wn(q, "www.example.org");
	int i, n;

	REQUIRE(dns_build_begin(&b, out, sizeof(out), 7, DNS_F_QR, q, ql, DNS_T_A, DNS_C_IN) == 0);
	CHECK_EQ(dns_build_add(&b, DNS_S_NS, q, ql, DNS_T_A, 1, 60, a, 4), 0);
	CHECK_EQ(dns_build_add(&b, DNS_S_AN, q, ql, DNS_T_A, 1, 60, a, 4), -EINVAL);
	CHECK_EQ(dns_build_add(&b, DNS_S_AR + 1, q, ql, DNS_T_A, 1, 60, a, 4), -EINVAL);
	/* glue until the 512 bytes are full: the rest is left out, but counted */
	for (i = 1; i < DNS_MAX_RRS; i++)
		CHECK_EQ(dns_build_add(&b, DNS_S_AR, q, ql, DNS_T_A, 1, 60, a, 4), 0);
	CHECK_EQ(dns_build_add(&b, DNS_S_AR, q, ql, DNS_T_A, 1, 60, a, 4), -E2BIG);
	n = dns_build_end(&b);
	CHECK_EQ(n, 33 + 16 * 29);
	CHECK_EQ(out[2] & 0x02, 0);
	CHECK_EQ(out[9], 1);
	CHECK_EQ(out[11], 28);

	/* an answer record that does not fit: TC, header and question only,
	 * whatever comes after */
	REQUIRE(dns_build_begin(&b, out, 60, 7, DNS_F_QR, q, ql, DNS_T_A, DNS_C_IN) == 0);
	CHECK_EQ(dns_build_add(&b, DNS_S_AN, q, ql, DNS_T_A, 1, 60, a, 4), 0);
	CHECK_EQ(dns_build_add(&b, DNS_S_AN, q, ql, DNS_T_CNAME, 1, 60, q, ql), 0);
	CHECK_EQ(dns_build_add(&b, DNS_S_AR, q, ql, DNS_T_A, 1, 60, a, 4), 0);
	CHECK_EQ(dns_build_end(&b), 33);
	CHECK(out[2] & 0x02);
	CHECK(!out[7] && !out[9] && !out[11]);

	/* no room for the question */
	CHECK_EQ(dns_build_begin(&b, out, 20, 7, 0, q, ql, DNS_T_A, DNS_C_IN), -ENOSPC);
	CHECK_EQ(dns_build_begin(&b, out, 11, 7, 0, NULL, 0, 0, 0), -ENOSPC);
	REQUIRE(dns_build_begin(&b, out, 12, 7, 0, NULL, 0, 0, 0) == 0);
	CHECK_EQ(dns_build_end(&b), 12);
	CHECK_EQ(out[5], 0);
}

int main(void)
{
	uint8_t key[16] = { 1, 2, 3 };

	hash_init_fixed(key);
	RUN(basic_parse);
	RUN(ttl_msb_clamp);
	RUN(cname_compressed_rdata);
	RUN(pointer_loops);
	RUN(jump_limit);
	RUN(jump_limit_ok);
	RUN(oversize_names);
	RUN(truncation);
	RUN(rdlength_overrun);
	RUN(opt_rules);
	RUN(qdcount);
	RUN(too_many_rrs);
	RUN(round_trip_compress);
	RUN(round_trip_parsed);
	RUN(truncate_512);
	RUN(compress_nocase);
	RUN(reply_render);
	RUN(names);
	RUN(copy_compact);
	RUN(question_storage);
	RUN(caller_storage);
	RUN(recycle);
	RUN(growth_rebase);
	RUN(rcode_and_types);
	RUN(build_reuse);
	RUN(build_golden);
	RUN(stream_rules);
	return test_summary();
}
