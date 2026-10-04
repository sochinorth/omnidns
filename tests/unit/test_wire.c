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
			 a->qname.len != b->qname.len ||
			 memcmp(a->qname.data, b->qname.data, a->qname.len)))
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
	CHECK_EQ(m.qname.len, 255);
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
	CHECK_EQ(dns_name_labels(a, al), 3);
	CHECK_EQ(dns_name_labels((const uint8_t *)"", 1), 0);
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

TEST(copy_footprint)
{
	struct dns_msg m, c;
	struct pkt p;

	dns_msg_init(&m);
	dns_msg_init(&c);
	build_cname_resp(&p);
	REQUIRE(parse(&m, &p) == 0);
	CHECK(dns_msg_footprint(&m) >= m.buf_len);
	REQUIRE(dns_msg_copy(&c, &m) == 0);
	CHECK(msg_equal(&m, &c));
	CHECK(c.buf != m.buf);
	CHECK_EQ(c.buf_cap, c.buf_len);
	CHECK_EQ(c.rr_cap, c.nrr);
	CHECK(dns_msg_footprint(&c) <= dns_msg_footprint(&m));
	CHECK_EQ(dns_msg_footprint(&c), c.buf_len + c.nrr * sizeof(struct dns_rr));
	/* source can go away */
	dns_msg_free(&m);
	CHECK(c.rr[1].rdata[3] == 1);
	/* copy into a non-empty destination */
	build_cname_resp(&p);
	REQUIRE(parse(&m, &p) == 0);
	REQUIRE(dns_msg_copy(&m, &c) == 0);
	CHECK(msg_equal(&m, &c));
	dns_msg_free(&m);
	dns_msg_free(&c);
	CHECK_EQ(dns_msg_footprint(&c), 0);
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
	CHECK(m.buf_len == 300 * 2 * 193);
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
	RUN(names);
	RUN(copy_footprint);
	RUN(growth_rebase);
	RUN(rcode_and_types);
	return test_summary();
}
