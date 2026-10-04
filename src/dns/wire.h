/* SPDX-License-Identifier: MIT */
#ifndef OMNI_DNS_WIRE_H
#define OMNI_DNS_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * DNS wire-format parsing and building.
 *
 * Names are handled in *uncompressed wire format* (length-prefixed labels,
 * terminated by the root label 0). Original case is preserved; comparisons
 * and hashing are ASCII case-insensitive.
 *
 * Parsing is strictly bounded:
 *  - compression pointers must point strictly backwards and at most
 *    DNS_MAX_PTR_JUMPS jumps are followed;
 *  - names > 255 bytes, labels > 63, and label types 0x40/0x80 are rejected;
 *  - at most DNS_MAX_RRS RRs per message;
 *  - rdata of types that may contain compressed names (RFC 3597 sec. 4:
 *    NS MD MF CNAME SOA MB MG MR PTR MINFO MX) is *expanded* to uncompressed
 *    form; for SOA/MX/MINFO the fixed fields are carried along. RDATA of all
 *    other types is copied verbatim (SVCB/HTTPS/SRV/DNAME names are never
 *    compressed on the wire per their RFCs; if malformed, we keep the bytes).
 *  - For CNAME, DNAME, PTR, NS the expanded rdata must be exactly one valid
 *    name, otherwise the message is rejected (-EBADMSG).
 *
 * A parsed message owns a single heap buffer; all rr owner/rdata pointers
 * point into it. Messages may also be constructed programmatically.
 */

#define DNS_MAX_NAME		255
#define DNS_MAX_LABEL		63
#define DNS_MAX_RRS		512
#define DNS_MAX_PTR_JUMPS	32
#define DNS_MAX_MSG		65535

/* types */
enum {
	DNS_T_A = 1, DNS_T_NS = 2, DNS_T_CNAME = 5, DNS_T_SOA = 6,
	DNS_T_PTR = 12, DNS_T_MX = 15, DNS_T_TXT = 16, DNS_T_AAAA = 28,
	DNS_T_SRV = 33, DNS_T_DNAME = 39, DNS_T_OPT = 41, DNS_T_DS = 43,
	DNS_T_RRSIG = 46, DNS_T_NSEC = 47, DNS_T_DNSKEY = 48, DNS_T_NSEC3 = 50,
	DNS_T_NSEC3PARAM = 51, DNS_T_SVCB = 64, DNS_T_HTTPS = 65,
	DNS_T_IXFR = 251, DNS_T_AXFR = 252, DNS_T_ANY = 255,
};
enum { DNS_C_IN = 1, DNS_C_ANY = 255 };

/* rcodes (4-bit header part; extended rcodes via EDNS) */
enum {
	DNS_R_NOERROR = 0, DNS_R_FORMERR = 1, DNS_R_SERVFAIL = 2,
	DNS_R_NXDOMAIN = 3, DNS_R_NOTIMP = 4, DNS_R_REFUSED = 5,
	DNS_R_BADVERS = 16,
};

/* header flag bits (host order of the 16-bit flags word) */
#define DNS_F_QR	0x8000
#define DNS_F_OPCODE	0x7800
#define DNS_F_AA	0x0400
#define DNS_F_TC	0x0200
#define DNS_F_RD	0x0100
#define DNS_F_RA	0x0080
#define DNS_F_AD	0x0020
#define DNS_F_CD	0x0010
#define DNS_F_RCODE	0x000f

enum dns_section { DNS_S_AN = 0, DNS_S_NS = 1, DNS_S_AR = 2 };

struct dns_name {
	uint8_t len;			/* total wire length incl. root label, 1..255 */
	uint8_t data[DNS_MAX_NAME];
};

struct dns_rr {
	const uint8_t *owner;		/* uncompressed wire name */
	uint8_t owner_len;
	uint8_t section;		/* enum dns_section */
	uint16_t type, cls;
	uint32_t ttl;
	uint16_t rdlen;
	const uint8_t *rdata;		/* expanded (uncompressed) rdata */
};

struct dns_edns {
	bool present;
	uint8_t version;
	uint8_t ext_rcode;		/* upper 8 bits of the 12-bit rcode */
	bool do_bit;
	uint16_t udp_size;
	/* EDNS options are not retained (ECS, cookies, padding are dropped). */
};

struct dns_msg {
	uint16_t id;
	uint16_t flags;			/* includes 4-bit rcode */
	bool has_q;
	struct dns_name qname;		/* original case as received */
	uint16_t qtype, qclass;
	struct dns_edns edns;		/* OPT is never kept in rr[] */
	uint16_t nrr;			/* RRs in order: all AN, then NS, then AR */
	uint16_t rr_cap;
	struct dns_rr *rr;
	/* storage */
	uint8_t *buf;
	size_t buf_len, buf_cap;
};

/* ---- names ---- */

/* Parse "www.Example.com" or "www.example.com." or "." ; supports \. and \DDD
 * escapes. Returns 0 or -EINVAL. */
int dns_name_from_text(struct dns_name *n, const char *text);

/*
 * Render as lowercase dotted text without trailing dot ("" for root).
 * Bytes outside [a-z0-9-_*] and '.' inside labels are escaped as \DDD so
 * that they never collide with LDH nameset patterns.
 * Returns length written (excluding NUL) or -ENOSPC. out needs <= 1009 bytes
 * worst case; DNS_NAME_TEXT_MAX is sufficient.
 */
#define DNS_NAME_TEXT_MAX 1024
int dns_name_to_text(const uint8_t *wire, uint8_t wire_len, char *out, size_t cap);

bool dns_name_eq(const uint8_t *a, uint8_t alen, const uint8_t *b, uint8_t blen);	/* case-insensitive */
uint64_t dns_name_hash(const uint8_t *wire, uint8_t len);	/* case-insensitive, keyed */
void dns_name_lower(uint8_t *wire, uint8_t len);
int dns_name_labels(const uint8_t *wire, uint8_t len);		/* count excluding root */
/* true if `name` equals `zone` or is below it (case-insensitive). */
bool dns_name_is_under(const uint8_t *name, uint8_t nlen, const uint8_t *zone, uint8_t zlen);
/*
 * DNAME substitution (RFC 6672): `qname` is under `owner`; replace the owner
 * suffix with `target`. Returns 0, -EINVAL if qname is not strictly below
 * owner, or -EOVERFLOW if the result exceeds 255 bytes (=> YXDOMAIN).
 */
int dns_name_dname_subst(const uint8_t *qname, uint8_t qlen,
			 const uint8_t *owner, uint8_t olen,
			 const uint8_t *target, uint8_t tlen,
			 struct dns_name *out);
/* Validate an uncompressed wire name at p (max avail bytes); returns its
 * length (1..255) or -EBADMSG. */
int dns_name_check(const uint8_t *p, size_t avail);

/* ---- messages ---- */

void dns_msg_init(struct dns_msg *m);
void dns_msg_free(struct dns_msg *m);
void dns_msg_reset(struct dns_msg *m);		/* drop RRs/storage, keep allocation */

/*
 * Parse a full message. Accepts both queries and responses.
 * Returns 0, -EBADMSG (malformed: FORMERR material), -E2BIG (too many RRs),
 * -ENOMEM.
 * QDCOUNT must be 0 or 1. If the OPT RR is malformed or duplicated
 * -EBADMSG is returned. TSIG/SIG(0) are treated as ordinary AR RRs.
 * A message with QDCOUNT==1 but truncated after the question (e.g. a
 * TC response) parses successfully with whatever complete RRs exist only if
 * the header TC bit is set; otherwise truncation is -EBADMSG.
 */
int dns_parse(struct dns_msg *m, const uint8_t *buf, size_t len);

/* Parse only header + question (cheap path for queries). Same errors. */
int dns_parse_query(struct dns_msg *m, const uint8_t *buf, size_t len);

/* Append an RR; owner and rdata are copied into m's storage. rdata must be
 * uncompressed. RRs must be appended in section order (AN, NS, AR);
 * returns -EINVAL otherwise, -E2BIG past DNS_MAX_RRS. */
int dns_msg_add_rr(struct dns_msg *m, enum dns_section sec,
		   const uint8_t *owner, uint8_t owner_len,
		   uint16_t type, uint16_t cls, uint32_t ttl,
		   const uint8_t *rdata, uint16_t rdlen);
int dns_msg_set_question(struct dns_msg *m, const uint8_t *qname, uint8_t qlen,
			 uint16_t qtype, uint16_t qclass);
int dns_msg_copy(struct dns_msg *dst, const struct dns_msg *src);	/* deep, compact */

/* Count of RRs in a section. */
uint16_t dns_msg_count(const struct dns_msg *m, enum dns_section sec);

static inline int dns_msg_rcode(const struct dns_msg *m)
{
	return (m->flags & DNS_F_RCODE) | (m->edns.present ? (m->edns.ext_rcode << 4) : 0);
}
void dns_msg_set_rcode(struct dns_msg *m, int rcode);	/* sets ext_rcode too */

/* Size of storage held (for cache accounting). */
size_t dns_msg_footprint(const struct dns_msg *m);

/*
 * Serialize with name compression (owner names and the compressible rdata
 * types listed above). `maxlen` is the size limit (512..65535).
 *
 * If the message does not fit, RRs are dropped from the end of AR first;
 * if it still does not fit, the AN/NS sections are dropped entirely, TC is
 * set and only header + question (+ OPT) are emitted.
 * The OPT RR is emitted from m->edns when present.
 * Returns the number of bytes written or a negative errno.
 */
int dns_build(const struct dns_msg *m, uint8_t *out, size_t maxlen);

/* Accessors for well-known rdata (expanded form). Return -EBADMSG when the
 * rdata is malformed. */
int dns_rr_target(const struct dns_rr *rr, struct dns_name *out);	/* CNAME/DNAME/PTR/NS */
int dns_soa_minimum(const struct dns_rr *rr, uint32_t *minimum);

/* Debug helpers */
const char *dns_type_str(uint16_t type, char buf[16]);

#endif
