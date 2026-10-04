// SPDX-License-Identifier: MIT
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/hash.h"
#include "wire.h"

#define DNS_HDR_LEN	12
#define DNS_RR_FIXED	10
#define DNS_OPT_LEN	11

/* internal: input ended early (may be tolerated when TC is set) */
#define E_TRUNC		ENODATA

static inline uint16_t get16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static inline uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static inline void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

static inline void put32(uint8_t *p, uint32_t v)
{
	put16(p, v >> 16);
	put16(p + 2, v & 0xffff);
}

static inline uint8_t lc(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* ---- names ---- */

int dns_name_check(const uint8_t *p, size_t avail)
{
	size_t i = 0;

	if (avail > DNS_MAX_NAME)
		avail = DNS_MAX_NAME;
	while (i < avail) {
		uint8_t l = p[i];

		if (!l)
			return (int)i + 1;
		if (l > DNS_MAX_LABEL)
			return -EBADMSG;
		i += (size_t)l + 1;
	}
	return -EBADMSG;
}

bool dns_name_eq(const uint8_t *a, uint8_t alen, const uint8_t *b, uint8_t blen)
{
	uint8_t i;

	if (alen != blen)
		return false;
	for (i = 0; i < alen; i++)
		if (lc(a[i]) != lc(b[i]))
			return false;
	return true;
}

uint64_t dns_name_hash(const uint8_t *wire, uint8_t len)
{
	uint8_t tmp[DNS_MAX_NAME];
	uint8_t i;

	for (i = 0; i < len; i++)
		tmp[i] = lc(wire[i]);
	return omni_hash(tmp, len);
}

void dns_name_lower(uint8_t *wire, uint8_t len)
{
	uint8_t i;

	for (i = 0; i < len; i++)
		wire[i] = lc(wire[i]);
}

int dns_name_labels(const uint8_t *wire, uint8_t len)
{
	size_t i = 0;
	int n = 0;

	while (i < len && wire[i]) {
		if (wire[i] > DNS_MAX_LABEL)
			return -EBADMSG;
		i += (size_t)wire[i] + 1;
		n++;
	}
	if (i >= len)
		return -EBADMSG;
	return n;
}

/* Offset in `name` where a suffix of length `slen` starts, or -1. */
static int suffix_off(const uint8_t *name, uint8_t nlen, uint8_t slen)
{
	size_t i = 0;

	if (slen > nlen)
		return -1;
	while (i < nlen) {
		if (nlen - i == slen)
			return (int)i;
		if (!name[i] || name[i] > DNS_MAX_LABEL)
			return -1;
		i += (size_t)name[i] + 1;
	}
	return -1;
}

bool dns_name_is_under(const uint8_t *name, uint8_t nlen, const uint8_t *zone, uint8_t zlen)
{
	int off = suffix_off(name, nlen, zlen);

	return off >= 0 && dns_name_eq(name + off, zlen, zone, zlen);
}

int dns_name_dname_subst(const uint8_t *qname, uint8_t qlen,
			 const uint8_t *owner, uint8_t olen,
			 const uint8_t *target, uint8_t tlen,
			 struct dns_name *out)
{
	size_t plen;

	if (qlen <= olen || !dns_name_is_under(qname, qlen, owner, olen))
		return -EINVAL;
	if (dns_name_check(target, tlen) != tlen)
		return -EINVAL;
	plen = (size_t)qlen - olen;
	if (plen + tlen > DNS_MAX_NAME)
		return -EOVERFLOW;
	memcpy(out->data, qname, plen);
	memcpy(out->data + plen, target, tlen);
	out->len = (uint8_t)(plen + tlen);
	return 0;
}

/* ---- rdata layouts of types with compressible names ---- */

struct rd_layout {
	uint8_t pre, names, post;
};

static const struct rd_layout *rd_layout(uint16_t type)
{
	static const struct rd_layout one = { 0, 1, 0 }, soa = { 0, 2, 20 },
		mx = { 2, 1, 0 }, minfo = { 0, 2, 0 };

	switch (type) {
	case DNS_T_NS: case 3: case 4: case DNS_T_CNAME: case 7: case 8:
	case 9: case DNS_T_PTR:
		return &one;
	case DNS_T_SOA:
		return &soa;
	case DNS_T_MX:
		return &mx;
	case 14:
		return &minfo;
	}
	return NULL;
}

static bool single_name_type(uint16_t type)
{
	return type == DNS_T_CNAME || type == DNS_T_DNAME ||
	       type == DNS_T_PTR || type == DNS_T_NS;
}

/* Validate expanded rdata against its layout. */
static bool rd_valid(const struct rd_layout *lo, const uint8_t *rd, size_t len)
{
	size_t off = lo->pre;
	int i, r;

	if (len < off)
		return false;
	for (i = 0; i < lo->names; i++) {
		r = dns_name_check(rd + off, len - off);
		if (r < 0)
			return false;
		off += r;
	}
	return len - off == lo->post;
}

static bool rdata_ok(uint16_t type, const uint8_t *rd, uint16_t len)
{
	const struct rd_layout *lo = rd_layout(type);

	if (lo)
		return rd_valid(lo, rd, len);
	if (type == DNS_T_DNAME)
		return dns_name_check(rd, len) == len;
	return true;
}

/* ---- storage ---- */

void dns_msg_init(struct dns_msg *m)
{
	memset(m, 0, sizeof(*m));
}

void dns_msg_free(struct dns_msg *m)
{
	free(m->rr);
	free(m->buf);
	dns_msg_init(m);
}

void dns_msg_reset(struct dns_msg *m)
{
	m->id = m->flags = 0;
	m->has_q = false;
	m->qname.len = 0;
	m->qtype = m->qclass = 0;
	memset(&m->edns, 0, sizeof(m->edns));
	m->nrr = 0;
	m->buf_len = 0;
}

/*
 * Grow the buffer to hold `extra` more bytes. RR pointers are rebased onto
 * the new allocation while the old one is still valid.
 */
static int buf_reserve(struct dns_msg *m, size_t extra)
{
	size_t need = m->buf_len + extra, cap;
	uint8_t *nb, *ob = m->buf;
	uint16_t i;

	if (need <= m->buf_cap && ob)
		return 0;
	cap = m->buf_cap ? m->buf_cap : 256;
	while (cap < need)
		cap *= 2;
	nb = malloc(cap);
	if (!nb)
		return -ENOMEM;
	if (m->buf_len)
		memcpy(nb, ob, m->buf_len);
	for (i = 0; i < m->nrr; i++) {
		m->rr[i].owner = nb + (m->rr[i].owner - ob);
		m->rr[i].rdata = nb + (m->rr[i].rdata - ob);
	}
	free(ob);
	m->buf = nb;
	m->buf_cap = cap;
	return 0;
}

static int rr_reserve(struct dns_msg *m)
{
	struct dns_rr *n;
	uint16_t cap;

	if (m->nrr >= DNS_MAX_RRS)
		return -E2BIG;
	if (m->nrr < m->rr_cap)
		return 0;
	cap = m->rr_cap ? m->rr_cap * 2 : 8;
	if (cap > DNS_MAX_RRS)
		cap = DNS_MAX_RRS;
	n = realloc(m->rr, cap * sizeof(*n));
	if (!n)
		return -ENOMEM;
	m->rr = n;
	m->rr_cap = cap;
	return 0;
}

static int push_rr(struct dns_msg *m, uint8_t sec,
		   const uint8_t *owner, uint8_t olen,
		   uint16_t type, uint16_t cls, uint32_t ttl,
		   const uint8_t *rdata, uint16_t rdlen)
{
	struct dns_rr *rr;
	uint8_t *p;
	int r;

	r = rr_reserve(m);
	if (r)
		return r;
	r = buf_reserve(m, (size_t)olen + rdlen);
	if (r)
		return r;
	p = m->buf + m->buf_len;
	memcpy(p, owner, olen);
	if (rdlen)
		memcpy(p + olen, rdata, rdlen);
	m->buf_len += (size_t)olen + rdlen;
	rr = &m->rr[m->nrr++];
	rr->owner = p;
	rr->owner_len = olen;
	rr->section = sec;
	rr->type = type;
	rr->cls = cls;
	rr->ttl = ttl;
	rr->rdlen = rdlen;
	rr->rdata = p + olen;
	return 0;
}

int dns_msg_add_rr(struct dns_msg *m, enum dns_section sec,
		   const uint8_t *owner, uint8_t owner_len,
		   uint16_t type, uint16_t cls, uint32_t ttl,
		   const uint8_t *rdata, uint16_t rdlen)
{
	if ((unsigned)sec > DNS_S_AR || type == DNS_T_OPT)
		return -EINVAL;
	if (m->nrr && sec < m->rr[m->nrr - 1].section)
		return -EINVAL;
	if (!owner || dns_name_check(owner, owner_len) != owner_len)
		return -EINVAL;
	if (rdlen && !rdata)
		return -EINVAL;
	if (!rdata_ok(type, rdata, rdlen))
		return -EINVAL;
	return push_rr(m, sec, owner, owner_len, type, cls, ttl, rdata, rdlen);
}

int dns_msg_set_question(struct dns_msg *m, const uint8_t *qname, uint8_t qlen,
			 uint16_t qtype, uint16_t qclass)
{
	if (dns_name_check(qname, qlen) != qlen)
		return -EINVAL;
	memcpy(m->qname.data, qname, qlen);
	m->qname.len = qlen;
	m->qtype = qtype;
	m->qclass = qclass;
	m->has_q = true;
	return 0;
}

int dns_msg_copy(struct dns_msg *dst, const struct dns_msg *src)
{
	struct dns_rr *rr = NULL;
	uint8_t *buf, *p;
	size_t total = 0;
	uint16_t i;

	if (dst == src)
		return 0;
	for (i = 0; i < src->nrr; i++)
		total += (size_t)src->rr[i].owner_len + src->rr[i].rdlen;
	if (!total) {
		dns_msg_free(dst);
		*dst = *src;
		dst->rr = NULL;
		dst->rr_cap = dst->nrr = 0;
		dst->buf = NULL;
		dst->buf_len = dst->buf_cap = 0;
		return 0;
	}
	buf = malloc(total);
	if (!buf)
		return -ENOMEM;
	rr = malloc(src->nrr * sizeof(*rr));
	if (!rr) {
		free(buf);
		return -ENOMEM;
	}
	p = buf;
	for (i = 0; i < src->nrr; i++) {
		const struct dns_rr *s = &src->rr[i];

		rr[i] = *s;
		memcpy(p, s->owner, s->owner_len);
		rr[i].owner = p;
		p += s->owner_len;
		if (s->rdlen)
			memcpy(p, s->rdata, s->rdlen);
		rr[i].rdata = p;
		p += s->rdlen;
	}
	dns_msg_free(dst);
	*dst = *src;
	dst->rr = rr;
	dst->rr_cap = src->nrr;
	dst->buf = buf;
	dst->buf_len = total;
	dst->buf_cap = total;
	return 0;
}

uint16_t dns_msg_count(const struct dns_msg *m, enum dns_section sec)
{
	uint16_t i, n = 0;

	for (i = 0; i < m->nrr; i++)
		if (m->rr[i].section == sec)
			n++;
	return n;
}

void dns_msg_set_rcode(struct dns_msg *m, int rcode)
{
	m->flags = (m->flags & ~DNS_F_RCODE) | (rcode & DNS_F_RCODE);
	m->edns.ext_rcode = (rcode >> 4) & 0xff;
}

size_t dns_msg_footprint(const struct dns_msg *m)
{
	return m->buf_cap + (size_t)m->rr_cap * sizeof(struct dns_rr);
}

/* ---- parsing ---- */

struct pctx {
	const uint8_t *p;
	size_t len;
	size_t off;
};

/*
 * Read a possibly compressed name at *off. In-place bytes must end before
 * `lim`; running past it is E_TRUNC when lim is the message end, otherwise
 * malformed. Pointers must go strictly backwards (and not into the header).
 */
static int read_name(const struct pctx *c, size_t *off, size_t lim,
		     struct dns_name *n)
{
	size_t pos = *off, end = 0;
	int jumps = 0, outlen = 0;
	int trunc = lim == c->len ? -E_TRUNC : -EBADMSG;

	for (;;) {
		size_t bound = end ? c->len : lim;
		uint8_t l;

		if (pos >= bound)
			return end ? -EBADMSG : trunc;
		l = c->p[pos];
		if ((l & 0xc0) == 0xc0) {
			size_t t;

			if (pos + 1 >= bound)
				return end ? -EBADMSG : trunc;
			t = (size_t)(l & 0x3f) << 8 | c->p[pos + 1];
			if (t >= pos || t < DNS_HDR_LEN || ++jumps > DNS_MAX_PTR_JUMPS)
				return -EBADMSG;
			if (!end)
				end = pos + 2;
			pos = t;
			continue;
		}
		if (l & 0xc0)
			return -EBADMSG;
		if (outlen + l + 1 > DNS_MAX_NAME)
			return -EBADMSG;
		if (pos + 1 + l > bound)
			return end ? -EBADMSG : trunc;
		memcpy(n->data + outlen, c->p + pos, (size_t)l + 1);
		outlen += l + 1;
		pos += (size_t)l + 1;
		if (!l)
			break;
	}
	n->len = (uint8_t)outlen;
	*off = end ? end : pos;
	return 0;
}

static int parse_header(struct dns_msg *m, struct pctx *c, uint16_t cnt[4])
{
	int i;

	if (c->len < DNS_HDR_LEN)
		return -EBADMSG;
	m->id = get16(c->p);
	m->flags = get16(c->p + 2);
	for (i = 0; i < 4; i++)
		cnt[i] = get16(c->p + 4 + 2 * i);
	c->off = DNS_HDR_LEN;
	if (cnt[0] > 1)
		return -EBADMSG;
	return 0;
}

static int parse_question(struct dns_msg *m, struct pctx *c, uint16_t qd)
{
	int r;

	if (!qd)
		return 0;
	r = read_name(c, &c->off, c->len, &m->qname);
	if (r)
		return -EBADMSG;
	if (c->len - c->off < 4)
		return -EBADMSG;
	m->qtype = get16(c->p + c->off);
	m->qclass = get16(c->p + c->off + 2);
	c->off += 4;
	m->has_q = true;
	return 0;
}

/* Expand compressible rdata into out (>= 2 + 2*255 + 20 bytes). */
static int expand_rdata(const struct pctx *c, const struct rd_layout *lo,
			size_t start, size_t end, uint8_t *out, uint16_t *outlen)
{
	size_t off = start, o = 0;
	struct dns_name n;
	int i, r;

	if (end - start < lo->pre)
		return -EBADMSG;
	memcpy(out, c->p + off, lo->pre);
	off += lo->pre;
	o += lo->pre;
	for (i = 0; i < lo->names; i++) {
		r = read_name(c, &off, end, &n);
		if (r)
			return -EBADMSG;
		memcpy(out + o, n.data, n.len);
		o += n.len;
	}
	if (end - off != lo->post)
		return -EBADMSG;
	memcpy(out + o, c->p + off, lo->post);
	*outlen = (uint16_t)(o + lo->post);
	return 0;
}

static int parse_opt(struct dns_msg *m, uint8_t sec, const struct dns_name *owner,
		     uint16_t cls, uint32_t ttl, const uint8_t *rd, uint16_t rdlen)
{
	size_t off = 0;

	if (sec != DNS_S_AR || m->edns.present || owner->len != 1)
		return -EBADMSG;
	while (off < rdlen) {
		if (rdlen - off < 4)
			return -EBADMSG;
		off += 4 + (size_t)get16(rd + off + 2);
		if (off > rdlen)
			return -EBADMSG;
	}
	m->edns.present = true;
	m->edns.udp_size = cls;
	m->edns.ext_rcode = ttl >> 24;
	m->edns.version = (ttl >> 16) & 0xff;
	m->edns.do_bit = ttl & 0x8000;
	return 0;
}

static int parse_rr(struct dns_msg *m, struct pctx *c, uint8_t sec)
{
	uint8_t tmp[2 + 2 * DNS_MAX_NAME + 20];
	const struct rd_layout *lo;
	const uint8_t *rd;
	struct dns_name owner;
	uint16_t type, cls, rdlen;
	uint32_t ttl;
	size_t off = c->off;
	int r;

	r = read_name(c, &off, c->len, &owner);
	if (r)
		return r;
	if (c->len - off < DNS_RR_FIXED)
		return -E_TRUNC;
	type = get16(c->p + off);
	cls = get16(c->p + off + 2);
	ttl = get32(c->p + off + 4);
	/* RFC 2181 sec. 8: a TTL with the MSB set is treated as zero (not OPT) */
	if (ttl & 0x80000000u && type != DNS_T_OPT)
		ttl = 0;
	rdlen = get16(c->p + off + 8);
	off += DNS_RR_FIXED;
	if (c->len - off < rdlen)
		return -E_TRUNC;
	rd = c->p + off;
	c->off = off + rdlen;

	if (type == DNS_T_OPT)
		return parse_opt(m, sec, &owner, cls, ttl, rd, rdlen);
	lo = rd_layout(type);
	if (lo) {
		r = expand_rdata(c, lo, off, off + rdlen, tmp, &rdlen);
		if (r)
			return r;
		rd = tmp;
	}
	if (single_name_type(type) && dns_name_check(rd, rdlen) != rdlen)
		return -EBADMSG;
	return push_rr(m, sec, owner.data, owner.len, type, cls, ttl, rd, rdlen);
}

static int parse_common(struct dns_msg *m, const uint8_t *buf, size_t len,
			bool full)
{
	struct pctx c = { .p = buf, .len = len };
	uint16_t cnt[4];
	uint8_t sec;
	unsigned i;
	int r;

	dns_msg_reset(m);
	r = parse_header(m, &c, cnt);
	if (!r)
		r = parse_question(m, &c, cnt[0]);
	for (sec = DNS_S_AN; !r && full && sec <= DNS_S_AR; sec++) {
		for (i = 0; !r && i < cnt[sec + 1]; i++)
			r = parse_rr(m, &c, sec);
	}
	if (r == -E_TRUNC && (m->flags & DNS_F_TC))
		return 0;
	if (r == -E_TRUNC)
		r = -EBADMSG;
	if (r)
		dns_msg_reset(m);
	return r;
}

int dns_parse(struct dns_msg *m, const uint8_t *buf, size_t len)
{
	return parse_common(m, buf, len, true);
}

int dns_parse_query(struct dns_msg *m, const uint8_t *buf, size_t len)
{
	return parse_common(m, buf, len, false);
}

/* ---- building ---- */

#define CTAB_MAX	256
#define CTAB_BUCKETS	256
#define CTAB_OFF_MAX	0x3fff
#define CTAB_NONE	0xffff

/*
 * Compression table: remembered name suffixes already written to the
 * output, hashed into buckets so lookups stay O(1) for hostile inputs.
 */
struct ctab_ent {
	const uint8_t *name;		/* uncompressed suffix in the source */
	uint32_t hash;
	uint16_t off, next;
	uint8_t len;
};

struct bctx {
	uint8_t *out;
	size_t cap, len;
	int nent;
	uint16_t head[CTAB_BUCKETS];
	struct ctab_ent ent[CTAB_MAX];
};

static void ctab_rehead(struct bctx *b)
{
	int i;

	memset(b->head, 0xff, sizeof(b->head));
	for (i = 0; i < b->nent; i++) {
		struct ctab_ent *e = &b->ent[i];

		e->next = b->head[e->hash % CTAB_BUCKETS];
		b->head[e->hash % CTAB_BUCKETS] = (uint16_t)i;
	}
}

/* Drop entries added after a rollback point. */
static void ctab_truncate(struct bctx *b, int nent)
{
	if (b->nent != nent) {
		b->nent = nent;
		ctab_rehead(b);
	}
}

static int ctab_find(const struct bctx *b, const uint8_t *s, uint8_t slen,
		     uint32_t h)
{
	uint16_t i;

	for (i = b->head[h % CTAB_BUCKETS]; i != CTAB_NONE; i = b->ent[i].next) {
		const struct ctab_ent *e = &b->ent[i];

		if (e->hash == h && e->len == slen && !memcmp(e->name, s, slen))
			return e->off;
	}
	return -1;
}

static void ctab_add(struct bctx *b, const uint8_t *s, uint8_t slen, uint32_t h)
{
	struct ctab_ent *e;

	if (b->len >= CTAB_OFF_MAX || b->nent >= CTAB_MAX)
		return;
	e = &b->ent[b->nent];
	e->name = s;
	e->len = slen;
	e->hash = h;
	e->off = (uint16_t)b->len;
	e->next = b->head[h % CTAB_BUCKETS];
	b->head[h % CTAB_BUCKETS] = (uint16_t)b->nent++;
}

static int put_bytes(struct bctx *b, const void *p, size_t n)
{
	if (b->cap - b->len < n)
		return -ENOSPC;
	memcpy(b->out + b->len, p, n);
	b->len += n;
	return 0;
}

static int put_u16(struct bctx *b, uint16_t v)
{
	uint8_t t[2];

	put16(t, v);
	return put_bytes(b, t, 2);
}

/*
 * Write an uncompressed name with compression. Suffix hashes are computed
 * right to left so that each suffix costs O(its first label).
 */
static int put_name(struct bctx *b, const uint8_t *name, uint8_t len)
{
	uint8_t offs[DNS_MAX_NAME / 2 + 1];
	uint32_t hash[DNS_MAX_NAME / 2 + 1], h = 2166136261u;
	int nl = 0, k, off;
	size_t i = 0, j;

	if (dns_name_check(name, len) != len)
		return -EINVAL;
	while (name[i]) {
		offs[nl++] = (uint8_t)i;
		i += (size_t)name[i] + 1;
	}
	for (k = nl - 1; k >= 0; k--) {
		for (j = offs[k]; j <= offs[k] + (size_t)name[offs[k]]; j++)
			h = (h ^ name[j]) * 16777619u;
		hash[k] = h;
	}
	for (k = 0; k < nl; k++) {
		uint8_t sl = len - offs[k];

		off = ctab_find(b, name + offs[k], sl, hash[k]);
		if (off >= 0)
			return put_u16(b, 0xc000 | off);
		ctab_add(b, name + offs[k], sl, hash[k]);
		if (put_bytes(b, name + offs[k], (size_t)name[offs[k]] + 1))
			return -ENOSPC;
	}
	return put_bytes(b, "", 1);
}

static int put_rdata(struct bctx *b, const struct dns_rr *rr)
{
	const struct rd_layout *lo = rd_layout(rr->type);
	const uint8_t *rd = rr->rdata;
	size_t off;
	int i, r;

	if (!lo || !rd_valid(lo, rd, rr->rdlen))
		return put_bytes(b, rd, rr->rdlen);
	r = put_bytes(b, rd, lo->pre);
	off = lo->pre;
	for (i = 0; !r && i < lo->names; i++) {
		int n = dns_name_check(rd + off, rr->rdlen - off);

		r = put_name(b, rd + off, (uint8_t)n);
		off += n;
	}
	if (!r)
		r = put_bytes(b, rd + off, lo->post);
	return r;
}

static int put_rr(struct bctx *b, const struct dns_rr *rr)
{
	size_t save = b->len, rdpos;
	int nent = b->nent, r;
	uint8_t fix[DNS_RR_FIXED];

	r = put_name(b, rr->owner, rr->owner_len);
	if (!r) {
		put16(fix, rr->type);
		put16(fix + 2, rr->cls);
		put32(fix + 4, rr->ttl);
		put16(fix + 8, 0);
		r = put_bytes(b, fix, sizeof(fix));
	}
	rdpos = b->len;
	if (!r)
		r = put_rdata(b, rr);
	if (!r && b->len - rdpos > 0xffff)
		r = -EINVAL;
	if (r) {
		b->len = save;
		ctab_truncate(b, nent);
		return r;
	}
	put16(b->out + rdpos - 2, (uint16_t)(b->len - rdpos));
	return 0;
}

static void put_opt(struct bctx *b, const struct dns_edns *e)
{
	uint8_t *p = b->out + b->len;

	p[0] = 0;
	put16(p + 1, DNS_T_OPT);
	put16(p + 3, e->udp_size);
	put32(p + 5, (uint32_t)e->ext_rcode << 24 | (uint32_t)e->version << 16 |
		     (e->do_bit ? 0x8000u : 0));
	put16(p + 9, 0);
	b->len += DNS_OPT_LEN;
}

int dns_build(const struct dns_msg *m, uint8_t *out, size_t maxlen)
{
	struct bctx *b;
	uint16_t cnt[3] = { 0 }, flags = m->flags;
	size_t qend, optlen = m->edns.present ? DNS_OPT_LEN : 0;
	int nent, r = 0;
	uint16_t i;

	if (maxlen > DNS_MAX_MSG)
		maxlen = DNS_MAX_MSG;
	if (maxlen < DNS_HDR_LEN + optlen)
		return -ENOSPC;
	b = malloc(sizeof(*b));
	if (!b)
		return -ENOMEM;
	b->out = out;
	b->cap = maxlen - optlen;
	b->len = DNS_HDR_LEN;
	b->nent = 0;
	ctab_rehead(b);
	if (m->has_q) {
		r = put_name(b, m->qname.data, m->qname.len);
		if (!r)
			r = put_u16(b, m->qtype);
		if (!r)
			r = put_u16(b, m->qclass);
		if (r)
			goto out;
	}
	qend = b->len;
	nent = b->nent;
	for (i = 0; i < m->nrr; i++) {
		const struct dns_rr *rr = &m->rr[i];

		if (rr->section > DNS_S_AR) {
			r = -EINVAL;
			goto out;
		}
		r = put_rr(b, rr);
		if (r == -ENOSPC && rr->section == DNS_S_AR) {
			r = 0;
			break;
		}
		if (r == -ENOSPC) {
			flags |= DNS_F_TC;
			b->len = qend;
			ctab_truncate(b, nent);
			memset(cnt, 0, sizeof(cnt));
			r = 0;
			break;
		}
		if (r)
			goto out;
		cnt[rr->section]++;
	}
	put16(out, m->id);
	put16(out + 2, flags);
	put16(out + 4, m->has_q);
	put16(out + 6, cnt[0]);
	put16(out + 8, cnt[1]);
	put16(out + 10, cnt[2] + (m->edns.present ? 1 : 0));
	if (m->edns.present)
		put_opt(b, &m->edns);
	r = (int)b->len;
out:
	free(b);
	return r;
}

/* ---- accessors ---- */

int dns_rr_target(const struct dns_rr *rr, struct dns_name *out)
{
	if (!single_name_type(rr->type))
		return -EINVAL;
	if (dns_name_check(rr->rdata, rr->rdlen) != rr->rdlen)
		return -EBADMSG;
	memcpy(out->data, rr->rdata, rr->rdlen);
	out->len = (uint8_t)rr->rdlen;
	return 0;
}

int dns_soa_minimum(const struct dns_rr *rr, uint32_t *minimum)
{
	if (rr->type != DNS_T_SOA)
		return -EINVAL;
	if (!rd_valid(rd_layout(DNS_T_SOA), rr->rdata, rr->rdlen))
		return -EBADMSG;
	*minimum = get32(rr->rdata + rr->rdlen - 4);
	return 0;
}

const char *dns_type_str(uint16_t type, char buf[16])
{
	static const struct { uint16_t t; const char *s; } tab[] = {
		{ DNS_T_A, "A" }, { DNS_T_NS, "NS" }, { DNS_T_CNAME, "CNAME" },
		{ DNS_T_SOA, "SOA" }, { DNS_T_PTR, "PTR" }, { DNS_T_MX, "MX" },
		{ DNS_T_TXT, "TXT" }, { DNS_T_AAAA, "AAAA" }, { DNS_T_SRV, "SRV" },
		{ DNS_T_DNAME, "DNAME" }, { DNS_T_OPT, "OPT" }, { DNS_T_DS, "DS" },
		{ DNS_T_RRSIG, "RRSIG" }, { DNS_T_NSEC, "NSEC" },
		{ DNS_T_DNSKEY, "DNSKEY" }, { DNS_T_NSEC3, "NSEC3" },
		{ DNS_T_NSEC3PARAM, "NSEC3PARAM" }, { DNS_T_SVCB, "SVCB" },
		{ DNS_T_HTTPS, "HTTPS" }, { DNS_T_IXFR, "IXFR" },
		{ DNS_T_AXFR, "AXFR" }, { DNS_T_ANY, "ANY" },
	};
	size_t i;

	for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++)
		if (tab[i].t == type)
			return tab[i].s;
	snprintf(buf, 16, "TYPE%u", type);
	return buf;
}
