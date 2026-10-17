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

void dns_msg_init_buf(struct dns_msg *m, uint8_t *buf, uint32_t cap)
{
	dns_msg_init(m);
	m->buf = buf;
	m->buf_cap = cap;
	m->buf_ext = true;
}

void dns_msg_free(struct dns_msg *m)
{
	free(m->rr);
	if (!m->buf_ext)
		free(m->buf);
	dns_msg_init(m);
}

void dns_msg_reset(struct dns_msg *m)
{
	m->id = m->flags = 0;
	m->has_q = false;
	m->qlen = 0;
	m->qoff = 0;
	m->qtype = m->qclass = 0;
	memset(&m->edns, 0, sizeof(m->edns));
	m->nrr = 0;
	m->buf_len = 0;
}

/* what dns_msg_recycle() keeps: a few kilobytes, for a handful of records */
#define KEEP_BUF	2048
#define KEEP_RRS	32

void dns_msg_recycle(struct dns_msg *m)
{
	if (m->buf_ext || m->buf_cap > KEEP_BUF || m->rr_cap > KEEP_RRS)
		dns_msg_free(m);
	else
		dns_msg_reset(m);
}

/*
 * Grow the buffer to hold `extra` more bytes. RR pointers are rebased onto
 * the new allocation while the old one is still valid (the question is
 * kept as an offset, so it needs no rebasing).
 */
static int buf_reserve(struct dns_msg *m, size_t extra)
{
	size_t need = (size_t)m->buf_len + extra, cap;
	uint8_t *nb, *ob = m->buf;
	uint16_t i;

	if (need <= m->buf_cap && ob)
		return 0;
	cap = m->buf_cap ? m->buf_cap : 256;
	while (cap < need)
		cap *= 2;
	if (cap > UINT32_MAX)
		return -ENOMEM;
	nb = malloc(cap);
	if (!nb)
		return -ENOMEM;
	if (m->buf_len)
		memcpy(nb, ob, m->buf_len);
	for (i = 0; i < m->nrr; i++) {
		m->rr[i].owner = nb + (m->rr[i].owner - ob);
		m->rr[i].rdata = nb + (m->rr[i].rdata - ob);
	}
	if (!m->buf_ext)
		free(ob);
	m->buf = nb;
	m->buf_cap = (uint32_t)cap;
	m->buf_ext = false;
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
	m->buf_len += (uint32_t)olen + rdlen;
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

/*
 * Store the question name (a valid wire name) in m's storage: over the
 * current one when it fits there (the same name in another case, typically),
 * else appended. qname may point into m's own storage.
 */
static int put_qname(struct dns_msg *m, const uint8_t *qname, uint8_t qlen)
{
	uint8_t tmp[DNS_MAX_NAME];
	int r;

	if (m->has_q && qlen <= m->qlen) {
		memmove(m->buf + m->qoff, qname, qlen);
	} else {
		memcpy(tmp, qname, qlen);	/* buf_reserve() may move it */
		r = buf_reserve(m, qlen);
		if (r)
			return r;
		m->qoff = m->buf_len;
		memcpy(m->buf + m->buf_len, tmp, qlen);
		m->buf_len += qlen;
	}
	m->qlen = qlen;
	m->has_q = true;
	return 0;
}

int dns_msg_set_question(struct dns_msg *m, const uint8_t *qname, uint8_t qlen,
                         uint16_t qtype, uint16_t qclass)
{
	int r;

	if (dns_name_check(qname, qlen) != qlen)
		return -EINVAL;
	r = put_qname(m, qname, qlen);
	if (r)
		return r;
	m->qtype = qtype;
	m->qclass = qclass;
	return 0;
}

int dns_msg_copy(struct dns_msg *dst, const struct dns_msg *src)
{
	struct dns_rr *rr = NULL;
	uint8_t *buf = NULL, *p;
	size_t total = src->has_q ? src->qlen : 0;
	uint16_t i;

	if (dst == src)
		return 0;
	for (i = 0; i < src->nrr; i++)
		total += (size_t)src->rr[i].owner_len + src->rr[i].rdlen;
	if (total) {
		buf = malloc(total);
		if (!buf)
			return -ENOMEM;
	}
	if (src->nrr) {
		rr = malloc(src->nrr * sizeof(*rr));
		if (!rr) {
			free(buf);
			return -ENOMEM;
		}
	}
	p = buf;
	if (src->has_q) {
		memcpy(p, dns_msg_qname(src), src->qlen);
		p += src->qlen;
	}
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
	dst->qoff = 0;
	dst->rr = rr;
	dst->rr_cap = src->nrr;
	dst->buf = buf;
	dst->buf_len = dst->buf_cap = (uint32_t)total;
	dst->buf_ext = false;
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
	struct dns_name n;
	int r;

	if (!qd)
		return 0;
	r = read_name(c, &c->off, c->len, &n);
	if (r)
		return -EBADMSG;
	if (c->len - c->off < 4)
		return -EBADMSG;
	r = put_qname(m, n.data, n.len);
	if (r)
		return r;
	m->qtype = get16(c->p + c->off);
	m->qclass = get16(c->p + c->off + 2);
	c->off += 4;
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

#define CTAB_OFF_MAX	0x3fff
#define CTAB_NONE	0xffff

/*
 * Compression table (struct dns_builder): remembered name suffixes already
 * written to the output, hashed into buckets so lookups stay O(1) for
 * hostile inputs. Suffixes match case-insensitively (names are equal
 * regardless of case, RFC 4343), so a name compresses against an earlier
 * one in another case and takes that name's case. This makes the
 * compression structure of a message independent of case: replacing the
 * question by the same name in another case (dns_reply_render()) yields
 * exactly what building with that question would have.
 */
static void wb_rehead(struct dns_builder *b)
{
	int i;

	memset(b->head, 0xff, sizeof(b->head));
	for (i = 0; i < b->nent; i++) {
		struct dns_ctab_ent *e = &b->ent[i];

		e->next = b->head[e->hash % DNS_CTAB_BUCKETS];
		b->head[e->hash % DNS_CTAB_BUCKETS] = (uint16_t)i;
	}
}

/* Roll the output and the table back to a record boundary. */
static void wb_rollback(struct dns_builder *b, size_t len, int nent)
{
	b->len = len;
	if (b->nent != nent) {
		b->nent = nent;
		wb_rehead(b);
	}
}

static int wb_find(const struct dns_builder *b, const uint8_t *s, uint8_t slen, uint32_t h)
{
	uint16_t i;

	for (i = b->head[h % DNS_CTAB_BUCKETS]; i != CTAB_NONE; i = b->ent[i].next) {
		const struct dns_ctab_ent *e = &b->ent[i];

		if (e->hash == h && dns_name_eq(e->name, e->len, s, slen))
			return e->off;
	}
	return -1;
}

static void wb_remember(struct dns_builder *b, const uint8_t *s, uint8_t slen, uint32_t h)
{
	struct dns_ctab_ent *e;

	if (b->len >= CTAB_OFF_MAX || b->nent >= DNS_CTAB_MAX)
		return;
	e = &b->ent[b->nent];
	e->name = s;
	e->len = slen;
	e->hash = h;
	e->off = (uint16_t)b->len;
	e->next = b->head[h % DNS_CTAB_BUCKETS];
	b->head[h % DNS_CTAB_BUCKETS] = (uint16_t)b->nent++;
}

static int wb_bytes(struct dns_builder *b, const void *p, size_t n)
{
	if (b->cap - b->len < n)
		return -ENOSPC;
	memcpy(b->out + b->len, p, n);
	b->len += n;
	return 0;
}

/*
 * Write a valid uncompressed name, compressed; returns its length or
 * -ENOSPC. Suffix hashes are computed right to left so that each suffix
 * costs O(its first label).
 */
static int wb_name(struct dns_builder *b, const uint8_t *name)
{
	uint8_t offs[DNS_MAX_NAME / 2 + 1];
	uint32_t hash[DNS_MAX_NAME / 2 + 1], h = 2166136261u;
	int nl = 0, k, off;
	size_t i = 0, j;
	uint8_t len;

	while (name[i]) {
		offs[nl++] = (uint8_t)i;
		i += (size_t)name[i] + 1;
	}
	len = (uint8_t)(i + 1);
	for (k = nl - 1; k >= 0; k--) {
		for (j = offs[k]; j <= offs[k] + (size_t)name[offs[k]]; j++)
			h = (h ^ lc(name[j])) * 16777619u;
		hash[k] = h;
	}
	for (k = 0; k < nl; k++) {
		uint8_t sl = len - offs[k], ptr[2];

		off = wb_find(b, name + offs[k], sl, hash[k]);
		if (off >= 0) {
			put16(ptr, 0xc000 | off);
			return wb_bytes(b, ptr, 2) ? -ENOSPC : len;
		}
		wb_remember(b, name + offs[k], sl, hash[k]);
		if (wb_bytes(b, name + offs[k], (size_t)name[offs[k]] + 1))
			return -ENOSPC;
	}
	return wb_bytes(b, "", 1) ? -ENOSPC : len;
}

static int wb_rdata(struct dns_builder *b, uint16_t type, const uint8_t *rd, uint16_t rdlen)
{
	const struct rd_layout *lo = rd_layout(type);
	size_t off;
	int i, n;

	if (!lo)
		return wb_bytes(b, rd, rdlen);
	if (wb_bytes(b, rd, lo->pre))
		return -ENOSPC;
	off = lo->pre;
	for (i = 0; i < lo->names; i++) {
		n = wb_name(b, rd + off);
		if (n < 0)
			return n;
		off += (size_t)n;
	}
	return wb_bytes(b, rd + off, rdlen - off);
}

int dns_build_begin(struct dns_builder *b, uint8_t *out, size_t cap, uint16_t id,
                    uint16_t flags, const uint8_t *qname, uint8_t qlen, uint16_t qtype,
                    uint16_t qclass)
{
	uint8_t q[4];

	b->out = out;
	b->cap = cap > DNS_MAX_MSG ? DNS_MAX_MSG : cap;
	b->len = DNS_HDR_LEN;
	b->id = id;
	b->flags = flags;
	b->qd = qname != NULL;
	b->nrr = 0;
	memset(b->cnt, 0, sizeof(b->cnt));
	b->sec = DNS_S_AN;
	b->cut = false;
	b->nent = 0;
	memset(b->head, 0xff, sizeof(b->head));
	if (b->cap < DNS_HDR_LEN)
		return -ENOSPC;
	if (qname) {
		put16(q, qtype);
		put16(q + 2, qclass);
		if (wb_name(b, qname) < 0 || wb_bytes(b, q, 4))
			return -ENOSPC;
	}
	b->qend = b->len;
	b->qent = b->nent;
	return 0;
}

int dns_build_add(struct dns_builder *b, enum dns_section sec,
                  const uint8_t *owner, uint8_t owner_len,
                  uint16_t type, uint16_t cls, uint32_t ttl,
                  const uint8_t *rdata, uint16_t rdlen)
{
	size_t save = b->len, rdpos;
	int nent = b->nent;
	uint8_t fix[DNS_RR_FIXED];

	if ((unsigned)sec > DNS_S_AR || sec < b->sec)
		return -EINVAL;
	if (b->nrr == DNS_MAX_RRS)
		return -E2BIG;
	b->nrr++;
	b->sec = (uint8_t)sec;
	if (b->cut)
		return 0;
	put16(fix, type);
	put16(fix + 2, cls);
	put32(fix + 4, ttl);
	put16(fix + 8, 0);
	if (wb_name(b, owner) < 0 || wb_bytes(b, fix, DNS_RR_FIXED))
		goto cut;
	rdpos = b->len;
	if (wb_rdata(b, type, rdata, rdlen))
		goto cut;
	put16(b->out + rdpos - 2, (uint16_t)(b->len - rdpos));
	b->cnt[sec]++;
	return 0;
cut:
	b->cut = true;
	if (sec == DNS_S_AR) {
		wb_rollback(b, save, nent);
	} else {
		wb_rollback(b, b->qend, b->qent);
		b->flags |= DNS_F_TC;
		memset(b->cnt, 0, sizeof(b->cnt));
	}
	return 0;
}

int dns_build_end(struct dns_builder *b)
{
	put16(b->out, b->id);
	put16(b->out + 2, b->flags);
	put16(b->out + 4, b->qd);
	put16(b->out + 6, b->cnt[0]);
	put16(b->out + 8, b->cnt[1]);
	put16(b->out + 10, b->cnt[2]);
	return (int)b->len;
}

static void opt_write(uint8_t *p, const struct dns_edns *e)
{
	p[0] = 0;
	put16(p + 1, DNS_T_OPT);
	put16(p + 3, e->udp_size);
	put32(p + 5, (uint32_t)e->ext_rcode << 24 | (uint32_t)e->version << 16 |
	             (e->do_bit ? 0x8000u : 0));
	put16(p + 9, 0);
}

/*
 * One builder for dns_build() (~6.7 KB: too big for the stack of small
 * targets, wasteful to malloc per message). This is safe because the
 * daemon is single-threaded and dns_build() is not re-entrant by
 * construction: nothing below it calls back into other code.
 */
static struct dns_builder build_ctx;

int dns_build(const struct dns_msg *m, uint8_t *out, size_t maxlen)
{
	struct dns_builder *b = &build_ctx;
	size_t optlen = m->edns.present ? DNS_OPT_LEN : 0;
	uint16_t i;
	int r, n;

	if (maxlen > DNS_MAX_MSG)
		maxlen = DNS_MAX_MSG;
	if (maxlen < DNS_HDR_LEN + optlen)
		return -ENOSPC;
	r = dns_build_begin(b, out, maxlen - optlen, m->id, m->flags, dns_msg_qname(m), m->qlen,
	                    m->qtype, m->qclass);
	for (i = 0; !r && i < m->nrr; i++)
		r = dns_build_add_rr(b, m->rr[i].section, &m->rr[i]);
	if (r)
		return r;
	n = dns_build_end(b);
	if (m->edns.present) {
		put16(out + 10, b->cnt[DNS_S_AR] + 1);
		opt_write(out + n, &m->edns);
		n += DNS_OPT_LEN;
	}
	return n;
}

/* ---- rendering a built response ---- */

/* Offset just past the (possibly compressed) name at off, or 0. */
static size_t skip_name(const uint8_t *p, size_t off, size_t len)
{
	while (off < len) {
		uint8_t l = p[off];

		if (!l)
			return off + 1;
		if ((l & 0xc0) == 0xc0)
			return off + 2 <= len ? off + 2 : 0;
		if (l > DNS_MAX_LABEL)
			return 0;
		off += (size_t)l + 1;
	}
	return 0;
}

int dns_reply_render(const uint8_t *msg, size_t len, const struct dns_reply *rp,
                     uint8_t *out, size_t maxlen)
{
	size_t optlen = rp->edns ? DNS_OPT_LEN : 0, cap, qend, end, off, n;
	uint16_t cnt[3], kept[3], flags, i;
	bool tc = false;
	int sec;

	if (maxlen > DNS_MAX_MSG)
		maxlen = DNS_MAX_MSG;
	if (len < DNS_HDR_LEN || len > DNS_MAX_MSG || get16(msg + 4) != 1)
		return -EINVAL;
	qend = DNS_HDR_LEN + (size_t)rp->qlen + 4;
	if (qend > len || dns_name_check(msg + DNS_HDR_LEN, len - DNS_HDR_LEN) != rp->qlen ||
	    !dns_name_eq(msg + DNS_HDR_LEN, rp->qlen, rp->qname, rp->qlen))
		return -EINVAL;
	if (maxlen < qend + optlen)
		return -ENOSPC;
	cap = maxlen - optlen;
	for (sec = 0; sec < 3; sec++)
		kept[sec] = cnt[sec] = get16(msg + 6 + 2 * sec);
	/* everything that fits is copied; the walk below finds where to cut */
	n = len < cap ? len : cap;
	memcpy(out, msg, n);
	end = len;
	if (len > cap || rp->age) {
		off = qend;
		for (sec = 0; sec < 3; sec++) {
			for (i = 0; i < cnt[sec]; i++) {
				size_t o = skip_name(msg, off, len), rend;
				uint32_t ttl;

				if (!o || len - o < DNS_RR_FIXED)
					return -EINVAL;
				rend = o + DNS_RR_FIXED + get16(msg + o + 8);
				if (rend > len)
					return -EINVAL;
				/* as dns_build(): AR is cut at the first record that
				 * does not fit, AN/NS not fitting truncates to TC */
				if (rend > cap) {
					end = off;
					if (sec == DNS_S_AR) {
						kept[DNS_S_AR] = i;
					} else {
						tc = true;
						end = qend;
						memset(kept, 0, sizeof(kept));
					}
					goto cut;
				}
				ttl = get32(msg + o + 4);
				put32(out + o + 4, ttl > rp->age ? ttl - rp->age : 0);
				off = rend;
			}
		}
		if (off != len)
			return -EINVAL;
	}
cut:
	put16(out, rp->id);
	flags = (get16(msg + 2) & ~(DNS_F_RD | DNS_F_CD | DNS_F_OPCODE | DNS_F_AA)) |
	        DNS_F_QR | DNS_F_RA | rp->rdcd | (tc ? DNS_F_TC : 0);
	put16(out + 2, flags);
	put16(out + 6, kept[0]);
	put16(out + 8, kept[1]);
	put16(out + 10, kept[2] + (rp->edns ? 1 : 0));
	memcpy(out + DNS_HDR_LEN, rp->qname, rp->qlen);
	if (rp->edns) {
		struct dns_edns e = { .present = true, .udp_size = rp->edns_udp };

		opt_write(out + end, &e);
		end += DNS_OPT_LEN;
	}
	return (int)end;
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
