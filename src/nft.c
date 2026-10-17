// SPDX-License-Identifier: MIT
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/common.h>
#include <libnftnl/udata.h>
#include <libubox/uloop.h>

#include "log.h"
#include "nft.h"
#include "util/hash.h"

#define NFT_TABLE_MAX	64
/*
 * Elements per NEWSETELEM/DESTROYSETELEM message. All of a message's
 * elements sit in one NFTA_SET_ELEM_LIST_ELEMENTS nest, whose length is
 * 16 bits (at most 65535 bytes). The largest element is 64 bytes (element
 * nest 4, key 4 + 4 + 16 for a v6 address, data nest 4, verdict nest 4,
 * code 8, chain name "mark_%08x" 4 + 16; a restore_marks vmap element is 52
 * with its 4-byte key), so at most 1023 fit; 256 keeps a 4x margin and
 * bounds a message to about 16.5 KB.
 */
#define CHUNK_MAX	256
#define PENDING_SLOTS	(2 * NFT_BATCH_MAX)	/* power of two, load <= 1/2 */
#define SPARE_MAX	8		/* recycled struct ebatch */
#define FAIL_RING	32
#define RECV_TIMEOUT_MS	10000
#define SOCK_BUF	(4 << 20)

/*
 * Persistent state in the table's userdata (NFTA_TABLE_USERDATA, libnftnl
 * udata TLVs), written once when the table is created: the layout version,
 * the fwmask and the fake IP allocation secret. Policy rules carry a tag
 * (NFTA_RULE_USERDATA) identifying the shadow state that wrote them. nft
 * uses the low TLV types itself (comments) and ignores unknown ones.
 */
enum { UD_VERSION = 0x80, UD_FWMASK, UD_SECRET };	/* table */
#define UD_TAG		0x80				/* policy rules */

#define TYPE_MARK	19		/* nft userspace datatypes */
#define TYPE_IPADDR	7
#define TYPE_IP6ADDR	8

enum { S_REAL4, S_MARK4, S_REAL6, S_MARK6, S_NUM };

static const char *const set_names[S_NUM] = {
	"fake2real_v4", "fake2mark_v4", "fake2real_v6", "fake2mark_v6",
};

struct nbuf {
	char *p;
	size_t len, cap;
	uint32_t low;		/* consecutive uses below cap / 4 (nbuf_trim) */
};

/*
 * One transaction under construction: BEGIN, msgs, END. Only the last
 * message before END asks for an ack (see ctl_commit() and nft_flush()).
 */
struct txn {
	struct nbuf b;
	uint32_t seq_first, seq_last, nmsg;
	size_t last_off;	/* offset of the last message added by txn_msg() */
};

struct ebatch {
	struct list_head list;
	uint64_t ticket;
	uint32_t nops;
	uint32_t seq_first, seq_last;
	uint32_t ack_seq;	/* the one message asking for an ack */
	int err;
};

/* encoded elements of the open batch for one (set, phase), see queue_elem() */
struct ebuf {
	struct nbuf b;		/* closed messages, then the open one */
	uint32_t nelem;		/* elements in the open message, 0: none open */
	uint32_t nest_off;	/* NFTA_SET_ELEM_LIST_ELEMENTS in the open message */
};

struct pend_key {
	uint8_t family;
	uint8_t addr[16];
};

struct shadow {
	uint32_t fwmask;
	bool has_pool4, has_pool6;
	struct ip_prefix pool4, pool6;
	uint32_t *marks;		/* sorted, unique */
	uint32_t nmarks;
};

struct nft_ctx {
	char table[NFT_TABLE_MAX];
	struct mnl_socket *ctl, *async;
	uint32_t ctl_portid, async_portid;
	uint32_t seq, set_id;
	struct txn ctl_tx;

	bool have_state;
	bool stale;		/* policy rules may not match sh: rewrite them */
	struct shadow sh;
	uint8_t secret[NFT_SECRET_LEN];	/* stored in a table we create */

	struct uloop_fd ufd;
	struct uloop_timeout submit_tmo, ready_tmo, kick_tmo;
	struct ebatch *open;
	struct ebatch *spare[SPARE_MAX];
	uint32_t nspare;
	struct list_head inflight;
	struct txn etx;				/* element batch being sent */
	struct ebuf ebuf[S_NUM * 2];		/* [set * 2 + add] */
	uint16_t pend_gen;			/* generation of the open batch */
	uint32_t pend_n;
	uint32_t pend_slot[PENDING_SLOTS];	/* gen << 16 | pend_key index + 1 */
	struct pend_key pend_key[NFT_BATCH_MAX];
	struct list_head waiters, ready;
	uint64_t next_ticket;
	void (*fail_fn)(void *priv, uint64_t ticket, int err);
	void *fail_priv;
	struct { uint64_t ticket; int err; } fails[FAIL_RING];
	unsigned fail_pos;
	bool draining;
	int drain_err;
};

static void *oom(void *p)
{
	if (!p) {
		log_err("nft: out of memory");
		abort();
	}
	return p;
}

/* ---- buffers and transactions ---- */

static void nbuf_reserve(struct nbuf *b, size_t n)
{
	size_t cap = b->cap ? b->cap : 1024;

	if (b->len + n <= b->cap)
		return;
	while (cap < b->len + n)
		cap *= 2;
	b->p = oom(realloc(b->p, cap));
	b->cap = cap;
}

static void nbuf_commit(struct nbuf *b, struct nlmsghdr *nlh)
{
	b->len += MNL_ALIGN(nlh->nlmsg_len);
}

static void txn_begin(struct nft_ctx *n, struct txn *t)
{
	t->b.len = 0;
	t->nmsg = 0;
	nbuf_reserve(&t->b, MNL_NLMSG_HDRLEN + 64);
	t->seq_first = n->seq;
	nbuf_commit(&t->b, nftnl_batch_begin(t->b.p, n->seq++));
}

static void txn_end(struct nft_ctx *n, struct txn *t)
{
	nbuf_reserve(&t->b, MNL_NLMSG_HDRLEN + 64);
	t->seq_last = n->seq;
	nbuf_commit(&t->b, nftnl_batch_end(t->b.p + t->b.len, n->seq++));
}

static struct nlmsghdr *txn_msg(struct nft_ctx *n, struct txn *t, int type,
				uint16_t flags, size_t room)
{
	nbuf_reserve(&t->b, room);
	t->nmsg++;
	t->last_off = t->b.len;
	return nftnl_nlmsg_build_hdr(t->b.p + t->b.len, type, NFPROTO_INET, flags,
	                             n->seq++);
}

/* `fwmask` non-zero: a NEWTABLE carrying the persistent state */
static void txn_table(struct nft_ctx *n, struct txn *t, int type, uint16_t flags,
                      uint32_t fwmask)
{
	struct nftnl_table *tb = oom(nftnl_table_alloc());
	struct nlmsghdr *nlh;

	nftnl_table_set_str(tb, NFTNL_TABLE_NAME, n->table);
	if (fwmask) {
		struct nftnl_udata_buf *u = oom(nftnl_udata_buf_alloc(64));

		nftnl_udata_put_u32(u, UD_VERSION, NFT_LAYOUT_VERSION);
		nftnl_udata_put_u32(u, UD_FWMASK, fwmask);
		nftnl_udata_put(u, UD_SECRET, NFT_SECRET_LEN, n->secret);
		nftnl_table_set_data(tb, NFTNL_TABLE_USERDATA, nftnl_udata_buf_data(u),
		                     nftnl_udata_buf_len(u));
		nftnl_udata_buf_free(u);
	}
	nlh = txn_msg(n, t, type, flags, 1024);
	nftnl_table_nlmsg_build_payload(nlh, tb);
	nbuf_commit(&t->b, nlh);
	nftnl_table_free(tb);
}

static struct nftnl_chain *chain_new(struct nft_ctx *n, const char *name)
{
	struct nftnl_chain *c = oom(nftnl_chain_alloc());

	nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, n->table);
	nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, name);
	return c;
}

static void txn_chain(struct nft_ctx *n, struct txn *t, int type,
                      struct nftnl_chain *c)
{
	struct nlmsghdr *nlh;

	nlh = txn_msg(n, t, type, type == NFT_MSG_NEWCHAIN ? NLM_F_CREATE : 0, 1024);
	nftnl_chain_nlmsg_build_payload(nlh, c);
	nbuf_commit(&t->b, nlh);
	nftnl_chain_free(c);
}

static void txn_base_chain(struct nft_ctx *n, struct txn *t, const char *name,
                           const char *type, int hook, int prio)
{
	struct nftnl_chain *c = chain_new(n, name);

	nftnl_chain_set_str(c, NFTNL_CHAIN_TYPE, type);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, hook);
	nftnl_chain_set_s32(c, NFTNL_CHAIN_PRIO, prio);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	txn_chain(n, t, NFT_MSG_NEWCHAIN, c);
}

static void txn_flush_chain(struct nft_ctx *n, struct txn *t, const char *chain)
{
	struct nftnl_rule *r = oom(nftnl_rule_alloc());
	struct nlmsghdr *nlh;

	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, n->table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);
	nlh = txn_msg(n, t, NFT_MSG_DELRULE, 0, 1024);
	nftnl_rule_nlmsg_build_payload(nlh, r);
	nbuf_commit(&t->b, nlh);
	nftnl_rule_free(r);
}

static void txn_set(struct nft_ctx *n, struct txn *t, struct nftnl_set *s)
{
	struct nlmsghdr *nlh;

	nlh = txn_msg(n, t, NFT_MSG_NEWSET, NLM_F_CREATE, 1024);
	nftnl_set_nlmsg_build_payload(nlh, s);
	nbuf_commit(&t->b, nlh);
}

static void txn_elems(struct nft_ctx *n, struct txn *t, int type,
                      struct nftnl_set *s, uint32_t nelem)
{
	struct nlmsghdr *nlh;

	nlh = txn_msg(n, t, type, type == NFT_MSG_NEWSETELEM ? NLM_F_CREATE : 0,
	              1024 + (size_t)nelem * 160);
	nftnl_set_elems_nlmsg_build_payload(nlh, s);
	nbuf_commit(&t->b, nlh);
}

/* ---- rule expressions ---- */

static struct nftnl_rule *rule_new(struct nft_ctx *n, const char *chain)
{
	struct nftnl_rule *r = oom(nftnl_rule_alloc());

	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, n->table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);
	return r;
}

static void txn_rule(struct nft_ctx *n, struct txn *t, struct nftnl_rule *r)
{
	struct nlmsghdr *nlh;

	nlh = txn_msg(n, t, NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND, 4096);
	nftnl_rule_nlmsg_build_payload(nlh, r);
	nbuf_commit(&t->b, nlh);
	nftnl_rule_free(r);
}

/* a policy rule: tagged with the shadow state it was written for */
static void txn_prule(struct nft_ctx *n, struct txn *t, struct nftnl_rule *r, uint64_t tag)
{
	struct nftnl_udata_buf *u = oom(nftnl_udata_buf_alloc(32));

	nftnl_udata_put(u, UD_TAG, sizeof(tag), &tag);
	nftnl_rule_set_data(r, NFTNL_RULE_USERDATA, nftnl_udata_buf_data(u),
	                    nftnl_udata_buf_len(u));
	nftnl_udata_buf_free(u);
	txn_rule(n, t, r);
}

static struct nftnl_expr *expr(struct nftnl_rule *r, const char *name)
{
	struct nftnl_expr *e = oom(nftnl_expr_alloc(name));

	nftnl_rule_add_expr(r, e);
	return e;
}

static void e_meta(struct nftnl_rule *r, int key, bool set)
{
	struct nftnl_expr *e = expr(r, "meta");

	nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, key);
	nftnl_expr_set_u32(e, set ? NFTNL_EXPR_META_SREG : NFTNL_EXPR_META_DREG,
	                   NFT_REG_1);
}

static void e_ct(struct nftnl_rule *r, int key, bool set)
{
	struct nftnl_expr *e = expr(r, "ct");

	nftnl_expr_set_u32(e, NFTNL_EXPR_CT_KEY, key);
	nftnl_expr_set_u32(e, set ? NFTNL_EXPR_CT_SREG : NFTNL_EXPR_CT_DREG,
	                   NFT_REG_1);
}

/* reg1 = (reg1 & mask) ^ xor */
static void e_bitwise(struct nftnl_rule *r, const void *mask, const void *xor,
                      uint32_t len)
{
	struct nftnl_expr *e = expr(r, "bitwise");

	nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
	nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
	nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_OP, NFT_BITWISE_BOOL);
	nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_LEN, len);
	nftnl_expr_set(e, NFTNL_EXPR_BITWISE_MASK, mask, len);
	nftnl_expr_set(e, NFTNL_EXPR_BITWISE_XOR, xor, len);
}

static void e_cmp_eq(struct nftnl_rule *r, const void *data, uint32_t len)
{
	struct nftnl_expr *e = expr(r, "cmp");

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, len);
}

static void e_payload(struct nftnl_rule *r, uint32_t off, uint32_t len)
{
	struct nftnl_expr *e = expr(r, "payload");

	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, off);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
}

static void e_lookup(struct nftnl_rule *r, const char *set, uint32_t id, int dreg)
{
	struct nftnl_expr *e = expr(r, "lookup");

	nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SREG, NFT_REG_1);
	nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_DREG, dreg);
	nftnl_expr_set_str(e, NFTNL_EXPR_LOOKUP_SET, set);
	if (id)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SET_ID, id);
}

/* ---- ruleset pieces ---- */

static void mark_chain_name(char *buf, uint32_t v)
{
	snprintf(buf, 32, "mark_%08x", v);
}

static void txn_mark_rules(struct nft_ctx *n, struct txn *t, const char *chain,
                           uint32_t mask, uint32_t v)
{
	uint32_t keep = ~mask;
	struct nftnl_rule *r;

	r = rule_new(n, chain);
	e_meta(r, NFT_META_MARK, false);
	e_bitwise(r, &keep, &v, 4);
	e_meta(r, NFT_META_MARK, true);
	txn_rule(n, t, r);

	r = rule_new(n, chain);
	e_ct(r, NFT_CT_MARK, false);
	e_bitwise(r, &keep, &v, 4);
	e_ct(r, NFT_CT_MARK, true);
	txn_rule(n, t, r);
}

static void txn_mark_chain(struct nft_ctx *n, struct txn *t, uint32_t mask, uint32_t v)
{
	char name[32];

	mark_chain_name(name, v);
	txn_chain(n, t, NFT_MSG_NEWCHAIN, chain_new(n, name));
	txn_mark_rules(n, t, name, mask, v);
}

/* Lets `nft list` print mark keys correctly; the kernel ignores it. */
static void set_key_host_endian(struct nftnl_set *s)
{
	struct nftnl_udata_buf *u = oom(nftnl_udata_buf_alloc(64));

	nftnl_udata_put_u32(u, NFTNL_UDATA_SET_KEYBYTEORDER, 1 /* host */);
	nftnl_set_set_data(s, NFTNL_SET_USERDATA, nftnl_udata_buf_data(u),
	                   nftnl_udata_buf_len(u));
	nftnl_udata_buf_free(u);
}

/* ct mark & M vmap { V : jump mark_V, ... } via an anonymous constant map */
static void txn_restore_rule(struct nft_ctx *n, struct txn *t, uint32_t mask,
                             const uint32_t *marks, uint32_t nmarks, uint64_t tag)
{
	struct nftnl_set *s = oom(nftnl_set_alloc());
	uint32_t id = ++n->set_id, zero = 0;
	struct nftnl_rule *r;
	char name[32];

	if (!id)
		id = ++n->set_id;
	nftnl_set_set_str(s, NFTNL_SET_TABLE, n->table);
	nftnl_set_set_str(s, NFTNL_SET_NAME, "__map%d");
	nftnl_set_set_u32(s, NFTNL_SET_ID, id);
	nftnl_set_set_u32(s, NFTNL_SET_FLAGS,
	                  NFT_SET_ANONYMOUS | NFT_SET_CONSTANT | NFT_SET_MAP);
	nftnl_set_set_u32(s, NFTNL_SET_KEY_TYPE, TYPE_MARK);
	nftnl_set_set_u32(s, NFTNL_SET_KEY_LEN, 4);
	nftnl_set_set_u32(s, NFTNL_SET_DATA_TYPE, NFT_DATA_VERDICT);
	nftnl_set_set_u32(s, NFTNL_SET_DATA_LEN, 0);
	set_key_host_endian(s);
	txn_set(n, t, s);
	nftnl_set_free(s);

	/* elements in messages of CHUNK_MAX, all before the rule binds the set
	 * (a bound constant set takes no more elements) */
	for (uint32_t i = 0; i < nmarks;) {
		uint32_t end = nmarks - i > CHUNK_MAX ? i + CHUNK_MAX : nmarks;

		s = oom(nftnl_set_alloc());
		nftnl_set_set_str(s, NFTNL_SET_TABLE, n->table);
		nftnl_set_set_str(s, NFTNL_SET_NAME, "__map%d");
		nftnl_set_set_u32(s, NFTNL_SET_ID, id);
		for (; i < end; i++) {
			struct nftnl_set_elem *e = oom(nftnl_set_elem_alloc());

			mark_chain_name(name, marks[i]);
			nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &marks[i], 4);
			nftnl_set_elem_set_u32(e, NFTNL_SET_ELEM_VERDICT, NFT_JUMP);
			nftnl_set_elem_set_str(e, NFTNL_SET_ELEM_CHAIN, name);
			nftnl_set_elem_add(s, e);
		}
		txn_elems(n, t, NFT_MSG_NEWSETELEM, s, CHUNK_MAX);
		nftnl_set_free(s);
	}

	r = rule_new(n, "restore_marks");
	e_ct(r, NFT_CT_MARK, false);
	e_bitwise(r, &mask, &zero, 4);
	e_lookup(r, "__map%d", id, NFT_REG_VERDICT);
	txn_prule(n, t, r, tag);
}

/*
 * meta nfproto P <daddr> PREFIX, as nft encodes it: byte-aligned prefixes
 * load only the prefix bytes, others load the whole address and mask it.
 */
static struct nftnl_rule *pool_rule(struct nft_ctx *n, const char *chain,
                                    const struct ip_prefix *p)
{
	struct nftnl_rule *r = rule_new(n, chain);
	bool v6 = p->family == AF_INET6;
	uint8_t proto = v6 ? NFPROTO_IPV6 : NFPROTO_IPV4;
	uint32_t alen = v6 ? 16 : 4, len = p->plen / 8;
	uint8_t mask[16] = { 0 }, zero[16] = { 0 };

	e_meta(r, NFT_META_NFPROTO, false);
	e_cmp_eq(r, &proto, 1);
	if (p->plen % 8) {
		memset(mask, 0xff, len);
		mask[len] = (uint8_t)(0xff << (8 - p->plen % 8));
		e_payload(r, v6 ? 24 : 16, alen);
		e_bitwise(r, mask, zero, alen);
		e_cmp_eq(r, p->addr, alen);
	} else if (len) {
		e_payload(r, v6 ? 24 : 16, len);
		e_cmp_eq(r, p->addr, len);
	}
	return r;
}

static void txn_dstnat_rules(struct nft_ctx *n, struct txn *t, const char *chain,
                             const struct ip_prefix *p, uint64_t tag)
{
	bool v6 = p->family == AF_INET6;
	uint32_t off = v6 ? 24 : 16, alen = v6 ? 16 : 4;
	struct nftnl_rule *r;
	struct nftnl_expr *e;

	r = pool_rule(n, chain, p);
	e_payload(r, off, alen);
	e_lookup(r, set_names[v6 ? S_MARK6 : S_MARK4], 0, NFT_REG_VERDICT);
	txn_prule(n, t, r, tag);

	r = pool_rule(n, chain, p);
	e_payload(r, off, alen);
	e_lookup(r, set_names[v6 ? S_REAL6 : S_REAL4], 0, NFT_REG_1);
	e = expr(r, "nat");
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_TYPE, NFT_NAT_DNAT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_FAMILY, v6 ? NFPROTO_IPV6 : NFPROTO_IPV4);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
	txn_prule(n, t, r, tag);
}

static void txn_reject_rule(struct nft_ctx *n, struct txn *t, const char *chain,
                            const struct ip_prefix *p, uint64_t tag)
{
	struct nftnl_rule *r = pool_rule(n, chain, p);
	struct nftnl_expr *e = expr(r, "reject");

	/* icmp(v6) port-unreachable, as nft's plain `reject` in inet */
	nftnl_expr_set_u32(e, NFTNL_EXPR_REJECT_TYPE, NFT_REJECT_ICMP_UNREACH);
	nftnl_expr_set_u8(e, NFTNL_EXPR_REJECT_CODE, p->family == AF_INET6 ? 4 : 3);
	txn_prule(n, t, r, tag);
}

static void txn_jump_rule(struct nft_ctx *n, struct txn *t, const char *chain,
                          const char *target)
{
	struct nftnl_rule *r = rule_new(n, chain);
	struct nftnl_expr *e = expr(r, "immediate");

	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, NFT_JUMP);
	nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, target);
	txn_rule(n, t, r);
}

static const char *const dstnat_chains[] = { "prerouting_dstnat", "output_dstnat" };
static const char *const reject_chains[] = { "forward_reject", "output_reject" };

static uint64_t shadow_tag(const struct shadow *s);

/* Rules of restore_marks, *_dstnat and *_reject (chains assumed empty). */
static void txn_policy_rules(struct nft_ctx *n, struct txn *t, const struct shadow *s)
{
	uint64_t tag = shadow_tag(s);

	if (s->nmarks)
		txn_restore_rule(n, t, s->fwmask, s->marks, s->nmarks, tag);
	for (int i = 0; i < 2; i++) {
		if (s->has_pool4)
			txn_dstnat_rules(n, t, dstnat_chains[i], &s->pool4, tag);
		if (s->has_pool6)
			txn_dstnat_rules(n, t, dstnat_chains[i], &s->pool6, tag);
		if (s->has_pool4)
			txn_reject_rule(n, t, reject_chains[i], &s->pool4, tag);
		if (s->has_pool6)
			txn_reject_rule(n, t, reject_chains[i], &s->pool6, tag);
	}
}

/* rules per policy chain for `s`: restore_marks, then dstnat_chains[i] and
 * reject_chains[i] alike for both i */
static void policy_rule_counts(const struct shadow *s, uint32_t *restore, uint32_t *dstnat,
                               uint32_t *reject)
{
	*restore = s->nmarks ? 1 : 0;
	*reject = (uint32_t)s->has_pool4 + s->has_pool6;
	*dstnat = 2 * *reject;
}

static void txn_maps(struct nft_ctx *n, struct txn *t)
{
	for (int i = 0; i < S_NUM; i++) {
		struct nftnl_set *s = oom(nftnl_set_alloc());
		bool v6 = i >= S_REAL6, mark = i & 1;
		uint32_t alen = v6 ? 16 : 4, atype = v6 ? TYPE_IP6ADDR : TYPE_IPADDR;

		nftnl_set_set_str(s, NFTNL_SET_TABLE, n->table);
		nftnl_set_set_str(s, NFTNL_SET_NAME, set_names[i]);
		nftnl_set_set_u32(s, NFTNL_SET_FLAGS, NFT_SET_MAP);
		nftnl_set_set_u32(s, NFTNL_SET_KEY_TYPE, atype);
		nftnl_set_set_u32(s, NFTNL_SET_KEY_LEN, alen);
		nftnl_set_set_u32(s, NFTNL_SET_DATA_TYPE, mark ? NFT_DATA_VERDICT : atype);
		nftnl_set_set_u32(s, NFTNL_SET_DATA_LEN, mark ? 0 : alen);
		nftnl_set_set_u32(s, NFTNL_SET_ID, ++n->set_id);
		txn_set(n, t, s);
		nftnl_set_free(s);
	}
}

/* ---- sync netlink I/O ---- */

static bool seq_in(uint32_t seq, uint32_t first, uint32_t last)
{
	return seq - first <= last - first;
}

static int sock_setup(struct mnl_socket *nl)
{
	int fd = mnl_socket_get_fd(nl), one = 1, sz = SOCK_BUF;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		return -errno;
	setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof(one));
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sz, sizeof(sz)) < 0)
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz)) < 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	return 0;
}

/* Walk received messages, calling fn for each ack/error until it returns false. */
typedef bool (*ack_fn)(void *priv, uint32_t seq, int err);

static void parse_acks(const char *buf, int len, ack_fn fn, void *priv)
{
	const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;

	for (; mnl_nlmsg_ok(nlh, len); nlh = mnl_nlmsg_next(nlh, &len)) {
		const struct nlmsgerr *e;

		if (nlh->nlmsg_type != NLMSG_ERROR)
			continue;
		if (nlh->nlmsg_len < mnl_nlmsg_size(sizeof(*e)))
			continue;
		e = mnl_nlmsg_get_payload(nlh);
		if (!fn(priv, nlh->nlmsg_seq, e->error))
			return;
	}
}

/*
 * Control-plane transactions can be large (bootstrap with 4096 mark chains
 * is about 12000 messages), and the kernel queues all replies at once,
 * after processing the whole batch inside sendmsg(): an ack per message
 * would overrun the receive buffer (ENOBUFS). So only the last message
 * before END asks for an ack. nfnetlink reports every failing message
 * regardless of NLM_F_ACK, and a failed commit with an error for BEGIN,
 * all before the acks of the batch's own messages are delivered in message
 * order; so an error in the transaction's sequence range always arrives no
 * later than the final ack, and the final ack without an earlier error
 * means the transaction committed. Errors keep their message's sequence
 * number for diagnostics; the first one is returned.
 *
 * A transaction failing in thousands of messages can still overrun the
 * buffer: the first errors are queued before the overrun, so after ENOBUFS
 * the queue is read without blocking, and ENOBUFS is returned only if it
 * holds no error. Replies left over from an earlier transaction (after its
 * first error) are discarded before sending.
 */
struct sync_state {
	uint32_t first, last, want;
	bool done;
	int err;
};

static bool sync_ack(void *priv, uint32_t seq, int err)
{
	struct sync_state *st = priv;

	if (!seq_in(seq, st->first, st->last))
		return true;
	if (err) {
		st->err = err;
		return false;
	}
	if (seq == st->want)
		st->done = true;
	return !st->done;
}

static void ctl_discard(int fd, char *buf, size_t size)
{
	while (recv(fd, buf, size, MSG_DONTWAIT) >= 0 || errno == EINTR || errno == ENOBUFS)
		;
}

static int ctl_commit(struct nft_ctx *n, struct txn *t, const char *what)
{
	struct nlmsghdr *last = (struct nlmsghdr *)(t->b.p + t->last_off);
	struct sync_state st = { t->seq_first, t->seq_last, last->nlmsg_seq, false, 0 };
	int fd = mnl_socket_get_fd(n->ctl);
	bool overrun = false;
	char buf[16384];

	last->nlmsg_flags |= NLM_F_ACK;
	ctl_discard(fd, buf, sizeof(buf));
	if (mnl_socket_sendto(n->ctl, t->b.p, t->b.len) < 0) {
		st.err = -errno;
		goto out;
	}
	while (!st.done && !st.err) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t len;

		if (!overrun && poll(&pfd, 1, RECV_TIMEOUT_MS) <= 0) {
			st.err = -ETIMEDOUT;
			break;
		}
		len = recv(fd, buf, sizeof(buf), overrun ? MSG_DONTWAIT : 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno == ENOBUFS && !overrun) {
				log_debug("nft: %s: replies overran the receive buffer", what);
				overrun = true;
				continue;
			}
			st.err = overrun && (errno == EAGAIN || errno == EWOULDBLOCK) ?
			         -ENOBUFS : -errno;
			break;
		}
		parse_acks(buf, (int)len, sync_ack, &st);
	}
out:
	if (st.err)
		log_err("nft: %s (table %s) failed: %s", what, n->table, strerror(-st.err));
	return st.err;
}

/* ---- shadow state ---- */

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

static void shadow_free(struct shadow *s)
{
	free(s->marks);
	memset(s, 0, sizeof(*s));
}

static int shadow_from(struct shadow *s, const struct nft_desired *d)
{
	uint32_t i, k = 0;

	memset(s, 0, sizeof(*s));
	if (!d->fwmask) {
		log_err("nft: fwmask must be non-zero");
		return -EINVAL;
	}
	if ((d->has_pool4 && d->pool4.family != AF_INET) ||
	    (d->has_pool6 && d->pool6.family != AF_INET6)) {
		log_err("nft: bad pool family");
		return -EINVAL;
	}
	for (i = 0; i < d->nmarks; i++) {
		if (!d->marks[i] || (d->marks[i] & ~d->fwmask)) {
			log_err("nft: mark 0x%08x invalid for mask 0x%08x",
				d->marks[i], d->fwmask);
			return -EINVAL;
		}
	}
	s->fwmask = d->fwmask;
	s->has_pool4 = d->has_pool4;
	s->has_pool6 = d->has_pool6;
	s->pool4 = d->pool4;
	s->pool6 = d->pool6;
	s->marks = oom(malloc(sizeof(uint32_t) * (d->nmarks + 1)));
	if (d->nmarks)
		memcpy(s->marks, d->marks, sizeof(uint32_t) * d->nmarks);
	qsort(s->marks, d->nmarks, sizeof(uint32_t), cmp_u32);
	for (i = 0; i < d->nmarks; i++)
		if (!k || s->marks[k - 1] != s->marks[i])
			s->marks[k++] = s->marks[i];
	s->nmarks = k;
	return 0;
}

static bool prefix_eq(bool has, const struct ip_prefix *a, const struct ip_prefix *b)
{
	return !has || (a->family == b->family && a->plen == b->plen &&
	                !memcmp(a->addr, b->addr, sizeof(a->addr)));
}

static bool shadow_eq(const struct shadow *a, const struct shadow *b)
{
	return a->fwmask == b->fwmask && a->has_pool4 == b->has_pool4 &&
	       a->has_pool6 == b->has_pool6 && prefix_eq(a->has_pool4, &a->pool4, &b->pool4) &&
	       prefix_eq(a->has_pool6, &a->pool6, &b->pool6) && a->nmarks == b->nmarks &&
	       (!a->nmarks || !memcmp(a->marks, b->marks, a->nmarks * sizeof(*a->marks)));
}

static bool has_mark(const struct shadow *s, uint32_t v)
{
	return bsearch(&v, s->marks, s->nmarks, sizeof(v), cmp_u32) != NULL;
}

bool nft_mark_known(const struct nft_ctx *n, uint32_t mark)
{
	return n->have_state && has_mark(&n->sh, mark);
}

/*
 * Identifies the policy rules written for `s`, across processes (a fixed
 * key: it detects edits and stale rules, not an adversary who can edit the
 * ruleset anyway).
 */
static uint64_t shadow_tag(const struct shadow *s)
{
	static const uint8_t key[16];
	struct {
		uint64_t marks;
		uint32_t fwmask;
		uint8_t has4, has6, plen4, plen6;
		uint8_t a4[16], a6[16];
	} v;

	memset(&v, 0, sizeof(v));
	v.marks = siphash24(key, s->marks, s->nmarks * sizeof(*s->marks));
	v.fwmask = s->fwmask;
	v.has4 = s->has_pool4;
	v.has6 = s->has_pool6;
	if (s->has_pool4) {
		v.plen4 = s->pool4.plen;
		memcpy(v.a4, s->pool4.addr, sizeof(v.a4));
	}
	if (s->has_pool6) {
		v.plen6 = s->pool6.plen;
		memcpy(v.a6, s->pool6.addr, sizeof(v.a6));
	}
	return siphash24(key, &v, sizeof(v));
}

/* ---- control plane ---- */

/*
 * The whole table for `s`, in one transaction. `exists`: the table must be
 * there already (an fwmask change), so a table deleted meanwhile (omnidns
 * -F at stop) makes the transaction fail instead of coming back; otherwise
 * add+delete is "delete if exists".
 */
static void txn_create(struct nft_ctx *n, struct txn *t, const struct shadow *s, bool exists)
{
	txn_begin(n, t);
	if (!exists)
		txn_table(n, t, NFT_MSG_NEWTABLE, NLM_F_CREATE, 0);
	txn_table(n, t, NFT_MSG_DELTABLE, 0, 0);
	txn_table(n, t, NFT_MSG_NEWTABLE, NLM_F_CREATE, s->fwmask);
	txn_maps(n, t);
	for (uint32_t i = 0; i < s->nmarks; i++)
		txn_mark_chain(n, t, s->fwmask, s->marks[i]);
	txn_chain(n, t, NFT_MSG_NEWCHAIN, chain_new(n, "restore_marks"));
	txn_base_chain(n, t, "prerouting_mangle", "filter", NF_INET_PRE_ROUTING,
	               NF_IP_PRI_MANGLE);
	txn_base_chain(n, t, "output_mangle", "route", NF_INET_LOCAL_OUT,
	               NF_IP_PRI_MANGLE);
	txn_base_chain(n, t, "prerouting_dstnat", "nat", NF_INET_PRE_ROUTING,
	               NF_IP_PRI_NAT_DST);
	txn_base_chain(n, t, "output_dstnat", "nat", NF_INET_LOCAL_OUT,
	               NF_IP_PRI_NAT_DST);
	txn_base_chain(n, t, "forward_reject", "filter", NF_INET_FORWARD,
	               NF_IP_PRI_FILTER - 1);
	txn_base_chain(n, t, "output_reject", "filter", NF_INET_LOCAL_OUT,
	               NF_IP_PRI_FILTER - 1);
	txn_jump_rule(n, t, "prerouting_mangle", "restore_marks");
	txn_jump_rule(n, t, "output_mangle", "restore_marks");
	txn_policy_rules(n, t, s);
	txn_end(n, t);
}

/* Commit t; on success s becomes the shadow state, else it is freed. */
static int ctl_apply(struct nft_ctx *n, struct txn *t, struct shadow *s, const char *what)
{
	int err = ctl_commit(n, t, what);

	if (err) {
		shadow_free(s);
		return err;
	}
	shadow_free(&n->sh);
	n->sh = *s;
	n->have_state = true;
	n->stale = false;
	return 0;
}

void nft_set_secret(struct nft_ctx *n, const uint8_t secret[NFT_SECRET_LEN])
{
	memcpy(n->secret, secret, NFT_SECRET_LEN);
}

int nft_bootstrap(struct nft_ctx *n, const struct nft_desired *d)
{
	struct shadow s;
	int err;

	err = shadow_from(&s, d);
	if (err)
		return err;
	txn_create(n, &n->ctl_tx, &s, false);
	return ctl_apply(n, &n->ctl_tx, &s, "bootstrap");
}

int nft_reconcile(struct nft_ctx *n, const struct nft_desired *d)
{
	struct txn *t = &n->ctl_tx;
	struct shadow s;
	char name[32];
	int err;

	if (!n->have_state) {
		log_err("nft: reconcile before bootstrap");
		return -EINVAL;
	}
	err = shadow_from(&s, d);
	if (err)
		return err;
	if (!n->stale && shadow_eq(&s, &n->sh)) {
		/* nothing to do; rules changed behind our back stay changed */
		shadow_free(&s);
		return 0;
	}
	/*
	 * A new fwmask comes with no live binding (main.c), and the table's
	 * userdata, which records the fwmask, cannot be updated in place:
	 * recreate the table. That also drops elements a failed element batch
	 * may have left jumping to an old chain (deleting that chain would
	 * fail with EBUSY).
	 */
	if (s.fwmask != n->sh.fwmask) {
		txn_create(n, t, &s, true);
		return ctl_apply(n, t, &s, "reconcile (new fwmask)");
	}

	txn_begin(n, t);
	for (uint32_t i = 0; i < s.nmarks; i++)
		if (!has_mark(&n->sh, s.marks[i]))
			txn_mark_chain(n, t, s.fwmask, s.marks[i]);
	txn_flush_chain(n, t, "restore_marks");
	for (int i = 0; i < 2; i++) {
		txn_flush_chain(n, t, dstnat_chains[i]);
		txn_flush_chain(n, t, reject_chains[i]);
	}
	txn_policy_rules(n, t, &s);
	for (uint32_t i = 0; i < n->sh.nmarks; i++) {
		if (has_mark(&s, n->sh.marks[i]))
			continue;
		mark_chain_name(name, n->sh.marks[i]);
		txn_chain(n, t, NFT_MSG_DELCHAIN, chain_new(n, name));
	}
	txn_end(n, t);
	return ctl_apply(n, t, &s, "reconcile");
}

int nft_destroy_table(struct nft_ctx *n)
{
	struct txn *t = &n->ctl_tx;
	int err;

	txn_begin(n, t);
	txn_table(n, t, NFT_MSG_NEWTABLE, NLM_F_CREATE, 0);
	txn_table(n, t, NFT_MSG_DELTABLE, 0, 0);
	txn_end(n, t);
	err = ctl_commit(n, t, "destroy table");
	if (!err) {
		shadow_free(&n->sh);
		n->have_state = false;
	}
	return err;
}

/* ---- adoption: reading an existing table ---- */

/*
 * A reply larger than this would be truncated: netlink sizes dump messages
 * by the largest buffer recv() was given, capped at 32 KiB.
 */
#define DUMP_BUF	32768
/* chains in a table to adopt: the fixed ones, mark chains, some foreign */
#define ADOPT_MAX_CHAINS	8192

static const char *const fixed_chains[] = {
	"restore_marks", "prerouting_mangle", "output_mangle", "prerouting_dstnat",
	"output_dstnat", "forward_reject", "output_reject",
};
#define NFIXED (sizeof(fixed_chains) / sizeof(fixed_chains[0]))

struct attrs {
	const struct nlattr **tb;
	int max;
};

static int attr_cb(const struct nlattr *a, void *data)
{
	struct attrs *s = data;
	int type = mnl_attr_get_type(a);

	if (type <= s->max)
		s->tb[type] = a;
	return MNL_CB_OK;
}

static void parse_msg(const struct nlmsghdr *nlh, const struct nlattr **tb, int max)
{
	struct attrs s = { tb, max };

	memset(tb, 0, sizeof(*tb) * (max + 1));
	mnl_attr_parse(nlh, sizeof(struct nfgenmsg), attr_cb, &s);
}

static void parse_nest(const struct nlattr *nest, const struct nlattr **tb, int max)
{
	struct attrs s = { tb, max };

	memset(tb, 0, sizeof(*tb) * (max + 1));
	if (nest)
		mnl_attr_parse_nested(nest, attr_cb, &s);
}

/* NUL-terminated string attribute, or NULL */
static const char *attr_str(const struct nlattr *a)
{
	uint16_t len = a ? mnl_attr_get_payload_len(a) : 0;

	if (!len || ((const char *)mnl_attr_get_payload(a))[len - 1])
		return NULL;
	return mnl_attr_get_str(a);
}

static bool our_table(const struct nft_ctx *n, const struct nlattr *a)
{
	const char *t = attr_str(a);

	return t && !strcmp(t, n->table);
}

/*
 * Send a GET request (a dump, or one object asking for an ack) on the
 * control socket and pass each reply message to cb. 0, or -errno (-ENOENT:
 * no such object); a callback failing with errno set ends it early.
 */
static int ctl_get(struct nft_ctx *n, struct nlmsghdr *nlh, mnl_cb_t cb, void *priv)
{
	int fd = mnl_socket_get_fd(n->ctl), r;
	uint32_t seq = nlh->nlmsg_seq, portid = mnl_socket_get_portid(n->ctl);
	char *buf = oom(malloc(DUMP_BUF));

	ctl_discard(fd, buf, DUMP_BUF);
	r = mnl_socket_sendto(n->ctl, nlh, nlh->nlmsg_len) < 0 ? -errno : MNL_CB_OK;
	while (r == MNL_CB_OK) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t len;

		if (poll(&pfd, 1, RECV_TIMEOUT_MS) <= 0) {
			r = -ETIMEDOUT;
			break;
		}
		len = recv(fd, buf, DUMP_BUF, 0);
		if (len < 0) {
			if (errno != EINTR)
				r = -errno;
			continue;
		}
		r = mnl_cb_run(buf, (size_t)len, seq, portid, cb, priv);
		if (r < 0)
			r = errno ? -errno : -EPROTO;
	}
	free(buf);
	return r < 0 ? r : 0;
}

static struct nlmsghdr *get_msg(struct nft_ctx *n, char *buf, int type, uint16_t flags)
{
	return nftnl_nlmsg_build_hdr(buf, type, NFPROTO_INET, flags, n->seq++);
}

struct table_st {
	uint32_t version, fwmask;
	bool has_secret;
	uint8_t secret[NFT_SECRET_LEN];
};

static int table_ud_cb(const struct nftnl_udata *a, void *data)
{
	struct table_st *st = data;
	uint8_t len = nftnl_udata_len(a);

	switch (nftnl_udata_type(a)) {
	case UD_VERSION:
		if (len == 4)
			st->version = nftnl_udata_get_u32(a);
		break;
	case UD_FWMASK:
		if (len == 4)
			st->fwmask = nftnl_udata_get_u32(a);
		break;
	case UD_SECRET:
		if (len == NFT_SECRET_LEN) {
			memcpy(st->secret, nftnl_udata_get(a), NFT_SECRET_LEN);
			st->has_secret = true;
		}
		break;
	}
	return MNL_CB_OK;
}

static int table_cb(const struct nlmsghdr *nlh, void *priv)
{
	const struct nlattr *tb[NFTA_TABLE_MAX + 1];
	const struct nlattr *u;

	parse_msg(nlh, tb, NFTA_TABLE_MAX);
	u = tb[NFTA_TABLE_USERDATA];
	if (u)
		nftnl_udata_parse(mnl_attr_get_payload(u), mnl_attr_get_payload_len(u),
		                  table_ud_cb, priv);
	return MNL_CB_OK;
}

/* mark_%08x, exactly as mark_chain_name() prints it, valid for `fwmask` */
static bool parse_mark_chain(const char *name, uint32_t fwmask, uint32_t *v)
{
	char buf[32];
	unsigned long x;

	if (strncmp(name, "mark_", 5) || strlen(name) != 13)
		return false;
	x = strtoul(name + 5, NULL, 16);
	mark_chain_name(buf, (uint32_t)x);
	if (strcmp(buf, name) || !x || (x & ~(unsigned long)fwmask))
		return false;
	*v = (uint32_t)x;
	return true;
}

struct chain_st {
	const struct nft_ctx *n;
	uint32_t fwmask;
	uint32_t nchains, fixed;	/* fixed: bit i = fixed_chains[i] seen */
	uint32_t *marks, nmarks;
};

static int chain_cb(const struct nlmsghdr *nlh, void *priv)
{
	const struct nlattr *tb[NFTA_CHAIN_MAX + 1];
	struct chain_st *st = priv;
	const char *name;
	uint32_t v;

	parse_msg(nlh, tb, NFTA_CHAIN_MAX);
	name = attr_str(tb[NFTA_CHAIN_NAME]);
	if (!our_table(st->n, tb[NFTA_CHAIN_TABLE]) || !name)
		return MNL_CB_OK;
	if (++st->nchains > ADOPT_MAX_CHAINS) {
		errno = E2BIG;
		return MNL_CB_ERROR;
	}
	for (uint32_t i = 0; i < NFIXED; i++)
		if (!strcmp(name, fixed_chains[i]))
			st->fixed |= 1u << i;
	if (parse_mark_chain(name, st->fwmask, &v))
		st->marks[st->nmarks++] = v;
	return MNL_CB_OK;
}

struct rule_st {
	uint64_t tag;
	uint32_t n;
	bool bad;
};

static int rule_ud_cb(const struct nftnl_udata *a, void *data)
{
	struct rule_st *st = data;
	uint64_t tag;

	if (nftnl_udata_type(a) == UD_TAG && nftnl_udata_len(a) == sizeof(tag)) {
		memcpy(&tag, nftnl_udata_get(a), sizeof(tag));
		if (tag == st->tag)
			st->bad = false;
	}
	return MNL_CB_OK;
}

static int rule_cb(const struct nlmsghdr *nlh, void *priv)
{
	const struct nlattr *tb[NFTA_RULE_MAX + 1];
	struct rule_st *st = priv;
	const struct nlattr *u;
	bool bad = st->bad;

	parse_msg(nlh, tb, NFTA_RULE_MAX);
	st->n++;
	st->bad = true;		/* unless this rule carries the tag */
	u = tb[NFTA_RULE_USERDATA];
	if (u)
		nftnl_udata_parse(mnl_attr_get_payload(u), mnl_attr_get_payload_len(u),
		                  rule_ud_cb, st);
	st->bad |= bad;
	return MNL_CB_OK;
}

/* true if `chain` holds exactly `want` rules, all tagged `tag` */
static bool rules_current(struct nft_ctx *n, const char *chain, uint64_t tag, uint32_t want)
{
	struct rule_st st = { .tag = tag };
	char buf[512];
	struct nlmsghdr *nlh = get_msg(n, buf, NFT_MSG_GETRULE, NLM_F_DUMP);

	mnl_attr_put_strz(nlh, NFTA_RULE_TABLE, n->table);
	mnl_attr_put_strz(nlh, NFTA_RULE_CHAIN, chain);
	return !ctl_get(n, nlh, rule_cb, &st) && !st.bad && st.n == want;
}

struct elem_st {
	const struct shadow *sh;
	uint8_t family;
	bool mark;			/* a fake2mark map */
	struct nft_elem *v;
	uint32_t n, cap, max;
};

static int elem_cb(const struct nlmsghdr *nlh, void *priv)
{
	const struct nlattr *tb[NFTA_SET_ELEM_LIST_MAX + 1], *a;
	struct elem_st *st = priv;
	uint32_t alen = st->family == 6 ? 16 : 4;

	parse_msg(nlh, tb, NFTA_SET_ELEM_LIST_MAX);
	if (!tb[NFTA_SET_ELEM_LIST_ELEMENTS])
		return MNL_CB_OK;
	mnl_attr_for_each_nested(a, tb[NFTA_SET_ELEM_LIST_ELEMENTS]) {
		const struct nlattr *e[NFTA_SET_ELEM_MAX + 1], *k[NFTA_DATA_MAX + 1];
		const struct nlattr *dt[NFTA_DATA_MAX + 1], *vd[NFTA_VERDICT_MAX + 1];
		struct nft_elem *x;
		const char *chain;

		parse_nest(a, e, NFTA_SET_ELEM_MAX);
		parse_nest(e[NFTA_SET_ELEM_KEY], k, NFTA_DATA_MAX);
		if (!k[NFTA_DATA_VALUE] || mnl_attr_get_payload_len(k[NFTA_DATA_VALUE]) != alen)
			continue;	/* not a key of ours: nothing we could destroy */
		if (st->n == st->max) {
			errno = E2BIG;
			return MNL_CB_ERROR;
		}
		if (st->n == st->cap) {
			st->cap = st->cap ? st->cap * 2 : 256;
			st->v = oom(realloc(st->v, st->cap * sizeof(*st->v)));
		}
		x = &st->v[st->n++];
		memset(x, 0, sizeof(*x));
		x->family = st->family;
		memcpy(x->fake, mnl_attr_get_payload(k[NFTA_DATA_VALUE]), alen);
		parse_nest(e[NFTA_SET_ELEM_DATA], dt, NFTA_DATA_MAX);
		if (!st->mark) {
			if (dt[NFTA_DATA_VALUE] &&
			    mnl_attr_get_payload_len(dt[NFTA_DATA_VALUE]) == alen) {
				memcpy(x->real, mnl_attr_get_payload(dt[NFTA_DATA_VALUE]), alen);
				x->ok = true;
			}
			continue;
		}
		parse_nest(dt[NFTA_DATA_VERDICT], vd, NFTA_VERDICT_MAX);
		chain = attr_str(vd[NFTA_VERDICT_CHAIN]);
		x->ok = vd[NFTA_VERDICT_CODE] &&
		        mnl_attr_get_payload_len(vd[NFTA_VERDICT_CODE]) == 4 &&
		        ntohl(mnl_attr_get_u32(vd[NFTA_VERDICT_CODE])) == (uint32_t)NFT_JUMP &&
		        chain && parse_mark_chain(chain, st->sh->fwmask, &x->mark) &&
		        has_mark(st->sh, x->mark);
	}
	return MNL_CB_OK;
}

static int dump_map(struct nft_ctx *n, int set, struct elem_st *st)
{
	char buf[512];
	struct nlmsghdr *nlh = get_msg(n, buf, NFT_MSG_GETSETELEM, NLM_F_DUMP);

	st->family = set >= S_REAL6 ? 6 : 4;
	st->mark = set & 1;
	mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_TABLE, n->table);
	mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, set_names[set]);
	return ctl_get(n, nlh, elem_cb, st);
}

static int cmp_elem(const void *a, const void *b)
{
	const struct nft_elem *x = a, *y = b;

	if (x->family != y->family)
		return x->family < y->family ? -1 : 1;
	return memcmp(x->fake, y->fake, sizeof(x->fake));
}

/*
 * Pair fake2real elements r[] with fake2mark elements m[] by fake (both
 * sorted): one entry per fake, ok only if both halves are.
 */
static uint32_t pair_elems(const struct nft_elem *r, uint32_t nr, const struct nft_elem *m,
                           uint32_t nm, struct nft_elem *out)
{
	uint32_t i = 0, j = 0, k = 0;

	while (i < nr || j < nm) {
		int c = i == nr ? 1 : j == nm ? -1 : cmp_elem(&r[i], &m[j]);

		out[k] = c <= 0 ? r[i] : m[j];
		if (c) {
			out[k].ok = false;
		} else {
			out[k].mark = m[j].mark;
			out[k].ok = r[i].ok && m[j].ok;
		}
		k++;
		i += c <= 0;
		j += c >= 0;
	}
	return k;
}

int nft_adopt(struct nft_ctx *n, const struct nft_desired *d, uint32_t max_elems,
              uint8_t secret[NFT_SECRET_LEN], struct nft_elem **elems, uint32_t *nelems)
{
	struct table_st tst = { 0 };
	struct chain_st cst = { .n = n, .fwmask = d->fwmask };
	struct elem_st est[2] = { { 0 } };	/* fake2real, fake2mark (both families) */
	uint32_t want[3], i;
	struct nft_elem *out = NULL;
	struct nlmsghdr *nlh;
	struct shadow s;
	const char *why;
	char buf[512];
	uint64_t tag;
	int err;

	*elems = NULL;
	*nelems = 0;
	if (shadow_from(&s, d))
		return 0;
	nlh = get_msg(n, buf, NFT_MSG_GETTABLE, NLM_F_ACK);
	mnl_attr_put_strz(nlh, NFTA_TABLE_NAME, n->table);
	err = ctl_get(n, nlh, table_cb, &tst);
	if (err == -ENOENT) {
		log_info("nft: no table %s yet", n->table);
		goto fail_quiet;
	}
	why = "cannot read it";
	if (err)
		goto fail;
	why = "made by another omnidns version";
	if (tst.version != NFT_LAYOUT_VERSION || !tst.has_secret)
		goto fail;
	why = "made for another fwmask";
	if (tst.fwmask != d->fwmask)
		goto fail;

	free(s.marks);
	s.marks = cst.marks = oom(malloc(ADOPT_MAX_CHAINS * sizeof(uint32_t)));
	s.nmarks = 0;
	nlh = get_msg(n, buf, NFT_MSG_GETCHAIN, NLM_F_DUMP);
	why = "cannot list its chains, or too many";
	if (ctl_get(n, nlh, chain_cb, &cst))
		goto fail;
	why = "a chain is missing";
	if (cst.fixed != (1u << NFIXED) - 1)
		goto fail;
	qsort(cst.marks, cst.nmarks, sizeof(uint32_t), cmp_u32);
	s.marks = oom(realloc(cst.marks, (cst.nmarks + 1) * sizeof(uint32_t)));
	s.nmarks = cst.nmarks;

	why = "cannot list its maps, or more elements than fakeip_max_bindings allows";
	for (i = 0; i < 2; i++) {
		est[i].sh = &s;
		est[i].max = max_elems;
		if (dump_map(n, i ? S_MARK4 : S_REAL4, &est[i]) ||
		    dump_map(n, i ? S_MARK6 : S_REAL6, &est[i]))
			goto fail;
		if (est[i].n)
			qsort(est[i].v, est[i].n, sizeof(*est[i].v), cmp_elem);
	}
	out = oom(malloc(((size_t)est[0].n + est[1].n + 1) * sizeof(*out)));
	*nelems = pair_elems(est[0].v, est[0].n, est[1].v, est[1].n, out);
	*elems = out;

	/* policy rules: exactly what `s` would install, or rewrite them */
	tag = shadow_tag(&s);
	policy_rule_counts(&s, &want[0], &want[1], &want[2]);
	n->stale = !rules_current(n, "restore_marks", tag, want[0]);
	for (i = 0; i < 2 && !n->stale; i++)
		n->stale = !rules_current(n, dstnat_chains[i], tag, want[1]) ||
		           !rules_current(n, reject_chains[i], tag, want[2]);

	shadow_free(&n->sh);
	n->sh = s;
	n->have_state = true;
	memcpy(n->secret, tst.secret, NFT_SECRET_LEN);
	memcpy(secret, tst.secret, NFT_SECRET_LEN);
	log_info("nft: adopting table %s: %u map elements, %u mark chains%s", n->table,
	         *nelems, s.nmarks, n->stale ? ", policy rules to rewrite" : "");
	free(est[0].v);
	free(est[1].v);
	return 1;

fail:
	log_warn("nft: not adopting table %s (%s): it is recreated, its fake IPs are lost",
	         n->table, why);
fail_quiet:
	free(est[0].v);
	free(est[1].v);
	shadow_free(&s);
	return 0;
}

/* ---- async element batches ---- */

/*
 * Elements of the open batch are encoded straight into netlink messages, one
 * persistent buffer per (set, phase), in the exact layout libnftnl's
 * nftnl_set_elems_nlmsg_build_payload() produces:
 *
 *   nlmsghdr + nfgenmsg (NFPROTO_INET), seq filled in at flush
 *   NFTA_SET_ELEM_LIST_SET     "fake2real_v4" ...
 *   NFTA_SET_ELEM_LIST_TABLE   table
 *   NFTA_SET_ELEM_LIST_ELEMENTS (nested)
 *     [1..CHUNK_MAX] (nested; libnftnl numbers the elements, the kernel
 *                     ignores the attribute type)
 *       NFTA_SET_ELEM_KEY  { NFTA_DATA_VALUE fake }
 *       NFTA_SET_ELEM_DATA { NFTA_DATA_VALUE real }                (adds, real)
 *       NFTA_SET_ELEM_DATA { NFTA_DATA_VERDICT { NFTA_VERDICT_CODE NFT_JUMP,
 *                            NFTA_VERDICT_CHAIN "mark_%08x" } }   (adds, mark)
 *
 * A message is closed at CHUNK_MAX elements (the ELEMENTS nest length is 16
 * bits: 256 elements of at most 64 bytes stay well below it). nft_flush()
 * copies the messages, destroys first, into the transaction buffer between
 * BEGIN and END, numbering them.
 */
#define EBUF_FLOOR	1024		/* per (set, phase) buffer */
#define ETX_FLOOR	4096		/* transaction buffer */
#define NBUF_LOW_RUN	64
/* message head (<= 112 bytes with a NFT_TABLE_MAX table name) + one element
 * (<= 64 bytes: a v6 key and a jump verdict) */
#define ELEM_ROOM	256

/*
 * Shrink back after a burst: halve once NBUF_LOW_RUN consecutive batches used
 * at most a quarter of the capacity (the run keeps batch sizes that merely
 * vary from bouncing between two sizes), never below `floor`.
 */
static void nbuf_trim(struct nbuf *b, size_t used, size_t floor)
{
	if (b->cap <= floor || used > b->cap / 4) {
		b->low = 0;
		return;
	}
	if (++b->low < NBUF_LOW_RUN)
		return;
	b->low = 0;
	b->cap /= 2;
	b->p = oom(realloc(b->p, b->cap));
}

static struct ebatch *batch_new(struct nft_ctx *n)
{
	struct ebatch *b;

	if (n->nspare)
		b = n->spare[--n->nspare];
	else
		b = oom(malloc(sizeof(*b)));
	memset(b, 0, sizeof(*b));
	b->ticket = n->next_ticket++;
	/* new pending-add generation: older slots read as empty */
	if (!++n->pend_gen) {
		memset(n->pend_slot, 0, sizeof(n->pend_slot));
		n->pend_gen = 1;
	}
	n->pend_n = 0;
	return b;
}

static void batch_free(struct nft_ctx *n, struct ebatch *b)
{
	if (n->nspare < SPARE_MAX)
		n->spare[n->nspare++] = b;
	else
		free(b);
}

static int fail_lookup(const struct nft_ctx *n, uint64_t ticket)
{
	for (int i = 0; i < FAIL_RING; i++)
		if (n->fails[i].ticket == ticket)
			return n->fails[i].err;
	return 0;
}

static void run_waiters(struct list_head *head, int err)
{
	while (!list_empty(head)) {
		struct nft_waiter *w = list_first_entry(head, struct nft_waiter, list);

		list_del_init(&w->list);
		w->cb(w, err);
	}
}

static void batch_complete(struct nft_ctx *n, struct ebatch *b, int err)
{
	struct nft_waiter *w, *tmp;
	uint64_t ticket = b->ticket;
	LIST_HEAD(done);

	list_del(&b->list);
	batch_free(n, b);
	if (err) {
		log_err("nft: element batch %llu failed: %s",
			(unsigned long long)ticket, strerror(-err));
		n->fails[n->fail_pos].ticket = ticket;
		n->fails[n->fail_pos].err = err;
		n->fail_pos = (n->fail_pos + 1) % FAIL_RING;
		if (n->draining && !n->drain_err)
			n->drain_err = err;
		if (n->fail_fn)
			n->fail_fn(n->fail_priv, ticket, err);
	}
	list_for_each_entry_safe(w, tmp, &n->waiters, list)
		if (w->ticket == ticket)
			list_move_tail(&w->list, &done);
	run_waiters(&done, err);
}

static void complete_failed(struct nft_ctx *n)
{
	struct ebatch *b, *tmp;

	list_for_each_entry_safe(b, tmp, &n->inflight, list)
		if (b->err)
			batch_complete(n, b, b->err);
}

static void kick_cb(struct uloop_timeout *tmo)
{
	complete_failed(container_of(tmo, struct nft_ctx, kick_tmo));
}

static void ebuf_close(struct ebuf *e)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)(e->b.p + e->b.len);

	if (!e->nelem)
		return;
	mnl_attr_nest_end(nlh, (struct nlattr *)((char *)nlh + e->nest_off));
	e->b.len += MNL_ALIGN(nlh->nlmsg_len);
	e->nelem = 0;
}

/* Append the closed messages of `e` to `t`, numbering them; empty `e`. */
static void ebuf_move(struct nft_ctx *n, struct ebuf *e, struct txn *t)
{
	size_t used;

	ebuf_close(e);
	used = e->b.len;
	nbuf_reserve(&t->b, e->b.len);
	for (size_t off = 0; off < e->b.len;) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)(t->b.p + t->b.len);
		size_t len = MNL_ALIGN(((struct nlmsghdr *)(e->b.p + off))->nlmsg_len);

		memcpy(nlh, e->b.p + off, len);
		nlh->nlmsg_seq = n->seq++;
		t->last_off = t->b.len;
		t->b.len += len;
		t->nmsg++;
		off += len;
	}
	e->b.len = 0;
	nbuf_trim(&e->b, used, EBUF_FLOOR);
}

void nft_flush(struct nft_ctx *n)
{
	struct ebatch *b = n->open;
	struct txn *t = &n->etx;
	struct nlmsghdr *nlh;

	uloop_timeout_cancel(&n->submit_tmo);
	if (!b)
		return;
	n->open = NULL;
	txn_begin(n, t);
	/* [set * 2 + 0] destroys, [set * 2 + 1] adds; destroys go first */
	for (int phase = 0; phase < 2; phase++)
		for (int i = 0; i < S_NUM; i++)
			ebuf_move(n, &n->ebuf[i * 2 + phase], t);
	if (!t->nmsg) {
		/*
		 * Unreachable today: a batch is opened only by an op that
		 * queues elements before returning its ticket. Should it
		 * happen, there is nothing to install and no message to carry
		 * the ack (t->last_off would be stale): the batch succeeds
		 * without a send, its waiters (if any) via the ready list.
		 */
		struct nft_waiter *w, *tmp;

		list_for_each_entry_safe(w, tmp, &n->waiters, list)
			if (w->ticket == b->ticket)
				list_move_tail(&w->list, &n->ready);
		if (!list_empty(&n->ready))
			uloop_timeout_set(&n->ready_tmo, 0);
		batch_free(n, b);
		return;
	}
	/*
	 * As for control-plane transactions (see ctl_commit()), only the last
	 * message asks for an ack: the kernel reports a failing message, or a
	 * failed commit (on BEGIN), whether it asked or not, and queues every
	 * reply of the batch at once, in message order, so an error arrives
	 * before the final ack and the final ack alone means success. One ack
	 * and one read per batch instead of one per message.
	 */
	nlh = (struct nlmsghdr *)(t->b.p + t->last_off);
	nlh->nlmsg_flags |= NLM_F_ACK;
	b->ack_seq = nlh->nlmsg_seq;
	txn_end(n, t);
	b->seq_first = t->seq_first;
	b->seq_last = t->seq_last;
	list_add_tail(&b->list, &n->inflight);
	if (mnl_socket_sendto(n->async, t->b.p, t->b.len) < 0) {
		b->err = -errno;
		uloop_timeout_set(&n->kick_tmo, 0);
	}
	nbuf_trim(&t->b, t->b.len, ETX_FLOOR);
}

static void submit_cb(struct uloop_timeout *tmo)
{
	nft_flush(container_of(tmo, struct nft_ctx, submit_tmo));
}

/*
 * Encode one element into the (set, phase) buffer: key only (destroy), key
 * and data (add to fake2real) or key and jump verdict (add to fake2mark).
 */
static void queue_elem(struct nft_ctx *n, int set, bool add, const uint8_t *key,
                       uint32_t alen, const uint8_t *real, uint32_t mark)
{
	struct ebuf *e = &n->ebuf[set * 2 + add];
	struct nlmsghdr *nlh;
	struct nlattr *elem, *data, *verdict, *k;
	char chain[32];

	if (e->nelem == CHUNK_MAX)
		ebuf_close(e);
	nbuf_reserve(&e->b, ELEM_ROOM +
	             (e->nelem ? ((struct nlmsghdr *)(e->b.p + e->b.len))->nlmsg_len : 0));
	nlh = (struct nlmsghdr *)(e->b.p + e->b.len);
	if (!e->nelem) {
		nlh = nftnl_nlmsg_build_hdr((char *)nlh,
		        add ? NFT_MSG_NEWSETELEM : NFT_MSG_DESTROYSETELEM, NFPROTO_INET,
		        add ? NLM_F_CREATE : 0, 0);
		mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, set_names[set]);
		mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_TABLE, n->table);
		e->nest_off = nlh->nlmsg_len;
		mnl_attr_nest_start(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
	}
	elem = mnl_attr_nest_start(nlh, (uint16_t)++e->nelem);
	k = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_KEY);
	mnl_attr_put(nlh, NFTA_DATA_VALUE, alen, key);
	mnl_attr_nest_end(nlh, k);
	if (add) {
		data = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_DATA);
		if (real) {
			mnl_attr_put(nlh, NFTA_DATA_VALUE, alen, real);
		} else {
			mark_chain_name(chain, mark);
			verdict = mnl_attr_nest_start(nlh, NFTA_DATA_VERDICT);
			mnl_attr_put_u32(nlh, NFTA_VERDICT_CODE, htonl((uint32_t)NFT_JUMP));
			mnl_attr_put_strz(nlh, NFTA_VERDICT_CHAIN, chain);
			mnl_attr_nest_end(nlh, verdict);
		}
		mnl_attr_nest_end(nlh, data);
	}
	mnl_attr_nest_end(nlh, elem);
}

/*
 * DESTROYSETELEM (kernel >= 6.3) is a delete that ignores missing keys.
 * Every element op goes through it, so element ops are idempotent and a
 * kernel state that drifted from the binding DB (e.g. after a failed,
 * rolled-back batch) can never make later batches fail.
 */
static void queue_destroy(struct nft_ctx *n, int real, int mark, const uint8_t *fake,
                          uint32_t alen)
{
	queue_elem(n, real, false, fake, alen, NULL, 0);
	queue_elem(n, mark, false, fake, alen, NULL, 0);
}

static uint64_t op_done(struct nft_ctx *n)
{
	struct ebatch *b = n->open;
	uint64_t ticket = b->ticket;

	b->nops++;
	if (b->nops >= NFT_BATCH_MAX)
		nft_flush(n);
	else if (b->nops == 1)
		uloop_timeout_set(&n->submit_tmo, 0);
	return ticket;
}

/*
 * Destroys are emitted before adds within a batch, which is only correct
 * while each key has at most one add and nothing after it. A second op on
 * a key with a pending add therefore starts a new batch.
 *
 * Keys with a pending add live in a fixed open-addressing table (at most
 * NFT_BATCH_MAX adds per batch, load <= 1/2): slots hold the batch's
 * generation and an index into pend_key, so a new batch empties the table
 * by bumping the generation.
 */
static void op_order_key(struct nft_ctx *n, int family, const uint8_t *fake, bool add)
{
	struct pend_key k = { 0 };
	uint32_t h, s, slot = 0;

	k.family = family == AF_INET6 ? 6 : 4;
	memcpy(k.addr, fake, family == AF_INET6 ? 16 : 4);
	h = (uint32_t)omni_hash(&k, sizeof(k));
	if (n->open) {
		for (s = h; ; s++) {
			slot = n->pend_slot[s & (PENDING_SLOTS - 1)];
			if (slot >> 16 != n->pend_gen)
				break;
			if (!memcmp(&n->pend_key[(slot & 0xffff) - 1], &k, sizeof(k))) {
				nft_flush(n);
				break;
			}
		}
	}
	if (!add)
		return;
	if (!n->open)
		n->open = batch_new(n);
	for (s = h; n->pend_slot[s & (PENDING_SLOTS - 1)] >> 16 == n->pend_gen; s++)
		;
	n->pend_key[n->pend_n++] = k;
	n->pend_slot[s & (PENDING_SLOTS - 1)] = (uint32_t)n->pend_gen << 16 | n->pend_n;
}

/* accepts 4/6 as well as AF_INET/AF_INET6 */
static int norm_family(int family)
{
	if (family == 4)
		return AF_INET;
	if (family == 6)
		return AF_INET6;
	return family;
}

static bool op_begin(struct nft_ctx *n, int family)
{
	if (family != AF_INET && family != AF_INET6) {
		log_err("nft: bad element family %d", family);
		return false;
	}
	if (!n->open)
		n->open = batch_new(n);
	return true;
}

/* An add always destroys the key first, so a key mapped to different data
 * never fails with EEXIST. */
uint64_t nft_elem_add(struct nft_ctx *n, int family, const uint8_t *fake,
                      const uint8_t *real, uint32_t mark)
{
	bool v6;
	int rs, ms;
	uint32_t alen;

	family = norm_family(family);
	if (!op_begin(n, family))
		return 0;
	op_order_key(n, family, fake, true);
	v6 = family == AF_INET6;
	rs = v6 ? S_REAL6 : S_REAL4;
	ms = v6 ? S_MARK6 : S_MARK4;
	alen = v6 ? 16 : 4;
	queue_destroy(n, rs, ms, fake, alen);
	queue_elem(n, rs, true, fake, alen, real, 0);
	queue_elem(n, ms, true, fake, alen, NULL, mark);
	return op_done(n);
}

uint64_t nft_elem_del(struct nft_ctx *n, int family, const uint8_t *fake)
{
	bool v6;

	family = norm_family(family);
	if (!op_begin(n, family))
		return 0;
	op_order_key(n, family, fake, false);
	if (!n->open)
		n->open = batch_new(n);
	v6 = family == AF_INET6;
	queue_destroy(n, v6 ? S_REAL6 : S_REAL4, v6 ? S_MARK6 : S_MARK4, fake,
	          v6 ? 16 : 4);
	return op_done(n);
}

size_t nft_batch_mem(const struct nft_ctx *n)
{
	size_t sum = n->etx.b.cap;

	for (int i = 0; i < S_NUM * 2; i++)
		sum += n->ebuf[i].b.cap;
	return sum;
}

bool nft_ticket_done(const struct nft_ctx *n, uint64_t ticket)
{
	struct ebatch *b;

	if (ticket >= n->next_ticket)
		return false;
	if (n->open && n->open->ticket == ticket)
		return false;
	list_for_each_entry(b, &n->inflight, list)
		if (b->ticket == ticket)
			return false;
	return true;
}

void nft_set_fail_hook(struct nft_ctx *n, void (*fn)(void *priv, uint64_t ticket, int err),
                       void *priv)
{
	n->fail_fn = fn;
	n->fail_priv = priv;
}

static void ready_cb(struct uloop_timeout *tmo)
{
	struct nft_ctx *n = container_of(tmo, struct nft_ctx, ready_tmo);

	while (!list_empty(&n->ready)) {
		struct nft_waiter *w = list_first_entry(&n->ready, struct nft_waiter, list);

		list_del_init(&w->list);
		w->cb(w, fail_lookup(n, w->ticket));
	}
}

void nft_wait(struct nft_ctx *n, struct nft_waiter *w, uint64_t ticket)
{
	nft_wait_cancel(w);
	w->ticket = ticket;
	if (nft_ticket_done(n, ticket)) {
		list_add_tail(&w->list, &n->ready);
		uloop_timeout_set(&n->ready_tmo, 0);
	} else {
		list_add_tail(&w->list, &n->waiters);
	}
}

void nft_wait_cancel(struct nft_waiter *w)
{
	if (w->list.next && !list_empty(&w->list))
		list_del_init(&w->list);
}

static bool async_ack(void *priv, uint32_t seq, int err)
{
	struct nft_ctx *n = priv;
	struct ebatch *b;

	list_for_each_entry(b, &n->inflight, list) {
		if (b->err || !seq_in(seq, b->seq_first, b->seq_last))
			continue;
		/* an error (earlier in the batch, or the commit), or the final ack */
		if (err || seq == b->ack_seq)
			batch_complete(n, b, err);
		break;
	}
	return true;
}

static void fail_inflight(struct nft_ctx *n, int err)
{
	struct ebatch *b, *tmp;

	/* lost acks: conservatively fail everything still pending */
	list_for_each_entry_safe(b, tmp, &n->inflight, list)
		batch_complete(n, b, b->err ? b->err : err);
}

/* Read all pending acks until the socket would block. */
static void async_read(struct nft_ctx *n)
{
	int fd = mnl_socket_get_fd(n->async);
	char buf[16384];

	for (;;) {
		ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);

		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				log_err("nft: async recv: %s", strerror(errno));
				fail_inflight(n, -errno);
			}
			return;
		}
		parse_acks(buf, (int)len, async_ack, n);
	}
}

static void async_fd_cb(struct uloop_fd *u, unsigned int events)
{
	struct nft_ctx *n = container_of(u, struct nft_ctx, ufd);

	async_read(n);
	complete_failed(n);
}

int nft_drain(struct nft_ctx *n)
{
	int fd = mnl_socket_get_fd(n->async);

	nft_flush(n);
	n->draining = true;
	n->drain_err = 0;
	complete_failed(n);
	while (!list_empty(&n->inflight)) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int r = poll(&pfd, 1, RECV_TIMEOUT_MS);

		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0) {
			fail_inflight(n, -ETIMEDOUT);
			break;
		}
		async_read(n);
		complete_failed(n);
	}
	n->draining = false;
	return n->drain_err;
}

/* ---- open/close ---- */

struct nft_ctx *nft_open(const char *table)
{
	struct nft_ctx *n = oom(calloc(1, sizeof(*n)));
	int err;

	snprintf(n->table, sizeof(n->table), "%s", table ? table : "omnidns");
	INIT_LIST_HEAD(&n->inflight);
	INIT_LIST_HEAD(&n->waiters);
	INIT_LIST_HEAD(&n->ready);
	n->submit_tmo.cb = submit_cb;
	n->ready_tmo.cb = ready_cb;
	n->kick_tmo.cb = kick_cb;
	n->next_ticket = 1;
	n->seq = (uint32_t)time(NULL);

	n->ctl = mnl_socket_open(NETLINK_NETFILTER);
	n->async = mnl_socket_open(NETLINK_NETFILTER);
	if (!n->ctl || !n->async) {
		err = -errno;
		goto fail;
	}
	if ((err = sock_setup(n->ctl)) || (err = sock_setup(n->async)))
		goto fail;
	n->ufd.fd = mnl_socket_get_fd(n->async);
	n->ufd.cb = async_fd_cb;
	if (uloop_fd_add(&n->ufd, ULOOP_READ) < 0)
		log_warn("nft: uloop_fd_add failed (uloop not initialized?)");
	return n;
fail:
	log_err("nft: netlink socket: %s", strerror(-err));
	if (n->ctl)
		mnl_socket_close(n->ctl);
	if (n->async)
		mnl_socket_close(n->async);
	free(n);
	return NULL;
}

void nft_close(struct nft_ctx *n)
{
	struct ebatch *b, *tmp;
	struct nft_waiter *w, *wt;

	if (!n)
		return;
	uloop_timeout_cancel(&n->submit_tmo);
	uloop_timeout_cancel(&n->ready_tmo);
	uloop_timeout_cancel(&n->kick_tmo);
	uloop_fd_delete(&n->ufd);
	if (n->open)
		batch_free(n, n->open);
	list_for_each_entry_safe(b, tmp, &n->inflight, list)
		batch_free(n, b);
	while (n->nspare)
		free(n->spare[--n->nspare]);
	free(n->etx.b.p);
	for (int i = 0; i < S_NUM * 2; i++)
		free(n->ebuf[i].b.p);
	list_for_each_entry_safe(w, wt, &n->waiters, list)
		list_del_init(&w->list);
	list_for_each_entry_safe(w, wt, &n->ready, list)
		list_del_init(&w->list);
	mnl_socket_close(n->ctl);
	mnl_socket_close(n->async);
	shadow_free(&n->sh);
	free(n->ctl_tx.b.p);
	free(n);
}
