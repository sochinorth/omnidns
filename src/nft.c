// SPDX-License-Identifier: MIT
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
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
 * the fwmask and the fake IP allocation secret. Every rule carries a tag
 * (NFTA_RULE_USERDATA) identifying what it was written for: the policy
 * rules the shadow state (shadow_tag()), the others their chain's mark
 * (own_tag()). nft uses the low TLV types itself (comments) and ignores
 * unknown ones.
 */
enum { UD_VERSION = 0x80, UD_FWMASK, UD_SECRET };	/* table */
#define UD_TAG		0x80				/* rules */

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
	uint32_t seq_first, seq_last;
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
	bool stale;		/* fixed chains may not be as made for sh: rewrite them */
	uint32_t *dirty, ndirty;	/* sorted marks whose chains to rewrite */
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

/* the table's chains other than mark chains; type NULL: a regular chain */
enum { C_RESTORE, C_PRE_MANGLE, C_OUT_MANGLE, C_PRE_DSTNAT, C_OUT_DSTNAT, C_FWD_REJECT,
       C_OUT_REJECT, NFIXED };
static const struct {
	const char *name, *type;
	int hook, prio;
} fixed_chains[NFIXED] = {
	{ "restore_marks", NULL, 0, 0 },
	{ "prerouting_mangle", "filter", NF_INET_PRE_ROUTING, NF_IP_PRI_MANGLE },
	{ "output_mangle", "route", NF_INET_LOCAL_OUT, NF_IP_PRI_MANGLE },
	{ "prerouting_dstnat", "nat", NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST },
	{ "output_dstnat", "nat", NF_INET_LOCAL_OUT, NF_IP_PRI_NAT_DST },
	{ "forward_reject", "filter", NF_INET_FORWARD, NF_IP_PRI_FILTER - 1 },
	{ "output_reject", "filter", NF_INET_LOCAL_OUT, NF_IP_PRI_FILTER - 1 },
};

/* i of fixed_chains[i] named `name`, else NFIXED */
static int fixed_index(const char *name)
{
	int i = 0;

	while (i < NFIXED && strcmp(name, fixed_chains[i].name))
		i++;
	return i;
}

static void txn_fixed_chain(struct nft_ctx *n, struct txn *t, int i)
{
	struct nftnl_chain *c = chain_new(n, fixed_chains[i].name);

	if (fixed_chains[i].type) {
		nftnl_chain_set_str(c, NFTNL_CHAIN_TYPE, fixed_chains[i].type);
		nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, fixed_chains[i].hook);
		nftnl_chain_set_s32(c, NFTNL_CHAIN_PRIO, fixed_chains[i].prio);
		nftnl_chain_set_u32(c, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	}
	txn_chain(n, t, NFT_MSG_NEWCHAIN, c);
}

static struct nftnl_rule *rule_new(struct nft_ctx *n, const char *chain)
{
	struct nftnl_rule *r = oom(nftnl_rule_alloc());

	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, n->table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);
	return r;
}

static void txn_flush_chain(struct nft_ctx *n, struct txn *t, const char *chain)
{
	struct nftnl_rule *r = rule_new(n, chain);
	struct nlmsghdr *nlh;

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

/* ---- rule expressions ---- */

static void txn_rule(struct nft_ctx *n, struct txn *t, struct nftnl_rule *r, uint64_t tag)
{
	struct nftnl_udata_buf *u = oom(nftnl_udata_buf_alloc(32));
	struct nlmsghdr *nlh;

	nftnl_udata_put(u, UD_TAG, sizeof(tag), &tag);
	nftnl_rule_set_data(r, NFTNL_RULE_USERDATA, nftnl_udata_buf_data(u),
	                    nftnl_udata_buf_len(u));
	nftnl_udata_buf_free(u);
	nlh = txn_msg(n, t, NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND, 4096);
	nftnl_rule_nlmsg_build_payload(nlh, r);
	nbuf_commit(&t->b, nlh);
	nftnl_rule_free(r);
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

/* the tag of the rules of mark_<v>, or with v 0 of the jumps to restore_marks */
static uint64_t own_tag(uint32_t fwmask, uint32_t v)
{
	static const uint8_t key[16] = { 1 };
	uint32_t x[2] = { fwmask, v };

	return siphash24(key, x, sizeof(x));
}

static void txn_mark_rules(struct nft_ctx *n, struct txn *t, const char *chain,
                           uint32_t mask, uint32_t v)
{
	uint64_t tag = own_tag(mask, v);
	uint32_t keep = ~mask;
	struct nftnl_rule *r;

	r = rule_new(n, chain);
	e_meta(r, NFT_META_MARK, false);
	e_bitwise(r, &keep, &v, 4);
	e_meta(r, NFT_META_MARK, true);
	txn_rule(n, t, r, tag);

	r = rule_new(n, chain);
	e_ct(r, NFT_CT_MARK, false);
	e_bitwise(r, &keep, &v, 4);
	e_ct(r, NFT_CT_MARK, true);
	txn_rule(n, t, r, tag);
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
	struct nlmsghdr *nlh;
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
		nlh = txn_msg(n, t, NFT_MSG_NEWSETELEM, NLM_F_CREATE, 1024 + CHUNK_MAX * 160);
		nftnl_set_elems_nlmsg_build_payload(nlh, s);
		nbuf_commit(&t->b, nlh);
		nftnl_set_free(s);
	}

	r = rule_new(n, "restore_marks");
	e_ct(r, NFT_CT_MARK, false);
	e_bitwise(r, &mask, &zero, 4);
	e_lookup(r, "__map%d", id, NFT_REG_VERDICT);
	txn_rule(n, t, r, tag);
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
	txn_rule(n, t, r, tag);

	r = pool_rule(n, chain, p);
	e_payload(r, off, alen);
	e_lookup(r, set_names[v6 ? S_REAL6 : S_REAL4], 0, NFT_REG_1);
	e = expr(r, "nat");
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_TYPE, NFT_NAT_DNAT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_FAMILY, v6 ? NFPROTO_IPV6 : NFPROTO_IPV4);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
	txn_rule(n, t, r, tag);
}

static void txn_reject_rule(struct nft_ctx *n, struct txn *t, const char *chain,
                            const struct ip_prefix *p, uint64_t tag)
{
	struct nftnl_rule *r = pool_rule(n, chain, p);
	struct nftnl_expr *e = expr(r, "reject");

	/* icmp(v6) port-unreachable, as nft's plain `reject` in inet */
	nftnl_expr_set_u32(e, NFTNL_EXPR_REJECT_TYPE, NFT_REJECT_ICMP_UNREACH);
	nftnl_expr_set_u8(e, NFTNL_EXPR_REJECT_CODE, p->family == AF_INET6 ? 4 : 3);
	txn_rule(n, t, r, tag);
}

static void txn_jump_rule(struct nft_ctx *n, struct txn *t, const char *chain,
                          const char *target, uint64_t tag)
{
	struct nftnl_rule *r = rule_new(n, chain);
	struct nftnl_expr *e = expr(r, "immediate");

	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, NFT_JUMP);
	nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, target);
	txn_rule(n, t, r, tag);
}


/*
 * The rules fixed chain i holds for `s` (ptag: shadow_tag(s)): returns how
 * many, each tagged *tag; written by txn_fixed_rules() into the empty chain.
 */
static uint32_t fixed_rules(const struct shadow *s, int i, uint64_t ptag, uint64_t *tag)
{
	uint32_t pools = (uint32_t)s->has_pool4 + s->has_pool6;

	*tag = ptag;
	switch (i) {
	case C_RESTORE:
		return s->nmarks != 0;
	case C_PRE_MANGLE:
	case C_OUT_MANGLE:
		*tag = own_tag(s->fwmask, 0);
		return 1;
	case C_PRE_DSTNAT:
	case C_OUT_DSTNAT:
		return 2 * pools;
	default:
		return pools;
	}
}

static void txn_fixed_rules(struct nft_ctx *n, struct txn *t, const struct shadow *s, int i,
                            uint64_t ptag)
{
	const char *name = fixed_chains[i].name;
	uint64_t tag;

	fixed_rules(s, i, ptag, &tag);
	for (int v6 = 0; v6 < 2; v6++) {
		const struct ip_prefix *p = v6 ? &s->pool6 : &s->pool4;

		if (!(v6 ? s->has_pool6 : s->has_pool4))
			continue;
		if (i == C_PRE_DSTNAT || i == C_OUT_DSTNAT)
			txn_dstnat_rules(n, t, name, p, tag);
		else if (i == C_FWD_REJECT || i == C_OUT_REJECT)
			txn_reject_rule(n, t, name, p, tag);
	}
	if (i == C_RESTORE && s->nmarks)
		txn_restore_rule(n, t, s->fwmask, s->marks, s->nmarks, tag);
	else if (i == C_PRE_MANGLE || i == C_OUT_MANGLE)
		txn_jump_rule(n, t, name, fixed_chains[C_RESTORE].name, tag);
}

static const uint16_t map_attrs[4] = {
	NFTNL_SET_KEY_TYPE, NFTNL_SET_KEY_LEN, NFTNL_SET_DATA_TYPE, NFTNL_SET_DATA_LEN,
};

/* map i's map_attrs[] */
static void map_def(int i, uint32_t def[4])
{
	bool v6 = i >= S_REAL6, mark = i & 1;

	def[0] = v6 ? TYPE_IP6ADDR : TYPE_IPADDR;
	def[1] = v6 ? 16 : 4;
	def[2] = mark ? NFT_DATA_VERDICT : def[0];
	def[3] = mark ? 0 : def[1];
}

static void txn_maps(struct nft_ctx *n, struct txn *t)
{
	for (int i = 0; i < S_NUM; i++) {
		struct nftnl_set *s = oom(nftnl_set_alloc());
		uint32_t def[4];

		map_def(i, def);
		nftnl_set_set_str(s, NFTNL_SET_TABLE, n->table);
		nftnl_set_set_str(s, NFTNL_SET_NAME, set_names[i]);
		nftnl_set_set_u32(s, NFTNL_SET_FLAGS, NFT_SET_MAP);
		for (int k = 0; k < 4; k++)
			nftnl_set_set_u32(s, map_attrs[k], def[k]);
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
	struct timeval tv = { RECV_TIMEOUT_MS / 1000, RECV_TIMEOUT_MS % 1000 * 1000 };
	int fd = mnl_socket_get_fd(nl), one = 1, sz = SOCK_BUF;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		return -errno;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

/*
 * Receive datagrams into buf, passing each to fn until it returns <= 0 (0:
 * done, else -errno). Waiting longer than RECV_TIMEOUT_MS (SO_RCVTIMEO)
 * fails with -ETIMEDOUT. `overrun_ok`: after ENOBUFS, read what is queued
 * without waiting, then fail with -ENOBUFS (see above); else ENOBUFS fails.
 */
typedef int (*recv_fn)(void *priv, const char *buf, size_t len);

static int recv_loop(int fd, char *buf, size_t size, bool overrun_ok, recv_fn fn, void *priv)
{
	bool overrun = false;

	for (;;) {
		ssize_t len = recv(fd, buf, size, overrun ? MSG_DONTWAIT : 0);
		int r;

		if (len < 0 && errno == EINTR)
			continue;
		if (len < 0 && errno == ENOBUFS && overrun_ok && !overrun) {
			log_debug("nft: replies overran the receive buffer");
			overrun = true;
			continue;
		}
		if (len < 0)
			return errno != EAGAIN && errno != EWOULDBLOCK ? -errno :
			       overrun ? -ENOBUFS : -ETIMEDOUT;
		r = fn(priv, buf, (size_t)len);
		if (r <= 0)
			return r;
	}
}

static int sync_recv(void *priv, const char *buf, size_t len)
{
	struct sync_state *st = priv;

	parse_acks(buf, (int)len, sync_ack, st);
	return st->err ? st->err : !st->done;
}

static int ctl_commit(struct nft_ctx *n, struct txn *t, const char *what)
{
	struct nlmsghdr *last = (struct nlmsghdr *)(t->b.p + t->last_off);
	struct sync_state st = { t->seq_first, t->seq_last, last->nlmsg_seq, false, 0 };
	int fd = mnl_socket_get_fd(n->ctl), err;
	char buf[16384];

	last->nlmsg_flags |= NLM_F_ACK;
	ctl_discard(fd, buf, sizeof(buf));
	err = mnl_socket_sendto(n->ctl, t->b.p, t->b.len) < 0 ? -errno :
	      recv_loop(fd, buf, sizeof(buf), true, sync_recv, &st);
	if (err)
		log_err("nft: %s (table %s) failed: %s", what, n->table, strerror(-err));
	return err;
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
	uint64_t tag = shadow_tag(s);

	txn_begin(n, t);
	if (!exists)
		txn_table(n, t, NFT_MSG_NEWTABLE, NLM_F_CREATE, 0);
	txn_table(n, t, NFT_MSG_DELTABLE, 0, 0);
	txn_table(n, t, NFT_MSG_NEWTABLE, NLM_F_CREATE, s->fwmask);
	txn_maps(n, t);
	for (uint32_t i = 0; i < s->nmarks; i++)
		txn_mark_chain(n, t, s->fwmask, s->marks[i]);
	for (int i = 0; i < NFIXED; i++)
		txn_fixed_chain(n, t, i);
	for (int i = 0; i < NFIXED; i++)
		txn_fixed_rules(n, t, s, i, tag);
	txn_end(n, t);
}

/* s (taken over) becomes the shadow state, with the chains to rewrite */
static void state_set(struct nft_ctx *n, struct shadow *s, bool stale, uint32_t *dirty,
                      uint32_t ndirty)
{
	shadow_free(&n->sh);
	n->sh = *s;
	n->have_state = true;
	n->stale = stale;
	free(n->dirty);
	n->dirty = dirty;
	n->ndirty = ndirty;
}

/* Commit t; on success s becomes the shadow state, else it is freed. */
static int ctl_apply(struct nft_ctx *n, struct txn *t, struct shadow *s, const char *what)
{
	int err = ctl_commit(n, t, what);

	if (err)
		shadow_free(s);
	else
		state_set(n, s, false, NULL, 0);
	return err;
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
	uint64_t tag;
	int err;

	if (!n->have_state) {
		log_err("nft: reconcile before bootstrap");
		return -EINVAL;
	}
	err = shadow_from(&s, d);
	if (err)
		return err;
	if (!n->stale && !n->ndirty && shadow_eq(&s, &n->sh)) {
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

	/*
	 * New mark chains, then the policy rules, rewritten. Stale (adopted
	 * chains not as made): the base chains are also defined again, which
	 * sets their policy back, and the jumps to restore_marks rewritten;
	 * dirty mark chains get their rules rewritten.
	 */
	tag = shadow_tag(&s);
	txn_begin(n, t);
	for (uint32_t i = 0; i < s.nmarks; i++) {
		if (!has_mark(&n->sh, s.marks[i])) {
			txn_mark_chain(n, t, s.fwmask, s.marks[i]);
		} else if (n->ndirty &&
		           bsearch(&s.marks[i], n->dirty, n->ndirty, sizeof(uint32_t), cmp_u32)) {
			mark_chain_name(name, s.marks[i]);
			txn_flush_chain(n, t, name);
			txn_mark_rules(n, t, name, s.fwmask, s.marks[i]);
		}
	}
	for (int i = 0; i < NFIXED; i++) {
		if (n->stale && fixed_chains[i].type)
			txn_fixed_chain(n, t, i);
		if (n->stale || (i != C_PRE_MANGLE && i != C_OUT_MANGLE)) {
			txn_flush_chain(n, t, fixed_chains[i].name);
			txn_fixed_rules(n, t, &s, i, tag);
		}
	}
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
#define ADOPT_TRIES		16

/*
 * What one reading of the table finds. It reads on a socket of its own,
 * closed when the reading ends or gives up, which ends a dump left unread:
 * the kernel produces the next part of a dump only when its socket is read,
 * so a dump stopped at a cap costs nothing more. Reading to the end instead
 * is unbounded (the maps have no size), and a dump left on the control
 * socket was read by the next transaction.
 */
struct readback {
	struct nft_ctx *n;
	struct mnl_socket *nl;
	uint32_t seq;
	mnl_cb_t cb;
	struct shadow s;		/* d's, with the mark chains found */
	uint32_t nobj, maxobj;		/* objects in this dump, and the cap */
	uint32_t version, fwmask, flags;	/* table */
	bool has_secret;
	uint8_t secret[NFT_SECRET_LEN];
	uint32_t fixed, maps;		/* bit i: fixed_chains[i], set_names[i] found */
	bool unusable;			/* a chain of ours that rules cannot repair */
	bool stale;			/* a fixed chain to rewrite */
	uint64_t ptag;			/* shadow_tag(&s) */
	struct {			/* per fixed chain, then per mark chain */
		uint32_t n;
		bool bad;		/* a rule without its tag */
	} *rules;
	int set;			/* map being dumped */
	struct nft_elem *v[2];		/* fake2real, fake2mark elements (both families) */
	uint32_t nv[2], cap[2], max_elems;
};

static bool too_many(struct readback *rb)
{
	errno = E2BIG;
	return ++rb->nobj > rb->maxobj;
}

/*
 * The value of the first TLV (type, length, value) of `type` and length
 * `vlen` in libnftnl userdata, or NULL. Bounds-checked: nftnl_udata_parse()
 * only checks where a TLV starts, and the kernel stores userdata as given.
 */
static const void *udata_get(const uint8_t *p, uint32_t len, uint8_t type, uint8_t vlen)
{
	for (uint32_t off = 0; off + 2 <= len && off + 2 + p[off + 1] <= len; off += 2 + p[off + 1])
		if (p[off] == type && p[off + 1] == vlen)
			return p + off + 2;
	return NULL;
}

static int table_cb(const struct nlmsghdr *nlh, void *priv)
{
	struct nftnl_table *t = oom(nftnl_table_alloc());
	struct readback *rb = priv;
	const void *u, *v;
	uint32_t len = 0;
	int r = nftnl_table_nlmsg_parse(nlh, t);

	u = r ? NULL : nftnl_table_get_data(t, NFTNL_TABLE_USERDATA, &len);
	if ((v = udata_get(u, len, UD_VERSION, 4)))
		memcpy(&rb->version, v, 4);
	if ((v = udata_get(u, len, UD_FWMASK, 4)))
		memcpy(&rb->fwmask, v, 4);
	if ((v = udata_get(u, len, UD_SECRET, NFT_SECRET_LEN)))
		memcpy(rb->secret, v, NFT_SECRET_LEN);
	rb->has_secret = v;
	rb->flags = r ? 0 : nftnl_table_get_u32(t, NFTNL_TABLE_FLAGS);
	nftnl_table_free(t);
	errno = EPROTO;
	return r ? MNL_CB_ERROR : MNL_CB_OK;
}

/* mark_%08x, exactly as mark_chain_name() prints it, valid for `fwmask` */
static bool parse_mark_chain(const char *name, uint32_t fwmask, uint32_t *v)
{
	char buf[32];
	unsigned long x;

	if (strncmp(name, "mark_", 5))
		return false;
	x = strtoul(name + 5, NULL, 16);
	mark_chain_name(buf, (uint32_t)x);
	if (strcmp(buf, name) || !x || (x & ~(unsigned long)fwmask))
		return false;
	*v = (uint32_t)x;
	return true;
}

/*
 * A fixed chain must be of its kind (base chains: type, hook, priority), a
 * mark chain a regular chain; else the chain cannot be repaired in place. A
 * base chain's policy can be: NEWCHAIN with the same hook updates it.
 */
static int chain_cb(const struct nlmsghdr *nlh, void *priv)
{
	struct nftnl_chain *c = oom(nftnl_chain_alloc());
	struct readback *rb = priv;
	const char *name, *table, *type;
	int r = MNL_CB_ERROR, i;
	bool base;
	uint32_t v;

	errno = EPROTO;
	if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
		goto out;
	r = MNL_CB_OK;
	table = nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE);
	name = nftnl_chain_get_str(c, NFTNL_CHAIN_NAME);
	if (!table || !name || strcmp(table, rb->n->table))
		goto out;
	if (too_many(rb)) {
		r = MNL_CB_ERROR;
		goto out;
	}
	base = nftnl_chain_is_set(c, NFTNL_CHAIN_HOOKNUM);
	type = nftnl_chain_get_str(c, NFTNL_CHAIN_TYPE);
	if ((i = fixed_index(name)) < NFIXED) {
		rb->fixed |= 1u << i;
		rb->unusable |= fixed_chains[i].type ? !base || !type ||
		        strcmp(type, fixed_chains[i].type) ||
		        nftnl_chain_get_u32(c, NFTNL_CHAIN_HOOKNUM) != (uint32_t)fixed_chains[i].hook ||
		        nftnl_chain_get_s32(c, NFTNL_CHAIN_PRIO) != fixed_chains[i].prio : base;
		rb->stale |= base && nftnl_chain_get_u32(c, NFTNL_CHAIN_POLICY) != NF_ACCEPT;
	}
	if (parse_mark_chain(name, rb->s.fwmask, &v)) {
		rb->unusable |= base;
		rb->s.marks[rb->s.nmarks++] = v;
	}
out:
	nftnl_chain_free(c);
	return r;
}

static int set_cb(const struct nlmsghdr *nlh, void *priv)
{
	struct nftnl_set *set = oom(nftnl_set_alloc());
	struct readback *rb = priv;
	const char *name;
	int r = MNL_CB_ERROR;

	errno = EPROTO;
	if (nftnl_set_nlmsg_parse(nlh, set) < 0 || too_many(rb))
		goto out;
	r = MNL_CB_OK;
	name = nftnl_set_get_str(set, NFTNL_SET_NAME);
	for (int i = 0; name && i < S_NUM; i++) {
		uint32_t def[4];
		bool ok = !strcmp(name, set_names[i]) &&
		          nftnl_set_get_u32(set, NFTNL_SET_FLAGS) == NFT_SET_MAP;

		/* the kernel reports a verdict map's data length as 16 */
		map_def(i, def);
		for (int k = 0; k < (i & 1 ? 3 : 4); k++)
			ok &= nftnl_set_get_u32(set, map_attrs[k]) == def[k];
		rb->maps |= (uint32_t)ok << i;
	}
out:
	nftnl_set_free(set);
	return r;
}

/* counts the rules of each chain of ours, and those lacking their tag */
static int rule_cb(const struct nlmsghdr *nlh, void *priv)
{
	struct nftnl_rule *r = oom(nftnl_rule_alloc());
	struct readback *rb = priv;
	const void *u, *utag;
	uint32_t len = 0, v, *m, i;
	const char *chain;
	uint64_t tag;

	if (too_many(rb)) {
		nftnl_rule_free(r);
		return MNL_CB_ERROR;
	}
	if (nftnl_rule_nlmsg_parse(nlh, r) < 0) {
		/* in a chain we cannot tell: rewrite them all */
		for (i = 0; i < NFIXED + rb->s.nmarks; i++)
			rb->rules[i].bad = true;
		goto out;
	}
	if (!(chain = nftnl_rule_get_str(r, NFTNL_RULE_CHAIN)))
		goto out;
	if ((i = (uint32_t)fixed_index(chain)) < NFIXED) {
		fixed_rules(&rb->s, (int)i, rb->ptag, &tag);
	} else if (parse_mark_chain(chain, rb->s.fwmask, &v) &&
	           (m = bsearch(&v, rb->s.marks, rb->s.nmarks, sizeof(v), cmp_u32))) {
		i = NFIXED + (uint32_t)(m - rb->s.marks);
		tag = own_tag(rb->s.fwmask, v);
	} else {
		goto out;	/* a foreign chain */
	}
	u = nftnl_rule_get_data(r, NFTNL_RULE_USERDATA, &len);
	utag = udata_get(u, len, UD_TAG, sizeof(tag));
	rb->rules[i].n++;
	rb->rules[i].bad |= !utag || memcmp(utag, &tag, sizeof(tag));
out:
	nftnl_rule_free(r);
	return MNL_CB_OK;
}

static int elem_one(struct nftnl_set_elem *e, void *priv)
{
	struct readback *rb = priv;
	int k = rb->set & 1;		/* fake2mark */
	uint32_t alen = rb->set >= S_REAL6 ? 16 : 4, len;
	const void *key = nftnl_set_elem_get(e, NFTNL_SET_ELEM_KEY, &len), *val;
	const char *chain;
	struct nft_elem *x;

	if (!key || len != alen)
		return 0;	/* not a key of ours: nothing we could destroy */
	if (rb->nv[k] == rb->max_elems) {
		errno = E2BIG;
		return -1;
	}
	if (rb->nv[k] == rb->cap[k]) {
		rb->cap[k] = rb->cap[k] ? rb->cap[k] * 2 : 256;
		rb->v[k] = oom(realloc(rb->v[k], rb->cap[k] * sizeof(*rb->v[k])));
	}
	x = &rb->v[k][rb->nv[k]++];
	memset(x, 0, sizeof(*x));
	x->family = alen == 16 ? 6 : 4;
	memcpy(x->fake, key, alen);
	if (!k) {
		val = nftnl_set_elem_get(e, NFTNL_SET_ELEM_DATA, &len);
		if ((x->ok = val && len == alen))
			memcpy(x->real, val, alen);
		return 0;
	}
	chain = nftnl_set_elem_get_str(e, NFTNL_SET_ELEM_CHAIN);
	x->ok = nftnl_set_elem_get_u32(e, NFTNL_SET_ELEM_VERDICT) == (uint32_t)NFT_JUMP &&
	        chain && parse_mark_chain(chain, rb->s.fwmask, &x->mark) &&
	        has_mark(&rb->s, x->mark);
	return 0;
}

static int elem_cb(const struct nlmsghdr *nlh, void *priv)
{
	struct nftnl_set *s = oom(nftnl_set_alloc());
	int r = nftnl_set_elems_nlmsg_parse(nlh, s);

	if (r < 0)
		errno = EPROTO;
	else
		r = nftnl_set_elem_foreach(s, elem_one, priv);
	nftnl_set_free(s);
	return r < 0 ? MNL_CB_ERROR : MNL_CB_OK;
}

static int dump_recv(void *priv, const char *buf, size_t len)
{
	struct readback *rb = priv;
	int r;

	errno = 0;
	r = mnl_cb_run(buf, len, rb->seq, mnl_socket_get_portid(rb->nl), rb->cb, rb);
	return r >= 0 ? r : errno ? -errno : -EPROTO;
}

/*
 * A GET of `type` in our table (attribute `tattr`; `set`: of that set's
 * elements), passing each reply to cb, at most `max` objects. 0, or -errno
 * (-ENOENT: no such object); a callback failing with errno set ends it.
 */
static int rb_get(struct readback *rb, int type, uint16_t flags, uint16_t tattr, const char *set,
                  mnl_cb_t cb, uint32_t max)
{
	char buf[DUMP_BUF];
	struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, type, NFPROTO_INET, flags,
	                                             rb->seq = rb->n->seq++);

	mnl_attr_put_strz(nlh, tattr, rb->n->table);
	if (set)
		mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, set);
	rb->cb = cb;
	rb->nobj = 0;
	rb->maxobj = max;
	if (mnl_socket_sendto(rb->nl, nlh, nlh->nlmsg_len) < 0)
		return -errno;
	return recv_loop(mnl_socket_get_fd(rb->nl), buf, sizeof(buf), false, dump_recv, rb);
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

/*
 * One reading of the table: 1 adopted, 0 not (logged), -EINTR if a commit
 * anywhere in the netns interrupted a dump (NLM_F_DUMP_INTR).
 */
static int adopt_read(struct nft_ctx *n, const struct nft_desired *d, uint32_t max_elems,
                      uint8_t secret[NFT_SECRET_LEN], struct nft_elem **elems, uint32_t *nelems)
{
	struct readback rb = { .n = n, .max_elems = max_elems };
	const char *why = "cannot read it";
	uint32_t *dirty = NULL, ndirty = 0, nr, i;
	struct nft_elem *out;
	uint64_t tag;
	int err = 0;

	if (shadow_from(&rb.s, d))
		return 0;
	free(rb.s.marks);
	rb.s.marks = oom(malloc(ADOPT_MAX_CHAINS * sizeof(uint32_t)));
	rb.s.nmarks = 0;
	rb.nl = mnl_socket_open(NETLINK_NETFILTER);
	if (!rb.nl || sock_setup(rb.nl))
		goto fail;
	err = rb_get(&rb, NFT_MSG_GETTABLE, NLM_F_ACK, NFTA_TABLE_NAME, NULL, table_cb, 1);
	if (err == -ENOENT) {
		log_info("nft: no table %s yet", n->table);
		goto fail_quiet;
	}
	if (err)
		goto fail;
	why = "made by another omnidns version";
	if (rb.version != NFT_LAYOUT_VERSION || !rb.has_secret)
		goto fail;
	why = "made for another fwmask";
	if (rb.fwmask != d->fwmask)
		goto fail;
	why = "dormant, or owned by a process";
	if (rb.flags)
		goto fail;

	/* kernels up to 6.18 at least ignore the table here and dump all chains */
	why = "cannot list its chains, or too many";
	if ((err = rb_get(&rb, NFT_MSG_GETCHAIN, NLM_F_DUMP, NFTA_CHAIN_TABLE, NULL, chain_cb,
	                  ADOPT_MAX_CHAINS)))
		goto fail;
	why = "a chain is missing, or has another type, hook or priority";
	if (rb.fixed != (1u << NFIXED) - 1 || rb.unusable)
		goto fail;
	why = "cannot list its maps";
	if ((err = rb_get(&rb, NFT_MSG_GETSET, NLM_F_DUMP, NFTA_SET_TABLE, NULL, set_cb,
	                  ADOPT_MAX_CHAINS)))
		goto fail;
	why = "a map is missing, or of another type";
	if (rb.maps != (1u << S_NUM) - 1)
		goto fail;

	/* each chain of ours: exactly the rules made for rb.s, else rewrite it */
	qsort(rb.s.marks, rb.s.nmarks, sizeof(uint32_t), cmp_u32);
	rb.ptag = shadow_tag(&rb.s);
	nr = NFIXED + rb.s.nmarks;
	rb.rules = oom(calloc(nr, sizeof(*rb.rules)));
	why = "cannot list its rules, or too many";
	if ((err = rb_get(&rb, NFT_MSG_GETRULE, NLM_F_DUMP, NFTA_RULE_TABLE, NULL, rule_cb,
	                  2 * ADOPT_MAX_CHAINS + 64)))
		goto fail;
	dirty = oom(malloc((rb.s.nmarks + 1) * sizeof(uint32_t)));
	for (i = 0; i < nr; i++) {
		if (!rb.rules[i].bad && rb.rules[i].n == (i < NFIXED ?
		    fixed_rules(&rb.s, (int)i, rb.ptag, &tag) : 2))
			continue;
		if (i < NFIXED)
			rb.stale = true;
		else
			dirty[ndirty++] = rb.s.marks[i - NFIXED];
	}

	why = "cannot list its maps, or more elements than fakeip_max_bindings allows";
	for (rb.set = 0; rb.set < S_NUM; rb.set++)
		if ((err = rb_get(&rb, NFT_MSG_GETSETELEM, NLM_F_DUMP, NFTA_SET_ELEM_LIST_TABLE,
		                  set_names[rb.set], elem_cb, UINT32_MAX)))
			goto fail;
	for (i = 0; i < 2; i++)
		if (rb.nv[i])
			qsort(rb.v[i], rb.nv[i], sizeof(*rb.v[i]), cmp_elem);
	out = oom(malloc(((size_t)rb.nv[0] + rb.nv[1] + 1) * sizeof(*out)));
	*nelems = pair_elems(rb.v[0], rb.nv[0], rb.v[1], rb.nv[1], out);
	*elems = out;

	rb.s.marks = oom(realloc(rb.s.marks, nr * sizeof(uint32_t)));
	state_set(n, &rb.s, rb.stale, dirty, ndirty);
	memcpy(n->secret, rb.secret, NFT_SECRET_LEN);
	memcpy(secret, rb.secret, NFT_SECRET_LEN);
	log_info("nft: adopting table %s: %u map elements, %u mark chains (%u to rewrite)%s",
	         n->table, *nelems, rb.s.nmarks, ndirty,
	         rb.stale ? ", other chains to rewrite" : "");
	err = 1;
	goto out;

fail:
	if (err != -EINTR)
		log_warn("nft: not adopting table %s (%s): it is recreated, its fake IPs are lost",
		         n->table, why);
fail_quiet:
	shadow_free(&rb.s);
	free(dirty);
	err = err == -EINTR ? -EINTR : 0;
out:
	free(rb.rules);
	free(rb.v[0]);
	free(rb.v[1]);
	if (rb.nl)
		mnl_socket_close(rb.nl);
	return err;
}

/*
 * A dump interrupted by a commit (in any table: fw4, dnsmasq's nftset,
 * mwan3) may be incomplete or mix two generations: the whole reading starts
 * over on a fresh socket, as nft does, at most ADOPT_TRIES times, after a
 * pause doubling from 1 ms up to 128 ms (about 1.2 s in all) to let a burst
 * of commits pass.
 */
int nft_adopt(struct nft_ctx *n, const struct nft_desired *d, uint32_t max_elems,
              uint8_t secret[NFT_SECRET_LEN], struct nft_elem **elems, uint32_t *nelems)
{
	int r;

	*elems = NULL;
	*nelems = 0;
	for (int i = 0; i < ADOPT_TRIES; i++) {
		if ((r = adopt_read(n, d, max_elems, secret, elems, nelems)) != -EINTR)
			return r;
		log_debug("nft: a dump of table %s was interrupted, reading it again", n->table);
		usleep(1000u << (i < 7 ? i : 7));
	}
	log_warn("nft: not adopting table %s (the ruleset kept changing while it was read): "
	         "it is recreated, its fake IPs are lost", n->table);
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
	/*
	 * Never empty: a batch is opened only by an op that queues elements
	 * before anything can flush it. As for control-plane transactions (see
	 * ctl_commit()), only the last message asks for an ack: the kernel reports a failing message, or a
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
 * by bumping the generation. Opens a batch if none is open.
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
	if (!n->open)
		n->open = batch_new(n);
	if (!add)
		return;
	for (s = h; n->pend_slot[s & (PENDING_SLOTS - 1)] >> 16 == n->pend_gen; s++)
		;
	n->pend_key[n->pend_n++] = k;
	n->pend_slot[s & (PENDING_SLOTS - 1)] = (uint32_t)n->pend_gen << 16 | n->pend_n;
}

/*
 * Every element op destroys the key first, through DESTROYSETELEM (kernel
 * >= 6.3, a delete that ignores missing keys): element ops are idempotent, a
 * key mapped to different data never fails with EEXIST, and a kernel state
 * that drifted from the binding DB (e.g. after a failed, rolled-back batch)
 * can never make later batches fail. `family` is 4/6 or AF_INET/AF_INET6.
 */
static uint64_t elem_op(struct nft_ctx *n, int family, const uint8_t *fake, bool add,
                        const uint8_t *real, uint32_t mark)
{
	bool v6 = family == 6 || family == AF_INET6;
	int rs = v6 ? S_REAL6 : S_REAL4, ms = v6 ? S_MARK6 : S_MARK4;
	uint32_t alen = v6 ? 16 : 4;

	if (!v6 && family != 4 && family != AF_INET) {
		log_err("nft: bad element family %d", family);
		return 0;
	}
	op_order_key(n, v6 ? AF_INET6 : AF_INET, fake, add);
	queue_elem(n, rs, false, fake, alen, NULL, 0);
	queue_elem(n, ms, false, fake, alen, NULL, 0);
	if (add) {
		queue_elem(n, rs, true, fake, alen, real, 0);
		queue_elem(n, ms, true, fake, alen, NULL, mark);
	}
	return op_done(n);
}

uint64_t nft_elem_add(struct nft_ctx *n, int family, const uint8_t *fake,
                      const uint8_t *real, uint32_t mark)
{
	return elem_op(n, family, fake, true, real, mark);
}

uint64_t nft_elem_del(struct nft_ctx *n, int family, const uint8_t *fake)
{
	return elem_op(n, family, fake, false, NULL, 0);
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

/* Read all pending acks until the socket would block; complete failed batches. */
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
				int err = errno;

				log_err("nft: async recv: %s", strerror(err));
				fail_inflight(n, -err);
			}
			break;
		}
		parse_acks(buf, (int)len, async_ack, n);
	}
	complete_failed(n);
}

static void async_fd_cb(struct uloop_fd *u, unsigned int events)
{
	async_read(container_of(u, struct nft_ctx, ufd));
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
	free(n->dirty);
	free(n->ctl_tx.b.p);
	free(n);
}
