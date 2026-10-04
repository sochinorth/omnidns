// SPDX-License-Identifier: GPL-2.0-only
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

#define NFT_TABLE_MAX	64
#define CHUNK_MAX	256		/* elements per NEWSETELEM/DELSETELEM msg */
#define BATCH_MSG_MAX	256		/* messages per async batch */
#define FAIL_RING	32
#define RECV_TIMEOUT_MS	10000
#define SOCK_BUF	(4 << 20)

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
};

/* One transaction under construction: BEGIN, msgs (all NLM_F_ACK), END. */
struct txn {
	struct nbuf b;
	uint32_t seq_first, seq_last, nmsg;
};

struct echunk {
	struct list_head list;
	int type;
	uint32_t n;
	struct nftnl_set *s;
};

struct ebatch {
	struct list_head list;
	uint64_t ticket;
	struct list_head chunks[S_NUM];
	uint32_t nops, nmsgs;
	uint32_t seq_first, seq_last, acks_left;
	int err;
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
	struct shadow sh;

	struct uloop_fd ufd;
	struct uloop_timeout submit_tmo, ready_tmo, kick_tmo;
	struct ebatch *open;
	struct list_head inflight;
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
	size_t cap = b->cap ? b->cap : 16384;

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
	return nftnl_nlmsg_build_hdr(t->b.p + t->b.len, type, NFPROTO_INET,
				     flags | NLM_F_ACK, n->seq++);
}

static void txn_table(struct nft_ctx *n, struct txn *t, int type, uint16_t flags)
{
	struct nftnl_table *tb = oom(nftnl_table_alloc());
	struct nlmsghdr *nlh;

	nftnl_table_set_str(tb, NFTNL_TABLE_NAME, n->table);
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
			     const uint32_t *marks, uint32_t nmarks)
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

	for (uint32_t i = 0; i < nmarks; i++) {
		struct nftnl_set_elem *e = oom(nftnl_set_elem_alloc());

		mark_chain_name(name, marks[i]);
		nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &marks[i], 4);
		nftnl_set_elem_set_u32(e, NFTNL_SET_ELEM_VERDICT, NFT_JUMP);
		nftnl_set_elem_set_str(e, NFTNL_SET_ELEM_CHAIN, name);
		nftnl_set_elem_add(s, e);
	}
	txn_elems(n, t, NFT_MSG_NEWSETELEM, s, nmarks);
	nftnl_set_free(s);

	r = rule_new(n, "restore_marks");
	e_ct(r, NFT_CT_MARK, false);
	e_bitwise(r, &mask, &zero, 4);
	e_lookup(r, "__map%d", id, NFT_REG_VERDICT);
	txn_rule(n, t, r);
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
			     const struct ip_prefix *p)
{
	bool v6 = p->family == AF_INET6;
	uint32_t off = v6 ? 24 : 16, alen = v6 ? 16 : 4;
	struct nftnl_rule *r;
	struct nftnl_expr *e;

	r = pool_rule(n, chain, p);
	e_payload(r, off, alen);
	e_lookup(r, set_names[v6 ? S_MARK6 : S_MARK4], 0, NFT_REG_VERDICT);
	txn_rule(n, t, r);

	r = pool_rule(n, chain, p);
	e_payload(r, off, alen);
	e_lookup(r, set_names[v6 ? S_REAL6 : S_REAL4], 0, NFT_REG_1);
	e = expr(r, "nat");
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_TYPE, NFT_NAT_DNAT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_FAMILY, v6 ? NFPROTO_IPV6 : NFPROTO_IPV4);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
	txn_rule(n, t, r);
}

static void txn_reject_rule(struct nft_ctx *n, struct txn *t, const char *chain,
			    const struct ip_prefix *p)
{
	struct nftnl_rule *r = pool_rule(n, chain, p);
	struct nftnl_expr *e = expr(r, "reject");

	/* icmp(v6) port-unreachable, as nft's plain `reject` in inet */
	nftnl_expr_set_u32(e, NFTNL_EXPR_REJECT_TYPE, NFT_REJECT_ICMP_UNREACH);
	nftnl_expr_set_u8(e, NFTNL_EXPR_REJECT_CODE, p->family == AF_INET6 ? 4 : 3);
	txn_rule(n, t, r);
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

/* Rules of restore_marks, *_dstnat and *_reject (chains assumed empty). */
static void txn_policy_rules(struct nft_ctx *n, struct txn *t, const struct shadow *s)
{
	if (s->nmarks)
		txn_restore_rule(n, t, s->fwmask, s->marks, s->nmarks);
	for (int i = 0; i < 2; i++) {
		if (s->has_pool4)
			txn_dstnat_rules(n, t, dstnat_chains[i], &s->pool4);
		if (s->has_pool6)
			txn_dstnat_rules(n, t, dstnat_chains[i], &s->pool6);
		if (s->has_pool4)
			txn_reject_rule(n, t, reject_chains[i], &s->pool4);
		if (s->has_pool6)
			txn_reject_rule(n, t, reject_chains[i], &s->pool6);
	}
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

struct sync_state {
	uint32_t first, last, left;
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
	if (st->left)
		st->left--;
	return st->left > 0;
}

static int ctl_commit(struct nft_ctx *n, struct txn *t, const char *what)
{
	struct sync_state st = { t->seq_first, t->seq_last, t->nmsg, 0 };
	int fd = mnl_socket_get_fd(n->ctl);
	char buf[16384];

	if (mnl_socket_sendto(n->ctl, t->b.p, t->b.len) < 0) {
		st.err = -errno;
		goto out;
	}
	while (st.left && !st.err) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t len;

		if (poll(&pfd, 1, RECV_TIMEOUT_MS) <= 0) {
			st.err = -ETIMEDOUT;
			break;
		}
		len = recv(fd, buf, sizeof(buf), 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			st.err = -errno;
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

static bool has_mark(const struct shadow *s, uint32_t v)
{
	return bsearch(&v, s->marks, s->nmarks, sizeof(v), cmp_u32) != NULL;
}

/* ---- control plane ---- */

int nft_bootstrap(struct nft_ctx *n, const struct nft_desired *d)
{
	struct txn *t = &n->ctl_tx;
	struct shadow s;
	int err;

	err = shadow_from(&s, d);
	if (err)
		return err;
	txn_begin(n, t);
	/* add+delete: "delete if exists" */
	txn_table(n, t, NFT_MSG_NEWTABLE, NLM_F_CREATE);
	txn_table(n, t, NFT_MSG_DELTABLE, 0);
	txn_table(n, t, NFT_MSG_NEWTABLE, NLM_F_CREATE);
	txn_maps(n, t);
	for (uint32_t i = 0; i < s.nmarks; i++)
		txn_mark_chain(n, t, s.fwmask, s.marks[i]);
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
	txn_policy_rules(n, t, &s);
	txn_end(n, t);

	err = ctl_commit(n, t, "bootstrap");
	if (err) {
		shadow_free(&s);
		return err;
	}
	shadow_free(&n->sh);
	n->sh = s;
	n->have_state = true;
	return 0;
}

int nft_reconcile(struct nft_ctx *n, const struct nft_desired *d)
{
	struct txn *t = &n->ctl_tx;
	struct shadow s;
	char name[32];
	bool remask;
	int err;

	if (!n->have_state) {
		log_err("nft: reconcile before bootstrap");
		return -EINVAL;
	}
	err = shadow_from(&s, d);
	if (err)
		return err;
	remask = s.fwmask != n->sh.fwmask;

	txn_begin(n, t);
	for (uint32_t i = 0; i < s.nmarks; i++) {
		if (!has_mark(&n->sh, s.marks[i])) {
			txn_mark_chain(n, t, s.fwmask, s.marks[i]);
		} else if (remask) {
			mark_chain_name(name, s.marks[i]);
			txn_flush_chain(n, t, name);
			txn_mark_rules(n, t, name, s.fwmask, s.marks[i]);
		}
	}
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

	err = ctl_commit(n, t, "reconcile");
	if (err) {
		shadow_free(&s);
		return err;
	}
	shadow_free(&n->sh);
	n->sh = s;
	return 0;
}

int nft_destroy_table(struct nft_ctx *n)
{
	struct txn *t = &n->ctl_tx;
	int err;

	txn_begin(n, t);
	txn_table(n, t, NFT_MSG_NEWTABLE, NLM_F_CREATE);
	txn_table(n, t, NFT_MSG_DELTABLE, 0);
	txn_end(n, t);
	err = ctl_commit(n, t, "destroy table");
	if (!err) {
		shadow_free(&n->sh);
		n->have_state = false;
	}
	return err;
}

/* ---- async element batches ---- */

static struct ebatch *batch_new(struct nft_ctx *n)
{
	struct ebatch *b = oom(calloc(1, sizeof(*b)));

	b->ticket = n->next_ticket++;
	for (int i = 0; i < S_NUM; i++)
		INIT_LIST_HEAD(&b->chunks[i]);
	return b;
}

static void batch_free(struct ebatch *b)
{
	for (int i = 0; i < S_NUM; i++) {
		struct echunk *c, *tmp;

		list_for_each_entry_safe(c, tmp, &b->chunks[i], list) {
			nftnl_set_free(c->s);
			free(c);
		}
	}
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
	batch_free(b);
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

static void batch_build(struct nft_ctx *n, struct ebatch *b, struct txn *t)
{
	txn_begin(n, t);
	for (int i = 0; i < S_NUM; i++) {
		struct echunk *c;

		list_for_each_entry(c, &b->chunks[i], list)
			txn_elems(n, t, c->type, c->s, c->n);
	}
	txn_end(n, t);
}

void nft_flush(struct nft_ctx *n)
{
	struct ebatch *b = n->open;
	struct txn t = { 0 };

	uloop_timeout_cancel(&n->submit_tmo);
	if (!b)
		return;
	n->open = NULL;
	batch_build(n, b, &t);
	b->seq_first = t.seq_first;
	b->seq_last = t.seq_last;
	b->acks_left = t.nmsg;
	list_add_tail(&b->list, &n->inflight);
	if (mnl_socket_sendto(n->async, t.b.p, t.b.len) < 0) {
		b->err = -errno;
		uloop_timeout_set(&n->kick_tmo, 0);
	}
	free(t.b.p);
}

static void submit_cb(struct uloop_timeout *tmo)
{
	nft_flush(container_of(tmo, struct nft_ctx, submit_tmo));
}

static void append_elem(struct nft_ctx *n, int set, int type, struct nftnl_set_elem *e)
{
	struct ebatch *b = n->open;
	struct list_head *head = &b->chunks[set];
	struct echunk *c = NULL;

	if (!list_empty(head))
		c = list_last_entry(head, struct echunk, list);
	if (!c || c->type != type || c->n >= CHUNK_MAX) {
		c = oom(calloc(1, sizeof(*c)));
		c->type = type;
		c->s = oom(nftnl_set_alloc());
		nftnl_set_set_str(c->s, NFTNL_SET_TABLE, n->table);
		nftnl_set_set_str(c->s, NFTNL_SET_NAME, set_names[set]);
		list_add_tail(&c->list, head);
		b->nmsgs++;
	}
	nftnl_set_elem_add(c->s, e);
	c->n++;
}

static struct nftnl_set_elem *elem_key(const uint8_t *key, uint32_t len)
{
	struct nftnl_set_elem *e = oom(nftnl_set_elem_alloc());

	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, key, len);
	return e;
}

static void queue_del(struct nft_ctx *n, int real, int mark, const uint8_t *fake,
		      uint32_t alen)
{
	append_elem(n, real, NFT_MSG_DELSETELEM, elem_key(fake, alen));
	append_elem(n, mark, NFT_MSG_DELSETELEM, elem_key(fake, alen));
}

static uint64_t op_done(struct nft_ctx *n)
{
	struct ebatch *b = n->open;
	uint64_t ticket = b->ticket;

	b->nops++;
	if (b->nops >= NFT_BATCH_MAX || b->nmsgs >= BATCH_MSG_MAX)
		nft_flush(n);
	else if (b->nops == 1)
		uloop_timeout_set(&n->submit_tmo, 0);
	return ticket;
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

/*
 * Adds use NLM_F_CREATE without EXCL: re-adding an identical element is a
 * no-op, but a key already mapped to different data fails (EEXIST). Hence
 * `replace`, which deletes the key from both maps first. A delete of a
 * missing key fails with ENOENT and aborts the whole batch, so callers
 * must only pass replace=true when the element is known to exist.
 */
uint64_t nft_elem_add(struct nft_ctx *n, int family, const uint8_t *fake,
		      const uint8_t *real, uint32_t mark, bool replace)
{
	bool v6 = family == AF_INET6;
	int rs = v6 ? S_REAL6 : S_REAL4, ms = v6 ? S_MARK6 : S_MARK4;
	uint32_t alen = v6 ? 16 : 4;
	struct nftnl_set_elem *e;
	char chain[32];

	if (!op_begin(n, family))
		return 0;
	if (replace)
		queue_del(n, rs, ms, fake, alen);

	e = elem_key(fake, alen);
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_DATA, real, alen);
	append_elem(n, rs, NFT_MSG_NEWSETELEM, e);

	mark_chain_name(chain, mark);
	e = elem_key(fake, alen);
	nftnl_set_elem_set_u32(e, NFTNL_SET_ELEM_VERDICT, NFT_JUMP);
	nftnl_set_elem_set_str(e, NFTNL_SET_ELEM_CHAIN, chain);
	append_elem(n, ms, NFT_MSG_NEWSETELEM, e);
	return op_done(n);
}

uint64_t nft_elem_del(struct nft_ctx *n, int family, const uint8_t *fake)
{
	bool v6 = family == AF_INET6;

	if (!op_begin(n, family))
		return 0;
	queue_del(n, v6 ? S_REAL6 : S_REAL4, v6 ? S_MARK6 : S_MARK4, fake,
		  v6 ? 16 : 4);
	return op_done(n);
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
		if (err)
			batch_complete(n, b, err);
		else if (!--b->acks_left)
			batch_complete(n, b, 0);
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
		batch_free(n->open);
	list_for_each_entry_safe(b, tmp, &n->inflight, list)
		batch_free(b);
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
