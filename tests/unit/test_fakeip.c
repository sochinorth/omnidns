// SPDX-License-Identifier: MIT
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

#include "test.h"
#include "fakeip.h"
#include "nft.h"
#include "util/hash.h"
#include "util/time.h"

#define PIN_V4 0x5ad003565eae26dbull
#define PIN_V4_0 0xc6120708
#define PIN_V4_1 0xc6120729
#define PIN_V4_2 0xc61207fb
#define PIN_V4_3 0xc6120796
#define PIN_V6_80 0x7ed8b11c88d6aa37ull
#define PIN_V6_48 0x79d624e34f225742ull
#define PIN_V6_120 0x4a7d7670eeea6cd1ull
#define PIN_RECLAIM 0xd67ef546d77e254dull
#define PIN_RELOAD 0x99c5b34e1f26e159ull

/* ---- nft stubs with a model of the kernel maps ---- */

struct kelem {
	int family;
	uint8_t fake[16];
	uint32_t mark;
	uint64_t ticket;
};

#define KMAX 8192
static struct kelem kern[KMAX];
static uint32_t n_kern;
static uint32_t n_add, n_add_replace, n_del, kern_bad;
static uint64_t cur_ticket = 1;
static void (*fail_fn)(void *priv, uint64_t ticket, int err);
static void *fail_priv;
static int nft_dummy;
static bool kern_off;	/* skip the kernel model (linear) in huge tests */
#define NFT ((struct nft_ctx *)&nft_dummy)

static int alen(int family)
{
	return family == 4 ? 4 : 16;
}

static int kern_find(int family, const uint8_t *fake)
{
	uint32_t i;

	for (i = 0; i < n_kern; i++)
		if (kern[i].family == family && !memcmp(kern[i].fake, fake, alen(family)))
			return i;
	return -1;
}

static void kern_remove(uint32_t i)
{
	kern[i] = kern[--n_kern];
}

/* an add destroys any element of the key first: n_add_replace counts those */
uint64_t nft_elem_add(struct nft_ctx *n, int family, const uint8_t *fake,
                      const uint8_t *real, uint32_t mark)
{
	int i;

	n_add++;
	if (kern_off)
		return cur_ticket;
	i = kern_find(family, fake);
	if (n != NFT || (family != 4 && family != 6))
		kern_bad++;
	if (i >= 0) {
		n_add_replace++;
		kern_remove(i);
	}
	if (n_kern == KMAX) {
		kern_bad++;
		return cur_ticket;
	}
	kern[n_kern].family = family;
	memset(kern[n_kern].fake, 0, 16);
	memcpy(kern[n_kern].fake, fake, alen(family));
	kern[n_kern].mark = mark;
	kern[n_kern].ticket = cur_ticket;
	n_kern++;
	return cur_ticket;
}

uint64_t nft_elem_del(struct nft_ctx *n, int family, const uint8_t *fake)
{
	int i;

	n_del++;
	if (kern_off)
		return cur_ticket;
	i = kern_find(family, fake);
	if (i < 0)
		kern_bad++;
	else
		kern_remove(i);
	return cur_ticket;
}

void nft_set_fail_hook(struct nft_ctx *n, void (*fn)(void *priv, uint64_t ticket, int err),
                       void *priv)
{
	fail_fn = fn;
	fail_priv = priv;
}

/* marks without a chain (deleted by an fwmask change) */
static uint32_t dead_mark = 0xdead;

bool nft_mark_known(const struct nft_ctx *n, uint32_t mark)
{
	return mark != dead_mark;
}

bool nft_ticket_done(const struct nft_ctx *n, uint64_t ticket)
{
	return ticket < cur_ticket;
}

/* the batch failed: the kernel never saw its adds */
static void fail_batch(uint64_t ticket)
{
	uint32_t i = 0;

	while (i < n_kern) {
		if (kern[i].ticket == ticket)
			kern_remove(i);
		else
			i++;
	}
	fail_fn(fail_priv, ticket, -EINVAL);
}

static void reset(void)
{
	n_kern = n_add = n_add_replace = n_del = kern_bad = 0;
	kern_off = false;
	cur_ticket = 1;
	time_override_set(1000);
}

/* ---- helpers ---- */

static const uint8_t SECRET[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

static struct ip_prefix pfx(const char *addr, int plen)
{
	struct ip_prefix p = { 0 };

	if (inet_pton(AF_INET, addr, p.addr) == 1) {
		p.family = AF_INET;
	} else {
		inet_pton(AF_INET6, addr, p.addr);
		p.family = AF_INET6;
	}
	p.plen = plen;
	return p;
}

static uint8_t wire_len;
static uint8_t *wire(const char *name)
{
	static uint8_t buf[256];
	uint8_t *lp = buf, *p = buf + 1;

	for (; *name; name++) {
		if (*name == '.') {
			*lp = p - lp - 1;
			lp = p++;
		} else {
			*p++ = *name;
		}
	}
	*lp = p - lp - 1;
	*p++ = 0;
	wire_len = p - buf;
	return buf;
}

static struct binding *bind4(struct fakeip_db *db, const char *rule, uint32_t mark,
                             const char *name, uint32_t real, uint32_t ttl, int *err)
{
	uint8_t r[4];
	uint8_t *w = wire(name);

	real = htonl(real);
	memcpy(r, &real, 4);
	*err = 0;
	return fakeip_bind(db, rule, mark, w, wire_len, 4, r, ttl, err);
}

static struct binding *bind6(struct fakeip_db *db, const char *rule, uint32_t mark,
                             const char *name, uint32_t real, uint32_t ttl, int *err)
{
	uint8_t r[16] = { 0x20, 0x01, 0x0d, 0xb8 };
	uint8_t *w = wire(name);

	memcpy(r + 12, &real, 4);
	*err = 0;
	return fakeip_bind(db, rule, mark, w, wire_len, 6, r, ttl, err);
}

static uint32_t fake4(const struct binding *b)
{
	uint32_t v;

	memcpy(&v, b->fake, 4);
	return ntohl(v);
}

/* in the prefix and not an excluded address */
static bool allocatable(const struct ip_prefix *p, const struct binding *b)
{
	if (b->family == 4) {
		uint32_t base, a = fake4(b), hmask = p->plen ? (1u << (32 - p->plen)) - 1 : ~0u;

		memcpy(&base, p->addr, 4);
		base = ntohl(base);
		return (a & ~hmask) == base && (a & hmask) && (a & hmask) != hmask;
	}
	for (int i = 0; i < 16; i++) {
		int bits = p->plen - 8 * i;
		uint8_t m = bits >= 8 ? 0xff : bits <= 0 ? 0 : (uint8_t)(0xff00 >> bits);

		if ((b->fake[i] ^ p->addr[i]) & m)
			return false;
	}
	for (int i = 0; i < 16; i++)
		if (b->fake[i] != p->addr[i])
			return true;
	return false;	/* subnet-router anycast */
}

/* ---- tests ---- */

TEST(determinism)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	uint8_t other[16] = { 16, 15, 14 };
	struct fakeip_db *a, *b, *c;
	struct binding *x, *y, *z;
	int err, differ = 0;

	reset();
	a = fakeip_new(&p4, NULL, 1000, 600, SECRET, NFT);
	b = fakeip_new(&p4, NULL, 1000, 600, SECRET, NFT);
	c = fakeip_new(&p4, NULL, 1000, 600, other, NFT);
	REQUIRE(a && b && c);
	for (uint32_t i = 0; i < 16; i++) {
		char name[32];

		snprintf(name, sizeof(name), "host%u.example.com", i);
		x = bind4(a, "r1", 0x100, name, 0x01020300 + i, 60, &err);
		y = bind4(b, "r1", 0x100, name, 0x01020300 + i, 60, &err);
		z = bind4(c, "r1", 0x100, name, 0x01020300 + i, 60, &err);
		REQUIRE(x && y && z);
		CHECK(!memcmp(x->fake, y->fake, 4));
		CHECK(allocatable(&p4, x));
		CHECK(allocatable(&p4, z));
		differ += !!memcmp(x->fake, z->fake, 4);
	}
	CHECK(differ >= 15);
	CHECK(!fakeip_has_pool(a, 6));
	CHECK(fakeip_has_pool(a, 4));
	x = bind6(a, "r1", 0, "v6.example", 1, 60, &err);
	CHECK(!x);
	CHECK_EQ(err, -EAFNOSUPPORT);
	fakeip_free(a);
	fakeip_free(b);
	fakeip_free(c);
	/* three DBs share one kernel model here: kern_bad is meaningless */
}

TEST(exclusions)
{
	struct ip_prefix p30 = pfx("10.0.0.0", 30), p31 = pfx("10.0.0.0", 31);
	struct fakeip_db *db;
	struct binding *a, *b;
	uint8_t sec[16];
	int err;

	reset();
	for (int s = 0; s < 64; s++) {
		memset(sec, s, sizeof(sec));
		db = fakeip_new(&p30, NULL, 100, 0, sec, NFT);
		a = bind4(db, "r", 0, "a.example", 1, 60, &err);
		b = bind4(db, "r", 0, "b.example", 1, 60, &err);
		REQUIRE(a && b);
		CHECK(fake4(a) == 0x0a000001 || fake4(a) == 0x0a000002);
		CHECK(fake4(b) == 0x0a000001 || fake4(b) == 0x0a000002);
		CHECK(fake4(a) != fake4(b));
		CHECK(!bind4(db, "r", 0, "c.example", 1, 60, &err));
		CHECK_EQ(err, -ENOSPC);
		CHECK_EQ(fakeip_count(db), 2);
		fakeip_free(db);
	}
	db = fakeip_new(&p31, NULL, 100, 0, SECRET, NFT);
	CHECK(!bind4(db, "r", 0, "a.example", 1, 60, &err));
	CHECK_EQ(err, -ENOSPC);
	fakeip_free(db);
}

TEST(renewal)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, 100, 600, SECRET, NFT);
	struct binding *a, *b;
	int err;

	reset();
	a = bind4(db, "r", 0, "a.example", 1, 60, &err);
	REQUIRE(a);
	CHECK_EQ(a->safe_until, 1660);
	CHECK_EQ(n_add, 1);
	time_override_advance(100);
	b = bind4(db, "r", 0, "a.example", 1, 60, &err);
	CHECK(a == b);
	CHECK_EQ(a->safe_until, 1760);
	b = bind4(db, "r", 0, "a.example", 1, 0, &err);
	CHECK(a == b);
	CHECK_EQ(a->safe_until, 1760);
	b = bind4(db, "r", 0, "a.example", 1, UINT32_MAX, &err);
	CHECK_EQ(a->safe_until, UINT32_MAX);
	CHECK_EQ(n_add, 1);
	CHECK_EQ(n_del, 0);
	/* expired but not evicted: renewal revives it */
	b = bind4(db, "r", 0, "b.example", 1, 0, &err);
	time_override_advance(1000);
	CHECK_EQ(fakeip_live_count(db), 1);
	CHECK(bind4(db, "r", 0, "b.example", 1, 10, &err) == b);
	CHECK_EQ(fakeip_live_count(db), 2);
	CHECK_EQ(n_add, 2);
	fakeip_free(db);
}

TEST(reclaim)
{
	struct ip_prefix p30 = pfx("10.0.0.0", 30);
	struct fakeip_db *db = fakeip_new(&p30, NULL, 100, 0, SECRET, NFT);
	struct binding *a, *b, *c, *d;
	uint32_t it = 0, seen = 0;
	int err;

	reset();
	a = bind4(db, "r", 0, "a.example", 1, 10, &err);
	b = bind4(db, "r", 0, "b.example", 1, 20, &err);
	REQUIRE(a && b);
	CHECK(!bind4(db, "r", 0, "c.example", 1, 10, &err));
	time_override_advance(10);	/* a: safe_until == now, still live */
	CHECK(!bind4(db, "r", 0, "c.example", 1, 10, &err));
	time_override_advance(1);	/* a expired */
	uint32_t afake = fake4(a);
	c = bind4(db, "r", 0, "c.example", 1, 10, &err);
	REQUIRE(c);
	CHECK_EQ(fake4(c), afake);
	CHECK_EQ(n_add, 3);
	CHECK_EQ(n_add_replace, 1);
	CHECK_EQ(n_del, 0);
	CHECK_EQ(fakeip_count(db), 2);
	CHECK(fakeip_lookup(db, 4, c->fake) == c);
	while ((d = fakeip_next(db, &it)))
		seen |= (d == b) | (d == c) << 1;
	CHECK_EQ(seen, 3);
	CHECK_EQ(kern_bad, 0);
	CHECK_EQ(n_kern, 2);
	fakeip_free(db);
}

TEST(pins)
{
	struct ip_prefix p30 = pfx("10.0.0.0", 30), p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p30, NULL, 100, 0, SECRET, NFT);
	struct binding *a, *b, *c, *bs[5];
	int err;

	reset();
	a = bind4(db, "r", 0, "a.example", 1, 1, &err);
	b = bind4(db, "r", 0, "b.example", 1, 1, &err);
	REQUIRE(a && b);
	fakeip_ref(a);
	fakeip_ref(b);
	fakeip_ref(b);
	time_override_advance(100);
	CHECK_EQ(fakeip_live_count(db), 2);
	CHECK(!bind4(db, "r", 0, "c.example", 1, 1, &err));
	CHECK_EQ(err, -ENOSPC);
	fakeip_unref(db, b);
	CHECK(!bind4(db, "r", 0, "c.example", 1, 1, &err));
	uint32_t bfake = fake4(b);
	fakeip_unref(db, b);
	CHECK_EQ(fakeip_live_count(db), 1);
	c = bind4(db, "r", 0, "c.example", 1, 1, &err);
	REQUIRE(c);
	CHECK_EQ(fake4(c), bfake);
	fakeip_unref(db, a);
	fakeip_free(db);

	/* capacity eviction respects pins */
	reset();
	db = fakeip_new(&p4, NULL, 4, 0, SECRET, NFT);
	for (int i = 0; i < 4; i++) {
		char name[16];

		snprintf(name, sizeof(name), "h%d", i);
		bs[i] = bind4(db, "r", 0, name, 1, 1, &err);
		REQUIRE(bs[i]);
		fakeip_ref(bs[i]);
	}
	time_override_advance(10);
	CHECK(!bind4(db, "r", 0, "h4", 1, 1, &err));
	CHECK_EQ(err, -ENOSPC);
	CHECK_EQ(n_del, 0);
	fakeip_unref(db, bs[2]);
	bs[4] = bind4(db, "r", 0, "h4", 1, 1, &err);
	REQUIRE(bs[4]);
	CHECK_EQ(n_del, 1);
	CHECK_EQ(fakeip_count(db), 4);
	CHECK(fakeip_lookup(db, 4, bs[0]->fake) == bs[0]);
	CHECK(fakeip_lookup(db, 4, bs[4]->fake) == bs[4]);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

TEST(keys)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, 100, 0, SECRET, NFT);
	struct binding *b[8];
	char rule[8];
	int err;

	reset();
	b[0] = bind4(db, "r1", 1, "www.Example.com", 0x01020304, 10, &err);
	b[1] = bind4(db, "r2", 1, "www.Example.com", 0x01020304, 10, &err);
	b[2] = bind4(db, "r1", 2, "www.Example.com", 0x01020304, 10, &err);
	b[3] = bind4(db, "r1", 1, "www.example.org", 0x01020304, 10, &err);
	b[4] = bind4(db, "r1", 1, "www.Example.com", 0x01020305, 10, &err);
	strcpy(rule, "r1");
	b[5] = bind4(db, rule, 1, "WWW.EXAMPLE.COM", 0x01020304, 10, &err);
	b[6] = bind4(db, "r1", 1, "www.example.com", 0x01020304, 10, &err);
	for (int i = 0; i < 7; i++)
		REQUIRE(b[i]);
	CHECK(b[5] == b[0]);
	CHECK(b[6] == b[0]);
	for (int i = 0; i < 5; i++)
		for (int j = i + 1; j < 5; j++)
			CHECK(b[i] != b[j] && memcmp(b[i]->fake, b[j]->fake, 4));
	CHECK_EQ(fakeip_count(db), 5);
	CHECK_STR(fakeip_rule_id(db, b[0]), "r1");
	CHECK_STR(fakeip_rule_id(db, b[2]), "r1");
	CHECK_EQ(fakeip_mark(db, b[2]), 2);
	CHECK(b[0]->policy != b[2]->policy);
	CHECK_STR(fakeip_rule_id(db, b[1]), "r2");
	CHECK_EQ(fakeip_policy_count(db), 3);
	CHECK_EQ(fakeip_policy_refs(db, "r1", 1), 3);
	CHECK(!memcmp(b[0]->endpoint, "\3www\7example\3com", 17));
	CHECK_EQ(b[0]->endpoint_len, 17);
	CHECK(fakeip_in_pool(db, 4, b[0]->fake));
	CHECK(fakeip_in_pool(db, AF_INET, (const uint8_t *)"\xc6\x13\xff\xff"));
	CHECK(!fakeip_in_pool(db, 4, (const uint8_t *)"\xc6\x14\0\0"));
	CHECK(!fakeip_lookup(db, 4, (const uint8_t *)"\xc6\x14\0\0"));
	CHECK(fakeip_lookup(db, AF_INET, b[3]->fake) == b[3]);
	fakeip_free(db);
}

static void check_v6(const char *base, int plen)
{
	struct ip_prefix p6 = pfx(base, plen);
	struct fakeip_db *db = fakeip_new(NULL, &p6, 100000, 0, SECRET, NFT);
	struct binding *b;
	uint32_t ok = 0, i;
	int err = 0;

	for (i = 0; i < 400; i++) {
		char name[16];

		snprintf(name, sizeof(name), "h%u", i);
		b = bind6(db, "r", 0, name, i, 60, &err);
		if (!b)
			break;
		ok++;
		CHECK(allocatable(&p6, b));
		CHECK(fakeip_in_pool(db, 6, b->fake));
		CHECK(fakeip_lookup(db, AF_INET6, b->fake) == b);
		CHECK_EQ(b->family, 6);
		if (plen <= 64)
			CHECK(!memcmp(b->fake, p6.addr, 8));	/* low 2^64 only */
	}
	if (plen == 120) {
		CHECK(ok <= 255);
		CHECK(ok >= 200);
		CHECK_EQ(err, -ENOSPC);
	} else {
		CHECK_EQ(ok, 400);
	}
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

TEST(v6_pools)
{
	reset();
	check_v6("64:ff9b:1::", 48);
	reset();
	check_v6("fd00:1:2:3:4:5:6:0", 120);
	reset();
	check_v6("fd00::", 8);
	reset();
	check_v6("fd00:1:2:3::", 64);
}

TEST(fail_hook)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, 100, 0, SECRET, NFT);
	struct binding *a, *b, *c, *a2;
	int err;

	reset();
	cur_ticket = 5;
	a = bind4(db, "r", 7, "a.example", 1, 60, &err);
	b = bind4(db, "r", 8, "b.example", 1, 60, &err);
	cur_ticket = 6;
	c = bind4(db, "r", 7, "c.example", 1, 60, &err);
	REQUIRE(a && b && c);
	CHECK_EQ(a->ticket, 5);
	CHECK_EQ(c->ticket, 6);
	/* renewal keeps the installing ticket */
	CHECK(bind4(db, "r", 7, "a.example", 1, 60, &err) == a);
	CHECK_EQ(a->ticket, 5);
	fakeip_ref(a);
	uint8_t afake[4];
	memcpy(afake, a->fake, 4);
	fail_batch(5);
	CHECK_EQ(n_del, 0);
	CHECK_EQ(fakeip_count(db), 1);
	CHECK(!fakeip_lookup(db, 4, afake));
	CHECK(fakeip_lookup(db, 4, c->fake) == c);
	CHECK_STR(fakeip_rule_id(db, a), "r");
	CHECK_EQ(fakeip_mark(db, a), 7);	/* detached but still valid while referenced */
	a2 = bind4(db, "r", 7, "a.example", 1, 60, &err);
	REQUIRE(a2);
	CHECK(a2 != a);
	CHECK_EQ(a2->ticket, 6);
	CHECK(!memcmp(a2->fake, afake, 4));	/* deterministic */
	fakeip_unref(db, a);
	CHECK_EQ(n_add, 4);
	CHECK_EQ(n_kern, 2);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

TEST(set_config)
{
	struct ip_prefix p15 = pfx("198.18.0.0", 15), p16 = pfx("198.18.0.0", 16);
	struct ip_prefix p6 = pfx("64:ff9b:1::", 48);
	struct fakeip_db *db = fakeip_new(&p15, &p6, 100, 0, SECRET, NFT);
	struct binding *b, *v6;
	uint32_t it, in = 0, out = 0;
	uint8_t hi[4] = { 198, 19, 0, 1 };
	int err;

	reset();
	for (int i = 0; i < 20; i++) {
		char name[16];

		snprintf(name, sizeof(name), "h%d", i);
		b = bind4(db, "r", 0, name, 1, i < 10 ? 10 : 1000, &err);
		REQUIRE(b);
	}
	v6 = bind6(db, "r", 0, "six", 1, 10, &err);
	REQUIRE(v6);
	it = 0;
	while ((b = fakeip_next(db, &it)))
		if (b->family == 4)
			*(b->fake[1] == 18 ? &in : &out) += 1;
	REQUIRE(in && out);
	/* live bindings outside the shrunk pool */
	time_override_advance(100);
	CHECK_EQ(fakeip_set_config(db, &p16, &p6, 50, 5), -EBUSY);
	CHECK_EQ(fakeip_count(db), 21);
	CHECK_EQ(n_del, 0);
	CHECK(fakeip_in_pool(db, 4, hi));
	/* removing the v6 pool: v6 binding is expired, fine; v4 still busy */
	CHECK_EQ(fakeip_set_config(db, &p15, NULL, 100, 0), 0);
	CHECK_EQ(n_del, 1);
	CHECK(!fakeip_has_pool(db, 6));
	CHECK_EQ(fakeip_count(db), 20);
	v6 = NULL;
	CHECK_EQ(fakeip_set_config(db, &p15, &p6, 100, 0), 0);
	v6 = bind6(db, "r", 0, "six", 1, 10, &err);
	REQUIRE(v6);
	CHECK_EQ(fakeip_set_config(db, &p15, NULL, 100, 0), -EBUSY);
	CHECK(fakeip_has_pool(db, 6));
	/* everything expired: shrink evicts the outside ones only */
	time_override_advance(2000);
	n_del = 0;
	CHECK_EQ(fakeip_live_count(db), 0);
	uint32_t before = fakeip_count(db);
	CHECK_EQ(fakeip_set_config(db, &p16, &p6, 100, 5), 0);
	CHECK_EQ(n_del, out);
	CHECK_EQ(fakeip_count(db), before - out);
	CHECK(!fakeip_in_pool(db, 4, hi));
	it = 0;
	while ((b = fakeip_next(db, &it)))
		CHECK(b->family == 6 || b->fake[1] == 18);
	b = bind4(db, "r", 0, "new", 1, 10, &err);
	REQUIRE(b);
	CHECK_EQ(b->fake[1], 18);
	CHECK_EQ(b->safe_until, omni_now() + 15);
	/* shrinking max_bindings evicts expired ones */
	CHECK_EQ(fakeip_set_config(db, &p16, &p6, 4, 5), 0);
	CHECK(fakeip_count(db) <= 4);
	CHECK(fakeip_lookup(db, 4, b->fake) == b);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

TEST(stale_mark)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, 100, 0, SECRET, NFT);
	int err = 0;

	reset();
	REQUIRE(bind4(db, "r", 7, "a.example", 1, 60, &err));
	CHECK(!bind4(db, "r", dead_mark, "b.example", 1, 60, &err));
	CHECK_EQ(err, -ESTALE);
	CHECK_EQ(fakeip_count(db), 1);
	CHECK_EQ(n_add, 1);
	CHECK_EQ(n_kern, 1);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

TEST(capacity)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, 8, 0, SECRET, NFT);
	struct binding *b;
	char name[16];
	int err;

	reset();
	for (int i = 0; i < 8; i++) {
		snprintf(name, sizeof(name), "h%d", i);
		REQUIRE(bind4(db, "r", 0, name, 1, 5, &err));
	}
	CHECK(!bind4(db, "r", 0, "h8", 1, 5, &err));
	CHECK_EQ(err, -ENOSPC);
	time_override_advance(6);
	b = bind4(db, "r", 0, "h8", 1, 5, &err);
	REQUIRE(b);
	CHECK(fakeip_count(db) <= 8);
	CHECK(n_del >= 1);
	CHECK_EQ(n_del + fakeip_count(db), 9);
	CHECK_EQ(n_kern, fakeip_count(db));
	CHECK_EQ(fakeip_live_count(db), 1);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

/*
 * A full table of live bindings: the first failing bind runs one eviction
 * pass, the next ones none, until a binding can become evictable (an
 * unref, a new binding with an earlier safe_until, time, a reload).
 */
TEST(evict_stall)
{
	enum { CAP = 2000 };
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, CAP, 0, SECRET, NFT);
	struct binding *held = NULL, *b;
	uint32_t scans;
	char name[16];
	int err;

	reset();
	kern_off = true;
	for (int i = 0; i < CAP; i++) {
		snprintf(name, sizeof(name), "h%d", i);
		/* h0 expires first, h1 is referenced and expires right after */
		b = bind4(db, "r", 0, name, 1, i < 2 ? 10 + i : 100, &err);
		REQUIRE(b);
		if (i == 1)
			fakeip_ref(held = b);
	}
	CHECK_EQ(fakeip_evict_scans(db), 0);
	CHECK(!bind4(db, "r", 0, "x0", 1, 100, &err));
	CHECK_EQ(err, -ENOSPC);
	scans = fakeip_evict_scans(db);
	CHECK_EQ(scans, 1);
	/* the second failing bind does not rescan */
	for (int i = 1; i < 50; i++) {
		snprintf(name, sizeof(name), "x%d", i);
		CHECK(!bind4(db, "r", 0, name, 1, 100, &err));
		CHECK_EQ(err, -ENOSPC);
	}
	CHECK_EQ(fakeip_evict_scans(db), scans);
	/* nor does a reference going away while its binding is live */
	fakeip_ref(held);
	fakeip_unref(db, held);
	CHECK(!bind4(db, "r", 0, "y", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), scans);
	/* time reaching h0's safe_until (1010) is not enough: it must pass it */
	time_override_set(1010);
	CHECK(!bind4(db, "r", 0, "y", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), scans);
	time_override_set(1011);
	b = bind4(db, "r", 0, "y", 1, 100, &err);
	REQUIRE(b);
	CHECK_EQ(fakeip_evict_scans(db), ++scans);
	CHECK_EQ(n_del, 1);	/* h0 */
	/* that pass stalled again: h1 has expired too, but is referenced */
	time_override_set(1012);
	CHECK(!bind4(db, "r", 0, "z", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), scans);
	/* its last reference goes: evictable now, a pass runs */
	fakeip_unref(db, held);
	REQUIRE(bind4(db, "r", 0, "z", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), ++scans);
	CHECK_EQ(n_del, 2);
	CHECK(!bind4(db, "r", 0, "w", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), scans);
	/* a new binding expiring before the others wakes the stall at its time */
	CHECK_EQ(fakeip_set_config(db, &p4, NULL, CAP + 1, 0), 0);
	REQUIRE(bind4(db, "r", 0, "short", 1, 3, &err));	/* safe_until 1015 */
	CHECK_EQ(fakeip_evict_scans(db), scans);
	CHECK(!bind4(db, "r", 0, "w", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), ++scans);
	CHECK(!bind4(db, "r", 0, "w", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), scans);
	time_override_set(1016);
	REQUIRE(bind4(db, "r", 0, "w", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), ++scans);
	CHECK_EQ(n_del, 3);
	CHECK_EQ(fakeip_count(db), CAP + 1);
	CHECK(!bind4(db, "r", 0, "v", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), scans);
	/* a reload clears the stall */
	CHECK_EQ(fakeip_set_config(db, &p4, NULL, CAP + 1, 0), 0);
	CHECK(!bind4(db, "r", 0, "v", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), ++scans);
	/* and the h* bindings expire at 1101 */
	time_override_set(1101);
	REQUIRE(bind4(db, "r", 0, "v", 1, 100, &err));
	CHECK_EQ(fakeip_evict_scans(db), ++scans);
	CHECK_EQ(fakeip_count(db), (CAP + 1) * 7 / 8 + 1);
	fakeip_free(db);
}

/* ---- randomized stress ---- */

static uint64_t rng = 88172645463325252ull;
static uint32_t rnd(uint32_t n)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng % n;
}

static void check_invariants(struct fakeip_db *db, const struct ip_prefix *p4,
                             const struct ip_prefix *p6)
{
	uint32_t it = 0, n = 0;
	struct binding *b;
	int k;

	while ((b = fakeip_next(db, &it))) {
		n++;
		CHECK(allocatable(b->family == 4 ? p4 : p6, b));
		CHECK(fakeip_lookup(db, b->family, b->fake) == b);
		k = kern_find(b->family, b->fake);
		CHECK(k >= 0);
		if (k >= 0)
			CHECK_EQ(kern[k].mark, fakeip_mark(db, b));
	}
	CHECK_EQ(n, fakeip_count(db));
	CHECK_EQ(n, n_kern);	/* distinct fakes, 1:1 with kernel elements */
	CHECK_EQ(kern_bad, 0);
}

#define NHELD 64

static const char *stress_rules[] = { "a", "b", "c" };

/*
 * Policy refcounts vs a model: every binding in the db, plus every distinct
 * held binding that was detached (still referenced), holds its pair.
 */
static void check_policies(struct fakeip_db *db, struct binding *const *held, int nheld)
{
	uint32_t model[3][4] = { { 0 } }, it = 0, live = 0;
	struct binding *b;

	while ((b = fakeip_next(db, &it))) {
		const char *r = fakeip_rule_id(db, b);
		uint32_t m = fakeip_mark(db, b);

		REQUIRE(r[0] >= 'a' && r[0] <= 'c' && !r[1] && m >= 1 && m <= 3);
		model[r[0] - 'a'][m]++;
	}
	for (int h = 0; h < nheld; h++) {
		bool dup = false;

		b = held[h];
		if (!b || fakeip_lookup(db, b->family, b->fake) == b)
			continue;
		for (int j = 0; j < h; j++)
			dup |= held[j] == b;
		if (!dup)
			model[fakeip_rule_id(db, b)[0] - 'a'][fakeip_mark(db, b)]++;
	}
	for (int r = 0; r < 3; r++)
		for (uint32_t m = 1; m <= 3; m++) {
			CHECK_EQ(fakeip_policy_refs(db, stress_rules[r], m), model[r][m]);
			live += model[r][m] > 0;
		}
	CHECK_EQ(fakeip_policy_count(db), live);
}

TEST(stress)
{
	struct ip_prefix p4 = pfx("10.64.0.0", 22), p6 = pfx("fd00:64::", 118);
	struct fakeip_db *db = fakeip_new(&p4, &p6, 900, 3, SECRET, NFT);
	struct binding *held[NHELD] = { 0 }, *b;
	uint32_t fails = 0, ok = 0;
	int err;

	reset();
	for (int i = 0; i < 40000; i++) {
		char name[32];
		uint32_t r = rnd(100);

		if (r < 3) {
			time_override_advance(rnd(4));
		} else if (r < 8) {
			uint32_t h = rnd(NHELD);

			if (held[h]) {
				fakeip_unref(db, held[h]);
				held[h] = NULL;
			}
		} else if (r < 9) {
			fakeip_maybe_evict(db);
		} else if (r < 10) {
			CHECK_EQ(fakeip_set_config(db, &p4, &p6, 600 + rnd(600), 3), 0);
		} else {
			snprintf(name, sizeof(name), "N%u.example", rnd(60));
			b = (rnd(3) ? bind4 : bind6)(db, stress_rules[rnd(3)], 1 + rnd(3), name,
			                            rnd(8), rnd(20), &err);
			if (!b) {
				CHECK_EQ(err, -ENOSPC);
				fails++;
			} else {
				uint32_t h = rnd(NHELD);

				ok++;
				if (r < 20 && !held[h]) {
					fakeip_ref(b);
					held[h] = b;
				}
			}
		}
		if (i % 500 == 0) {
			check_invariants(db, &p4, &p6);
			check_policies(db, held, NHELD);
		}
		if (test_cur_failed)
			break;
	}
	check_invariants(db, &p4, &p6);
	check_policies(db, held, NHELD);
	for (int h = 0; h < NHELD; h++)
		if (held[h]) {
			fakeip_unref(db, held[h]);
			held[h] = NULL;
		}
	check_policies(db, held, NHELD);
	fprintf(stderr, "  stress: %u ok, %u enospc, %u adds (%u replace), %u dels\n",
		ok, fails, n_add, n_add_replace, n_del);
	CHECK(n_add_replace > 0);
	CHECK(n_del > 0);
	fakeip_free(db);
}

/* policy churn: short TTLs, evictions and failed batches (which detach
 * held bindings) against the refcount model */
TEST(policy_stress)
{
	struct ip_prefix p4 = pfx("10.64.0.0", 24), p6 = pfx("fd00:64::", 120);
	struct fakeip_db *db = fakeip_new(&p4, &p6, 200, 0, SECRET, NFT);
	struct binding *held[NHELD] = { 0 }, *b;
	uint32_t churn = 0;
	int err;

	reset();
	for (int i = 0; i < 30000 && !test_cur_failed; i++) {
		uint32_t r = rnd(100), h = rnd(NHELD);
		char name[32];

		if (r < 4) {
			time_override_advance(rnd(3));
		} else if (r < 10) {
			if (held[h]) {
				fakeip_unref(db, held[h]);
				held[h] = NULL;
			}
		} else if (r < 11) {
			if (!rnd(4))	/* rare: each failure logs a line */
				fail_batch(cur_ticket);
			cur_ticket++;
		} else if (r < 13) {
			churn += fakeip_evict_expired(db);
		} else {
			snprintf(name, sizeof(name), "n%u", rnd(40));
			b = (rnd(2) ? bind4 : bind6)(db, stress_rules[rnd(3)], 1 + rnd(3), name,
			                            rnd(4), rnd(3), &err);
			if (!b)
				CHECK_EQ(err, -ENOSPC);
			else if (r < 25 && !held[h]) {
				fakeip_ref(b);
				held[h] = b;
			}
		}
		if (i % 97 == 0)
			check_policies(db, held, NHELD);
	}
	check_policies(db, held, NHELD);
	for (int h = 0; h < NHELD; h++)
		if (held[h]) {
			fakeip_unref(db, held[h]);
			held[h] = NULL;
		}
	check_policies(db, held, NHELD);
	time_override_advance(10);
	fakeip_evict_expired(db);
	CHECK_EQ(fakeip_count(db), 0);
	CHECK_EQ(fakeip_policy_count(db), 0);
	CHECK(churn > 100);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

TEST(policy_refcount)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, 10000, 0, SECRET, NFT);
	struct binding *a, *b, *c, *d, *t, *x;
	uint16_t idc, idd, maxid = 0;
	char rule[16];
	int err;

	reset();
	a = bind4(db, "r", 1, "a.example", 1, 5, &err);
	b = bind4(db, "r", 1, "b.example", 1, 60, &err);
	c = bind4(db, "r", 2, "a.example", 1, 5, &err);
	d = bind4(db, "s", 1, "a.example", 1, 5, &err);
	REQUIRE(a && b && c && d);
	CHECK(a->policy == b->policy);
	CHECK(a->policy != c->policy && a->policy != d->policy && c->policy != d->policy);
	CHECK_EQ(fakeip_policy_count(db), 3);
	CHECK_EQ(fakeip_policy_refs(db, "r", 1), 2);
	CHECK_EQ(fakeip_policy_refs(db, "r", 2), 1);
	CHECK_EQ(fakeip_policy_refs(db, "s", 1), 1);
	CHECK_EQ(fakeip_policy_refs(db, "s", 2), 0);
	CHECK_EQ(fakeip_policy_refs(db, "t", 1), 0);
	/* renewal takes no extra reference */
	CHECK(bind4(db, "r", 1, "a.example", 1, 5, &err) == a);
	CHECK_EQ(fakeip_policy_refs(db, "r", 1), 2);
	idc = c->policy;
	idd = d->policy;

	/* drop: the last binding of a pair frees it */
	fakeip_ref(b);
	time_override_advance(10);
	CHECK_EQ(fakeip_evict_expired(db), 3);
	CHECK_EQ(fakeip_policy_count(db), 1);
	CHECK_EQ(fakeip_policy_refs(db, "r", 1), 1);
	CHECK_EQ(fakeip_policy_refs(db, "r", 2), 0);
	CHECK_EQ(fakeip_policy_refs(db, "s", 1), 0);

	/* reuse: a new pair takes a freed id */
	cur_ticket++;	/* not in b's batch, which fails below */
	t = bind4(db, "t", 9, "a.example", 1, 5, &err);
	REQUIRE(t);
	CHECK(t->policy == idc || t->policy == idd);
	CHECK_STR(fakeip_rule_id(db, t), "t");
	CHECK_EQ(fakeip_mark(db, t), 9);
	CHECK_EQ(fakeip_policy_count(db), 2);

	/* a detached binding keeps its pair until the last unref */
	fail_batch(b->ticket);
	CHECK(!fakeip_lookup(db, 4, b->fake));
	CHECK_EQ(fakeip_policy_refs(db, "r", 1), 1);
	CHECK_STR(fakeip_rule_id(db, b), "r");
	x = bind4(db, "r", 1, "b.example", 1, 60, &err);	/* same key, new binding */
	REQUIRE(x && x != b && x->policy == b->policy);
	CHECK_EQ(fakeip_policy_refs(db, "r", 1), 2);
	fakeip_unref(db, b);
	CHECK_EQ(fakeip_policy_refs(db, "r", 1), 1);
	CHECK_EQ(fakeip_policy_count(db), 2);

	/* many rules: accessors stay right, ids are reused, not grown */
	time_override_advance(100);
	fakeip_evict_expired(db);
	CHECK_EQ(fakeip_policy_count(db), 0);
	for (int round = 0; round < 3; round++) {
		for (int i = 0; i < 1000; i++) {
			snprintf(rule, sizeof(rule), "rule%d", i);
			for (uint32_t m = 1; m <= 2; m++) {
				x = bind4(db, rule, m, "h.example", round, 5, &err);
				REQUIRE(x);
				CHECK_STR(fakeip_rule_id(db, x), rule);
				CHECK_EQ(fakeip_mark(db, x), m);
				if (x->policy > maxid)
					maxid = x->policy;
			}
		}
		CHECK_EQ(fakeip_policy_count(db), 2000);
		CHECK(maxid < 2000);
		time_override_advance(10);
		CHECK_EQ(fakeip_evict_expired(db), 2000);
		CHECK_EQ(fakeip_policy_count(db), 0);
	}
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

/* at most FAKEIP_MAX_POLICIES pairs: then bind fails (never a real IP) */
TEST(policy_exhaustion)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, 70000, 0, SECRET, NFT);
	struct binding *b, *keep = NULL;
	char rule[16];
	int err;

	reset();
	kern_off = true;
	for (uint32_t i = 0; i < FAKEIP_MAX_POLICIES; i++) {
		snprintf(rule, sizeof(rule), "p%u", i);
		b = bind4(db, rule, 1, "x.example", 1, i ? 5 : 60, &err);
		REQUIRE(b);
		if (!i)
			keep = b;
	}
	CHECK_EQ(fakeip_policy_count(db), FAKEIP_MAX_POLICIES);
	CHECK_EQ(fakeip_count(db), FAKEIP_MAX_POLICIES);
	CHECK(!bind4(db, "overflow", 1, "x.example", 1, 5, &err));
	CHECK_EQ(err, -ENOSPC);
	CHECK(!bind4(db, "p7", 2, "x.example", 1, 5, &err));	/* new mark = new pair */
	CHECK_EQ(err, -ENOSPC);
	CHECK_EQ(fakeip_count(db), FAKEIP_MAX_POLICIES);
	CHECK_EQ(fakeip_policy_count(db), FAKEIP_MAX_POLICIES);
	/* existing pairs still bind */
	b = bind4(db, "p7", 1, "y.example", 1, 5, &err);
	REQUIRE(b);
	CHECK_EQ(fakeip_policy_refs(db, "p7", 1), 2);
	/* once bindings expire, a full table makes room from them */
	fakeip_ref(keep);
	time_override_advance(10);
	b = bind4(db, "overflow", 1, "x.example", 1, 5, &err);
	REQUIRE(b);
	CHECK_STR(fakeip_rule_id(db, b), "overflow");
	CHECK(b->policy < FAKEIP_MAX_POLICIES);
	CHECK_EQ(fakeip_policy_count(db), 2);	/* keep (referenced) + overflow */
	CHECK_EQ(fakeip_count(db), 2);
	CHECK_STR(fakeip_rule_id(db, keep), "p0");
	fakeip_unref(db, keep);
	fakeip_free(db);
}

/* ---- pinned allocations (regression guard for the binding layout) ---- */

static uint64_t fnv(uint64_t h, const void *p, size_t n)
{
	const uint8_t *c = p;

	while (n--)
		h = (h ^ *c++) * 0x100000001b3ull;
	return h;
}

#define FNV0 0xcbf29ce484222325ull

/* v4 under heavy probing: 200 keys into a /24 (254 usable) */
static uint64_t pin_v4(struct fakeip_db *db, uint32_t *first)
{
	static const char *rules[] = { "r1", "rule-two", "x" };
	uint64_t h = FNV0;
	int err;

	for (uint32_t i = 0; i < 200; i++) {
		char name[32];
		struct binding *b;

		snprintf(name, sizeof(name), "Host%u.Example.%s", i % 37, i & 1 ? "com" : "net");
		b = bind4(db, rules[i % 3], (i % 5) << 24, name, 0x0a000000 + i * 7919, 60, &err);
		if (!b) {
			h = fnv(h, &err, sizeof(err));
			continue;
		}
		if (i < 4)
			first[i] = fake4(b);
		h = fnv(h, b->fake, 4);
		CHECK(fakeip_lookup(db, 4, b->fake) == b);
	}
	return h;
}

static uint64_t pin_v6(const char *base, int plen)
{
	struct ip_prefix p6 = pfx(base, plen);
	struct fakeip_db *db = fakeip_new(NULL, &p6, 1000, 0, SECRET, NFT);
	uint64_t h = FNV0;
	int err;

	for (uint32_t i = 0; i < 300; i++) {
		char name[32];
		struct binding *b;

		snprintf(name, sizeof(name), "v6-%u.example", i % 50);
		b = bind6(db, i & 1 ? "a" : "bb", i % 3, name, i, 60, &err);
		if (!b) {
			h = fnv(h, &err, sizeof(err));
			continue;
		}
		h = fnv(h, b->fake, 16);
		CHECK(fakeip_lookup(db, 6, b->fake) == b);
	}
	fakeip_free(db);
	return h;
}

TEST(pinned)
{
	static const uint8_t hkey[16] = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
	struct ip_prefix p24 = pfx("198.18.7.0", 24), p28 = pfx("10.9.0.0", 28);
	struct ip_prefix p15 = pfx("198.18.0.0", 15), p16 = pfx("198.18.0.0", 16);
	struct fakeip_db *db;
	struct binding *b, *olds[14];
	uint32_t first[4] = { 0 }, it;
	uint64_t h;
	int err;

	hash_init_fixed(hkey);
	reset();
	db = fakeip_new(&p24, NULL, 1000, 0, SECRET, NFT);
	h = pin_v4(db, first);
	fprintf(stderr, "  pin v4 %#llx %#x %#x %#x %#x\n", (unsigned long long)h,
		first[0], first[1], first[2], first[3]);
	CHECK_EQ(h, PIN_V4);
	CHECK_EQ(first[0], PIN_V4_0);
	CHECK_EQ(first[1], PIN_V4_1);
	CHECK_EQ(first[2], PIN_V4_2);
	CHECK_EQ(first[3], PIN_V4_3);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);

	/* v6: usable = 2^48-1 and 2^64-1 (both > 2^32: the full 64-bit key
	 * hash picks the first candidate), and a tiny /120 that probes */
	reset();
	h = pin_v6("fd00:1:2::", 80);
	fprintf(stderr, "  pin v6/80 %#llx\n", (unsigned long long)h);
	CHECK_EQ(h, PIN_V6_80);
	h = pin_v6("64:ff9b:1::", 48);
	fprintf(stderr, "  pin v6/48 %#llx\n", (unsigned long long)h);
	CHECK_EQ(h, PIN_V6_48);
	h = pin_v6("fd00:9::100", 120);
	fprintf(stderr, "  pin v6/120 %#llx\n", (unsigned long long)h);
	CHECK_EQ(h, PIN_V6_120);
	CHECK_EQ(kern_bad, 0);

	/* reclaim of expired slots and PTR lookups through by_fake */
	reset();
	db = fakeip_new(&p28, NULL, 1000, 0, SECRET, NFT);
	h = FNV0;
	for (int i = 0; i < 14; i++) {
		char name[16];

		snprintf(name, sizeof(name), "old%d", i);
		olds[i] = bind4(db, "r", 0, name, i, 5, &err);
		REQUIRE(olds[i]);
		h = fnv(h, olds[i]->fake, 4);
	}
	CHECK(!bind4(db, "r", 0, "new0", 1, 5, &err));
	time_override_advance(10);
	for (int i = 0; i < 14; i++) {
		char name[16];

		snprintf(name, sizeof(name), "new%d", i);
		b = bind4(db, "r", 0, name, i, 5, &err);
		REQUIRE(b);
		h = fnv(h, b->fake, 4);
		CHECK(fakeip_lookup(db, 4, b->fake) == b);
		CHECK(!memcmp(b->endpoint + 1, "new", 3));
	}
	fprintf(stderr, "  pin reclaim %#llx\n", (unsigned long long)h);
	CHECK_EQ(h, PIN_RECLAIM);
	CHECK_EQ(n_add_replace, 14);
	CHECK_EQ(fakeip_count(db), 14);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);

	/* reload: shrink the pool, evicted keys come back in the new pool */
	reset();
	db = fakeip_new(&p15, NULL, 1000, 0, SECRET, NFT);
	for (int i = 0; i < 64; i++) {
		char name[16];

		snprintf(name, sizeof(name), "k%d", i);
		REQUIRE(bind4(db, "r", 1, name, i, 5, &err));
	}
	time_override_advance(10);
	CHECK_EQ(fakeip_set_config(db, &p16, NULL, 1000, 0), 0);
	it = 0;
	while ((b = fakeip_next(db, &it))) {
		CHECK_EQ(b->fake[1], 18);
		CHECK(fakeip_lookup(db, 4, b->fake) == b);
	}
	h = FNV0;
	for (int i = 0; i < 80; i++) {
		char name[16];

		snprintf(name, sizeof(name), "k%d", i);
		b = bind4(db, "r", 1, name, i, 5, &err);
		REQUIRE(b);
		CHECK_EQ(b->fake[1], 18);
		h = fnv(h, b->fake, 4);
	}
	fprintf(stderr, "  pin reload %#llx\n", (unsigned long long)h);
	CHECK_EQ(h, PIN_RELOAD);
	CHECK_EQ(kern_bad, 0);
	fakeip_free(db);
}

int main(void)
{
	RUN(determinism);
	RUN(exclusions);
	RUN(renewal);
	RUN(reclaim);
	RUN(pins);
	RUN(keys);
	RUN(v6_pools);
	RUN(fail_hook);
	RUN(set_config);
	RUN(stale_mark);
	RUN(capacity);
	RUN(evict_stall);
	RUN(stress);
	RUN(policy_stress);
	RUN(policy_refcount);
	RUN(policy_exhaustion);
	RUN(pinned);
	return test_summary();
}
