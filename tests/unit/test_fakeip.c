// SPDX-License-Identifier: MIT
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

#include "test.h"
#include "fakeip.h"
#include "nft.h"
#include "util/hash.h"
#include "util/time.h"

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

uint64_t nft_elem_add(struct nft_ctx *n, int family, const uint8_t *fake,
		      const uint8_t *real, uint32_t mark, bool replace)
{
	int i = kern_find(family, fake);

	if (n != NFT || (family != 4 && family != 6))
		kern_bad++;
	n_add++;
	if (replace) {
		n_add_replace++;
		if (i < 0)
			kern_bad++;
		else
			kern_remove(i);
	} else if (i >= 0) {
		kern_bad++;
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
	int i = kern_find(family, fake);

	n_del++;
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
	CHECK(b[0]->rule_id == b[2]->rule_id);
	CHECK_STR(b[1]->rule_id, "r2");
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
	uint32_t marks[4];
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
	CHECK_EQ(fakeip_marks_in_use(db, marks, 4), 1);
	CHECK_EQ(marks[0], 7);
	CHECK_STR(a->rule_id, "r");	/* detached but still valid while referenced */
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

TEST(marks)
{
	struct ip_prefix p4 = pfx("198.18.0.0", 15);
	struct fakeip_db *db = fakeip_new(&p4, NULL, 100, 0, SECRET, NFT);
	uint32_t m[8];
	int err;

	reset();
	CHECK_EQ(fakeip_marks_in_use(db, m, 8), 0);
	bind4(db, "r", 0x100, "a", 1, 10, &err);
	bind4(db, "r", 0x200, "b", 1, 1000, &err);
	bind4(db, "q", 0x100, "c", 1, 1000, &err);
	CHECK_EQ(fakeip_marks_in_use(db, m, 8), 2);
	CHECK((m[0] == 0x100 && m[1] == 0x200) || (m[0] == 0x200 && m[1] == 0x100));
	CHECK_EQ(fakeip_marks_in_use(db, m, 1), 1);
	time_override_advance(2000);
	/* force eviction of everything */
	CHECK_EQ(fakeip_set_config(db, &p4, NULL, 1, 0), 0);
	fakeip_maybe_evict(db);
	CHECK_EQ(fakeip_count(db), 0);
	CHECK_EQ(fakeip_marks_in_use(db, m, 8), 0);
	CHECK_EQ(n_del, 3);
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
	uint32_t it = 0, n = 0, nm = 0, marks[16], seen = 0;
	struct binding *b;

	while ((b = fakeip_next(db, &it))) {
		n++;
		CHECK(allocatable(b->family == 4 ? p4 : p6, b));
		CHECK(fakeip_lookup(db, b->family, b->fake) == b);
		CHECK(kern_find(b->family, b->fake) >= 0);
		seen |= 1u << (b->mark & 15);
	}
	CHECK_EQ(n, fakeip_count(db));
	CHECK_EQ(n, n_kern);	/* distinct fakes, 1:1 with kernel elements */
	nm = fakeip_marks_in_use(db, marks, 16);
	CHECK_EQ(nm, __builtin_popcount(seen));
	for (uint32_t i = 0; i < nm; i++)
		CHECK(seen & (1u << (marks[i] & 15)));
	CHECK_EQ(kern_bad, 0);
}

#define NHELD 64

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
			static const char *rules[] = { "a", "b", "c" };

			snprintf(name, sizeof(name), "N%u.example", rnd(60));
			b = (rnd(3) ? bind4 : bind6)(db, rules[rnd(3)], 1 + rnd(3), name,
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
		if (i % 500 == 0)
			check_invariants(db, &p4, &p6);
		if (test_cur_failed)
			break;
	}
	check_invariants(db, &p4, &p6);
	for (int h = 0; h < NHELD; h++)
		if (held[h])
			fakeip_unref(db, held[h]);
	fprintf(stderr, "  stress: %u ok, %u enospc, %u adds (%u replace), %u dels\n",
		ok, fails, n_add, n_add_replace, n_del);
	CHECK(n_add_replace > 0);
	CHECK(n_del > 0);
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
	RUN(marks);
	RUN(capacity);
	RUN(stress);
	return test_summary();
}
