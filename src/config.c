// SPDX-License-Identifier: MIT
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <uci.h>

#include "config.h"
#include "log.h"
#include "match.h"
#include "util/hash.h"

#define NAMESET_LOG_INVALID	5
#define FILE_MAX_SIZE		(256u << 20)

/* ---- small helpers ---- */

static int read_fd(int fd, size_t size, char **out, size_t *len)
{
	size_t cap = size + 1, n = 0;
	char *buf = malloc(cap);

	if (!buf)
		return -ENOMEM;
	for (;;) {
		ssize_t r;

		if (n + 1 >= cap) {
			char *nb;

			if (cap >= FILE_MAX_SIZE) {
				free(buf);
				return -EFBIG;
			}
			nb = realloc(buf, cap * 2);
			if (!nb) {
				free(buf);
				return -ENOMEM;
			}
			buf = nb;
			cap *= 2;
		}
		r = read(fd, buf + n, cap - n - 1);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			int e = -errno;

			free(buf);
			return e;
		}
		if (!r)
			break;
		n += (size_t)r;
	}
	buf[n] = 0;
	*out = buf;
	*len = n;
	return 0;
}

static int read_file(const char *path, char **out, size_t *len, struct stat *st)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC), ret;

	if (fd < 0)
		return -errno;
	if (fstat(fd, st)) {
		ret = -errno;
	} else if (!S_ISREG(st->st_mode)) {
		ret = -EINVAL;
	} else if ((uint64_t)st->st_size > FILE_MAX_SIZE) {
		ret = -EFBIG;
	} else {
		ret = read_fd(fd, (size_t)st->st_size, out, len);
	}
	close(fd);
	return ret;
}

static bool is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

/* Next line of [*p, end); returns false at end. Trims surrounding space. */
static bool next_line(const char **p, const char *end, const char **ls, const char **le)
{
	const char *s = *p, *e;

	if (s >= end)
		return false;
	e = memchr(s, '\n', (size_t)(end - s));
	*p = e ? e + 1 : end;
	if (!e)
		e = end;
	while (s < e && is_space(*s))
		s++;
	while (e > s && is_space(e[-1]))
		e--;
	*ls = s;
	*le = e;
	return true;
}

static int parse_u32(const char *s, uint32_t *out)
{
	unsigned long long v;
	char *end;

	if (!s || !*s || *s == '-' || isspace((unsigned char)*s))
		return -EINVAL;
	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || *end || v > UINT32_MAX)
		return -EINVAL;
	*out = (uint32_t)v;
	return 0;
}

/* ---- addresses ---- */

static int parse_scope(const char *s, uint32_t *scope)
{
	if (parse_u32(s, scope) == 0)
		return 0;
	*scope = if_nametoindex(s);
	return *scope ? 0 : -EINVAL;
}

/* Numeric "v4", "v6" or "v6%scope" into sa (port left zero). */
static int parse_addr(const char *s, struct sockaddr_storage *ss, socklen_t *salen)
{
	char buf[INET6_ADDRSTRLEN + IF_NAMESIZE + 2];
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	char *pct;

	memset(ss, 0, sizeof(*ss));
	if (strlen(s) >= sizeof(buf))
		return -EINVAL;
	strcpy(buf, s);
	if (inet_pton(AF_INET, buf, &sin->sin_addr) == 1) {
		sin->sin_family = AF_INET;
		*salen = sizeof(*sin);
		return 0;
	}
	pct = strchr(buf, '%');
	if (pct) {
		uint32_t scope;

		*pct = 0;
		if (!pct[1] || parse_scope(pct + 1, &scope))
			return -EINVAL;
		sin6->sin6_scope_id = scope;
	}
	if (inet_pton(AF_INET6, buf, &sin6->sin6_addr) != 1)
		return -EINVAL;
	sin6->sin6_family = AF_INET6;
	*salen = sizeof(*sin6);
	return 0;
}

static void sa_set_port(struct sockaddr_storage *ss, uint16_t port)
{
	if (ss->ss_family == AF_INET)
		((struct sockaddr_in *)ss)->sin_port = htons(port);
	else
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
}

/* "ADDR[#PORT]" */
static int parse_server(const char *tok, size_t len, struct upstream_server *srv)
{
	char buf[128];
	char *hash;
	uint32_t port = 53;

	if (len >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, tok, len);
	buf[len] = 0;
	hash = strchr(buf, '#');
	if (hash) {
		*hash = 0;
		if (!isdigit((unsigned char)hash[1]) || parse_u32(hash + 1, &port) ||
		    !port || port > 65535)
			return -EINVAL;
	}
	if (parse_addr(buf, &srv->sa, &srv->salen))
		return -EINVAL;
	sa_set_port(&srv->sa, (uint16_t)port);
	return 0;
}

static bool server_eq(const struct upstream_server *a, const struct upstream_server *b)
{
	return a->salen == b->salen && !memcmp(&a->sa, &b->sa, a->salen);
}

int resolvconf_parse(const char *text, size_t len,
		     struct upstream_server *out, int max, int *nskipped)
{
	const char *p = text, *end = text + len, *s, *e;
	int n = 0, skipped = 0;

	if (max > UPSTREAM_MAX_SERVERS)
		max = UPSTREAM_MAX_SERVERS;
	while (next_line(&p, end, &s, &e)) {
		struct upstream_server srv;
		const char *t;
		bool dup = false;

		if (e - s < 11 || memcmp(s, "nameserver", 10) || !is_space(s[10]))
			continue;
		for (s += 10; s < e && is_space(*s); s++)
			;
		for (t = s; t < e && !is_space(*t); t++)
			;
		if (parse_server(s, (size_t)(t - s), &srv)) {
			skipped++;
			continue;
		}
		for (int i = 0; i < n && !dup; i++)
			dup = server_eq(&out[i], &srv);
		if (!dup && n < max)
			out[n++] = srv;
	}
	if (nskipped)
		*nskipped = skipped;
	return n;
}

/* ---- upstream sets ---- */

static uint64_t upstream_id(const struct upstream_server *srv, int n)
{
	uint8_t buf[UPSTREAM_MAX_SERVERS * 23], *q = buf;

	for (int i = 0; i < n; i++) {
		const struct sockaddr_storage *ss = &srv[i].sa;

		if (ss->ss_family == AF_INET) {
			const struct sockaddr_in *sin = (const void *)ss;

			*q++ = 4;
			memcpy(q, &sin->sin_addr, 4);
			memcpy(q + 4, &sin->sin_port, 2);
			q += 6;
		} else {
			const struct sockaddr_in6 *sin6 = (const void *)ss;
			uint32_t scope = htonl(sin6->sin6_scope_id);

			*q++ = 6;
			memcpy(q, &sin6->sin6_addr, 16);
			memcpy(q + 16, &sin6->sin6_port, 2);
			memcpy(q + 18, &scope, 4);
			q += 22;
		}
	}
	return omni_hash(buf, (size_t)(q - buf));
}

struct upstream_set *upstream_set_load(const char *path, char *err, size_t errlen)
{
	struct upstream_server srv[UPSTREAM_MAX_SERVERS];
	struct upstream_set *u;
	struct stat st;
	size_t len;
	char *text;
	int n, skipped, ret;

	ret = read_file(path, &text, &len, &st);
	if (ret) {
		snprintf(err, errlen, "upstream file '%s': %s", path, strerror(-ret));
		return NULL;
	}
	n = resolvconf_parse(text, len, srv, UPSTREAM_MAX_SERVERS, &skipped);
	free(text);
	if (skipped)
		log_warn("upstream file '%s': %d invalid nameserver line(s) ignored",
			 path, skipped);
	if (n <= 0) {
		snprintf(err, errlen, "upstream file '%s': no usable nameserver", path);
		return NULL;
	}
	u = calloc(1, sizeof(*u) + (size_t)n * sizeof(u->srv[0]));
	if (!u) {
		snprintf(err, errlen, "out of memory");
		return NULL;
	}
	u->refcnt = 1;
	u->n = (uint16_t)n;
	memcpy(u->srv, srv, (size_t)n * sizeof(srv[0]));
	u->id = upstream_id(srv, n);
	return u;
}

struct upstream_set *upstream_set_get(struct upstream_set *u)
{
	if (u)
		u->refcnt++;
	return u;
}

void upstream_set_put(struct upstream_set *u)
{
	if (u && --u->refcnt == 0)
		free(u);
}

/* ---- namesets ---- */

static bool label_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
	       c == '-' || c == '_';
}

/* Lowercases s in place; validates the dotted name. */
static bool pattern_valid(char *s, size_t len)
{
	size_t lab = 0, labels = 0;

	if (!len || len > 253)
		return false;
	for (size_t i = 0; i <= len; i++) {
		if (i == len || s[i] == '.') {
			if (!lab || lab > 63)
				return false;
			labels++;
			lab = 0;
			continue;
		}
		s[i] = (char)tolower((unsigned char)s[i]);
		if (!label_char(s[i]))
			return false;
		lab++;
	}
	return labels <= 127;
}

/* Strip a trailing "# comment" preceded by whitespace; re-trim. */
static const char *strip_comment(const char *s, const char *e)
{
	for (const char *c = s + 1; c < e; c++) {
		if (*c == '#' && is_space(c[-1])) {
			e = c;
			break;
		}
	}
	while (e > s && is_space(e[-1]))
		e--;
	return e;
}

struct pat_vec {
	struct ns_pattern *v;
	uint32_t n, cap;
};

static int pat_push(struct pat_vec *pv, struct arena *a, const char *s,
		    size_t len, bool suffix)
{
	struct ns_pattern *p;

	if (pv->n == pv->cap) {
		uint32_t cap = pv->cap ? pv->cap * 2 : 64;
		struct ns_pattern *nv = realloc(pv->v, cap * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		pv->v = nv;
		pv->cap = cap;
	}
	p = &pv->v[pv->n];
	p->name = arena_strndup(a, s, len);
	if (!p->name)
		return -ENOMEM;
	p->len = (uint8_t)len;
	p->suffix = suffix;
	pv->n++;
	return 0;
}

int nameset_parse(const char *text, size_t len, struct arena *a,
		  struct ns_pattern **out, uint32_t *n, uint32_t *ninvalid,
		  const char *path)
{
	const char *p = text, *end = text + len, *s, *e, *line;
	struct pat_vec pv = { 0 };
	uint32_t lineno = 0, bad = 0;
	char buf[260];

	*out = NULL;
	*n = 0;
	while (next_line(&p, end, &s, &e)) {
		bool suffix = false;
		size_t l;

		lineno++;
		if (s == e || *s == '#')
			continue;
		e = strip_comment(s, e);
		line = s;
		if (e - s >= 2 && s[0] == '*' && s[1] == '.') {
			suffix = true;
			s += 2;
		}
		l = (size_t)(e - s);
		if (l < sizeof(buf)) {
			memcpy(buf, s, l);
			if (pattern_valid(buf, l)) {
				if (pat_push(&pv, a, buf, l, suffix))
					goto nomem;
				continue;
			}
		}
		if (++bad <= NAMESET_LOG_INVALID)
			log_warn("%s:%u: invalid pattern '%.*s'", path ? path : "nameset",
				 lineno, (int)(e - line > 80 ? 80 : e - line), line);
	}
	if (bad > NAMESET_LOG_INVALID)
		log_warn("%s: %u invalid patterns in total", path ? path : "nameset", bad);
	if (ninvalid)
		*ninvalid = bad;
	if (pv.n) {
		*out = arena_alloc(a, pv.n * sizeof(*pv.v), _Alignof(struct ns_pattern));
		if (!*out)
			goto nomem;
		memcpy(*out, pv.v, pv.n * sizeof(*pv.v));
	}
	*n = pv.n;
	free(pv.v);
	return 0;
nomem:
	free(pv.v);
	return -ENOMEM;
}

/* ---- nameset cache ----
 * Entries replaced by a re-parse stay in the map (they may still be
 * referenced) under the flipped hash so lookups never find them; nsc_sweep()
 * drops them once unreferenced. */

static uint64_t path_hash(const char *path)
{
	return omni_hash(path, strlen(path));
}

static bool nsf_eq(const void *val, const void *key, void *ctx)
{
	return !strcmp(((const struct nameset_file *)val)->path, key);
}

static void nsf_free(struct nameset_file *f)
{
	arena_free(&f->arena);
	free(f->path);
	free(f);
}

void nsc_init(struct nameset_cache *c)
{
	c->by_path = (struct hmap)HMAP_INIT;
}

static bool nsf_unchanged(const struct nameset_file *f, const struct stat *st)
{
	return f->dev == st->st_dev && f->ino == st->st_ino &&
	       f->size == st->st_size &&
	       f->mtime.tv_sec == st->st_mtim.tv_sec &&
	       f->mtime.tv_nsec == st->st_mtim.tv_nsec;
}

static struct nameset_file *nsf_load(const char *path, int *err)
{
	struct nameset_file *f = calloc(1, sizeof(*f));
	uint32_t ninval;
	struct stat st;
	size_t len;
	char *text = NULL;
	int ret;

	if (!f || !(f->path = strdup(path))) {
		free(f);
		*err = -ENOMEM;
		return NULL;
	}
	arena_init(&f->arena, 0);
	ret = read_file(path, &text, &len, &st);
	if (!ret)
		ret = nameset_parse(text, len, &f->arena, &f->pat, &f->npat, &ninval, path);
	free(text);
	if (ret) {
		nsf_free(f);
		*err = ret;
		return NULL;
	}
	f->dev = st.st_dev;
	f->ino = st.st_ino;
	f->mtime = st.st_mtim;
	f->size = st.st_size;
	return f;
}

struct nameset_file *nsc_get(struct nameset_cache *c, const char *path, int *err)
{
	uint64_t h = path_hash(path);
	struct nameset_file *f, *old;
	struct stat st;
	int e = 0;

	if (!err)
		err = &e;
	if (stat(path, &st)) {
		*err = -errno;
		return NULL;
	}
	old = hmap_get(&c->by_path, h, path, nsf_eq, NULL);
	if (old && nsf_unchanged(old, &st)) {
		old->refcnt++;
		return old;
	}
	f = nsf_load(path, err);
	if (!f)
		return NULL;
	if (hmap_put(&c->by_path, h, f)) {
		nsf_free(f);
		*err = -ENOMEM;
		return NULL;
	}
	if (old) {
		hmap_del_ptr(&c->by_path, h, old);
		if (!old->refcnt)
			nsf_free(old);
		else if (hmap_put(&c->by_path, ~h, old))
			log_err("nameset cache: leaking stale '%s'", old->path);
	}
	f->refcnt = 1;
	return f;
}

void nsc_put(struct nameset_file *f)
{
	if (f && f->refcnt > 0)
		f->refcnt--;
}

void nsc_sweep(struct nameset_cache *c)
{
	struct nameset_file *f;

	for (uint32_t it = 0; (f = hmap_next(&c->by_path, &it)); ) {
		uint64_t h;

		if (f->refcnt)
			continue;
		h = path_hash(f->path);
		if (!hmap_del_ptr(&c->by_path, h, f))
			hmap_del_ptr(&c->by_path, ~h, f);
		nsf_free(f);
	}
}

void nsc_destroy(struct nameset_cache *c)
{
	struct nameset_file *f;

	for (uint32_t it = 0; (f = hmap_next(&c->by_path, &it)); )
		nsf_free(f);
	hmap_free(&c->by_path);
}

/* ---- prefixes / marks ---- */

int ip_prefix_parse(const char *s, struct ip_prefix *out)
{
	char buf[INET6_ADDRSTRLEN + 8];
	const char *slash = strchr(s, '/');
	uint32_t plen;
	size_t alen;
	int maxlen;

	if (!slash || (alen = (size_t)(slash - s)) >= sizeof(buf) ||
	    !isdigit((unsigned char)slash[1]) || parse_u32(slash + 1, &plen))
		return -EINVAL;
	memcpy(buf, s, alen);
	buf[alen] = 0;
	memset(out, 0, sizeof(*out));
	if (inet_pton(AF_INET, buf, out->addr) == 1) {
		out->family = AF_INET;
		maxlen = 32;
	} else if (inet_pton(AF_INET6, buf, out->addr) == 1) {
		out->family = AF_INET6;
		maxlen = 128;
	} else {
		return -EINVAL;
	}
	if (plen > (uint32_t)maxlen)
		return -EINVAL;
	out->plen = (uint8_t)plen;
	/* host bits must be zero */
	for (int i = 0; i < maxlen / 8; i++) {
		int bits = (int)plen - i * 8;
		uint8_t m = bits >= 8 ? 0xff : bits <= 0 ? 0 : (uint8_t)(0xff << (8 - bits));

		if (out->addr[i] & ~m)
			return -EINVAL;
	}
	return 0;
}

static bool prefix_bits_eq(const uint8_t *a, const uint8_t *b, unsigned plen)
{
	unsigned full = plen / 8, rem = plen % 8;

	if (memcmp(a, b, full))
		return false;
	if (!rem)
		return true;
	return !((a[full] ^ b[full]) & (uint8_t)(0xff << (8 - rem)));
}

bool ip_prefix_contains(const struct ip_prefix *p, int family, const uint8_t *addr)
{
	return p->family == family && prefix_bits_eq(p->addr, addr, p->plen);
}

static bool prefix_overlap(const struct ip_prefix *a, const struct ip_prefix *b)
{
	return a->family == b->family &&
	       prefix_bits_eq(a->addr, b->addr, a->plen < b->plen ? a->plen : b->plen);
}

uint32_t config_mark_shift(uint32_t value, uint32_t mask)
{
	uint64_t v;

	if (!value || !mask)
		return 0;
	v = (uint64_t)value << __builtin_ctz(mask);
	if (v & ~(uint64_t)mask)
		return 0;
	return (uint32_t)v;
}

/* ---- config loading ---- */

struct loader {
	struct uci_context *uci;
	struct config *cfg;
	struct nameset_cache *nsc;
	char *err;
	size_t errlen;
};

static int fail(struct loader *L, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static int fail(struct loader *L, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(L->err, L->errlen, fmt, ap);
	va_end(ap);
	return -EINVAL;
}

static const char *opt_str(struct loader *L, struct uci_section *s, const char *name,
			   const char *where, int *ret)
{
	struct uci_option *o = uci_lookup_option(L->uci, s, name);

	if (!o)
		return NULL;
	if (o->type != UCI_TYPE_STRING) {
		*ret = fail(L, "%s: option '%s' must not be a list", where, name);
		return NULL;
	}
	return o->v.string;
}

struct u32_opt {
	const char *name;
	size_t off;
	uint32_t def, min, max;
};

#define U32OPT(n, field, d, lo, hi) { n, offsetof(struct config, field), d, lo, hi }

static const struct u32_opt u32_opts[] = {
	U32OPT("fwmask", fwmask, 0xff000000u, 1, UINT32_MAX),
	U32OPT("fakeip_grace", fakeip_grace, 600, 0, 30 * 86400),
	U32OPT("fakeip_ttl_max", fakeip_ttl_max, 3600, 1, 7 * 86400),
	U32OPT("fakeip_max_bindings", fakeip_max_bindings, 65536, 1, 1u << 24),
	U32OPT("cache_size", cache_size, 10000, 0, 1u << 24),
	U32OPT("cache_max_bytes", cache_max_bytes, 16u << 20, 0, UINT32_MAX),
	U32OPT("neg_ttl_max", neg_ttl_max, 3600, 0, 7 * 86400),
	U32OPT("block_ttl", block_ttl, 300, 0, 7 * 86400),
	U32OPT("upstream_timeout", upstream_timeout_ms, 1500, 10, 60000),
	U32OPT("upstream_total_timeout", upstream_total_timeout_ms, 5000, 10, 300000),
	U32OPT("max_clients_tcp", max_clients_tcp, 64, 1, 65536),
	U32OPT("max_pending", max_pending, 1024, 1, 1u << 20),
	U32OPT("max_pending_per_client", max_pending_per_client, 64, 1, 1u << 20),
};

static const char *const known_global[] = {
	"port", "listen_addr", "fakeip_v4", "fakeip_v6", "block_mode", "log_level",
};

static void global_defaults(struct config *cfg)
{
	for (size_t i = 0; i < sizeof(u32_opts) / sizeof(u32_opts[0]); i++)
		*(uint32_t *)((char *)cfg + u32_opts[i].off) = u32_opts[i].def;
	cfg->port = 53;
	cfg->block_mode = BLOCK_NODATA;
	cfg->log_level = LOG_INFO;
}

static int load_u32_opts(struct loader *L, struct uci_section *s)
{
	int ret = 0;

	for (size_t i = 0; i < sizeof(u32_opts) / sizeof(u32_opts[0]); i++) {
		const struct u32_opt *d = &u32_opts[i];
		const char *v = opt_str(L, s, d->name, "global", &ret);
		uint32_t x;

		if (ret)
			return ret;
		if (!v)
			continue;
		if (parse_u32(v, &x) || x < d->min || x > d->max)
			return fail(L, "global: option '%s': invalid value '%s' (%u..%u)",
				    d->name, v, d->min, d->max);
		*(uint32_t *)((char *)L->cfg + d->off) = x;
	}
	return 0;
}

static int lookup_enum(const char *v, const char *const *names, int n)
{
	for (int i = 0; i < n; i++)
		if (!strcmp(v, names[i]))
			return i;
	return -1;
}

static int load_enums(struct loader *L, struct uci_section *s)
{
	static const char *const modes[] = { "nodata", "nxdomain", "null" };
	static const char *const levels[] = { "err", "warn", "info", "debug" };
	static const int prios[] = { LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG };
	int ret = 0, i;
	const char *v;

	v = opt_str(L, s, "block_mode", "global", &ret);
	if (v && (i = lookup_enum(v, modes, 3)) < 0)
		return fail(L, "global: invalid block_mode '%s' (nodata|nxdomain|null)", v);
	if (v)
		L->cfg->block_mode = (enum block_mode)i;
	v = opt_str(L, s, "log_level", "global", &ret);
	if (v && (i = lookup_enum(v, levels, 4)) < 0)
		return fail(L, "global: invalid log_level '%s' (err|warn|info|debug)", v);
	if (v)
		L->cfg->log_level = prios[i];
	return ret;
}

static int add_listen(struct loader *L, const char *v)
{
	struct config *cfg = L->cfg;
	struct sockaddr_storage *ss;
	socklen_t salen;

	if (cfg->nlisten >= CONFIG_MAX_LISTEN)
		return fail(L, "global: too many listen_addr (max %d)", CONFIG_MAX_LISTEN);
	ss = &cfg->listen[cfg->nlisten];
	if (parse_addr(v, ss, &salen))
		return fail(L, "global: invalid listen_addr '%s' (numeric IPv4/IPv6 expected)", v);
	sa_set_port(ss, cfg->port);
	for (int i = 0; i < cfg->nlisten; i++)
		if (!memcmp(&cfg->listen[i], ss, sizeof(*ss)))
			return fail(L, "global: duplicate listen_addr '%s'", v);
	cfg->nlisten++;
	return 0;
}

static int load_listen(struct loader *L, struct uci_section *s)
{
	struct uci_option *o = uci_lookup_option(L->uci, s, "listen_addr");
	struct uci_element *e;
	int ret;

	if (!o)
		return fail(L, "global: listen_addr is required");
	if (o->type == UCI_TYPE_STRING)
		return add_listen(L, o->v.string);
	uci_foreach_element(&o->v.list, e) {
		ret = add_listen(L, e->name);
		if (ret)
			return ret;
	}
	return 0;
}

static const struct {
	int family;
	const char *pfx;
} reserved_nets[] = {
	{ AF_INET, "0.0.0.0/8" },
	{ AF_INET, "127.0.0.0/8" },
	{ AF_INET, "224.0.0.0/3" },
	{ AF_INET6, "::/128" },
	{ AF_INET6, "::1/128" },
	{ AF_INET6, "::ffff:0:0/96" },
	{ AF_INET6, "ff00::/8" },
};

static int load_pool(struct loader *L, struct uci_section *s, int family)
{
	const char *name = family == AF_INET ? "fakeip_v4" : "fakeip_v6";
	struct config *cfg = L->cfg;
	struct ip_prefix *p = family == AF_INET ? &cfg->pool4 : &cfg->pool6;
	unsigned lo = family == AF_INET ? 8 : 32, hi = family == AF_INET ? 30 : 120;
	int ret = 0;
	const char *v = opt_str(L, s, name, "global", &ret);

	if (!v)
		return ret;
	if (ip_prefix_parse(v, p) || p->family != family)
		return fail(L, "global: %s: invalid prefix '%s'", name, v);
	if (p->plen < lo || p->plen > hi)
		return fail(L, "global: %s: prefix length must be %u..%u", name, lo, hi);
	for (size_t i = 0; i < sizeof(reserved_nets) / sizeof(reserved_nets[0]); i++) {
		struct ip_prefix r;

		if (reserved_nets[i].family != family)
			continue;
		ip_prefix_parse(reserved_nets[i].pfx, &r);
		if (prefix_overlap(p, &r))
			return fail(L, "global: %s '%s' overlaps reserved %s",
				    name, v, reserved_nets[i].pfx);
	}
	if (family == AF_INET)
		cfg->has_pool4 = true;
	else
		cfg->has_pool6 = true;
	return 0;
}

static bool option_known(const char *name, const char *const *list, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (!strcmp(name, list[i]))
			return true;
	return false;
}

static void warn_unknown_global(struct uci_section *s)
{
	struct uci_element *e;

	uci_foreach_element(&s->options, e) {
		bool known = option_known(e->name, known_global,
					  sizeof(known_global) / sizeof(known_global[0]));

		for (size_t i = 0; !known && i < sizeof(u32_opts) / sizeof(u32_opts[0]); i++)
			known = !strcmp(e->name, u32_opts[i].name);
		if (!known)
			log_warn("config: global: unknown option '%s' ignored", e->name);
	}
}

static int load_global(struct loader *L, struct uci_section *s)
{
	struct config *cfg = L->cfg;
	int ret = 0;
	const char *v;
	uint32_t x;

	warn_unknown_global(s);
	v = opt_str(L, s, "port", "global", &ret);
	if (ret)
		return ret;
	if (v && (parse_u32(v, &x) || !x || x > 65535))
		return fail(L, "global: invalid port '%s'", v);
	if (v)
		cfg->port = (uint16_t)x;
	if ((ret = load_u32_opts(L, s)) || (ret = load_enums(L, s)) ||
	    (ret = load_listen(L, s)) || (ret = load_pool(L, s, AF_INET)) ||
	    (ret = load_pool(L, s, AF_INET6)))
		return ret;
	if (cfg->upstream_total_timeout_ms < cfg->upstream_timeout_ms)
		return fail(L, "global: upstream_total_timeout must be >= upstream_timeout");
	if (cfg->max_pending_per_client > cfg->max_pending)
		return fail(L, "global: max_pending_per_client must be <= max_pending");
	return 0;
}

/* ---- rules ---- */

static int rule_upstream(struct loader *L, struct rule *r, const char *path)
{
	char e[256];

	r->upstream_path = strdup(path);
	if (!r->upstream_path)
		return fail(L, "out of memory");
	for (uint16_t i = 0; i < r->ord; i++) {
		struct rule *o = &L->cfg->rules[i];

		if (o->up && !strcmp(o->upstream_path, path)) {
			r->up = upstream_set_get(o->up);
			return 0;
		}
	}
	r->up = upstream_set_load(path, e, sizeof(e));
	if (!r->up)
		return fail(L, "rule '%s': %s", r->id, e);
	return 0;
}

static int rule_add_file(struct loader *L, struct rule *r, const char *path)
{
	struct nameset_file *f, **nf;
	int err = 0;

	f = nsc_get(L->nsc, path, &err);
	if (!f) {
		if (err == -ENOMEM)
			return fail(L, "out of memory");
		log_warn("rule '%s': nameset '%s' unreadable (%s), skipped",
			 r->id, path, strerror(-err));
		return 0;
	}
	for (uint16_t i = 0; i < r->nfiles; i++) {
		if (r->files[i] == f || (r->files[i]->dev == f->dev &&
					 r->files[i]->ino == f->ino)) {
			nsc_put(f);
			return 0;
		}
	}
	if (r->nfiles == UINT16_MAX) {
		nsc_put(f);
		return fail(L, "rule '%s': too many nameset files", r->id);
	}
	nf = realloc(r->files, (r->nfiles + 1u) * sizeof(*nf));
	if (!nf) {
		nsc_put(f);
		return fail(L, "out of memory");
	}
	r->files = nf;
	r->files[r->nfiles++] = f;
	return 0;
}

static int rule_glob(struct loader *L, struct rule *r, const char *pattern)
{
	glob_t g;
	int ret = 0, gr;

	gr = glob(pattern, 0, NULL, &g);
	if (gr == GLOB_NOMATCH) {
		log_debug("rule '%s': nameset glob '%s' matched nothing", r->id, pattern);
		return 0;
	}
	if (gr) {
		globfree(&g);
		if (gr == GLOB_NOSPACE)
			return fail(L, "out of memory");
		log_warn("rule '%s': nameset glob '%s' failed", r->id, pattern);
		return 0;
	}
	for (size_t i = 0; i < g.gl_pathc && !ret; i++) {
		struct stat st;

		if (stat(g.gl_pathv[i], &st) || !S_ISREG(st.st_mode)) {
			log_warn("rule '%s': nameset '%s' is not a readable regular file, skipped",
				 r->id, g.gl_pathv[i]);
			continue;
		}
		ret = rule_add_file(L, r, g.gl_pathv[i]);
	}
	globfree(&g);
	return ret;
}

static int rule_namesets(struct loader *L, struct rule *r, struct uci_option *o)
{
	struct uci_element *e;
	int ret;

	if (o->type == UCI_TYPE_STRING)
		ret = rule_glob(L, r, o->v.string);
	else {
		ret = 0;
		uci_foreach_element(&o->v.list, e) {
			ret = rule_glob(L, r, e->name);
			if (ret)
				break;
		}
	}
	if (!ret && !r->nfiles)
		log_warn("rule '%s': nameset globs matched no readable files; rule matches nothing",
			 r->id);
	return ret;
}

static int rule_action(struct loader *L, struct rule *r, struct uci_section *s)
{
	static const char *const actions[] = { "block", "forward", "fakeip" };
	int ret = 0, a;
	const char *v = opt_str(L, s, "action", r->id, &ret);

	if (ret)
		return fail(L, "rule '%s': option 'action' must not be a list", r->id);
	if (!v)
		return fail(L, "rule '%s': missing option 'action'", r->id);
	a = lookup_enum(v, actions, 3);
	if (a < 0)
		return fail(L, "rule '%s': invalid action '%s' (block|forward|fakeip)", r->id, v);
	r->action = (enum rule_action)a;
	return 0;
}

static int rule_mark(struct loader *L, struct rule *r, const char *v)
{
	uint32_t x;

	if (!v)
		return fail(L, "rule '%s': fakeip requires option 'fwmark'", r->id);
	if (parse_u32(v, &x))
		return fail(L, "rule '%s': invalid fwmark '%s'", r->id, v);
	r->mark = config_mark_shift(x, L->cfg->fwmask);
	if (!r->mark)
		return fail(L, "rule '%s': fwmark '%s' must be non-zero and fit fwmask 0x%x",
			    r->id, v, L->cfg->fwmask);
	for (uint16_t i = 0; i < r->ord; i++) {
		const struct rule *o = &L->cfg->rules[i];

		if (o->action == RULE_FAKEIP && o->mark == r->mark) {
			log_warn("rule '%s': shares fwmark 0x%x with rule '%s'",
				 r->id, r->mark, o->id);
			break;
		}
	}
	return 0;
}

static int rule_options(struct loader *L, struct rule *r, struct uci_section *s)
{
	static const char *const known[] = { "action", "upstream", "fwmark", "nameset" };
	struct config *cfg = L->cfg;
	const char *up, *mark;
	struct uci_element *e;
	int ret = 0;

	uci_foreach_element(&s->options, e)
		if (!option_known(e->name, known, 4))
			log_warn("config: rule '%s': unknown option '%s' ignored", r->id, e->name);
	if ((ret = rule_action(L, r, s)))
		return ret;
	up = opt_str(L, s, "upstream", r->id, &ret);
	mark = ret ? NULL : opt_str(L, s, "fwmark", r->id, &ret);
	if (ret)
		return ret;
	if (r->action == RULE_BLOCK && up)
		log_warn("rule '%s': upstream ignored for action block", r->id);
	if (r->action != RULE_FAKEIP && mark)
		log_warn("rule '%s': fwmark ignored for action %s", r->id,
			 r->action == RULE_BLOCK ? "block" : "forward");
	if (r->action == RULE_BLOCK)
		return 0;
	if (!up || !*up)
		return fail(L, "rule '%s': missing option 'upstream'", r->id);
	if ((ret = rule_upstream(L, r, up)))
		return ret;
	if (r->action != RULE_FAKEIP)
		return 0;
	if (!cfg->has_pool4 && !cfg->has_pool6)
		return fail(L, "rule '%s': fakeip requires fakeip_v4 and/or fakeip_v6", r->id);
	return rule_mark(L, r, mark);
}

static void put_prefix(uint8_t **q, bool has, const struct ip_prefix *p)
{
	*(*q)++ = has;
	if (!has)
		return;
	*(*q)++ = p->family == AF_INET ? 4 : 6;
	memcpy(*q, p->addr, 16);
	*q += 16;
	*(*q)++ = p->plen;
}

static uint64_t rule_fingerprint(const struct config *cfg, const struct rule *r)
{
	uint8_t buf[128], *q = buf;
	uint64_t upid = r->up ? r->up->id : 0, h;

	*q++ = (uint8_t)r->action;
	memcpy(q, &upid, 8);
	memcpy(q + 8, &r->mark, 4);
	q += 12;
	if (r->action == RULE_BLOCK) {
		*q++ = (uint8_t)cfg->block_mode;
		memcpy(q, &cfg->block_ttl, 4);
		q += 4;
	} else if (r->action == RULE_FAKEIP) {
		put_prefix(&q, cfg->has_pool4, &cfg->pool4);
		put_prefix(&q, cfg->has_pool6, &cfg->pool6);
		memcpy(q, &cfg->fakeip_grace, 4);
		memcpy(q + 4, &cfg->fakeip_ttl_max, 4);
		q += 8;
	}
	h = omni_hash(r->id, strlen(r->id) + 1);
	memcpy(q, &h, 8);
	q += 8;
	return omni_hash(buf, (size_t)(q - buf));
}

static int load_rule(struct loader *L, struct uci_section *s)
{
	struct config *cfg = L->cfg;
	struct uci_option *ns;
	struct rule *r;
	int ret;

	if (s->anonymous)
		return fail(L, "rule #%u: anonymous rule sections are not allowed "
			    "(give each rule a stable name)", cfg->nrules + 1);
	if (cfg->nrules >= CONFIG_MAX_RULES)
		return fail(L, "too many rules (max %d)", CONFIG_MAX_RULES);
	if (cfg->nrules && cfg->rules[cfg->nrules - 1].catchall)
		return fail(L, "rule '%s': catchall rule '%s' (no nameset) must be the last rule",
			    s->e.name, cfg->rules[cfg->nrules - 1].id);
	r = &cfg->rules[cfg->nrules];
	memset(r, 0, sizeof(*r));
	r->ord = cfg->nrules++;
	r->id = strdup(s->e.name);
	if (!r->id)
		return fail(L, "out of memory");
	if ((ret = rule_options(L, r, s)))
		return ret;
	ns = uci_lookup_option(L->uci, s, "nameset");
	if (!ns)
		r->catchall = true;
	else if ((ret = rule_namesets(L, r, ns)))
		return ret;
	r->fingerprint = rule_fingerprint(cfg, r);
	return 0;
}

static int load_sections(struct loader *L, struct uci_package *pkg)
{
	struct uci_section *global = NULL;
	struct uci_element *e;
	int ret;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "omnidns"))
			continue;
		if (global)
			return fail(L, "multiple 'omnidns' sections");
		global = s;
	}
	if (!global)
		return fail(L, "missing 'config omnidns' section");
	if ((ret = load_global(L, global)))
		return ret;
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "rule")) {
			if ((ret = load_rule(L, s)))
				return ret;
		} else if (strcmp(s->type, "omnidns")) {
			log_warn("config: unknown section type '%s' ignored", s->type);
		}
	}
	if (!L->cfg->nrules || !L->cfg->rules[L->cfg->nrules - 1].catchall)
		return fail(L, "no catchall rule (a last rule without 'nameset') defined");
	return 0;
}

/*
 * Load by absolute path: libuci then reads the committed file only and
 * ignores uncommitted deltas in /tmp/.uci (which a confdir load would apply).
 */
static int load_uci(struct loader *L, const char *path)
{
	char *abs = realpath(path, NULL), *msg = NULL;
	struct uci_package *pkg = NULL;
	int ret;

	if (!abs)
		return fail(L, "cannot load '%s': %s", path, strerror(errno));
	L->uci = uci_alloc_context();
	if (!L->uci) {
		ret = fail(L, "out of memory");
		goto out;
	}
	if (uci_load(L->uci, abs, &pkg) || !pkg) {
		uci_get_errorstr(L->uci, &msg, NULL);
		ret = fail(L, "cannot load '%s': %s", path, msg ? msg : "uci error");
		free(msg);
		goto out;
	}
	ret = load_sections(L, pkg);
out:
	free(abs);
	return ret;
}

struct config *config_load(const char *path, struct nameset_cache *nsc,
			   char *err, size_t errlen)
{
	struct loader L = { .nsc = nsc, .err = err, .errlen = errlen };
	struct config *cfg = calloc(1, sizeof(*cfg));
	struct rule *shrink;

	if (errlen)
		err[0] = 0;
	if (!cfg || !(cfg->rules = calloc(CONFIG_MAX_RULES, sizeof(*cfg->rules)))) {
		free(cfg);
		snprintf(err, errlen, "out of memory");
		return NULL;
	}
	L.cfg = cfg;
	global_defaults(cfg);
	if (load_uci(&L, path))
		goto fail;
	shrink = realloc(cfg->rules, cfg->nrules * sizeof(*cfg->rules));
	if (shrink)
		cfg->rules = shrink;
	cfg->idx = match_build(cfg->rules, cfg->nrules);
	if (!cfg->idx) {
		fail(&L, "out of memory building match index");
		goto fail;
	}
	uci_free_context(L.uci);
	return cfg;
fail:
	if (L.uci)
		uci_free_context(L.uci);
	config_free(cfg);
	return NULL;
}

void config_free(struct config *cfg)
{
	if (!cfg)
		return;
	for (uint16_t i = 0; i < cfg->nrules; i++) {
		struct rule *r = &cfg->rules[i];

		for (uint16_t j = 0; j < r->nfiles; j++)
			nsc_put(r->files[j]);
		free(r->files);
		upstream_set_put(r->up);
		free(r->upstream_path);
		free(r->id);
	}
	free(cfg->rules);
	match_free(cfg->idx);
	free(cfg);
}
