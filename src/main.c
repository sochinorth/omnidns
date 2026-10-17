// SPDX-License-Identifier: MIT
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include <libubox/uloop.h>

#include "cache.h"
#include "config.h"
#include "fakeip.h"
#include "log.h"
#include "nft.h"
#include "omnidns.h"
#include "resolve.h"
#include "server.h"
#include "upstream.h"
#include "util/hash.h"
#include "util/time.h"

/*
 * Mark chains installed at once: bounds the bootstrap/reconcile transaction,
 * which must fit the netlink socket's send buffer (with 4096 chains a
 * bootstrap is about 12000 messages and 2.1 MB, a reconcile replacing every
 * chain 16000 and 2.4 MB; both tested on the real kernel in test_nft).
 * A config has at most CONFIG_MAX_RULES marks of its own.
 */
#define MAX_MARKS 4096
_Static_assert(CONFIG_MAX_RULES <= MAX_MARKS, "a config's own marks must fit");

static struct omni omni;
static const char *nft_table;
static const char *run_dir = "/var/run";
static bool destroy_on_exit;
static bool log_to_stderr;

/*
 * <run_dir>/omnidns-<table>.hold: the hold file (fakeip_hold_save()), how
 * long each fake of the table must still be kept, written by a clean exit
 * and consumed by the next adoption.
 *
 * <run_dir>/omnidns-<table>.lock: one instance of a table at a time. A
 * daemon takes an exclusive flock on it before it reads the table or the
 * hold file and keeps it until it has written the hold file at exit (the
 * process ending releases it); `-F` takes it before deleting the table.
 * Without it, a restart through procd (which lets the new process start
 * before the old one has exited; SO_REUSEPORT lets both bind) would have
 * the old daemon's exit drain destroy elements the new one just adopted,
 * and a `-F` racing a starting daemon could leave the table behind. With
 * it, a restart always finds the old daemon's hold file.
 *
 * The wait is bounded by LOCK_WAIT_MS, longer than an exiting daemon can
 * take: procd SIGKILLs it 5 s after SIGTERM (term_timeout) and its exit
 * drain gives up after the 10 s netlink receive timeout. On timeout the
 * daemon exits non-zero (procd respawns it) rather than run beside an
 * instance still holding the table, which is the unsafe overlap; `-F`
 * fails without deleting anything. If the lock file cannot be opened
 * (no such directory), the daemon runs without it and without hold file,
 * as before there was one.
 *
 * Empty paths (the table name is no file name): neither.
 */
#define LOCK_WAIT_MS 15000

static char hold_path[512], lock_path[512];
static int lock_fd = -1;

static void run_paths(void)
{
	const char *t = nft_table ? nft_table : "omnidns";
	int a, b;

	if (strchr(t, '/'))
		return;
	a = snprintf(hold_path, sizeof(hold_path), "%s/omnidns-%s.hold", run_dir, t);
	b = snprintf(lock_path, sizeof(lock_path), "%s/omnidns-%s.lock", run_dir, t);
	if (a < 0 || (size_t)a >= sizeof(hold_path) || b < 0 || (size_t)b >= sizeof(lock_path))
		hold_path[0] = lock_path[0] = 0;
}

/* The table lock, see above: 0 (or no lock file: logged, lock_fd -1) or
 * -ETIMEDOUT (logged). */
static int lock_table(void)
{
	static const struct timespec poll = { .tv_nsec = 50 * 1000 * 1000 };
	uint64_t deadline = omni_now_ms() + LOCK_WAIT_MS;
	bool waiting = false;
	int fd;

	if (!lock_path[0])
		return 0;
	fd = open(lock_path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		log_warn("%s: %s; running without the table lock and hold file", lock_path,
		         strerror(errno));
		return 0;
	}
	while (flock(fd, LOCK_EX | LOCK_NB)) {
		if (errno == EINTR)
			continue;
		if (errno != EWOULDBLOCK) {
			log_warn("%s: flock: %s; running without the table lock and hold file",
			         lock_path, strerror(errno));
			close(fd);
			return 0;
		}
		if (omni_now_ms() >= deadline) {
			log_err("%s: another instance still holds the table after %d s",
			        lock_path, LOCK_WAIT_MS / 1000);
			close(fd);
			return -ETIMEDOUT;
		}
		if (!waiting)
			log_info("waiting for another instance of the table to exit");
		waiting = true;
		nanosleep(&poll, NULL);
	}
	lock_fd = fd;
	return 0;
}

/* CLOCK_BOOTTIME seconds: steady across processes, unlike the wall clock,
 * which NTP steps (on routers without RTC, at the first sync after boot) */
static uint64_t boot_clock(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (uint64_t)ts.tv_sec;
}

/* At exit, after the last element batch is acked, under the table lock.
 * The table is left alone. */
static void save_hold(void)
{
	int ret;

	if (lock_fd < 0 || !omni.fdb || destroy_on_exit)
		return;
	ret = fakeip_hold_save(omni.fdb, hold_path, boot_clock());
	if (ret)
		log_warn("%s: %s (a restart keeps every fake IP for fakeip_ttl_max + "
		         "fakeip_grace)", hold_path, strerror(-ret));
	else
		log_info("saved the fake IPs in use to %s", hold_path);
}

/*
 * Mark chains installed so far (= the nft shadow's marks). They are kept
 * across reloads until the fwmask changes: walks in flight across a reload
 * may still bind with a mark the new config no longer uses, and chains are
 * tiny.
 *
 * Invariant: at reconcile time every binding's mark is in kept_marks (or
 * the binding DB is empty), so the desired state never has to consult the
 * DB. reload() drains all element batches first; a failed batch drops its
 * bindings (fakeip fail hook) and a batch only succeeds if its mark chains
 * exist, i.e. were in the desired state of the last successful reconcile,
 * which is kept_marks. Waiter callbacks run during the drain only answer
 * or fail queries and never create bindings. Without an fwmask change
 * kept_marks is carried into the new desired state, so no chain a binding
 * uses is deleted. An fwmask change is only accepted once the DB is empty
 * (live bindings reject it, expired ones are evicted). A walk that latched
 * a mark before the change and binds after it is refused by fakeip_bind()
 * (nft_mark_known(): the chain is gone), so it never creates a binding.
 * At startup, the bindings adopted from an earlier process's table
 * (placeholders) bring their marks (adopt_table()).
 */
static uint32_t kept_marks[MAX_MARKS];
static uint32_t nkept_marks;

static int add_mark(uint32_t *marks, uint32_t *n, uint32_t m)
{
	uint32_t i;

	for (i = 0; i < *n; i++)
		if (marks[i] == m)
			return 0;
	if (*n == MAX_MARKS)
		return -E2BIG;
	marks[(*n)++] = m;
	return 0;
}

/*
 * Desired dataplane: pools and fwmask from cfg, marks = marks of fakeip
 * rules in cfg and (unless the mask changes) every mark installed before,
 * which covers every mark still referenced by a binding (see kept_marks).
 * -E2BIG if that is more than MAX_MARKS: no mark may be left out, since a
 * kept one may still be in use.
 */
static int build_desired(const struct config *cfg, struct nft_desired *d, uint32_t *marks,
                         bool keep_old)
{
	uint32_t n = 0, i;
	int r;

	for (r = 0; r < cfg->nrules; r++)
		if (cfg->rules[r].action == RULE_FAKEIP && add_mark(marks, &n, cfg->rules[r].mark))
			return -E2BIG;
	if (keep_old)
		for (i = 0; i < nkept_marks; i++)
			if (add_mark(marks, &n, kept_marks[i]))
				return -E2BIG;
	memset(d, 0, sizeof(*d));
	d->fwmask = cfg->fwmask;
	d->has_pool4 = cfg->has_pool4;
	d->has_pool6 = cfg->has_pool6;
	d->pool4 = cfg->pool4;
	d->pool6 = cfg->pool6;
	d->marks = marks;
	d->nmarks = n;
	return 0;
}

/*
 * Startup with the table an earlier process left (a restart): take over its
 * secret, so keys probe the same fakes, and keep its map elements as
 * placeholder bindings, so fakes clients still hold keep working. With a
 * hold file of this table (a clean exit before), an element is kept for
 * the hold it lists, and one it does not list (evictable at that exit) is
 * destroyed; without one, every element is kept for fakeip_ttl_max +
 * fakeip_grace. Elements that are not a consistent pair inside the current
 * pools with a known mark chain are destroyed; beyond fakeip_max_bindings,
 * those after the first max_bindings in address order (v4 first) are too,
 * since the kernel keeps no age. Their marks join kept_marks. On success
 * omni.fdb exists and the table is reconciled with the configuration;
 * otherwise nothing is kept and the caller bootstraps.
 */
static bool adopt_table(void)
{
	static uint32_t marks[MAX_MARKS];
	const struct config *cfg = omni.cfg;
	struct nft_desired d;
	struct nft_elem *el;
	struct fakeip_hold *h = NULL;
	struct binding *b;
	uint8_t secret[NFT_SECRET_LEN];
	uint32_t nel, kept, max32, it = 0;
	uint64_t max = 2 * (uint64_t)cfg->fakeip_max_bindings;
	uint64_t hold = (uint64_t)cfg->fakeip_ttl_max + cfg->fakeip_grace;
	int ret, herr = -ENOENT;

	max32 = max > UINT32_MAX ? UINT32_MAX : (uint32_t)max;
	if (build_desired(cfg, &d, marks, false))
		return false;
	if (nft_adopt(omni.nft, &d, max32, secret, &el, &nel) != 1)
		return false;
	omni.fdb = fakeip_new(cfg->has_pool4 ? &cfg->pool4 : NULL,
	                      cfg->has_pool6 ? &cfg->pool6 : NULL,
	                      cfg->fakeip_max_bindings, cfg->fakeip_grace, secret, omni.nft);
	if (!omni.fdb) {
		free(el);
		return false;
	}
	if (lock_fd >= 0)
		h = fakeip_hold_load(hold_path, secret, max32, boot_clock(), &herr);
	if (h)
		log_info("startup: %s lists %u fake IPs in use", hold_path, fakeip_hold_count(h));
	else if (herr != -ENOENT)
		log_warn("startup: ignoring %s (%s)", hold_path, strerror(-herr));
	else
		log_info("startup: no hold file (no clean exit before): every fake IP of the "
		         "existing table is kept for fakeip_ttl_max + fakeip_grace");
	kept = fakeip_adopt_elems(omni.fdb, el, nel,
	                          hold > UINT32_MAX ? UINT32_MAX : (uint32_t)hold, h);
	fakeip_hold_free(h);
	free(el);
	nkept_marks = 0;
	ret = 0;
	while (!ret && (b = fakeip_next(omni.fdb, &it)))
		ret = add_mark(kept_marks, &nkept_marks, fakeip_mark(omni.fdb, b));
	if (ret) {
		log_warn("startup: fake IPs of the existing table use more than %d marks",
		         MAX_MARKS);
		goto fail;
	}
	ret = build_desired(cfg, &d, marks, true);
	if (ret) {
		log_warn("startup: more than %d marks with those of the existing table's fake IPs",
		         MAX_MARKS);
		goto fail;
	}
	/* the deletes must land before chains they reference go */
	nft_flush(omni.nft);
	ret = nft_drain(omni.nft);
	if (!ret)
		ret = nft_reconcile(omni.nft, &d);
	if (ret)
		goto fail;
	memcpy(kept_marks, marks, d.nmarks * sizeof(*marks));
	nkept_marks = d.nmarks;
	log_info("startup: kept %u fake IPs of the existing table, dropped %u", kept, nel - kept);
	return true;

fail:
	log_warn("startup: cannot take over the existing table; recreating it");
	fakeip_free(omni.fdb);
	omni.fdb = NULL;
	nkept_marks = 0;
	return false;
}

static void apply_runtime_limits(const struct config *cfg)
{
	upstream_set_timeouts(cfg->upstream_timeout_ms, cfg->upstream_total_timeout_ms);
	cache_set_limits(omni.cache, cfg->cache_size, cfg->cache_max_bytes);
	log_init("omnidns", log_to_stderr, cfg->log_level);
}

static int reload(void)
{
	static uint32_t marks[MAX_MARKS];
	struct config *ncfg, *old = omni.cfg;
	struct nft_desired d;
	bool mask_changed, same;
	char err[512];
	int ret;

	ncfg = config_reload(omni.config_path, &omni.nsc, old, err, sizeof(err));
	if (!ncfg) {
		log_err("reload: %s; keeping previous configuration", err);
		nsc_sweep(&omni.nsc);	/* drop files parsed for the failed config */
		return -EINVAL;
	}
	mask_changed = ncfg->fwmask != old->fwmask;
	ret = build_desired(ncfg, &d, marks, !mask_changed);
	if (ret) {
		log_err("reload: more than %d fwmark chains needed (marks of this "
			"configuration plus those kept from earlier ones); keeping previous "
			"configuration (a restart drops unused chains)", MAX_MARKS);
		goto fail;
	}
	if (mask_changed) {
		uint32_t live;

		/*
		 * Cached answers pin bindings. Only expired ones are dropped
		 * here: a binding outlives an answer carrying it (by
		 * fakeip_grace), so an unexpired answer's bindings are live
		 * anyway, and a rejected reload keeps the cache.
		 */
		cache_sweep_expired(omni.cache);
		live = fakeip_remask_blockers(omni.fdb);
		if (live) {
			log_err("reload: fwmask change rejected while %u fake IP bindings are "
				"live; keeping previous configuration", live);
			ret = -EBUSY;
			goto fail;
		}
	}
	ret = fakeip_set_config(omni.fdb, ncfg->has_pool4 ? &ncfg->pool4 : NULL,
				ncfg->has_pool6 ? &ncfg->pool6 : NULL,
				ncfg->fakeip_max_bindings, ncfg->fakeip_grace);
	if (ret) {
		log_err("reload: fake IP pool change rejected (%s): live bindings outside the "
			"new pool; keeping previous configuration", strerror(-ret));
		goto fail;
	}
	/* element deletes of evicted bindings must land before their chains go */
	nft_flush(omni.nft);
	nft_drain(omni.nft);
	ret = nft_reconcile(omni.nft, &d);
	if (ret) {
		log_err("reload: nftables reconciliation failed (%s); keeping previous "
			"configuration", strerror(-ret));
		/* bindings were allocated inside the old pools: reverting cannot fail */
		fakeip_set_config(omni.fdb, old->has_pool4 ? &old->pool4 : NULL,
		                  old->has_pool6 ? &old->pool6 : NULL,
		                  old->fakeip_max_bindings, old->fakeip_grace);
		goto fail;
	}
	/* answers resolved under the old fwmask (none carries a fake now) */
	if (mask_changed)
		cache_flush(omni.cache);
	memcpy(kept_marks, marks, d.nmarks * sizeof(*marks));
	nkept_marks = d.nmarks;
	/* same index, fwmask and fingerprints: cached answers need no
	 * revalidation (deps_valid would accept every one of them) */
	same = config_same_policy(old, ncfg);
	ncfg->gen = same ? old->gen : ++omni.next_gen;
	omni.cfg = ncfg;
	ret = server_reconfigure(&omni);
	if (ret)
		log_err("reload: keeping previous listeners (%s)", strerror(-ret));
	apply_runtime_limits(ncfg);
	config_free(old);
	nsc_sweep(&omni.nsc);
	log_info("configuration reloaded (generation %llu%s, %u rules)",
	         (unsigned long long)ncfg->gen, same ? " kept: resolution unchanged" : "",
	         ncfg->nrules);
	return 0;

fail:
	config_free(ncfg);
	nsc_sweep(&omni.nsc);
	return ret;
}

static void sighup_cb(struct uloop_signal *s)
{
	reload();
}

static struct uloop_signal sighup = { .signo = SIGHUP, .cb = sighup_cb };

/* Expired cache entries pin their bindings: sweep them regularly so expired
 * bindings become reclaimable, then trim the binding DB. */
#define SWEEP_INTERVAL_MS 30000

static void sweep_cb(struct uloop_timeout *t)
{
	cache_sweep_expired(omni.cache);
	fakeip_maybe_evict(omni.fdb);
	uloop_timeout_set(t, SWEEP_INTERVAL_MS);
}

static struct uloop_timeout sweep_timer = { .cb = sweep_cb };

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-c config] [-f] [-t nft_table] [-r run_dir] [-x | -F]\n"
		"  -c  UCI config file (default /etc/config/omnidns)\n"
		"  -f  log to stderr instead of syslog\n"
		"  -t  nftables table name (default omnidns)\n"
		"  -r  directory of the hold and lock files (default /var/run)\n"
		"  -x  delete the nftables table on exit (by default a restarted\n"
		"      daemon takes it over, with the fake IPs clients hold)\n"
		"  -F  delete the nftables table and exit (service stop)\n", prog);
}

int main(int argc, char **argv)
{
	static uint32_t marks[MAX_MARKS];
	struct nft_desired d;
	uint8_t secret[NFT_SECRET_LEN];
	bool flush_only = false;
	char err[512];
	int opt, ret = 1;

	omni.config_path = "/etc/config/omnidns";
	while ((opt = getopt(argc, argv, "c:ft:r:xFh")) != -1) {
		switch (opt) {
		case 'c': omni.config_path = optarg; break;
		case 'f': log_to_stderr = true; break;
		case 't': nft_table = optarg; break;
		case 'r': run_dir = optarg; break;
		case 'x': destroy_on_exit = true; break;
		case 'F': flush_only = true; break;
		default: usage(argv[0]); return opt == 'h' ? 0 : 1;
		}
	}

	log_init("omnidns", log_to_stderr, LOG_INFO);
	run_paths();
	if (flush_only) {
		/* the config is not read: a broken one must not keep the table */
		if (lock_table())
			return 1;
		omni.nft = nft_open(nft_table);
		ret = !omni.nft || nft_destroy_table(omni.nft);
		nft_close(omni.nft);
		if (hold_path[0])
			unlink(hold_path);
		if (lock_fd >= 0)
			close(lock_fd);
		return ret;
	}
	hash_init();
	if (getrandom(secret, sizeof(secret), 0) != sizeof(secret)) {
		log_err("getrandom: %s", strerror(errno));
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	nsc_init(&omni.nsc);

	omni.cfg = config_load(omni.config_path, &omni.nsc, err, sizeof(err));
	if (!omni.cfg) {
		log_err("config: %s", err);
		return 1;
	}
	omni.cfg->gen = ++omni.next_gen;
	log_init("omnidns", log_to_stderr, omni.cfg->log_level);

	if (uloop_init()) {
		log_err("uloop_init failed");
		goto out_cfg;
	}
	omni.nft = nft_open(nft_table);
	if (!omni.nft) {
		log_err("cannot open nftables netlink socket");
		goto out_loop;
	}
	nft_set_secret(omni.nft, secret);
	if (lock_table())
		goto out_nft;
	if (!adopt_table()) {
		nft_set_secret(omni.nft, secret);	/* adoption may have read another */
		if (build_desired(omni.cfg, &d, marks, false) || nft_bootstrap(omni.nft, &d)) {
			log_err("nftables bootstrap failed");
			goto out_nft;
		}
		memcpy(kept_marks, marks, d.nmarks * sizeof(*marks));
		nkept_marks = d.nmarks;
		omni.fdb = fakeip_new(omni.cfg->has_pool4 ? &omni.cfg->pool4 : NULL,
		                      omni.cfg->has_pool6 ? &omni.cfg->pool6 : NULL,
		                      omni.cfg->fakeip_max_bindings, omni.cfg->fakeip_grace,
		                      secret, omni.nft);
	}
	/* read by the adoption, or stale (of another table, or of none) */
	if (lock_fd >= 0)
		unlink(hold_path);
	omni.cache = cache_new(omni.cfg->cache_size, omni.cfg->cache_max_bytes, omni.fdb);
	if (!omni.fdb || !omni.cache) {
		log_err("out of memory");
		goto out_state;
	}
	upstream_init(omni.cfg->upstream_timeout_ms, omni.cfg->upstream_total_timeout_ms);
	if (server_start(&omni))
		goto out_upstream;
	uloop_signal_add(&sighup);
	uloop_timeout_set(&sweep_timer, SWEEP_INTERVAL_MS);

	log_info("omnidns started: %u rules, port %u", omni.cfg->nrules, omni.cfg->port);
	uloop_run();
	log_info("shutting down");
	ret = 0;

	server_stop();
	resolve_shutdown();
out_upstream:
	upstream_shutdown();
out_state:
	if (omni.cache)
		cache_free(omni.cache);
	nft_flush(omni.nft);
	nft_drain(omni.nft);
	save_hold();
	if (omni.fdb)
		fakeip_free(omni.fdb);
	if (destroy_on_exit)
		nft_destroy_table(omni.nft);
out_nft:
	if (lock_fd >= 0)
		close(lock_fd);
	nft_close(omni.nft);
out_loop:
	uloop_done();
out_cfg:
	config_free(omni.cfg);
	nsc_destroy(&omni.nsc);
	return ret;
}
