// SPDX-License-Identifier: MIT
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include <libubox/uloop.h>

#include "cache.h"
#include "config.h"
#include "fakeip.h"
#include "log.h"
#include "nft.h"
#include "omnidns.h"
#include "server.h"
#include "upstream.h"
#include "util/hash.h"

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
static bool destroy_on_exit;
static bool log_to_stderr;

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
		/* cached answers pin bindings and all embed the old marks */
		cache_flush(omni.cache);
		fakeip_evict_expired(omni.fdb);
		if (fakeip_live_count(omni.fdb)) {
			log_err("reload: fwmask change rejected while %u fake IP bindings are "
				"live; keeping previous configuration",
				fakeip_live_count(omni.fdb));
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
		"usage: %s [-c config] [-f] [-t nft_table] [-x]\n"
		"  -c  UCI config file (default /etc/config/omnidns)\n"
		"  -f  log to stderr instead of syslog\n"
		"  -t  nftables table name (default omnidns)\n"
		"  -x  delete the nftables table on exit\n", prog);
}

int main(int argc, char **argv)
{
	static uint32_t marks[MAX_MARKS];
	struct nft_desired d;
	uint8_t secret[16];
	char err[512];
	int opt, ret = 1;

	omni.config_path = "/etc/config/omnidns";
	while ((opt = getopt(argc, argv, "c:ft:xh")) != -1) {
		switch (opt) {
		case 'c': omni.config_path = optarg; break;
		case 'f': log_to_stderr = true; break;
		case 't': nft_table = optarg; break;
		case 'x': destroy_on_exit = true; break;
		default: usage(argv[0]); return opt == 'h' ? 0 : 1;
		}
	}

	log_init("omnidns", log_to_stderr, LOG_INFO);
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
out_upstream:
	upstream_shutdown();
out_state:
	if (omni.cache)
		cache_free(omni.cache);
	nft_flush(omni.nft);
	nft_drain(omni.nft);
	if (omni.fdb)
		fakeip_free(omni.fdb);
	if (destroy_on_exit)
		nft_destroy_table(omni.nft);
out_nft:
	nft_close(omni.nft);
out_loop:
	uloop_done();
out_cfg:
	config_free(omni.cfg);
	nsc_destroy(&omni.nsc);
	return ret;
}
