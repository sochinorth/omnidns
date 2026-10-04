/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OMNI_OMNIDNS_H
#define OMNI_OMNIDNS_H

#include <stdint.h>

#include "config.h"

/*
 * Global daemon state. Passed explicitly (tests build their own instances).
 * cfg is replaced atomically on successful reload; holders of the previous
 * config must not keep pointers into it across loop iterations (in-flight
 * walks keep refs to upstream_sets only, and re-read o->cfg each step).
 */
struct fakeip_db;
struct nft_ctx;
struct cache;

struct omni {
	struct config *cfg;
	uint64_t next_gen;
	struct nameset_cache nsc;
	struct fakeip_db *fdb;
	struct nft_ctx *nft;
	struct cache *cache;
	const char *config_path;
};

#endif
