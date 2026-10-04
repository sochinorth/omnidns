# omnidns — implementation plan

## Context

omnidns is a new DNS proxy daemon for OpenWrt. It answers LAN clients directly and matches each name against an ordered UCI ruleset. It follows alias chains and checks policy again at each step. For selected names it returns fake "token" IPs. A fake IP encodes routing policy, and nftables DNATs it back to the real IP and applies an fwmark. The project starts empty. We have an aarch64 OpenWrt SDK (kernel 6.12, so the single-register arith limit applies), plus host libmnl 1.0.5 and libnftnl 1.3.2. There is no host libubox, `dig` or dnspython. nftables does work inside `unshare -rn`, so integration tests can run without root.

### Decisions you made (Q&A)
- **The latch pins the upstream.** Once fakeip latches, both the fwmark and the upstream are frozen. Later rules can only `block`.
- **The block response is configurable.** Global `option block_mode nodata|nxdomain|null`, default `nodata` (with a synthetic SOA, neg-TTL `block_ttl`, default 300). The same response is used when a CNAME-cloaked tracker matches mid-chain.
- **Binding key** = `(rule_id, fwmark, endpoint_name, real_ip)`. endpoint_name is the owner of the terminal A/AAAA RRset, or the effective SVCB TargetName. The upstream is not part of the key, so changing it does not churn fakes.
- **Aliases chased by the client are a documented limitation.** These are HTTPS AliasMode targets and hintless ServiceMode targets. Their follow-up queries are evaluated on their own name only.

### Spec corrections and assumptions (correct me at review)
1. **The recursion bug in the pseudocode.** `return omni_resolve(rules, answ.cname)` drops the CNAME prefix, so clients reject the answer. It also discards the fakeip latch. Replaced by the walk-state machine below: the prefix RRs are spliced in front of the re-queried answer.
2. **The re-query condition.** Re-query the target only when the *effective upstream identity* changes. A different verdict with the same upstream keeps walking the same response. Upstream identity is the canonical server list (file content), not the path.
3. **Typo:** `fake2real_v6`/`fake2mark_v6` keys must be `ipv6_addr`.
4. **fwmark encoding:** a rule's `fwmark '0x01'` is a small value shifted into `fwmask` (`0x01 << ctz(0xff000000)` = `0x01000000`). It must be non-zero and fit the mask.
5. **Masked marks everywhere.** Your sketch's `ct mark != 0 meta mark set ct mark` clobbers bits that other software owns (mwan3, fw4 offload, qos). The fix:
   - each mark chain uses a single bitwise statement, which is legal on 6.12: `meta mark set meta mark and ~M or V; ct mark set ct mark and ~M or V`.
   - restore becomes `ct mark and M vmap { V1 : jump mark_V1, ... }`, which reuses the mark chains.
6. **Unmatched fake IPs.** You can't reject inside a nat chain. After DNAT, daddr is the real IP, so a filter chain in forward/output does `ip daddr <pool> reject`. That catches only *unmapped* fakes, and clients fail fast instead of hanging.
7. **`listen '5353'` collides with mDNS** (umdns/avahi). Clients can't use non-53 ports anyway. So: `option port 53` plus `list listen_addr` (default: LAN addresses), and dnsmasq moves to e.g. `127.0.0.1#5335`. Never bind the WAN, so we don't become an open resolver.
8. **resolv.conf has no port syntax**, yet dnsmasq needs one to be an upstream. Extension: `nameserver 127.0.0.1#5335`. `%scope` is accepted for link-local IPv6.
9. **Catchall rules.** A rule with no `nameset` option matches everything. It must be the last rule, or the config is rejected. Any action is allowed, so "fakeip everything except domestic" works. A rule whose nameset globs resolve to no readable files matches nothing (warn). A config with no catchall is rejected.
10. **DNSSEC.** Upstream queries use EDNS0 (bufsize 1232) with DO=0. Responses that need rewriting get RRSIG/NSEC* stripped. Unmodified responses are forwarded as received (only ID/question case/EDNS rebuilt per client). ECS is never sent.
11. **AAAA under a fakeip latch when no v6 pool is configured** returns NODATA, and ipv6hint is stripped. Real v6 is never leaked past a policy.
12. **Pool exhausted** (no slot free past its `safe_until`): SERVFAIL plus a rate-limited syslog warning. Never fall back to the real IP.
13. **`safe_until` = expiry of the answered TTL + `fakeip_grace` (default 600s).** Established flows survive map deletion anyway, because the NAT is in conntrack. So `safe_until` only has to cover clients that cache past the TTL.
14. **fwmask changes are rejected while live bindings exist**, same as pool changes.
15. **PTR queries for fake-pool addresses** are answered locally from the binding (endpoint name), else NXDOMAIN. They are never leaked upstream.
16. **Other qtypes** (MX, TXT, SRV, …) take the same walk for steering and blocking, with no rewriting. ANY → NOTIMP (RFC 8482-ish minimal). Non-IN class and AXFR/IXFR → REFUSED.
17. **Upstream files change at runtime** (WAN reconnect). The procd init uses `procd_add_reload_trigger omnidns` plus interface triggers, which send SIGHUP. Unchanged upstream content means no invalidation.
18. **libuci** is used for config parsing (standard on OpenWrt, sits alongside libubox).

---

## Architecture

Single-threaded `uloop` event loop. Repo layout (CMake, the OpenWrt-native choice for libubox projects):

```
CMakeLists.txt
src/
  main.c         uloop setup, signals, procd-friendly foreground, syslog
  log.h          ulog wrappers + rate-limited logging
  util/hmap.[ch] open-addressing hashmap, SipHash-2-4 keyed (generic, arena keys)
  util/s3fifo.[ch] generic intrusive S3-FIFO (small/main/ghost), watermark batch eviction
  util/arena.[ch] bump allocator for nameset strings
  dns/wire.[ch]  parser/builder: bounded, compression-loop-safe, RR iterator, name normalize
  dns/svcb.[ch]  SVCB/HTTPS rdata parse/rewrite (ipv4hint/ipv6hint), preserve other params
  config.[ch]    UCI → struct config; nameset file cache (path,dev,ino,mtime,size → parsed)
  upstream.[ch]  resolv.conf parse, upstream identity hash, UDP/TCP client, retry, coalescing
  match.[ch]     suffix index: hmap<suffix → {min_exact_ord, min_suffix_ord}>, match_rules()
  resolve.[ch]   walk state machine (async continuation), answer assembly
  fakeip.[ch]    pools, allocator, binding DB (key→b, fake→b), renew/evict
  nft.[ch]       libmnl/libnftnl: table bootstrap, mark chains, element batches, reconcile
  cache.[ch]     answer cache + dependency validation
  server.[ch]    UDP + TCP listeners, client limits, response truncation/EDNS
  ubus.[ch]      (phase 6) status/dump/flush methods
openwrt/
  Makefile       package recipe (DEPENDS: +libubox +libuci +libmnl +libnftnl +kmod-nft-nat)
  files/omnidns.init  procd service
  files/omnidns.config  default UCI
tests/
  unit/*.c       per-module tests (plain asserts, run on host)
  fuzz/*.c       libFuzzer targets: wire parser, svcb rewrite, resolv.conf, nameset
  integ/         python3 stdlib-only fake upstream + client, netns runner
```

### Core algorithms

**Matching (match.c).** All rules' patterns go into one hmap keyed by the normalized dotted suffix string. Each value holds `{min_exact_ord, min_suffix_ord}` (uint16, `NONE`=0xffff). To match `a.b.google.com`:
- at the full name, consider exact and suffix;
- at each ancestor (`b.google.com`, `google.com`, `com`), consider suffix only;
- the minimum ordinal wins;
- if nothing matched, use the catchall ordinal.

`*.x` is stored as a suffix entry for `x`, apex-inclusive. Names containing non-LDH/escaped bytes still match by ancestor suffix. Reload rebuilds the index from cached per-file pattern arrays. Unchanged files are not re-read.

**The walk (resolve.c).** State is `{name, upstream, latch (fakeip policy|NULL), prefix_rrs[], deps[], steps}`. The `steps` limit is 12, and a visited-name set detects loops.
1. `r = match(name)`, then `deps += (name, r.id, r.fingerprint)`.
2. `block` → stop, using block_mode for the original qname.
3. If there is no latch:
   - `forward` → `want = r.upstream`.
   - `fakeip` → `latch = r` and `want = r.upstream`.
   If there is a latch, `want = latch.upstream`.
4. If no response is in hand or `want != upstream`: query `(name, qtype)` at `want` and set `upstream = want`.
5. Scan the answer from `name`. For a CNAME, DNAME (use the synthesized CNAME, or substitute it ourselves) or HTTPS/SVCB AliasMode (qtype HTTPS/SVCB only), append the alias RRs to the prefix, set `name = target`, and loop to step 1. That re-evaluates the alias against the current response, and step 4 re-queries only when the upstream changes. If the chain dangles with no terminal RRset and no further alias, query the target ourselves.
6. Terminal RRset:
   - A/AAAA with a latch → allocate or renew bindings, then rewrite.
   - SVCB/HTTPS ServiceMode: each RR is its own endpoint. Its effective TargetName (`.` means the owner) is matched:
     - `block` → drop that RR;
     - else if a latch exists → rewrite the hints with the latch;
     - else if `fakeip` → that RR gets its own latch and rewritten hints;
     - else leave it alone.
     The target is never resolved. If every RR is dropped, the answer is NODATA.
7. Assemble the answer from the prefix RRs, the terminal RRs and the original authority/additional when unchanged. Nothing is rewritten, so the reply can be forwarded verbatim.
8. Bindings are collected during the walk but committed only once the walk finishes and the answer is final, which honours the "defer allocation" note. Commit order: allocate → one nft batch (add elements) → wait for ACK → cache insert → reply. If nft fails, return SERVFAIL.

**Fake IPs (fakeip.c).**
- **Allocation:** the first candidate is `base + siphash(secret, key) mod size`, then linear probing. Excluded: the pool's network/broadcast (v4), the subnet-router anycast (v6), 0/::, multicast, and loopback (checked on pool config).
- **Probe outcomes:** a free slot → take it. A slot with an expired occupant (`safe_until` < now) → reclaim it: queue a nft delete+add for that fake in the same batch. Probing is bounded at 64; past that, use the S3-FIFO eviction pass.
- **Renewal:** a lookup by key that finds an existing binding (live or expired, not yet evicted) just extends `safe_until`. A real IP that disappears is simply not extended.
- **Data structures:** two hmaps (key→binding, fake→binding) and a capacity cap `fakeip_max_bindings` (default 65536). S3-FIFO skips non-evictable entries. Batched eviction runs from a high to a low watermark, with nft deletes in bounded batches (`nft_batch_max`, default 1024 elements).
- **Policy identity:** a fakeip policy is `(rule_id, fwmark)`. The mark-chain refcount is the number of bindings using that mark. A chain is removed only when its refcount hits 0 and no rule references it.

**nftables (nft.c).** The process owns `table inet omnidns`. At startup, one transaction does delete-table-if-exists + create. Contents:
- maps `fake2real_v4/v6` (addr:addr) and `fake2mark_v4/v6` (addr:verdict).
- chains `mark_<V>`.
- `prerouting_restore` (mangle) and `prerouting_classify` (dstnat: vmap → ct mark set meta mark and M → dnat via map).
- `output_restore`/`output_classify` (hook output, for router-originated traffic).
- `reject_unmapped` (filter forward/output).

Netlink runs async on a uloop fd with sequence-tracked ACKs. Element adds from concurrent resolutions in one loop iteration are coalesced into one batch. Reload builds the desired mark chains and classify rules, then diffs against our shadow state. Changes go in as bounded transactions; on failure the old config stays and the error goes to syslog. Maps are never flushed on reload.

**Cache (cache.c).**
- **Key** = `(lowercased qname, qtype, qclass)`. The DO bit is irrelevant because upstream queries always use DO=0.
- **Value:**
  - the assembled answer, compressed off and pre-parsed into RR offsets so TTLs can be patched;
  - its insert time and the per-RR original TTLs;
  - `deps[]` of `(name, rule_id, rule_fingerprint)`. The fingerprint is a hash of action, upstream identity, fwmark and the latch-relevant settings;
  - the binding refs;
  - the `cfg_gen` it was validated against.
- **Hit:** if `entry.cfg_gen != cur_gen`, call `match()` again for each dep name and compare `(rule_id, fingerprint)`. A mismatch drops the entry; a match re-stamps the gen. This catches newly inserted earlier rules, nameset edits and upstream changes cheaply and conservatively. Then decrement the TTLs (floor 0). An entry expires at its minimum TTL.
- **Negative answers:** cached for the SOA minimum, capped at `neg_ttl_max` (default 3600).
- **Eviction:** bounded S3-FIFO by entries and bytes (`cache_size`, default 10000), batched with watermarks. Dropping an entry never touches bindings. A served fakeip hit keeps its bindings at or past the remaining TTL + grace, extending them if needed.

**Upstream (upstream.c).**
- Each query uses a fresh random-port UDP socket and a random ID. Responses are checked against the source addr/port, ID and question.
- Servers are tried in order with a per-try timeout (`upstream_timeout`, default 1500ms) and an overall deadline of 5s.
- TC=1 → retry once over TCP on the same server.
- SERVFAIL/REFUSED/timeouts → next server. All failing → SERVFAIL to the client.
- Identical in-flight `(upstream_id, name, qtype)` queries are coalesced.

**Server (server.c).**
- UDP and TCP on each listen addr. The listen sockets are opened before privileges drop.
- **EDNS:** honour the client's bufsize, clamped to [512, 1232]. A response larger than that is truncated with TC=1. Echo OPT if the client sent one. Return FORMERR for malformed queries and BADVERS for EDNS version > 0.
- **TCP:** pipelined queries with out-of-order answers (RFC 7766), at most 64 connections and 16 in-flight per connection, a 10s idle timeout and a 64KiB read cap.
- **Global limits:** at most 1024 pending client queries and 64 per client IP; past those, REFUSED/drop. The question section is echoed byte-exact so 0x20 clients keep their case.

### Config (UCI)

```uci
config omnidns 'main'
	option port '53'
	list listen_addr '192.168.1.1'
	option fwmask '0xff000000'
	option fakeip_v4 '198.18.0.0/15'
	option fakeip_v6 '64:ff9b:1::/48'      # optional
	option fakeip_grace '600'
	option fakeip_max_bindings '65536'
	option cache_size '10000'
	option block_mode 'nodata'              # nodata|nxdomain|null
	option block_ttl '300'
	option upstream_timeout '1500'

config rule 'adblock'            # section name = stable rule id
	option action 'block'
	list nameset '/tmp/omnidns.d/adlist/*'
...
config rule 'catchall'           # no nameset → must be last
	option action 'forward'
	option upstream '/etc/omnidns.d/dns_1111.conf'
```

On SIGHUP, the full new config is built off to the side (nameset file cache, index, upstreams). It is validated: pool and fwmask changes are rejected if live bindings would be stranded. The nft changes are applied, and only then is the new config swapped in atomically with `cfg_gen++`. If any step fails, the old config stays and the error goes to syslog.

---

## Execution plan (root agent + implementation subagents)

I'm the integration agent. Before fanning out I write the headers myself: types, function signatures and invariants for every module. Subagents then work against frozen interfaces, each with its own unit tests. Every phase ends with me building, running all tests and reviewing.

**Phase 0 — scaffold (me).**
- `git init`, CMake, and a host build of libubox + libuci. Both are fetched from git.openwrt.org into `third_party/` (gitignored) and installed to `build/host-prefix`; libmnl/libnftnl come from the system.
- All `src/**/*.h` interfaces, `log.h`, a test runner target, and sanitizer flags (`-fsanitize=address,undefined`) for the host build.

**Phase 1 — leaf modules (4 parallel subagents, git worktrees):**
- A: `util/hmap`, `util/arena`, `util/s3fifo`, with tests (including eviction with skip-pinned).
- B: `dns/wire` + `dns/svcb`, with tests and fuzz targets (compression loops, truncated RRs, oversize names, SVCB param ordering).
- C: `config` (UCI + nameset globbing/caching + resolv.conf w/ `#port`) and `match`, with tests including the 100k-pattern ordinal-semantics test.
- D: `nft`, covering bootstrap, mark chains, element batching and reconcile. Tested in `unshare -rn` by asserting `nft -j list table inet omnidns`.

**Phase 2 — `fakeip` + `upstream` (2 parallel subagents).**
- fakeip: allocator determinism, exclusions, reclaim of expired occupants, renewal, exhaustion, and pool/mask-change rejection.
- upstream: tested against a python stdlib fake server for retries, TC→TCP, coalescing, spoofed-response rejection and timeouts.

**Phase 3 — `resolve` + `cache` + `server` + `main` (1 subagent for resolve/cache, me for server/main/integration).** The walk is the core semantic piece. It gets a table-driven test suite with a scripted upstream, one case per rule in the "walk" section:
- latch + downstream forward with a pinned upstream;
- block mid-chain;
- DNAME;
- an AliasMode chase;
- ServiceMode siblings with different latches;
- a dangling CNAME;
- loop/step limits;
- AAAA without a v6 pool.

**Phase 4 — integration (me + 1 test subagent).** `tests/integ/run.sh` sets up a netns (`unshare -rn`, veth pairs between "lan" and "wan" namespaces). It runs omnidns plus python fake upstreams (one per upstream identity) and drives queries with a stdlib python DNS client. It checks:
- answers, rewritten hints and TTL countdown;
- nft maps/chains after each step;
- a real TCP connect to a fake IP that gets DNATed to a listener on "wan" with the expected fwmark (`nft` counter / `meta mark` log rule);
- a SIGHUP reload that keeps bindings, a rejected pool change and cache invalidation on rule reorder;
- fuzz/garbage flooding, which must stay within its memory limits.

**Phase 5 — OpenWrt packaging (subagent).** Covers the `openwrt/Makefile`, procd init (respawn, reload triggers, interface trigger), default UCI and a README section on moving dnsmasq to :5335. Then a cross-build in the SDK: add the `base`/`packages` feeds, `make package/omnidns/compile`, and confirm the aarch64 ipk links.

**Phase 6 — polish (optional).** A ubus `status`/`dump_bindings`/`flush_cache`, a `/code-review high` pass, and docs for the known limitations (client-chased aliases, no DNSSEC passthrough when rewriting, flow offload bypasses marks).

## Verification
- `cmake -B build -DHOST=1 && cmake --build build && ctest --test-dir build`: all unit tests pass under ASan/UBSan.
- Each fuzz target runs 5 min each with no crashes (`clang -fsanitize=fuzzer`).
- `tests/integ/run.sh` passes end-to-end in an unprivileged netns, including real DNATed TCP flows carrying the correct mark.
- The SDK cross-build produces `omnidns_*.ipk` for aarch64_cortex-a53, and `file`/`readelf` confirm it links against libubox/libuci/libmnl/libnftnl.
