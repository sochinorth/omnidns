# omnidns manual

omnidns is a policy-aware DNS proxy for OpenWrt. It answers LAN clients directly. It evaluates every name against an
ordered ruleset, and does so again for every alias the resolution passes
through (CNAME, DNAME, HTTPS/SVCB AliasMode). Each name is blocked, forwarded
to a rule-specific upstream, or answered with **fake IPs**. A fake IP is a
token: nftables DNATs it back to the real address and applies an fwmark, so
routing policy (WARP, VPN, …) follows the DNS decision.

See [DESIGN.md](DESIGN.md) for how it works internally.

## Rules

```uci
config omnidns 'main'
	option port '53'
	list listen_addr '192.168.1.1'
	option fwmask '0xff000000'
	option fakeip_v4 '198.18.0.0/15'
	option fakeip_v6 'fd00:198:18::/64'     # optional

config rule 'adblock'                      # section name = stable rule id
	option action 'block'
	list nameset '/tmp/omnidns.d/adlist/*'

config rule 'fakeip_warp'
	option action 'fakeip'
	option upstream '/etc/omnidns.d/dns_1111.conf'
	option fwmark '0x01'                    # -> mark 0x01000000 within fwmask
	list nameset '/etc/omnidns.d/warp/*.txt'

config rule 'catchall'                     # no nameset: must be last
	option action 'forward'
	option upstream '/tmp/resolv.conf.d/resolv.conf.auto'
```

- **Order matters.** The first matching rule wins and specificity is
  ignored, so you can write exceptions by placing them earlier.
- **Nameset files** hold one pattern per line, plus `#` comments.
  - `example.com` matches that exact name.
  - `*.example.com` matches `example.com` and every name below it.
- **Upstream files** use `resolv.conf` syntax. Only numeric `nameserver`
  lines are read. Two extensions are supported: `ADDR#PORT` and IPv6
  `%scope`. Servers are tried in order, with a TCP retry when the answer is
  truncated (TC).
- **block** answers per `block_mode`: `nodata` (the default), `nxdomain`, or
  `null` (0.0.0.0 / ::). It applies even when the blocked name appears
  mid-chain, which catches CNAME cloaking.
- **forward** picks the upstream for the next step.
- **fakeip** latches its fwmark *and* its upstream. Rules further down the
  alias chain can only block.

## Option reference

Global options (`config omnidns 'main'`):

| option | default | meaning |
|---|---|---|
| `port` | 53 | listen port (UDP and TCP) |
| `listen_addr` | (required) | list of numeric IPv4/IPv6 addresses to bind |
| `fwmask` | `0xff000000` | bits of the packet mark owned by omnidns |
| `fakeip_v4` | unset | IPv4 fake pool, prefix length 8–30 |
| `fakeip_v6` | unset | IPv6 fake pool, prefix length 32–120 |
| `fakeip_grace` | 600 | seconds a binding outlives its TTL |
| `fakeip_ttl_max` | 3600 | TTL cap for fake records and their bindings |
| `fakeip_max_bindings` | 65536 | binding table capacity |
| `cache_size` | 10000 | cached answers (entries) |
| `cache_max_bytes` | 16 MiB | cached answers (memory) |
| `neg_ttl_max` | 3600 | cap for negative caching |
| `block_mode` | `nodata` | `nodata`, `nxdomain` or `null` |
| `block_ttl` | 300 | TTL of block responses |
| `upstream_timeout` | 1500 | per-server timeout, ms |
| `upstream_total_timeout` | 5000 | overall deadline per query, ms |
| `max_clients_tcp` | 64 | concurrent TCP clients |
| `max_pending` | 1024 | queries in flight, total |
| `max_pending_per_client` | 64 | queries in flight per client IP (IPv6: per /64) |
| `log_level` | `info` | `err`, `warn`, `info` or `debug` |

Rule options (`config rule '<id>'`, evaluated in file order):

| option | meaning |
|---|---|
| `action` | `block`, `forward` or `fakeip` |
| `upstream` | resolv.conf-style file (`forward`, `fakeip`) |
| `fwmark` | `fakeip` only: non-zero value inside `fwmask`, unshifted |
| `nameset` | list of glob patterns of nameset files; omit for the catchall |

## Fake IPs

- Rewritten in A/AAAA records and in SVCB/HTTPS `ipv4hint`/`ipv6hint`.
- When a response is rewritten, its DNSSEC records are stripped.
- With no IPv6 pool configured, AAAA under a fakeip verdict returns NODATA,
  so the real IPv6 address never leaks.
- Allocation is deterministic: `hash(secret, rule, mark, name, real IP)`.
  The secret is kept in the nftables table, so it survives restarts.
- A binding stays alive until its TTL plus `fakeip_grace` (600 s) has passed.
  Established flows survive beyond that through conntrack.
- Fake records get their TTL capped at `fakeip_ttl_max` (3600 s), and so do
  the bindings behind them.
- A single answer yields at most 32 fakes.
- Upstream TTLs of 2³¹ or more are treated as 0 (RFC 2181).
- omnidns owns `table inet omnidns`. A restart keeps it and the fake IPs
  clients hold (see below); a stop deletes it.
- Reverse lookups (PTR) for fake addresses are answered locally.

nftables sketch:

- `fake2real_v4/v6` and `fake2mark_v4/v6` maps.
- One `mark_<V>` chain per fwmark. It sets `meta mark` and `ct mark` with a
  single masked bitwise operation; kernel ≤ 6.13 has no two-register
  arithmetic.
- DNAT in `prerouting`/`output` at dstnat priority.
- Marks are restored from conntrack.
- Unmapped fakes are rejected.

You provide the policy routing itself, e.g.
`ip rule add fwmark 0x01000000/0xff000000 lookup warp`.

## Reload

`SIGHUP` (or `/etc/init.d/omnidns reload`; also triggered on interface up):

- Re-reads the config, the upstream files and the namesets. Unchanged
  nameset files are reused.
- Reconciles nftables chains without flushing the maps, so live bindings
  survive.
- Invalidates cached answers whose rule decisions changed.
- Rejects fake-pool or fwmask changes that would strand live bindings.
- If anything fails, the previous config stays in effect and the error is
  logged to syslog.

## Restart and stop

- **Restart** (`/etc/init.d/omnidns restart`, a procd respawn after a
  crash, an instance restart): the new daemon takes over the existing
  table. Every fake a client may still hold keeps working, with its mark,
  and a name queried again gets the same fake back. Startup logs
  `kept N fake IPs of the existing table`.
- On a clean exit (SIGTERM, SIGINT) the daemon writes
  `/var/run/omnidns-<table>.hold` (`/var/run` is tmpfs on OpenWrt, so the
  file never outlives a boot): which fakes clients may still hold, and for
  how long. The next start reads and deletes it, keeps those fakes for what
  is left of their lifetime and drops every other element, the expired
  ones lazy eviction left in the kernel. Startup logs
  `<path> lists N fake IPs in use`.
- Without that file (after a crash or a `kill -9`, or when it cannot be
  written or does not match the table, logged) every fake of the table is
  kept for `fakeip_ttl_max` + `fakeip_grace` (70 minutes by default), the
  longest a client may hold one. `-r dir` moves the hold file and the
  `omnidns-<table>.lock` next to it (tests).
- One daemon per table runs at a time: a daemon started while another one
  still holds the table (a restart starts the new one before the old one
  has exited) logs `waiting for another instance of the table to exit`
  and starts once it has, with its hold file. After 15 s it gives up and
  exits non-zero (procd starts it again). `omnidns -F` waits the same way.
- The table is recreated from scratch instead (all fakes lost, logged) when
  it was made by another omnidns version, the `fwmask` changed while the
  daemon was down, or it cannot be taken over. Fakes outside a changed pool
  are dropped.
- Fakes taken over count against `fakeip_max_bindings` until they expire
  or a query takes them over again. After a crash with a table nearly
  full, new fake-IP names can get SERVFAIL for up to `fakeip_ttl_max` +
  `fakeip_grace`; after a clean restart only for as long as the fakes
  still in use fill the table.
- **Stop** (`/etc/init.d/omnidns stop`, shutdown, package removal) runs
  `omnidns -F`, which deletes the table and the hold file and exits. The
  daemon itself never deletes it on exit (unless started with `-x`, for
  tests). Use `omnidns -F [-t table]` by hand to remove the table after
  killing the daemon yourself.
- A package **upgrade** (opkg/apk) stops the old package with
  `PKG_UPGRADE=1` and starts the new one: the init script then skips `-F`,
  so an upgrade keeps the fakes like a restart. The stop that runs is the
  old package's, so this takes effect for upgrades from the first release
  carrying it onwards; upgrading to it from an earlier release still
  drops every fake once.

## Deploying on OpenWrt

omnidns needs port 53, so move dnsmasq's DNS service elsewhere and keep it
for DHCP and local names:

```sh
uci set dhcp.@dnsmasq[0].port='5335'
uci commit dhcp && /etc/init.d/dnsmasq restart
```

Then route `*.lan` and reverse zones to it with a `forward` rule. The default
config already does this through `/etc/omnidns.d/dnsmasq.conf`, which
contains `nameserver 127.0.0.1#5335`.

Package dependencies: `libubox libuci libmnl libnftnl kmod-nft-core kmod-nft-nat` (reject and ct are part of kmod-nft-core).
The kernel must be ≥ 6.3, because omnidns uses `NFT_MSG_DESTROYSETELEM`.

## Known limitations

- **Aliases that clients chase themselves** are evaluated on their own name.
  This covers HTTPS AliasMode targets, and ServiceMode targets without hints,
  that the client resolves later. Add such CDN names to the nameset.
- **DNSSEC** records are dropped from rewritten answers. Upstream queries are
  sent with DO=0.
- **Pool capacity is shared by all clients.** A LAN client that controls an
  authoritative zone, and queries many of its names through a `fakeip` rule,
  can fill the pool (`fakeip_max_bindings`, default 65536) for up to
  `fakeip_ttl_max` + `fakeip_grace`. After that, new fakeip names get
  SERVFAIL. Real IPs are never returned as a fallback.

  This matters most with a catchall `fakeip` rule on networks with untrusted
  clients. Mitigations: lower `fakeip_ttl_max`, use a larger pool, or limit
  `fakeip` rules to curated namesets.
- **Hardware/software flow offloading** bypasses nftables marks for
  offloaded flows.

## Building and testing

Host requirements: a C compiler, cmake, ninja, json-c (for libubox),
libmnl, libnftnl, python3; clang for fuzzing.

```sh
scripts/host-deps.sh                  # libubox + libuci into third_party/
scripts/host-build.sh                 # host build, ASan/UBSan, unit tests
python3 tests/integ/test_integ.py     # end-to-end in an unprivileged netns
# fuzzing (clang): cmake -DFUZZ=ON -DSANITIZE=ON ... ; ./fuzz_wire -max_total_time=300

# OpenWrt SDK
ln -s /path/to/omnidns/openwrt package/omnidns
./scripts/feeds update base && ./scripts/feeds install libubox uci libmnl libnftnl
make package/omnidns/compile
```

The nftables unit tests and the end-to-end suite run in unprivileged user
and network namespaces (`unshare -rn`); no root is needed.
