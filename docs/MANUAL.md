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
- Allocation is deterministic per process run:
  `hash(secret, rule, mark, name, real IP)`.
- A binding stays alive until its TTL plus `fakeip_grace` (600 s) has passed.
  Established flows survive beyond that through conntrack.
- Fake records get their TTL capped at `fakeip_ttl_max` (3600 s), and so do
  the bindings behind them.
- A single answer yields at most 32 fakes.
- Upstream TTLs of 2³¹ or more are treated as 0 (RFC 2181).
- Bindings live in RAM only. On startup omnidns owns and recreates
  `table inet omnidns`.
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
