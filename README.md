# omnidns

A policy-aware DNS proxy for OpenWrt that can route by domain name.

omnidns checks every name in a resolution chain against an ordered ruleset,
CNAMEs included. Depending on the matching rule it blocks the name, forwards
it to a specific upstream, or answers with **fake IPs**. nftables translates a
fake IP back to the real address and sets an fwmark, which your policy routing
uses to pick a WAN, VPN or tunnel.

- First-match rules over large domain lists (200k+ patterns, exact or `*.suffix`)
- Policy is re-evaluated at every CNAME/DNAME/HTTPS alias, so CNAME cloaking gets blocked
- Fake IPs in A/AAAA records and HTTPS `ipv4hint`/`ipv6hint`
- Live connections survive cache eviction and config reloads
- Hardened against hostile clients and upstreams, and fuzzed
- Plain C: libubox, libuci, libmnl, libnftnl

## Example

```uci
config omnidns 'main'
	list listen_addr '192.168.1.1'
	option fakeip_v4 '198.18.0.0/15'

config rule 'adblock'
	option action 'block'
	list nameset '/etc/omnidns.d/hagezi.txt'

config rule 'warp'
	option action 'fakeip'
	option upstream '/etc/omnidns.d/dns_1111.conf'
	option fwmark '0x01'
	list nameset '/etc/omnidns.d/warp.txt'

config rule 'catchall'
	option action 'forward'
	option upstream '/tmp/resolv.conf.d/resolv.conf.auto'
```

```sh
ip rule add fwmark 0x01000000/0xff000000 lookup warp
```

Every name in `warp.txt`, and every CNAME it resolves through, now gets a fake
IP from `198.18.0.0/15`. Its traffic goes out marked for the `warp` routing
table.

## Install

Build the package with the OpenWrt SDK:

```sh
ln -s /path/to/omnidns/openwrt package/omnidns
./scripts/feeds update base && ./scripts/feeds install libubox uci libmnl libnftnl
make package/omnidns/compile
```

omnidns needs port 53, so move dnsmasq off it (e.g. to `5335`). Requires Linux 6.3 or newer.

## Documentation

- [Manual](docs/MANUAL.md): rules, options, deployment, limitations, building and testing
- [Design](docs/DESIGN.md): how it works internally

## License

MIT
