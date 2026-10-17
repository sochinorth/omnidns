# omnidns design

omnidns is a DNS proxy for OpenWrt routers that applies policy **per name and
per alias**, and can turn a DNS decision into a routing decision. LAN clients
use it as their resolver. For each query it walks the resolution chain
(CNAME, DNAME, HTTPS/SVCB AliasMode). At every step it evaluates the current
name against an ordered ruleset, and it may answer with *fake IPs*: tokens
that nftables translates back to the real address while applying an fwmark.

This document describes how it works and why. For configuration and usage,
see [MANUAL.md](MANUAL.md).

## Goals and non-goals

Goals:

- Policy follows the whole alias chain, not just the queried name. A
  CNAME-cloaked tracker is blocked; a CDN alias behind a VPN-routed name stays
  VPN-routed.
- Routing policy is expressed through DNS without per-destination routes.
  The fake IP itself carries the policy.
- Live connections never break because of DNS-side events: cache eviction,
  reloads, re-resolution.
- Safe to expose to arbitrary LAN clients: every input is bounded, and
  memory and work are capped.
- Small and dependency-light: plain C11, libubox, libuci, libmnl, libnftnl.

Non-goals:

- Recursive resolution or DNSSEC validation; omnidns forwards to upstreams.
- Encrypted DNS transports.
- Configuring policy routing (`ip rule`, routing tables). omnidns only marks
  packets.

## Architecture

A single-threaded `uloop` event loop. All I/O is non-blocking, except
nftables control-plane transactions at startup and reload, which are short
synchronous netlink exchanges.

```
 client ──► server ──► cache (hit) ──────────────────────────────────► reply
              │ miss
              └──► resolve
                      ├──► match (rule per name)
                      ├──► upstream (UDP/TCP, coalesced)
                      └──► fakeip (bindings) ──► nft (async batches)
                                                   │ ack
                      reply ◄── cache insert ◄─────┘
```

| module | role |
|---|---|
| `server` | UDP/TCP listeners, query validation, EDNS, per-client limits |
| `resolve` | the policy walk and answer assembly |
| `match` | suffix index: name → first matching rule |
| `config` | UCI loading, nameset and upstream files, rule fingerprints |
| `upstream` | async DNS client with failover, TCP fallback, coalescing |
| `fakeip` | binding table and deterministic allocator |
| `nft` | nftables table: chains, maps, async element batches |
| `cache` | cache of final answers, with dependency revalidation |
| `dns/wire`, `dns/svcb` | bounded DNS message parser/builder, SVCB rewriting |
| `util/*` | hash map, SipHash, S3-FIFO, clock, object pools |

A cache hit allocates nothing. A miss allocates its cache entry (and, for
`fakeip`, its new bindings) and nothing else in steady state: per-query
state (the server's pending query and client counter, the resolver's
request, the upstream exchange and query) comes from small free lists, and
the resolver's messages keep their storage across requests. Upstream
responses are parsed into one message whose storage the request taking it
over swaps for its own. Each list keeps at most 64 objects and gives back
those left unused for 5 s, down to 4.

## Configuration model

Rules are UCI sections evaluated in file order; **the first match wins**.
Specificity does not matter, so exceptions are written by placing them
earlier. A rule's UCI section name is its stable identity. Each rule has one
action:

- `block`: answer per `block_mode` (NODATA with a synthetic SOA, NXDOMAIN, or
  `0.0.0.0`/`::`).
- `forward`: query the rule's upstream for the next step.
- `fakeip`: like `forward`, and additionally *latch* the rule's fwmark.

The last rule has no nameset and matches everything; exactly one such
catchall must exist.

**Namesets** are files of patterns: `example.com` matches exactly, and
`*.example.com` matches the apex and everything below it. Files are cached by
`(path, dev, inode, mtime, size)`, so a reload re-reads only changed files.

**Upstreams** are resolv.conf files. Only numeric `nameserver` lines are used,
extended with `#port` and IPv6 `%scope`. An upstream's identity is a hash of
the ordered server list, not of the file path. Two files with the same
servers are the same upstream, and rewriting a file with identical contents
changes nothing.

Every rule has a **fingerprint**: a hash of everything that influences
resolution for a name it matches. That is its id, action and upstream
identity, plus the mark, pools, grace and TTL cap for `fakeip`, or the block
mode and TTL for `block`. Fingerprints let cached answers be revalidated
after a reload without re-resolving them (see [Cache](#answer-cache)).

## Name matching

All patterns from all rules go into a single hash table keyed by the dotted
name. Each node stores two rule ordinals: the first rule with an exact
pattern for this name, and the first rule with a suffix pattern. To match
`a.b.example.com`, the lookup checks:

| node | considered |
|---|---|
| `a.b.example.com` | exact and suffix |
| `b.example.com`, `example.com`, `com` | suffix only |

The lowest ordinal wins; if nothing matches, the catchall applies. A lookup
costs one hash probe per label and never allocates.

Each pattern is stored once. A nameset file is read through a fixed 64 KiB
window into one exact-size blob of NUL-terminated names. The pattern type is
encoded by region, not per entry: suffix names (without `*.`) come first and
exact names after them, with one boundary offset per file. The parser fills
a single buffer from both ends, suffix names forward from the front and exact
names backward from the back, then moves the exact region down and trims the
buffer. The exact region thus comes out in reverse file order, which matching
ignores, and identical text always gives an identical blob. Dropping the `*.`
saves 2 bytes per suffix pattern, 389 KiB on HaGeZi Pro (all 199k patterns
are `*.`; its blob shrinks from 4.17 to 3.77 MB). Parsed files are cached
across reloads, keyed by inode, mtime and size. The table is built once per configuration, sized for the patterns of
the distinct files, and never grows. Its 12-byte slots hold no names: they
point into the blobs (file index and offset) and carry a 16-bit hash tag and
the two ordinals. The configuration's references keep the files alive as long
as the table.

The table is sized at exactly 80% load (at least 16 slots, always at least one
empty), not rounded up to a power of two: the home slot is
`(low 32 hash bits * capacity) >> 32` and linear probing wraps at the
capacity; the tag comes from the top 16 hash bits, independent of the home
slot. Rounding up wasted up to half the table: a 199k-pattern list (HaGeZi Pro)
needed 6.3 MB at 38% load and now takes 3.0 MB. Most probes are misses
(ancestors such as `com`), and a linear-probing miss scans to the next empty
slot: about 13 slots on average at 80% load, against about 23 at 85% and 50 at
90%, for a further saving of only 6% and 11%. So 80% is the knee.

A reload whose rules reference the same parsed files, rule by rule and in
the same order, shares the previous table (it is refcounted) instead of
building one. Both configurations then hold references to exactly the files
the table borrows from, so the files outlive it whichever is freed last. A
file that is re-read but yields the same patterns (touched, or atomically
replaced by a list refresh) keeps its identity in the file cache, so it
doesn't force a rebuild either. On a desktop CPU, the 199k patterns of HaGeZi
Pro build in about 6 ms into a 3.0 MB table, plus the blob text. Looking up a
3- or 4-label name takes about 110 ns when every label misses and about 145 ns
when it hits. At the old 38% load the same lookups took about 77 ns and
145 ns.

## Resolution: the walk

Resolution is a state machine over the alias chain. Its state:

- `name`: the name currently being evaluated (starts as the qname)
- `upstream`: the upstream whose response is in hand
- `latch`: the fakeip rule in force, if any (rule id, mark, upstream)
- `prefix`: alias records collected so far, in order
- `deps`: every (name, rule fingerprint) that influenced the result

Each step:

1. Match `name` and record the dependency.
2. If the rule is `block`, stop and answer the block response *for the
   original qname*. This applies mid-chain too, which is what defeats CNAME
   cloaking.
3. Pick the wanted upstream. A latch, once set, pins the upstream for the rest
   of the walk. Otherwise a `fakeip` rule sets the latch, and a `fakeip` or
   `forward` rule selects its own upstream.
4. Re-query only if the wanted upstream's **identity** differs from the one
   that produced the response in hand. A changed verdict with the same
   upstream keeps reading the same response.
5. Scan the response for the next alias owned by `name`:
   - a DNAME covering `name` (its synthesized CNAME is used, or synthesized
     here if the upstream left it out),
   - a CNAME,
   - for HTTPS/SVCB queries, an AliasMode record with a non-root target.

   The alias records join the prefix and the walk continues with the target.
6. Otherwise the walk ends at `name`:
   - data of the requested type → terminal processing;
   - NXDOMAIN or NODATA → negative answer: the prefix plus the upstream's SOA;
   - neither (the upstream did not follow the chain) → query `name`
     directly.

A walk is limited to 12 alias steps, and revisiting a name fails as a loop
(both SERVFAIL).

### Why the latch pins the upstream

Once a name is decided to go through, say, a VPN, its CDN aliases must
resolve through the same upstream. A domestic upstream would return
geo-local addresses that are then tunnelled abroad. Downstream rules can
still `block`, but they cannot change the routing decision.

### Terminal processing

- **A/AAAA under a latch**: every address gets a binding and is rewritten to
  its fake. If the latch has no pool for the address family, the answer is
  NODATA: a real address never escapes a fakeip policy.
- **HTTPS/SVCB ServiceMode**: each record is an independent endpoint. Its
  effective target (the TargetName, or the owner name for `.`) is matched on
  its own:
  - `block` drops just that record;
  - an active latch, or a target that matches a `fakeip` rule, gets
    `ipv4hint`/`ipv6hint` rewritten under that policy. So sibling endpoints
    may carry different policies.

  All other parameters (alpn, ech, …) are preserved byte for byte. A dropped
  hint is also removed from `mandatory`. Targets are never resolved
  proactively. If every record is dropped, the answer is NODATA.
- **HTTPS/SVCB AliasMode**: whether followed (it joins the prefix) or
  terminal (target `.`), the record is passed through as received,
  SvcParams included, under a latch too. RFC 9460 §2.4.2 has clients
  ignore the SvcParams of an AliasMode record, so any hints there are
  never used as addresses and need no policy.
- **Other types** pass through unchanged after the walk.

### Answer assembly

The answer section is the prefix followed by the terminal records: the
kept, rewritten or bound records of the queried type owned by the final
name. Nothing else in the final response's answer section (its RRSIGs, for
instance) is carried over. The authority and additional sections are the
final response's, filtered:

- when a terminal record was rewritten or dropped, RRSIG, NSEC, NSEC3 and
  (unless DS was asked for) DS records are removed;
- A/AAAA/SVCB/HTTPS records in the authority section are always dropped:
  they never belong there, and whatever their owner's rule they would carry
  real addresses past the policy;
- additional A/AAAA/SVCB/HTTPS records are dropped entirely when a latch is
  in force or the answer made bindings. Otherwise each is kept only if its
  owner's rule is a plain `forward`, and that owner is recorded as a
  dependency. This stops glue (e.g. SRV/MX targets) from leaking real
  addresses of fakeip or blocked names. An SVCB/HTTPS record must also be
  safe as received (below), since its hints are its target's addresses.

An SVCB/HTTPS record is *safe as received* when it parses and either is
AliasMode (whatever its SvcParams, as above), or is ServiceMode and carries no
`ipv4hint`/`ipv6hint`, or is ServiceMode and its effective target matches a
plain `forward` rule (that target is then recorded as a dependency). Only
terminal records are planned per target as above; any other SVCB/HTTPS
record (in the additional section, at a walk name before the final one, or
not of the queried type) leaves only if it is safe as received, so real
hints of a blocked or fakeip target never escape.

A negative answer is the prefix plus the final response's authority and
additional sections, with the same address filtering and DNSSEC records
kept.

The header is always omnidns's own: QR, RA, the client's RD and CD, and the
upstream's 4-bit rcode. AA and AD are never set.

When a single upstream response needed no change at all (no alias
synthesized from a DNAME, no latch, no bindings, no address record to
filter from the authority or additional section, every SVCB/HTTPS record of
the answer section safe as received, nothing rewritten), and
every record of its answer section belongs to the chain (owned by a name
the walk evaluated, or a DNAME it followed and that DNAME's RRSIG), its
records are passed through as received; only the header is replaced and
OPT dropped. Any other answer record, including other records of a DNAME's
owner, belongs to a name never matched against the rules, so such a
response is assembled instead, which leaves the record out.

The finished answer is serialized once, with name compression, into the
bytes the cache stores and every reply is rendered from (see
[Cache](#answer-cache)).

### Deferred binding

Bindings are created only after the final answer is fully determined, then
committed to nftables. The reply is sent only after the kernel has
acknowledged the batch carrying those bindings: a client must never receive a
fake IP before the dataplane can translate it. If the batch fails, the
client gets SERVFAIL.

## Fake IPs

### Bindings

A binding maps a fake address to a real one under a policy:

```
key:   (rule id, mark, endpoint name, family, real IP)
value: fake IP, safe_until, nft ticket, refcount
```

The *endpoint name* is the owner of the terminal A/AAAA record set, or the
effective SVCB target. Two names that alias to the same CDN host share fakes.
The upstream is not part of the key, so changing a rule's upstream does not
churn fakes.

### Allocation

```
candidate₀ = pool_first + SipHash(secret, key) mod pool_usable
candidateᵢ = next usable address (linear probing)
```

- **Excluded addresses**: the IPv4 network and broadcast addresses, and the
  IPv6 all-zero host. Pools may not overlap 0/8, loopback, multicast, `::`,
  `::1`, v4-mapped space or `ff00::/8`.
- **Determinism**: allocation is deterministic for a given 16-byte secret.
  The secret is random when the nftables table is created and is stored in
  it, so a restarted daemon that takes the table over keeps it (see
  [Restart](#restart)). A binding that was evicted and comes back usually
  gets the same fake again, also across a restart.
- **Probing**: up to 64 candidates are tried.
  - A free slot is taken.
  - A slot whose binding is expired and unreferenced is reclaimed.
  - A live slot is skipped.
  - A placeholder left by a restart that maps to the key's (family, real
    address, mark) is claimed. While placeholders exist, the whole window
    is searched for one before a free slot is taken.
- **Exhaustion**: if the probe fails, expired cache entries are swept and
  allocation is retried once. If that also fails, the result is SERVFAIL;
  omnidns never falls back to the real address.

### Lifetime

```
safe_until = now + min(TTL, fakeip_ttl_max) + fakeip_grace
```

- **Expiry**: a binding becomes evictable only when `safe_until` has passed
  *and* no cached answer references it. The fake records sent to clients
  carry the same capped TTL, so a client that respects TTLs never holds a
  fake past `safe_until`. The grace period covers clients that don't.
- **Established flows**: they don't depend on bindings at all. DNAT and the
  mark are recorded in conntrack on the first packet, so removing a map
  element only affects *new* connections.
- **Eviction**: an S3-FIFO bounded by `fakeip_max_bindings`. It runs lazily,
  only under pressure, and only evicts evictable bindings. A pass that ends
  short of its target has found every binding pinned, so the next one waits
  until one can be evictable: time passes the earliest `safe_until` of an
  unreferenced binding, a binding's last reference goes, or a reload. With
  a table full of live bindings, a failing bind therefore costs a probe and
  no scan, and the cache sweep before its retry runs at most once a
  second (a second sweep within the same second would find nothing).
- **Persistence**: bindings live in RAM; the nftables maps outlive the
  process. A restart turns their elements back into placeholder bindings
  (below), held as long as a clean exit's hold file says, or for the
  longest life a binding can have without one; only a stop deletes the
  table.

### Restart

procd sends SIGTERM both to stop and to restart, so the daemon never
deletes its table on exit. `omnidns -F` deletes it (and the hold file,
below): the init script runs it when the service stops (`stop`,
`shutdown`, package removal) but not from its own `restart` or a package
upgrade (`stop` with `PKG_UPGRADE=1` from the old package's prerm, so
only when upgrading from a release that has this check), and a procd
respawn after a crash never runs it. `-F` waits for a daemon that is
still exiting (the table lock, below).

At startup omnidns reads the table, if any:

1. The table's userdata holds a layout version, the fwmask and the
   allocation secret. If the table is missing, has another version or
   fwmask, is dormant, or cannot be read, omnidns bootstraps with a fresh
   secret, as on a first start, and logs why. So does a table in which a
   fixed chain is missing or not of its type, hook and priority, a
   `mark_V` chain is a base chain, or one of the four maps is missing or
   of another type: those cannot be changed in place without losing the
   elements. Layout version 2 tags every rule (below); a table of version
   1, which tagged only the policy rules, is bootstrapped. A
   commit anywhere in the netns (fw4, dnsmasq's nftset, mwan3) interrupts
   a dump that is under way (`NLM_F_DUMP_INTR`): the whole reading then
   starts over, as nft does, up to 16 times with pauses doubling from 1 to
   128 ms (about 1.2 s); only then does it bootstrap. Each reading uses a
   netlink socket of its own, closed when it ends or gives up, which ends
   a dump left unread: the kernel produces the next part of a dump only
   when its socket is read, so stopping at a cap (below) bounds the work.
2. Otherwise the shadow state is rebuilt from the kernel: the mark chains
   present and the configuration's pools. Every rule omnidns writes
   carries a tag (rule userdata) of what it was written for: the policy
   rules (`restore_marks`, `*_dstnat`, `*_reject`) the shadow state, a
   mark chain's rules the fwmask and its mark, the jumps to
   `restore_marks` the fwmask. One rule dump of the table checks every
   chain of ours by tag and count. A chain with another count, a rule
   without its tag, or a base chain whose policy is not accept, is
   rewritten by the reconcile that follows (a base chain is also defined
   again, which restores its policy); the maps and their elements stay.
   This also repairs, say, a flushed `prerouting_mangle`, after which ct
   marks would no longer be restored, or a foreign chain named like a
   mark chain.
3. The four maps are read and paired per fake. A pair `fake → real`,
   `fake → jump mark_V` with `mark_V` present and the fake allocatable in
   the current pool becomes a *placeholder* binding: a reserved policy
   carrying the mark, the fake as its endpoint (a unique key, not a name),
   refcount 0, nothing to wait for, and `safe_until = now + hold`. With a
   trusted hold file (below), `hold` is what the file lists for that fake, less the time since it was written,
   and an element it does not list is destroyed: it was evictable when the
   earlier process exited, so no client may use it. Without one, `hold` is
   `fakeip_ttl_max + fakeip_grace`, the longest a client may legitimately
   hold any fake. Every other element is destroyed, as are
   pairs beyond `fakeip_max_bindings` (the first ones in address order, v4
   first, are kept: the kernel keeps no age). A map with more than twice
   `fakeip_max_bindings` elements, more than 8192 chains or sets, or more
   than 16448 rules, makes it bootstrap instead, which bounds the work on
   kernel state.
4. The placeholders' marks join the kept marks (more than 4096 in all:
   bootstrap). After the destroys have landed, a normal reconcile runs,
   which sends nothing if the table already matches the configuration.

A placeholder is evicted like any expired binding and counts against
`fakeip_max_bindings`. A bind that probes a placeholder with its own
(family, real, mark) claims it: the new binding takes over the fake with
no nftables operation, since the kernel already has that mapping, and
keeps at least the placeholder's `safe_until`. With the earlier secret, a
key's candidates are the same as before the restart, so a re-queried name
usually gets its old fake back; claiming is safe without that, because
the mapping is identical. A placeholder with any other mapping is a live
binding until its `safe_until`, so no fake is re-pointed while a client of
the earlier process may still use it. Placeholders answer no PTR query
(they have no name).

Eviction is lazy, so after weeks of uptime the maps hold close to
`fakeip_max_bindings` elements, most long expired. Without the hold file
they would all come back as live placeholders and fill the table: new
fake-IP names would get SERVFAIL for up to `fakeip_ttl_max` +
`fakeip_grace`. That remains the behaviour after a crash.

### Hold file

On a clean exit (SIGTERM or SIGINT ends the loop; the cache and the walks
in flight are freed and every element batch is acked) the daemon writes
`<run_dir>/omnidns-<table>.hold` (`/var/run` by default, tmpfs; `-r`
overrides it for tests, as `-t` does the table: an option, not an
environment variable, because `-F` must find the same file and the
daemon's other knobs are options too). Big-endian, a 32-byte header and
24-byte records:

```
"OMNIHOLD" | u32 format version | u32 record count
u64 fingerprint = SipHash-2-4(secret, "omnidns hold" | u32 layout version)
u64 CLOCK_BOOTTIME seconds at the write
records: u8 family | 3 zero bytes | u32 hold seconds | fake[16] (v4: 4 + 12 zero)
```

One record per binding not evictable at the write instant, placeholders
included: `hold = max(safe_until - now, 0)`. A binding still referenced
(`refcnt > 0`) is not evictable and is listed, with 0 if its `safe_until`
has passed. That is enough: a reference only stops eviction while the
process can still serve the answer holding it. Every answer already sent
carries a TTL capped like the binding's, so its client stops using the
fake by `safe_until`, and the new process has no cache to serve it from
again. The fingerprint ties the file to the table instance without
revealing the secret. It is written to a temporary file and renamed over
the old one, so a reader sees the whole file or none of it; no fsync,
since it lives on tmpfs and matters only within one boot.

The clock is `CLOCK_BOOTTIME`, not the wall clock: it is the same for all
processes of a boot and NTP never steps it. A router without RTC steps
its wall clock at the first sync after boot, often around the time
interface events restart services, and a forward step would shorten every
hold.

At adoption the file is read and deleted, whether it is trusted or not,
so a later crash never reuses it. It is ignored (logged; full quarantine)
when it is missing, has another magic, version or fingerprint, has more
than `2 × fakeip_max_bindings` records, is not a regular file, its size
is not exactly header + count × 24 (truncated, trailing bytes), a record
has a bad family or non-zero padding, a fake is listed twice, or it was
written later than now on the boot clock (another boot). The startup
deletes it again once adopted or bootstrapped, so a file of another table
or of no table never lingers. A write failure is logged and only costs
the next start its full quarantine. `-x` (table deleted on exit) writes
none.

One instance of a table runs at a time: `<run_dir>/omnidns-<table>.lock`
serializes them. A daemon takes an exclusive flock on it before it reads
the table or the hold file and holds it until the hold file is written at
exit; `omnidns -F` takes it before deleting the table and the hold file.
procd's restart starts the new process before the old one has exited,
and SO_REUSEPORT lets both bind, so without the lock the old daemon's
exit drain could destroy elements the new one had just adopted (a claimed
placeholder would then answer a fake with no element), and a `-F` racing
a starting daemon could leave the table behind. With it:

- The new daemon reads the table only after the old one is done with it,
  and a clean restart always finds the old daemon's hold file.
- The old daemon never touches the table at exit: everything it changed
  was acked before the file was written, so the file and the maps agree.
- The wait is bounded at 15 s, longer than an exiting daemon can last
  (procd SIGKILLs it 5 s after SIGTERM, and its exit drain gives up after
  the 10 s netlink receive timeout). On timeout the daemon logs and exits
  non-zero, and procd respawns it: going on beside an instance still
  holding the table is the unsafe overlap itself. `-F` then fails without
  deleting anything.
- If the lock file cannot be opened (no such directory), the daemon runs
  without lock and without hold file, i.e. as before either existed.

### Abuse limits

- TTLs of 2³¹ or more are treated as 0 (RFC 2181 §8).
- One answer yields at most 32 fakes; extra addresses are omitted.
- The TTL cap bounds how long any single answer can pin pool space.

## Dataplane (nftables)

omnidns owns `table inet omnidns`:

```
map fake2real_v4 { type ipv4_addr : ipv4_addr }      # and _v6
map fake2mark_v4 { type ipv4_addr : verdict }        # and _v6

chain mark_<V> {                                     # one per mark value V
    meta mark set meta mark & ~M | V
    ct mark   set ct mark   & ~M | V
}
chain restore_marks { ct mark & M vmap { V : jump mark_V, ... } }

prerouting_mangle  (filter, prerouting, mangle):  jump restore_marks
output_mangle      (route,  output,     mangle):  jump restore_marks
prerouting_dstnat  (nat,    prerouting, dstnat):
    ip daddr <pool> ip daddr vmap @fake2mark_v4
    ip daddr <pool> dnat ip to ip daddr map @fake2real_v4
output_dstnat      (nat,    output,     dstnat):  same
forward_reject     (filter, forward,    filter-1):  ip daddr <pool> reject
output_reject      (filter, output,     filter-1):  same
```

- **Mark encoding**: `M` is `fwmask`, and a rule's `fwmark` value is shifted
  into it (`0x01` with mask `0xff000000` is `0x01000000`). Only the bits in
  `M` are ever touched, so marks owned by mwan3, QoS or offloading survive.
- **Why per-mark chains**: up to kernel 6.13, nftables cannot compute
  `mark = (mark & ~M) | map_lookup(daddr)`, because bitwise operations take
  immediates, not a second register. So the fake→mark map yields a *verdict*
  that jumps to a per-mark chain, where each statement is a single
  load–bitwise–store with immediates. The same chains restore marks from
  conntrack.
- **Unmapped fakes**: a mapped fake is rewritten by DNAT before routing. A
  packet that still has a pool address in the forward or output path is
  therefore unmapped, and it is rejected so the client fails fast instead of
  timing out.

### Control plane and data plane

- **Startup**: the existing table is taken over and reconciled (see
  [Restart](#restart)); otherwise one transaction deletes and recreates it.
- **Reload**: one transaction reconciles chains and rules against the
  desired state. It never touches the maps, except on an fwmask change (see
  below). Mark chains are kept across reloads
  until the fwmask changes, because walks in flight may still bind with a
  mark the new config no longer uses. An fwmask change is only accepted
  with no live binding (see [Reload](#reload)). The kernel cannot update a
  table's userdata, which records the fwmask, so that transaction
  recreates the whole table (same secret, empty maps). That also drops
  elements a failed element batch left behind: it rolls back the deletes
  it carried, so the kernel may still hold elements the binding table
  already dropped, jumping to an old mark chain that could otherwise never
  be deleted (EBUSY). The transaction fails if the table is gone (deleted
  by `omnidns -F`), so it never brings a table back. At most 4096 mark chains are
  installed, which bounds the transaction (a bootstrap is then about
  12000 messages and 2.1 MB, a reconcile replacing every chain 16000 and
  2.4 MB; the socket send buffer is 4 MB, doubled by the kernel, and must
  hold the whole transaction): a reload that would
  need more, counting the kept ones, is rejected rather than drop a chain
  that may still be in use; a restart keeps only the configuration's own
  marks and those of the fakes it takes over. If the desired state (pools, fwmask, mark set) equals what
  the last successful transaction installed, no transaction is sent. The
  cost is that a no-op reload no longer repairs rules someone edited
  inside our chains; the next real change repairs the policy rules, and
  a restart every chain (every rule carries a tag of what it was written
  for, see [Restart](#restart)). A deleted chain or map makes the restart
  bootstrap.
- **Large transactions** stay one transaction each. Element lists (only
  the `restore_marks` vmap) go in messages of 256 elements, since a
  message's elements share one nest with a 16-bit length (at most 1023
  elements of the worst-case 64 bytes). The kernel queues all replies of a
  batch at once, so only the last message before END asks for an ack:
  failing messages are reported regardless, and before that final ack. A
  transaction failing in more messages than the receive buffer holds
  still reports its first error.
- **Element updates** go through a separate netlink socket.
  - **Batching**: they are coalesced into batches, submitted at the end of
    the loop iteration or at 1024 operations. Each batch has a monotonically
    increasing *ticket*, and callers wait on tickets.
  - **Idempotency**: every add first destroys the key, and every delete is a
    destroy (`NFT_MSG_DESTROYSETELEM`, kernel ≥ 6.3). The kernel rolls back a
    failed batch as a whole, so kernel and binding table may briefly
    disagree, but such drift can never make a later batch fail.
  - **Ordering**: within a batch, destroys are sent before adds. A second
    operation on a key that already has a pending add starts a new batch.
  - **Failure**: if a batch fails, the bindings it carried are dropped and
    their waiters get SERVFAIL.
  - **Acks**: as in control-plane transactions, only the last message
    before END asks for an ack. An error, in any message of the batch or
    in its commit, arrives before that ack and fails the batch whose
    sequence range it falls in; the ack alone completes it. A batch costs
    one ack and one read, not one per message (four for a single binding).
  - **Encoding**: elements are encoded straight into netlink messages (256
    elements each, the same bytes libnftnl would produce), one persistent
    buffer per map and phase, and copied into a persistent transaction
    buffer at submission. Keys with a pending add sit in a fixed
    open-addressing table emptied per batch. In steady state an element
    update allocates nothing; buffers grown by a burst (at most a few
    hundred KB at 1024 operations) halve after 64 batches that use under a
    quarter of them.

## Answer cache

- **Key**: qname (compared case-insensitively), qtype, qclass. Upstream
  queries always use DO=0, so the DO bit is not part of the key.
- **Value**, in a single allocation (about 260 bytes, overhead included,
  for a CNAME plus three A records):
  - the final response in wire format, as it was serialized once when the
    answer was complete: header, question (the key, in the case it was first
    asked with), the records with their names compressed; no OPT. An answer
    larger than a DNS message is stored as serialization cuts it (trailing
    additional records dropped, or just header and question with TC set),
    which is what every client got for it anyway;
  - insert time and lifetime;
  - the walk's dependencies;
  - references to the bindings in the answer;
  - the configuration generation it was last validated against.
- **Lifetime**:
  - positive answers: the minimum answer TTL;
  - negative answers: min(SOA TTL, SOA MINIMUM, `neg_ttl_max`);
  - block answers: `block_ttl`;
  - SERVFAIL and other errors: not cached.
- **Hits**: the server looks the cache up right after validating a query,
  before it allocates any request state, and replies synchronously. ANY and
  PTR queries for fake-pool addresses are not looked up: they keep their own
  handling, which comes first. A hit is rendered from the stored bytes
  without rebuilding the message: they are copied, the id, flags and
  question bytes are patched in (the client's question is the same name, so
  it has the same length and pointers into it stay valid), every TTL is
  reduced by the entry's age (floored at 0) by a walk over the records, an
  OPT record is appended if the query had one, and the message is cut to
  the client's size limit at exactly the record where serializing would
  have cut it (see [Client-facing server](#client-facing-server)). Fresh
  answers take the same path with age 0, so there is one reply path.
  Because names compress case-insensitively (a name pointing at an equal
  one takes its case), patching in another case of the question gives
  exactly the bytes serializing for that question would have.
- **Revalidation**: if the entry's generation differs from the current
  config's, every dependency name is matched again, and each rule
  fingerprint must equal the recorded one; otherwise the entry is dropped.
  This catches inserted or reordered rules, nameset edits and upstream
  changes. A reload doesn't flush the cache (only an accepted fwmask
  change does), and an entry is never served
  under the wrong policy. A reload that keeps the match table, the fwmask
  and every fingerprint by ordinal keeps the generation, since every
  revalidation would succeed.
- **Binding references** pin bindings while an answer can still be served. A
  30 s sweep drops expired entries so their bindings become reclaimable.
  Dropping a cache entry never deletes a binding.
- **Eviction**: an S3-FIFO bounded by entry count and bytes, run in batches
  down to 7/8 of the limit. Its ghost (the hashes of the last keys evicted
  from the small queue, 90% of the capacity, in a ring and a set at most
  75% full: 4 + 5.3 bytes per key) is allocated by the first eviction and
  released after 10 minutes without one; the binding table's is the same.
- **Index**: the cache, like the binding table, indexes entries in an
  open-addressing hash map (`util/hmap`, linear probing, tombstones). The
  tombstones that churn leaves behind are purged in place, without
  allocating, so a steady cache allocates only its entries; a table less
  than 1/8 full is shrunk on the next insert, so the index of a burst is
  given back once the burst's entries are gone.

## Upstream client

- **Transport**: every attempt uses a fresh connected UDP socket with a
  kernel-random source port and a random ID. A response is accepted only if
  its source, ID, QR/opcode and question all match. Queries carry EDNS0
  (1232 bytes), DO=0 and no client subnet.
- **Failover**: servers are tried in order. SERVFAIL, REFUSED, NOTIMP,
  FORMERR, an unparsable response, a socket error or a per-try timeout moves
  on to the next server; an overall deadline bounds the whole query. TC=1
  over UDP retries the same server over TCP. A truncated TCP response counts
  as a failure and is never delivered or cached.
- **Coalescing**: concurrent identical queries `(upstream identity, name,
  type)` share one exchange, capped at 1024 exchanges in flight.

## Client-facing server

- **Transports**: UDP and TCP on every `listen_addr`. Binding specific
  addresses keeps omnidns off the WAN.
- **Validation**:
  - QR=0, opcode QUERY, one question, class IN, and EDNS version 0;
    otherwise FORMERR, NOTIMP, REFUSED or BADVERS;
  - ANY gets NOTIMP;
  - AXFR/IXFR get REFUSED.
- **Responses** echo the client's id, RD/CD bits and question bytes, so
  0x20-randomized case survives (and so does it in owner names compressed
  against the question). They carry an OPT record only if the query did.
  Every answer reply, fresh or cached, is rendered from the answer's wire
  form (see [Cache](#answer-cache)); only error replies (FORMERR, NOTIMP,
  REFUSED, BADVERS and SERVFAIL when a query cannot be started) are built
  from the query alone.
- **Size limits**: UDP answers are limited to 512 bytes without EDNS, or
  max(512, min(client size, 1232)) with it, the OPT record included. A
  larger answer loses additional-section records from the first one that
  does not fit; if an answer or authority record does not fit, the reply is
  the header and question (and OPT) with TC=1.
- **PTR**: lookups for fake-pool addresses are answered locally from the
  binding table and never sent upstream.
- **TCP**: pipelining with out-of-order replies (RFC 7766), up to 16 queries
  in flight per connection and a 10 s idle timeout. A cache hit is answered
  as soon as it is read, possibly before earlier queries of the same
  connection. Reading stops above 256 KiB of queued output (checked before
  each query, so a run of hits backs off too), and the connection is
  dropped above 1 MiB.
- **Limits**:
  - `max_pending` queries in flight in total;
  - `max_pending_per_client` per client, where IPv6 clients are accounted
    per /64;
  - `max_clients_tcp` TCP connections.

  Over the limits, UDP queries are dropped and TCP queries get REFUSED. The
  pending limits bound requests waiting for upstreams or nftables; a cache
  hit never waits, so it is answered whatever they are and does not count
  against them (nor against the 16 in flight per TCP connection).
- **Pending replies across a reload**: a UDP listener closed by a reload
  keeps its socket open until its last pending reply is sent. A reused file
  descriptor can never receive another client's answer.

## Reload

`SIGHUP` builds a complete new configuration on the side. Only if every
step succeeds does it replace the old one:

1. Load and validate the UCI file. Nameset files are re-read only if
   changed. If every rule references the same nameset files as before, the
   match table is shared instead of rebuilt.
2. Compute the dataplane state: the configuration's marks plus, unless
   `fwmask` changed, every mark chain installed before. Reject the reload if
   that is more than 4096 marks.
3. If `fwmask` changed:
   - drop expired cache entries, which pin their bindings;
   - evict expired bindings;
   - reject the reload if any binding is left. Eviction and this check
     use one clock reading, so every binding left is live at that instant;
     one that expires a second later still holds the table, and accepting
     would flush its map elements while it is still served. A binding outlives
     the answers carrying it (by `fakeip_grace`), so a cached answer still
     valid holds only live bindings, and a rejected reload keeps the
     cache.
4. Apply new pool and capacity settings to the binding table. Reject the
   reload if a live binding would fall outside a new pool.
5. Drain pending nftables deletes, then reconcile chains and rules in one
   transaction, or send none if the dataplane state is unchanged. If
   `fwmask` changed, flush the cache now: no fake is left in it, but its
   answers were resolved under the old marks.
6. Swap in the new configuration and re-bind the listeners if they changed.
   It gets a new generation number unless resolution is unchanged: a shared
   match table, the same fwmask and equal rule fingerprints by ordinal.

On any failure, the previous configuration stays in effect and the reason
goes to syslog. Live bindings and their map elements are never touched by a
reload (an fwmask change, which needs none to be live, recreates the table
and with it the maps).
A walk that latched a mark before an fwmask change and binds after it
finds that mark's chain gone, so that query alone gets SERVFAIL.

The procd service sends SIGHUP on config changes and whenever an interface
comes up, since WAN reconnects rewrite `resolv.conf.auto`. Most of these
reloads change nothing, and such a no-op reload costs a UCI parse, one
`stat` per nameset file and a re-read of each upstream file. It builds no
match table, sends no nftables transaction and keeps the generation, so
cached answers skip revalidation. The log still says
`configuration reloaded (generation N kept: resolution unchanged, ...)`.

## Limitations

- **Aliases chased by clients**: some aliases are followed by the client
  rather than by omnidns. HTTPS AliasMode targets and hintless ServiceMode
  targets come back as separate queries, and those are evaluated on their own
  names, so the original name's policy does not carry over.
- **DNSSEC**: rewritten answers cannot be validated by clients, so DNSSEC
  records are stripped from them.
- **Shared pool**: pool capacity is shared by all clients. A client that
  controls an authoritative zone can, through a `fakeip` rule, fill the pool
  for up to `fakeip_ttl_max` + `fakeip_grace`.
- **Flow offloading**: offloaded flows bypass nftables, so they are not
  marked.

## Testing

- **Unit tests**: each module has unit tests under ASan/UBSan, including
  randomized model tests for the hash map, S3-FIFO and the binding table.
  Replies rendered from cached bytes are compared byte for byte with
  serializing the message for the client (a recorded corpus covering
  truncation, TTL aging, flags and 0x20 case, plus randomized messages). The
  nftables tests run in an unprivileged user+net namespace against the real
  kernel, including a real DNATed connection with the expected marks.
- **Resolver tests**: the walk has a table-driven suite with a scripted
  upstream and real nftables underneath.
- **End-to-end**: `tests/integ/test_integ.py` builds a router namespace and a
  client namespace connected by veth, runs omnidns with Python fake
  upstreams, and checks:
  - answers, caching and TTLs;
  - real IPv4/IPv6 connections through fake IPs, including the marks they
    carry;
  - router-originated traffic;
  - reload semantics;
  - a garbage-packet flood.
- **Memory**: `tests/integ/test_mem.py` runs an unsanitized Release build
  with 75k synthetic patterns, fills the cache and 20k bindings, then reloads
  six times, each rebuilding the match table. It fails if RssAnon grows
  across the reloads, or if absolute RssAnon, VmHWM or the per-phase growth
  exceed `tests/integ/mem_baseline.json`.
- **Per-query cost**: `tests/integ/test_perf.py` runs the Release build with
  an allocation counter preloaded (`tests/integ/mcount.c`). It fills the
  cache past `cache_size`, then measures allocations and bytes per query for
  cache hits (which must not reach an upstream), forward, CNAME and fake-IP
  misses, and blocked names, against `tests/integ/perf_baseline.json`. A case
  with no allocations in the baseline fails on any allocation. Throughput and
  latency are printed but not gated.
- **Gate**: `scripts/gate.sh` runs everything above in one go. It does a
  clean sanitized build with the unit tests, `test_integ.py` against it, a
  clean Release build in `build/rel`, then `test_mem.py` and `test_perf.py`
  against that. It prints the compiler warning count of both builds and stops
  at the first failure. `--quick` skips the two benchmarks. Re-record the
  baselines (`--save-baseline`) only from a Release build of a committed
  tree, and name that commit in the commit message.
- **Fuzzing**: the DNS parser/builder and the SVCB rewriter have libFuzzer
  targets.
