#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Per-query cost benchmark for omnidns (run against an unsanitized Release build).

    tests/integ/test_perf.py [path/to/omnidns] [--save-baseline]

Reuses test_integ.py's namespace topology / upstreams / daemon handling and
test_mem.py's windowed UDP client (48 queries in flight from one socket,
below max_pending_per_client). The daemon runs with tests/integ/mcount.c
LD_PRELOADed (compiled at startup with `cc`), which keeps malloc-family call
and byte counters in a shared file mapping that this script snapshots.

Before measuring, the cache is filled past cache_size (default 10000) with
distinct forwarded names, so the miss cases measure the steady state in
which every insert also evicts. Cases (each: warm up, snapshot, N queries,
snapshot):

    hit           ~1000 cached names queried over and over; the upstream
                  logs must not grow while it is measured
    forward miss  distinct names through the catchall forward rule
    cname miss    distinct names answered with a CNAME to a synthetic A
    fakeip miss   distinct names under a fakeip rule (new bindings + nft batch)
    block         distinct names under a block rule (no upstream queries)

Reports allocations/query, bytes allocated/query (requested sizes, see
mcount.c), queries/s and p50/p99 latency. Compared with
tests/integ/perf_baseline.json when present (--save-baseline rewrites it).
Exits non-zero if the daemon fails or does not answer, or if a case costs
more than its baseline allows:

    baseline <= 0.005 (none)  fails above 0.005/query, i.e. on any regular
                              allocation (allocs and bytes alike)
    allocs/query              fails above max(baseline * 1.10, baseline + 0.25)
    bytes/query               fails above max(baseline * 1.10, baseline + 32)

qps and latency are informational only and never gated (noisy; the miss
cases are bounded by the Python fake upstreams).
"""
import ipaddress
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_integ as ti  # noqa: E402
import test_mem as tm  # noqa: E402

BASELINE = os.path.join(HERE, "perf_baseline.json")
TOLERANCE = 0.10                        # relative slack, allocs and bytes
ALLOC_SLACK, BYTES_SLACK = 0.25, 32.0   # absolute slack per query
ZERO = 0.005                            # a baseline at or below this is "none"
CACHE_SIZE = 10000                      # the daemon's default cache_size
N_FILL = CACHE_SIZE * 6 // 5
WINDOW = 48
N_HIT_NAMES, N_HIT = 1000, 20000
N_FWD, N_CNAME, N_FAKE, N_BLOCK, N_WARM = 3000, 2000, 3000, 20000, 200
REAL_NET = ipaddress.IPv4Network("10.64.0.0/10")
FAKE_NET = ipaddress.IPv4Network("198.18.0.0/15")
FIELDS = ("malloc", "calloc", "realloc", "free", "memalign", "bytes")

CONFIG = """
config omnidns 'main'
	option port '53'
	list listen_addr '{lan}'
	option fwmask '0xff000000'
	option fakeip_v4 '198.18.0.0/15'
	option block_mode 'nodata'
	option log_level 'info'

config rule 'adblock'
	option action 'block'
	list nameset '{d}/block.txt'

config rule 'proxied'
	option action 'fakeip'
	option upstream '{d}/cf.conf'
	option fwmark '0x01'
	list nameset '{d}/fake.txt'

config rule 'catchall'
	option action 'forward'
	option upstream '{d}/isp.conf'
"""


def build_mcount(tmp):
    cc = shutil.which(os.environ.get("CC", "cc"))
    if not cc:
        print("SKIP: no C compiler (cc) to build tests/integ/mcount.c")
        sys.exit(0)
    so = os.path.join(tmp, "mcount.so")
    subprocess.run([cc, "-O2", "-shared", "-fPIC", "-o", so, os.path.join(HERE, "mcount.c"),
                    "-ldl"], check=True)
    return so


def counters(path):
    with open(path, "rb") as f:
        data = f.read(8 * len(FIELDS))
    return dict(zip(FIELDS, struct.unpack("=%dQ" % len(FIELDS), data)))


def no_answer(r):
    return r["rcode"] == 0 and not ti.answers(r, "A")


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))] if xs else float("nan")


def upstream_queries(env):
    return sum(len(env.upstream_log(u)) for u in ti.UP)


def measure(env, mfile, name, warm, names, ok, no_upstream):
    bad = tm.blast(warm, ok, window=WINDOW)
    ti.check(not bad, "%s warm-up failures: %r" % (name, bad[:5]))
    time.sleep(0.2)
    u0 = upstream_queries(env)
    c0, lat = counters(mfile), []
    t0 = time.monotonic()
    bad = tm.blast(names, ok, window=WINDOW, lat=lat)
    dt = time.monotonic() - t0
    time.sleep(0.2)   # let trailing work (nft acks) land in the counters
    c1 = counters(mfile)
    ti.check(not bad, "%s failures (%d): %r" % (name, len(bad), bad[:5]))
    if no_upstream:
        nup = upstream_queries(env) - u0
        ti.check(nup == 0, "%s sent %d queries upstream" % (name, nup))
    ti.check(env.daemon.poll() is None, "daemon died during %s" % name)
    d = {k: c1[k] - c0[k] for k in FIELDS}
    n = len(names)
    allocs = d["malloc"] + d["calloc"] + d["realloc"] + d["memalign"]
    return {"allocs": allocs / n, "frees": d["free"] / n, "bytes": d["bytes"] / n,
            "qps": n / dt, "p50": pct(lat, 0.5) * 1e3, "p99": pct(lat, 0.99) * 1e3, "n": n}


def run(env, so, mfile):
    hit = ["h%d.hit.test" % i for i in range(N_HIT_NAMES)]
    cname_names = ["n%d.chain.test" % i for i in range(N_WARM + N_CNAME)]
    zone = {"records": [["plain.test", "A", 300, ti.REAL_B]] +
            [[n, "CNAME", 300, "t%d.target.test" % i] for i, n in enumerate(cname_names)],
            "synth_a": str(REAL_NET), "synth_ttl": 3600}
    env.files(zone=zone, config=CONFIG,
              namesets={"block.txt": "*.blk.test\n", "fake.txt": "*.fake.test\n"})
    env.upstreams()
    # only the daemon gets the preload (Env.start_daemon copies os.environ):
    # anything else inheriting it (the Python fake upstreams) would map the
    # same counter file and add its own allocations to the daemon's
    os.environ.update(LD_PRELOAD=so, MCOUNT_FILE=mfile)
    try:
        env.start_daemon()
    finally:
        os.environ.pop("LD_PRELOAD", None)
        os.environ.pop("MCOUNT_FILE", None)
    ti.check(counters(mfile)["malloc"] > 0, "mcount not active in the daemon")

    def distinct(fmt, n):
        return [fmt % i for i in range(n)]

    real, fake = tm.a_in(REAL_NET), tm.a_in(FAKE_NET)
    t0 = time.monotonic()
    bad = tm.blast(distinct("f%d.fill.test", N_FILL), real, window=WINDOW)
    ti.check(not bad, "cache fill failures: %r" % bad[:5])
    print("  %-13s %d queries in %.2fs" % ("cache fill", N_FILL, time.monotonic() - t0))
    # (name, warm-up names, measured names, answer check, no upstream queries)
    cases = [
        ("hit", hit, (hit * (N_HIT // N_HIT_NAMES + 1))[:N_HIT], real, True),
        ("forward miss", distinct("w%d.fwd.test", N_WARM), distinct("m%d.fwd.test", N_FWD),
         real, False),
        ("cname miss", cname_names[:N_WARM], cname_names[N_WARM:], real, False),
        ("fakeip miss", distinct("w%d.fake.test", N_WARM), distinct("m%d.fake.test", N_FAKE),
         fake, False),
        ("block", distinct("w%d.blk.test", N_WARM), distinct("m%d.blk.test", N_BLOCK),
         no_answer, True),
    ]
    rows = []
    for name, warm, names, ok, no_upstream in cases:
        m = measure(env, mfile, name, warm, names, ok, no_upstream)
        print("  %-13s %d queries in %.2fs" % (name, m["n"], m["n"] / m["qps"]))
        rows.append((name, m))
    return rows


def limit(base, slack):
    """Highest passing per-query cost for a baseline of `base`."""
    if base <= ZERO:
        return ZERO
    return max(base * (1 + TOLERANCE), base + slack)


def report(rows, baseline):
    print("\n%-13s %8s %8s %9s %8s %8s %8s" %
          ("case", "allocs/q", "frees/q", "bytes/q", "qps", "p50 ms", "p99 ms"))
    for name, m in rows:
        print("%-13s %8.3f %8.3f %9.1f %8.0f %8.2f %8.2f" %
              (name, m["allocs"], m["frees"], m["bytes"], m["qps"], m["p50"], m["p99"]))
    if not baseline:
        print("\n(no baseline at %s)" % os.path.relpath(BASELINE, ti.ROOT))
        return []
    worse = []
    print("\nvs baseline (qps informational):\n%-13s %8s %8s %8s %9s %9s %9s %8s %8s" %
          ("case", "base a/q", "allocs/q", "limit", "base b/q", "bytes/q", "limit",
           "base qps", "qps"))
    for name, m in rows:
        b = baseline.get(name)
        if not b:
            print("%-13s (not in baseline)" % name)
            continue
        bad = [k for k, slack in (("allocs", ALLOC_SLACK), ("bytes", BYTES_SLACK))
               if m[k] > limit(b[k], slack)]
        flag = ""
        if bad:
            worse.append("%s (%s)" % (name, "+".join(bad)))
            flag = "  WORSE: " + "+".join(bad)
        print("%-13s %8.3f %8.3f %8.3f %9.1f %9.1f %9.1f %8.0f %8.0f%s" %
              (name, b["allocs"], m["allocs"], limit(b["allocs"], ALLOC_SLACK),
               b["bytes"], m["bytes"], limit(b["bytes"], BYTES_SLACK), b["qps"], m["qps"], flag))
    return worse


def main():
    ti.enter_netns()
    binary = ti.binary_arg("build/rel/omnidns")
    tmp = tempfile.mkdtemp(prefix="omniperf.")
    so = build_mcount(tmp)
    mfile = os.path.join(tmp, "counters")
    env = ti.Env(binary)
    rows, err = None, None
    try:
        env.netns()
        rows = run(env, so, mfile)
    except Exception as e:  # noqa: BLE001
        err = e
    finally:
        env.teardown()
        shutil.rmtree(tmp, ignore_errors=True)
    if err is not None or rows is None:
        print("FAIL: %s" % err)
        print("--- daemon log (tail) ---")
        print(env.daemon_log()[-3000:] if env.daemon else "")
        sys.exit(1)
    baseline = None
    if os.path.exists(BASELINE):
        with open(BASELINE) as f:
            baseline = json.load(f)
    worse = report(rows, baseline)
    if "--save-baseline" in sys.argv:
        worse = []
        with open(BASELINE, "w") as f:
            json.dump({n: {k: round(m[k], 3) for k in ("allocs", "bytes", "qps")}
                       for n, m in rows}, f, indent=1)
            f.write("\n")
        print("\nbaseline saved to %s" % os.path.relpath(BASELINE, ti.ROOT))
    if worse:
        print("\nper-query cost above the baseline's limit: %s" % ", ".join(worse))
        sys.exit(1)
    print("\nok")


if __name__ == "__main__":
    main()
