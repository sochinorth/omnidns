#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Per-query cost benchmark for omnidns (run against an unsanitized Release build).

    tests/integ/test_perf.py [path/to/omnidns] [--save-baseline]

Reuses test_integ.py's namespace topology / upstreams / daemon handling and
test_mem.py's windowed UDP client (48 queries in flight from one socket,
below max_pending_per_client). The daemon runs with tests/integ/mcount.c
LD_PRELOADed (compiled at startup with `cc`), which keeps malloc-family call
and byte counters in a shared file mapping that this script snapshots.

Cases (each: warm up, snapshot, N queries, snapshot):

    hit           ~1000 cached names queried over and over
    forward miss  distinct names through the catchall forward rule
    cname miss    distinct names answered with a CNAME to a synthetic A
    fakeip miss   distinct names under a fakeip rule (new bindings + nft batch)
    block         distinct names under a block rule

Reports allocations/query, bytes allocated/query, queries/s and p50/p99
latency. Compared with tests/integ/perf_baseline.json when present
(--save-baseline rewrites it). Exits non-zero if the daemon fails or does not
answer, or if any case's allocs/query is more than 10% (and more than 0.25)
above the baseline. qps and latency are informational only (noisy; the miss
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
TOLERANCE, ABS_SLACK = 0.10, 0.25
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


def measure(env, mfile, name, warm, names, ok):
    bad = tm.blast(warm, ok, window=WINDOW)
    ti.check(not bad, "%s warm-up failures: %r" % (name, bad[:5]))
    time.sleep(0.2)
    c0, lat = counters(mfile), []
    t0 = time.monotonic()
    bad = tm.blast(names, ok, window=WINDOW, lat=lat)
    dt = time.monotonic() - t0
    time.sleep(0.2)   # let trailing work (nft acks) land in the counters
    c1 = counters(mfile)
    ti.check(not bad, "%s failures (%d): %r" % (name, len(bad), bad[:5]))
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
    cases = [
        ("hit", hit, (hit * (N_HIT // N_HIT_NAMES + 1))[:N_HIT], real),
        ("forward miss", distinct("w%d.fwd.test", N_WARM), distinct("m%d.fwd.test", N_FWD), real),
        ("cname miss", cname_names[:N_WARM], cname_names[N_WARM:], real),
        ("fakeip miss", distinct("w%d.fake.test", N_WARM), distinct("m%d.fake.test", N_FAKE), fake),
        ("block", distinct("w%d.blk.test", N_WARM), distinct("m%d.blk.test", N_BLOCK), no_answer),
    ]
    rows = []
    for name, warm, names, ok in cases:
        m = measure(env, mfile, name, warm, names, ok)
        print("  %-13s %d queries in %.2fs" % (name, m["n"], m["n"] / m["qps"]))
        rows.append((name, m))
    return rows


def report(rows, baseline):
    print("\n%-13s %8s %8s %9s %8s %8s %8s" %
          ("case", "allocs/q", "frees/q", "bytes/q", "qps", "p50 ms", "p99 ms"))
    for name, m in rows:
        print("%-13s %8.2f %8.2f %9.0f %8.0f %8.2f %8.2f" %
              (name, m["allocs"], m["frees"], m["bytes"], m["qps"], m["p50"], m["p99"]))
    if not baseline:
        print("\n(no baseline at %s)" % os.path.relpath(BASELINE, ti.ROOT))
        return []
    worse = []
    print("\nvs baseline:\n%-13s %8s %8s %8s %9s %9s %8s %8s %8s" %
          ("case", "base a/q", "allocs/q", "%", "base b/q", "bytes/q", "%", "base qps", "qps"))
    for name, m in rows:
        b = baseline.get(name)
        if not b:
            print("%-13s (not in baseline)" % name)
            continue

        def rel(x, y):
            return 100.0 * (x - y) / y if y else 0.0
        flag = ""
        if m["allocs"] > max(b["allocs"] * (1 + TOLERANCE), b["allocs"] + ABS_SLACK):
            worse.append(name)
            flag = "  WORSE"
        print("%-13s %8.2f %8.2f %+7.1f%% %9.0f %9.0f %+7.1f%% %8.0f %8.0f%s" %
              (name, b["allocs"], m["allocs"], rel(m["allocs"], b["allocs"]),
               b["bytes"], m["bytes"], rel(m["bytes"], b["bytes"]), b["qps"], m["qps"], flag))
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
            json.dump({n: {k: round(m[k], 2) for k in ("allocs", "bytes", "qps")}
                       for n, m in rows}, f, indent=1)
            f.write("\n")
        print("\nbaseline saved to %s" % os.path.relpath(BASELINE, ti.ROOT))
    if worse:
        print("\nallocs/query more than %d%% above baseline: %s" %
              (TOLERANCE * 100, ", ".join(worse)))
        sys.exit(1)
    print("\nok")


if __name__ == "__main__":
    main()
