#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Memory benchmark for omnidns (run against an unsanitized Release build).

    tests/integ/test_mem.py [path/to/omnidns] [--save-baseline]

Reuses test_integ.py's namespace topology, upstreams and daemon handling.
One daemon run with 75k synthetic nameset patterns (2 block lists, 1 fakeip
list, catchall forward); RSS is sampled from /proc/<pid>/status after:

    startup        daemon up and idle
    cache 10k      10,000 distinct forwarded names (fills cache_size)
    bindings 20k   ~20,000 distinct names under fakeip suffix patterns
    reload         one block list grown, SIGHUP, "configuration reloaded"

Results are compared with tests/integ/mem_baseline.json when it exists
(--save-baseline rewrites it). Exits non-zero if the daemon fails or any
row's RssAnon is more than 10% above the baseline.
"""
import ipaddress
import json
import os
import random
import select
import signal
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dnsmini  # noqa: E402
import test_integ as ti  # noqa: E402

BASELINE = os.path.join(HERE, "mem_baseline.json")
TOLERANCE = 0.10
SEED = 20261016
N_BLOCK_A, N_BLOCK_B, N_FAKE, N_EXTRA = 35000, 25000, 15000, 50
N_CACHE, N_BIND = 10000, 20000
REAL_NET = "10.64.0.0/10"
FAKE_NET = ipaddress.IPv4Network("198.18.0.0/15")

ZONE = {"records": [["plain.test", "A", 300, ti.REAL_B]],
        "synth_a": REAL_NET, "synth_ttl": 3600}

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
	list nameset '{d}/block_a.txt'
	list nameset '{d}/block_b.txt'

config rule 'proxied'
	option action 'fakeip'
	option upstream '{d}/cf.conf'
	option fwmark '0x01'
	list nameset '{d}/fake.txt'

config rule 'catchall'
	option action 'forward'
	option upstream '{d}/isp.conf'
"""

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
TLDS = ["com"] * 10 + ["net"] * 3 + ["org"] * 2 + ["io", "ru", "de", "xyz", "info", "co",
                                                   "cn", "top", "online", "site"]


# ------------------------------------------------------------------ patterns

def gen_patterns(n, rnd):
    """Adblock-style list: 2-5 labels, mean ~22 chars (8..60), ~30% `*.`
    suffix patterns, ~12% derived from (and so subdomains of) earlier ones."""
    def label():
        ln = max(1, min(40, int(rnd.lognormvariate(1.9, 0.5))))
        return "".join(rnd.choice(ALPHABET) for _ in range(ln))

    seen, out = set(), []
    while len(out) < n:
        if out and rnd.random() < 0.12:
            name = label() + "." + rnd.choice(out).lstrip("*.")
        else:
            k = rnd.choices([2, 3, 4, 5], [30, 40, 20, 10])[0]
            name = ".".join([label() for _ in range(k - 1)] + [rnd.choice(TLDS)])
        if not 8 <= len(name) <= 60:
            continue
        pat = "*." + name if rnd.random() < 0.3 else name
        if pat not in seen:
            seen.add(pat)
            out.append(pat)
    return out


def suffixes(name):
    parts = name.split(".")
    return (".".join(parts[i:]) for i in range(len(parts)))


# ------------------------------------------------------------------ helpers

def blast(names, ok, window=48, timeout=1.0, tries=6):
    """Send A queries for `names` to the daemon with `window` in flight
    (below max_pending_per_client), retrying on timeout. Returns a list of
    (name, problem) for queries that failed `ok(resp)` or never got answered."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    s.setblocking(False)
    pending, bad, it, nid = {}, [], iter(names), 0
    more = True

    def send(qid, name):
        s.sendto(dnsmini.build_query(name, "A", id=qid), (ti.LAN, 53))

    while more or pending:
        while more and len(pending) < window:
            name = next(it, None)
            if name is None:
                more = False
                break
            while nid in pending:
                nid = (nid + 1) & 0xFFFF
            pending[nid] = [name, time.monotonic() + timeout, 1]
            send(nid, name)
            nid = (nid + 1) & 0xFFFF
        if select.select([s], [], [], 0.05)[0]:
            while True:
                try:
                    data = s.recv(4096)
                except BlockingIOError:
                    break
                r = dnsmini.parse_msg(data)
                p = pending.get(r["id"])
                if not p or not r["question"] or r["question"][0].lower() != p[0]:
                    continue
                del pending[r["id"]]
                if not ok(r):
                    bad.append((p[0], "rcode %d an %r" % (r["rcode"], ti.answers(r))))
        now = time.monotonic()
        for qid, p in list(pending.items()):
            if p[1] > now:
                continue
            if p[2] >= tries:
                bad.append((p[0], "timeout"))
                del pending[qid]
            else:
                p[1], p[2] = now + timeout, p[2] + 1
                send(qid, p[0])
    s.close()
    return bad


def a_in(net):
    def ok(r):
        ips = ti.answers(r, "A")
        return r["rcode"] == 0 and len(ips) == 1 and ipaddress.IPv4Address(ips[0]) in net
    return ok


def sample(pid):
    time.sleep(1.0)   # let the event loop settle
    out = {}
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            k, _, v = line.partition(":")
            if k in ("VmRSS", "RssAnon"):
                out[k] = int(v.split()[0])
    try:
        with open("/proc/%d/smaps_rollup" % pid) as f:
            for line in f:
                if line.startswith("Anonymous:"):
                    out["Anonymous"] = int(line.split()[1])
    except OSError:
        pass
    return out


def wait_log(env, offset, needle, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        tail = env.daemon_log()[offset:]
        if needle in tail:
            return tail
        if "keeping previous" in tail or env.daemon.poll() is not None:
            break
        time.sleep(0.1)
    raise RuntimeError("no %r in daemon log:\n%s" % (needle, env.daemon_log()[offset:][-2000:]))


def report(rows, baseline):
    start = rows[0][1]
    print("\n%-13s %9s %9s %10s %9s" % ("row", "VmRSS kB", "RssAnon", "dAnon", "Anon(sm)"))
    for name, m in rows:
        print("%-13s %9d %9d %+10d %9s" % (name, m["VmRSS"], m["RssAnon"],
                                          m["RssAnon"] - start["RssAnon"],
                                          m.get("Anonymous", "-")))
    if not baseline:
        print("\n(no baseline at %s)" % os.path.relpath(BASELINE, ti.ROOT))
        return []
    worse = []
    print("\nvs baseline:\n%-13s %9s %9s %8s %9s %9s %8s" %
          ("row", "base RSS", "VmRSS", "%", "base Anon", "RssAnon", "%"))
    for name, m in rows:
        b = baseline.get(name)
        if not b:
            print("%-13s (not in baseline)" % name)
            continue
        drss = 100.0 * (m["VmRSS"] - b["VmRSS"]) / b["VmRSS"]
        danon = 100.0 * (m["RssAnon"] - b["RssAnon"]) / b["RssAnon"]
        flag = ""
        if m["RssAnon"] > b["RssAnon"] * (1 + TOLERANCE):
            worse.append(name)
            flag = "  WORSE"
        print("%-13s %9d %9d %+7.1f%% %9d %9d %+7.1f%%%s" %
              (name, b["VmRSS"], m["VmRSS"], drss, b["RssAnon"], m["RssAnon"], danon, flag))
    return worse


# ------------------------------------------------------------------ main

def run(env):
    rnd = random.Random(SEED)
    pats = gen_patterns(N_BLOCK_A + N_BLOCK_B + N_FAKE + N_EXTRA, rnd)
    block_a = pats[:N_BLOCK_A]
    block_b = pats[N_BLOCK_A:N_BLOCK_A + N_BLOCK_B]
    fake = pats[N_BLOCK_A + N_BLOCK_B:N_BLOCK_A + N_BLOCK_B + N_FAKE]
    extra = pats[-N_EXTRA:]
    lens = [len(p) for p in pats]
    print("patterns: %d (mean len %.1f, min %d, max %d, %d%% suffix)" %
          (len(pats) - N_EXTRA, sum(lens) / len(lens), min(lens), max(lens),
           100 * sum(p.startswith("*.") for p in pats) // len(pats)))

    # fakeip query bases: suffix patterns not shadowed by a block pattern
    blocked = {p[2:] for p in block_a + block_b + extra if p.startswith("*.")}
    blocked_exact = set(block_a + block_b + extra)
    bases = [p[2:] for p in fake if p.startswith("*.")
             and not any(s in blocked for s in suffixes(p[2:]))]
    bind_names = ["x%d.%s" % (i, bases[i % len(bases)]) for i in range(N_BIND)]
    bind_names = [n for n in bind_names if n not in blocked_exact]
    cache_names = ["c%d.mem.test" % i for i in range(N_CACHE)]

    env.files(zone=ZONE, config=CONFIG, namesets={
        "block_a.txt": "\n".join(block_a) + "\n",
        "block_b.txt": "\n".join(block_b) + "\n",
        "fake.txt": "\n".join(fake) + "\n"})
    env.upstreams()
    t0 = time.time()
    env.start_daemon()
    print("daemon up in %.2fs" % (time.time() - t0))
    for line in env.daemon_log().splitlines():
        if "started" in line or "pattern" in line:
            print("  log: " + line.strip())
    pid = env.daemon.pid
    rows = [("startup", sample(pid))]

    t0 = time.time()
    bad = blast(cache_names, a_in(ipaddress.IPv4Network(REAL_NET)))
    print("cache: %d queries in %.1fs, %d failed" % (len(cache_names), time.time() - t0, len(bad)))
    ti.check(not bad, "cache phase failures: %r" % bad[:5])
    rows.append(("cache 10k", sample(pid)))

    t0 = time.time()
    bad = blast(bind_names, a_in(FAKE_NET))
    print("bindings: %d queries over %d suffixes in %.1fs, %d failed" %
          (len(bind_names), len(bases), time.time() - t0, len(bad)))
    ti.check(not bad, "binding phase failures: %r" % bad[:5])
    nft = sum(1 for _ in env.nft_map("fake2real_v4"))
    print("fake2real_v4 elements: %d" % nft)
    rows.append(("bindings 20k", sample(pid)))

    with open(env.dir + "/block_a.txt", "a") as f:
        f.write("\n".join(extra) + "\n")
    off = len(env.daemon_log())
    env.daemon.send_signal(signal.SIGHUP)
    t0 = time.time()
    line = wait_log(env, off, "configuration reloaded")
    print("reload in %.2fs: %s" % (time.time() - t0, line.strip().splitlines()[-1]))
    probe = "z." + next(p for p in extra if p.startswith("*."))[2:]
    r = dnsmini.query(ti.LAN, 53, probe, "A")
    ti.check(r["rcode"] == 0 and not r["an"], "appended pattern not blocked: %r" % r)
    rows.append(("reload", sample(pid)))
    ti.check(env.daemon.poll() is None, "daemon died")
    return rows


def main():
    ti.enter_netns()
    binary = ti.binary_arg("build/rel/omnidns")
    env = ti.Env(binary)
    rows, err = None, None
    try:
        env.netns()
        rows = run(env)
    except Exception as e:  # noqa: BLE001
        err = e
    finally:
        env.teardown()
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
            json.dump({n: {"VmRSS": m["VmRSS"], "RssAnon": m["RssAnon"]} for n, m in rows},
                      f, indent=1)
            f.write("\n")
        print("\nbaseline saved to %s" % os.path.relpath(BASELINE, ti.ROOT))
    if worse:
        print("\nRssAnon more than %d%% above baseline: %s" % (TOLERANCE * 100, ", ".join(worse)))
        sys.exit(1)
    print("\nok")


if __name__ == "__main__":
    main()
