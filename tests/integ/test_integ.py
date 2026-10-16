#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end tests for omnidns in unprivileged network namespaces.

    tests/integ/test_integ.py [path/to/omnidns] [-k substring]

Re-execs itself under `unshare -rn` (user + net namespace). Topology:

    client netns                      router netns (this process)
    lan1 192.168.77.2/24  <-veth->    lan0 192.168.77.1/24   omnidns :53
    default via .1                    wan0 (dummy) 203.0.113.1/24
                                      real services on 203.0.113.10/.11 :8080
                                      fake upstreams on 127.0.1.{1,2,3}#53xx
                                      198.18.0.0/15 routed to wan0

Client-side commands run via `nsenter -t <pid> -n`.
"""
import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dnsmini  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(HERE))
TABLE = "omniinteg"
LAN = "192.168.77.1"
CLIENT = "192.168.77.2"
REAL_A, REAL_B = "203.0.113.10", "203.0.113.11"
LAN6, CLIENT6, REAL6 = "fd77::1", "fd77::2", "2001:db8:1::10"
UP = {"isp": ("127.0.1.1", 5301), "cf": ("127.0.1.2", 5302), "alt": ("127.0.1.3", 5303)}

ZONE = {
    "records": [
        ["plain.test", "A", 300, REAL_B],
        ["warp.test", "A", 120, REAL_A],
        ["warp.test", "AAAA", 120, REAL6],
        ["www.warp.test", "CNAME", 300, "edge.cdn.test"],
        ["edge.cdn.test", "A", 60, REAL_A],
        ["long.warp.test", "A", 86400, REAL_A],
        ["cloak.test", "CNAME", 300, "tracker.ads.test"],
        ["tracker.ads.test", "A", 60, "203.0.113.66"],
        ["ads.test", "A", 60, "203.0.113.66"],
        ["svc.test", "HTTPS", 300,
         "1 . alpn=h2,h3 ipv4hint=" + REAL_A + " ipv6hint=2001:db8::10 ech=AAAA"],
        ["svc.warp.test", "HTTPS", 300,
         "1 . alpn=h2 ipv4hint=" + REAL_A + " ipv6hint=2001:db8::10 ech=AAAA"],
        ["big.test", "TXT", 60, "x" * 200],
        ["big.test", "TXT", 60, "y" * 200],
        ["big.test", "TXT", 60, "z" * 200],
        ["mixed.test", "CNAME", 300, "inner.warp.test"],
        ["inner.warp.test", "A", 60, REAL_A],
    ],
}

CONFIG = """
config omnidns 'main'
	option port '53'
	list listen_addr '{lan}'
	option fwmask '0xff000000'
	option fakeip_v4 '198.18.0.0/15'
	option block_mode 'nodata'
	option log_level 'debug'

config rule 'adblock'
	option action 'block'
	list nameset '{d}/ads.txt'

config rule 'warp'
	option action 'fakeip'
	option upstream '{d}/cf.conf'
	option fwmark '0x01'
	list nameset '{d}/warp.txt'

config rule 'catchall'
	option action 'forward'
	option upstream '{d}/isp.conf'
"""

NAMESETS = {"ads.txt": "*.ads.test\n", "warp.txt": "*.warp.test\n"}

failures = []
tests = []


def test(fn):
    tests.append(fn)
    return fn


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def sh(cmd, check_rc=True, **kw):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)
    if check_rc and r.returncode:
        raise RuntimeError("%s: %s%s" % (cmd, r.stdout, r.stderr))
    return r.stdout


class Env:
    def __init__(self, binary):
        self.binary = binary
        self.dir = tempfile.mkdtemp(prefix="omniinteg.")
        self.procs = []
        self.client_pid = None
        self.daemon = None

    # ---- setup ----
    def netns(self):
        sh("ip link set lo up")
        child = subprocess.Popen(["unshare", "-n", "sleep", "3600"])
        self.procs.append(child)
        time.sleep(0.2)
        self.client_pid = child.pid
        sh("ip link add lan0 type veth peer name lan1")
        sh("ip link set lan1 netns %d" % child.pid)
        sh("ip addr add %s/24 dev lan0 && ip link set lan0 up" % LAN)
        self.cl("ip link set lo up && ip addr add %s/24 dev lan1 && ip link set lan1 up "
                "&& ip route add default via %s" % (CLIENT, LAN))
        sh("ip link add wan0 type dummy && ip link set wan0 up")
        sh("ip addr add 203.0.113.1/24 dev wan0")
        for a in (REAL_A, REAL_B):
            sh("ip addr add %s/32 dev wan0" % a)
        sh("ip route add 198.18.0.0/15 dev wan0")
        sh("ip -6 addr add %s/64 dev lan0 nodad" % LAN6)
        self.cl("ip -6 addr add %s/64 dev lan1 nodad && ip -6 route add default via %s"
                % (CLIENT6, LAN6))
        sh("ip -6 addr add %s/128 dev wan0 nodad" % REAL6)
        sh("ip -6 route add fd00:198:18::/64 dev wan0")
        with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as f:
            f.write("1")
        for ip, _ in UP.values():
            sh("ip addr add %s/8 dev lo" % ip, check_rc=False)
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        # observer table: counts marked packets arriving at real services
        sh("""nft -f - <<'EOF'
table ip omniobs {
  chain input { type filter hook input priority 10; policy accept;
    tcp dport 8080 meta mark & 0xff000000 == 0x01000000 counter
    tcp dport 8080 ct mark & 0xff000000 == 0x01000000 counter
    tcp dport 8080 counter
  }
}
EOF""")

    def cl(self, cmd, check_rc=True):
        return sh("nsenter -t %d -n sh -c %s" % (self.client_pid, sh_quote(cmd)), check_rc)

    def files(self, zone=ZONE, namesets=NAMESETS, config=CONFIG):
        d = self.dir
        with open(d + "/zone.json", "w") as f:
            json.dump(zone, f)
        for name, (ip, port) in UP.items():
            with open("%s/%s.conf" % (d, name), "w") as f:
                f.write("nameserver %s#%d\n" % (ip, port))
        for fname, text in namesets.items():
            with open("%s/%s" % (d, fname), "w") as f:
                f.write(text)
        self.write_config(config)

    def write_config(self, text):
        with open(self.dir + "/omnidns", "w") as f:
            f.write(text.format(lan=LAN, d=self.dir))

    def upstreams(self):
        for name, (ip, port) in UP.items():
            p = subprocess.Popen([sys.executable, HERE + "/dnsmini.py", "serve", "--addr", ip,
                                  "--port", str(port), "--zone", self.dir + "/zone.json",
                                  "--log", "%s/%s.log" % (self.dir, name)],
                                 stdout=subprocess.PIPE, text=True)
            check(p.stdout.readline().strip() == "ready", "upstream %s failed" % name)
            self.procs.append(p)

    def services(self):
        for addr in (REAL_A, REAL_B, REAL6):
            s = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((addr, 8080))
            s.listen(64)

            def loop(sock=s, a=addr):
                while True:
                    c, _ = sock.accept()
                    c.sendall(("hello from %s\n" % a).encode())
                    c.close()
            threading.Thread(target=loop, daemon=True).start()

    def start_daemon(self):
        log = open(self.dir + "/daemon.log", "a")
        env = dict(os.environ)
        self.daemon = subprocess.Popen([self.binary, "-f", "-t", TABLE, "-x",
                                        "-c", self.dir + "/omnidns"],
                                       stdout=log, stderr=log, env=env)
        for _ in range(50):
            try:
                dnsmini.query(LAN, 53, "plain.test", "A", timeout=0.2)
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("daemon did not come up:\n" + self.daemon_log())

    def daemon_log(self):
        with open(self.dir + "/daemon.log") as f:
            return f.read()

    def hup(self):
        self.daemon.send_signal(signal.SIGHUP)
        time.sleep(0.5)

    def upstream_log(self, name):
        try:
            with open("%s/%s.log" % (self.dir, name)) as f:
                return [json.loads(x) for x in f]
        except FileNotFoundError:
            return []

    def clear_upstream_logs(self):
        for name in UP:
            open("%s/%s.log" % (self.dir, name), "w").close()

    # ---- client actions ----
    def q(self, name, qtype, tcp=False, **kw):
        """DNS query from the client netns."""
        code = ("import sys,json; sys.path.insert(0,%r); import dnsmini as d; "
                "print(json.dumps(d.query(%r,53,%r,%r,tcp=%r,**%r)))"
                % (HERE, LAN, name, qtype, tcp, kw))
        return json.loads(self.cl("%s -c %s" % (sys.executable, sh_quote(code))))

    def connect(self, ip, port=8080, router=False):
        code = ("import socket,sys\n"
                "s=socket.socket(%s); s.settimeout(2)\n"
                "try:\n s.connect((%r,%d)); print(s.recv(100).decode().strip())\n"
                "except Exception as e: print('ERR', type(e).__name__)\n"
                % ("socket.AF_INET6" if ":" in ip else "", ip, port))
        cmd = "%s -c %s" % (sys.executable, sh_quote(code))
        return (sh(cmd) if router else self.cl(cmd)).strip()

    def nft_map(self, name):
        out = json.loads(sh("nft -j list map inet %s %s" % (TABLE, name)))
        for o in out["nftables"]:
            if "map" in o:
                return {e[0]: e[1] for e in o["map"].get("elem", [])}
        return {}

    def counters(self):
        out = sh("nft list chain ip omniobs input")
        return [int(x.split("packets ")[1].split()[0]) for x in out.splitlines() if "packets" in x]

    def teardown(self):
        if self.daemon:
            self.daemon.terminate()
            try:
                self.daemon.wait(5)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
        for p in self.procs:
            p.kill()


def sh_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def answers(r, rtype=None):
    return [a["data"] for a in r["an"] if rtype is None or a["type"] == rtype]


def in_pool(ip):
    return ip.startswith("198.18.") or ip.startswith("198.19.")


# ------------------------------------------------------------------ tests

@test
def forward_udp_tcp(env):
    for tcp in (False, True):
        r = env.q("plain.test", "A", tcp=tcp)
        check(r["rcode"] == 0 and answers(r, "A") == [REAL_B], r)
    check(any(e["name"] == "plain.test" for e in env.upstream_log("isp")), "isp not asked")


@test
def edns_and_case(env):
    r = env.q("PlAiN.TeSt", "A")
    check(r["question"][0] == "PlAiN.TeSt", "question case not preserved: %r" % (r["question"],))
    check(r["edns"] is not None, "no OPT echoed")
    r = env.q("plain.test", "A", edns=False)
    check(r["edns"] is None, "OPT without client EDNS")


@test
def truncation_tcp(env):
    r = env.q("big.test", "TXT", edns=False)
    check(r["tc"], "expected TC over 512-byte UDP")
    r = env.q("big.test", "TXT", tcp=True)
    check(not r["tc"] and len(answers(r, "TXT")) == 3, r)


@test
def block_direct_and_cloaked(env):
    r = env.q("ads.test", "A")
    check(r["rcode"] == 0 and not r["an"] and r["ns"] and r["ns"][0]["type"] == "SOA", r)
    r = env.q("cloak.test", "A")
    check(r["rcode"] == 0 and not r["an"], "CNAME cloaking not blocked: %r" % r)


@test
def fakeip_dataplane(env):
    env.clear_upstream_logs()
    r = env.q("warp.test", "A")
    ips = answers(r, "A")
    check(len(ips) == 1 and in_pool(ips[0]), r)
    fake = ips[0]
    check(any(e["name"] == "warp.test" for e in env.upstream_log("cf")), "fakeip upstream (cf) not used")
    check(not any(e["name"] == "warp.test" for e in env.upstream_log("isp")), "isp asked for warp.test")
    m = env.nft_map("fake2real_v4")
    check(m.get(fake) == REAL_A, "fake2real: %r" % m)
    before = env.counters()
    out = env.connect(fake)
    check(out == "hello from " + REAL_A, "connect via fake: %r" % out)
    after = env.counters()
    check(after[0] > before[0], "meta mark not set on DNATed flow: %r -> %r" % (before, after))
    check(after[1] > before[1], "ct mark not set: %r -> %r" % (before, after))
    # stable answer from cache, TTL counting down
    time.sleep(1.1)
    r2 = env.q("warp.test", "A")
    check(answers(r2, "A") == [fake], "fake changed: %r" % r2)
    check(r2["an"][0]["ttl"] < r["an"][0]["ttl"], "TTL not decremented")


@test
def fakeip_ttl_capped(env):
    r = env.q("long.warp.test", "A")
    check(in_pool(answers(r, "A")[0]) and r["an"][0]["ttl"] <= 3600,
          "fake TTL not capped by fakeip_ttl_max: %r" % r)


@test
def fakeip_aaaa_without_v6_pool(env):
    r = env.q("warp.test", "AAAA")
    check(r["rcode"] == 0 and not answers(r, "AAAA"), "real v6 leaked past policy: %r" % r)


@test
def unmapped_fake_rejected(env):
    out = env.connect("198.19.255.200")
    check(out.startswith("ERR ConnectionRefused"), "unmapped fake: %r" % out)


@test
def cname_into_fakeip(env):
    # mixed.test (catchall, isp) -> inner.warp.test (warp, cf): re-query at cf
    env.clear_upstream_logs()
    r = env.q("mixed.test", "A")
    check(r["an"][0]["type"] == "CNAME" and r["an"][0]["name"] == "mixed.test", r)
    ips = answers(r, "A")
    check(ips and all(in_pool(i) for i in ips), r)
    check(any(e["name"] == "inner.warp.test" for e in env.upstream_log("cf")), "no re-query at cf")
    check(env.connect(ips[0]) == "hello from " + REAL_A, "connect")


@test
def https_hints(env):
    r = env.q("svc.test", "HTTPS")
    check(r["an"] and r["an"][0]["data"]["params"]["ipv4hint"] == [REAL_A], "catchall must not rewrite")
    r = env.q("svc.warp.test", "HTTPS")
    p = r["an"][0]["data"]["params"]
    check(all(in_pool(h) for h in p["ipv4hint"]), "ipv4hint not rewritten: %r" % p)
    check("ipv6hint" not in p, "ipv6hint must be dropped without a v6 pool: %r" % p)
    check(p["alpn"] == ["h2"] and p["ech"] == "000000", "other params not preserved: %r" % p)
    check(env.connect(p["ipv4hint"][0]) == "hello from " + REAL_A, "connect via hint")


@test
def ptr_for_fake(env):
    fake = answers(env.q("warp.test", "A"), "A")[0]
    rev = ".".join(reversed(fake.split("."))) + ".in-addr.arpa"
    env.clear_upstream_logs()
    r = env.q(rev, "PTR")
    check(answers(r, "PTR") == ["warp.test"], r)
    check(not env.upstream_log("isp") and not env.upstream_log("cf"), "PTR leaked upstream")


@test
def garbage_flood(env):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rnd = random.Random(1)
    for i in range(20000):
        n = rnd.randrange(0, 600)
        pkt = bytes(rnd.randrange(256) for _ in range(n))
        if i % 3 == 0 and n >= 12:
            pkt = bytes([pkt[0], pkt[1], pkt[2] & 0x7f]) + pkt[3:]   # look like a query
        s.sendto(pkt, (LAN, 53))
    s.close()
    # TCP: half-open and junk connections
    socks = []
    for _ in range(80):
        try:
            c = socket.create_connection((LAN, 53), timeout=1)
            c.send(b"\x00\x05junk")
            socks.append(c)
        except OSError:
            pass
    for c in socks:
        c.close()
    time.sleep(0.5)
    check(env.daemon.poll() is None, "daemon died:\n" + env.daemon_log()[-3000:])
    r = env.q("plain.test", "A")
    check(answers(r, "A") == [REAL_B], "not answering after flood")


@test
def reload_keeps_bindings_and_invalidates(env):
    fake = answers(env.q("warp.test", "A"), "A")[0]
    # move warp.test into a block rule placed first; bindings must survive
    cfg = CONFIG.replace("config rule 'adblock'", """config rule 'blockwarp'
	option action 'block'
	list nameset '{d}/warp.txt'

config rule 'adblock'""")
    env.write_config(cfg)
    env.hup()
    r = env.q("warp.test", "A")
    check(not r["an"], "cache not invalidated by rule change: %r" % r)
    check(env.nft_map("fake2real_v4").get(fake) == REAL_A, "binding lost on reload")
    check(env.connect(fake) == "hello from " + REAL_A, "live flow broken after reload")
    # pool change while bindings are live must be rejected
    env.write_config(CONFIG.replace("198.18.0.0/15", "100.64.0.0/16"))
    env.hup()
    check("rejected" in env.daemon_log(), "pool change not rejected")
    r = env.q("ads.test", "A")
    check(not r["an"], "previous config not retained")
    # restore
    env.write_config(CONFIG)
    env.hup()
    check(answers(env.q("warp.test", "A"), "A") == [fake], "same fake after restore")


def last_reload(env, after):
    lines = [x for x in env.daemon_log()[after:].splitlines() if "configuration reloaded" in x]
    check(lines, "no reload logged:\n" + env.daemon_log()[-800:])
    m = re.search(r"configuration reloaded \(generation (\d+)", lines[-1])
    return int(m.group(1)), "kept" in lines[-1]


@test
def reload_noop_keeps_generation(env):
    env.write_config(CONFIG)
    off = len(env.daemon_log())
    env.hup()
    gen, _ = last_reload(env, off)
    fake = answers(env.q("warp.test", "A"), "A")[0]
    check(answers(env.q("plain.test", "A"), "A") == [REAL_B], "plain.test")
    chains = sh("nft -a list table inet %s | grep -v elements" % TABLE)
    env.clear_upstream_logs()
    # nothing changed: same generation, cache still valid, no nft transaction
    off = len(env.daemon_log())
    env.hup()
    g, kept = last_reload(env, off)
    check(kept and g == gen, "no-op reload changed generation %d -> %d" % (gen, g))
    check(answers(env.q("warp.test", "A"), "A") == [fake], "fake changed")
    check(answers(env.q("plain.test", "A"), "A") == [REAL_B], "plain.test changed")
    check(not any(env.upstream_log(n) for n in UP), "cache not used after no-op reload")
    check(sh("nft -a list table inet %s | grep -v elements" % TABLE) == chains,
          "no-op reload rewrote nftables chains")
    check(env.nft_map("fake2real_v4").get(fake) == REAL_A, "binding lost on reload")
    # a nameset touched / replaced with identical content is still a no-op
    t = time.time() + 10
    os.utime(env.dir + "/warp.txt", (t, t))
    with open(env.dir + "/ads.tmp", "w") as f:
        f.write(NAMESETS["ads.txt"])
    os.rename(env.dir + "/ads.tmp", env.dir + "/ads.txt")
    off = len(env.daemon_log())
    env.hup()
    g, kept = last_reload(env, off)
    check(kept and g == gen, "touched namesets changed generation %d -> %d" % (gen, g))
    # an edited nameset: new generation, takes effect on cached names too
    with open(env.dir + "/ads.txt", "a") as f:
        f.write("plain.test\n")
    off = len(env.daemon_log())
    env.hup()
    g, kept = last_reload(env, off)
    check(not kept and g > gen, "edit kept generation %d" % g)
    r = env.q("plain.test", "A")
    check(r["rcode"] == 0 and not r["an"], "edited nameset not applied: %r" % r)
    # a changed upstream for the catchall: new generation
    env.write_config(CONFIG.replace("{d}/isp.conf", "{d}/alt.conf"))
    off = len(env.daemon_log())
    env.hup()
    g2, kept = last_reload(env, off)
    check(not kept and g2 > g, "upstream change kept generation %d" % g2)
    with open(env.dir + "/ads.txt", "w") as f:
        f.write(NAMESETS["ads.txt"])
    env.write_config(CONFIG)
    env.hup()
    check(answers(env.q("plain.test", "A"), "A") == [REAL_B], "plain.test after restore")
    check(answers(env.q("warp.test", "A"), "A") == [fake], "same fake after restore")


@test
def router_originated_output_hook(env):
    fake = answers(env.q("warp.test", "A"), "A")[0]
    before = env.counters()
    out = env.connect(fake, router=True)
    check(out == "hello from " + REAL_A, "router-originated connect via fake: %r" % out)
    after = env.counters()
    check(after[0] > before[0], "mark not set on output path: %r -> %r" % (before, after))


@test
def v6_pool_via_reload(env):
    cfg = CONFIG.replace("option fakeip_v4 '198.18.0.0/15'",
                         "option fakeip_v4 '198.18.0.0/15'\n\toption fakeip_v6 'fd00:198:18::/64'")
    cfg = cfg.replace("list listen_addr '{lan}'", "list listen_addr '{lan}'\n\tlist listen_addr '%s'" % LAN6)
    env.write_config(cfg)
    env.hup()
    check("reloaded" in env.daemon_log().splitlines()[-1], "v6 reload failed:\n" + env.daemon_log()[-800:])
    r = env.q("warp.test", "AAAA")
    ips = answers(r, "AAAA")
    check(len(ips) == 1 and ips[0].startswith("fd00:198:18:"), "no v6 fake: %r" % r)
    check(env.nft_map("fake2real_v6").get(ips[0]) == REAL6, "fake2real_v6 missing")
    out = env.connect(ips[0])
    check(out == "hello from " + REAL6, "connect via v6 fake: %r" % out)
    p = env.q("svc.warp.test", "HTTPS")["an"][0]["data"]["params"]
    check(p.get("ipv6hint") and all(h.startswith("fd00:198:18:") for h in p["ipv6hint"]),
          "ipv6hint not rewritten: %r" % p)
    # v6 transport to the daemon
    r = dnsmini.query(LAN6, 53, "plain.test", "A")
    check(answers(r, "A") == [REAL_B], "query over v6 transport")
    env.write_config(CONFIG)
    env.hup()
    check("rejected" in env.daemon_log().splitlines()[-1],
          "removing the v6 pool with live v6 bindings must be rejected")


@test
def mark_chain_overflow_rejects_reload(env):
    """Mark chains are kept across reloads; past their cap a reload must be
    rejected (clearly, keeping the previous configuration), never drop a
    chain that live bindings still jump to."""
    table, port, nrules = TABLE + "m", 5399, 1000
    d = env.dir + "/marks"
    os.makedirs(d, exist_ok=True)
    with open(d + "/none.txt", "w") as f:
        f.write("*.none.test\n")

    def config(k):
        rules = "".join("config rule 'r%d'\n\toption action 'fakeip'\n"
                        "\toption upstream '%s/cf.conf'\n\toption fwmark '%d'\n"
                        "\tlist nameset '%s/%s'\n\n"
                        % (i, env.dir, k * nrules + i + 1, d if i < nrules - 1 else env.dir,
                           "none.txt" if i < nrules - 1 else "warp.txt")
                        for i in range(nrules))
        with open(d + "/omnidns", "w") as f:
            f.write("config omnidns 'main'\n\toption port '%d'\n\tlist listen_addr '%s'\n"
                    "\toption fwmask '0x00ffffff'\n\toption fakeip_v4 '100.64.0.0/16'\n\n"
                    "%sconfig rule 'catchall'\n\toption action 'forward'\n"
                    "\toption upstream '%s/isp.conf'\n" % (port, LAN, rules, env.dir))

    def log():
        with open(d + "/daemon.log") as f:
            return f.read()

    def hup():
        n = len(log())
        p.send_signal(signal.SIGHUP)
        for _ in range(100):
            new = log()[n:]
            if "reloaded" in new or "keeping previous" in new:
                return new
            time.sleep(0.1)
        raise AssertionError("reload did not finish:\n" + log()[-800:])

    config(0)
    lf = open(d + "/daemon.log", "a")
    p = subprocess.Popen([env.binary, "-f", "-t", table, "-x", "-c", d + "/omnidns"],
                         stdout=lf, stderr=lf)
    try:
        for _ in range(100):
            try:
                r = dnsmini.query(LAN, port, "warp.test", "A", timeout=0.2)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("second daemon did not come up:\n" + log()[-800:])
        fake = answers(r, "A")[0]
        check(fake.startswith("100.64."), "no fake: %r" % r)
        mark = "mark_%08x" % nrules  # rule r999 of config 0, installed last
        # a reload adds 1000 new mark chains and keeps the old ones
        config(1)
        out = hup()
        check("reloaded" in out, "reload failed:\n" + out)
        config(2)  # would need 3000 mark chains (the cap is 2048)
        out = hup()
        check("fwmark chains needed" in out, "overflow not reported:\n" + out)
        check("reloaded" not in out, "overflowing reload accepted:\n" + out)
        elems = sh("nft list map inet %s fake2mark_v4" % table)
        check(fake in elems and mark in elems, "binding lost:\n" + elems)
        check(mark in sh("nft list chain inet %s %s" % (table, mark)), "mark chain deleted")
        # config 1 still in force: a new name binds with its mark
        fake2 = answers(dnsmini.query(LAN, port, "inner.warp.test", "A"), "A")[0]
        elems = sh("nft list map inet %s fake2mark_v4" % table)
        check("%s : jump mark_%08x" % (fake2, 2 * nrules) in elems,
              "previous configuration not kept:\n" + elems)
        # a config within the kept chains still reloads
        config(0)
        out = hup()
        check("reloaded" in out, "reload after overflow failed:\n" + out)
    finally:
        p.terminate()
        p.wait(10)


def enter_netns():
    """Re-exec the running script under `unshare -rn` (once)."""
    if os.environ.get("OMNI_INTEG_NS") != "1":
        os.environ["OMNI_INTEG_NS"] = "1"
        os.execvp("unshare", ["unshare", "-rn", sys.executable] + sys.argv)


def binary_arg(default="build/host/omnidns"):
    return os.path.abspath(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-")
                           else os.path.join(ROOT, default))


def main():
    enter_netns()
    binary = binary_arg()
    only = sys.argv[sys.argv.index("-k") + 1] if "-k" in sys.argv else None
    env = Env(binary)
    try:
        env.netns()
        env.files()
        env.upstreams()
        env.services()
        env.start_daemon()
        for t in tests:
            if only and only not in t.__name__:
                continue
            try:
                t(env)
                print("ok   %s" % t.__name__)
            except Exception as e:
                failures.append(t.__name__)
                print("FAIL %s: %s" % (t.__name__, e))
                if not isinstance(e, AssertionError):
                    traceback.print_exc()
            if env.daemon.poll() is not None:
                print("daemon exited (%s)" % env.daemon.returncode)
                break
    finally:
        env.teardown()
        print("--- daemon log (tail) ---")
        print(env.daemon_log()[-4000:] if env.daemon else "")
    print("%d failed" % len(failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
