#!/usr/bin/env python3
"""Minimal stdlib-only DNS toolkit for omnidns tests.

Library:
    build_query(name, qtype, id=None, edns=True, do=False) -> bytes
    parse_msg(bytes) -> dict(id, flags, rcode, tc, question, an, ns, ar, edns)
        each RR: dict(name, type, ttl, data) with data decoded for
        A/AAAA (str), CNAME/DNAME/PTR/NS (name str), SOA (tuple),
        SVCB/HTTPS (dict(prio, target, params{key: value})), else hex
    query(server, port, name, qtype, tcp=False, timeout=2.0, **kw) -> dict

Fake upstream server (acts like a recursive resolver over a static zone):
    python3 dnsmini.py serve --addr 127.0.0.1 --port 5301 --zone zone.json \
        [--log queries.jsonl]

zone.json:
    {"records": [["www.example.com", "CNAME", 300, "cdn.example.net"],
                 ["cdn.example.net", "A", 60, "192.0.2.1"],
                 ["svc.example.com", "HTTPS", 300,
                  "1 . alpn=h2 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1"],
                 ["example.org", "DNAME", 300, "example.net"]],
     "behaviors": {"tc.example.com": "tc",       # UDP answers truncated
                   "slow.example.com": "delay:3",  # seconds
                   "drop.example.com": "drop",
                   "fail.example.com": "servfail",
                   "refuse.example.com": "refused"},
     "chase": true}   # follow CNAME/DNAME chains inside the zone (default true)

Each received query is appended to --log as a JSON line
{"name":..., "type":..., "proto": "udp"|"tcp"}.
"""
import argparse
import base64
import ipaddress
import json
import random
import socket
import socketserver
import struct
import sys
import threading
import time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
         "AAAA": 28, "SRV": 33, "DNAME": 39, "OPT": 41, "RRSIG": 46, "NSEC": 47,
         "SVCB": 64, "HTTPS": 65, "ANY": 255, "AXFR": 252}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
SVC_KEYS = {"mandatory": 0, "alpn": 1, "no-default-alpn": 2, "port": 3,
            "ipv4hint": 4, "ech": 5, "ipv6hint": 6}
SVC_KEY_NAMES = {v: k for k, v in SVC_KEYS.items()}


def tnum(t):
    if isinstance(t, int):
        return t
    if t.upper().startswith("TYPE"):
        return int(t[4:])
    return TYPES[t.upper()]


def tname(n):
    return TYPE_NAMES.get(n, "TYPE%d" % n)


# ---------------------------------------------------------------- encoding

def enc_name(name):
    name = name.rstrip(".")
    out = b""
    if name:
        for label in name.split("."):
            lb = label.encode()
            assert 0 < len(lb) < 64, name
            out += bytes([len(lb)]) + lb
    return out + b"\0"


def enc_svcb(text):
    parts = text.split()
    prio = int(parts[0])
    out = struct.pack("!H", prio) + enc_name(parts[1])
    params = []
    for p in parts[2:]:
        k, _, v = p.partition("=")
        if k in SVC_KEYS:
            key = SVC_KEYS[k]
        elif k.startswith("key"):
            key = int(k[3:])
        else:
            raise ValueError(k)
        if k == "alpn":
            val = b"".join(bytes([len(x)]) + x.encode() for x in v.split(","))
        elif k == "port":
            val = struct.pack("!H", int(v))
        elif k == "ipv4hint":
            val = b"".join(ipaddress.IPv4Address(x).packed for x in v.split(","))
        elif k == "ipv6hint":
            val = b"".join(ipaddress.IPv6Address(x).packed for x in v.split(","))
        elif k == "ech":
            val = base64.b64decode(v)
        elif k == "mandatory":
            val = b"".join(struct.pack("!H", SVC_KEYS[x]) for x in v.split(","))
        elif k == "no-default-alpn":
            val = b""
        else:
            val = bytes.fromhex(v)
        params.append((key, val))
    for key, val in sorted(params):
        out += struct.pack("!HH", key, len(val)) + val
    return out


def enc_rdata(rtype, data):
    if rtype == 1:
        return ipaddress.IPv4Address(data).packed
    if rtype == 28:
        return ipaddress.IPv6Address(data).packed
    if rtype in (2, 5, 12, 39):
        return enc_name(data)
    if rtype == 6:
        mname, rname, serial, refresh, retry, expire, minimum = data.split()
        return enc_name(mname) + enc_name(rname) + struct.pack(
            "!IIIII", int(serial), int(refresh), int(retry), int(expire), int(minimum))
    if rtype == 15:
        pref, exch = data.split()
        return struct.pack("!H", int(pref)) + enc_name(exch)
    if rtype == 16:
        b = data.encode()
        return bytes([len(b)]) + b
    if rtype in (64, 65):
        return enc_svcb(data)
    return bytes.fromhex(data)


def enc_rr(name, rtype, ttl, rdata, cls=1):
    return enc_name(name) + struct.pack("!HHIH", rtype, cls, ttl, len(rdata)) + rdata


def build_query(name, qtype, id=None, edns=True, do=False, rd=True, udp_size=1232):
    id = random.randrange(65536) if id is None else id
    flags = 0x0100 if rd else 0
    msg = struct.pack("!HHHHHH", id, flags, 1, 0, 0, 1 if edns else 0)
    msg += enc_name(name) + struct.pack("!HH", tnum(qtype), 1)
    if edns:
        msg += b"\0" + struct.pack("!HHIH", 41, udp_size, 0x8000 if do else 0, 0)
    return msg


# ---------------------------------------------------------------- decoding

def dec_name(msg, off):
    labels, jumps, end = [], 0, None
    while True:
        ln = msg[off]
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if end is None:
                end = off + 2
            off = ptr
            jumps += 1
            if jumps > 32:
                raise ValueError("pointer loop")
            continue
        off += 1
        if ln == 0:
            break
        labels.append(msg[off:off + ln].decode("ascii", "backslashreplace"))
        off += ln
    return ".".join(labels), (end if end is not None else off)


def dec_svcb(rd):
    prio = struct.unpack("!H", rd[:2])[0]
    target, off = dec_name(rd, 2)
    params = {}
    while off < len(rd):
        key, ln = struct.unpack("!HH", rd[off:off + 4])
        val = rd[off + 4:off + 4 + ln]
        off += 4 + ln
        name = SVC_KEY_NAMES.get(key, "key%d" % key)
        if key == 4:
            val = [str(ipaddress.IPv4Address(val[i:i + 4])) for i in range(0, len(val), 4)]
        elif key == 6:
            val = [str(ipaddress.IPv6Address(val[i:i + 16])) for i in range(0, len(val), 16)]
        elif key == 1:
            out, i = [], 0
            while i < len(val):
                out.append(val[i + 1:i + 1 + val[i]].decode())
                i += 1 + val[i]
            val = out
        elif key == 3:
            val = struct.unpack("!H", val)[0]
        else:
            val = val.hex()
        params[name] = val
    return {"prio": prio, "target": target or ".", "params": params}


def dec_rdata(msg, rtype, off, rdlen):
    rd = msg[off:off + rdlen]
    if rtype == 1:
        return str(ipaddress.IPv4Address(rd))
    if rtype == 28:
        return str(ipaddress.IPv6Address(rd))
    if rtype in (2, 5, 12, 39):
        return dec_name(msg, off)[0]
    if rtype == 6:
        m, o = dec_name(msg, off)
        r, o = dec_name(msg, o)
        return (m, r) + struct.unpack("!IIIII", msg[o:o + 20])
    if rtype in (64, 65):
        return dec_svcb(rd)
    return rd.hex()


def parse_msg(msg):
    id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    off = 12
    res = {"id": id, "flags": flags, "rcode": flags & 0xF, "tc": bool(flags & 0x200),
           "aa": bool(flags & 0x400), "ad": bool(flags & 0x20),
           "question": None, "an": [], "ns": [], "ar": [], "edns": None}
    for _ in range(qd):
        name, off = dec_name(msg, off)
        qt, qc = struct.unpack("!HH", msg[off:off + 4])
        off += 4
        res["question"] = (name, tname(qt), qc)
    for sec, cnt in (("an", an), ("ns", ns), ("ar", ar)):
        for _ in range(cnt):
            name, off = dec_name(msg, off)
            rtype, cls, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            off += 10
            if rtype == 41:
                res["edns"] = {"udp_size": cls, "ext_rcode": ttl >> 24,
                               "version": (ttl >> 16) & 0xFF, "do": bool(ttl & 0x8000)}
                res["rcode"] |= (ttl >> 24) << 4
            else:
                res[sec].append({"name": name, "type": tname(rtype), "ttl": ttl,
                                 "data": dec_rdata(msg, rtype, off, rdlen)})
            off += rdlen
    return res


def query(server, port, name, qtype, tcp=False, timeout=2.0, raw=None, **kw):
    msg = raw if raw is not None else build_query(name, qtype, **kw)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    if tcp:
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((server, port))
            s.sendall(struct.pack("!H", len(msg)) + msg)
            ln = struct.unpack("!H", recv_exact(s, 2))[0]
            return parse_msg(recv_exact(s, ln))
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(msg, (server, port))
        while True:
            data, _ = s.recvfrom(65535)
            if data[:2] == msg[:2]:
                return parse_msg(data)


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


# ---------------------------------------------------------------- fake upstream

class Zone:
    def __init__(self, spec):
        self.rrs = {}
        self.names = set()
        for name, t, ttl, data in spec.get("records", []):
            name = name.rstrip(".").lower()
            self.rrs.setdefault((name, tnum(t)), []).append((ttl, data))
            parts = name.split(".")
            for i in range(len(parts)):
                self.names.add(".".join(parts[i:]))
        self.behaviors = {k.rstrip(".").lower(): v for k, v in spec.get("behaviors", {}).items()}
        self.chase = spec.get("chase", True)

    def find_dname(self, name):
        parts = name.split(".")
        for i in range(1, len(parts)):
            owner = ".".join(parts[i:])
            if (owner, 39) in self.rrs:
                return owner, self.rrs[(owner, 39)][0]
        return None

    def answer(self, qname, qtype):
        """Returns (rcode, answer rrs as bytes list, authority list)."""
        an, name, seen = [], qname.lower(), set()
        for _ in range(16):
            if name in seen:
                break
            seen.add(name)
            if (name, qtype) in self.rrs:
                for ttl, data in self.rrs[(name, qtype)]:
                    an.append(enc_rr(name, qtype, ttl, enc_rdata(qtype, data)))
                return 0, an, []
            if (name, 5) in self.rrs and qtype != 5:
                ttl, target = self.rrs[(name, 5)][0]
                an.append(enc_rr(name, 5, ttl, enc_rdata(5, target)))
                if not self.chase:
                    return 0, an, []
                name = target.rstrip(".").lower()
                continue
            d = self.find_dname(name)
            if d and qtype != 39:
                owner, (ttl, target) = d
                an.append(enc_rr(owner, 39, ttl, enc_rdata(39, target)))
                new = name[: -len(owner)] + target.rstrip(".").lower()
                an.append(enc_rr(name, 5, ttl, enc_rdata(5, new)))
                if not self.chase:
                    return 0, an, []
                name = new
                continue
            soa = enc_rr(name.split(".", 1)[-1] or name, 6, 300,
                         enc_rdata(6, "ns.test. host.test. 1 3600 600 86400 60"))
            rcode = 0 if (name in self.names or an) else 3
            return rcode, an, [soa]
        return 2, [], []


class Handler:
    zone = None
    log = None
    lock = threading.Lock()

    @classmethod
    def handle(cls, data, proto):
        try:
            q = parse_msg(data)
        except Exception:
            return None
        if not q["question"]:
            return None
        qname, qt, _ = q["question"]
        qtype = tnum(qt)
        if cls.log:
            with cls.lock, open(cls.log, "a") as f:
                f.write(json.dumps({"name": qname, "type": qt, "proto": proto}) + "\n")
        beh = cls.zone.behaviors.get(qname.lower(), "")
        if beh == "drop":
            return None
        if beh.startswith("delay:"):
            time.sleep(float(beh.split(":")[1]))
        rcode, an, ns = 0, [], []
        if beh == "servfail":
            rcode = 2
        elif beh == "refused":
            rcode = 5
        else:
            rcode, an, ns = cls.zone.answer(qname, qtype)
        flags = 0x8000 | 0x0080 | (q["flags"] & 0x0100) | rcode
        tc = beh == "tc" and proto == "udp"
        if tc:
            flags |= 0x0200
            an, ns = [], []
        qsec = enc_name(qname) + struct.pack("!HH", qtype, 1)
        out = struct.pack("!HHHHHH", q["id"], flags, 1, len(an), len(ns), 0) + qsec
        return out + b"".join(an) + b"".join(ns)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        resp = Handler.handle(data, "udp")
        if resp is not None:
            sock.sendto(resp, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                ln = struct.unpack("!H", recv_exact(self.request, 2))[0]
                resp = Handler.handle(recv_exact(self.request, ln), "tcp")
                if resp is not None:
                    self.request.sendall(struct.pack("!H", len(resp)) + resp)
        except (ConnectionError, OSError):
            pass


def serve(addr, port, zone, log):
    Handler.zone = zone
    Handler.log = log
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET

    class U(socketserver.ThreadingUDPServer):
        address_family = fam
        allow_reuse_address = True
        daemon_threads = True

    class T(socketserver.ThreadingTCPServer):
        address_family = fam
        allow_reuse_address = True
        daemon_threads = True

    u = U((addr, port), UDPHandler)
    t = T((addr, port), TCPHandler)
    threading.Thread(target=t.serve_forever, daemon=True).start()
    print("ready", flush=True)
    u.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--addr", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5301)
    s.add_argument("--zone", required=True)
    s.add_argument("--log")
    q = sub.add_parser("query")
    q.add_argument("server")
    q.add_argument("port", type=int)
    q.add_argument("name")
    q.add_argument("qtype")
    q.add_argument("--tcp", action="store_true")
    a = ap.parse_args()
    if a.cmd == "serve":
        with open(a.zone) as f:
            serve(a.addr, a.port, Zone(json.load(f)), a.log)
    else:
        print(json.dumps(query(a.server, a.port, a.name, a.qtype, tcp=a.tcp), indent=1))


if __name__ == "__main__":
    main()
