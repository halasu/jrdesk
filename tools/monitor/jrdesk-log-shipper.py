#!/usr/bin/env python3
"""JRDesk server log shipper (v1.1 - auto IP block)

Follows `docker logs -f` of rustdesk-hbbs / rustdesk-hbbr, extracts security
events and POSTs them as JSON to an n8n webhook.

Events
  invalid_key        hbbs/hbbr: client without our server key tried to use the server
  connect_attempt    hbbs (debug): IP X requested a connection to device ID Y
  relay_start        hbbr: relay session paired (traffic goes through our server)
  relay_end          hbbr: relay session closed

Requires hbbs started with RUST_LOG=info,hbbs::rendezvous_server=debug
for connect_attempt events. Python 3.8+ stdlib only.

Config (environment, e.g. /etc/jrdesk-monitor.env)
  N8N_WEBHOOK_URL   required  e.g. http://127.0.0.1:5678/webhook/jrdesk-events
  N8N_SECRET        required  shared secret, sent as header X-JRDesk-Secret
  DEDUP_SECONDS     optional  suppress identical events within N s (default 60)
  HBBS_CONTAINER    optional  default rustdesk-hbbs
  HBBR_CONTAINER    optional  default rustdesk-hbbr
  DRY_RUN=1         optional  print events instead of POSTing
  BLOCK_ENABLED     optional  1 = auto-block (default 1)
  BLOCK_THRESHOLD   optional  invalid_key events per IP within window (default 10)
  BLOCK_WINDOW_SEC  optional  counting window (default 86400 = 24h)
  BLOCK_TTL_SEC     optional  block duration, auto-expires (default 604800 = 7d)
  ALLOWLIST         optional  comma-separated IPs never blocked

Auto-block uses nftables: table inet jrdesk, sets block4/block6 (with timeout),
dropping TCP 21115-21119 and UDP 21116 from blocked IPs (hbbs + hbbr).
CLI:  --selftest | --test-block | --unblock <ip> | --list
"""
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# SocketAddr display: 1.2.3.4:5 or [::ffff:1.2.3.4]:5 (port always present)
IP = r"\[?(?:::ffff:)?(?P<ip>[0-9a-fA-F.:]+?)\]?:(?P<port>\d+)\b"

PATTERNS = [
    # hbbs
    ("invalid_key", "hbbs",
     re.compile(r"Authentication failed from " + IP + r" for peer (?P<id>\S+) - invalid key")),
    ("connect_attempt", "hbbs",
     re.compile(r'Punch hole "(?P<id>[^"]+)" (?P<peer>\S+) request from ' + IP)),
    ("connect_attempt", "hbbs",
     re.compile(r'Fetch local addr "(?P<id>[^"]+)" (?P<peer>\S+) request from ' + IP)),
    # hbbr
    ("invalid_key", "hbbr",
     re.compile(r"Relay authentication failed from " + IP + r" - invalid key")),
    ("relay_start", "hbbr",
     re.compile(r"Relayrequest (?P<uuid>\S+) from " + IP + r" got paired")),
    ("relay_end", "hbbr",
     re.compile(r"Relay of " + IP + r" closed")),
]

CFG = {
    "url": os.environ.get("N8N_WEBHOOK_URL", ""),
    "secret": os.environ.get("N8N_SECRET", ""),
    "dedup": int(os.environ.get("DEDUP_SECONDS", "60")),
    "dry": os.environ.get("DRY_RUN") == "1",
}
BLOCK = {
    "enabled": os.environ.get("BLOCK_ENABLED", "1") == "1",
    "threshold": int(os.environ.get("BLOCK_THRESHOLD", "10")),
    "window": int(os.environ.get("BLOCK_WINDOW_SEC", "86400")),
    "ttl": int(os.environ.get("BLOCK_TTL_SEC", "604800")),
    "allow": {x.strip() for x in os.environ.get("ALLOWLIST", "").split(",") if x.strip()},
}
NFT_SETUP = """
table inet jrdesk {
  set block4 { type ipv4_addr; flags timeout; }
  set block6 { type ipv6_addr; flags timeout; }
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr @block4 tcp dport 21115-21119 drop
    ip saddr @block4 udp dport 21116 drop
    ip6 saddr @block6 tcp dport 21115-21119 drop
    ip6 saddr @block6 udp dport 21116 drop
  }
}
"""
_hits = {}      # ip -> [timestamps] of invalid_key
_blocked = {}   # ip -> expiry ts (local view)
_seen = {}
_relay_started = {}  # ip:port -> start ts
_lock = threading.Lock()


def parse(line, source):
    line = ANSI.sub("", line).strip()
    for etype, src, rx in PATTERNS:
        if src != source:
            continue
        m = rx.search(line)
        if not m:
            continue
        g = m.groupdict()
        ev = {
            "type": etype,
            "source": source,
            "ip": (g.get("ip") or "").strip("[]"),
            "port": g.get("port"),
            "device_id": g.get("id"),
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "raw": line[-300:],
        }
        if g.get("uuid"):
            ev["session"] = g["uuid"]
        return ev
    return None


def enrich_relay(ev):
    key = "%s:%s" % (ev["ip"], ev.get("port"))
    now = time.time()
    with _lock:
        if ev["type"] == "relay_start":
            _relay_started[key] = now
        elif ev["type"] == "relay_end":
            st = _relay_started.pop(key, None)
            if st is None:
                return None  # end of an unpaired/unknown socket -> noise
            ev["duration_sec"] = int(now - st)
    return ev


def is_dup(ev):
    key = (ev["type"], ev["ip"], ev.get("device_id"))
    now = time.time()
    with _lock:
        last = _seen.get(key)
        _seen[key] = now
        if len(_seen) > 5000:
            for k in [k for k, t in _seen.items() if now - t > 3600]:
                _seen.pop(k, None)
    return last is not None and now - last < CFG["dedup"] and ev["type"] in ("connect_attempt", "invalid_key")


def _nft(args, stdin=None):
    return subprocess.run(["nft"] + args, input=stdin, text=True,
                          capture_output=True, timeout=10)


def nft_ensure():
    r = _nft(["list", "table", "inet", "jrdesk"])
    if r.returncode == 0:
        return True
    r = _nft(["-f", "-"], stdin=NFT_SETUP)
    if r.returncode != 0:
        print("nft setup failed: %s" % r.stderr.strip(), file=sys.stderr, flush=True)
        return False
    return True


def is_protected(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (ip in BLOCK["allow"] or a.is_private or a.is_loopback or a.is_link_local
            or a.is_multicast or a.is_unspecified or a.is_reserved)


def nft_block(ip, ttl):
    setname = "block6" if ":" in ip else "block4"
    if not nft_ensure():
        return False
    r = _nft(["add", "element", "inet", "jrdesk", setname,
              "{ %s timeout %ds }" % (ip, ttl)])
    if r.returncode != 0:
        print("nft block %s failed: %s" % (ip, r.stderr.strip()), file=sys.stderr, flush=True)
        return False
    return True


def nft_unblock(ip):
    setname = "block6" if ":" in ip else "block4"
    return _nft(["delete", "element", "inet", "jrdesk", setname, "{ %s }" % ip]).returncode == 0


def maybe_block(ev):
    """Count invalid_key per IP (before dedup); block when threshold reached."""
    if not BLOCK["enabled"] or ev["type"] != "invalid_key":
        return None
    ip, now = ev["ip"], time.time()
    if is_protected(ip):
        return None
    with _lock:
        if _blocked.get(ip, 0) > now:
            return None
        hits = [t for t in _hits.get(ip, []) if now - t <= BLOCK["window"]]
        hits.append(now)
        _hits[ip] = hits
        if len(hits) < BLOCK["threshold"]:
            return None
        _blocked[ip] = now + BLOCK["ttl"]
        _hits.pop(ip, None)
        count = len(hits)
    ok = nft_block(ip, BLOCK["ttl"])
    return {
        "type": "blocked" if ok else "block_failed",
        "source": "monitor",
        "ip": ip,
        "port": None,
        "device_id": None,
        "count": count,
        "window_sec": BLOCK["window"],
        "ttl_sec": BLOCK["ttl"],
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def send(ev):
    if CFG["dry"]:
        print(json.dumps(ev, ensure_ascii=False), flush=True)
        return
    data = json.dumps(ev).encode()
    req = urllib.request.Request(CFG["url"], data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "X-JRDesk-Secret": CFG["secret"]})
    for attempt in range(3):
        try:
            urllib.request.urlopen(req, timeout=10).read()
            return
        except Exception as e:  # noqa
            print("send failed (%s): %s" % (attempt + 1, e), file=sys.stderr, flush=True)
            time.sleep(2 * (attempt + 1))


def follow(container, source):
    while True:
        try:
            p = subprocess.Popen(["docker", "logs", "-f", "--since", "1s", container],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1)
            for line in p.stdout:
                ev = parse(line, source)
                if not ev:
                    continue
                if ev["type"] in ("relay_start", "relay_end"):
                    ev = enrich_relay(ev)
                    if not ev:
                        continue
                bev = maybe_block(ev)
                if not is_dup(ev):
                    send(ev)
                if bev:
                    send(bev)
            p.wait()
        except Exception as e:  # noqa
            print("follow %s error: %s" % (container, e), file=sys.stderr, flush=True)
        time.sleep(5)  # container restarted -> re-attach


def selftest():
    samples = [
        ("hbbs", "[2026-11-15 16:03:47 +00:00] WARN [src/rendezvous_server.rs:683] Authentication failed from 1.2.3.4:5555 for peer 123456789 - invalid key"),
        ("hbbs", '[2026-11-15 16:03:47 +00:00] DEBUG [src/rendezvous_server.rs:761] Punch hole "987654321" 10.0.0.2:21116 request from 5.6.7.8:40000'),
        ("hbbr", "[2026-11-15 16:03:47 +00:00] INFO [src/relay_server.rs:437] Relayrequest 0f1e-uuid from 5.6.7.8:40001 got paired"),
        ("hbbr", "[2026-11-15 16:03:49 +00:00] INFO [src/relay_server.rs:449] Relay of 5.6.7.8:40001 closed"),
        ("hbbr", "[2026-11-15 16:03:47 +00:00] WARN [src/relay_server.rs:431] Relay authentication failed from 9.9.9.9:1 - invalid key"),
        ("hbbs", "[2026-11-15 16:03:47 +00:00] DEBUG [src/rendezvous_server.rs:1135] Tcp connection from 1.1.1.1:2, ws: false"),
    ]
    out = []
    for src, line in samples:
        ev = parse(line, src)
        if ev and ev["type"] in ("relay_start", "relay_end"):
            ev = enrich_relay(ev)
        out.append(ev and {k: ev[k] for k in ("type", "ip", "device_id") if k in ev} | ({"duration_sec": ev["duration_sec"]} if ev and "duration_sec" in ev else {}))
    for o in out:
        print(o)
    assert [o and o["type"] for o in out] == ["invalid_key", "connect_attempt", "relay_start", "relay_end", "invalid_key", None]
    assert out[1]["device_id"] == "987654321" and out[1]["ip"] == "5.6.7.8"
    print("selftest OK")


def selftest_block():
    BLOCK.update(threshold=3, window=60, ttl=60, allow={"198.51.100.7"})
    calls = []
    global nft_block
    real = nft_block
    nft_block = lambda ip, ttl: calls.append((ip, ttl)) or True  # noqa: E731
    try:
        mk = lambda ip: {"type": "invalid_key", "ip": ip}  # noqa: E731
        r = [maybe_block(mk("8.8.8.8")) for _ in range(3)]
        assert r[0] is None and r[1] is None and r[2]["type"] == "blocked" and r[2]["count"] == 3
        assert maybe_block(mk("8.8.8.8")) is None                    # already blocked
        assert all(maybe_block(mk("198.51.100.7")) is None for _ in range(5))  # allowlist
        assert all(maybe_block(mk("10.0.0.5")) is None for _ in range(5))      # private
        assert maybe_block({"type": "connect_attempt", "ip": "1.1.1.1"}) is None
        assert calls == [("8.8.8.8", 60)]
    finally:
        nft_block = real
    print("block selftest OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        selftest_block()
        sys.exit(0)
    if "--list" in sys.argv:
        print(_nft(["list", "table", "inet", "jrdesk"]).stdout or "(no table)")
        sys.exit(0)
    if "--unblock" in sys.argv:
        ip = sys.argv[sys.argv.index("--unblock") + 1]
        print("unblocked" if nft_unblock(ip) else "not found")
        sys.exit(0)
    if "--test-block" in sys.argv:
        # TEST-NET-3 address, 120 s timeout: verifies nft + n8n notification path
        test_ip = "203.0.113.250"
        ok = nft_block(test_ip, 120)
        ev = {"type": "blocked" if ok else "block_failed", "source": "test", "ip": test_ip,
              "count": 0, "window_sec": 0, "ttl_sec": 120,
              "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        send(ev)
        print(_nft(["list", "set", "inet", "jrdesk", "block4"]).stdout)
        sys.exit(0 if ok else 1)
    if not CFG["dry"] and (not CFG["url"] or not CFG["secret"]):
        sys.exit("N8N_WEBHOOK_URL and N8N_SECRET are required (or DRY_RUN=1)")
    threads = [
        threading.Thread(target=follow, args=(os.environ.get("HBBS_CONTAINER", "rustdesk-hbbs"), "hbbs"), daemon=True),
        threading.Thread(target=follow, args=(os.environ.get("HBBR_CONTAINER", "rustdesk-hbbr"), "hbbr"), daemon=True),
    ]
    if BLOCK["enabled"]:
        print("nft ready" if nft_ensure() else "nft NOT ready (auto-block disabled in effect)", flush=True)
    for t in threads:
        t.start()
    print("jrdesk-log-shipper v1.1 started (block=%s threshold=%d/%ds ttl=%ds)" % (
        BLOCK["enabled"], BLOCK["threshold"], BLOCK["window"], BLOCK["ttl"]), flush=True)
    while True:
        time.sleep(3600)
