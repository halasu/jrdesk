#!/usr/bin/env python3
"""JRDesk server log shipper (v1)

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
                if is_dup(ev):
                    continue
                send(ev)
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


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    if not CFG["dry"] and (not CFG["url"] or not CFG["secret"]):
        sys.exit("N8N_WEBHOOK_URL and N8N_SECRET are required (or DRY_RUN=1)")
    threads = [
        threading.Thread(target=follow, args=(os.environ.get("HBBS_CONTAINER", "rustdesk-hbbs"), "hbbs"), daemon=True),
        threading.Thread(target=follow, args=(os.environ.get("HBBR_CONTAINER", "rustdesk-hbbr"), "hbbr"), daemon=True),
    ]
    for t in threads:
        t.start()
    print("jrdesk-log-shipper started", flush=True)
    while True:
        time.sleep(3600)
