#!/usr/bin/env python3
"""Same-day loan-applicant extractor (requires admin_token.json).

Pulls, for TODAY (arg: YYYYMMDD, default today):
  1. members?adminMemberSearchType=LIMIT_DT   -> credit-checked today (=applied)
  2. members?adminMemberSearchType=JOIN_DT    -> joined today
  3. limit/list                               -> credit-check records
  4. loan/list                                -> executed loans
Outputs same_day_applicants.csv + same_day_raw/*.json.
Date format tries YYYYMMDD then YYYY-MM-DD per endpoint.
"""
import csv
import json
import os
import ssl
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443/bigyo/admin-api"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126 Safari/537.36"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

DAY = os.sys.argv[1] if len(os.sys.argv) > 1 else time.strftime("%Y%m%d")
RAW_DIR = os.path.join(HERE, "same_day_raw")
os.makedirs(RAW_DIR, exist_ok=True)


def token():
    p = os.path.join(HERE, "admin_token.json")
    if not os.path.exists(p):
        return None
    creds = json.load(open(p))[0]["data"]
    return creds.get("token") or creds.get("accessToken")


def get(tok, path, params):
    qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
    url = f"{BASE}{path}" + ("?" + qs if qs else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=CTX) as r:
            return json.loads(r.read().decode("utf-8", "replace")), None
    except Exception as e:
        return None, str(e)[:200]


def rows_of(payload):
    """Extract a list of records from DataResponse wrappers."""
    if payload is None:
        return []
    d = payload.get("data") if isinstance(payload, dict) else payload
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        for k in ("list", "records", "rows", "content", "items"):
            if isinstance(d.get(k), list):
                return d[k]
    return []


def save_raw(name, payload):
    with open(os.path.join(RAW_DIR, name + ".json"), "w") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)


FLAT = [
    ("name", "name"), ("mobile", "mobile"), ("mobileEnc", "mobileEnc"),
    ("memberNo", "memberNo"), ("memberSeq", "memberSeq"),
    ("joinDt", "joinDt"), ("limitDt", "limitDt"), ("loExDt", "loExDt"),
    ("lastAccessDay", "lastAccessDay"), ("lastAccessDt", "lastAccessDt"),
    ("age", "age"), ("gender", "gender"), ("birthday", "birthday"),
    ("joinChannel", "joinChannel"), ("joinPath", "joinPath"),
    ("bankName", "bankName"), ("productName", "productName"),
    ("loReqAmt", "loReqAmt"), ("interestRateBf", "interestRateBf"),
    ("loReqtNo", "loReqtNo"), ("jonCls", "jonCls"), ("aplyDt", "aplyDt"),
    ("imgLinkUrl", "imgLinkUrl"), ("resultCode", "resultCode"),
    ("rstStCd", "rstStCd"), ("rstDt", "rstDt"), ("loanType", "loanType"),
    ("requestDt", "requestDt"),
]


def main():
    tok = token()
    if not tok:
        print("no admin token yet")
        return
    fmts = [DAY, DAY[:4] + "-" + DAY[4:6] + "-" + DAY[6:]]
    out_csv = os.path.join(HERE, "same_day_applicants.csv")
    header_written = not os.path.exists(out_csv)
    nfld = [f for f, _ in FLAT] + ["source"]
    total = 0
    jobs = [
        ("members_limit_dt", "/members",
         {"adminMemberSearchType": "LIMIT_DT"}),
        ("members_join_dt", "/members",
         {"adminMemberSearchType": "JOIN_DT"}),
        ("limit_list", "/limit/list", {}),
        ("loan_list", "/loan/list", {}),
    ]
    for fname, path, base_params in jobs:
        payload, err = None, None
        for dfmt in fmts:
            params = dict(base_params)
            if "searchStrtDt" in base_params or "members" in path:
                params["searchStrtDt"] = dfmt
                params["searchEndDt"] = dfmt
            else:
                params["start"] = dfmt
                params["end"] = dfmt
            payload, err = get(tok, path, params)
            if payload is not None:
                break
        save_raw(fname, payload if payload is not None else {"error": err})
        rows = rows_of(payload)
        print(f"{fname}: {len(rows)} rows (fmt={dfmt})", flush=True)
        with open(out_csv, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=nfld, extrasaction="ignore")
            if header_written:
                w.writeheader()
                header_written = False
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rec = {dst: r.get(src, "") for src, dst in FLAT}
                rec["source"] = fname
                w.writerow(rec)
                total += 1
        time.sleep(1)
    print(f"SAME-DAY EXTRACT DONE: {total} rows for {DAY}")


if __name__ == "__main__":
    main()
