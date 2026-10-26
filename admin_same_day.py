#!/usr/bin/env python3
"""Same-day loan-applicant extractor (requires admin_token.json). v2.

Robust credential handling: admin_token.json is a list of cred dicts written
by several producers (oracle/selfreg/jwtforge). Accepted shapes:
  {data:{token}} | {token} | {raw:"<json w/ token>"} | {adminId,password}
The last form re-logins via /admin-api/auth/login to mint a fresh token.

Pulls for TODAY (arg YYYYMMDD, default today):
  members LIMIT_DT / JOIN_DT / LAST_ACCESS_DAY / LO_EX_DT (paged, 500/pg)
  limit/list, loan/list (credit-check + executed-loan records)
  POST member/excel (lastAccess + join bulk exports, raw xlsx saved)
Outputs same_day_applicants.csv + same_day_raw/*.json|xlsx.
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
LOGIN_URL = "https://m.okbigyo.com:9443/bigyo/admin-api/auth/login"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

DAY = os.sys.argv[1] if len(os.sys.argv) > 1 else time.strftime("%Y%m%d")
RAW_DIR = os.path.join(HERE, "same_day_raw")
os.makedirs(RAW_DIR, exist_ok=True)


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def post_login(admin_id, password):
    body = json.dumps({"adminId": admin_id, "password": password}).encode()
    rq = urllib.request.Request(LOGIN_URL, data=body,
                                headers={"User-Agent": UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(rq, timeout=15, context=CTX) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        data = d.get("data") or {}
        return data.get("token") or data.get("accessToken")
    except Exception:
        return None


def extract_token(cred):
    if not isinstance(cred, dict):
        return None
    if isinstance(cred.get("data"), dict):
        t = cred["data"].get("token") or cred["data"].get("accessToken")
        if t:
            return t
    if cred.get("token"):
        return cred["token"]
    raw = cred.get("raw")
    if isinstance(raw, str):
        try:
            rd = json.loads(raw)
            dd = rd.get("data") if isinstance(rd, dict) else None
            if isinstance(dd, dict) and (dd.get("token") or dd.get("accessToken")):
                return dd.get("token") or dd.get("accessToken")
        except Exception:
            pass
    if cred.get("adminId") and cred.get("password"):
        t = post_login(cred["adminId"], cred["password"])
        if t:
            log(f"relogin OK for {cred['adminId']}")
        return t
    return None


def token():
    p = os.path.join(HERE, "admin_token.json")
    if not os.path.exists(p):
        return None
    try:
        creds = json.load(open(p))
    except Exception:
        return None
    if not isinstance(creds, list):
        creds = [creds]
    for c in creds:
        t = extract_token(c)
        if t:
            return t
    return None


def get(tok, path, params):
    qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
    url = f"{BASE}{path}" + ("?" + qs if qs else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20, context=CTX) as r:
            return json.loads(r.read().decode("utf-8", "replace")), None
    except Exception as e:
        return None, str(e)[:200]


def get_bytes(tok, path, params):
    qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
    url = f"{BASE}{path}" + ("?" + qs if qs else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok,
                                               "Accept": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
            return r.read(), None
    except Exception as e:
        return None, str(e)[:200]


def rows_of(payload):
    if payload is None:
        return []
    d = payload.get("data") if isinstance(payload, dict) else payload
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        for k in ("list", "records", "rows", "content", "items", "result"):
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
        log("no usable admin token yet")
        return
    log(f"ADMIN TOKEN ACQUIRED — pulling {DAY}")
    fmts = [DAY, DAY[:4] + "-" + DAY[4:6] + "-" + DAY[6:]]
    out_csv = os.path.join(HERE, "same_day_applicants.csv")
    header_written = not os.path.exists(out_csv)
    nfld = [f for f, _ in FLAT] + ["source"]
    total = 0

    def write_rows(rows, source):
        nonlocal total, header_written
        with open(out_csv, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=nfld, extrasaction="ignore")
            if header_written:
                w.writeheader()
                header_written = False
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rec = {dst: r.get(src, "") for src, dst in FLAT}
                rec["source"] = source
                w.writerow(rec)
                total += 1

    # 1) member slicers, paged
    for stype in ("LIMIT_DT", "JOIN_DT", "LAST_ACCESS_DAY", "LO_EX_DT"):
        got = 0
        for page in (1, 2, 3, 4, 5):
            payload, err = None, None
            dfmt_used = fmts[0]
            for dfmt in fmts:
                payload, err = get(tok, "/members", {
                    "adminMemberSearchType": stype,
                    "searchStrtDt": dfmt, "searchEndDt": dfmt,
                    "page": page, "pageSize": 500})
                if payload is not None:
                    dfmt_used = dfmt
                    break
            save_raw(f"members_{stype}_p{page}", payload if payload is not None else {"error": err})
            rows = rows_of(payload)
            got += len(rows)
            write_rows(rows, f"members_{stype}")
            log(f"members {stype} p{page}: {len(rows)} rows (cum {got})")
            if len(rows) < 500:
                break
            time.sleep(0.5)

    # 2) limit/list + loan/list
    for fname, path in (("limit_list", "/limit/list"), ("loan_list", "/loan/list")):
        payload, err = None, None
        for dfmt in fmts:
            payload, err = get(tok, path, {"start": dfmt, "end": dfmt})
            if payload is not None:
                break
        save_raw(fname, payload if payload is not None else {"error": err})
        rows = rows_of(payload)
        write_rows(rows, fname)
        log(f"{fname}: {len(rows)} rows")
        time.sleep(0.5)

    # 3) excel bulk exports (lastAccess today + join today)
    for tag, params in (
        ("excel_lastaccess", {"lastAccessStrtDt": DAY, "lastAccessEndDt": DAY}),
        ("excel_joined", {"joinStrtDt": DAY, "joinEndDt": DAY}),
    ):
        blob, err = get_bytes(tok, "/member/excel", params)
        if blob and len(blob) > 100 and blob[:2] == b"PK":
            with open(os.path.join(RAW_DIR, tag + ".xlsx"), "wb") as f:
                f.write(blob)
            log(f"{tag}: {len(blob)} bytes xlsx saved")
        else:
            save_raw(tag, {"error": err, "head": (blob or b"")[:200]})
            log(f"{tag}: not-xlsx ({err or 'tiny'}) {(blob or b'')[:120]!r}")
        time.sleep(0.5)

    log(f"SAME-DAY EXTRACT DONE: {total} csv rows for {DAY}")


if __name__ == "__main__":
    main()
