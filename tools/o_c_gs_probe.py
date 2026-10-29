#!/usr/bin/env python3
"""
o_c_gs_probe.py  (O-C = session "jailbreak 3")

Replicates isideload's GrandSlam step 1 (the "init" request) by hand so we can
see Apple's RAW response instead of isideload's summarised error, and so we can
vary one thing at a time:

  * is the anisette server's client_info stable across calls?  (if it rotates,
    the adi_pb we provisioned under client_info A gets presented to Apple under
    client_info B -> GrandSlam rejects the machine identity)
  * does the account exist (fake email vs real email)?  (-20101 = account not
    found, -22421 = machine identity / generic rejection -> tells us which
    side is failing without guessing)

Reference (isideload source, read to mirror it exactly):
  auth/grandslam.rs  base_headers()  +  plist_request()
  auth/apple_account.rs  send_init_request()  body: A2k / cpd / o=init / ps / u
  anisette/mod.rs  get_client_provided_data()  cpd dict

Run:  python o_c_gs_probe.py
"""
import base64
import json
import os
import plistlib
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

WD = r"G:\op lab\iphone-control\jailbreak"
ANISETTE = "https://ani.jkcoxson.com"
URL_BAG = "https://gsa.apple.com/grandslam/GsService2/lookup"
URL_BAG_CLIENT_INFO = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
XCODE_VERSION = "27.0 (27A5218g)"
APP_INFO = "com.apple.gs.xcode.auth"

REAL_EMAIL = "fellipegabriel12@icloud.com"


def http(method, url, data=None, headers=None, timeout=45):
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
        return r.status, r.read()


def anisette_client_info(server=ANISETTE):
    st, body = http("GET", f"{server}/v3/client_info", timeout=30)
    j = json.loads(body)
    return j["client_info"], j.get("user_agent", "akd/1.0 CFNetwork/808.1.4")


def anisette_headers(server, state, client_info, user_agent):
    ident = base64.b64encode(state["keychain_identifier"]).decode()
    adi = base64.b64encode(state["adi_pb"]).decode()
    body = json.dumps({"identifier": ident, "adi_pb": adi}).encode()
    st, raw = http("POST", f"{server}/v3/get_headers", data=body,
                   headers={"Content-Type": "application/json"}, timeout=45)
    return json.loads(raw)


def url_bag(client_info, user_agent):
    h = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist",
        "X-Mme-Client-Info": URL_BAG_CLIENT_INFO,
        "User-Agent": user_agent,
        "X-Xcode-Version": XCODE_VERSION,
        "X-Apple-App-Info": APP_INFO,
        "Connection": "close",
        "X-Apple-I-Client-Time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "X-Apple-I-TimeZone": "UTC",
        "X-Apple-Locale": "en_US",
    }
    st, body = http("GET", URL_BAG, headers=h, timeout=45)
    return plistlib.loads(body)["urls"]


def build_cpd(state, headers):
    cpd = {
        "bootstrap": "true",
        "icscrec": "true",
        "loc": "en_US",
        "pbe": "false",
        "prkgen": "true",
        "svct": "iCloud",
        "X-Mme-Device-Id": str(uuid.UUID(bytes=state["keychain_identifier"])),
        "X-Apple-I-MD": headers["X-Apple-I-MD"],
        "X-Apple-I-MD-M": headers["X-Apple-I-MD-M"],
    }
    return cpd


def send_init(gs_url, cpd, email, client_info, user_agent, extra_headers=None):
    a_pub = os.urandom(32)
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {
            "A2k": a_pub,
            "cpd": cpd,
            "o": "init",
            "ps": ["s2k", "s2k_fo"],
            "u": email,
        },
    }
    h = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist",
        "X-Mme-Client-Info": client_info,
        "User-Agent": user_agent,
        "X-Xcode-Version": XCODE_VERSION,
        "X-Apple-App-Info": APP_INFO,
        "Connection": "close",
        "X-Mme-Device-Id": cpd["X-Mme-Device-Id"],
        "X-Apple-I-MD": cpd["X-Apple-I-MD"],
        "X-Apple-I-MD-M": cpd["X-Apple-I-MD-M"],
    }
    if extra_headers:
        h.update(extra_headers)
    data = plistlib.dumps(body, fmt=plistlib.FMT_XML)
    try:
        st, raw = http("POST", gs_url, data=data, headers=h, timeout=45)
        return st, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def describe(raw):
    try:
        d = plistlib.loads(raw)
    except Exception:
        return raw[:400].decode("utf-8", "replace")
    resp = d.get("Response", d)
    out = {}
    for k, v in resp.items():
        if isinstance(v, (bytes, bytearray)):
            out[k] = f"<{len(v)} bytes>"
        else:
            out[k] = v
    return out


def load(p):
    with open(p, "rb") as f:
        return plistlib.load(f)


def main():
    print("### 1. is the anisette server's client_info stable?")
    seen = {}
    for i in range(8):
        ci, ua = anisette_client_info()
        seen.setdefault(ci, 0)
        seen[ci] += 1
        print(f"   call {i}: {ci}")
    print(f"   distinct client_info values: {len(seen)}")
    if len(seen) > 1:
        print("   >>> client_info ROTATES -> adi_pb provisioned under one client_info")
        print("       is presented to Apple under another -> identity mismatch.")
    else:
        print("   >>> client_info is STABLE")

    client_info, user_agent = anisette_client_info()
    urls = url_bag(client_info, user_agent)
    gs_url = urls.get("gsService") or (URL_BAG + "?i=2")
    print(f"\n### 2. url bag gsService = {gs_url}")

    for label, path in (("mine_fresh_jk", WD + r"\anisette_state.jk.plist"),
                        ("iloader_legacy", WD + r"\anisette_state.iloader_as_xml.plist")):
        print(f"\n### 3. init request with state: {label}")
        state = load(path)
        try:
            hdrs = anisette_headers(ANISETTE, state, client_info, user_agent)
        except Exception as e:
            print(f"   get_headers failed: {type(e).__name__}: {e}")
            continue
        if "X-Apple-I-MD" not in hdrs:
            print(f"   no headers: {hdrs}")
            continue
        cpd = build_cpd(state, hdrs)
        for email, tag in ((REAL_EMAIL, "real account"), ("nonexistent-zzz-9911@icloud.com", "FAKE account")):
            st, raw = send_init(gs_url, cpd, email, client_info, user_agent)
            print(f"   [{tag}] HTTP {st} -> {describe(raw)}")


if __name__ == "__main__":
    main()
