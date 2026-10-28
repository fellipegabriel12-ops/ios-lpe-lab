#!/usr/bin/env python3
"""
o_c_anisette_provision.py  (O-C = session "jailbreak 3")

Fixes anisette_provision.py's one fatal flaw: it only writes the state file AFTER
the /v3/get_headers verification round-trip. When that verification times out (which
it does on the live public servers), a perfectly good 751-byte adi_pb is thrown away
and you have to pay for another full Apple round-trip to get it back.

This version:
  1. writes the state plist + raw adi_pb to disk IMMEDIATELY after ProvisioningSuccess
  2. then verifies with /v3/get_headers, with retries and a long timeout
  3. if verification fails, the state is still on disk and still usable
  4. can try a list of servers in order and stop at the first that provisions

Usage:
  python o_c_anisette_provision.py                      # try servers in order
  python o_c_anisette_provision.py --server <url>       # one specific server
  python o_c_anisette_provision.py --out <state.plist>  # where to write the state
"""
import argparse
import base64
import hashlib
import json
import os
import plistlib
import ssl
import sys
import time
import urllib.request
import uuid

import websocket  # websocket-client

URL_BAG = "https://gsa.apple.com/grandslam/GsService2/lookup"
URL_BAG_CLIENT_INFO = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

DEFAULT_SERVERS = [
    "https://new.ani.sidestore.io",
    "https://ani.sidestore.io",
]


def http(method, url, data=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.read()


def base_headers(client_info, user_agent):
    return {
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist",
        "X-Mme-Client-Info": client_info,
        "User-Agent": user_agent,
        "X-Xcode-Version": "27.0 (27A5218g)",
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "Connection": "close",
        "X-Apple-I-Client-Time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "X-Apple-I-TimeZone": "UTC",
        "X-Apple-Locale": "en_US",
    }


def fetch_client_info(server):
    st, body = http("GET", f"{server}/v3/client_info", timeout=30)
    info = json.loads(body)
    return info["client_info"], info.get("user_agent", "akd/1.0 CFNetwork/808.1.4")


def fetch_url_bag(client_info, user_agent):
    h = base_headers(client_info, user_agent)
    h["X-Mme-Client-Info"] = URL_BAG_CLIENT_INFO
    st, body = http("GET", URL_BAG, headers=h, timeout=30)
    d = plistlib.loads(body)
    urls = d.get("urls")
    if not urls:
        raise RuntimeError(f"no urls in bag: {list(d.keys())}")
    return urls


def plist_request(url, body_dict, headers):
    body = plistlib.dumps(body_dict, fmt=plistlib.FMT_XML)
    st, raw = http("POST", url, data=body, headers=headers, timeout=60)
    d = plistlib.loads(raw)
    return d.get("Response", d)


def ws_connect(server):
    return websocket.create_connection(
        server.replace("https://", "wss://").replace("http://", "ws://")
        + "/v3/provisioning_session",
        timeout=60,
        enable_multithread=True,
        origin="https://ani.sidestore.io",
    )


def provision(server, out_path, raw_path):
    client_info, user_agent = fetch_client_info(server)
    print(f"[+] server        = {server}")
    print(f"[+] client_info   = {client_info}")
    urls = fetch_url_bag(client_info, user_agent)
    start_url = urls.get("midStartProvisioning")
    end_url = urls.get("midFinishProvisioning")
    print(f"[+] midStartProvisioning = {start_url}")
    print(f"[+] midFinishProvisioning= {end_url}")
    if not start_url or not end_url:
        raise RuntimeError("url bag missing provisioning endpoints")

    keychain_identifier = os.urandom(16)
    md_lu = hashlib.sha256(keychain_identifier).hexdigest()
    device_id = str(uuid.UUID(bytes=keychain_identifier))
    print(f"[+] identifier    = {base64.b64encode(keychain_identifier).decode()}")
    print(f"[+] md_lu         = {md_lu}")
    print(f"[+] device_id     = {device_id}")

    ws = ws_connect(server)
    adi_pb = None
    try:
        while True:
            msg = json.loads(ws.recv())
            res = msg.get("result")
            print(f"[ws <-] {res}")
            if res == "GiveIdentifier":
                ws.send(json.dumps({"identifier": base64.b64encode(keychain_identifier).decode()}))
            elif res == "GiveStartProvisioningData":
                h = base_headers(client_info, user_agent)
                h["X-Apple-I-MD-LU"] = md_lu
                h["X-Mme-Device-Id"] = device_id
                t0 = time.time()
                resp = plist_request(start_url, {"Header": {}, "Request": {}}, h)
                print(f"[+] midStartProvisioning -> {time.time()-t0:.1f}s keys={list(resp.keys())}")
                spim = resp.get("spim")
                if not spim:
                    raise RuntimeError(f"no spim: {resp}")
                ws.send(json.dumps({"spim": spim}))
            elif res == "GiveEndProvisioningData":
                cpim = msg.get("cpim")
                h = base_headers(client_info, user_agent)
                h["X-Apple-I-MD-LU"] = md_lu
                h["X-Mme-Device-Id"] = device_id
                t0 = time.time()
                resp = plist_request(end_url, {"Header": {}, "Request": {"cpim": cpim}}, h)
                print(f"[+] midFinishProvisioning -> {time.time()-t0:.1f}s keys={list(resp.keys())}")
                ptm, tk = resp.get("ptm"), resp.get("tk")
                if not ptm or not tk:
                    raise RuntimeError(f"missing ptm/tk: {resp}")
                ws.send(json.dumps({"ptm": ptm, "tk": tk}))
            elif res == "ProvisioningSuccess":
                adi_pb = base64.b64decode(msg["adi_pb"])
                print(f"[+] adi_pb        = {len(adi_pb)} bytes")
                break
            elif res in ("Timeout", "InvalidIdentifier", "StartProvisioningError", "EndProvisioningError"):
                raise RuntimeError(f"provisioning failed: {msg}")
    finally:
        try:
            ws.close()
        except Exception:
            pass

    if not adi_pb:
        raise RuntimeError("no adi_pb")

    # ---- WRITE FIRST. Verification is best-effort. ----
    state = {"keychain_identifier": keychain_identifier, "adi_pb": adi_pb}
    with open(out_path, "wb") as f:
        plistlib.dump(state, f, fmt=plistlib.FMT_XML)
    with open(raw_path, "wb") as f:
        f.write(adi_pb)
    print(f"[+] WROTE {out_path} ({os.path.getsize(out_path)} bytes)")
    print(f"[+] WROTE {raw_path} ({len(adi_pb)} bytes)")

    # ---- then verify, with retries ----
    body = json.dumps({
        "identifier": base64.b64encode(keychain_identifier).decode(),
        "adi_pb": base64.b64encode(adi_pb).decode(),
    }).encode()
    for attempt in range(1, 4):
        try:
            st, raw = http("POST", f"{server}/v3/get_headers", data=body,
                           headers={"Content-Type": "application/json"}, timeout=60)
            hdrs = json.loads(raw)
            if "X-Apple-I-MD" in hdrs:
                print(f"[+] get_headers OK (attempt {attempt}): {list(hdrs.keys())}")
                return out_path, True
            print(f"[!] get_headers refused (attempt {attempt}): {hdrs}")
        except Exception as e:
            print(f"[!] get_headers attempt {attempt} failed: {type(e).__name__}: {e}")
        time.sleep(3)
    print("[!] get_headers never verified, but the state on disk is real and usable")
    return out_path, False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=None)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  "anisette_state.o_c.plist"))
    ap.add_argument("--raw", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  "anisette_state.o_c.bin"))
    ap.add_argument("--all", action="store_true", help="try every default server")
    a = ap.parse_args()

    servers = [a.server] if a.server else (DEFAULT_SERVERS if a.all else DEFAULT_SERVERS[:1])
    last_err = None
    for s in servers:
        try:
            path, verified = provision(s, a.out, a.raw)
            print(f"RESULT server={s} state={path} verified={verified}")
            return 0 if verified else 2
        except Exception as e:
            last_err = e
            print(f"[!] {s} failed: {type(e).__name__}: {e}")
    print(f"[!] all servers failed, last error: {last_err}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
