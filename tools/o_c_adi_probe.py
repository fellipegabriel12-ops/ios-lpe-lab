#!/usr/bin/env python3
"""
o_c_adi_probe.py  (O-C = session "jailbreak 3")

Question this answers: does the anisette server HONOR the adi_pb we hand it, or
does it ignore it and return headers minted from whatever state it has stored?

This matters because isideload's state is (identifier, adi_pb) and it POSTs both to
/v3/get_headers. If the server ignores the adi_pb and returns its own stale one,
then a perfectly fresh Apple identity still gets rejected by GrandSlam - and the
fix is to use a server that honours it, or to match the server's stored state.

Run:  python o_c_adi_probe.py
"""
import base64
import hashlib
import json
import plistlib
import urllib.request

WD = r"G:\op lab\iphone-control\jailbreak"
SERVERS = ["https://ani.jkcoxson.com", "https://ani.sidestore.io", "https://new.ani.sidestore.io"]

STATES = {
    "mine_fresh_jk": WD + r"\anisette_state.jk.plist",
    "iloader_legacy": WD + r"\anisette_state.iloader_as_xml.plist",
}


def load(p):
    with open(p, "rb") as f:
        return plistlib.load(f)


def get_headers(server, st):
    ident = base64.b64encode(st["keychain_identifier"]).decode()
    adi = base64.b64encode(st["adi_pb"]).decode()
    body = json.dumps({"identifier": ident, "adi_pb": adi}).encode()
    req = urllib.request.Request(
        f"{server}/v3/get_headers", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read())


def client_info(server):
    with urllib.request.urlopen(f"{server}/v3/client_info", timeout=30) as r:
        return json.loads(r.read())


def main():
    states = {k: load(v) for k, v in STATES.items()}
    for server in SERVERS:
        print("=" * 78)
        print("SERVER", server)
        try:
            ci = client_info(server)
            print(f"  client_info: {ci.get('client_info')}")
        except Exception as e:
            print(f"  client_info ERROR {type(e).__name__}: {e}")
        seen = {}
        for name, st in states.items():
            try:
                h = get_headers(server, st)
                md = h.get("X-Apple-I-MD", "")
                mid = h.get("X-Apple-I-MD-M", "")
                rinfo = h.get("X-Apple-I-MD-RINFO", "")
                sig = hashlib.sha256(md.encode()).hexdigest()[:20]
                seen[name] = sig
                print(f"  {name:16s} md_len={len(md):4d} md_sig={sig} mid_sig={hashlib.sha256(mid.encode()).hexdigest()[:12]}")
                print(f"                   rinfo={rinfo[:40]}")
                if "result" in h:
                    print(f"                   result={h['result']}")
            except Exception as e:
                print(f"  {name:16s} ERROR {type(e).__name__}: {e}")
        if len(set(seen.values())) == 1 and len(seen) > 1:
            print("  >>> VERDICT: server IGNORES the adi_pb we send (same headers for both states)")
        elif len(set(seen.values())) == len(seen):
            print("  >>> VERDICT: server HONORS the adi_pb (different headers per state)")


if __name__ == "__main__":
    main()
