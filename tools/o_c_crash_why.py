#!/usr/bin/env python3
"""o_c_crash_why.py - pull the human-readable reason out of an .ips crash report."""
import glob
import json
import os
import sys

D = sys.argv[1] if len(sys.argv) > 1 else r"G:\op lab\iphone-control\jailbreak\.o_c\crash"
files = sorted(glob.glob(os.path.join(D, "*.ips")))
if not files:
    print("no .ips in", D)
    raise SystemExit(1)
f = files[-1]
raw = open(f, "rb").read()
nl = raw.find(b"\n")
head = json.loads(raw[:nl])
body = json.loads(raw[nl + 1:])
print("file:", os.path.basename(f))
print("head keys:", list(head.keys()))
for k in ("app_name", "bundleID", "os_version", "incident", "bug_type", "asi"):
    if k in head:
        print(f"  {k}: {head[k]}")
print("body keys:", list(body.keys()))
for k in ("exception", "termination", "asi", "lastExceptionBacktrace", "vmregioninfo",
          "ktriage", "isCorpse", "procRole", "coalitionName", "translated", "reason"):
    if k in body:
        v = body[k]
        s = json.dumps(v) if not isinstance(v, str) else v
        print(f"  {k}: {s[:900]}")
used = body.get("usedImages") or []
for t in body.get("threads", []):
    if t.get("triggered"):
        print("  crashed thread name:", t.get("name"), "id", t.get("id"))
        for fr in t.get("frames", [])[:14]:
            i = fr.get("imageIndex", 0)
            nm = used[i]["name"] if i < len(used) else "?"
            sym = fr.get("symbol") or ""
            print(f"    {nm:26s} +{fr.get('imageOffset')} {sym}")
        break
