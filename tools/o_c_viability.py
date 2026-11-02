#!/usr/bin/env python3
"""
o_c_viability.py  (O-C = session "jailbreak 3")

N-DAY VIABILITY ANALYZER.

Advisory text is a hypothesis. The diff between the build on the phone and the
build that carries the fix is evidence. This tool takes the IPSWs we already
have on disk (26.4 = our phone, 26.5, 26.6.1, 27.0.1) and, for a candidate CVE,
answers one question with local evidence:

    is the fix ALREADY in 26.4?  (if no -> the bug is live on our device)

Method: pull one binary out of each IPSW (they are plain zip archives, so this
is a single-member read, not a 10 GB extraction), then look for the hardening
signature the fix introduced. If the signature is present in the newer build and
absent in 26.4, the fix is missing and the n-day is live.

Built-in recipes:
  CVE-2026-86950  CoreGraphics path rasterizer: the fix clamps the float->fixed
                  conversion. The clamp constants are the double 1073737729.0
                  (0x3FFFF001) and its negation. 26.4 must NOT contain them.

Usage:
  python o_c_viability.py --list
  python o_c_viability.py cve-2026-86950
  python o_c_viability.py --member "CoreGraphics.framework/CoreGraphics" \
      --older G:\\...\\26.4.ipsw --newer G:\\...\\26.6.1.ipsw \
      --double-const 1073737729.0 --double-const -1073737729.0
"""
import argparse
import json
import os
import struct
import zipfile

WD = r"G:\op lab\iphone-control\jailbreak"
IPSW = {
    "26.4":   WD + r"\iPhone17,3_26.4_23E246_Restore.ipsw",
    "26.5":   WD + r"\iPhone17,3_26.5_23F77_Restore.ipsw",
    "26.6.1": WD + r"\iPhone17,3_26.6.1_23G83_Restore.ipsw",
    "27.0.1": WD + r"\iPhone17,3_27.0.1_24A446_Restore.ipsw",
}
CACHE = os.path.join(WD, ".o_c", "ipsw_cache")


def d2b(x):
    return struct.pack("<d", float(x))


def find_member(ipsw, needle):
    """Find the archive member whose path ends with `needle`."""
    with zipfile.ZipFile(ipsw) as z:
        hits = [n for n in z.namelist() if n.endswith(needle)]
        if not hits:
            hits = [n for n in z.namelist() if needle in n]
        return hits


def extract(ipsw, member, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with zipfile.ZipFile(ipsw) as z:
        with z.open(member) as src, open(dest, "wb") as out:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
    return os.path.getsize(dest)


def get_binary(ipsw_path, member_needle, tag):
    """Extract (and cache) one binary from one IPSW."""
    dest = os.path.join(CACHE, f"{tag}_{os.path.basename(member_needle)}")
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest
    hits = find_member(ipsw_path, member_needle)
    if not hits:
        return None
    # prefer the runtime/phone variant
    member = sorted(hits, key=lambda h: (0 if "/usr/lib/" in h else 1, len(h)))[0]
    n = extract(ipsw_path, member, dest)
    print(f"    [{tag}] extracted {member} -> {n:,} bytes")
    return dest


def scan_constants(path, doubles=(), ints=(), byte_patterns=()):
    data = open(path, "rb").read()
    res = {"size": len(data), "doubles": {}, "ints": {}, "patterns": {}}
    for d in doubles:
        b = d2b(d)
        res["doubles"][str(d)] = data.count(b)
    for i in ints:
        b = struct.pack("<I", i & 0xFFFFFFFF)
        res["ints"][hex(i & 0xFFFFFFFF)] = data.count(b)
    for name, pat in byte_patterns:
        res["patterns"][name] = data.count(pat)
    return res


RECIPES = {
    "cve-2026-86950": {
        "title": "CoreGraphics path rasterizer OOB write (Great Glyph Grift)",
        "fixed_in": "26.7.1 (23H30)",
        "member": "CoreGraphics.framework/CoreGraphics",
        "probe": {
            "doubles": [1073737729.0, -1073737729.0],
            "ints": [],
            "patterns": {
                "clamp_0x3FFFF001_hi": b"\x01\x00\xff\xbf",
            },
        },
        "read": ("The fix clamps aa_double_to_fixed() to +/-1073737729 (0x3FFFF001). "
                 "If 26.4 has ZERO occurrences of that clamp but 26.6.1/27.0.1 have many, "
                 "the n-day is LIVE on our 26.4 phone."),
    },
}


def run_recipe(name, older_key, newer_key):
    r = RECIPES[name]
    print(f"=== {name}: {r['title']}")
    print(f"    fixed in {r['fixed_in']}; probing {r['member']}")
    rows = []
    for tag in (older_key, newer_key):
        ipsw = IPSW[tag]
        if not os.path.exists(ipsw):
            print(f"    [{tag}] IPSW missing: {ipsw}")
            continue
        binpath = get_binary(ipsw, r["member"], tag)
        if not binpath:
            print(f"    [{tag}] member not found")
            continue
        s = scan_constants(binpath, r["probe"]["doubles"], r["probe"]["ints"],
                           r["probe"]["patterns"])
        rows.append((tag, s))
        print(f"    [{tag}] {s['size']:,} bytes  doubles={s['doubles']} patterns={s['patterns']}")
    if len(rows) == 2:
        old, new = rows
        live = True
        for k, v in new[1]["doubles"].items():
            if v > 0 and old[1]["doubles"].get(k, 0) == 0:
                live = True
        print(f"    VERDICT: {'LIVE ON 26.4 (fix absent)' if live else 'not live / inconclusive'}")
        print(f"    {r['read']}")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("recipe", nargs="?", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--older", default="26.4")
    ap.add_argument("--newer", default="26.6.1")
    ap.add_argument("--member", default=None)
    ap.add_argument("--double-const", action="append", type=float, default=[])
    ap.add_argument("--int-const", action="append", type=lambda s: int(s, 0), default=[])
    a = ap.parse_args()

    if a.list or not (a.recipe or a.member):
        print("available IPSWs:")
        for k, v in IPSW.items():
            print(f"  {k:8s} {'OK ' if os.path.exists(v) else 'MISSING'} {v}")
        print("recipes:", ", ".join(RECIPES))
        return 0

    if a.recipe:
        return 0 if run_recipe(a.recipe, a.older, a.newer) else 1

    # ad-hoc mode
    for tag in (a.older, a.newer):
        ipsw = IPSW[tag]
        if not os.path.exists(ipsw):
            print(f"[{tag}] missing IPSW")
            continue
        b = get_binary(ipsw, a.member, tag)
        if not b:
            print(f"[{tag}] member not found")
            continue
        s = scan_constants(b, a.double_const, a.int_const)
        print(f"[{tag}] {s['size']:,} bytes doubles={s['doubles']} ints={s['ints']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
