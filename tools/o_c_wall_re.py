#!/usr/bin/env python3
"""
o_c_wall_re.py (O-D) - the SANDBOX/AMFI wall pair, carved + diffed between
kcache-26.4 (23E246, our target) and kcache-27.0.1 (the comparison wave).

Why: the operation's stage E = the "sandbox patch" (kirby is doing one publicly
for 27.0.x; we want the map for 26.4). The two walls from our app to root:
  - amfi.kext / AppleMobileFileIntegrity (trustcache, restrictions, the RM family)
  - sandbox.kext + the embedded SeatBelt profile compiled sets
Carving + marker census + a 26.4-vs-27.0.1 string diff = T-0-ish read of what
Apple hardened between our build and the comparison band (the ADDED CHECKS
reveal the bug class, per IV.1 patch-diffing law).

Usage: python o_c_wall_re.py [--kcache <26.4 kcache>] [--compare <27.0.1 kcache>] [--out <dir>]
"""
import argparse
import os
import re
import struct
import sys

MH_MAGIC_64 = b"\xcf\xfa\xed\xfe"  # little-endian 0xFEEDFACF written as memory
LC_SEGMENT_64 = 0x19
FILETYPE_KEXT = 0x0E
FILETYPE_KEXT_BUNDLE = 0x0B


def iter_macho(buf):
    pos = 0
    while True:
        pos = buf.find(MH_MAGIC_64, pos)
        if pos < 0:
            break
        off = pos
        pos += 4
        if off + 32 > len(buf):
            break
        cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = struct.unpack_from(
            "<iiIIIII", buf, off + 4)
        yield off, filetype, ncmds


def macho_extent(buf, off, ncmds):
    end = off + 32
    p = off + 32
    for _ in range(ncmds):
        if p + 8 > len(buf):
            break
        cmd, cmdsize = struct.unpack_from("<II", buf, p)
        if cmd == LC_SEGMENT_64 and p + 8 + 40 <= len(buf):
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", buf, p + 24)
            end = max(end, off + fileoff + filesize)
        p += cmdsize
    return end


def carve_named(buf, names):
    """return {name: blob} for any carved kext whose name matches the list
    (matched against the LC_IDENTIFIER-ish string bytes inside the first 4k)."""
    out = {}
    for off, filetype, ncmds in iter_macho(buf):
        if filetype not in (FILETYPE_KEXT, FILETYPE_KEXT_BUNDLE):
            continue
        end = macho_extent(buf, off, ncmds)
        blob = buf[off:end]
        if len(blob) < 40000:
            continue
        head = blob[:8192]
        for n in names:
            if n.encode() in head and n not in out:
                out[n] = blob
                break
    return out


def strings_45(blob):
    return set(re.findall(rb"[\x20-\x7e]{5,}", blob))


def count_ops(blob, label):
    """the class-count census: mul48/68(text关怀) families + atomic pair densities"""
    m = {"bytes": len(blob), "mul_1a52": 0, "smull": 0, "atomics": 0}
    for i in range(0, len(blob) - 4, 4):
        w = blob[i:i + 4]
        if (w[3] & 0xFE) == 0x22 and (w[2] & 0x20):
            m["mul_1a52"] += 1
        elif (w[3] & 0xFE) == 0x23 and (w[2] & 0x20) == 0x20:
            m["smull"] += 1
        if (w[3] & 0x3F) == 0x08 and (w[2] & 0xE0) in (0x00, 0x20, 0x40, 0x60):
            m["atomics"] += 1
    return m


MARKERS_BASE = [
    "sandbox", "amfi", "AMFI", "AppleMobileFileIntegrity",
    "trust", "trustcache", "TrustCache", "Library/Preferences",
    "unsupported profile", "seatbelt", "SeatBelt", "PROFILE",
    "deny-all", "deny-all-with-exeception", "apple_client_container",
    "cs_kill", "csflags", "SIGKILL", "code sign invariant",
    "pid_callout", "spawncheck", "sandbox-init", "iokit-user-client-class",
]


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    jb = os.path.dirname(here)
    ap.add_argument("--kcache", default=os.path.join(
        jb, "kcache-26.4", "23E246__iPhone17,3", "kernelcache.research.iPhone17,3"))
    ap.add_argument("--compare", default=os.path.join(
        jb, "kcache-27.0.1", "24A446__iPhone17,3", "kernelcache.release.iPhone17,3"))
    ap.add_argument("--out", default=os.path.join(jb, "kexts"))
    args = ap.parse_args()

    names = ["amfi", "AppleMobileFileIntegrity", "sandbox", "Sandbox"]
    for label, path in (("26.4", args.kcache), ("27.0.1", args.compare)):
        print(f"==============================================================================")
        print(f"{label}: {path}  ({os.path.getsize(path):,} bytes)")
        if not os.path.exists(path):
            print("  MISSING - skipped")
            continue
        buf = open(path, "rb").read()
        carved = carve_named(buf, names)
        if not carved:
            print("  no amfi/sandbox kext found by name (the caches may be LFN-packaged)")
            continue
        for n, blob in carved.items():
            d = os.path.join(args.out, label, n)
            os.makedirs(d, exist_ok=True)
            blob_f = os.path.join(d, f"{n}.{label}.bin")
            open(blob_f, "wb").write(blob)
            s = strings_45(blob)
            ops = count_ops(blob, n)
            print(f"  --- {n}: {len(blob):,} bytes -> {blob_f}")
            print(f"      ops: mul={ops['mul_1a52']} smull={ops['smull']} atomics={ops['atomics']}")
            hits = []
            for mk in MARKERS_BASE:
                if mk.encode() in blob:
                    hits.append(mk)
            print(f"      markers ({len(hits)}): " + ", ".join(hits[:14]))
            open(os.path.join(d, f"markers.{label}.txt"), "w", encoding="utf-8").write(
                "\n".join(sorted(hits))
            )
        globals()["_saved_" + label] = carved  # stash for the diff step (same process)

    # cross-diff the marker strings 26.4 -> 27.0.1 (what Apple ADDED)
    a = globals().get("_saved_26.4", {})
    b = globals().get("_saved_27.0.1", {})
    for n in set(a) & set(b):
        sa = strings_45(a[n])
        sb = strings_45(b[n])
        added = sb - sa
        removed = sa - sb
        print(f"==============================================================================")
        print(f"DIFF {n}: added-checks strings in 27.0.1 (research gold - the NEW checks reveal the wall's shape):")
        for x in sorted(added)[:40]:
            try:
                print(f"  + {x.decode()}")
            except Exception:
                pass
        print(f"  (added: {len(added)}, removed: {len(removed)})")


if __name__ == "__main__":
    main()
