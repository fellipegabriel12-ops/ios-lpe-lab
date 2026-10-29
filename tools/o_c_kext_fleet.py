#!/usr/bin/env python3
"""
o_c_kext_fleet.py  (O-C = session "jailbreak 3")

Carve the interesting kexts out of the 26.4 and 27.0.1 kernelcaches and census
them with the sibling's tool. The point is NOT to re-check CVE-2026-64747 (the
encoder, already mapped) but to look at the components nobody has mapped on
THIS build:

  AppleAVD      the DECODER kext. Apple's advisories give it eight 2026 CVEs on
                26.4 that are all "kernel memory corruption" class and all
                reachable from plain VideoToolbox with no entitlement:
                CVE-2026-65407 (UAF), CVE-2026-84520 (buffer overflow),
                CVE-2026-84571, CVE-2026-84620 (integer overflow),
                CVE-2026-84561 (double free), CVE-2026-65415 (race),
                CVE-2026-84489, CVE-2026-64760 (kernel state leak).
  AGXG17P       the GPU driver - 1.1 MB of almost-unmapped attack surface.
  IOSurface     memory/surface management.
  IOGPUFamily   the GPU family shim.
  AGX / AVF     the media engine frameworks.

For each kext we compare 26.4 against 27.0.1: bare 32-bit muls that became
64-bit in the newer build are the size calculations Apple hardened, i.e. the
ones that were UNCHECKED in our build. A kext with a lot of them is where the
next CVE lives.

Usage:  python o_c_kext_fleet.py [--builds 26.4,27.0.1] [--out file]
"""
import os
import re
import struct
import subprocess
import sys

WD = r"G:\op lab\iphone-control\jailbreak"
CENSUS = os.path.join(WD, "ave2-analyze", "ave2_census.py")
KCACHE = {
    "26.4": os.path.join(WD, "kcache-26.4", "23E246__iPhone17,3", "kernelcache.release.iPhone17,3"),
    "26.5": os.path.join(WD, "kcache-26.5", "23F77__iPhone17,3", "kernelcache.release.iPhone17,3"),
    "26.6.1": os.path.join(WD, "kcache-26.6.1", "23G83__iPhone17,3", "kernelcache.release.iPhone17,3"),
    "27.0.1": os.path.join(WD, "kcache-27.0.1", "24A446__iPhone17,3", "kernelcache.release.iPhone17,3"),
}
WANT = [
    ("AppleAVD", (b"AppleAVD", b"CAVDAvcDecoder", b"AVC_RBSP")),
    ("AppleAVE2", (b"AppleAVE2", b"AVE_CalcBufSize")),
    ("AGXG17P", (b"AGXG17P",)),
    ("IOSurface", (b"IOSurface",)),
    ("IOGPUFamily", (b"IOGPUFamily",)),
    ("AppleAVF", (b"AppleAVF",)),
    ("AppleGVA", (b"AppleGVA",)),
]
MH_KEXT_BUNDLE = 11


def carve(path):
    buf = open(path, "rb").read()
    magic = b"\xcf\xfa\xed\xfe"
    pos = 0
    out = []
    while True:
        pos = buf.find(magic, pos)
        if pos < 0:
            break
        off = pos
        pos += 4
        if off + 32 > len(buf):
            break
        ft = struct.unpack_from("<I", buf, off + 12)[0]
        if ft != MH_KEXT_BUNDLE:
            continue
        ncmds = struct.unpack_from("<I", buf, off + 16)[0]
        p = off + 32
        end = off + 32
        for _ in range(ncmds):
            if p + 8 > len(buf):
                break
            cmd, cmdsize = struct.unpack_from("<II", buf, p)
            if cmd == 0x19:  # LC_SEGMENT_64
                fileoff, filesize = struct.unpack_from("<QQ", buf, p + 8 + 24)
                end = max(end, off + fileoff + filesize)
            p += cmdsize
        blob = buf[off:end]
        if len(blob) < 20000:
            continue
        txt = b" ".join(re.findall(rb"[\x20-\x7e]{4,}", blob))
        for name, markers in WANT:
            if any(m in txt for m in markers):
                out.append((name, blob))
    return out


def census(path):
    try:
        r = subprocess.run([sys.executable, CENSUS, path], capture_output=True,
                           text=True, timeout=900)
    except Exception as e:
        return {}, str(e)
    out = r.stdout + r.stderr
    m = {}

    def num(pat):
        mm = re.search(pat, out)
        return int(mm.group(1)) if mm else 0
    m["mul32"] = num(r"mul\s+w-form[^:]*:\s*(\d+)")
    m["mul64"] = num(r"mul\s+x-form[^:]*:\s*(\d+)")
    m["smull"] = num(r"smull[^:]*:\s*(\d+)")
    m["umull"] = num(r"umull[^:]*:\s*(\d+)")
    m["tbnz"] = num(r"tbnz wN,#0x1f[^:]*:\s*(\d+)")
    m["cmp2p31"] = num(r"cmp\s+#0x80000000[^:]*:\s*(\d+)")
    m["sizeovf"] = num(r"'size overflow' -> (\d+) hit")
    m["funcs"] = num(r"functions containing >=1 bare 32-bit mul\s*:\s*(\d+)")
    m["text"] = num(r"__text\s*:\s*(\d+) bytes")
    return m, None


def main():
    builds = (sys.argv[1] if len(sys.argv) > 1 else "26.4,27.0.1").split(",")
    outdir = os.path.join(WD, "kexts")
    data = {}
    for b in builds:
        kc = KCACHE.get(b)
        if not kc or not os.path.exists(kc):
            print(f"!! {b}: no kernelcache")
            continue
        print(f"=== {b}: carving {kc}")
        hits = carve(kc)
        print(f"    matched {len(hits)} kexts: {[h[0] for h in hits]}")
        for name, blob in hits:
            d = os.path.join(outdir, b, name)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            with open(d, "wb") as f:
                f.write(blob)
            m, err = census(d)
            if err:
                print(f"    {name:12s} census failed: {err}")
                continue
            data.setdefault(name, {})[b] = m
            print(f"    {name:12s} {len(blob):>9,}B  mul32={m['mul32']:4d} smull={m['smull']:4d} "
                  f"tbnz={m['tbnz']:5d} cmp#2^31={m['cmp2p31']:3d} "
                  f"'size overflow'={m['sizeovf']:3d} fns_with_mul32={m['funcs']:4d}")
    print("\n=== DIFF (what Apple hardened between the two builds) ===")
    for name, per in data.items():
        ks = sorted(per.keys())
        if len(ks) < 2:
            continue
        a, b = per[ks[0]], per[ks[-1]]
        conv = a["mul32"] - b["mul32"]
        wide = (b["smull"] + b["umull"] + b["mul64"]) - (a["smull"] + a["umull"] + a["mul64"])
        print(f"  {name:12s} {ks[0]}->{ks[-1]}:  bare32 {a['mul32']}->{b['mul32']} "
              f"(converted {conv:+d})   64-bit widened {wide:+d}   "
              f"new 'size overflow' strings {a['sizeovf']}->{b['sizeovf']}   "
              f"new cmp#0x80000000 {a['cmp2p31']}->{b['cmp2p31']}")
    print("\nA kext with a big 'converted' count and new 'size overflow' strings is a kext where")
    print("Apple ADDED overflow guards to multiplies that were UNCHECKED in our 26.4 build.")


if __name__ == "__main__":
    main()
