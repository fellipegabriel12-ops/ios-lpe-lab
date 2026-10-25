#!/usr/bin/env python3
"""
o_c_sym.py - symbolize .ips frame offsets against a Mach-O from our own IPA.

.ips "imageOffset" is the offset from the image base. For arm64 the unslid
__TEXT vmaddr is 0x100000000, so a frame at imageOffset N belongs to the
function whose vmaddr covers 0x100000000 + N.
"""
import os
import sys
import zipfile

IPAS = {
    "CGPOC": r"G:\op lab\iphone-control\jailbreak\ci-out\dist9\CGPOC.ipa",
    "VT4":   r"G:\op lab\iphone-control\jailbreak\ci-out\dist8\VT4.ipa",
}
OFFSETS = [29744, 30772]


def load_binary(ipa, exe):
    dest = os.path.join(r"G:\op lab\iphone-control\jailbreak\.o_c", f"sym_{exe}")
    if not os.path.exists(dest):
        with zipfile.ZipFile(ipa) as z:
            name = [n for n in z.namelist() if n.endswith("/" + exe)][0]
            with z.open(name) as src, open(dest, "wb") as out:
                out.write(src.read())
    return dest


def main():
    import lief
    for label, ipa in IPAS.items():
        if not os.path.exists(ipa):
            print(f"{label}: no IPA at {ipa}")
            continue
        exe = "CGPOC" if label == "CGPOC" else "VT4"
        try:
            path = load_binary(ipa, exe)
        except Exception as e:
            print(f"{label}: extract failed {e}")
            continue
        try:
            b = lief.MachO.parse(path).at(0)
        except Exception as e:
            print(f"{label}: parse failed {e}")
            continue
        syms = []
        for s in b.symbols:
            if s.value and s.name and not s.name.startswith("l_"):
                syms.append((s.value, s.value + max(s.size, 4), s.name))
        syms.sort()
        print("=" * 70)
        print(f"{label}  ({os.path.getsize(path):,} bytes)  {len(syms)} symbols")
        for off in OFFSETS:
            va = 0x100000000 + off
            hit = None
            for lo, hi, nm in syms:
                if lo <= va < hi:
                    hit = (nm, va - lo)
                    break
            if hit:
                print(f"  +{off:<8} -> {hit[0]}  (+{hit[1]} into it)")
            else:
                near = [nm for lo, hi, nm in syms if abs(lo - va) < 0x2000]
                print(f"  +{off:<8} -> no symbol; nearby: {near[:4]}")


if __name__ == "__main__":
    main()
