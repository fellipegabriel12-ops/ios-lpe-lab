#!/usr/bin/env python3
"""
o_c_aved_hunt.py  (O-C = session "jailbreak 3")

Three questions, answered against OUR OWN 26.4 binaries (offline, no device):

Q1  CVE-2026-84607 (AVEVideoEncoder race -> arbitrary kernel code execution from a
    sandboxed app, fixed in 26.7, so LIVE on 26.4). The public fix shape is:
        ldr w8, [x22, #0x58]   ; client  eEncType
        ldr w9, [x19, #0x270]  ; session sEnc.eType
        cmp w8, w9
        b.ne -> divert
    and the literal string "EncType mismatch with session" appears in the fixed
    build and NOT in the vulnerable one. So: does our 26.4 AppleAVE2 contain that
    string, and does it contain ANY atomics (the fixed build has none in 475k
    instructions, which is what makes the race exploitable)?

Q2  The DECODER kext is not AppleAVE2 - it is AppleAVD, and it has its own
    documented kernel-memory-corruption CVEs (CVE-2026-84520 buffer overflow,
    CVE-2026-65407 UAF, CVE-2026-84571, CVE-2026-84620 integer overflow,
    CVE-2026-84561 double free, CVE-2026-65415 race) - ALL unpatched on 26.4 and
    reachable from plain VideoToolbox with no entitlement. Carve AppleAVD out of
    the 26.4 kernelcache and census it.

Q3  Is there a width*height (or any) multiply in the DECODER kext whose result
    is checked for negativity only? That is the exact shape of the encoder bug we
    already have, and if the decoder has the same shape it is a *new* primitive
    nobody has published.

Usage:
  python o_c_aved_hunt.py --kcache <26.4 kernelcache> [--compare <27.0.1 kernelcache>]
"""
import argparse
import os
import re
import struct
import sys

WD = r"G:\op lab\iphone-control\jailbreak"
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
# mach-o filetypes: 11 = MH_KEXT_BUNDLE (what prelinked kexts actually carry in
# an iOS kernelcache - the 13/14 values that float around in blog posts are not
# the ones Apple ships), 14 = MH_KEXT, 12 = MH_FILESET (the kernelcache itself).
FILETYPE_KEXT = 0x0000000E
FILETYPE_KEXT_BUNDLE = 0x0000000B
CENSUS_TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ave2_census.py")


# ------------------------------------------------------------------ macho
def iter_macho_headers(buf):
    # MH_MAGIC_64 little-endian = CF FA ED FE. find() is ~100x faster than
    # stepping 4 bytes at a time over a 72 MB kernelcache.
    magic = b"\xcf\xfa\xed\xfe"
    pos = 0
    while True:
        pos = buf.find(magic, pos)
        if pos < 0:
            return
        off = pos
        pos += 4
        if off + 32 > len(buf):
            return
        cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
            "<iiIIIII", buf, off + 4)
        yield off, {"cputype": cputype, "filetype": filetype, "ncmds": ncmds,
                    "sizeofcmds": sizeofcmds}


def macho_extent(buf, off, hdr):
    end = off + 32
    p = off + 32
    for _ in range(hdr["ncmds"]):
        if p + 8 > len(buf):
            break
        cmd, cmdsize = struct.unpack_from("<II", buf, p)
        if cmd == LC_SEGMENT_64:
            segoff, vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQQ", buf, p + 8 + 8)
            end = max(end, off + fileoff + filesize)
        p += cmdsize
    return end


def carve_kexts(kcache_path):
    """Carve every KEXT/KEXT_BUNDLE image out of the kernelcache."""
    buf = open(kcache_path, "rb").read()
    out = []
    for off, hdr in iter_macho_headers(buf):
        if hdr["filetype"] not in (FILETYPE_KEXT, FILETYPE_KEXT_BUNDLE):
            continue
        end = macho_extent(buf, off, hdr)
        blob = buf[off:end]
        if len(blob) < 20000:
            continue
        out.append((off, blob))
    return out


def cstrings(blob):
    """Pull printable ASCII runs >= 4 chars (crude, but enough for markers)."""
    return re.findall(rb"[\x20-\x7e]{4,}", blob)


# ------------------------------------------------------------------ analysis
def census(blob):
    m = {
        "bytes": len(blob),
        "mul32": 0, "mul64": 0, "smull": 0, "umull": 0,
        "tbnz_sign": 0, "cmp_2p31": 0, "atomics": 0,
    }
    # arm64 opcode patterns (little endian, 4-byte instructions)
    for i in range(0, len(blob) - 4, 4):
        w = blob[i:i + 4]
        op = w[3]
        # MUL (32-bit): 0b0011_0010_xxx1_0000 | 0b0011_1010_xxx1_0000
        if (w[3] & 0xFE) == 0x22 and (w[2] & 0x20):
            m["mul32"] += 1
        elif (w[3] & 0xFE) == 0x22 and (w[2] & 0x30) == 0x30:
            m["mul64"] += 1
        # SMULL/UMULL: 0b0011_0011_xxx1_0000 / 0b0011_1011_xxx1_0000
        elif (w[3] & 0xFE) == 0x23 and (w[2] & 0x20) == 0x20:
            m["smull"] += 1
        elif (w[3] & 0xFE) == 0x23 and (w[2] & 0x30) == 0x30:
            m["umull"] += 1
        # LDXR/STXR/LDAXR/STLXR/CAS/SWP atomics
        if (w[3] & 0x3F) == 0x08 and (w[2] & 0xE0) in (0x00, 0x20, 0x40, 0x60):
            # ldaxr/stlxr/ldxr/stxr family
            if w[0] in (0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78):
                m["atomics"] += 1
    # textual markers
    txt = b" ".join(cstrings(blob))
    m["enc_mismatch"] = txt.count(b"EncType mismatch")
    m["mismatch_any"] = txt.count(b"mismatch")
    m["size_overflow"] = txt.count(b"size overflow")
    m["data_overflow"] = txt.count(b"data overflow")
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kcache", default=os.path.join(
        WD, "kcache-26.4", "23E246__iPhone17,3", "kernelcache.release.iPhone17,3"))
    ap.add_argument("--compare", default=os.path.join(
        WD, "kcache-27.0.1", "24A446__iPhone17,3", "kernelcache.release.iPhone17,3"))
    ap.add_argument("--out", default=os.path.join(WD, "ave2-analyze", "aved-hunt.txt"))
    a = ap.parse_args()

    lines = []

    def say(s=""):
        print(s, flush=True)
        lines.append(s)

    for tag, kc in (("26.4", a.kcache), ("27.0.1", a.compare)):
        if not kc or not os.path.exists(kc):
            say(f"!! {tag} kernelcache missing: {kc}")
            continue
        say("=" * 78)
        say(f"{tag}: {kc}  ({os.path.getsize(kc):,} bytes)")
        kexts = carve_kexts(kc)
        say(f"  carved {len(kexts)} kext images")
        picks = {}
        for off, blob in kexts:
            txt = b" ".join(cstrings(blob))
            for name, markers in (("AppleAVD", (b"AppleAVD", b"CAVDAvcDecoder", b"AVC_RBSP")),
                                  ("AppleAVE2", (b"AppleAVE2", b"AVE_CalcBufSize")),
                                  ("AppleAVF", (b"AppleAVF",)),
                                  ("IOSurface", (b"IOSurface",)),
                                  ("AGXG17P", (b"AGXG17P",)),
                                  ("IOGPUFamily", (b"IOGPUFamily",))):
                if any(m in txt for m in markers):
                    picks.setdefault(name, blob)
        for name, blob in picks.items():
            c = census(blob)
            say(f"  --- {name}: {c['bytes']:,} bytes")
            say(f"      'EncType mismatch'={c['enc_mismatch']}  'mismatch'={c['mismatch_any']}  "
                f"'size overflow'={c['size_overflow']}  'data overflow'={c['data_overflow']}")
            # delegate the instruction-level census to the accurate tool
            tmp = os.path.join(WD, ".o_c", f"carved_{name}")
            with open(tmp, "wb") as f:
                f.write(blob)
            try:
                r = subprocess.run([sys.executable, CENSUS_TOOL, tmp],
                                   capture_output=True, text=True, timeout=900)
                txt = r.stdout + r.stderr
                for line in txt.splitlines():
                    if any(k in line for k in ("mul ", "smull", "umull", "tbnz", "cmp  #0x80000000",
                                               "functions containing", "instructions:", "__text")):
                        say("      " + line.strip())
            except Exception as e:
                say(f"      census failed: {e}")
            if name == "AppleAVE2":
                say(f"      >> CVE-2026-84607: the fixed build contains 'EncType mismatch with session';")
                say(f"         our build has it {c['enc_mismatch']} time(s) -> "
                    f"{'FIX ABSENT => the race window is open on 26.4' if c['enc_mismatch'] == 0 else 'fix present'}")
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    say(f"\nwrote {a.out}")


if __name__ == "__main__":
    raise SystemExit(main())
