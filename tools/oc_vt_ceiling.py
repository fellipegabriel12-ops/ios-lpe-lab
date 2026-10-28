#!/usr/bin/env python3
"""
oc_vt_ceiling.py  (O-C = session "jailbreak 3") - runs inside a-Shell on the iPhone.

Measures VideoToolbox's REAL client-side dimension ceiling on iOS 26.4, because
the AppleAVE2 overflow multiply is width x height:

    mul w24, w22, w21   (fn#152) = width * height
    65537 * 65537 = 0x1_0002_0001 -> 0x0002_0001 (131073) in 32 bits
    65536 * 65536 = 0x1_0000_0000 -> 0x0000_0000 (ZERO) in 32 bits

and the size that comes out of that multiply is allocated with a NEGATIVE-only
check (ldr w8,[x19,#0x16c] ; tbnz w8,#0x1f,fail) - so a wrapped-to-small value
passes and the encoder/decoder writes outside the allocation.

Sweeps the encoder at a ladder of dimensions, for H264 and HEVC, and for the
DPBMode values the sibling identified (fn#152 skips the cap when the mode byte
is not in {2,3}, and the caller fn#660 skips it when w20 == 0xb).

Output goes to stdout AND to oc_vt_ceiling_out.txt so the rig can pull it.
"""
import ctypes
import os
import sys
import time

OUTS = ["/var/mobile/Media/Downloads/oc_vt_ceiling_out.txt",
        os.path.join(os.getcwd(), "oc_vt_ceiling_out.txt")]
log = []


def say(s):
    s = str(s)
    log.append(s)
    try:
        sys.stdout.write(s + "\n")
        sys.stdout.flush()
    except Exception:
        pass
    for p in OUTS:
        try:
            f = open(p, "a")
            f.write(s + "\n")
            f.flush()
            f.close()
            break
        except Exception:
            pass


try:
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    vt = ctypes.CDLL("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox")
except Exception as e:
    say("LOAD FAILED: %r" % (e,))
    raise SystemExit(1)

cf.CFStringCreateWithCString.restype = ctypes.c_void_p
cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
cf.CFDictionaryCreate.restype = ctypes.c_void_p
cf.CFDictionaryCreate.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                  ctypes.POINTER(ctypes.c_void_p), ctypes.c_long,
                                  ctypes.c_void_p, ctypes.c_void_p]
cf.CFRelease.argtypes = [ctypes.c_void_p]
vt.VTCompressionSessionCreate.restype = ctypes.c_int32
vt.VTCompressionSessionCreate.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_int32,
                                          ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_void_p]
try:
    vt.VTCompressionSessionInvalidate.argtypes = [ctypes.c_void_p]
except Exception:
    pass

H264, HEVC = 0x61766331, 0x68766331
DIMS = [(4096, 2160), (8192, 8192), (16384, 16384), (32768, 32768),
        (32769, 32769), (54000, 54000), (65536, 65536), (65537, 65537),
        (65537, 2160), (16384, 65537)]
MODES = [0, -1, 2, 3]


def cfs(s):
    return cf.CFStringCreateWithCString(None, s.encode(), 0x08000100)


def cfb(v):
    try:
        return ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue" if v else "kCFBooleanFalse")
    except Exception:
        return cfs("true" if v else "false")


def cfd(pairs):
    n = len(pairs)
    ks = (ctypes.c_void_p * n)()
    vs = (ctypes.c_void_p * n)()
    for i, (k, v) in enumerate(pairs):
        ks[i] = k
        vs[i] = v
    d = cf.CFDictionaryCreate(None, ks, vs, n, None, None)
    for k, v in pairs:
        cf.CFRelease(k)
        if isinstance(v, int):
            cf.CFRelease(v)
    return d


def try_create(w, h, codec, props):
    sess = ctypes.c_void_p()
    st = vt.VTCompressionSessionCreate(None, w, h, codec, None, props, None, None, None,
                                       ctypes.byref(sess))
    if st == 0 and sess:
        try:
            vt.VTCompressionSessionInvalidate(sess)
        except Exception:
            pass
        cf.CFRelease(sess)
    return st


def props_for(codec, mode):
    prof = 0x0A000000 if codec == HEVC else 0x640028
    pairs = [(cfs("ProfileLevel"), ctypes.c_int32(prof)),
             (cfs("AllowFrameReordering"), cfb(True)),
             (cfs("RealTime"), cfb(True))]
    if mode is not None:
        pairs.append((cfs("DPBMode"), ctypes.c_int32(mode)))
    return cfd(pairs)


say("=== oc_vt_ceiling %s ===" % time.strftime("%H:%M:%S"))
say("(VT status 0 = accepted; the kext only sees dims the client passed through)")
for codec, cname in ((HEVC, "HEVC"), (H264, "H264")):
    for mode in MODES:
        pr = props_for(codec, mode)
        say("--- %s  DPBMode=%d ---" % (cname, mode))
        for (w, h) in DIMS:
            st = try_create(w, h, codec, pr)
            area = (w * h) & 0xFFFFFFFF
            flag = "  <== 32-bit product %d" % area if area < 0x10000 else ""
            say("  %6d x %-6d -> st=%-8d area32=%d%s" % (w, h, st, area, flag))
        cf.CFRelease(pr)
say("DONE")
