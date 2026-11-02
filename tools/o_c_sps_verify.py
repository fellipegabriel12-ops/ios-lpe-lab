#!/usr/bin/env python3
"""
o_c_sps_verify.py  (O-C = session "jailbreak 3")

Parse our own crafted SPS back out of the generated .h264 files and print every
field, so we can PROVE the bit layout instead of trusting the writer.

Checks:
  * nal header (forbidden/nal_ref_idc/type)
  * profile_idc, constraint flags, level_idc
  * seq_parameter_set_id, log2_max_frame_num_minus4, pic_order_cnt_type,
    max_num_ref_frames, gaps flag
  * pic_width_in_mbs_minus1 / pic_height_in_map_units_minus1 and the derived
    pixel size
  * the 32-bit product and whether it lands on a small positive
  * the NAL sizes (no padding)
"""
import glob
import os
import sys

CH = os.path.dirname(os.path.abspath(__file__))


class R:
    def __init__(self, b):
        self.b = b
        self.i = 0

    def u(self, n):
        v = 0
        for _ in range(n):
            byte = self.b[self.i >> 3]
            v = (v << 1) | ((byte >> (7 - (self.i & 7))) & 1)
            self.i += 1
        return v

    def ue(self):
        z = 0
        while self.u(1) == 0:
            z += 1
            if z > 32:
                raise ValueError("bad ue(v)")
        v = 1
        for _ in range(z):
            v = (v << 1) | self.u(1)
        return v - 1


def annexb_nals(data):
    out, i = [], 0
    while True:
        j = data.find(b"\x00\x00\x00\x01", i)
        if j < 0:
            break
        k = data.find(b"\x00\x00\x00\x01", j + 4)
        if k < 0:
            out.append(data[j + 4:])
            break
        out.append(data[j + 4:k])
        i = k
    return out


def main():
    files = sorted(glob.glob(os.path.join(CH, "oc_*.h264")))
    if not files:
        print("no crafted streams in", CH)
        return 1
    for f in files:
        data = open(f, "rb").read()
        nals = annexb_nals(data)
        print(f"\n=== {os.path.basename(f)}  ({len(data)} bytes, {len(nals)} NALs) ===")
        for nal in nals:
            hdr = nal[0]
            ntype = hdr & 0x1F
            nref = (hdr >> 5) & 3
            if ntype != 25:
                print(f"   NAL type={ntype} ref={nref} len={len(nal)}")
                continue
            r = R(nal[1:])
            profile = r.u(8)
            cons = r.u(8)
            level = r.u(8)
            sps_id = r.ue()
            log2mfn = r.ue()
            poc = r.ue()
            refs = r.ue()
            gaps = r.u(1)
            w = r.ue()
            h = r.ue()
            mbs_only = r.u(1)
            direct8x8 = r.u(1)
            crop = r.u(1)
            vui = r.u(1)
            px_w, px_h = (w + 1) * 16, (h + 1) * 16
            exact = px_w * px_h
            prod = exact & 0xFFFFFFFF
            signed = prod - (1 << 32) if prod & 0x80000000 else prod
            print(f"   SPS len={len(nal)} profile={profile} constraints=0x{cons:02x} level_idc={level}")
            print(f"       sps_id={sps_id} log2_max_frame_num_minus4={log2mfn} "
                  f"pic_order_cnt_type={poc} max_num_ref_frames={refs} gaps={gaps}")
            print(f"       pic_width_in_mbs_minus1={w}  -> {w+1} MBs = {px_w} px")
            print(f"       pic_height_in_map_units_minus1={h} -> {h+1} MBs = {px_h} px")
            print(f"       frame_mbs_only={mbs_only} direct_8x8={direct8x8} crop={crop} vui={vui}")
            print(f"       EXACT product={exact}  32-bit={prod}  signed={signed} "
                  f"{'<== SMALL POSITIVE (passes the negative-only check)' if 0 < signed < 0x10000000 else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
