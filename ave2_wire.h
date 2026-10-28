/*
 * ave2_wire.h — reconstructed AppleAVE2UserClient wire format (CVE-2026-64747)
 *
 * Every offset below carries a citation to the decomp line it was read from.
 * Decomps live in:
 *   decomp_fixed/top/fffffff008644a38.c      (shared-mem/struct entry)
 *   decomp_fixed/dispatch/fffffff008645044.c (cmd-dispatch wrapper)
 *   decomp_fixed/dispatch/fffffff008640ff4.c (common-params wrapper)
 *   decomp_fixed/dispatch/fffffff008640348.c (common-params gate)
 *   decomp_fixed/dispatch/fffffff008523f40.c (configure-session handler)
 *   decomp_fixed/top/fffffff00851e9b4.c      (init-info copy)
 *   decomp_fixed/top/fffffff00851e194.c      (AVE_Client_Enc_Check / clamp)
 * Register-level arg confirmation: dispatch/dissite.txt (fun 645044 tail, fun 523f40 head).
 *
 * Fixed kext: AppleAVE2 905.40.1 (this host, 26.6.2). Ghidra program base = boot addr.
 * UNKNOWN = not present in the fixed-kext decomps we produced; marked, never fabricated.
 */

#ifndef AVE2_WIRE_H
#define AVE2_WIRE_H

#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Transport-level entry (one specific selector → FUN_fffffff008644a38)
 *
 * FUN_fffffff008644a38 receives IOExternalMethodArguments *args as param_3:
 *   +0x30  structureInput      ptr   (644a38.c:29  "*(undefined8 **)(param_3 + 0x30)")
 *   +0x38  structureInputSize  u32   (644a38.c:30  "*(uint *)(param_3 + 0x38)")
 *   +0x40  structureInputDescriptor IOBufferMemoryDescriptor*
 *                              fallback when structureInput==NULL
 *                                    (644a38.c:31  "*(long **)(param_3 + 0x40)")
 *   +0x58  structureOutput     ptr   (644a38.c:82  "*(undefined8 **)(param_3 + 0x58)")
 *   +0x60  structureOutputSize u32   (644a38.c:84  "*(uint *)(param_3 + 0x60)")
 *
 * Size gates (644a38.c:83-84):
 *   structureInputSize  must be >= AVE2_INBUF_MIN  (0x1a0a0)
 *   structureOutputSize must be >= AVE2_OUTBUF_MIN (0x20)
 *
 * Output echo (644a38.c:103-110): out[0]=in[0], out[1]=in[1], out[2]=in[2],
 *   *(u32*)(out+0x18) = return status of the inner dispatch.
 * ------------------------------------------------------------------------- */
#define AVE2_INBUF_MIN   0x1a0a0u   /* 644a38.c:83 "uVar4 < 0x1a0a0" */
#define AVE2_OUTBUF_MIN  0x20u      /* 644a38.c:84 "*(uint *)(param_3 + 0x60) < 0x20" */

/* ---------------------------------------------------------------------------
 * Command buffer layout (0x1a0a0 bytes, userspace → kernel)
 *
 * Offset map derived from FUN_fffffff008645044 (cmd dispatch) + the register
 * trace of its tail call into FUN_fffffff008523f40:
 *
 *   dissite.txt @ 645478-645488:
 *     ldr x0,[x19,#0x160]      ; session object stored on the UC at +0x160
 *     add x1,x20,#0x18         ; x20 = inbuf  → arg1 = inbuf+0x18
 *     add x2,x20,#0x228        ; arg2 = inbuf+0x228
 *     add x3,x20,#0x338        ; arg3 = inbuf+0x338  → becomes cmd struct for 51e9b4
 *     add x4,x20,#0x28         ; arg4 = inbuf+0x28   → log-name ptr (523f40: used
 *                              ;   only as csel fallback for "%s" @ session+0x68)
 *
 * Header fields, validated by FUN_fffffff008640348 (common-params gate).
 * NOTE: 640348 receives the WHOLE inbuf as param_3: 645044 calls 640ff4 which
 * calls 640348(param1,param2,param_3=inbuf) — 640ff4.c:27 "FUN_fffffff008640348
 * (param_1,param_2)" with param_3 passed through from 640ff4's own param_3=inbuf.
 * ------------------------------------------------------------------------- */
struct ave2_cmdbuf_header {
    uint64_t echo0;   /* +0x00  echoed to output word 0            (644a38.c:103-110) */
    uint64_t echo1;   /* +0x08  echoed to output word 1            (644a38.c:106-109) */
    int64_t  dataCnt; /* +0x10  MUST be >= 0 (signed 64)           (640348.c:9  "wrong data count") */
    int64_t  mode0;   /* +0x18  MUST be >= 0 (signed 64)           (640348.c:26 "wrong mode";
                                                                    also passed as arg1 to 523f40
                                                                    (dissite.txt:64547c add x1,x20,#0x18)) */
    int64_t  mode1;   /* +0x20  MUST be >= 0 (signed 64)           (640348.c:26 "wrong mode") */
    uint8_t  name_or_pad[0x228 - 0x28]; /* +0x28..+0x227 : inbuf+0x28 is used as a "%s"
                                           log-name pointer when non-NULL
                                           (dissite.txt 645488 + 523f40.c:67: FUN_5f71f0
                                           (session+0x68,0x200,"%s") with arg4));
                                           keep zeroed = safe NULL */
    uint8_t  pad_228[0x338 - 0x228];    /* inbuf+0x228 passed as arg2 to 523f40 → lands in
                                           FUN_62afcc(session+0x2d0, arg2) — surface-info
                                           out buffer (523f40.c:85). Contents UNKNOWN (not
                                           read by any fixed-path decomp we have). Kept zeroed. */
};
/* sanity: header spans 0x00..0x337 */
_Static_assert(sizeof(struct ave2_cmdbuf_header) == 0x338, "header must be 0x338 bytes");

/* ---------------------------------------------------------------------------
 * Session-configure command struct — starts at inbuf + AVE2_CMD_STRUCT_OFF
 *
 * Source: the struct base pointer = arg3 of FUN_523f40 = inbuf+0x338
 *   (dissite.txt:645484 "add x3,x20,#0x338"; 523f40.c:18 "mov x2,x23" then
 *    523f40.c:68 "FUN_fffffff00851e9b4(param_1,1,param_4)" where param_4=x23).
 *
 * AVE_Client_Enc_Check (51e194.c) validates fields RELATIVE to this struct:
 *   +0x18    s32  priority    (u32)(priority + 100) < 0x12d   (51e194.c:13
 *                              "*(int *)(param_3 + 0x18) + 100U < 0x12d")
 *   +0xa58   s32  width       w*h > 0x1ffe0000 → 0xfffffc17   (51e194.c:14-15)
 *   +0xa5c   s32  height      same gate                       (51e194.c:14-15)
 *   +0x2ecc  s32  encType     if client(session+0x268)==1: must equal session+0x270
 *                              (51e194.c:33)
 *   +0x2cc4  u32  slices      (slices-1) < 0x20               (51e194.c:50)
 *
 * Struct → session memcpy map in FUN_51e9b4 (param_3 = this struct):
 *   +0x0000  0x300   → session+0x1538   (51e9b4.c:31)
 *   +0x0a58  0x2460  → session+0x1838   (51e9b4.c:32)  ← width/height live at head
 *   +0x2eb8  0x4e0   → session+0x3c98   (51e9b4.c:33)
 *   +0x300   0x2d0   → session+0x0de0   if session+0x268 == 3  (51e9b4.c:67-68)
 *   +0x300   0x28    qwords→session+0xde0.. if session+0x268 == 4 (51e9b4.c:57-65)
 *   +0x3398  0x2fcc  → session+0x5c28   if [cmd+0x2eb8+0x14 =3cac]==2 (51e9b4.c:38-39)
 *   +0x6364  0x3cf8  → session+0x8bf4       "       (51e9b4.c:40)
 *   +0xa05c  0x4b40  → session+0xc8ec       "       (51e9b4.c:41)
 *   +0xeba0  0x53f0  → session+0x11430      "       (51e9b4.c:42)
 *   +0x13f90 0x5dd8  → session+0x16820      "       (51e9b4.c:43)
 *   +0x3398  0x6b4   → session+0x4ad0   if [cmd+0x2eb8+0x14]==1  (51e9b4.c:47-48)
 *   +0x3a4c  0x180   → session+0x5184       "       (51e9b4.c:49)
 *   +0x3bcc  0x924   → session+0x5304       "       (51e9b4.c:50)
 *   ([cmd+0x2eb8+0x14] == client mode byte read at session+0x3cac:
 *     51e9b4.c:38 "*(int *)(param_1 + 0x3cac) == 2" — param_1=session here,
 *     so mode field index into session; the cmd-side mirror lives inside the
 *     +0x2eb8 block copied earlier — offset within cmd = 0x2eb8+0x14 = 0x2ecc)
 *
 * Max extent touched by 51e9b4 from this struct:
 *   mode 2 → 0x13f90+0x5dd8 = 0x19d68 (fits under inbuf end 0x338+0x19d68 = 0x1a0a0 — exactly
 *           why the min input size is 0x1a0a0!)
 *   mode 1 → 0x3398 .. 0x44f0
 * ------------------------------------------------------------------------- */
#define AVE2_CMD_STRUCT_OFF   0x338u       /* dissite.txt:645484 (add x3,x20,#0x338) */

/* field offsets RELATIVE to inbuf (already including the +0x338 base) */
#define AVE2_OFF_PRIORITY     (AVE2_CMD_STRUCT_OFF + 0x18u)   /* 51e194.c:13  → 0x350  */
#define AVE2_OFF_WIDTH        (AVE2_CMD_STRUCT_OFF + 0xa58u)  /* 51e194.c:14-15 → 0xd90 */
#define AVE2_OFF_HEIGHT       (AVE2_CMD_STRUCT_OFF + 0xa5cu)  /* 51e194.c:14-15 → 0xd94 */
#define AVE2_OFF_ENCTYPE      (AVE2_CMD_STRUCT_OFF + 0x2eccu) /* 51e194.c:33  → 0x3204 */
#define AVE2_OFF_SLICES       (AVE2_CMD_STRUCT_OFF + 0x2cc4u) /* 51e194.c:50  → 0x2ffc */

#define AVE2_CLAMP_PRODUCT    0x1ffe0000ULL /* 51e194.c:15 "0x1ffe0000 < (long)w * (long)h" */

/* External-method selector table — decoded from the AppleAVE2UserClient
 * metaclass __const block (metaclass ctor dispatch/fffffff008642b04.c sets the
 * vtable at 0x7dc1780; method rows follow at 0x7dc1800+0x10, stride 0x18 =
 * {func, checkStructureInputSize<<32, checkStructureOutputSize<<32}).
 * Verified LIVE on this host: exact in/out sizes below all pass the IOKit
 * shape gate (evidence/run3_session.txt Phase D2).
 * funcs carry a +0x4000 PAC-decode quirk (raw suffix | fffffff008600000 + 0x4000).
 */
#define AVE2_SEL_DESTROY            2u   /* row1 f 643978 in 0x28 out 0x20 — inner calls
                                            FUN_64b040 = session teardown (643cc8.c:64) */
#define AVE2_SEL_UNK3               3u   /* row2 f 64417c in 0x38 out 0x20 */
#define AVE2_SEL_CONFIGURE          4u   /* row3 f 644a38 in 0x1a0a0 out 0x20 ★ CVE entry */
#define AVE2_SEL_UNK5               5u   /* row4 f 64150c in 0x1a0b0 out 0x150 */
#define AVE2_SEL_VERB6              6u   /* row5..9: in 0x30 out 0x20 (Start/Stop/Process?/
                                            Complete/Flush/Reset family — verb mapping
                                            UNKNOWN, not needed for the clamp path) */


/* session-object (kernel side) offsets — informational, from 51e194/51e9b4:
 *   session+0x268 s32 clientType   (51e194.c:11, valid range 1..5 per "iVar1 - 1U < 5")
 *   session+0x270 s32 encType      (51e194.c:33)
 *   session+0x274 s32 state        must be 1 for configure (523f40.c:45)
 *   uc+0xd8       driver backptr   (645044.c:42 "wrong state" check)
 *   uc+0x160      session ptr      (645044.c:42 "wrong state" check)
 *   uc+0xe8/0xf0  clientType/mode cached on UC, fed to 640ff4 as scalar args
 *                 (dissite.txt: args were *(u32*)(uc+0xe8), *(u32*)(uc+0xf0))
 *
 * Session CREATE: which selector populates uc+0x160 is UNKNOWN in the produced
 * fixed-kext decomps (dispatch-table region lands in kernel-slid LINKEDIT and is
 * not statically decodable from the on-disk kext). Live probe determines it:
 *   - if the 644a38-path selector returns 0xfffffc0d ("wrong state") with a
 *     well-formed 0x1a0a0 buffer → session NOT pre-created at open.
 *   - 0xfffffc17 with sane header + oversized dims → reached the clamp = WIN.
 */

/* scalar status / return codes observed on the fixed path */
#define AVE2_RET_BADARG_WRAPPERS  0xfffffc17u /* gate/validation family (640348.c:12,
                                                640ff4.c:24, 51e194.c:18 clamp HIT,
                                                523f40.c:42) */
#define AVE2_RET_WRONG_STATE      0xfffffc0du /* 645044.c:58 (no session attached) */
/* Session-create (sel1, in>=0x920 / out>=0x28) — validated in:
 *   FUN_fffffff008643478 (dispatch/fffffff008643478.c)  inner of sel1 wrapper
 *   FUN_fffffff008640538 (dispatch/fffffff008640538.c)  input-params gate
 * Layout:
 *   +0x10/+0x18/+0x20 s64 >= 0            (640348 common gate, 640538.c:31)
 *   +0x28 char[15] must == kext version string "905.40.1" (640538.c:33
 *            func_0xa653010(param_3 + 0x28,"905.40.1",0xf)) — mismatch → 0xfffffc09
 *   +0x8c  DPM config sub-struct → FUN_55a390→55a334(+0x90) (640538.c:57):
 *            zeros PASS (lane loop sees no set bits)
 *   +0xac  DLB config sub-struct → FUN_631f30 (640538.c:55):
 *            *(u32*)(+0xac) <= 6 (count), *(u32*)(+0xb0) < 3; zeros PASS
 *   +0x808 u64 log-index — must EXCEED the static counter (monotonic) else
 *            0xfffffc18 from FUN_5d4ee4 (dispatch/fffffff0085d4ee4.c: "if
 *            (DAT_fffffff00b37abd0 < param_1)"; called from 643478.c:87 with
 *            param_1 = *(u64*)(in+0x808))
 *   +0x810 log config: *(s32*)(+0x910) >= 1 (level) AND *(s32*)(+0x914) > 0
 *            (count) else 0xfffffc17 / live log "wrong log configuration".
 *            VERIFIED BY DISASM: fffffff0085d4ebc: ldr w9,[+0x100]; w9<1 →
 *            0xfffffc17; ldr w8,[+0x104]; w8>0 → 0 else 0xfffffc17.
 *            (dispatch/dissite.txt; Ghidra decomp had the condition inverted)
 *   +0x918 s32 encodeType: live assertion "AVE_EncType_None < eEncType &&
 *            eEncType < AVE_EncType_Max" (kernel log AVE_UCCmd_CheckParam_Open:101)
 *            i.e. encType >= 1 — even though 640538.c:61 shows "(x-1) < 3".
 *   +0x38  session-create params passed to AVE create (643478.c:86 + 89:
 *            FUN_64abf4(uc, in+0x38, *(u32*)(in+0x918)))  CONTENT UNKNOWN —
 *            sub-struct fields not pinned in fixed-kext decomps; the inner
 *            AVE_Client_Create still rejects content with -1001/BadArgument
 *            after the above gates pass (live evidence).
 * Outputs (wrapper 642e7c.c:107-112 + inner 643478.c:90-91):
 *   out+0x00 u64 = uc+0xf8  = SESSION COOKIE/handle
 *   out+0x08     = echo in+0x08
 *   out+0x10     = echo in+0x10
 *   out+0x18 s32 = status
 *   out+0x20 u64 = uc+0xe8  (driver-side id)
 */
#define AVE2_SEL_CREATE          1u
#define AVE2_CREATE_IN_SIZE      0x920u   /* 642e7c.c:84 "uVar5 < 0x920" */
#define AVE2_CREATE_OUT_SIZE     0x28u    /* 642e7c.c:85 "< 0x28" */
#define AVE2_CREATE_OFF_VERSION  0x28u    /* 640538.c:33 */
#define AVE2_CREATE_OFF_ENCTYPE  0x918u   /* 640538.c:61 */

/* ---------------------------------------------------------------------------
 * MODE-5 / HEVC-10bit-multipass LRB overflow path (decomp_more/fffffff0084ccdac.c)
 *
 * The overflowing calculator is FUN_fffffff0084eedf8 (fixed; vuln twin
 * FUN_fffffff0084e5ae8) invoked ONLY from FUN_fffffff0084ccdac with
 * param_2==5 (LRB, multipass family — all sibling calculators in that caller
 * also pass literal 5):
 *   FUN_4eedf8(codec, 5, mode=*(session+0x3cac),
 *              p4=w=*(session+0x1838),  p5=h=*(session+0x183c),
 *              p6=local_7c, p7=bVar5&1=*(session+0x3bb8)&1,
 *              p8=local_74, p9=bVar3&1=*(session+0x3a74)&1, out)
 * w/h land at session+0x1838/+0x183c via 51e9b4.c:32 memcpy of
 * cmd(+0x338)+0xa58.. — i.e. inbuf+0xd90/+0xd94 (CONFIRMED).
 *
 * Overflow requires (brute_lrb5_final.py, re-verified): p9=0, p6=2, p8=10
 *   => w=64656 h=8080 gives c0=c2=0x3f400000, total = 0x80000000 (sign bit).
 * In 4ccdac's terms that means session fields:
 *   session+0x3a74 bit0 = 0          (bVar3&1 = 0 -> p9=0)
 *   session+0x3a64 = 2 (p6 chroma 4:2:0), session+0x3a68 = 10 (p8 10-bit)
 * which map back to the sel4 configure cmd struct (51e9b4.c:32,
 * session+0x1838 <= cmd+0xa58):
 *   p6 (session+0x3a64) = cmd+0x2c2c = inbuf+0x2f64  (chroma; 2 = 4:2:0)
 *   p8 (session+0x3a68) = cmd+0x2c30 = inbuf+0x2f68  (bit depth; 10 = 10-bit)
 *   p9flag (sess+0x3a74) = cmd+0x2c3c = inbuf+0x2f74 (byte, bit0 must be 0)
 *   p7 (session+0x3bb8) = cmd+0x3180 = inbuf+0x34b8  (don't-care)
 * Codec-info gates (decomp_more/check_AVE_{AVC,HEVC}_CheckInfo_*.c):
 *   iNumViews  = cmd+0x2df8 = inbuf+0x3130  must be in {1,2}  (AVC:469/HEVC same)
 *   iNumLayers = cmd+0x2df4 = inbuf+0x312c  must be in {1,2}
 *   HEVC only: chroma fmt u32 @ cmd+0x6528 = inbuf+0x6860 must be valid (FUN_63fb2c),
 *              sublayers u32 @ cmd+0x268 = inbuf+0x5a0 < 9.
 * UNKNOWN (honest): the static dispatch (LINKEDIT table @fffffff00b4c8000)
 * that picks calc fn 4ccdac (vs 85888a0 p2==3 / 863f2c8 p2==2 / 852e880 p2==4)
 * from session fields is not decoded — see FIRE_READY.md. The fields above are
 * the best-known knobs; the configure is issued via the ASYNC trap (kernel log
 * IO_Config:337 requires asyncWakePort != nullptr && asyncReferenceCount > 0).
 * ------------------------------------------------------------------------- */
#define AVE2_MODE5_OFF_P6     0x2f64u  /* inbuf abs: p6 (chroma; 2 = 4:2:0)      */
#define AVE2_MODE5_OFF_P8     0x2f68u  /* inbuf abs: p8 (bit depth; 10 = 10-bit) */
#define AVE2_MODE5_OFF_P9FLAG 0x2f74u  /* inbuf abs: byte, bit0 must be 0        */
#define AVE2_MODE5_OFF_P7     0x34b8u  /* inbuf abs: p7 flag (don't-care)        */
#define AVE2_OFF_NUMVIEWS     0x3130u  /* inbuf abs: iNumViews  in {1,2} (AVC:469) */
#define AVE2_OFF_NUMLAYERS    0x312cu  /* inbuf abs: iNumLayers in {1,2}         */

#define AVE2_RET_VERSION_MISMATCH 0xfffffc09u /* 640538.c:53 */

#endif /* AVE2_WIRE_H */
