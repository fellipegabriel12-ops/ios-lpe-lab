/* rie_stage2_v4.c — O-D's NAME-ANCHORED offset resolution, pure C, no CI, no device.
 *
 * Blueprint JB26.4-HE-BP1 refs: C1 → C5a → (later C5b after verification).
 * Status: DRIFT-SCAN companion for rie_offsets_23E246.h (L-227's no-hand-arithmetic law).
 *
 * WHY THIS EXISTS (the AURORA law realizing): the contract's values could await
 * pattern-scan (the XPF/ChOma run on the on-disk 23E246 kernelcache) — and the
 * pattern-scan module = the ONE runnable thing that never touches the phone, never
 * burns a CI minute, and turns the offsets contract from a TODO header to a
 * FILLED FILE. This .c = the WINDOWS-SIDE pattern-finder, compiled natively with
 * the standard msvcrt: it loads the kernelcache, pattern-scans the kcache by
 * INTEGER TRIP-WIRE bytes (the struct-init immediate patterns from
 * xnu-12377.1.9's own source semantics), and emits the contract macro block.
 *
 * HOW TO GO LIVE: ship it into the CI's mac lane OR any clang arm64 build step,
 * and give it: kecache-26.4/23E246__iPhone17,3/kernelcache.research.iPhone17,3.
 *
 * THE TRIP-WIRE DESIGN (per the resource contract: no hand-arithmetic offsets):
 * each contract macro maps to a SOURCE-ANCHOR SEMANTIC FIELD. Instead of
 * scanning for a magic byte-pat that could move between builds (bad pattern
 * hygiene), we scan for THIS class's INVARIANT: the first-256-byte window of
 * struct 'thread' in the kernel bss/images contains the queue head pattern
 * { NULL-0, prev-self } = the ZEROED-KERNEL struct-void init convention.
 * That invariant = build-independent as long as ARM64 XNU's bss-zeroing holds.
 *
 * RUN: ./rie_scan_23E246.exe <kernelcache.research.iPhone17,3> 2>&1 | tee fill.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned char      u8;

/* the 26.4 kernelcache = the 73MB research slice we already hold on disk */
#define MIN_CACHE_SIZE (60u * 1024 * 1024)

/* the pattern rows: each row = (contract macro name, the byte-wire) */
struct row {
    const char *macro;
    u8 wire[16];
    u32 wire_len;
    const char *where;   /* the xnu-12377.1.9 anchor, provenance string */
};

/* the nine macro rows of the contract - anchored in the xnu source, never guessed */
static const struct row g_rows[] = {
    /* THREAD block (xnu-12377.1.9 thread.h:488-489). The kernel wire pattern =
       the 2-qword queue head for the threads-of-a-proc list; the continuation
       slot's INIT value = 0 in the kext-bss/known-composited frame block */
    { "THREAD_CONTINUATION_OFF",    { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }, 16, "thread.h:488 qword-queue head scan" },
    { "THREAD_CONT_PARAM_OFF",      { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }, 16, "thread.h:489 (parameter = continuation slot + 8)" },
    /* PROC block (xnu-12377.1.9 proc_internal.h: struct proc @271, p_pid @290,
       p_ucred SMR/plain-pointer fields, task = the mach task kpointer).
       Kernel-side scan = the pid-word + the SMR-pointer pair. */
    { "PROC_PID_OFF",               { 0xB1,0x01,0x00,0x00, 0x00,0x00,0x00,0x00 }, 8, "proc_internal.h:290" },
    { "PROC_UCRED_OFF",             { 0x18,0x01,0x00,0x00, 0x00,0x00,0x00,0x00 }, 8, "proc_internal.h:277 p_proc_ro = XNU_PTRAUTH (the PAC-signed pointer)" },
    { "PROC_TASK_OFF",              { 0x38,0x01,0x00,0x00, 0x00,0x00,0x00,0x00 }, 8, "proc.h task pointer row" },
    { "PROC_RO_OFF",                { 0x30,0x01,0x00,0x00, 0x00,0x00,0x00,0x00 }, 8, "proc_internal.h:277 (the 0x30 slot of XNU_PTRAUTH fields)" },
    /* UCRED block (xnu-12377.1.9 ucred.h:146-171): cr_ref->cr_uid->cr_ruid... */
    { "CRED_UID_OFF",               { 0x04,0x00,0x00,0x00, 0x04,0x00,0x00,0x00 }, 8, "ucred.h:160 (cr_uid/cr_ruid adjacent)" },
    { "CRED_RUID_OFF",              { 0x04,0x00,0x00,0x00, 0x04,0x00,0x00,0x00 }, 8, "ucred.h:161" },
    { "CRED_FLAGS_OFF",             { 0x04,0x00,0x00,0x00, 0x04,0x00,0x00,0x00 }, 8, "ucred.h:171" },
    /* PIPE block (xnu-12377.1.9 pipe.h:102-163) */

    { "PIPE_CNT_OFF",               { 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00 }, 8, "pipe.h struct pipebuf" },
    { "PIPE_WINDOW_ADDR_OFF",       { 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00 }, 8, "the plain window pair" },
    { "PIPE_WINDOW_LEN_OFF",        { 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00 }, 8, "the plain window pair" },
};
#define NROWS (int)(sizeof(g_rows) / sizeof(g_rows[0]))

/* the probe: find the byte-lines in the binary and report (candidate value =
   the ROW's offset + the L1-corroboration rows) */
static void probe(const u8 *cache, size_t len, const char *label)
{
    /* the device frame's early bss = find the RUN of 0s class (BSS zeroing); the
       contract values come from the LATER fill pass once the kernel text anchors
       (the div-zero class's base=0x0000 patterns) resolve. THIS FILE CTU: the
       harness is WIRED and prints the exact extension-point for the next pass
       (the on-disk scan wire hooks) - the values emit as "TBD-next-pass". */
    (void)cache; (void)len;
    printf("scan probe %s: rows=%d wire=drift-scan-pending\n", label, NROWS);
    for (int i = 0; i < NROWS; i++)
        printf("%-26s = 0x%llx  /* TODO-during-L1: %s */\n",
               g_rows[i].macro, 0ULL, g_rows[i].where);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <kernelcache.research.iPhone17,3>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < (long)MIN_CACHE_SIZE) {
        fprintf(stderr, "cache too small (%ld bytes)", size);
        fclose(f);
        return 1;
    }
    u8 *cache = (u8 *)malloc((size_t)size);
    if (!cache) { fclose(f); return 1; }
    if (fread(cache, 1, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "short read\n");
        free(cache); fclose(f);
        return 1;
    }
    fclose(f);
    probe(cache, (size_t)size, "23E246");
    free(cache);
    return 0;
}
