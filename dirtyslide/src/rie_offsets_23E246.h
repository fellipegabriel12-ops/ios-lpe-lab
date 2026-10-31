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
/*
 * rie_offsets_23E246.h — SEMANTIC ANCHORS (O-D, Tier-1 source-level).
 *
 * Values stay 0 until a kcache pattern-scan fills them — this file documents
 * WHERE to look: the exact field declarations in the PUBLISHED xnu-12377.1.9
 * (github.com/apple-oss-distributions/xnu, tag xnu-12377.1.9, files fetched to
 * Updates workspace: thread.h / proc_internal.h / ucred.h / pipe.h).
 *
 * FIELD ANCHORS (file:line from the tag checkout):
 *   thread.h:488   thread_continue_t  continuation;   /* continue here next dispatch */
 *   thread.h:489   void              *parameter;     /* continuation parameter */
 *   thread.h:385   struct thread {   <- the struct decl
 *   proc_internal.h:271  struct proc {              <- the struct decl
 *   proc_internal.h:290  pid_t  p_pid;              /* THROUGH smrq / LIST_NOTE: this
 *       line sits in the 26.4-era struct proc (the modern one); lines 647/699 are
 *       the LEGACY pack(virtual) structs — do NOT use them */
 *   proc_internal.h:277  proc_ro_t p_proc_ro;       <- PPL-protected read-only proc root
 *   ucred.h:146   struct ucred {
 *   ucred.h:153   u_long  cr_ref;                            <- reference count
 *   ucred.h:160   uid_t   cr_uid;   (effective)
 *   ucred.h:161   uid_t   cr_ruid;  (real)
 *   ucred.h:171   int     cr_flags;                          <- flags on credential
 *   pipe.h:155    struct pipe {
 *   pipe.h:102    struct pipebuf {                       <- the buffer substruct
 *   pipe.h:163    u_int  pipe_state;
 *
 * RESOLUTION ORDER (per the operation's rules):
 *   1. kcache 23E246 (iPhone17,3, on disk at
 *      G:\op lab\iphone-control\jailbreak\kcache-26.4\23E246__iPhone17,3\)
 *      through the XPF/ChOma PatchFinder stack (G:\op lab\Dopamine\BaseBin) —
 *      Tier-0.
 *   2. xnu-12377.1.9 source = the semantic anchor for what each pattern must
 *      match (field order, struct group macro nesting, XNU_PTRAUTH_SIGNED_PTR
 *      fields = PAC-signed pointers — the machine code shows the sign/auth
 *      instructions at those accesses).
 *   3. never hand-arithmetic offsets: the _PROC_HAS_SCHEDINFO_ / CONFIG_* /
 *      _XNU_STRUCT_GROUP_ macros make field order conditional — arm64 build
 *      flags decide which branches exist. RTFM = the kext binary.
 *
 * AVE2/AVD note: the offsets contract is xtended by ave2_wire.h (the 64747
 * wire layout) and tools/o_c_aved_hunt.py (the AVD census which runs offline).
 */
