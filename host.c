/*
 * host.c -- injector / first-mapper validation harness (arm64, non-e).
 *
 * Steps:
 *   1. posix_spawn(child, START_SUSPENDED | _POSIX_SPAWN_RESLIDE)
 *      -> child is suspended at exec, BEFORE its dyld maps the cache, with a
 *         fresh bound-EMPTY reslide region.
 *   2. task_for_pid(child)  (child is signed get-task-allow; same uid)
 *   3. locate the child's main-executable load base (find MH_EXECUTE in its map)
 *   4. hijack the suspended main thread: set PC = base + PROBE_OFFSET (child_probe,
 *      which lives in the child's signed __TEXT -- no injected exec memory)
 *   5. task_resume -> child_probe runs pre-dyld and exits with the check_np errno
 *   6. waitpid -> exit code tells us the region state:
 *         12 (ENOMEM) = BOUND-but-EMPTY  => viable #536 first-mapper  [WANT]
 *          0          = populated
 *         22 (EINVAL) = no region bound
 *
 * arm64 (non-e) avoids arm64e thread_set_state PAC signing for this gate; the
 * real #536 payload will port to arm64e with the task_vaccine PAC technique.
 *
 * Run in the VM (needs task_for_pid: child get-task-allow + same uid, or root):
 *     ./host ./child
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <spawn.h>
#include <sys/spawn.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/arm/thread_state.h>
#include <mach-o/loader.h>

#include "probe_off.h"   /* generated: #define PROBE_OFFSET 0x... (child_probe - __TEXT base) */

extern char **environ;

/* Find the load base of the main MH_EXECUTE image in the target task. */
static mach_vm_address_t find_exec_base(task_t task)
{
	mach_vm_address_t addr = 0;
	mach_vm_size_t    size = 0;
	natural_t         depth = 0;

	for (;;) {
		vm_region_submap_info_data_64_t info;
		mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t kr = mach_vm_region_recurse(task, &addr, &size, &depth,
		    (vm_region_recurse_info_t)&info, &cnt);
		if (kr != KERN_SUCCESS)
			break;

		/* read the first 16 bytes; check for a Mach-O exe header */
		uint32_t hdr[4] = {0};
		mach_vm_size_t got = 0;
		if (mach_vm_read_overwrite(task, addr, sizeof(hdr),
		        (mach_vm_address_t)hdr, &got) == KERN_SUCCESS &&
		    got == sizeof(hdr) &&
		    hdr[0] == MH_MAGIC_64 &&
		    hdr[3] == MH_EXECUTE) {
			return addr;
		}
		addr += size;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <child-path>\n", argv[0]);
		return 2;
	}
	const char *child = argv[1];

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	short flags = POSIX_SPAWN_START_SUSPENDED | (short)_POSIX_SPAWN_RESLIDE; /* 0x0880 */
	posix_spawnattr_setflags(&attr, flags);

	char *args[] = { (char *)child, NULL };
	pid_t pid = -1;
	int rc = posix_spawn(&pid, child, NULL, &attr, args, environ);
	posix_spawnattr_destroy(&attr);
	if (rc != 0) {
		fprintf(stderr, "[host] posix_spawn failed: %s (%d)\n", strerror(rc), rc);
		return 1;
	}
	fprintf(stderr, "[host] spawned child pid=%d (suspended, reslide)\n", pid);

	task_t ctask = TASK_NULL;
	kern_return_t kr = task_for_pid(mach_task_self(), pid, &ctask);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "[host] task_for_pid failed: %s (0x%x). "
		    "child needs get-task-allow, or run as root.\n",
		    mach_error_string(kr), kr);
		kill(pid, SIGKILL);
		return 1;
	}

	thread_act_array_t threads = NULL;
	mach_msg_type_number_t nthreads = 0;
	kr = task_threads(ctask, &threads, &nthreads);
	if (kr != KERN_SUCCESS || nthreads < 1) {
		fprintf(stderr, "[host] task_threads failed: %s (0x%x) n=%u\n",
		    mach_error_string(kr), kr, nthreads);
		kill(pid, SIGKILL);
		return 1;
	}
	thread_t th = threads[0];

	mach_vm_address_t base = find_exec_base(ctask);
	if (base == 0) {
		fprintf(stderr, "[host] could not locate child exec base\n");
		kill(pid, SIGKILL);
		return 1;
	}
	mach_vm_address_t probe = base + PROBE_OFFSET;
	fprintf(stderr, "[host] child exec base=0x%llx child_probe=0x%llx\n",
	    (unsigned long long)base, (unsigned long long)probe);

	arm_thread_state64_t st;
	mach_msg_type_number_t scount = ARM_THREAD_STATE64_COUNT;
	kr = thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&st, &scount);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "[host] thread_get_state failed: %s (0x%x)\n",
		    mach_error_string(kr), kr);
		kill(pid, SIGKILL);
		return 1;
	}

	/* arm64 (non-e): set PC; align SP to 16 bytes (else EXC_ARM_SP_ALIGN on the
	 * first sp-based store, since we bypass dyld's _dyld_start sp alignment) */
	st.__pc = (uint64_t)probe;
	st.__sp &= ~0xFULL;

	kr = thread_set_state(th, ARM_THREAD_STATE64, (thread_state_t)&st, scount);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "[host] thread_set_state failed: %s (0x%x)\n",
		    mach_error_string(kr), kr);
		kill(pid, SIGKILL);
		return 1;
	}

	kr = task_resume(ctask);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "[host] task_resume failed: %s (0x%x)\n",
		    mach_error_string(kr), kr);
		kill(pid, SIGKILL);
		return 1;
	}

	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		perror("[host] waitpid");
		return 1;
	}
	if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);
		const char *meaning =
		    code == 12 ? "ENOMEM: BOUND-but-EMPTY region  => viable #536 FIRST-MAPPER" :
		    code == 0  ? "region already populated" :
		    code == 22 ? "EINVAL: no region bound" :
		                 "unexpected";
		fprintf(stderr, "[host] child_probe exit=%d  (%s)\n", code, meaning);
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "[host] child killed by signal %d "
		    "(hijack/PAC/exec issue -- inspect)\n", WTERMSIG(status));
	}
	return 0;
}
