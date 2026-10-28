/*
 * probe_static.c — a STATIC, dependency-free iOS probe for the CVE-2026-43724 first-mapper
 * condition. This is the piece the macOS PoC had to fake with shim dylibs:
 *
 *   The kernel creates the process's shared-cache region EMPTY; dyld is what maps the cache
 *   into it. A normally-linked app therefore ends up with a POPULATED region (our LPE probe
 *   measured errno=0 = populated) and its #536 call is rejected because
 *   vm_shared_region_map_file() requires sr_first_mapping == -1.
 *
 *   A binary with NO dylib dependencies gives dyld nothing to map. If dyld also honours
 *   DYLD_SHARED_CACHE_DIR (macOS behaviour), the region stays EMPTY and the process itself
 *   becomes a viable #536 first-mapper -- no child, no posix_spawn, no sandbox problem.
 *
 * Built with: clang -nostdlib -static -Wl,-e,_start   (same shape as DirtySlide's child)
 *
 * At _start the stack is:  [argc][argv...][NULL][envp...][NULL][auxv...]
 * We walk envp to find HOME so we can drop the result in the app's Documents dir.
 */
#include <stdint.h>

#define SYS_exit                 1
#define SYS_open                 5
#define SYS_write                4
#define SYS_close                6
#define SYS_mkdir                488
#define SYS_shared_region_check  294


/* The iOS crt __start shim references the x86-style names ("_bzero"); with -nostdlib there
   is no libSystem to satisfy them, and a plain C definition lands under a different symbol
   name, so we pin the exact names with declaration-level asm labels. */
void my_bzero(void *dst, unsigned long n) __asm__("_bzero");
void my_bzero(void *dst, unsigned long n)
{
	unsigned char *d = (unsigned char *)dst;
	while (n--) *d++ = 0;
}
void *my_memset(void *d, int ch, unsigned long n) __asm__("memset");
void *my_memset(void *d, int ch, unsigned long n)
{
	unsigned char *p = (unsigned char *)d;
	unsigned char v = (unsigned char)ch;
	while (n--) *p++ = v;
	return d;
}
void *my_memset_us(void *d, int ch, unsigned long n) __asm__("_memset");
void *my_memset_us(void *d, int ch, unsigned long n) { return my_memset(d, ch, n); }
void *my_memcpy(void *d, const void *s, unsigned long n) __asm__("memcpy");
void *my_memcpy(void *d, const void *s, unsigned long n)
{
	unsigned char *p = (unsigned char *)d;
	const unsigned char *q = (const unsigned char *)s;
	while (n--) *p++ = *q++;
	return d;
}
void *my_memcpy_us(void *d, const void *s, unsigned long n) __asm__("_memcpy");
void *my_memcpy_us(void *d, const void *s, unsigned long n) { return my_memcpy(d, s, n); }

static long sc6(long num, long a0, long a1, long a2, long a3, long a4, long a5, int *err)
{
	register long x16 asm("x16") = num;
	register long x0 asm("x0") = a0;
	register long x1 asm("x1") = a1;
	register long x2 asm("x2") = a2;
	register long x3 asm("x3") = a3;
	register long x4 asm("x4") = a4;
	register long x5 asm("x5") = a5;
	long carry = 0;
	asm volatile("svc #0x80\n\tcset %1, cs\n\t"
	             : "+r"(x0), "=r"(carry)
	             : "r"(x16), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
	             : "cc", "memory");
	if (err) *err = carry ? (int)(x0 & 0xff) : 0;
	return carry ? -1 : x0;
}

static long sc(long num, long a0, long a1, long a2, long a3)
{
	int e = 0;
	long r = sc6(num, a0, a1, a2, a3, 0, 0, &e);
	return e ? -e : r;
}

static unsigned long slen(const char *s) { unsigned long n = 0; while (s[n]) n++; return n; }
static int seq(const char *a, const char *b)
{
	while (*a && *b) { if (*a != *b) return 0; a++; b++; }
	return *a == *b;
}
static void scpy(char *d, const char *s) { while (*s) { *d++ = *s; } *d = 0; }
static void scat(char *d, const char *s) { while (*d) d++; while (*s) { *d++ = *s; } *d = 0; }
static void unum(char *d, unsigned long v)
{
	char tmp[24]; int i = 0;
	if (v == 0) { d[0] = '0'; d[1] = 0; return; }
	while (v) { tmp[i++] = (char)('0' + (v % 10)); v /= 10; }
	int k = 0;
	while (i) d[k++] = tmp[--i];
	d[k] = 0;
}

static void probe_main(void);

void my_start(void) __asm__("_start");
void my_start(void)
{
	probe_main();
	__builtin_unreachable();
}

int main(void)
{
	probe_main();
	return 0;
}


static void probe_main(void)
{
	uint64_t *sp;
	__asm__ volatile("mov %0, sp" : "=r"(sp));
	long argc = (long)sp[0];
	char **envp = (char **)(sp + 1 + argc + 1);

	char home[512];
	for (char **e = envp; *e; e++) {
		if (seq(*e, "HOME=")) { scpy(home, *e + 5); break; }
	}

	char dir[640], path[768], out[256];
	out[0] = 0;
	if (home[0]) {
		scpy(dir, home);
		scat(dir, "/Documents");
		sc6(SYS_mkdir, (long)dir, 0755, 0, 0, 0, 0, 0);
		scpy(path, dir);
		scat(path, "/result.txt");
	} else {
		scpy(path, "/tmp/result.txt");
	}

	/* Q1: the state of OUR shared region */
	unsigned long long scratch = 0;
	int err = 0;
	sc6(SYS_shared_region_check, (long)&scratch, 0, 0, 0, 0, 0, &err);

	char *p = out;
	scpy(p, "region_errno="); p += slen(p);
	unum(p, (unsigned long)err); p += slen(p);
	*p++ = '\n';
	*p++ = 0;

	int fd = (int)sc(SYS_open, (long)path, 1 /*O_WRONLY*/, 0x200 /*O_CREAT*/, 0644);
	if (fd >= 0) {
		sc6(SYS_write, fd, (long)out, (long)slen(out), 0, 0, 0, 0);
		sc6(SYS_close, fd, 0, 0, 0, 0, 0, 0);
	}
	sc6(SYS_exit, 0, 0, 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
