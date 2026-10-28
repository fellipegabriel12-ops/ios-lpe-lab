#!/usr/bin/env python3
"""
vm_drive.py v2 - boots the darwin-vm iOS 26.4 QEMU image, drives the serial
console root shell, runs a probe battery, saves the transcript.

v2 fixes: prompt is bash-5.3 on 26.4 (regex-matched, version-agnostic),
chunked stdout reads for speed, longer boot window.
"""
import subprocess, sys, time, os, re

os.chdir(os.path.dirname(os.path.abspath(__file__)))

QEMU = os.path.join('qemu-sptm', 'build', 'qemu-system-aarch64')
ARGS = [
    '-M', 'darwin',
    '-bootkc', 'firmware/bootkc',
    '-dtree', 'firmware/dtree',
    '-tc', 'firmware/ramdisk.tc',
    '-ramdisk', 'firmware/ramdisk.dmg',
    '-args', 'rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort',
    '-nographic', '-serial', 'mon:stdio',
    '-m', '8G',
]
if os.path.exists('firmware/sptm'):
    ARGS += ['-sptm', 'firmware/sptm', '-txm', 'firmware/txm']

PROMPT_RE = re.compile(rb'bash-[\d.]+# $')

def main():
    p = subprocess.Popen([QEMU] + ARGS,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         bufsize=0)
    fd = p.stdout.fileno()
    tr = open('transcript.txt', 'wb')
    buf = b''

    def read_until_prompt(timeout):
        nonlocal buf
        end = time.time() + timeout
        while time.time() < end:
            chunk = os.read(fd, 65536)
            if not chunk:
                return None
            buf += chunk
            tr.write(chunk)
            tr.flush()
            m = PROMPT_RE.search(buf[-64:])
            if m:
                out, buf = buf, b''
                return out
        return None

    print('[vm] booting (TCG; first prompt may take several minutes)...', flush=True)
    first = read_until_prompt(900)
    if first is None:
        print('[vm] BOOT TIMEOUT - transcript saved', flush=True)
        tr.close()
        p.kill()
        sys.exit(2)
    tail = first.decode(errors='replace')[-2000:]
    print('[vm] BOOT OK, last output:\n' + tail, flush=True)

    CMDS = [
        'uname -v',
        'id',
        'mount',
        'ls /dev | head -60',
        'ls -la /dev/*disk* 2>/dev/null | head -20',
        'ls /usr/lib | head -40',
        'ls /usr/lib/dyld 2>/dev/null; file /usr/lib/dyld 2>/dev/null || true',
        'ls /System/Library/Extensions/ 2>/dev/null | head -40',
        'ls /sbin /bin /usr/sbin /usr/bin 2>/dev/null | head -60',
        'sysctl -a 2>/dev/null | head -60',
        'cat /etc/fstab 2>/dev/null; ls /etc 2>/dev/null | head -20',
        'dmesg 2>/dev/null | head -20 || true',
        'ls /private/var 2>/dev/null; ls /private/var/db 2>/dev/null | head',
        'ioreg -l 2>/dev/null | head -40 || true',
        'ls /System/Library/CoreServices 2>/dev/null | head',
    ]
    for c in CMDS:
        print(f'[vm] $ {c}', flush=True)
        try:
            p.stdin.write(c.encode() + b'\n')
            p.stdin.flush()
        except Exception as e:
            print(f'[vm] stdin failed: {e}', flush=True)
            break
        out = read_until_prompt(120)
        if out is None:
            print(f'[vm] TIMEOUT/EOF on: {c}', flush=True)
            break
        print(out.decode(errors='replace'), flush=True)

    try:
        p.stdin.write(b'\x01x')
        p.stdin.flush()
        p.wait(timeout=20)
    except Exception:
        p.kill()
    tr.close()
    print('[vm] session complete - transcript.txt saved', flush=True)

if __name__ == '__main__':
    main()
