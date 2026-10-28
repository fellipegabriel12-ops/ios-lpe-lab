#!/usr/bin/env python3
"""
vm_drive.py - boots the darwin-vm iOS 26.4 QEMU image on a CI macOS runner,
drives the serial console (root shell), runs a probe battery, saves the
full transcript as an artifact.
"""
import subprocess, sys, time, os

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

PROMPT = b'bash-3.2# '

def main():
    p = subprocess.Popen([QEMU] + ARGS,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         bufsize=0)
    tr = open('transcript.txt', 'wb')
    buf = b''

    def read_until_prompt(timeout):
        nonlocal buf
        end = time.time() + timeout
        while time.time() < end:
            ch = p.stdout.read(1)
            if not ch:
                return None
            buf += ch
            tr.write(ch)
            tr.flush()
            if buf.endswith(PROMPT):
                out, buf = buf, b''
                return out
        return None

    print('[vm] booting (TCG, expect 1-4 min to first prompt)...', flush=True)
    first = read_until_prompt(480)
    if first is None:
        print('[vm] BOOT TIMEOUT - transcript saved', flush=True)
        tr.close()
        p.kill()
        sys.exit(2)
    tail = first.decode(errors='replace')[-3000:]
    print('[vm] BOOT OK, last output:\n' + tail, flush=True)

    CMDS = [
        'uname -v',
        'uname -m',
        'sw_vers 2>/dev/null || true',
        'ls /',
        'ls /System/Library/Frameworks/ 2>/dev/null | head -50',
        'ls -d /System/Library/Frameworks/CoreGraphics.framework /System/Library/Frameworks/VideoToolbox.framework /System/Library/Frameworks/ImageIO.framework 2>/dev/null',
        'ls /System/Library/Caches/com.apple.dyld/ 2>/dev/null | head',
        'ls /System/Library/Extensions/ 2>/dev/null | grep -iE "AVE|AGX|apfs" | head',
        'kextstat 2>/dev/null | head -40 || true',
        'id',
        'sysctl hw.model 2>/dev/null || true',
        'sysctl -a 2>/dev/null | grep -iE "kern.osversion|kern.osrelease" | head',
    ]
    for c in CMDS:
        print(f'[vm] $ {c}', flush=True)
        try:
            p.stdin.write(c.encode() + b'\n')
            p.stdin.flush()
        except Exception as e:
            print(f'[vm] stdin failed: {e}', flush=True)
            break
        out = read_until_prompt(90)
        if out is None:
            print(f'[vm] TIMEOUT/EOF on: {c}', flush=True)
            break
        print(out.decode(errors='replace'), flush=True)

    # quit qemu: ctrl-a then x
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
