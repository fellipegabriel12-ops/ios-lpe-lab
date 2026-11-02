#!/usr/bin/env python3
"""
vm_push_file.py - helper snippet library for pushing files into the darwin-vm
over the serial console. The console is a root bash; we transfer files as
base64 chunks written with printf >> and decode with `base64 -d` (or openssl).

Usage pattern (called from vm_drive.py):
    push_file(send_line, local_path, remote_path, chunk=512)
"""
import base64
import os

def push_file(send_line, local_path, remote_path, chunk=384, log=print):
    """send_line(cmd_str) must write one line to the VM's stdin."""
    data = open(local_path, 'rb').read()
    b64 = base64.b64encode(data).decode()
    log(f'[push] {local_path} -> {remote_path} ({len(data)} bytes, b64 {len(b64)} chars)')
    # clear target
    send_line(f'rm -f "{remote_path}.b64"')
    n = (len(b64) + chunk - 1) // chunk
    for i in range(0, len(b64), chunk):
        part = b64[i:i + chunk]
        # printf '%s\n' 'part' >> file  - single-quote safe (base64 has no quotes)
        send_line(f"printf '%s\\n' '{part}' >> '{remote_path}.b64'")
    send_line(f"base64 -d '{remote_path}.b64' > '{remote_path}' 2>/dev/null "
              f"|| openssl base64 -d -in '{remote_path}.b64' -out '{remote_path}'")
    send_line(f"rm -f '{remote_path}.b64'; ls -la '{remote_path}'")
    log(f'[push] done ({n} chunks)')

if __name__ == '__main__':
    print('library module - import push_file()')
