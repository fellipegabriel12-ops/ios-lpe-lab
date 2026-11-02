#!/usr/bin/env python3
"""
o_c_code_watch.py  (O-C = session "jailbreak 3") - the eyes, running continuously.

The Apple 2FA banner lives about five seconds, so anything that looks for the
code only when it wants it will lose the race. This process keeps its eyes open:
every ~1.4 s it screenshots the phone, crops to the top third (where the banner
is) and downsizes, then OCRs that with Windows' built-in OCR. Any 6-digit code
it sees next to the word "code" is written to a stash file with a timestamp.

Two things that bit us and are handled here:
  * OCRing the FULL 1179x2556 screenshot takes tens of seconds and can wedge the
    OCR host entirely - so we crop to the top band and downscale first.
  * A wedged OCR host must not wedge us - every OCR call has a timeout and the
    host is respawned if it stops answering.

The stash is one line: "<code> <unix_timestamp>", written atomically.

Run:  python o_c_code_watch.py [--interval 1.4] [--out <file>]
"""
import argparse
import ctypes
import os
import queue
import re
import subprocess
import sys
import threading
import time

WD = r"G:\op lab\iphone-control\jailbreak"
IOS = r"G:\op lab\arsenal\ios-mirror\bin\ios.exe"
OCR = os.path.join(WD, "o_c_ocr_server.ps1")
WORK = os.path.join(WD, ".o_c")
CN = 0x08000000
CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
KEYWORDS = ("verification code", "apple account", "apple id", "sign in", "code")


def low_priority():
    try:
        ctypes.windll.kernel32.SetPriorityClass(
            ctypes.windll.kernel32.GetCurrentProcess(), 0x00004000)  # BELOW_NORMAL
    except Exception:
        pass


class Ocr:
    """Persistent Windows OCR host with a hard timeout on every request."""

    def __init__(self, script=OCR):
        self.script = script
        self.proc = None
        self.q = queue.Queue()

    def start(self):
        self.proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", self.script],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1, creationflags=CN)
        self.q = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()
        try:
            if self.q.get(timeout=20) != "READY":
                raise RuntimeError("OCR host not ready")
        except Exception as e:
            raise RuntimeError(f"OCR host failed: {e}")

    def _reader(self):
        try:
            for line in self.proc.stdout:
                self.q.put(line.rstrip("\n"))
        except Exception:
            pass
        self.q.put("__DEAD__")

    def ask(self, path, timeout=25):
        if self.proc is None or self.proc.poll() is not None:
            self.start()
        try:
            self.proc.stdin.write(path + "\n")
            self.proc.stdin.flush()
        except Exception as e:
            self.start()
            self.proc.stdin.write(path + "\n")
            self.proc.stdin.flush()
        try:
            res = self.q.get(timeout=timeout)
        except queue.Empty:
            # wedged host - kill and let the next call respawn it
            try:
                self.proc.kill()
            except Exception:
                pass
            self.proc = None
            return "ERR timeout"
        if res == "__DEAD__":
            self.proc = None
            return "ERR dead"
        return res


def capture_and_crop(raw_path, out_path, top_frac=0.55, max_w=880):
    """Screenshot, then crop the top band and downscale: OCR cost falls ~10x and
    the 2FA banner is always in that band. The band is 55% of the height because
    at 42% the digits of the banner were being cut off (we saw the words
    "Verification Code" but not the number)."""
    try:
        subprocess.run([IOS, "screenshot", f"--output={raw_path}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=40, creationflags=CN)
    except Exception:
        return None
    if not (os.path.exists(raw_path) and os.path.getsize(raw_path) > 1000):
        return None
    try:
        from PIL import Image
        im = Image.open(raw_path)
        w, h = im.size
        im = im.crop((0, 0, w, int(h * top_frac)))
        if im.width > max_w:
            im = im.resize((max_w, int(im.height * max_w / im.width)))
        im = im.convert("RGB")
        im.save(out_path)
        try:
            os.remove(raw_path)
        except Exception:
            pass
        return out_path
    except Exception:
        return raw_path


def find_code(text):
    best, best_score = None, -1
    for m in CODE_RE.finditer(text):
        around = text[max(0, m.start() - 90):m.end() + 40].lower()
        score = 1
        for kw in KEYWORDS:
            if kw in around:
                score += 6
        if "code" in around:
            score += 8
        if score > best_score:
            best, best_score = m.group(1), score
    return best, best_score


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=1.4)
    ap.add_argument("--out", default=os.path.join(WORK, "code_stash.txt"))
    ap.add_argument("--log", default=os.path.join(WORK, "code_watch.log"))
    ap.add_argument("--stop", default=os.path.join(WORK, "code_watch.stop"))
    a = ap.parse_args()
    low_priority()
    os.makedirs(WORK, exist_ok=True)
    ocr = Ocr()
    ocr.start()
    raw = os.path.join(WORK, "eye_raw.png")
    small = os.path.join(WORK, "eye_small.png")
    last_code = None
    last_text = None
    with open(a.log, "a", encoding="utf-8", buffering=1) as lf:
        lf.write(f"=== watcher up {time.strftime('%H:%M:%S')} interval={a.interval}s ===\n")
        while True:
            if os.path.exists(a.stop):
                lf.write("stop file seen, exiting\n")
                break
            t0 = time.time()
            p = capture_and_crop(raw, small)
            if p:
                res = ocr.ask(p, timeout=25)
                if res.startswith("OK "):
                    text = res[3:]
                    code, score = find_code(text)
                    # PRIVACY: the phone is a real phone with a Messages app open.
                    # We only ever want to know "is there a 2FA code on screen", so
                    # the log records the verdict, not the screen contents. Only a
                    # line that actually contains a code is quoted.
                    if code and score >= 7:
                        if text != last_text:
                            last_text = text
                            lf.write(f"[{time.strftime('%H:%M:%S')}] CODE {code} (score {score})")
                            # Only re-stamp when the code CHANGES. Re-stamping the
                            # same banner every frame made a stale code look fresh
                            # forever, and Apple answered -21669 (Incorrect
                            # verification code) because the code had rotated.
                            last_code = code
                            stamp = time.time()
                            tmp = a.out + ".tmp"
                            with open(tmp, "w", encoding="utf-8") as f:
                                f.write(f"{code} {stamp}\n")
                            os.replace(tmp, a.out)
                            lf.write(f"  -> STASHED {code} at {time.strftime('%H:%M:%S')}\n")
                    else:
                        # no code visible: record only that, never the text
                        if last_text is not None:
                            last_text = None
                            lf.write(f"[{time.strftime('%H:%M:%S')}] no code on screen\n")
                elif res.startswith("ERR"):
                    lf.write(f"[{time.strftime('%H:%M:%S')}] {res}\n")
            dt = time.time() - t0
            if dt < a.interval:
                time.sleep(a.interval - dt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
