#!/usr/bin/env python3
"""
o_c_jb.py  (O-C = session "jailbreak 3")

Self-serve Apple ID sign-in + 2FA reader for the isideload CLI on Windows.

Why this exists
---------------
The device lane kept dying in the same place: `minimal.exe` prints
"Enter the 2FA code sent to your devices:" and blocks on stdin forever, and the
code only ever exists on the iPhone's screen (a ~5 s banner). A human in the loop
means a human in the loop. This removes him.

Pieces
------
1. OcrServer   - one long-lived PowerShell process running Windows' built-in
                 OCR (Windows.Media.Ocr). Pay the ~500 ms startup once instead of
                 once per frame. No pip installs, no models, ~100 ms per crop.
2. capture()   - go-ios screenshot (1.5-1.9 s/frame) -> crop -> OCR -> hunt for
                 a 6-digit code near the word "code".
3. install()   - drives minimal.exe: feeds the 2FA code, picks team 1, and
                 answers the certificate-revocation prompt.
4. watch()     - standalone daemon mode: keep reading the phone's screen for a
                 code and stash it, so a code pushed at any moment is never lost.

Modes
-----
  python o_c_jb.py install --app <ipa> [--serial <serial>] [--log <file>]
  python o_c_jb.py watch   [--out <file>] [--stop <file>]
  python o_c_jb.py probe                      # one capture+OCR, print what we see
"""
import argparse
import ctypes
import json
import os
import re
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------- paths
IOS      = r"G:\op lab\arsenal\ios-mirror\bin\ios.exe"
MINIMAL  = r"G:\op lab\iphone-control\jailbreak\_scratch_isideload\isideload\target\release\minimal.exe"
OCR_SRV  = r"G:\op lab\iphone-control\jailbreak\o_c_ocr_server.ps1"
READ_CRD = r"G:\op lab\iphone-control\read-cred.ps1"
CRED_TGT = "fellipegabriel12@icloud.com.iloader"
WORKDIR  = r"G:\op lab\iphone-control\jailbreak\.o_c"
APPLE_ID = "fellipegabriel12@icloud.com.iloader"

CREATE_NO_WINDOW = 0x08000000

# Rust's `tracing`/panic output contains non-cp1252 glyphs (e.g. U+25CF). The Windows
# console default codec would raise UnicodeEncodeError mid-log and kill the watcher.
# Reconfigure stdout/stderr to UTF-8 with replacement so we never lose a log line.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")


def log(msg, fh=None):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    if fh:
        fh.write(line + "\n")
        fh.flush()


def low_priority():
    """Keep the rig quiet: this box is He, and 9 opencode processes already
    live on a 4.7 GB sqlite. Never be the reason his machine feels slow."""
    try:
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
        ctypes.windll.kernel32.SetPriorityClass(
            ctypes.windll.kernel32.GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:
        pass


# ---------------------------------------------------------------- OCR
class OcrServer:
    """Persistent Windows OCR host. Protocol: path per line -> one result line."""

    def __init__(self, script=OCR_SRV):
        self.script = script
        self.proc = None
        self.lock = threading.Lock()

    def start(self):
        self.proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", self.script],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, creationflags=CREATE_NO_WINDOW)
        line = self.proc.stdout.readline().strip()
        if line != "READY":
            err = self.proc.stderr.read()
            raise RuntimeError(f"OCR server did not become ready: {line!r} / {err!r}")
        return self

    def read(self, image_path):
        with self.lock:
            self.proc.stdin.write(image_path + "\n")
            self.proc.stdin.flush()
            return self.proc.stdout.readline().rstrip("\n")

    def stop(self):
        if self.proc:
            try:
                self.proc.stdin.write("quit\n")
                self.proc.stdin.flush()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()


# ---------------------------------------------------------------- capture
def capture(path, udid=None):
    """One screenshot from the phone. Returns path on success, None on failure."""
    cmd = [IOS, "screenshot", f"--output={path}"]
    if udid:
        cmd.append(f"--udid={udid}")
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=45, creationflags=CREATE_NO_WINDOW)
    except Exception:
        return None
    return path if os.path.exists(path) and os.path.getsize(path) > 1000 else None


def crop_regions(path, outdir):
    """The 2FA banner lives in the top third. Crop it (and a mid band) so the
    OCR call is ~10x cheaper. Returns [crop_paths]."""
    from PIL import Image
    crops = []
    try:
        im = Image.open(path)
        w, h = im.size
        bands = {
            "top": (0, 0, w, int(h * 0.34)),
            "mid": (0, int(h * 0.18), w, int(h * 0.72)),
        }
        for name, box in bands.items():
            c = im.crop(box)
            # downscale to bound OCR cost; digits are huge so this is safe
            if c.width > 900:
                c = c.resize((900, int(c.height * 900 / c.width)))
            p = os.path.join(outdir, f"crop_{name}.png")
            c.save(p)
            crops.append(p)
    except Exception:
        return []
    return crops


def score_code(text):
    """Rank 6-digit candidates. Apple codes sit next to the word 'code'."""
    best, best_score = None, -1
    for m in CODE_RE.finditer(text):
        cand = m.group(1)
        score = 1
        around = text[max(0, m.start() - 40):m.end() + 40].lower()
        if "code" in around:
            score += 10
        if "apple id" in around or "apple" in around:
            score += 4
        if "verification" in around:
            score += 3
        # a 6-digit run sitting next to other long digit runs is a clock/battery
        if len(CODE_RE.findall(text)) > 1 and score < 5:
            score -= 1
        if score > best_score:
            best, best_score = cand, score
    return best, best_score


def hunt_code(ocr, frame_path, outdir):
    """OCR the crops of one frame, return (code, raw_text)."""
    raw_parts = []
    code, score = None, -1
    for c in crop_regions(frame_path, outdir):
        res = ocr.read(c)
        if res.startswith("OK "):
            t = res[3:]
            raw_parts.append(t)
            cand, sc = score_code(t)
            if cand and sc > score:
                code, score = cand, sc
    return code, " | ".join(raw_parts)


# ---------------------------------------------------------------- credentials
def vault_creds(target=CRED_TGT):
    """Read (user, secret) out of the Windows vault.

    The keyring convention on this box is: service "iloader" + user "<apple id>"
    -> Windows target "<apple id>.iloader". So the TARGET is NOT the Apple ID - the
    USER field is. Passing the target as the Apple ID gets
    AuthWithMessage(-20970, "Your account information was entered incorrectly.")
    which is exactly what we hit on the first run.
    """
    out = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                          "-File", READ_CRD, "-Target", target],
                         capture_output=True, text=True, timeout=60,
                         creationflags=CREATE_NO_WINDOW)
    txt = out.stdout
    m_user = re.search(r"User\s*:\s*(.+)", txt)
    m_secret = re.search(r"Secret\s*:\s*(.+)", txt)
    if not m_user or not m_secret:
        raise RuntimeError(f"could not read credential {target}")
    user = m_user.group(1).strip()
    secret = m_secret.group(1).strip()
    if user.lower().endswith(".iloader") or user.lower().endswith(".isideload"):
        user = user.rsplit(".", 1)[0]
    return user, secret


def vault_password(target=CRED_TGT):
    return vault_creds(target)[1]


# ---------------------------------------------------------------- watch
def watch(args):
    os.makedirs(WORKDIR, exist_ok=True)
    ocr = OcrServer().start()
    log("watcher up, capturing every ~2s", fh=None)
    found = []
    try:
        while True:
            if args.stop and os.path.exists(args.stop):
                log("stop file seen, watcher exiting")
                break
            t0 = time.time()
            frame = os.path.join(WORKDIR, "watch_frame.png")
            if capture(frame):
                code, raw = hunt_code(ocr, frame, WORKDIR)
                if code:
                    log(f"CODE FOUND: {code}   (raw: {raw[:160]})")
                    found.append(code)
                    with open(args.out, "w", encoding="utf-8") as f:
                        f.write(code)
            dt = time.time() - t0
            if dt < args.interval:
                time.sleep(args.interval - dt)
    finally:
        ocr.stop()
    return 0


# ---------------------------------------------------------------- install
def reprovision():
    """Mint a brand-new anisette identity against the server isideload uses and
    drop it into the vault slot. Called when GrandSlam rejects the machine
    identity (-22421) or when the state has gone stale."""
    wd = os.path.dirname(os.path.abspath(__file__))
    plist_path = os.path.join(wd, "anisette_state.o_c_live.plist")
    raw_path = os.path.join(wd, "anisette_state.o_c_live.bin")
    cmd = [sys.executable, os.path.join(wd, "o_c_anisette_provision.py"),
           "--server", "https://ani.jkcoxson.com", "--out", plist_path, "--raw", raw_path]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                       creationflags=CREATE_NO_WINDOW)
    if "RESULT" not in r.stdout:
        raise RuntimeError(f"reprovision failed: {r.stdout[-500:]} {r.stderr[-500:]}")
    write_cred(plist_path)
    return plist_path


def write_cred(plist_path, target="anisette_state.isideload", user="anisette_state"):
    """Write the state plist into the Windows vault as RAW bytes.
    The isideload keyring uses set_secret/get_secret, so the slot holds the raw
    XML plist bytes - not UTF-16 text, and no trailing NUL."""
    script = r"G:\op lab\iphone-control\write-cred.ps1"
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
           "-Target", target, "-User", user, "-RawFile", plist_path]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                       creationflags=CREATE_NO_WINDOW)
    if "WROTE" not in r.stdout:
        raise RuntimeError(f"write-cred failed: {r.stdout[-300:]} {r.stderr[-300:]}")


def install(args):
    os.makedirs(WORKDIR, exist_ok=True)
    logf = open(args.log, "a", encoding="utf-8", buffering=1) if args.log else None
    log(f"install: app={args.app}", logf)
    if not os.path.exists(MINIMAL):
        log(f"FATAL: {MINIMAL} missing", logf)
        return 1
    if not os.path.exists(args.app):
        log(f"FATAL: app {args.app} missing", logf)
        return 1

    password = vault_password()
    apple_id, _ = vault_creds()
    log(f"credential read from vault: apple_id={apple_id} password_len={len(password)}", logf)

    ocr = OcrServer().start()
    attempt = 0
    # Apple's throttles need minutes, not seconds. -80046 ("This action cannot be
    # completed at this time") on the app-token request is a soft throttle; 503 on
    # the login request is a hard one. Both clear on their own with backoff.
    #
    # Measured on this account: the login endpoint (gsa.apple.com/GSService2)
    # 503s when we come back too fast, and succeeds when we come back after a
    # few minutes. So the cadence is a short-ish retry that still spaces attempts
    # out, and every throttle re-mints the machine identity in case the limit is
    # per-identity rather than per-account.
    backoff = [75, 120, 180, 240, 300, 300, 420, 420, 600, 600]
    max_attempts = 40
    try:
        while attempt < max_attempts:
            attempt += 1
            try:
                rc, tail = run_once(args, apple_id, password, ocr, logf, attempt)
            except Exception as e:
                # A dead stdin (minimal.exe exited under us) must not kill the
                # orchestrator - that is how we lost a good 2FA code earlier.
                log(f"attempt {attempt}: run_once raised {type(e).__name__}: {e}", logf)
                rc, tail = -1, []
            if rc == 0:
                log("INSTALL COMPLETE", logf)
                break
            blob = "\n".join(tail)
            throttle = ("503 Service Temporarily Unavailable" in blob
                        or "-80046" in blob
                        or "cannot be completed at this time" in blob
                        or "-20121" in blob)
            if throttle:
                wait = backoff[min(attempt - 1, len(backoff) - 1)]
                log(f"attempt {attempt}: Apple throttled us ({blob[-200:]!r}); "
                    f"backing off {wait}s then retrying", logf)
                # A 503/-80046 can be per-IDENTITY on Apple's edge, not just per
                # account. Mint a fresh machine identity before the next try so we
                # are not retrying with the same burnt adi_pb every time.
                try:
                    p = reprovision()
                    log(f"  fresh anisette identity written: {p}", logf)
                except Exception as e:
                    log(f"  reprovision failed: {e}", logf)
                time.sleep(wait)
                continue
            if "-22421" in blob or "IncorrectlyProvisioned" in blob or "-45061" in blob:
                log(f"attempt {attempt}: identity rejected -> minting a fresh anisette state", logf)
                try:
                    p = reprovision()
                    log(f"fresh state written: {p}", logf)
                except Exception as e:
                    log(f"reprovision failed: {e}", logf)
                time.sleep(10)
                continue
            log(f"attempt {attempt}: rc={rc}, no recognised retry trigger - "
                f"retrying anyway (a resend cycle can exit rc=101 here)", logf)
            time.sleep(20)
            continue
        else:
            log(f"gave up after {max_attempts} attempts", logf)
    finally:
        try:
            ocr.stop()
        except Exception:
            pass
    if logf:
        logf.close()
    return 0


def read_stash(max_age=300, exclude=None):
    """Read the freshest 2FA code the watcher saw.

    Apple's 2FA codes stay valid for minutes even though the banner that shows
    them only lives seconds - so the freshness window has to be generous (5
    minutes), not 90 seconds. If Apple says the code was wrong (-21669) the
    code goes into the rejected set and we wait for the next one.
    """
    path = os.path.join(WORKDIR, "code_stash.txt")
    try:
        with open(path, encoding="utf-8") as f:
            parts = f.read().split()
        if len(parts) < 2:
            return None
        code, stamp = parts[0], float(parts[1])
        if time.time() - stamp > max_age:
            return None
        if exclude and code in exclude:
            return None
        return code
    except Exception:
        return None


def run_once(args, apple_id, password, ocr, logf, attempt):
    """One full installer run. Returns (rc, log_lines)."""
    # NOTE: minimal.exe emits Rust `tracing` output with ANSI colour codes and UTF-8
    # (the arrow glyphs are 3-byte sequences). Windows' default cp1252 codec dies on
    # them, so decode explicitly with replacement instead of letting the pipe throw.
    proc = subprocess.Popen(
        [MINIMAL, apple_id, password, args.app, args.serial],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
        creationflags=CREATE_NO_WINDOW)
    log(f"[attempt {attempt}] minimal.exe pid={proc.pid}", logf)

    lines = []
    code_sent = False
    last_submit = 0.0         # when the last 2FA code was submitted (anti-churn guard)
    rejected = set()          # codes Apple already said were wrong (-21669)
    last_prompt_code = None
    deadline = time.time() + args.timeout
    try:
        while True:
            if proc.poll() is not None:
                log(f"[attempt {attempt}] installer exited rc={proc.returncode}", logf)
                return proc.returncode, lines
            if time.time() > deadline:
                log(f"[attempt {attempt}] TIMEOUT", logf)
                proc.kill()
                return -1, lines
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.15)
                continue
            line = line.rstrip()
            line = re.sub(r"\x1b\[[0-9;]*m", "", line)
            lines.append(line)
            log(f"installer> {line}", logf)

            low = line.lower()
            # Apple told us the code was wrong: forget it and wait for a new one.
            if "-21669" in low or "incorrect verification code" in low:
                log("  Apple rejected the code (-21669) - waiting for a NEW one", logf)
                code_sent = False
                rejected.add(last_prompt_code) if last_prompt_code else None
                time.sleep(1.0)
                continue

            if "2fa code" in low or "enter the 2fa" in low or "verification code" in low:
                if code_sent:
                    continue
                log("2FA prompt detected -> reading the code the watcher stashed", logf)
                # The eyes (o_c_code_watch.py) keep the freshest code on disk. We
                # read it, and if Apple rejects it (-21669) we ask for a resend
                # and wait for a DIFFERENT code to appear on screen.
                for rnd in range(240):
                    code = read_stash(max_age=300, exclude=rejected)
                    if code:
                        break
                    if rnd % 6 == 5:
                        log(f"  still waiting for a code on screen ({rnd+1} checks)", logf)
                    time.sleep(2.5)
                if code:
                    try:
                        proc.stdin.write(code + "\n")
                        proc.stdin.flush()
                        code_sent = True
                        last_submit = time.time()
                        last_prompt_code = code
                        rejected.add(code)
                        log(f"submitted 2FA code {code}", logf)
                    except (OSError, ValueError) as e:
                        log(f"FAILED to submit 2FA code: {type(e).__name__}: {e}", logf)
                        break
                else:
                    log("no code available after 6 rounds", logf)
            elif "select one of these numbers" in low or 'enter "r" to resend' in low:
                # isideload prints the fallback options as part of the same
                # prompt block - answering 'r' every time would churn requests
                # and invalidate the banner code mid-relay. Only resend if no
                # code was submitted in the last 2 minutes.
                if time.time() - last_submit > 120:
                    log("fallback prompt -> answering 'r' (nothing submitted recently)", logf)
                    try:
                        proc.stdin.write("r\n")
                        proc.stdin.flush()
                    except (OSError, ValueError) as e:
                        log(f"FAILED to answer resend prompt: {type(e).__name__}: {e}", logf)
                        break
                    time.sleep(2.0)
                else:
                    log("fallback prompt -> ignoring (a code was just submitted)", logf)
            elif "select a team" in low or "please select a team" in low:
                proc.stdin.write("1\n")
                proc.stdin.flush()
                log("answered team selection: 1", logf)
            elif "certificates to revoke" in low:
                proc.stdin.write("1\n")
                proc.stdin.flush()
                log("answered cert revocation: 1", logf)
    finally:
        if proc.poll() is None:
            proc.kill()


def probe(args):
    os.makedirs(WORKDIR, exist_ok=True)
    ocr = OcrServer().start()
    frame = os.path.join(WORKDIR, "probe_frame.png")
    p = capture(frame)
    if not p:
        print("capture failed")
        return 1
    code, raw = hunt_code(ocr, frame, WORKDIR)
    print(f"frame: {p}")
    print(f"raw OCR: {raw}")
    print(f"code guess: {code}")
    ocr.stop()
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("install")
    ins.add_argument("--app", required=True)
    ins.add_argument("--serial", default="CK0773N6TM")
    ins.add_argument("--log", default=os.path.join(WORKDIR, "install.log"))
    ins.add_argument("--timeout", type=int, default=900)
    ins.set_defaults(func=install)

    w = sub.add_parser("watch")
    w.add_argument("--out", default=os.path.join(WORKDIR, "2fa_code.txt"))
    w.add_argument("--stop", default="")
    w.add_argument("--interval", type=float, default=1.0)
    w.set_defaults(func=watch)

    pr = sub.add_parser("probe")
    pr.set_defaults(func=probe)

    a = ap.parse_args()
    low_priority()
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
