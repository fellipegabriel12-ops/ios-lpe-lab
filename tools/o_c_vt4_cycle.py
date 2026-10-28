#!/usr/bin/env python3
"""
o_c_vt4_cycle.py  (O-C = session "jailbreak 3")

End-to-end decisive cycle for the VideoToolbox clamp question:

  1. wait for the build-ios-lpe CI run that contains our commit
  2. fetch dist5/VT4.ipa from that run's artifact branch
  3. install it on the phone (self-serve: vault creds + 2FA read off the screen)
  4. launch it twice with env knobs (VT_REFS and VT_REFS2)
  5. pull Documents/vt4_report.txt back off the phone and print it

The report answers the only question that decides whether the CVE-2026-64747
DPB/LRB route is reachable from the public VideoToolbox API:
    "read-back ReferenceBufferCount: st=0 value=N CLAMPED=0/1"

Run:  python o_c_vt4_cycle.py [--head <sha>] [--refs 64] [--refs2 324] [--timeout 900]
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

WD = r"G:\op lab\iphone-control\jailbreak"
REPO = "fellipegabriel12-ops/ios-lpe-lab"
IOS = r"G:\op lab\arsenal\ios-mirror\bin\ios.exe"
PY = sys.executable
CREATE_NO_WINDOW = 0x08000000


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def api(path, token):
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/{path}",
                                 headers={"Authorization": f"Bearer {token}",
                                          "Accept": "application/vnd.github+json",
                                          "User-Agent": "o-c"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read())


def wait_for_run(token, head, timeout):
    log(f"waiting for CI run containing {head[:8]} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            runs = api("actions/workflows/build.yml/runs?per_page=10", token).get("workflow_runs", [])
            for r in runs:
                if r["head_sha"].startswith(head[:8]):
                    if r["status"] == "completed":
                        log(f"run {r['id']} completed: {r['conclusion']}")
                        if r["conclusion"] == "success":
                            return r
                        return None
                    log(f"  run {r['id']} is {r['status']}")
                    break
        except Exception as e:
            log(f"  api error: {e}")
        time.sleep(20)
    return None


def fetch_artifact(run_id, dest):
    sys.path.insert(0, WD)
    import fetch_ci_artifacts as fca
    ref = f"build-{run_id}"
    items, _ = fca.tree(ref)
    hit = [i for i in items if i["path"] == "dist5/VT4.ipa"]
    if not hit:
        raise RuntimeError(f"dist5/VT4.ipa not found on {ref}")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    n = fca.blob_to_file(hit[0]["sha"], dest)
    log(f"fetched {dest} ({n} bytes) from {ref}")
    return dest


def install(ipa):
    log("installing (2FA is read off the phone by OCR) ...")
    r = subprocess.run([PY, os.path.join(WD, "o_c_jb.py"), "install",
                        "--app", ipa, "--serial", "CK0773N6TM",
                        "--log", os.path.join(WD, ".o_c", "install.log")],
                       cwd=WD, capture_output=True, text=True, timeout=900,
                       creationflags=CREATE_NO_WINDOW)
    log(f"install rc={r.returncode}")
    tail = ""
    try:
        with open(os.path.join(WD, ".o_c", "install.log"), encoding="utf-8", errors="replace") as f:
            tail = "".join(f.readlines()[-12:])
    except Exception:
        pass
    print(tail)
    return r.returncode == 0


def launch(env):
    args = ["pymobiledevice3", "developer", "dvt", "launch"]
    for k, v in env.items():
        args += ["--env", f"{k}={v}"]
    args.append("com.lab.lpe.2BGBD62KA3")
    r = subprocess.run(args, capture_output=True, text=True, timeout=240,
                       creationflags=CREATE_NO_WINDOW)
    for line in (r.stdout + r.stderr).splitlines():
        if "launched" in line or "Error" in line:
            log("  " + line.strip()[:160])


def pull(dest):
    if os.path.exists(dest):
        os.remove(dest)
    r = subprocess.run([IOS, "file", "pull", "--app=com.lab.lpe.2BGBD62KA3",
                        "--remote=Documents/vt4_report.txt", f"--local={dest}"],
                       capture_output=True, text=True, timeout=180,
                       creationflags=CREATE_NO_WINDOW)
    if os.path.exists(dest):
        return open(dest, encoding="utf-8", errors="replace").read()
    log(f"pull failed: {r.stdout[-300:]} {r.stderr[-300:]}")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--head", default="3f14e7f")
    ap.add_argument("--refs", type=int, default=64)
    ap.add_argument("--refs2", type=int, default=324)
    ap.add_argument("--w", type=int, default=4096)
    ap.add_argument("--h", type=int, default=2160)
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()

    token = open(os.path.join(WD, "loot", "gh_token.txt")).read().strip()
    run = wait_for_run(token, a.head, a.timeout)
    if not run:
        log("CI did not succeed - aborting")
        return 2
    ipa = fetch_artifact(run["id"], os.path.join(WD, "ci-out", "dist8", "VT4.ipa"))
    if not install(ipa):
        log("install failed")
        return 3

    dest = os.path.join(WD, ".o_c", "vt4_report2.txt")
    log(f"launch 1: refs={a.refs} {a.w}x{a.h}")
    launch({"VT_W": str(a.w), "VT_H": str(a.h), "VT_REFS": str(a.refs),
            "VT_DEPTH": "10", "VT_HEVC": "1", "VT_FRAMES": "3"})
    time.sleep(10)
    log(f"launch 2: refs={a.refs2} (overflow candidate)")
    launch({"VT_W": str(a.w), "VT_H": str(a.h), "VT_REFS": str(a.refs),
            "VT_REFS2": str(a.refs2), "VT_DEPTH": "10", "VT_HEVC": "1", "VT_FRAMES": "3"})
    time.sleep(12)
    rep = pull(dest)
    log("=" * 70)
    print(rep if rep else "NO REPORT")
    log("=" * 70)
    return 0 if rep else 4


if __name__ == "__main__":
    sys.exit(main())
