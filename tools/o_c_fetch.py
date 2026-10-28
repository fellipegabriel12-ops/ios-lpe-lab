#!/usr/bin/env python3
"""
o_c_fetch.py - reliable CI artifact fetch + integrity check.

The old path (fetch_ci_artifacts.blob_to_file) went through the GitHub git-blob
API and, for dist5/CGPOC.ipa, produced 13,767 bytes of ZEROS - a silently broken
artifact that then "installed" and "crashed", which looked exactly like an
exploit result. So this fetcher:

  1. prefers `git cat-file blob` on the artifact branch (the repo is already
     cloned with credentials - no API quirks, no base64, no size limits)
  2. falls back to the contents API
  3. VERIFIES the result: a zip/IPA must start with PK\\x03\\x04, and the sha256
     is printed so two fetches can be compared
  4. refuses to return a file that fails verification

Usage:
  python o_c_fetch.py get <ref> <path-in-repo> <local-dest>
  python o_c_fetch.py verify <local-file>
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import urllib.request

REPO = "fellipegabriel12-ops/ios-lpe-lab"
CLONE = r"G:\op lab\iphone-control\jailbreak\loot\ci-repo"
CN = 0x08000000


def log(m):
    print(m, flush=True)


def git_blob(ref, path):
    """Pull a blob straight out of git. Returns bytes or None."""
    try:
        subprocess.run(["git", "-C", CLONE, "fetch", "--quiet", "origin", ref],
                       capture_output=True, timeout=180, creationflags=CN)
    except Exception as e:
        log(f"  git fetch failed: {e}")
        return None
    p = subprocess.run(["git", "-C", CLONE, "show", f"FETCH_HEAD:{path}"],
                       capture_output=True, timeout=180, creationflags=CN)
    if p.returncode != 0:
        log(f"  git show failed: {p.stderr.decode('utf-8', 'replace')[:200]}")
        return None
    return p.stdout


def api_blob(ref, path):
    """Contents API fallback (fine for files under ~1 MB)."""
    token = open(r"G:\op lab\iphone-control\jailbreak\loot\gh_token.txt").read().strip()
    url = f"https://api.github.com/repos/{REPO}/contents/{path}?ref={ref}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                               "Accept": "application/vnd.github+json",
                                               "User-Agent": "o-c"})
    with urllib.request.urlopen(req, timeout=60) as r:
        obj = json.loads(r.read())
    if obj.get("encoding") == "base64":
        return base64.b64decode(obj["content"])
    return None


def verify(data, path_in_repo):
    """A zero-filled or truncated artifact must never be handed to the installer."""
    if not data:
        return False, "empty"
    if len(data) > 1024 and data.count(b"\x00") > len(data) * 0.9:
        return False, f"looks zero-filled ({data.count(b'\\x00')} NUL bytes)"
    if data[:2] == b"PK":
        return True, f"zip, {len(data):,} bytes"
    if path_in_repo.endswith((".h", ".c", ".txt", ".md", ".m", ".sh")):
        return True, f"text, {len(data):,} bytes"
    return False, f"not a zip (head {data[:8]!r})"


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "verify":
        d = open(sys.argv[2], "rb").read()
        ok, why = verify(d, sys.argv[2])
        print(f"{sys.argv[2]}: {'OK' if ok else 'BAD'} - {why}")
        print(f"  sha256 {hashlib.sha256(d).hexdigest()}")
        return 0 if ok else 1

    ref, path_in_repo, dest = sys.argv[2], sys.argv[3], sys.argv[4]
    data = git_blob(ref, path_in_repo)
    src = "git"
    if data is None:
        data = api_blob(ref, path_in_repo)
        src = "api"
    if data is None:
        print("FETCH FAILED")
        return 1
    ok, why = verify(data, path_in_repo)
    if not ok:
        print(f"VERIFICATION FAILED ({src}): {why}")
        print("NOT writing a broken artifact to disk.")
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    print(f"wrote {dest} ({len(data):,} bytes) via {src} - {why}")
    print(f"  sha256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
