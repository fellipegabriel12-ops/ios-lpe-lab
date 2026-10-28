#!/usr/bin/env python3
"""
o_c_exp.py  (O-C = session "jailbreak 3") - client for the Experiential gateway.

The gateway is OpenAI Chat Completions compatible for chat models
(https://api.experientiallabs.ai/v1, model id e.g. "gpt-6-luna") and exposes the
typed decision models on /v1/systemone (model id "jev-latest" or
"gpt-6-luna-decisions").

Key handling, per the platform's own integration rules:
  * the key is read ONLY from the environment (EXPLABS_API_KEY for chat,
    EXPERIENTIAL_API_KEY for the decision endpoint - we accept either);
  * the key is never logged, never printed, never written to disk;
  * bounded timeout, no automatic retries (an unknown outcome may already be charged).

Usage:
  export EXPLABS_API_KEY=...        # set it locally; never paste it into a chat
  python o_c_exp.py chat  --model gpt-6-luna --prompt "..." [--system "..."] [--json]
  python o_c_exp.py decide --model jev-latest --state-file f.txt \
          --choice "review:accept=looks right,review=broken" --score "risk:how risky:l1,l2"
  python o_c_exp.py models
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BASE = "https://api.experientiallabs.ai/v1"
DECISIONS = "https://api.experientiallabs.ai/v1/systemone"


def key():
    for name in ("EXPLABS_API_KEY", "EXPERIENTIAL_API_KEY"):
        v = os.environ.get(name)
        if v:
            return v
    raise SystemExit(
        "No gateway key in this environment.\n"
        "Create one on the platform (Settings -> API Keys) and EXPORT it locally, e.g.\n"
        "  setx EXPLABS_API_KEY \"<your key>\"      (PowerShell, new shells only)\n"
        "  export EXPLABS_API_KEY=...                (bash)\n"
        "Do not paste the key into a chat - the helper only ever reads the env var.")


def post(url, body, timeout=180):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {key()}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def get(url, timeout=60):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key()}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def cmd_chat(a):
    msgs = []
    if a.system:
        msgs.append({"role": "system", "content": a.system})
    msgs.append({"role": "user", "content": a.prompt})
    body = {"model": a.model, "messages": msgs}
    if a.temperature is not None:
        body["temperature"] = a.temperature
    if a.max_tokens:
        body["max_tokens"] = a.max_tokens
    out = post(f"{BASE}/chat/completions", body, timeout=a.timeout)
    if a.json:
        print(json.dumps(out, indent=2)[:12000])
        return 0
    for ch in out.get("choices", []):
        msg = ch.get("message", {})
        c = msg.get("content")
        if isinstance(c, list):                      # some gateways return parts
            c = "".join(p.get("text", "") for p in c if isinstance(p, dict))
        print(c or "")
        rc = msg.get("reasoning_content") or msg.get("reasoning")
        if rc and a.show_reasoning:
            print("\n[reasoning]\n" + str(rc)[:4000])
    u = out.get("usage") or {}
    print(f"\n[usage] prompt={u.get('prompt_tokens')} completion={u.get('completion_tokens')} "
          f"total={u.get('total_tokens')}", file=sys.stderr)
    return 0


def cmd_decide(a):
    state = a.state
    if a.state_file:
        state = open(a.state_file, encoding="utf-8", errors="replace").read()
    if state is None:
        raise SystemExit("need --state or --state-file")
    questions = {}
    for spec in a.choice:
        qid, _, rest = spec.partition(":")
        opts = []
        for part in rest.split(" -"):
            k, _, v = part.partition("=")
            opts.append({"id": k.strip(), "description": v.strip()})
        questions[qid.strip()] = {"type": "choice", "question": qid.strip(), "criteria": opts}
    for spec in a.probability:
        qid, _, text = spec.partition(":")
        questions[qid.strip()] = {"type": "probability", "question": text.strip()}
    for spec in a.score:
        qid, _, rest = spec.partition(":")
        q, _, levels = rest.partition(":")
        lv = [{"level": x.strip(), "description": x.strip()} for x in levels.split(",") if x.strip()]
        questions[qid.strip()] = {"type": "score", "question": q.strip(), "criteria": lv}
    if not questions:
        raise SystemExit("need at least one --choice/--probability/--score")
    out = post(DECISIONS, {"model": a.model, "state": state, "questions": questions},
               timeout=a.timeout)
    print(json.dumps(out, indent=2)[:12000])
    return 0


def cmd_models(a):
    try:
        out = get(f"{BASE}/models", timeout=a.timeout)
    except Exception as e:
        print(f"models listing failed: {e}", file=sys.stderr)
        return 2
    for m in (out.get("data") or [])[:400]:
        print(m.get("id"))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("chat")
    c.add_argument("--model", default="gpt-6-luna")
    c.add_argument("--prompt", required=True)
    c.add_argument("--system", default="")
    c.add_argument("--temperature", type=float, default=None)
    c.add_argument("--max-tokens", type=int, default=0)
    c.add_argument("--timeout", type=int, default=300)
    c.add_argument("--json", action="store_true")
    c.add_argument("--show-reasoning", action="store_true")
    c.set_defaults(func=cmd_chat)

    d = sub.add_parser("decide")
    d.add_argument("--model", default="jev-latest")
    d.add_argument("--state", default=None)
    d.add_argument("--state-file", default=None)
    d.add_argument("--choice", action="append", default=[])
    d.add_argument("--probability", action="append", default=[])
    d.add_argument("--score", action="append", default=[])
    d.add_argument("--timeout", type=int, default=180)
    d.set_defaults(func=cmd_decide)

    m = sub.add_parser("models")
    m.add_argument("--timeout", type=int, default=60)
    m.set_defaults(func=cmd_models)

    a = ap.parse_args()
    try:
        return a.func(a)
    except urllib.error.HTTPError as e:
        body = e.read()[:800].decode("utf-8", "replace")
        print(f"HTTP {e.code}: {body}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"transport error: {type(e).__name__}: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
