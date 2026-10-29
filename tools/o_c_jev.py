#!/usr/bin/env python3
"""
o_c_jev.py  (O-C = session "jailbreak 3")

Native JEV helper for the Experiential gateway.

JEV (jev-latest) is NOT a chat model - it is TypeSafe's typed decision model
(probability / choice / score questions) served at
    POST https://api.experientiallabs.ai/v1/systemone
with a body of {model, state, questions}. Per the platform's own integration
rules: read the bearer key ONLY from EXPERIENTIAL_API_KEY, never log it, use a
bounded timeout, do not add automatic retries (an unknown outcome may already
be charged), and never execute a returned choice automatically.

Use it as a second opinion on the decisions this project keeps having to make:
  * "which trigger is most likely to reach the kext" (choice)
  * "is this SPS bit layout right" (probability)
  * "how likely is this chain to work end to end" (score)

Usage:
  export EXPERIENTIAL_API_KEY=...        # set it locally, do not paste it
  python o_c_jev.py --state-file <file> --question <qid> --choice "opt=desc" ...
  python o_c_jev.py --demo               # mocked response, no network
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

ENDPOINT = "https://api.experientiallabs.ai/v1/systemone"
MODEL = "jev-latest"


def build_request(state, questions):
    return {"model": MODEL, "state": state, "questions": questions}


def call(req, timeout=90):
    key = os.environ.get("EXPERIENTIAL_API_KEY")
    if not key:
        raise SystemExit("EXPERIENTIAL_API_KEY is not set in this environment. "
                         "Set it locally (do not paste it into a chat).")
    data = json.dumps(req).encode("utf-8")
    r = urllib.request.Request(ENDPOINT, data=data, method="POST", headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return json.loads(resp.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-file", required=False)
    ap.add_argument("--state", required=False, help="inline state text")
    ap.add_argument("--question", action="append", default=[],
                    help="qid:choice -a-desc -b-desc   (choice)")
    ap.add_argument("--probability", action="append", default=[],
                    help="qid:question text             (probability)")
    ap.add_argument("--score", action="append", default=[],
                    help="qid:question:l1,l2,l3        (score)")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--timeout", type=int, default=90)
    a = ap.parse_args()

    if a.demo:
        print(json.dumps({
            "ok": True, "demo": True,
            "answers": {"review": {"choice": "accept", "probability": 0.5},
                        "confidence": {"levels": {"low": 0.2, "high": 0.8}}},
            "usage": {"input": 0, "output": 0, "total": 0},
        }, indent=2))
        return 0

    state = a.state
    if a.state_file:
        state = open(a.state_file, encoding="utf-8", errors="replace").read()
    if state is None:
        raise SystemExit("need --state or --state-file")

    questions = {}
    for spec in a.question:
        qid, _, rest = spec.partition(":")
        opts = []
        for part in rest.split(" -"):
            k, _, v = part.partition("=")
            opts.append({"id": k.strip(), "description": v.strip()})
        questions[qid.strip()] = {"type": "choice", "question": qid.strip(),
                                  "criteria": opts}
    for spec in a.probability:
        qid, _, text = spec.partition(":")
        questions[qid.strip()] = {"type": "probability", "question": text.strip()}
    for spec in a.score:
        qid, _, rest = spec.partition(":")
        q, _, levels = rest.partition(":")
        lv = [{"level": x.strip(), "description": x.strip()} for x in levels.split(",") if x.strip()]
        questions[qid.strip()] = {"type": "score", "question": q.strip(), "criteria": lv}
    if not questions:
        raise SystemExit("need at least one --question/--probability/--score")

    try:
        out = call(build_request(state, questions), timeout=a.timeout)
    except urllib.error.HTTPError as e:
        body = e.read()[:600].decode("utf-8", "replace")
        print(f"HTTP {e.code}: {body}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"transport error: {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    print(json.dumps(out, indent=2)[:8000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
