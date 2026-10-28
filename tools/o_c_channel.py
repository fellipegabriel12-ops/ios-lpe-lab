#!/usr/bin/env python3
"""
o_c_channel.py - host<->device file channel for a-Shell.

The phone is on the same LAN as this box, so a-Shell can talk to us directly.
That gives us a real device shell channel without installing anything:

  GET  /get/<name>        -> file bytes from the inbox dir
  POST /put/<name>        -> store the body as inbox/<name>  (device -> host)
  GET  /ping              -> "pong"
  GET  /list              -> JSON listing of the inbox dir

Start it bound to 0.0.0.0 so the phone can reach it:
    python o_c_channel.py --port 8765
"""
import argparse
import http.server
import json
import os
import socketserver

INBOX = r"G:\op lab\iphone-control\jailbreak\.o_c\channel"


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0].lstrip("/")
        if path == "ping":
            return self._send(200, b"pong", "text/plain")
        if path == "list":
            os.makedirs(INBOX, exist_ok=True)
            names = sorted(os.listdir(INBOX))
            return self._send(200, json.dumps(names).encode(), "application/json")
        if path.startswith("get/"):
            name = os.path.basename(path[4:])
            p = os.path.join(INBOX, name)
            if not os.path.exists(p):
                return self._send(404, b"no such file")
            with open(p, "rb") as f:
                return self._send(200, f.read())
        if path.startswith("out/"):
            name = os.path.basename(path[4:])
            p = os.path.join(INBOX, name)
            if not os.path.exists(p):
                return self._send(404, b"no such file")
            with open(p, "rb") as f:
                return self._send(200, f.read())
        return self._send(404, b"?")

    def do_POST(self):
        path = self.path.split("?")[0].lstrip("/")
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if path.startswith("put/"):
            name = os.path.basename(path[4:]) or "unnamed"
            os.makedirs(INBOX, exist_ok=True)
            with open(os.path.join(INBOX, name), "wb") as f:
                f.write(body)
            return self._send(200, f"stored {len(body)} bytes as {name}".encode(), "text/plain")
        if path == "exec":
            # run a command on THIS host (the device asks us to do something)
            try:
                import subprocess
                r = subprocess.run(body.decode("utf-8", "replace"), shell=True,
                                   capture_output=True, timeout=120)
                out = (r.stdout or b"") + (r.stderr or b"")
                return self._send(200, out, "text/plain")
            except Exception as e:
                return self._send(500, str(e).encode(), "text/plain")
        return self._send(404, b"?")

    def log_message(self, fmt, *args):
        try:
            with open(os.path.join(INBOX, "..", "channel.log"), "a") as f:
                f.write("%s - %s\n" % (self.address_string(), fmt % args))
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--bind", default="0.0.0.0")
    a = ap.parse_args()
    os.makedirs(INBOX, exist_ok=True)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((a.bind, a.port), Handler) as httpd:
        print(f"channel listening on {a.bind}:{a.port}  inbox={INBOX}", flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
