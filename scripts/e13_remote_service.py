#!/usr/bin/env python3
"""Control plane for a split client/server E13 run.

When the benchmark host and the client machines are different boxes, the client
can no longer create a bare repository with `git init --bare`, nor measure what
the remote stores with `du`. Both are needed per point, and neither is part of
any timed operation -- they bracket the measurement rather than sit inside it.

This exposes exactly those two things over HTTP, next to the smart-HTTP git
server that carries the arms' actual traffic:

    POST /repo/create?name=X   fresh bare repo, receive-pack enabled
    GET  /repo/size?name=X     repack, then total bytes on disk
    GET  /safehub/size         total bytes in the SafeHub server's data dir
    POST /repo/drop?name=X     remove one repo
    POST /reset                remove every repo

Sizes are reported after a repack because loose objects and packs are two
representations of the same content: an arm whose push leaves objects loose
would otherwise look several times more expensive than one whose push packs.

Usage: e13_remote_service.py <project_root> <safehub_data_dir> <port> [bind]
"""
import json
import os
import re
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.abspath(sys.argv[1])
SAFEHUB_DATA = os.path.abspath(sys.argv[2])
PORT = int(sys.argv[3])
BIND = sys.argv[4] if len(sys.argv) > 4 else "127.0.0.1"

# Repository names come from the client over the network. Anything outside this
# shape is refused rather than sanitised, so a name can never walk out of ROOT.
SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,64}$")


def repo_path(name: str) -> str:
    if not SAFE.match(name or ""):
        raise ValueError(f"unsafe repository name: {name!r}")
    p = os.path.join(ROOT, name + ".git")
    if os.path.dirname(os.path.abspath(p)) != ROOT:
        raise ValueError("path escapes project root")
    return p


def dir_bytes(path: str) -> int:
    total = 0
    for dirpath, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return total


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def _send(self, code: int, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _route(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        name = (q.get("name") or [""])[0]
        try:
            if u.path == "/repo/create":
                p = repo_path(name)
                shutil.rmtree(p, ignore_errors=True)
                subprocess.run(["git", "init", "--bare", "-q", "--template=",
                                "--initial-branch=main", p], check=True)
                # git-http-backend refuses receive-pack for an anonymous caller
                # unless the repository opts in.
                for k, v in (("http.receivepack", "true"),
                             ("http.uploadpack", "true")):
                    subprocess.run(["git", "-C", p, "config", k, v], check=True)
                return self._send(200, {"ok": True, "path": p})

            if u.path == "/repo/size":
                p = repo_path(name)
                if not os.path.isdir(p):
                    return self._send(404, {"error": "no such repository"})
                subprocess.run(["git", "-C", p, "gc", "--quiet", "--prune=now"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return self._send(200, {"bytes": dir_bytes(p)})

            if u.path == "/safehub/size":
                return self._send(200, {"bytes": dir_bytes(SAFEHUB_DATA)})

            if u.path == "/repo/drop":
                shutil.rmtree(repo_path(name), ignore_errors=True)
                return self._send(200, {"ok": True})

            if u.path == "/reset":
                for e in os.listdir(ROOT):
                    if e.endswith(".git"):
                        shutil.rmtree(os.path.join(ROOT, e), ignore_errors=True)
                return self._send(200, {"ok": True})

            if u.path == "/health":
                return self._send(200, {"ok": True, "root": ROOT})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except subprocess.CalledProcessError as e:
            return self._send(500, {"error": f"git failed: {e}"})
        return self._send(404, {"error": "no such endpoint"})

    def do_GET(self):
        self._route()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        self._route()


class Server(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    os.makedirs(ROOT, exist_ok=True)
    Server((BIND, PORT), Handler).serve_forever()
