#!/usr/bin/env python3
"""Minimal git smart-HTTP server, so git is measured over the same transport
as SafeHub.

The parity benchmark must not hand either system a transport advantage.
`git daemon` speaks the native git:// protocol, which is leaner than HTTP:
no request/response header framing, no chunked encoding, one connection for
the whole exchange. SafeHub's client talks HTTP to safehub-server. Comparing
the two would credit git with a protocol it is not being compared on.

This serves git over HTTP by exec'ing the stock `git http-backend` CGI, which
is what real git hosts run behind nginx or Apache.

Usage: git_http_server.py <project_root> <port> [bind_addr]
"""
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJECT_ROOT = os.path.abspath(sys.argv[1])
PORT = int(sys.argv[2])
BACKEND = subprocess.run(
    ["git", "--exec-path"], capture_output=True, text=True, check=True
).stdout.strip() + "/git-http-backend"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass  # keep the benchmark output clean

    def _run(self, body: bytes = b""):
        path, _, query = self.path.partition("?")
        env = dict(os.environ)
        env.update(
            GIT_PROJECT_ROOT=PROJECT_ROOT,
            GIT_HTTP_EXPORT_ALL="1",
            REQUEST_METHOD=self.command,
            PATH_INFO=path,
            QUERY_STRING=query,
            REMOTE_USER="",
            REMOTE_ADDR=self.client_address[0],
            CONTENT_TYPE=self.headers.get("Content-Type", ""),
            CONTENT_LENGTH=str(len(body)),
            SERVER_PROTOCOL="HTTP/1.1",
            GATEWAY_INTERFACE="CGI/1.1",
        )
        enc = self.headers.get("Content-Encoding")
        if enc:
            env["HTTP_CONTENT_ENCODING"] = enc

        # Stream rather than buffer. `subprocess.run(..., capture_output=True)`
        # holds the entire CGI response in memory before a byte reaches the
        # socket, which on a 5 MiB fetch is 5 MiB copied through Python before
        # the client sees anything. Since this server is the git arm of a
        # benchmark, any cost it adds is charged to git, so it is worth keeping
        # thin. The response length is unknown until the CGI finishes, so the
        # body goes out chunked.
        proc = subprocess.Popen(
            [BACKEND], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env,
        )
        try:
            if body:
                proc.stdin.write(body)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

        # Read only as far as the CGI header terminator, then stream the rest.
        buf = b""
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            buf += chunk
        head, sep, rest = buf.partition(b"\r\n\r\n")
        if not sep:
            head, sep, rest = buf.partition(b"\n\n")

        status = 200
        headers = []
        for line in head.split(b"\n"):
            line = line.strip()
            if not line:
                continue
            name, _, value = line.partition(b":")
            name = name.strip().decode("latin-1")
            value = value.strip().decode("latin-1")
            if name.lower() == "status":
                status = int(value.split()[0])
            elif name.lower() != "content-length":
                headers.append((name, value))

        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def emit(data):
            if data:
                self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")

        emit(rest)
        while True:
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            emit(chunk)
        self.wfile.write(b"0\r\n\r\n")
        proc.stdout.close()
        proc.wait()

    def do_GET(self):
        self._run()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size_line = self.rfile.readline().strip()
                size = int(size_line.split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            body = b"".join(chunks)
        self._run(body)


class Server(ThreadingHTTPServer):
    # The default backlog of 5 is fine for one local client and not for a
    # benchmark host serving several client machines: a refused connection
    # would be charged to git as a failed operation.
    request_queue_size = 128
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    # Bind address is an argument so the same server can back a single-box run
    # (loopback) or a split client/server run (all interfaces). It defaults to
    # loopback: a git remote that accepts anonymous receive-pack should not be
    # exposed beyond the interface the caller asked for.
    BIND = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    Server((BIND, PORT), Handler).serve_forever()
