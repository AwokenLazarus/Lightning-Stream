#!/usr/bin/env python3
"""Serve the bare repositories in one directory read-only over git's smart HTTP (`git http-backend`), for
umbrelOS's "add community app store" (umbreld clones with isomorphic-git, which speaks smart HTTP only).

    serve_git.py BIND_IP PORT DIR       -> http://BIND_IP:PORT/<name>.git for each DIR/<name>.git

Bind it to a LAN address for the test only, and stop it afterwards. Pushes are refused (receive-pack is
never passed on), and only DIR/<name>.git paths are served.
"""
import http.server
import os
import re
import subprocess
import sys

BIND, PORT, ROOT = sys.argv[1], int(sys.argv[2]), os.path.abspath(sys.argv[3])
REPOS = {n for n in os.listdir(ROOT) if n.endswith(".git") and os.path.isdir(os.path.join(ROOT, n))}


class H(http.server.BaseHTTPRequestHandler):
    def _go(self):
        path, _, query = self.path.partition("?")
        m = re.match(r"^/([A-Za-z0-9_.-]+\.git)/", path)
        if not m or m.group(1) not in REPOS or "receive-pack" in self.path or ".." in path:
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        env = {"PATH": os.environ["PATH"], "GIT_PROJECT_ROOT": ROOT, "GIT_HTTP_EXPORT_ALL": "1",
               "PATH_INFO": path, "QUERY_STRING": query, "REQUEST_METHOD": self.command,
               "CONTENT_TYPE": self.headers.get("Content-Type", ""), "CONTENT_LENGTH": str(len(body)),
               "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""), "REMOTE_ADDR": self.client_address[0]}
        r = subprocess.run(["git", "-c", "http.receivepack=false", "http-backend"], input=body, env=env, capture_output=True)
        head, _, data = r.stdout.partition(b"\r\n\r\n")
        code, hdrs = 200, []
        for line in head.decode().split("\r\n"):
            k, _, v = line.partition(":")
            if k.lower() == "status":
                code = int(v.strip().split()[0])
            elif k:
                hdrs.append((k, v.strip()))
        self.send_response(code)
        for k, v in hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _go

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % a))


http.server.ThreadingHTTPServer((BIND, PORT), H).serve_forever()
