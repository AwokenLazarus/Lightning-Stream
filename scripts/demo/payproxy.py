#!/usr/bin/env python3
"""A paying proxy for one seller: an ordinary player reads from it, and the wallet pays behind it.

    player ---- payproxy ---- xbt-wallet-mcp ---- xbt-signer ==== the buyer's Lightning node
    (mpv, ffmpeg,  (this file)  (MCP, stdio)      (the wallet)
     a browser)        every GET is one `xbt402_pay` call; the body the wallet stored is passed on

The player is given this proxy's address in place of the seller's. Every GET it makes becomes one
`xbt402_pay` call for the same path at the seller, through the wallet's MCP server and so under
the owner's policy: the proxy holds no key, no macaroon and no ticket secret, and can do nothing an
AI agent with the same three tools (`xbt402_pay`, `ticket_status`, `ticket_stop`) could not. A
film served as HLS is a playlist and one GET for each few seconds of film, so the wallet pays as
the film plays, and stops when the player stops asking.

What it serves beside the seller's paths:

    GET  /-/           a page: the film in a <video> (where the browser plays HLS itself), the
                       readout, a stop button
    GET  /-/status     the readout as JSON: sats paid, tickets released and held, the balance left
                       with the seller, draws and wins where the lottery is used
    POST /-/stop       stop the session: the held tickets are cancelled and come back

It needs the signer started with B2_BODY_DIR set and B2_BODY_CAP=0, so that the wallet stores every
body whole; the proxy passes that file on and removes it. It is a demonstration, not a product:
one seller, one request at a time, GET only, no Range (a player that asks for a part of a file is
given the whole of it), loopback only.

    payproxy.py --seller http://127.0.0.1:18307 --listen 127.0.0.1:18310 --mcp target/release/xbt-wallet-mcp \\
                [--task film] [--max-sats 2000] [--idle-stop 60] [--play '/Videos/<id>/master.m3u8?...']

Environment: what xbt-wallet-mcp reads (B2_SIGNER_SOCK or B2_ROOT, B2_SIGNER_TIMEOUT).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PAGE = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Paid as it plays</title>
<style>
 body { font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 60rem; padding: 1rem; background: #111; color: #eee; }
 video { width: 100%; background: #000; }
 table { border-collapse: collapse; margin: 1rem 0; } td { padding: .15rem 1rem .15rem 0; } td:last-child { font-variant-numeric: tabular-nums; }
 code { background: #222; padding: .1rem .3rem; } button { font: inherit; padding: .3rem 1rem; }
</style>
<h1>Paid as it plays</h1>
<video id="v" controls src="__PLAY__"></video>
<p id="hint">If the film does not start, this browser does not play HLS itself. Use a player that does:
<code>mpv 'http://__HOST____PLAY__'</code></p>
<table id="t"></table>
<button onclick="fetch('/-/stop',{method:'POST'}).then(r=>r.json()).then(j=>{document.getElementById('s').textContent=JSON.stringify(j,null,1)})">Stop and take back what is unused</button>
<pre id="s"></pre>
<script>
const rows = [["paid_sats","sats paid"],["tickets_released","tickets released"],["held_tickets","tickets held, not spent"],["held_sats","sats held, not spent"],
              ["balance_sats","left of the last ticket, with the seller"],["bytes","bytes received"],["requests","requests"],["rail","paid by"],
              ["draws","draws"],["wins","wins"],["wins_paid","wins paid"],["state","state"],["refused","last refusal"]];
async function tick() {
  try {
    const j = await (await fetch('/-/status')).json();
    document.getElementById('t').innerHTML = rows.filter(r => j[r[0]] !== null && j[r[0]] !== undefined)
      .map(r => `<tr><td>${r[1]}</td><td>${typeof j[r[0]] === 'number' ? j[r[0]].toLocaleString() : j[r[0]]}</td></tr>`).join('');
  } catch (e) {}
}
setInterval(tick, 1000); tick();
</script>
"""


class Mcp:
    """An MCP client on the wallet's stdio server. One call at a time."""

    def __init__(self, cmd: str, log: Any) -> None:
        env = dict(os.environ, XBT_MCP_TICKETS="1")
        env.setdefault("B2_SIGNER_TIMEOUT", "170")
        self.proc = subprocess.Popen([cmd, "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, env=env)
        self.lock = threading.Lock()
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "payproxy", "version": "0"}})
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()

    def rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            assert self.proc.stdin and self.proc.stdout
            self.n += 1
            self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n")
            self.proc.stdin.flush()
            line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(f"the wallet's MCP server gave no answer to {method}")
        reply = json.loads(line)
        if "result" not in reply:
            raise RuntimeError(f"the wallet's MCP server refused {method}: {json.dumps(reply.get('error'))[:300]}")
        return reply["result"]

    def tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        text = r["content"][0]["text"]
        if r.get("isError"):
            raise RuntimeError(f"tool {name}: {text[:300]}")
        return json.loads(text)

    def close(self) -> None:
        if self.proc.poll() is None:
            assert self.proc.stdin
            self.proc.stdin.close()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class Meter:
    """What this proxy has caused the wallet to pay, by the wallet's own replies."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests = 0
        self.bytes = 0
        self.price_msat = 0
        self.paid_sats = 0
        self.tickets_released = 0
        self.tickets_prepaid = 0
        self.draws = 0
        self.wins = 0
        self.wins_paid = 0
        self.balance_msat: int | None = None
        self.rail: str | None = None
        self.session: str | None = None
        self.refused: str | None = None
        self.last = 0.0
        self.stopped: dict[str, Any] | None = None
        #: Answers that stopped part way: what had arrived was paid for, and the player asks again.
        self.cut_short: list[dict[str, Any]] = []

    def took(self, r: dict[str, Any]) -> None:
        """One reply of `xbt402_pay`."""
        with self.lock:
            self.requests += 1
            self.last = time.monotonic()
            if r.get("verdict") != "allow":
                self.refused = f"{r.get('rule')}: {str(r.get('reason'))[:200]}"
                return
            self.bytes += int(r.get("bytes") or 0)
            self.price_msat += int(r.get("price_msat") or 0)
            self.paid_sats += int(r.get("charged_sats") or 0)
            self.tickets_released += int(r.get("tickets_released") or 0)
            self.tickets_prepaid += int(r.get("tickets_prepaid") or 0)
            for k in ("draws", "wins", "wins_paid"):
                setattr(self, k, getattr(self, k) + int(r.get(k) or 0))
            if r.get("rail") not in (None, "none"):
                self.rail = r["rail"]
                self.stopped = None
            if r.get("balance_msat") is not None:
                self.balance_msat = int(r["balance_msat"])
            if r.get("session"):
                self.session = r["session"]
            if r.get("complete") is False:
                self.cut_short.append({"bytes": int(r.get("bytes") or 0), "price_msat": int(r.get("price_msat") or 0), "ended": str(r.get("ended"))[:160]})


class Proxy:
    def __init__(self, a: argparse.Namespace) -> None:
        self.seller = a.seller.rstrip("/")
        self.task, self.max_sats, self.play, self.idle_stop = a.task, a.max_sats, a.play, a.idle_stop
        self.log = open(a.log, "ab") if a.log else subprocess.DEVNULL
        # two clients: a paid call holds its one until the answer has arrived, and a stop must not wait for it
        self.pay, self.ctl = Mcp(a.mcp, self.log), Mcp(a.mcp, self.log)
        self.pay_lock = threading.Lock()
        self.meter = Meter()

    def fetch(self, target: str) -> dict[str, Any]:
        """One paid request: the wallet's reply."""
        with self.pay_lock:
            r = self.pay.tool("xbt402_pay", {"url": self.seller + target, "max_sats": self.max_sats, "task": self.task})
        self.meter.took(r)
        return r

    def sessions(self) -> list[dict[str, Any]]:
        """The wallet's open sessions with this seller."""
        st = self.ctl.tool("ticket_status", {})
        paying = {p.get("session") for p in st.get("paying", []) if p.get("origin") == self.seller}
        return [s for s in st.get("sessions", []) if s.get("state") == "open" and (s.get("session") in paying or s.get("session") == self.meter.session)]

    def status(self) -> dict[str, Any]:
        m = self.meter
        try:
            st = self.ctl.tool("ticket_status", {})
            locked = st.get("locked") or {}
            held = {"held_tickets": int(locked.get("tickets") or 0), "held_sats": int(locked.get("sats") or 0)}
        except (RuntimeError, OSError, ValueError) as e:
            held = {"held_tickets": None, "held_sats": None, "wallet": str(e)[:200]}
        with m.lock:
            idle = time.monotonic() - m.last if m.last else None
            state = "stopped" if m.stopped is not None else "waiting for the player" if idle is None else "paying" if self.pay_lock.locked() or idle < 2 else "idle"
            return {"seller": self.seller, "task": self.task, "state": state, "requests": m.requests, "bytes": m.bytes, "price_msat": m.price_msat, "paid_sats": m.paid_sats,
                    "tickets_released": m.tickets_released, "tickets_prepaid": m.tickets_prepaid, **held,
                    "balance_sats": None if m.balance_msat is None else m.balance_msat // 1000, "rail": m.rail,
                    "draws": m.draws if m.rail == "lottery" else None, "wins": m.wins if m.rail == "lottery" else None, "wins_paid": m.wins_paid if m.rail == "lottery" else None,
                    "session": m.session, "idle_s": None if idle is None else round(idle, 1), "refused": m.refused, "cut_short": m.cut_short[-8:], "stopped": m.stopped}

    def stop(self, why: str) -> dict[str, Any]:
        """Stop every open session with this seller. What came back: the tickets that were held are
        cancelled by the seller and their sats are free again; what is left of the last released
        ticket stays with the seller."""
        out: dict[str, Any] = {"why": why, "sessions": []}
        try:
            for s in self.sessions():
                r = self.ctl.tool("ticket_stop", {"session": s["session"]})
                http = r.get("http") or {}
                out["sessions"].append({"session": s["session"], "held_tickets_asked_back": http.get("cancel_asked"), "seller_took_the_cancel": http.get("cancel_sent"),
                                        "still_locked": http.get("still_locked"), "left_with_the_seller_msat": (http.get("account") or {}).get("balance_msat")})
        except (RuntimeError, OSError, ValueError) as e:
            out["error"] = str(e)[:300]
        with self.meter.lock:
            self.meter.stopped = out
        return out

    def watch_idle(self) -> None:
        """A player that has asked for nothing for `idle_stop` seconds has stopped or been closed:
        the session is stopped, so the tickets held for it come back."""
        while True:
            time.sleep(1)
            with self.meter.lock:
                idle = time.monotonic() - self.meter.last if self.meter.last else 0
                due = self.meter.stopped is None and self.meter.rail is not None and idle > self.idle_stop
            if due and not self.pay_lock.locked():
                self.stop(f"no request for {self.idle_stop} s")


def kind_of(target: str, head: bytes) -> str:
    path = target.split("?")[0].lower()
    if head.startswith(b"#EXTM3U") or path.endswith(".m3u8"):
        return "application/vnd.apple.mpegurl"
    for ext, kind in ((".ts", "video/mp2t"), (".mp4", "video/mp4"), (".m4s", "video/iso.segment"), (".mkv", "video/x-matroska"), (".json", "application/json"), (".txt", "text/plain")):
        if path.endswith(ext):
            return kind
    return "application/octet-stream"


def handler(px: Proxy) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_: Any) -> None:
            pass

        def answer(self, status: int, kind: str, body: bytes, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def say(self, status: int, obj: Any) -> None:
            self.answer(status, "application/json", json.dumps(obj, indent=1).encode())

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if self.path == "/-/stop":
                self.say(200, px.stop("asked"))
            else:
                self.say(405, {"error": "this proxy passes on GET only"})

        def do_GET(self) -> None:
            if self.path in ("/-/", "/-"):
                page = PAGE.replace("__PLAY__", px.play or "").replace("__HOST__", self.headers.get("Host") or "")
                self.answer(200, "text/html; charset=utf-8", page.encode())
            elif self.path == "/-/status":
                self.say(200, px.status())
            elif self.path.startswith("/-/"):
                self.say(404, {"error": "no such page"})
            else:
                self.paid()

        def paid(self) -> None:
            try:
                r = px.fetch(self.path)
            except (RuntimeError, OSError, ValueError) as e:
                self.say(502, {"error": "the wallet gave no answer", "detail": str(e)[:300]})
                return
            if r.get("verdict") != "allow":
                # the wallet's refusal, in its words: a budget, a cap, a seller it may not pay
                self.say(402, {"error": "the wallet did not pay", "rule": r.get("rule"), "reason": r.get("reason"), "retry_after_s": r.get("retry_after_s")})
                return
            status, size, stored = int(r.get("status") or 502), int(r.get("bytes") or 0), r.get("saved_to")
            if size and not stored:
                # the wallet's preview is text, cut to a length: only a body that is the same bytes again is passed on
                body = str((r.get("untrusted_provider_response") or {}).get("body", "")).encode()
                if len(body) != size or hashlib.sha256(body).hexdigest() != r.get("body_digest"):
                    self.say(502, {"error": "the wallet stored no copy of the body: start the signer with B2_BODY_DIR set and B2_BODY_CAP=0"})
                    return
            else:
                body = b""
            extra = {"X-Paid-Sats": str(r.get("charged_sats") or 0), "X-Paid-Rail": str(r.get("rail"))}
            if r.get("complete") is False:
                # a body that stopped part way (the connection dropped, the seller left, the call's limit): a player given
                # half a segment as if it were whole shows a fault, so it is told, and asks again. What arrived was paid for
                if stored:
                    try:
                        os.remove(stored)
                    except OSError:
                        pass
                self.say(502, {"error": "the answer stopped part way", "ended": r.get("ended"), "bytes": size, "charged_sats": r.get("charged_sats")})
                return
            if not stored:
                self.answer(status, kind_of(self.path, body[:8]), body, extra)
                return
            try:
                with open(stored, "rb") as f:
                    head = f.read(8)
                    f.seek(0)
                    self.send_response(status)
                    self.send_header("Content-Type", kind_of(self.path, head))
                    self.send_header("Content-Length", str(os.path.getsize(stored)))
                    self.send_header("Cache-Control", "no-store")
                    for k, v in extra.items():
                        self.send_header(k, v)
                    self.end_headers()
                    while chunk := f.read(1 << 16):
                        self.wfile.write(chunk)
            except OSError:
                self.close_connection = True  # the player went away: what was paid for is paid
            finally:
                try:
                    os.remove(stored)
                except OSError:
                    pass

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seller", required=True, help="the seller's origin, as the owner's policy names it")
    ap.add_argument("--listen", default="127.0.0.1:18310")
    ap.add_argument("--mcp", required=True, help="the xbt-wallet-mcp binary")
    ap.add_argument("--task", default="", help="the owner's task the calls are paid under")
    ap.add_argument("--max-sats", type=int, default=2000, help="the most one request may use")
    ap.add_argument("--idle-stop", type=int, default=60, help="stop the session after this many seconds without a request (0: never)")
    ap.add_argument("--play", default="", help="the film's path at the seller, for the page")
    ap.add_argument("--log", default="", help="where the MCP server's stderr goes")
    a = ap.parse_args()
    host, port = a.listen.rsplit(":", 1)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("payproxy: it listens on this machine only: whoever reaches it spends from the wallet", file=sys.stderr)
        return 2
    px = Proxy(a)
    server = ThreadingHTTPServer((host, int(port)), handler(px))
    server.daemon_threads = True
    if a.idle_stop > 0:
        threading.Thread(target=px.watch_idle, daemon=True).start()

    def leave(*_: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, leave)
    signal.signal(signal.SIGINT, leave)
    print(f"payproxy: http://{a.listen}/-/ pays {px.seller} for what a player reads from http://{a.listen}", flush=True)
    server.serve_forever()
    # closing returns what is unused: the held tickets are cancelled before the proxy leaves
    print("payproxy: " + json.dumps(px.stop("the proxy was closed")), flush=True)
    px.pay.close()
    px.ctl.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
