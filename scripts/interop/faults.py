"""Fault injection between real processes, for scripts/interop/failure_interop.py (stdlib only).

Two proxies that sit on the wire between two of the binaries and misbehave on purpose. The binaries
are the shipped ones; only the path between them is ours.

HttpFaultProxy     one HTTP upstream. Every request is shown to `rule(req)`, which answers what
                   happens to it:
                     "pass"                 forwarded, answered
                     "lose"                 forwarded, the upstream's answer read and thrown away, the
                                            client's connection closed: an answer lost on the way
                     "hold"                 not forwarded, never answered (until the proxy stops): a
                                            server that accepts the connection and says nothing
                     ("answer", status, json_body)
                                            answered here and not forwarded: a server that refuses
                   `rule` runs on the request's own thread, so it may block (to hold a request while
                   the driver kills a process) before it answers. `after(req)`, when set, runs once
                   the upstream has answered and before the client is (or is not) answered; it may
                   set `req["action"] = "lose"` now that it knows the answer. Every
                   request and what was done with it is in `log`. Each answer closes its connection, so no client reuses one and
                   silently sends a request twice.

ElectrumFaultProxy one Electrum server (newline-delimited JSON-RPC over TCP). Modes:
                     "hold"     honest until `trigger()` or the first request for `hold_from`, then
                                no line from the server is passed on
                     "hide"     the transactions in `hidden` (and every one broadcast through this
                                proxy) do not exist: left out of histories, unspent lists and the
                                mempool, and unknown to transaction.get and get_merkle
                     "malform"  every height, value and position in an answer is replaced by something
                                that is not a number a chain can have (negative, above 2^64, a string,
                                a fraction, null, 1e400), in turn
                   `seen` counts requests by method, `tampered` what was changed.
"""
import http.client
import json
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "content-length", "host"}


class HttpFaultProxy:
    def __init__(self, listen_port, upstream_port, rule=None, upstream_timeout=60.0):
        self.port, self.upstream_port, self.upstream_timeout = listen_port, upstream_port, upstream_timeout
        self.rule = rule or (lambda req: "pass")
        self.after = None
        self.log, self.lock, self.stopped = [], threading.Lock(), threading.Event()
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # quiet
                pass

            def handle_one(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                with proxy.lock:
                    n = len(proxy.log)
                    req = {"n": n, "t": time.time(), "method": self.command, "path": self.path, "body": body,
                           "headers": {k.lower(): v for k, v in self.headers.items()}, "action": None, "status": None}
                    req["paid"] = "payment-signature" in req["headers"]
                    proxy.log.append(req)
                action = proxy.rule(req)
                req["action"] = action if isinstance(action, str) else action[0]
                if action == "hold":
                    proxy.stopped.wait()
                    self.close_connection = True
                    return
                if isinstance(action, tuple) and action[0] == "answer":
                    _, status, payload = action
                    out = json.dumps(payload).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(out)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(out)
                    req["status"] = status
                    self.close_connection = True
                    return
                up = http.client.HTTPConnection("127.0.0.1", proxy.upstream_port, timeout=proxy.upstream_timeout)
                try:
                    hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
                    hdrs["Host"] = f"127.0.0.1:{proxy.port}"   # the origin the client signed for
                    up.request(self.command, self.path, body=body, headers=hdrs)
                    r = up.getresponse()
                    data = r.read()
                    req["status"] = r.status
                    req["answered_at"] = time.time()
                except OSError as e:
                    req["upstream_error"] = f"{type(e).__name__}: {e}"
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                finally:
                    up.close()
                self.close_connection = True
                if proxy.after:
                    proxy.after(req)          # may turn the action into "lose", now that the answer is known
                if req["action"] == "lose":
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                try:
                    self.send_response(r.status)
                    for k, v in r.getheaders():
                        if k.lower() not in HOP:
                            self.send_header(k, v)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(data)
                except OSError as e:           # the client went away (it was killed, or gave up)
                    req["client_gone"] = f"{type(e).__name__}"

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = handle_one

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", listen_port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def paid(self):
        """The paid requests seen so far (those that carried a payment)."""
        with self.lock:
            return [r for r in self.log if r["paid"]]

    def stop(self):
        self.stopped.set()
        self.server.shutdown()
        self.server.server_close()


# --- Electrum -------------------------------------------------------------------------------------

BAD_NUMBERS = [-1, "__BIG__", "12", 1.5, None, "__HUGE__"]   # __BIG__ -> 2^64 + 1, __HUGE__ -> 1e400, as bare JSON numbers
NUMBER_KEYS = ("height", "value", "block_height", "pos", "fee")


class ElectrumFaultProxy:
    def __init__(self, listen_port, upstream_port, mode, hold_from=None):
        assert mode in ("hold", "hide", "malform"), mode
        self.port, self.upstream_port, self.mode = listen_port, upstream_port, mode
        self.hold_from = hold_from      # hold: the method whose first request starts the silence (its own answer included)
        self.holding = threading.Event()
        self.hidden, self.seen, self.tampered, self.held = set(), {}, [], 0
        self.lock, self.turn = threading.Lock(), 0
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    up = socket.create_connection(("127.0.0.1", proxy.upstream_port), timeout=10)
                except OSError:
                    return
                up.settimeout(None)
                asked = {}           # id -> (method, params)

                def to_server():
                    try:
                        for line in self.request.makefile("rb"):
                            try:
                                msg = json.loads(line)
                                for m in msg if isinstance(msg, list) else [msg]:
                                    asked[m.get("id")] = (m.get("method"), m.get("params"))
                                    with proxy.lock:
                                        proxy.seen[m.get("method")] = proxy.seen.get(m.get("method"), 0) + 1
                                    if proxy.hold_from and m.get("method") == proxy.hold_from:
                                        proxy.holding.set()
                            except ValueError:
                                pass
                            up.sendall(line)
                    except OSError:
                        pass
                    finally:
                        try:
                            up.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

                threading.Thread(target=to_server, daemon=True).start()
                try:
                    for line in up.makefile("rb"):
                        out = proxy.answer(line, asked)
                        if out is not None:
                            self.request.sendall(out)
                except OSError:
                    pass
                finally:
                    try:
                        self.request.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", listen_port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def trigger(self):
        """hold: from now on the server says nothing."""
        self.holding.set()

    def hide(self, txid):
        with self.lock:
            self.hidden.add(txid)

    def note(self, what):
        with self.lock:
            self.tampered.append(what)

    def answer(self, line, asked):
        """One line from the real server: what the client gets instead (None: nothing)."""
        if self.mode == "hold":
            if self.holding.is_set():
                with self.lock:
                    self.held += 1
                return None
            return line
        try:
            msg = json.loads(line)
        except ValueError:
            return line
        batch = isinstance(msg, list)
        out = [self.one(m, asked) for m in (msg if batch else [msg])]
        text = json.dumps(out if batch else out[0])
        text = text.replace('"__BIG__"', str(2 ** 64 + 1)).replace('"__HUGE__"', "1e400")
        return text.encode() + b"\n"

    def one(self, m, asked):
        method, params = asked.get(m.get("id"), (m.get("method"), m.get("params")))
        if self.mode == "hide":
            return self.hide_in(m, method, params)
        return self.malform_in(m, method)

    def hide_in(self, m, method, params):
        res = m.get("result")
        if method == "blockchain.transaction.broadcast" and isinstance(res, str) and len(res) == 64:
            self.hide(res)       # it was passed on (the honest servers have it too); this server denies it from now on
            self.note(f"broadcast {res[:12]} passed on, then denied")
            return m
        with self.lock:
            hidden = set(self.hidden)
        if method in ("blockchain.scripthash.get_history", "blockchain.scripthash.listunspent", "blockchain.scripthash.get_mempool") \
                and isinstance(res, list):
            kept = [e for e in res if not (isinstance(e, dict) and e.get("tx_hash") in hidden)]
            if len(kept) != len(res):
                self.note(f"{method}: {len(res) - len(kept)} entr{'y' if len(res) - len(kept) == 1 else 'ies'} left out")
                return {**m, "result": kept}
        if method in ("blockchain.transaction.get", "blockchain.transaction.get_merkle") and params and params[0] in hidden \
                and "result" in m:
            self.note(f"{method} {params[0][:12]}: answered as unknown")
            return {"jsonrpc": "2.0", "id": m.get("id"), "error": {"code": 2, "message": "missing transaction"}}
        return m

    def malform_in(self, m, method):
        def bad():
            with self.lock:
                v = BAD_NUMBERS[self.turn % len(BAD_NUMBERS)]
                self.turn += 1
            return v

        def walk(v):
            if isinstance(v, dict):
                return {k: (bad() if k in NUMBER_KEYS and isinstance(x, (int, float)) and not isinstance(x, bool) else walk(x))
                        for k, x in v.items()}
            if isinstance(v, list):
                return [walk(x) for x in v]
            return v

        if method == "blockchain.headers.subscribe" and "result" not in m and isinstance(m.get("params"), list):
            new = {**m, "params": walk(m["params"])}      # a tip notification
        elif "result" in m and method not in ("server.version", "server.features", "server.banner", "server.ping"):
            new = {**m, "result": walk(m["result"])}
            if method == "blockchain.estimatefee" and isinstance(m["result"], (int, float)):
                new["result"] = bad()
        else:
            return m
        if new != m:
            self.note(f"{method}: numbers replaced")
        return new

    def stop(self):
        self.holding.set()
        self.server.shutdown()
        self.server.server_close()
