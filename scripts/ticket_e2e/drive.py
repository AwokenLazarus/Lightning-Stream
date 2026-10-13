#!/usr/bin/env python3
"""The wallet pays a gateway, end to end on a Lightning Fork regtest.

Run by scripts/ticket_e2e_regtest.sh, which brings up the chain node and builds the binaries.

    agent ---- xbt-wallet-mcp ---- xbt-signer ==== lf1 ---- lf2 ---- lf3 ==== xbt-gateway ---- file server
                                                  buyer     hop     seller

What is real: the signer, the MCP server and the gateway (the release binaries of this tree), three
Lightning Fork nodes with default settings, and a stock `python3 -m http.server` behind the gateway
that knows nothing of payments. What this file plays:

  the agent   `Mcp`: an MCP client on the wallet's stdio server. Every payment in every check is one
              `xbt402_pay` tool call with a URL; the wallet does the rest.
  the liar    `Proxy`: a reverse proxy in front of a second gateway on the same seller node, which
              changes what passes through it: the terms, the invoices, the receipts, the body.
  the hand    kills and restarts of each process and node.

Channels: lf1->lf2 of 5,000,000 sat from a coin that exists on XBT alone (the Lightning rail's
funding proof), lf2->lf3 of 5,000,000 sat. A ticket is 1,000 sat for 40 blocks; a page costs
2,500 msat and a file 200,000 msat per MiB. Checks, each PASS or FAIL with what it saw:

  page      a priced page through the wallet; a first request with its pool locked through the hop
  latency   a paid request against an unpaid one, both through the wallet
  stream    a 100 MB file whole, stopped half way by max_sats, stopped by the agent; the cancel; the
            four counts of money
  liar      seven lies, each at most one ticket and booked exactly
  kill      five things killed at two points of a session each

Usage: drive.py [check ...]   (all, in this order, when none is named)
Environment: LAB, RUN, OUT, BIN, TICKET_E2E_PORT_BASE (see the shell script).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ln_ticket"))
import lab  # noqa: E402  (the node and chain calls of the ticket lab)
from lab import LabError  # noqa: E402

RUN, OUT, BIN = (os.environ[k] for k in ("RUN", "OUT", "BIN"))
BASE = int(os.environ.get("TICKET_E2E_PORT_BASE", "17961"))
BUYER, HOP, SELLER = "lf1", "lf2", "lf3"
NODES = (BUYER, HOP, SELLER)
GW_PORT, UP_PORT, GW2_PORT, PROXY_PORT = BASE + 4, BASE + 5, BASE + 6, BASE + 7
ORIGIN = f"http://127.0.0.1:{GW_PORT}"
LIAR = f"http://127.0.0.1:{PROXY_PORT}"
SPLIT = 125  # the regtest stand-in for the height the chains split at
TICKET_MSAT = 1_000_000
BIG = 100_000_000
BYTE_MSAT, PER_BYTES = 200_000, 1_048_576
REQUEST_MSAT = 2_500
SOCK = f"{RUN}/signer.sock"
WALLET = f"{RUN}/wallet"
PAGE = "a small page\n" * 20
REPORT: dict[str, Any] = {"checks": [], "measured": {}}
FAILED: list[str] = []
PROCS: dict[str, subprocess.Popen[bytes]] = {}
#: The highest releasedMsat a seller's signed receipt has shown, by session.
RECEIPTS: dict[str, int] = {}


def check(name: str, ok: bool, saw: Any) -> None:
    REPORT["checks"].append({"check": name, "ok": bool(ok), "saw": saw})
    print(("PASS " if ok else "FAIL ") + name + "  " + json.dumps(saw)[: 300 if ok else 2500], flush=True)
    if not ok:
        FAILED.append(name)


def measured(key: str, value: Any) -> None:
    REPORT["measured"][key] = value
    print(f"     {key} = {json.dumps(value)}", flush=True)


def tick(blocks: int = 1) -> int:
    h = lab.mine(blocks, NODES)
    time.sleep(1.0)
    return h


# --- the signer and the MCP server -----------------------------------------------------------------------


def signer(method: str, params: dict[str, Any] | None = None, timeout: float = 180) -> dict[str, Any]:
    """One call on the signer's socket: for looking at the wallet, never for paying."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(SOCK)
        s.sendall((json.dumps({"id": 1, "method": method, "params": params or {}}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(1 << 16)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    reply = json.loads(buf)
    if reply.get("error"):
        raise LabError(f"signer {method}: {reply['error']}")
    return reply["result"]


class Wallet:
    """The signer process and its files."""

    def policy(self) -> dict[str, Any]:
        pk = lab.pubkey(SELLER)
        return {
            # the two origins of the one seller, each tied to its node id
            "allowlist": [ORIGIN, LIAR],
            "counterparties": {ORIGIN: {"ln_node": pk}, LIAR: {"ln_node": pk}},
            "max_per_tx_sats": 50_000,
            "daily_budget_sats": 4_000_000,
            "weekly_budget_sats": 8_000_000,
            "per_counterparty_cap_sats": 4_000_000,
            "velocity_max": 1_000,
            "velocity_window_s": 3600,
            "human_threshold_sats": 40_000,
            "split_window_s": 0,
            "regtest_mine": False,
            "anchor_interval_s": 3600,
            "ln": {"enabled": True, "split_height": SPLIT},
            # a session is one payment for velocity_max: a 100 MB file is twenty releases
            "tickets": {"enabled": True, "velocity": "session", "max_new_sellers_per_min": 200, "max_sends_per_hour": 100_000, "max_answer_s": 120,
                        "tasks": {"film": {"budget_sats": 3_000_000}}},
        }

    def write_policy(self) -> None:
        os.makedirs(f"{WALLET}/.run", exist_ok=True)
        with open(f"{WALLET}/policy.json", "w") as f:
            json.dump(self.policy(), f, indent=1)

    def start(self) -> None:
        env = dict(
            os.environ,
            B2_SIGNER_SOCK=SOCK,
            B2_RPCHOST="127.0.0.1",
            B2_RPCPORT=str(BASE),
            B2_RPCCOOKIE=f"{RUN}/rpc.cookie",
            B2_WALLET="agent",
            B2_HOT_KEYFILE=f"{RUN}/keys/wallet.key",
            B2_WATCH_INTERVAL="2",
            B2_BODY_DIR=f"{RUN}/bodies",
            B2_LN_REST=f"https://127.0.0.1:{lab.PORT[BUYER]}",
            B2_LN_MACAROON=f"{RUN}/rail.macaroon",
            B2_LN_TLS_CERT=f"{RUN}/{BUYER}.tls.cert",
        )
        if os.path.exists(SOCK):
            os.remove(SOCK)
        with open(f"{RUN}/signer.log", "ab") as log:
            PROCS["signer"] = subprocess.Popen([f"{BIN}/xbt-signer", "--root", WALLET], env=env, stdout=log, stderr=subprocess.STDOUT)
        lab.wait("the signer's socket", 60, lambda: os.path.exists(SOCK) and signer("health")["ok"])

    def ledger(self) -> list[dict[str, Any]]:
        """The committed payments, read from the wallet's files as written: a payment per line after
        the header, and amend lines that change or drop the last row of their id."""
        with open(f"{WALLET}/.run/ledger.json") as f:
            name = json.load(f)["payments_log"]
        rows: list[dict[str, Any]] = []
        with open(f"{WALLET}/.run/{name}") as f:
            for line in f.read().splitlines()[1:]:
                r = json.loads(line)
                if "amend" not in r:
                    rows.append(r)
                    continue
                i = max(i for i, p in enumerate(rows) if p["txid"] == r["amend"])
                if r["amount_sats"] is None:
                    del rows[i]
                else:
                    rows[i]["amount_sats"] = r["amount_sats"]
        return rows


WALLET_PROC = Wallet()


class Mcp:
    """An MCP client on the wallet's stdio server, with the ticket tools on. One call at a time."""

    def __init__(self) -> None:
        env = dict(os.environ, B2_SIGNER_SOCK=SOCK, XBT_MCP_TICKETS="1", B2_SIGNER_TIMEOUT="170")
        with open(f"{RUN}/mcp.log", "ab") as log:
            self.proc = subprocess.Popen([f"{BIN}/xbt-wallet-mcp", "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, env=env)
        self.lock = threading.Lock()
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ticket-e2e", "version": "1"}})
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
            raise LabError(f"the MCP server gave no answer to {method}")
        return json.loads(line)["result"]

    def tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        text = r["content"][0]["text"]
        if r.get("isError"):
            raise LabError(f"tool {name}: {text[:300]}")
        return json.loads(text)

    def tools(self) -> list[dict[str, Any]]:
        return self.rpc("tools/list", {})["tools"]

    def kill(self) -> None:
        self.proc.kill()
        self.proc.wait(10)

    def close(self) -> None:
        if self.proc.poll() is None:
            assert self.proc.stdin
            self.proc.stdin.close()
            self.proc.wait(10)


AGENT: list[Mcp] = []


def agent() -> Mcp:
    if not AGENT or AGENT[0].proc.poll() is not None:
        AGENT[:] = [Mcp()]
    return AGENT[0]


def note_receipts(r: dict[str, Any]) -> None:
    """Keep, for each session, the highest total the seller's signed receipts say was released: the
    wallet reports it as `credited_msat`, from the receipts whose signature it checked."""
    acct = r.get("account") or r
    if acct.get("session") and "credited_msat" in acct:
        RECEIPTS[acct["session"]] = max(RECEIPTS.get(acct["session"], 0), int(acct["credited_msat"]))


def pay(url: str, max_sats: int = 10, who: Mcp | None = None) -> dict[str, Any]:
    """The agent's call: one tool, one URL."""
    r = (who or agent()).tool("xbt402_pay", {"url": url, "max_sats": max_sats, "task": "film"})
    note_receipts(r)
    return r


def call_paid(r: dict[str, Any]) -> bool:
    """The call was allowed and the seller answered 200. (A refusal can carry the status of the
    answer it refused.)"""
    return r.get("verdict") == "allow" and r.get("status") == 200


def body_of(r: dict[str, Any]) -> str:
    return str((r.get("untrusted_provider_response") or {}).get("body", ""))


def status(session: str = "") -> dict[str, Any]:
    return signer("ticket_status", {"session": session} if session else {})


def brief(r: dict[str, Any]) -> dict[str, Any]:
    """A reply without the seller's body, for a check's line."""
    return {k: v for k, v in r.items() if k not in ("untrusted_provider_response", "tickets", "released", "rails_passed_over", "stopped")}


# --- what the nodes say -----------------------------------------------------------------------------------


def buyer_payments() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    offset = 0
    while True:
        page = lab.get(BUYER, f"/v1/payments?include_incomplete=true&index_offset={offset}&max_payments=500")
        for p in page["payments"]:
            out[p["payment_hash"]] = p
        if len(page["payments"]) < 500:
            return out
        offset = int(page["last_index_offset"])


def seller_invoices() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    offset = 0
    while True:
        page = lab.get(SELLER, f"/v1/invoices?index_offset={offset}&num_max_invoices=1000")
        for i in page.get("invoices", []):
            out[base64.b64decode(i["r_hash"]).hex()] = i
        if len(page.get("invoices", [])) < 1000:
            return out
        offset = int(page["last_index_offset"])


def cost_sats(p: dict[str, Any]) -> int:
    """What a settled payment cost, as the wallet books it: the amount and the fee, rounded up to a sat."""
    return -(-(int(p["value_msat"]) + int(p["fee_msat"])) // 1000)


def in_flight() -> int:
    return sum(1 for p in buyer_payments().values() if p["status"] == "IN_FLIGHT")


def held() -> int:
    return sum(1 for i in seller_invoices().values() if i["state"] == "ACCEPTED")


def quiet(secs: float = 120) -> float:
    """Wait until no ticket is locked anywhere: none in flight on the buyer's node, none held on the
    seller's, and the wallet's book agrees with its node. The seconds it took."""

    def ok() -> bool:
        if in_flight() or held():
            return False
        st = status()
        if not st.get("sessions") and not st.get("tickets"):
            return True  # a wallet that has never opened a session has no book to compare
        return st.get("synced") is True and (st.get("node") or {}).get("agree") is True and st["locked"]["tickets"] == 0

    return lab.wait("no ticket locked anywhere", secs, ok, every=0.25)


def stop_sessions(who: Mcp | None = None) -> None:
    """The agent stops every session that is open, and the tickets come back."""
    for s in status().get("sessions", []):
        if s["state"] == "open":
            note_receipts((who or agent()).tool("ticket_stop", {"session": s["session"]}).get("http") or {})
    quiet()


def money() -> dict[str, Any]:
    """The four counts that must be one: what the buyer's node paid, what the seller's node received,
    what the wallet booked, and what the seller's receipts say was released."""
    pays = [p for p in buyer_payments().values() if p["status"] == "SUCCEEDED"]
    invs = [i for i in seller_invoices().values() if i["state"] == "SETTLED"]
    st = status()
    rows = WALLET_PROC.ledger()
    return {
        "buyer_node_paid_msat": sum(int(p["value_msat"]) for p in pays),
        "seller_node_received_msat": sum(int(i["amt_paid_msat"]) for i in invs),
        "wallet_book_settled_msat": st["tickets"].get("settled", 0) * TICKET_MSAT,
        "receipts_released_msat": sum(RECEIPTS.values()),
        "wallet_ledger_sats": sum(int(r["amount_sats"]) for r in rows),
        "buyer_node_cost_sats": sum(cost_sats(p) for p in pays),
        "fees_msat": sum(int(p["fee_msat"]) for p in pays),
        "tickets": len(pays),
    }


def agrees(m: dict[str, Any], receipts: bool = True) -> bool:
    one = {m["buyer_node_paid_msat"], m["seller_node_received_msat"], m["wallet_book_settled_msat"]}
    if receipts:
        one.add(m["receipts_released_msat"])
    return len(one) == 1 and m["wallet_ledger_sats"] == m["buyer_node_cost_sats"]


def booked_and_once() -> dict[str, Any]:
    """Nothing the seller took that the wallet has not booked, and nothing paid twice: every invoice
    the seller's node settled is a ticket in the wallet's ledger, and is one payment of the buyer's
    node."""
    rows = {r["txid"] for r in WALLET_PROC.ledger()}
    settled = {h for h, i in seller_invoices().items() if i["state"] == "SETTLED"}
    paid = {h for h, p in buyer_payments().items() if p["status"] == "SUCCEEDED"}
    return {"settled_on_seller": len(settled), "not_in_ledger": sorted(h for h in settled if f"ticket:{h}" not in rows)[:3],
            "paid_on_buyer": len(paid), "same_tickets": settled == paid}


# --- the seller's processes -------------------------------------------------------------------------------


def send(method: str, target: str, port: int, headers: dict[str, str] | None = None, body: bytes = b"") -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        conn.request(method, target, body=body or None, headers=headers or {})
        r = conn.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    finally:
        conn.close()


def gateway_config(name: str, port: int, public: str) -> str:
    cfg = {
        "listen": f"127.0.0.1:{port}",
        "public_url": public,
        "upstream": f"http://127.0.0.1:{UP_PORT}",
        "state_dir": f"{RUN}/state-{name}",
        "chain": "regtest",
        "network": NETWORK[0],
        "node": {"rest": f"https://127.0.0.1:{lab.PORT[SELLER]}", "tls_cert": f"{RUN}/{SELLER}.tls.cert", "macaroon": f"{RUN}/invoices.macaroon",
                 "info_macaroon": f"{RUN}/info.macaroon"},
        "caps": {"sessions_per_address": 0, "first_use_secs": 20, "idle_secs": 40},
        "times": {"height_max_age_secs": 5},
        "routes": [
            {"path": "/big.bin", "price": {"byte_msat": BYTE_MSAT, "per_bytes": PER_BYTES}},
            {"path": "/small.txt", "price": {"request_msat": REQUEST_MSAT}},
            {"path": "/free/", "free": True},
        ],
    }
    path = f"{RUN}/{name}.json"
    with open(path, "w") as f:
        json.dump(cfg, f, indent=1)
    return path


def start_gateway(name: str, port: int) -> float:
    t0 = time.monotonic()
    with open(f"{RUN}/{name}.log", "ab") as log:
        PROCS[name] = subprocess.Popen([f"{BIN}/xbt-gateway", f"{RUN}/{name}.json"], stdout=log, stderr=log)
    lab.wait(f"{name}", 60, lambda: json.loads(send("GET", "/x402/ticket/health", port)[2])["height"] is not None, every=0.05)
    return time.monotonic() - t0


NETWORK: list[str] = [""]

# --- the liar: a proxy in front of the second gateway ----------------------------------------------------

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
RECEIPT_FIELDS = ("scheme", "session", "seq", "releasedMsat", "spentMsat", "charged", "req", "status", "bodyHash")


def _add(a: tuple[int, int] | None, b: tuple[int, int] | None) -> tuple[int, int] | None:
    if a is None or b is None:
        return a or b
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    m = (3 * a[0] * a[0] * pow(2 * a[1], -1, P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, P)) % P
    x = (m * m - a[0] - b[0]) % P
    return x, (m * (a[0] - x) - a[1]) % P


def _mul(k: int, pt: tuple[int, int] | None) -> tuple[int, int] | None:
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def sign_receipt(r: dict[str, Any], key: int) -> None:
    """Sign a receipt as the gateway signs one (ECDSA over secp256k1, low s, DER), with the seller's
    own receipt key: what a seller that lies in its own name sends."""
    t = hashlib.sha256(b"xbt402/ticket-receipt/v0").digest()
    h = hashlib.sha256(t + t)
    for k in RECEIPT_FIELDS:
        x = str(r[k]).encode()
        h.update(len(x).to_bytes(8, "little") + x)
    z = int.from_bytes(h.digest(), "big")
    while True:
        k = secrets.randbelow(N - 1) + 1
        pt = _mul(k, G)
        assert pt is not None
        rr = pt[0] % N
        s = pow(k, -1, N) * (z + rr * key) % N
        if rr and s:
            break
    s = min(s, N - s)

    def der_int(v: int) -> bytes:
        b = v.to_bytes(33, "big").lstrip(b"\x00")
        b = (b"\x00" if b[0] & 0x80 else b"") + b
        return b"\x02" + bytes([len(b)]) + b

    body = der_int(rr) + der_int(s)
    r["sig"] = (b"\x30" + bytes([len(body)]) + body).hex()


class Lies:
    """What the proxy does to what passes through it. One at a time; `None` passes everything on."""

    mode: str | None = None
    other_node = ""  # another node's id, for terms that name it
    receipt_key = 0  # the second gateway's receipt key
    kept_receipt: str | None = None
    cut_after = 0
    seen: list[tuple[str, str, bool]] = []  # (method, target, paid)


def lie_headers(method: str, target: str, paid: bool, headers: dict[str, str]) -> dict[str, str]:
    mode = Lies.mode
    if "payment-required" in headers and not paid and mode in ("other_node", "terms_change") and not target.startswith("/x402/"):
        pr = json.loads(base64.b64decode(headers["payment-required"]))
        pr["accepts"][0]["payTo"] = Lies.other_node
        headers["payment-required"] = base64.b64encode(json.dumps(pr).encode()).decode()
    if "payment-response" in headers and paid and target == "/small.txt":
        if mode == "no_receipt":
            del headers["payment-response"]
        elif mode == "replay":
            if Lies.kept_receipt is None:
                Lies.kept_receipt = headers["payment-response"]
            else:
                headers["payment-response"] = Lies.kept_receipt
        elif mode == "inflated":
            sr = json.loads(base64.b64decode(headers["payment-response"]))
            rc = sr["extra"]["receipt"]
            rc["charged"] = str(int(rc["charged"]) * 2)
            rc["spentMsat"] = str(int(rc["spentMsat"]) + REQUEST_MSAT)
            sign_receipt(rc, Lies.receipt_key)
            sr["extra"]["chargedAmount"] = rc["charged"]
            headers["payment-response"] = base64.b64encode(json.dumps(sr).encode()).decode()
    return headers


def lie_lock(body: bytes) -> bytes:
    """`other_payee`: for the buyer's hashes, hold invoices of another node."""
    v = json.loads(body)
    for t in v.get("tickets", []):
        made = lab.post(HOP, "/v2/invoices/hodl", {"hash": lab.b64(bytes.fromhex(t["hash"])), "value_msat": str(TICKET_MSAT), "cltv_expiry": "40", "expiry": "60"})
        t["invoice"] = made["payment_request"]
    return json.dumps(v).encode()


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_: Any) -> None:
        pass

    def pass_on(self, method: str) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        paid = "PAYMENT-SIGNATURE" in self.headers
        Lies.seen.append((method, self.path, paid))
        fwd = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "accept-encoding")}
        conn = http.client.HTTPConnection("127.0.0.1", GW2_PORT, timeout=60)
        try:
            conn.request(method, self.path, body=body or None, headers=fwd)
            r = conn.getresponse()
            headers = lie_headers(method, self.path, paid, {k.lower(): v for k, v in r.getheaders()})
            length = r.getheader("Content-Length")
            if self.path == "/x402/ticket/lock" and Lies.mode == "other_payee" and r.status == 200:
                data = lie_lock(r.read())
                length = str(len(data))
            else:
                data = None
            self.send_response(r.status)
            for k, v in headers.items():
                if k not in ("content-length", "transfer-encoding", "connection", "date", "server"):
                    self.send_header(k, v)
            self.send_header("Connection", "close")
            if length is not None:
                self.send_header("Content-Length", length)
            self.end_headers()
            if data is not None:
                self.wfile.write(data)
                return
            sent = 0
            cut = Lies.cut_after if (Lies.mode == "cut" and paid and self.path == "/big.bin") else 0
            while True:
                chunk = r.read(64 << 10)
                if not chunk:
                    break
                if cut and sent + len(chunk) > cut:
                    self.wfile.write(chunk[: cut - sent])
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_RDWR)  # the answer stops in the middle
                    return
                self.wfile.write(chunk)
                sent += len(chunk)
        except (OSError, http.client.HTTPException):
            pass
        finally:
            conn.close()
            self.close_connection = True

    def do_GET(self) -> None:
        self.pass_on("GET")

    def do_POST(self) -> None:
        self.pass_on("POST")

    def do_HEAD(self) -> None:
        self.pass_on("HEAD")


# --- setup ------------------------------------------------------------------------------------------------


def send_pinned(addr: str, btc: str) -> None:
    """Pay `addr` from a P2PKH coin of the lab wallet made after the split: the paying transaction
    then carries an XBT-only signature in its scriptSig, which its txid commits to. That is what
    the wallet's funding proof accepts for the channel funded from it."""
    legacy = lab.wallet("getnewaddress", "", "legacy")
    txid = lab.wallet("sendtoaddress", legacy, f"{float(btc) + 0.001:.8f}")
    lab.wallet("generatetoaddress", "1", lab.wallet("getnewaddress"))
    tx = json.loads(lab.wallet("gettransaction", txid, "true", "true"))["decoded"]
    vout = next(o["n"] for o in tx["vout"] if o["scriptPubKey"].get("address") == legacy)
    opts = json.dumps({"inputs": [{"txid": txid, "vout": vout}], "add_inputs": False})
    sent = json.loads(lab.wallet("send", json.dumps({addr: float(btc)}), "null", "unset", "2", opts))
    if not sent.get("complete"):
        raise LabError(f"send from the P2PKH coin: {sent}")


def active(node: str, count: int) -> bool:
    return sum(1 for c in lab.channels(node) if c["active"]) >= count


def open_channel(opener: str, peer: str, sats: int) -> None:
    """Open a channel, retried: right after a connect a peer can answer with a funding error."""
    for attempt in range(6):
        try:
            lab.open_channel(opener, peer, sats, 0)
            return
        except LabError:
            if attempt == 5:
                raise
            time.sleep(5)


def setup() -> None:
    lab.wait("the chain node", 120, lambda: lab.chain("getblockchaininfo"))
    lab.chain("createwallet", "lab")
    lab.chain("createwallet", "agent")
    lab.wallet("generatetoaddress", "130", lab.wallet("getnewaddress"))
    lab.dc("up", "-d", *NODES)

    def ready(node: str) -> bool:
        lab.load_credentials(node)
        return lab.synced(node)

    for node in NODES:
        lab.wait(f"{node} answering and synced", 180, partial(ready, node))
    send_pinned(lab.lncli(BUYER, "newaddress", "p2wkh")["address"], "0.2")
    lab.fund(HOP, "0.2")
    lab.mine(6, NODES)
    for node in (BUYER, HOP):
        lab.wait(f"{node}'s coin", 60, partial(lab.wallet_sat, node))
    open_channel(BUYER, HOP, 5_000_000)
    open_channel(HOP, SELLER, 5_000_000)
    lab.mine(8, NODES)
    for node, count in ((BUYER, 1), (HOP, 2), (SELLER, 1)):
        lab.wait(f"{node}'s channels active", 240, partial(active, node, count))
    lab.wait("the buyer knows both channels", 300, lambda: lab.known_channels(BUYER) >= 2, every=2)
    # the credentials: the wallet's rail macaroon for lf1, the gateway's two for lf3
    os.makedirs(f"{RUN}/keys", exist_ok=True)
    with open(f"{RUN}/rpc.cookie", "w") as f:
        f.write("lab:lab")
    for name, node, perms in (("rail", BUYER, lab.BUYER_PERMISSIONS), ("invoices", SELLER, lab.SELLER_PERMISSIONS), ("info", SELLER, ("info:read",))):
        with open(f"{RUN}/{name}.macaroon", "wb") as f:
            f.write(bytes.fromhex(lab.bake(node, perms)))
        os.chmod(f"{RUN}/{name}.macaroon", 0o600)
    NETWORK[0] = "lightning:" + lab.chain("getblockhash", "101")[:32]
    # the service: a stock file server, with a file where every MiB differs
    os.makedirs(f"{RUN}/www/free", exist_ok=True)
    block = os.urandom(1 << 20)
    with open(f"{RUN}/www/big.bin", "wb") as f:
        f.writelines((hashlib.sha256(block[:64] + i.to_bytes(8, "big")).digest() + block)[: min(len(block), BIG - i)] for i in range(0, BIG, len(block)))
    for name in ("small.txt", "free/small.txt"):
        with open(f"{RUN}/www/{name}", "w") as f:
            f.write(PAGE)
    with open(f"{RUN}/upstream.log", "ab") as log:
        PROCS["upstream"] = subprocess.Popen([sys.executable, "-m", "http.server", str(UP_PORT), "--bind", "127.0.0.1", "--directory", f"{RUN}/www"], stdout=log, stderr=log)
    lab.wait("the file server", 20, lambda: send("GET", "/small.txt", UP_PORT)[0] == 200, every=0.1)
    # two gateways beside the one seller node: the honest one, and one whose buyers reach it through the lying proxy
    gateway_config("gateway", GW_PORT, ORIGIN)
    gateway_config("gateway2", GW2_PORT, LIAR)
    measured("gateway_start_s", round(start_gateway("gateway", GW_PORT), 2))
    start_gateway("gateway2", GW2_PORT)
    with open(f"{RUN}/state-gateway2/receipt.key") as f:
        Lies.receipt_key = int(f.read().strip(), 16)
    Lies.other_node = lab.pubkey(HOP)
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), Proxy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    WALLET_PROC.write_policy()
    WALLET_PROC.start()
    st = signer("ln_status")
    check("setup: the Lightning rail is ready on lf1: chain verified, its one channel's funding proven", st.get("ready") is True, {"ready": st.get("ready"), "warnings": st.get("warnings")})
    tools = {t["name"]: t for t in agent().tools()}
    desc = tools["xbt402_pay"]["description"]
    check("setup: the MCP's xbt402_pay says which rails it chooses from and what an agent can and cannot cause, and takes the owner's task",
          all(w in desc for w in ("stream tickets", "What you can cause", "What you cannot cause")) and "task" in tools["xbt402_pay"]["inputSchema"]["properties"]
          and not any(t in tools for t in ("ticket_open", "ticket_offer", "ticket_lock", "ticket_release")), sorted(t for t in tools if "ticket" in t or t == "xbt402_pay"))


# --- the checks -------------------------------------------------------------------------------------------


def page() -> None:
    t0 = time.monotonic()
    r = pay(f"{ORIGIN}/small.txt")
    first = time.monotonic() - t0
    ok = (r.get("verdict") == "allow" and r.get("rail") == "ticket" and r.get("status") == 200 and body_of(r) == PAGE and r.get("tickets_released") == 1
          and r.get("price_msat") == str(REQUEST_MSAT) and r.get("balance_msat") == str(TICKET_MSAT - REQUEST_MSAT) and r["receipt"] == {"signed": True, "body": "as signed"})
    check("page: one xbt402_pay call fetched a priced page behind the gateway, through the hop: one ticket of the pool released, 2,500 msat used, the seller's receipt signs the body",
          ok, brief(r))
    # the node reports a payment settled a moment before it takes the HTLC off its channel: the book and the channel are
    # compared once that has happened
    try:
        lab.wait("the book and the node to agree", 10, lambda: status()["node"]["agree"] is True, every=0.2)
    except LabError:
        pass
    st = status()
    check("page: seven tickets stay locked and unreleased, and the wallet's book is its node's payments in flight",
          st["locked"] == {"tickets": 7, "sats": 7000} and st["node"]["agree"] is True and in_flight() == 7 and held() == 7,
          {"locked": st["locked"], "node": st["node"], "buyer_in_flight": in_flight(), "seller_held": held()})
    # a first request on a new session: the unpaid request, the pool locked through the hop, the seller's word, one release, the paid request
    firsts = [round(first, 3)]
    for _ in range(4):
        stop_sessions()
        t0 = time.monotonic()
        r = pay(f"{ORIGIN}/small.txt")
        firsts.append(round(time.monotonic() - t0, 3))
        if not call_paid(r) or r.get("tickets_released") != 1:
            raise LabError(f"a first request: {brief(r)}")
    measured("first_request_s", firsts)
    check("page: a first request, with the pool of 8 tickets locked through one hop, completes in 1 s (median of 5 new sessions, timed around the MCP tool call)",
          statistics.median(firsts) <= 1.0, {"median_s": statistics.median(firsts), "each_s": firsts})


def latency() -> None:
    r = pay(f"{ORIGIN}/small.txt")
    if not call_paid(r):
        raise LabError(f"latency: {brief(r)}")
    n = 200
    before = len(buyer_payments())

    def timed(url: str) -> list[float]:
        out = []
        for _ in range(n):
            t0 = time.perf_counter()
            r = pay(url)
            out.append((time.perf_counter() - t0) * 1000)
            if not call_paid(r):
                raise LabError(f"latency: {brief(r)}")
        return out

    # warm both paths, then interleave nothing: each list is one run of n calls through the same MCP process and signer
    timed_paid, timed_free = timed(f"{ORIGIN}/small.txt"), timed(f"{ORIGIN}/free/small.txt")
    direct = []
    for _ in range(n):
        t0 = time.perf_counter()
        send("GET", "/free/small.txt", GW_PORT)
        direct.append((time.perf_counter() - t0) * 1000)
    paid, free = statistics.median(timed_paid), statistics.median(timed_free)
    measured("paid_request_ms", {"median": round(paid, 3), "p90": round(sorted(timed_paid)[n * 9 // 10], 3)})
    measured("unpaid_request_ms", {"median": round(free, 3), "p90": round(sorted(timed_free)[n * 9 // 10], 3)})
    measured("direct_http_free_ms", {"median": round(statistics.median(direct), 3)})
    check("latency: a paid request from the balance adds at most 5 ms (median) over an unpaid one: 200 xbt402_pay calls of a priced page against 200 of a free page, each through the MCP, the signer and the gateway",
          paid - free <= 5.0, {"paid_ms": round(paid, 3), "unpaid_ms": round(free, 3), "added_ms": round(paid - free, 3), "tickets_locked_meanwhile": len(buyer_payments()) - before})


def digest_of_prefix(n: int) -> str:
    h = hashlib.sha256()
    with open(f"{RUN}/www/big.bin", "rb") as f:
        left = n
        while left:
            chunk = f.read(min(1 << 20, left))
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)
    return h.hexdigest()


def stream() -> None:
    stop_sessions()
    price_msat = -(-BIG * BYTE_MSAT // PER_BYTES)
    # whole: 100 MB at 200 sat a MiB is 19,074 sat, twenty tickets, each released when the last is used up
    t0 = time.monotonic()
    r = pay(f"{ORIGIN}/big.bin", max_sats=25_000)
    took = time.monotonic() - t0
    ok = (call_paid(r) and r.get("complete") is True and r.get("bytes") == BIG and r.get("body_digest") == digest_of_prefix(BIG) and r.get("price_msat") == str(price_msat)
          and r.get("tickets_released") == 20 and r["receipt"].get("body") == "as signed" and r["receipt"]["last"]["charged"] == str(price_msat))
    stored = r.get("saved_to", "")
    same_file = bool(stored) and os.path.getsize(stored) == BIG and hashlib.sha256(open(stored, "rb").read()).hexdigest() == r.get("body_digest")
    measured("file_100mb_s", round(took, 2))
    check("stream: a 100 MB file priced per byte came through the wallet whole: 20 tickets released one at a time as it arrived, the stored file is the seller's file, and the last receipt signs its hash and its price",
          ok and same_file, {**brief(r), "receipt": {"body": r["receipt"].get("body")}, "seconds": round(took, 2), "stored_is_the_file": same_file})
    if stored:
        os.remove(stored)
    # half way: the call allows half the price
    half = price_msat // 2 // 1000
    r = pay(f"{ORIGIN}/big.bin", max_sats=half)
    got = int(r.get("bytes", 0))
    by_count = -(-got * BYTE_MSAT // PER_BYTES)
    ok = (call_paid(r) and r.get("complete") is False and str(r.get("ended", "")).startswith("stopped by the wallet: max_sats") and r.get("body_digest") == digest_of_prefix(got)
          and half * 1000 <= by_count <= half * 1000 + (64 << 10) * BYTE_MSAT // PER_BYTES + 1 and got < BIG * 0.52)
    check("stream: the same file under a call that allows half its price stops half way, at the byte the call's max_sats pays for by the wallet's own count",
          ok, {**brief(r), "receipt": {"body": r["receipt"].get("body")}, "bytes": got, "max_sats": half, "price_of_bytes_msat": by_count})
    if r.get("saved_to"):
        os.remove(r["saved_to"])
    # stopped by the agent while it arrives
    other = Mcp()
    result: dict[str, Any] = {}

    def run() -> None:
        try:
            result.update(pay(f"{ORIGIN}/big.bin", max_sats=25_000, who=other))
        except LabError as e:
            result["error"] = str(e)

    t = threading.Thread(target=run)
    released_before = int((status().get("paying") or [{}])[0].get("released_msat", 0))
    t.start()
    lab.wait("the answer to be under way", 60, lambda: any(p.get("answer_open") and int(p["released_msat"]) >= released_before + 3 * TICKET_MSAT for p in status().get("paying", [])), every=0.02)
    sid = status()["sessions"][0]["session"]
    t0 = time.monotonic()
    stop = agent().tool("ticket_stop", {"session": sid})
    note_receipts(stop["http"])
    t.join(120)
    other.close()
    freed = lab.wait("the unused tickets to be back on both nodes", 30, lambda: in_flight() == 0 and held() == 0, every=0.05)
    cancelled_s = time.monotonic() - t0
    got = int(result.get("bytes", 0))
    ok = result.get("complete") is False and "ticket_session" in str(result.get("ended", "")) and 0 < got < BIG and result.get("body_digest") == digest_of_prefix(got)
    check("stream: the agent stops the session while the file arrives: the answer ends there, and what arrived is a true prefix of the file",
          ok, {**brief(result), "receipt": {"body": (result.get("receipt") or {}).get("body")}})
    if result.get("saved_to"):
        os.remove(result["saved_to"])
    measured("cancel_s", round(cancelled_s, 2))
    check("stream: after the stop the unused tickets are cancelled within 5 s: none in flight on the buyer's node, none held on the seller's",
          cancelled_s <= 5.0 and stop["http"]["cancel_sent"] is True, {"seconds": round(cancelled_s, 2), "wait_s": round(freed, 2), "stop": stop["http"]})
    quiet()
    m = money()
    check("stream: what the buyer's node paid, what the seller's node received, what the wallet booked and what the seller's receipts say was released are one number, to the millisat; the ledger is each ticket and its fee",
          agrees(m) and m["tickets"] > 20, m)


def lie(name: str, what: str, act: Any, expect: Any, most_tickets: int) -> None:
    """One lie: `act` makes the paid calls with the proxy in mode `name`; `expect` judges the last reply."""
    stop_sessions()
    before = money()
    paid_before = set(buyer_payments())
    Lies.mode, Lies.kept_receipt = None, None
    try:
        r = act()
    finally:
        Lies.mode = None
    stop_sessions()
    after = money()
    tickets = after["tickets"] - before["tickets"]
    started = len(set(buyer_payments()) - paid_before)
    verdict = expect(r)
    exact = agrees(after, receipts=False)
    check(f"liar: {what}", bool(verdict) and tickets <= most_tickets and exact,
          {"reply": brief(r), "tickets_it_cost": tickets, "payments_started": started, "booked_exactly": exact, "ledger_sats": after["wallet_ledger_sats"], "node_cost_sats": after["buyer_node_cost_sats"]})


def liar() -> None:
    page_url, big_url = f"{LIAR}/small.txt", f"{LIAR}/big.bin"

    def after_one_good(mode: str) -> Any:
        def act() -> dict[str, Any]:
            first = pay(page_url)
            if not call_paid(first):
                raise LabError(f"the honest first page: {brief(first)}")
            Lies.mode = mode
            return pay(page_url)

        return act

    def from_the_start(mode: str, url: str = page_url, max_sats: int = 10) -> Any:
        def act() -> dict[str, Any]:
            Lies.mode = mode
            return pay(url, max_sats=max_sats)

        return act

    through = pay(page_url)
    check("liar: with the proxy passing everything on, the second gateway is paid as the first is", call_paid(through) and through.get("tickets_released") == 1, brief(through))
    lie("other_node", "terms that name another node id than the one the owner tied to this origin: nothing is locked and nothing paid",
        from_the_start("other_node"), lambda r: r.get("rule") == "no_rail" and "ticket_admission" in json.dumps(r.get("rails_passed_over")), 0)
    lie("other_payee", "tickets for another payee (hold invoices of another node for the buyer's hashes): no payment leaves the buyer's node",
        from_the_start("other_payee"), lambda r: r.get("verdict") == "deny" and r.get("rule") == "ticket_payee", 0)
    lie("terms_change", "terms that change under an open session: the session is stopped and nothing more is paid",
        after_one_good("terms_change"), lambda r: r.get("rule") == "ticket_terms_changed", 1)
    lie("inflated", "inflated metering, in a receipt signed by the seller's own key (5,000 msat for a page priced at 2,500): the session is stopped",
        after_one_good("inflated"), lambda r: r.get("rule") == "ticket_seller_fault" and "charged 5000" in str(r.get("reason")), 1)
    lie("no_receipt", "a served answer with no receipt: the session is stopped",
        after_one_good("no_receipt"), lambda r: r.get("rule") == "ticket_seller_fault" and r.get("status") == 200, 1)
    lie("replay", "a receipt for another request (the page before's, replayed): the session is stopped",
        lambda: (after_one_good("replay")(), pay(page_url))[1], lambda r: r.get("rule") == "ticket_seller_fault" and "another request" in str(r.get("reason")), 1)
    Lies.cut_after = 7 << 20

    def cut_ok(r: dict[str, Any]) -> bool:
        # 7 MiB arrived and costs 1,400 sat: two tickets were released for it, so less than one ticket was paid for nothing
        got = int(r.get("bytes", 0))
        return r.get("complete") is False and str(r.get("ended", "")).startswith("cut short by the seller") and got == 7 << 20 and r.get("tickets_released") == 2

    lie("cut", "an answer that stops in the middle (7 MiB of a 100 MB file): what was released for it is paid, less than one ticket of it for nothing, and no ticket after it",
        from_the_start("cut", big_url, 25_000), cut_ok, 2)


def next_call_pays(what: str) -> dict[str, Any]:
    """After a kill and a restart: the next call pays, or says plainly why not and the one after pays."""
    said = []
    for _ in range(6):
        try:
            r = pay(f"{ORIGIN}/small.txt")
        except LabError as e:
            said.append(str(e)[:120])
            time.sleep(2)
            continue
        if call_paid(r):
            return {"calls": len(said) + 1, "said_first": said}
        said.append(f"{r.get('rule')}: {str(r.get('reason'))[:100]}")
        time.sleep(2)
    raise LabError(f"{what}: no call paid after the restart: {said}")


def killed(victim: str, at: str) -> None:
    """Kill `victim`, as a power cut, and start it again."""
    if victim == "signer":
        PROCS["signer"].kill()
        PROCS["signer"].wait(10)
        WALLET_PROC.start()
    elif victim == "mcp":
        agent().kill()
    elif victim == "gateway":
        PROCS["gateway"].kill()
        PROCS["gateway"].wait(10)
        start_gateway("gateway", GW_PORT)
    else:
        lab.dc("kill", victim)
        lab.forget_connections()
        lab.dc("start", victim)
        lab.wait(f"{victim} back and synced", 180, lambda: lab.synced(victim), every=0.2)
        peers = {BUYER: 1, SELLER: 1}[victim]
        lab.wait(f"{victim}'s channel active again", 180, partial(active, victim, peers), every=0.5)
        if victim == BUYER:
            lab.wait("the wallet's Lightning rail ready again", 120, lambda: signer("ln_status").get("ready") is True, every=1)
    print(f"     killed and restarted: {victim} ({at})", flush=True)


def kill() -> None:
    for victim in ("signer", "mcp", "gateway", BUYER, SELLER):
        # with a pool locked, between two calls
        stop_sessions()
        r = pay(f"{ORIGIN}/small.txt")
        if not call_paid(r):
            raise LabError(f"kill {victim}: the page before: {brief(r)}")
        killed(victim, "a pool locked")
        resumed = next_call_pays(f"kill {victim} with a pool locked")
        stop_sessions()
        inv, m = booked_and_once(), money()
        check(f"kill: {victim}, with a pool locked: after the restart nothing the seller took is missing from the wallet's ledger, nothing is paid twice, and the next call pays",
              not inv["not_in_ledger"] and inv["same_tickets"] and agrees(m, receipts=False), {"next": resumed, **inv, "ledger_sats": m["wallet_ledger_sats"], "node_cost_sats": m["buyer_node_cost_sats"]})
        # in the middle of an answer that is being paid for
        other = Mcp()
        result: dict[str, Any] = {}

        def run(who: Mcp = other, into: dict[str, Any] = result) -> None:
            try:
                into.update(pay(f"{ORIGIN}/big.bin", max_sats=25_000, who=who))
            except (LabError, OSError, ValueError) as e:
                into["error"] = str(e)[:200]

        base = int((status().get("paying") or [{}])[0].get("released_msat", 0))
        t = threading.Thread(target=run)
        t.start()
        lab.wait("the answer to be under way", 60, lambda: any(p.get("answer_open") and int(p["released_msat"]) >= base + 3 * TICKET_MSAT for p in status().get("paying", [])), every=0.02)
        if victim == "mcp":
            other.kill()
        else:
            killed(victim, "an answer open")
        t.join(200)
        if victim != "mcp":
            other.close()
        if result.get("saved_to"):
            os.remove(result["saved_to"])
        resumed = next_call_pays(f"kill {victim} with an answer open")
        stop_sessions()
        inv, m = booked_and_once(), money()
        how = result.get("error") or result.get("ended") or ("complete" if result.get("complete") else brief(result))
        check(f"kill: {victim}, in the middle of an answer: after the restart nothing the seller took is missing from the wallet's ledger, nothing is paid twice, and the next call pays",
              not inv["not_in_ledger"] and inv["same_tickets"] and agrees(m, receipts=False),
              {"the_call_ended": str(how)[:160], "bytes": result.get("bytes"), "next": resumed, **inv, "ledger_sats": m["wallet_ledger_sats"], "node_cost_sats": m["buyer_node_cost_sats"]})


CHECKS = {"page": page, "latency": latency, "stream": stream, "liar": liar, "kill": kill}


def main() -> int:
    names = sys.argv[1:] or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        print(f"unknown check {unknown}; the checks are {' '.join(CHECKS)}", file=sys.stderr)
        return 2
    t0 = time.time()
    try:
        setup()
        print(f"lab up in {time.time() - t0:.0f} s: {BUYER} (buyer) - {HOP} (hop) - {SELLER} (seller), height {lab.height()}", flush=True)
        for name in names:
            try:
                CHECKS[name]()
            except (LabError, OSError, http.client.HTTPException, KeyError, IndexError, ValueError, AssertionError) as e:
                check(f"{name}: ran to its end", False, f"{type(e).__name__}: {e}")
                break  # the lab is in an unknown state: later checks would report that, not themselves
    finally:
        for m in AGENT:
            if m.proc.poll() is None:
                m.proc.kill()
        for p in PROCS.values():
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
    REPORT["failed"] = FAILED
    REPORT["seconds"] = round(time.time() - t0)
    with open(os.path.join(OUT, "ticket_e2e_regtest.json"), "w") as f:
        json.dump(REPORT, f, indent=1)
    passed = sum(1 for c in REPORT["checks"] if c["ok"])
    print(f"ticket_e2e: {passed} of {len(REPORT['checks'])} checks passed, {REPORT['seconds']} s", flush=True)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
