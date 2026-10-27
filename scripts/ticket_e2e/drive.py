#!/usr/bin/env python3
"""The wallet pays a gateway, end to end on a Lightning Fork regtest.

Run by scripts/ticket_e2e_regtest.sh, which brings up the chain node and builds the binaries.

    agent ---- xbt-wallet-mcp ---- xbt-signer ==== lf1 ---- lf2 ---- lf3 ==== xbt-gateway ---- file server
                                                  buyer     hop     seller

What is real: the signer, the MCP server and the gateway (the release binaries of this tree), three
Lightning Fork nodes, and a stock `python3 -m http.server` behind the gateway that knows nothing of
payments. The wallet's policy sets no pool and the gateway's config no cap on held tickets: both as
they ship (2 tickets a session; 15 held in all). The hop and the seller accept 30 pending payments
from a peer, so the buyer's channel and the seller's inbound channel carry 30: the slot count of a
channel with a Core Lightning node at its default. What this file plays:

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
  slots     the 30-slot channel: with half of the buyer's channel taken by others the wallet holds
            nothing and buys prepaid tickets; a seller at its cap says slots_short and is paid the
            same way; a lock that finds no slot on the way makes the session hold less and wait
  offers    prepaid tickets and lottery wins paid by a BOLT 12 offer of an unannounced seller (lf4),
            over its blinded paths; a wallet with offers off paid by the gateway's invoices

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
#: The highest releasedMsat a seller's signed receipt has shown, by the wallet's session.
RECEIPTS: dict[str, int] = {}
#: The seller's session of a wallet's session, where a reply named it: two sessions of the wallet
#: that took over one balance share the seller's, whose totals count once.
SELLER_OF: dict[str, str] = {}


# The speed checks hold for a quiet machine. A run that starts with the load average above this
# (TICKET_E2E_LOAD_MAX, default 4) reports its timings and does not judge them: the money, body and
# crash checks are judged in every run.
LOAD_MAX = float(os.environ.get("TICKET_E2E_LOAD_MAX", "4"))
LOAD_AT_START = os.getloadavg()[0]
REPORT["load_at_start"] = {"load_average_1m": round(LOAD_AT_START, 2), "max_for_speed_checks": LOAD_MAX}


def timed_check(name: str, ok: bool, saw: dict[str, Any]) -> None:
    if LOAD_AT_START <= LOAD_MAX:
        check(name, ok, saw)
        return
    check(f"{name} (not judged: load average {LOAD_AT_START:.1f} at the start, above {LOAD_MAX:g})", True,
          {**saw, "judged": False, "would_pass": bool(ok), "load_at_start": round(LOAD_AT_START, 2)})


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
            # as shipped a session is one payment for velocity_max (a 100 MB file is twenty releases), a session holds
            # 2 tickets and the wallet 15 in all: none of that is set here
            "tickets": {"enabled": True, "max_new_sellers_per_min": 200, "max_sends_per_hour": 100_000, "max_answer_s": 120,
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
        if acct.get("seller_session"):
            SELLER_OF[acct["session"]] = acct["seller_session"]


# the limit of a call that pays a few cents' worth: room for whole tickets, since the wallet never pays a ticket that
# would take a call over its max_sats
CALL_SATS = 2_000


def pay(url: str, max_sats: int = CALL_SATS, who: Mcp | None = None) -> dict[str, Any]:
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
        # a buyer's node that was killed in the instant it sent a payment can go on calling that payment in flight with
        # nothing on its channel (docs/LIMITS.md): such a payment holds no money and no slot, and is not waited for
        on_channel = {base64.b64decode(h["hash_lock"]).hex() for c in lab.channels(BUYER) for h in c["pending_htlcs"]}
        flying = {h for h, p in buyer_payments().items() if p["status"] == "IN_FLIGHT"}
        if on_channel or held():
            return False
        ORPHANS.update(flying)
        st = status()
        if not st.get("sessions") and not st.get("tickets"):
            return True  # a wallet that has never opened a session has no book to compare
        node = st.get("node") or {}
        left = set(node.get("in_book_not_on_node") or [])
        return st.get("synced") is True and not node.get("on_node_not_in_book") and left <= ORPHANS and st["locked"]["tickets"] <= len(left)

    return lab.wait("no ticket locked anywhere", secs, ok, every=0.25)


ORPHANS: set[str] = set()  # payments the buyer's node calls in flight with nothing on its channel


def stop_sessions(who: Mcp | None = None, forget: bool = True) -> None:
    """The agent stops every session that is open, and the tickets come back. With `forget` (each
    check starts clean with the seller), the credit a session leaves there is given up as well, so
    the next session starts with none instead of taking it over."""
    for s in status().get("sessions", []):
        if s["state"] == "open":
            note_receipts((who or agent()).tool("ticket_stop", {"session": s["session"]}).get("http") or {})
            if forget:
                signer("ticket_stop", {"session": s["session"], "forget_credit": True})
    quiet()


def receipts_released() -> int:
    """What the seller's receipts say was released, each seller session counted once."""
    by_seller: dict[str, int] = {}
    for wallet, msat in RECEIPTS.items():
        seller = SELLER_OF.get(wallet, wallet)
        by_seller[seller] = max(by_seller.get(seller, 0), msat)
    return sum(by_seller.values())


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
        "receipts_released_msat": receipts_released(),
        "wallet_ledger_sats": sum(int(r["amount_sats"]) for r in rows),
        # booked as spent and not settled: after `quiet`, only tickets whose payment the buyer's node still calls in
        # flight with nothing on its channel (a node killed as it sent one). The wallet counts them until the node drops them
        "booked_for_payments_the_node_left_in_flight_sats": int(st.get("booked_sats") or 0),
        "buyer_node_cost_sats": sum(cost_sats(p) for p in pays),
        "fees_msat": sum(int(p["fee_msat"]) for p in pays),
        "tickets": len(pays),
    }


def agrees(m: dict[str, Any], receipts: bool = True) -> bool:
    one = {m["buyer_node_paid_msat"], m["seller_node_received_msat"], m["wallet_book_settled_msat"]}
    if receipts:
        one.add(m["receipts_released_msat"])
    left = m["booked_for_payments_the_node_left_in_flight_sats"]
    return len(one) == 1 and m["wallet_ledger_sats"] == m["buyer_node_cost_sats"] + left and (left == 0 or bool(ORPHANS))


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


def gateway_config(name: str, port: int, public: str, caps: dict[str, Any] | None = None) -> str:
    cfg = {
        "listen": f"127.0.0.1:{port}",
        "public_url": public,
        "upstream": f"http://127.0.0.1:{UP_PORT}",
        "state_dir": f"{RUN}/state-{name}",
        "chain": "regtest",
        "network": NETWORK[0],
        "node": {"rest": f"https://127.0.0.1:{lab.PORT[SELLER]}", "tls_cert": f"{RUN}/{SELLER}.tls.cert", "macaroon": f"{RUN}/invoices.macaroon",
                 "info_macaroon": f"{RUN}/info.macaroon"},
        # (every buyer of this lab comes from 127.0.0.1: the caps per address would count them all as one)
        "caps": {"sessions_per_address": 0, "unpaid_per_address": 0, "first_use_secs": 20, "idle_secs": 40, **(caps or {})},
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


def restart_gateway(caps: dict[str, Any]) -> None:
    """The lab's main gateway stopped and started again on its journal, with `caps` over its config's."""
    PROCS["gateway"].terminate()
    PROCS["gateway"].wait(10)
    gateway_config("gateway", GW_PORT, ORIGIN, caps)
    start_gateway("gateway", GW_PORT)


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
    NETWORK[0] = "bip122:" + lab.chain("getblockhash", "101")[:32]
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
    # one of the two was released, so the next was locked behind the call
    try:
        lab.wait("the refill behind the call", 15, lambda: status()["locked"]["tickets"] == 2 and status()["node"]["agree"] is True and held() == 2, every=0.1)
    except LabError:
        pass
    st = status()
    check("page: one ticket was left and the next was locked behind the call: two are locked and unreleased again, and the wallet's book is its node's payments in flight",
          st["locked"] == {"tickets": 2, "sats": 2000} and st["node"]["agree"] is True and in_flight() == 2 and held() == 2,
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
    timed_check("page: a first request, with the pool of 2 tickets locked through one hop, completes in 1 s (median of 5 new sessions, timed around the MCP tool call)",
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
    timed_check("latency: a paid request from the balance adds at most 5 ms (median) over an unpaid one: 200 xbt402_pay calls of a priced page against 200 of a free page, each through the MCP, the signer and the gateway",
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
    # no ticket is released that would take the call over its limit, fee limit included: it stops within a ticket
    # and its fee limit below half, never above
    ok = (call_paid(r) and r.get("complete") is False and str(r.get("ended", "")).startswith("stopped by the wallet: max_sats") and r.get("body_digest") == digest_of_prefix(got)
          and half * 1000 - 1_015_000 <= by_count <= half * 1000 + (64 << 10) * BYTE_MSAT // PER_BYTES + 1 and got < BIG * 0.52
          and int(r.get("charged_sats") or 0) <= half)
    check("stream: the same file under a call that allows half its price stops near half way, at the byte the tickets that fit the call's max_sats pay for by the wallet's own count",
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
          # (the cancel is sent when the stop finds a ticket locked; with a pool of 2 a stop can come between two
          # lock rounds, when both tickets are released and nothing is locked: then there is nothing to ask for)
          cancelled_s <= 5.0 and (stop["http"]["cancel_sent"] is True or stop["http"]["cancel_asked"] == 0),
          {"seconds": round(cancelled_s, 2), "wait_s": round(freed, 2), "stop": stop["http"]})
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

    def from_the_start(mode: str, url: str = page_url, max_sats: int = CALL_SATS) -> Any:
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
    end = time.time() + 150
    while time.time() < end:
        try:
            r = pay(f"{ORIGIN}/small.txt")
        except LabError as e:
            said.append(str(e)[:120])
            time.sleep(2)
            continue
        if call_paid(r):
            return {"calls": len(said) + 1, "said_first": said, "prepaid": r.get("tickets_prepaid")}
        said.append(f"{r.get('rule')}: {str(r.get('reason'))[:100]}")
        # a lock that failed while a node was coming back makes the wallet wait before it locks again, and says how long
        time.sleep(min(max(float(r.get("retry_after_s") or 2), 2), 35))
    raise LabError(f"{what}: no call paid after the restart: {said}")


def has_route() -> bool:
    """The buyer's node finds a route for a ticket to the seller, as its own payments look for one."""
    path = f"/v1/graph/routes/{lab.pubkey(SELLER)}/{TICKET_MSAT // 1000}?use_mission_control=true&fee_limit.fixed=1000"
    return bool(lab.get(BUYER, path).get("routes"))


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
        # the buyer's node finds a route to the seller again, as its payments will look for one (with what it has
        # learnt of failed hops): on a busy host the hop's channel to a seller that restarted went down and up for
        # minutes, and every payment meanwhile failed with no route, nothing spent (seen on this lab)
        lab.wait("a route from the buyer's node to the seller", 300, has_route, every=1)
    print(f"     killed and restarted: {victim} ({at})", flush=True)


def kill() -> None:
    for victim in ("signer", "mcp", "gateway", BUYER, SELLER):
        # with a pool locked, between two calls
        stop_sessions()
        r = pay(f"{ORIGIN}/small.txt")
        if not call_paid(r):
            raise LabError(f"kill {victim}: the page before: {brief(r)}")
        # the pool is filled again behind the call: the kill comes when that round is over and the channel lists both
        # tickets. (A buyer's node killed in the instant it sends a payment can keep that payment "in flight" with
        # nothing on its channel, also after a restart: seen on this lab, and stated in docs/LIMITS.md.)
        # (two tickets; one, for the ten minutes after the slots check, in which the wallet holds less with this seller;
        # and after a kill of the buyer's node left tickets locked in the book that are on none of its channels, the
        # session holds what the owner's cap for one seller has left, which can be nothing. Those tickets are in
        # neither count here: they are in the book, and not on the channel.) And the seller's node holds each of them:
        # a ticket is on the buyer's channel a moment before it is on the seller's, and a node killed in that moment
        # sends it back through the hop as a failure of that hop's channel, after which the buyer's node finds no
        # route for a while (seen on this lab: the download that follows was then refused, with nothing paid)
        saw: dict[str, Any] = {}

        def settled_down() -> bool:
            s = session_of(r)
            st = status()
            # (only those the book counts as locked: a payment the node left in flight after its secret was booked,
            # a prepaid ticket's for one, is on no channel either and is not among the locked)
            left = set((st.get("node") or {}).get("in_book_not_on_node") or []) & ORPHANS
            stranded = sum(1 for x in st.get("sessions", []) if left for t in status(x["session"]).get("session_tickets", [])
                           if t["hash"] in left and t["state"] in ("locked", "sending"))
            locked = st["locked"]["tickets"] - stranded
            waiting = float(s.get("hold_until") or 0) > time.time()
            saw.update(locked=st["locked"]["tickets"], stranded=stranded, on_channel=wallet_in_flight(0), held_by_seller=held(), pool=s.get("pool"), waiting=waiting,
                       hold_why=s.get("hold_why"), tickets=st.get("tickets"), node=st.get("node"), orphans=len(ORPHANS))
            return locked == saw["on_channel"] and locked == saw["held_by_seller"] and (waiting or locked == int(s.get("pool") or 0))

        try:
            lab.wait("the pool locked and listed", 30, settled_down, every=0.1)
        except LabError as e:
            raise LabError(f"{e}; last seen: {json.dumps(saw)[:900]}") from e
        killed(victim, "a pool locked")
        resumed = next_call_pays(f"kill {victim} with a pool locked")
        stop_sessions()
        inv, m = booked_and_once(), money()
        check(f"kill: {victim}, with a pool locked: after the restart nothing the seller took is missing from the wallet's ledger, nothing is paid twice, and the next call pays",
              not inv["not_in_ledger"] and inv["same_tickets"] and agrees(m, receipts=False), {"next": resumed, **inv, "ledger_sats": m["wallet_ledger_sats"], "node_cost_sats": m["buyer_node_cost_sats"], "money": m, "orphans": sorted(ORPHANS)})
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
              {"the_call_ended": str(how)[:160], "bytes": result.get("bytes"), "next": resumed, **inv, "ledger_sats": m["wallet_ledger_sats"], "node_cost_sats": m["buyer_node_cost_sats"], "money": m, "orphans": sorted(ORPHANS),
               "payments_the_node_still_calls_in_flight_with_nothing_on_its_channel": len(ORPHANS)})


def session_of(r: dict[str, Any]) -> dict[str, Any]:
    return next((x for x in status().get("sessions", []) if x.get("session") == r.get("session")), {})


def events(kind: str, session: str = "") -> list[dict[str, Any]]:
    return [e for e in signer("history", {"limit": 5000})["events"] if e.get("type") == kind and (not session or e.get("session") == session)]


def gateway_health() -> dict[str, Any]:
    return json.loads(send("GET", "/x402/ticket/health", GW_PORT)[2])


def wallet_in_flight(others: int) -> int:
    """Payments pending on the buyer's channel beyond the `others` the lab put there."""
    return sum(len(c["pending_htlcs"]) for c in lab.channels(BUYER)) - others


def slots() -> None:
    stop_sessions()
    chan = lab.channels(BUYER)[0]
    listed = {k: chan[k]["max_accepted_htlcs"] for k in ("local_constraints", "remote_constraints")}
    measured("buyer_channel", dict(listed, commitment_type=chan.get("commitment_type"), dust_limit_sat={k: chan[k]["dust_limit_sat"] for k in ("local_constraints", "remote_constraints")}))
    # 1. as shipped, with the channel empty
    r = pay(f"{ORIGIN}/small.txt")
    opened = events("ticket_open", str(r.get("session")))
    h = gateway_health()
    check("slots: on a channel that carries 30 the wallet holds 2 tickets with the seller, and the gateway holds at most 15 for all buyers",
          call_paid(r) and session_of(r).get("pool") == 2 and bool(opened) and opened[0].get("slots") == 30 and min(int(v) for v in listed.values()) == 30 and h["maxHeld"] == 15,
          {"pool": session_of(r).get("pool"), "slots_read_by_the_wallet": opened[0].get("slots") if opened else None, "node_lists": listed, "gateway_max_held": h["maxHeld"]})
    stop_sessions()
    # 2. half of the buyer's channel is taken by payments that are no ticket of the wallet's
    others, _ = lab.lock(BUYER, SELLER, 15, secs=60)
    t0 = time.monotonic()
    r = pay(f"{ORIGIN}/small.txt")
    first = time.monotonic() - t0
    st = status()
    check("slots: with 15 payments of others pending on its channel, half of the 30, the wallet holds no ticket and buys a prepaid one: the page is paid and nothing of the wallet's stays pending",
          call_paid(r) and r.get("tickets_prepaid") == 1 and r.get("tickets_released") == 1 and st["locked"]["tickets"] == 0 and wallet_in_flight(15) == 0
          and session_of(r).get("pool") == 0 and session_of(r).get("hold_why") == "ticket_slots",
          {**brief(r), "session": {k: session_of(r).get(k) for k in ("pool", "hold_why", "prepaid_msat")}, "pending_on_the_channel": wallet_in_flight(0)})
    measured("slots_first_request_prepaid_s", round(first, 3))
    peak = [0]
    done = threading.Event()

    def watch() -> None:
        while not done.is_set():
            peak[0] = max(peak[0], wallet_in_flight(15))
            time.sleep(0.02)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    t0 = time.monotonic()
    r2 = pay(f"{ORIGIN}/big.bin", max_sats=5_000)
    took = time.monotonic() - t0
    done.set()
    watcher.join(5)
    n = int(r2.get("tickets_released") or 0)
    check("slots: a file is paid for with prepaid tickets bought one at a time as the balance runs out: never more than one payment of the wallet's is pending beside the 15, and never more than half the channel plus one",
          r2.get("verdict") == "allow" and str(r2.get("ended", "")).startswith("stopped by the wallet: max_sats") and n >= 4 and r2.get("tickets_prepaid") == n and peak[0] <= 1,
          {**brief(r2), "most_pending_of_the_wallets": peak[0], "seconds": round(took, 2)})
    if n:
        measured("slots_prepaid_stream_s_per_ticket", round(took / n, 3))
    if r2.get("saved_to"):
        os.remove(r2["saved_to"])
    lab.cancel_all(SELLER, others)
    stop_sessions()
    # 3. the seller holds as many tickets as it will: other buyers have asked for its 15 places and not paid. A gateway
    # as shipped issues hold invoices only to a session that has paid a ticket, so for this step it is started again
    # letting a buyer lock before it pays (the crowd is that), and as shipped after it
    restart_gateway({"held_after_paid": False})
    crowd = 0
    while gateway_health()["heldTickets"] < 15:
        body = json.dumps({"version": "ticket/0", "hashes": [secrets.token_bytes(32).hex() for _ in range(2)]}).encode()
        code, _, raw = send("POST", "/x402/ticket/lock", GW_PORT, {"Content-Type": "application/json"}, body)
        if code != 200:
            raise LabError(f"a lock of the lab's own: {code} {raw[:200]!r}")
        crowd += 1
    r = pay(f"{ORIGIN}/small.txt")
    held_by = events("ticket_hold", str(r.get("session")))
    check("slots: a seller at its cap of 15 held tickets says slots_short before it issues anything: the wallet waits the 30 s it names before it asks for a held ticket again, and pays this page with a prepaid one",
          call_paid(r) and r.get("tickets_prepaid") == 1 and session_of(r).get("hold_why") == "ticket_slots_short" and len(held_by) == 1 and in_flight() == 0,
          {**brief(r), "sessions_of_other_buyers": crowd, "session": {k: session_of(r).get(k) for k in ("pool", "hold_why")}})
    lab.wait("the other buyers' unpaid tickets to lapse", 120, lambda: gateway_health()["heldTickets"] == 0, every=1)
    stop_sessions()
    restart_gateway({})
    # 4. a channel on the way with one slot left: 29 of the seller's 30 are taken by payments from the hop itself
    blockers, _ = lab.lock(HOP, SELLER, 29, secs=120)
    # the wait the seller named in step 3 is kept across sessions: a held ticket is asked for again only after it
    time.sleep(31)
    r = pay(f"{ORIGIN}/small.txt")
    # the ticket that found no slot is in flight on the wallet's node for a moment before the hop's refusal is back
    try:
        lab.wait("the wallet to have seen the failed lock", 20, lambda: bool(events("ticket_slot_failure", str(r.get("session")))), every=0.5)
    except LabError:
        pass
    failures = events("ticket_slot_failure", str(r.get("session")))
    reasons = sorted({p.get("failure_reason", "") for p in buyer_payments().values() if p["status"] == "FAILED"} - {"FAILURE_REASON_INCORRECT_PAYMENT_DETAILS"})
    s1 = session_of(r)
    check("slots: with one slot left on the seller's channel one of the wallet's two tickets locks and the other fails on the wallet's node as a full channel does: the page is paid, and the session holds one ticket from now on and waits before it locks again",
          call_paid(r) and len(failures) == 1 and failures[0].get("slot_failed") == 1 and failures[0].get("pool") == 1 and s1.get("pool") == 1 and s1.get("hold_why") == "ticket_slots",
          {**brief(r), "failure": failures[:1], "the_node_said": reasons, "session": {k: s1.get(k) for k in ("pool", "hold_why", "slot_fails")}})
    measured("slots_full_channel_failure_reasons", reasons)
    # what the wallet does next is the node's to allow: a payment through a channel that just failed can be refused by
    # the node's own routing for a while. Either a prepaid ticket pays, or the call says why not; nothing is lost
    r2 = pay(f"{ORIGIN}/big.bin", max_sats=3_000)
    measured("slots_after_a_failed_lock", {"verdict": r2.get("verdict"), "rule": r2.get("rule"), "tickets_released": r2.get("tickets_released"), "tickets_prepaid": r2.get("tickets_prepaid"),
                                          "ended": str(r2.get("ended"))[:160], "reason": str(r2.get("reason"))[:200]})
    if r2.get("saved_to"):
        os.remove(r2["saved_to"])
    lab.cancel_all(SELLER, blockers)
    stop_sessions()
    quiet()
    m = money()
    check("slots: after all of it, what the buyer's node paid, what the seller's node received, what the wallet's book holds as settled and what the seller's receipts say are one number, and the ledger is each ticket and its fee",
          agrees(m), m)


# --- a pruned chain node without txindex ------------------------------------------------------------------

PRUNED = os.environ.get("TICKET_E2E_PRUNED") == "1"
LOTTERY_PORT = BASE + 8
LOTTERY = f"http://127.0.0.1:{LOTTERY_PORT}"
KEPT = f"{WALLET}/.run/ln_funding.json"


def lottery_gateway() -> None:
    """A third gateway beside the seller node that also offers the lottery (docs/TICKETS.md, section 9),
    as the gateway ships it but for the piece size and the per-address caps: a 2 MiB file at 16 sat a
    piece of 64 KiB, so a call on it wins about 8 times."""
    with open(f"{RUN}/www/hot.bin", "wb") as f:
        f.write(os.urandom(2 << 20))
    cfg = {"listen": f"127.0.0.1:{LOTTERY_PORT}", "public_url": LOTTERY, "upstream": f"http://127.0.0.1:{UP_PORT}", "state_dir": f"{RUN}/state-lottery",
           "chain": "regtest", "network": NETWORK[0],
           "node": {"rest": f"https://127.0.0.1:{lab.PORT[SELLER]}", "tls_cert": f"{RUN}/{SELLER}.tls.cert", "macaroon": f"{RUN}/invoices.macaroon",
                    "info_macaroon": f"{RUN}/info.macaroon"},
           "caps": {"sessions_per_address": 0, "unpaid_per_address": 0},
           "lottery": {"piece_bytes": 65_536, "sessions_per_address": 0, "idle_secs": 300},
           "times": {"height_max_age_secs": 30, "tick_ms": 500},
           "routes": [{"path": "/hot.bin", "price": {"byte_msat": 16_000, "per_bytes": 65_536}}]}
    with open(f"{RUN}/lottery.json", "w") as f:
        json.dump(cfg, f, indent=1)
    with open(f"{RUN}/lottery.log", "ab") as log:
        PROCS["lottery"] = subprocess.Popen([f"{BIN}/xbt-gateway", f"{RUN}/lottery.json"], stdout=log, stderr=log)
    lab.wait("the lottery gateway", 60, lambda: json.loads(send("GET", "/x402/ticket/health", LOTTERY_PORT)[2])["height"] is not None, every=0.1)


def restart_signer(drop_kept: bool = False) -> None:
    """Stop the signer and start it again on its files (without its kept funding verdicts, with `drop_kept`)."""
    PROCS["signer"].terminate()
    PROCS["signer"].wait(20)
    if drop_kept and os.path.exists(KEPT):
        os.remove(KEPT)
    WALLET_PROC.start()


def funding_report() -> dict[str, Any]:
    """The buyer channel's line in ln_status: whether its funding is proven, and why not."""
    st = signer("ln_status")
    ch = (st.get("channels") or [{}])[0]
    f = ch.get("funding") or {}
    return {"ready": st.get("ready"), "usable": ch.get("usable"), "proven": f.get("proven"), "refused": ch.get("refused"),
            "pinned_by": (f.get("evidence") or {}).get("xbt_only", {}).get("pinned_by"), "not_kept": ch.get("funding_not_kept")}


def pruned() -> None:
    """The wallet against a chain node that is pruned and has no txindex, as the node packages most
    owners run (TICKET_E2E_PRUNED=1: knots-b2b with prune=550, fastprune and txindex=0). The buyer's
    channel was opened and proven while its blocks were recent. The node then prunes every block the
    funding proof read, the signer restarts (its memory goes), and each way the wallet pays over
    Lightning is tried: ln_status, ln_pay of the seller's invoice, a ticket purchase and a lottery win.
    Last, with the kept verdict removed, what the wallet says when it cannot prove the channel. Each
    step's outcome is a check, so a wallet that fails one still reports the rest."""
    if not PRUNED:
        raise LabError("the pruned check needs the pruned chain node: TICKET_E2E_PRUNED=1 scripts/ticket_e2e_regtest.sh pruned")
    bci = json.loads(lab.chain("getblockchaininfo"))
    idx = json.loads(lab.chain("getindexinfo"))
    check("pruned: the wallet's chain node is pruned and keeps no transaction index", bci.get("pruned") is True and "txindex" not in idx,
          {"pruned": bci.get("pruned"), "indexes": sorted(idx)})
    chan = lab.channels(BUYER)[0]
    fund_h = int(chan["chan_id"]) >> 40
    fund_bh = lab.chain("getblockhash", str(fund_h))
    before = funding_report()
    check("pruned: before pruning, the buyer's channel is proven from its blocks, and the verdict is on disk", before["proven"] is True and os.path.exists(KEPT),
          {**before, "kept_file": os.path.exists(KEPT)})
    # the seller's node id for ln_pay, and the lottery's origin, in the policy; the lottery paid by draws
    pk = lab.pubkey(SELLER)
    pol = WALLET_PROC.policy()
    pol["allowlist"] += [LOTTERY, f"ln:{pk}"]
    pol["counterparties"][LOTTERY] = {"ln_node": pk}
    pol["tickets"]["lottery"] = {"min_expected_wins": 0}
    with open(f"{WALLET}/policy.json", "w") as f:
        json.dump(pol, f, indent=1)
    lottery_gateway()
    # prune: the node keeps at least 288 blocks behind its tip, and fastprune's block files are small
    stop_sessions()
    tip = lab.mine(600, NODES)
    pruned_to = int(lab.chain("pruneblockchain", str(tip - 300)))
    gone = subprocess.run(["docker", "compose", "exec", "-T", "knots-b2b", "bitcoin-cli", "-datadir=/data", "-rpcuser=lab", "-rpcpassword=lab", "getblock", fund_bh],
                          cwd=os.environ["LAB"], capture_output=True, text=True)
    check("pruned: the node pruned the funding's block and every block below it", pruned_to > fund_h and gone.returncode != 0,
          {"funding_height": fund_h, "pruned_to": pruned_to, "tip": tip, "getblock": (gone.stderr or gone.stdout).strip()[-120:]})
    restart_signer()
    after = funding_report()
    measured("pruned_ln_status", after)
    check("pruned: after a restart, ln_status: ready, the channel proven by the verdict kept on disk", after["ready"] is True and after["proven"] is True, after)
    inv = lab.lncli(SELLER, "addinvoice", "--amt=1000")["payment_request"]
    r = signer("ln_pay", {"invoice": inv, "max_sats": 1100})
    measured("pruned_ln_pay", {k: r.get(k) for k in ("verdict", "rule", "reason", "status", "charged_sats")})
    check("pruned: ln_pay of the seller's invoice: paid", r.get("verdict") == "allow" and r.get("status") == "SUCCEEDED",
          {k: r.get(k) for k in ("verdict", "rule", "reason", "status")})
    r = pay(f"{ORIGIN}/small.txt")
    measured("pruned_ticket", {k: r.get(k) for k in ("verdict", "rule", "reason", "rail", "status", "tickets_released")})
    check("pruned: a ticket purchase: the priced page is paid with a ticket", call_paid(r) and r.get("rail") == "ticket" and body_of(r) == PAGE, brief(r))
    stop_sessions()
    r = agent().tool("xbt402_pay", {"url": f"{LOTTERY}/hot.bin", "max_sats": 1000, "task": "film"})
    if r.get("saved_to") and os.path.exists(r["saved_to"]):
        os.remove(r["saved_to"])
    lot = {k: r.get(k) for k in ("verdict", "rule", "reason", "rail", "status", "complete", "wins", "wins_paid", "wins_unpaid", "ended")}
    measured("pruned_lottery", lot)
    check("pruned: a lottery win: the file is bought by draws and every win is paid", call_paid(r) and r.get("rail") == "lottery" and r.get("complete") is True
          and int(r.get("wins") or 0) >= 1 and r.get("wins") == r.get("wins_paid") and not r.get("wins_unpaid"), lot)
    stop_sessions()
    # without the kept verdict the proof cannot be made again on this node: the channel is refused, and the wallet says what it needs
    restart_signer(drop_kept=True)
    lost = funding_report()
    measured("pruned_no_kept_ln_status", lost)
    check("pruned: with no kept verdict, the channel is refused and the refusal names what the proof needs of the node",
          lost["ready"] is False and lost["proven"] is False and "txindex=1" in str(lost["refused"]) and "pruned" in str(lost["refused"]), lost)
    inv = lab.lncli(SELLER, "addinvoice", "--amt=1000")["payment_request"]
    r = signer("ln_pay", {"invoice": inv, "max_sats": 1100})
    measured("pruned_no_kept_ln_pay", {k: r.get(k) for k in ("verdict", "rule", "reason")})
    check("pruned: with no kept verdict, ln_pay is refused before anything is sent (ln_no_safe_channel)", r.get("rule") == "ln_no_safe_channel", {k: r.get(k) for k in ("verdict", "rule", "reason")})


OFFER_NODE = "lf4"
OFFERS_PORT = BASE + 10
OFFERS = f"http://127.0.0.1:{OFFERS_PORT}"
OFFERS_PAGE_MSAT = 100_000


def passed_over() -> list[dict[str, Any]]:
    """Each time the wallet left an offer for the seller's invoice, and why."""
    return [{k: e.get(k) for k in ("rule", "reason", "win")} for e in events("ticket_offer_passed")]


def offer_invoices(node: str) -> dict[str, dict[str, Any]]:
    """Every invoice the node issued for an offer of its own, by payment hash."""
    rows = lab.post(node, "/v2/offers/invoices", {}).get("invoices", [])
    return {base64.b64decode(i["payment_hash"]).hex(): i for i in rows}


def settled_on(node: str) -> dict[str, int]:
    """What the node was paid, by payment hash: its BOLT 11 invoices and its offers' invoices."""
    out: dict[str, int] = {}
    offset = 0
    while True:
        page = lab.get(node, f"/v1/invoices?index_offset={offset}&num_max_invoices=1000")
        for i in page.get("invoices", []):
            if i["state"] == "SETTLED":
                out[base64.b64decode(i["r_hash"]).hex()] = int(i["amt_paid_msat"])
        if len(page.get("invoices", [])) < 1000:
            break
        offset = int(page["last_index_offset"])
    for h, i in offer_invoices(node).items():
        if i.get("state") == "SETTLED":
            out[h] = int(i.get("amount_paid_msat") or 0)
    return out


def offers_gateway() -> dict[str, Any]:
    """A gateway beside lf4 that sells prepaid tickets only, and the lottery, and names a BOLT 12 offer
    of lf4's in both terms (docs/TICKETS.md, section 15). Its 402 for the page."""
    cfg = {"listen": f"127.0.0.1:{OFFERS_PORT}", "public_url": OFFERS, "upstream": f"http://127.0.0.1:{UP_PORT}", "state_dir": f"{RUN}/state-offers",
           "chain": "regtest", "network": NETWORK[0],
           "node": {"rest": f"https://127.0.0.1:{lab.PORT[OFFER_NODE]}", "tls_cert": f"{RUN}/{OFFER_NODE}.tls.cert", "macaroon": f"{RUN}/offers-invoices.macaroon",
                    "info_macaroon": f"{RUN}/offers-info.macaroon"},
           "caps": {"sessions_per_address": 0, "unpaid_per_address": 0},
           "tickets": {"settle": ["on-arrival"]},
           "offers": {"enabled": True, "description": "ticket e2e shop"},
           "lottery": {"piece_bytes": 65_536, "sessions_per_address": 0, "idle_secs": 300},
           "times": {"height_max_age_secs": 30, "tick_ms": 500},
           # the page costs more than a win, so it is sold by prepaid ticket and never by draws
           "routes": [{"path": "/small.txt", "price": {"request_msat": OFFERS_PAGE_MSAT}},
                      {"path": "/hot.bin", "price": {"byte_msat": 16_000, "per_bytes": 65_536}}]}
    with open(f"{RUN}/offers.json", "w") as f:
        json.dump(cfg, f, indent=1)
    with open(f"{RUN}/offers.log", "ab") as log:
        PROCS["offers"] = subprocess.Popen([f"{BIN}/xbt-gateway", f"{RUN}/offers.json"], stdout=log, stderr=log)
    lab.wait("the offers gateway", 90, lambda: json.loads(send("GET", "/x402/ticket/health", OFFERS_PORT)[2])["height"] is not None, every=0.1)
    return json.loads(send("GET", "/small.txt", OFFERS_PORT)[2])


def offers_policy(on: bool) -> None:
    """The wallet's policy with the offers gateway allowed and tied to lf4, and the signer restarted on it."""
    pol = WALLET_PROC.policy()
    pol["allowlist"].append(OFFERS)
    pol["counterparties"][OFFERS] = {"ln_node": lab.pubkey(OFFER_NODE)}
    pol["tickets"]["lottery"] = {"min_expected_wins": 0}
    if not on:
        pol["tickets"]["offers"] = False
    with open(f"{WALLET}/policy.json", "w") as f:
        json.dump(pol, f, indent=1)
    restart_signer()


def offers() -> None:
    """BOLT 12 offers for prepaid tickets and lottery wins, on real nodes (docs/TICKETS.md, section 15).
    The seller is lf4: it announces no address and its one channel, from the hop, is private, so it is
    reached only by a route hint or a blinded path. The gateway beside it sells prepaid tickets and the
    lottery and names one offer of lf4's. The wallet pays a page three times and buys a file by draws:
    every payment lf4 takes must be an invoice of that offer, fetched over onion messages and paid
    through the offer's blinded paths. Then the wallet with `tickets.offers` false: the same page is
    paid with the gateway's BOLT 11 invoice, from /lock, as by a wallet that knows nothing of offers."""
    stop_sessions()
    lab.dc("up", "-d", OFFER_NODE)

    def ready() -> bool:
        lab.load_credentials(OFFER_NODE)
        return lab.synced(OFFER_NODE)

    lab.wait(f"{OFFER_NODE} answering and synced", 180, ready)
    pk = lab.pubkey(OFFER_NODE)
    # unchecked: "already connected" is as good as connected, and the wait below fails if neither holds
    lab.dc("exec", "-T", HOP, "lncli", "--network=regtest", "--rpcserver=127.0.0.1:10009", "connect", f"{pk}@{OFFER_NODE}:9735", check=False)
    lab.wait(f"{HOP} connected to {OFFER_NODE}", 30, lambda: any(p["pub_key"] == pk for p in lab.get(HOP, "/v1/peers")["peers"]))
    for attempt in range(6):
        try:
            lab.lncli(HOP, "openchannel", f"--node_key={pk}", "--local_amt=2000000", "--private")
            break
        except LabError:
            if attempt == 5:
                raise
            time.sleep(5)
    tick(8)
    lab.wait(f"{OFFER_NODE}'s channel active", 240, partial(active, OFFER_NODE, 1))
    info = lab.info(OFFER_NODE)
    chans = lab.channels(OFFER_NODE)
    check("offers: lf4 announces no address and its one channel is private",
          not info.get("uris") and len(chans) == 1 and chans[0].get("private") is True, {"uris": info.get("uris"), "private": [c.get("private") for c in chans]})
    for name, perms in (("offers-invoices", lab.SELLER_PERMISSIONS), ("offers-info", ("info:read",))):
        with open(f"{RUN}/{name}.macaroon", "wb") as f:
            f.write(bytes.fromhex(lab.bake(OFFER_NODE, perms)))
        os.chmod(f"{RUN}/{name}.macaroon", 0o600)
    with open(f"{RUN}/www/hot.bin", "wb") as f:
        f.write(os.urandom(2 << 20))
    terms = offers_gateway()
    by = {f"{a.get('scheme')}/{(a.get('extra') or {}).get('settle')}": (a.get("extra") or {}).get("offer") for a in terms.get("accepts", [])}
    named = {v for v in by.values() if v}
    lno = next(iter(named), "")
    dec = lab.post(OFFER_NODE, "/v2/offers/decode", {"bolt12": lno}) if lno else {}
    paths = int((dec.get("offer") or {}).get("num_paths") or 0)
    measured("offers_terms", {"entries": {k: bool(v) for k, v in by.items()}, "num_paths": paths})
    check("offers: the gateway's 402 names one BOLT 12 offer, on its prepaid entry, and the offer carries blinded paths (lf4's own decode)",
          len(named) == 1 and by.get("ticket/on-arrival") == lno and paths >= 1, {"entries": {k: bool(v) for k, v in by.items()}, "num_paths": paths})
    # lf4 issues invoices for its offer only once its blinded paths can be used: until then it refuses
    # invoice requests ("cannot issue an invoice right now"), and a ticket bought in that window falls
    # back to a BOLT 11 invoice whose route hint may not route yet either. So wait until the buyer's
    # node is given an invoice for the offer (not paid), then a few seconds more, so the probes do not
    # take the issuer's rate limit from the pages below
    if lno:
        lab.wait(f"{OFFER_NODE} issuing invoices for its offer", 180,
                 lambda: lab.post(BUYER, "/v2/offers/fetchinvoice", {"offer": lno, "amount_msat": "1000000", "timeout_seconds": 10}).get("invoice"),
                 every=3)
        time.sleep(5)
    offers_policy(on=True)
    before = settled_on(OFFER_NODE)
    pages = [pay(f"{OFFERS}/small.txt") for _ in range(3)]
    check("offers: three priced pages from the unannounced seller, each paid with a prepaid ticket",
          all(call_paid(r) and r.get("rail") == "ticket" and body_of(r) == PAGE for r in pages), [brief(r) for r in pages])
    stop_sessions()
    r = agent().tool("xbt402_pay", {"url": f"{OFFERS}/hot.bin", "max_sats": 1000, "task": "film"})
    if r.get("saved_to") and os.path.exists(r["saved_to"]):
        os.remove(r["saved_to"])
    lot = {k: r.get(k) for k in ("verdict", "rule", "reason", "rail", "status", "complete", "wins", "wins_paid", "wins_unpaid", "ended")}
    measured("offers_lottery", lot)
    check("offers: a file bought by draws from the unannounced seller, every win paid", call_paid(r) and r.get("rail") == "lottery" and r.get("complete") is True
          and int(r.get("wins") or 0) >= 1 and r.get("wins") == r.get("wins_paid") and not r.get("wins_unpaid"), lot)
    stop_sessions()
    after = settled_on(OFFER_NODE)
    new = {h: m for h, m in after.items() if h not in before}
    by_offer = set(offer_invoices(OFFER_NODE))
    paid = {h: p for h, p in buyer_payments().items() if p["status"] == "SUCCEEDED"}
    ledger = {row["txid"] for row in WALLET_PROC.ledger()}
    over = passed_over()
    seen = {"paid_to_lf4": len(new), "by_offer": sum(1 for h in new if h in by_offer), "received_msat": sum(new.values()),
            "buyer_node_paid_msat": sum(int(paid[h]["value_msat"]) for h in new if h in paid),
            "buyer_node_fees_msat": sum(int(paid[h]["fee_msat"]) for h in new if h in paid),
            "on_buyer_node": sum(1 for h in new if h in paid), "not_in_ledger": sum(1 for h in new if f"ticket:{h}" not in ledger),
            "passed_over": len(over), "passed_over_why": over[:5]}
    if over:
        # what the buyer's node said when it gave no invoice for the offer
        logs = subprocess.run(["docker", "compose", "logs", "--no-color", BUYER], cwd=os.environ["LAB"], capture_output=True, text=True).stdout
        seen["buyer_node_log"] = [ln[-300:] for ln in logs.splitlines() if any(w in ln.lower() for w in ("invoice request", "fetchinvoice", "fetch invoice", "onion message", "offer"))][-8:]
    measured("offers_paid", seen)
    # lf4 takes what the blinded path's padded fees leave over, so it is paid at least what the buyer's node sent it and
    # no more than that and the fees together; a ticket or win the offer gave no invoice for is paid by the seller's invoice
    # (docs/TICKETS.md, section 15), and only a failure to fetch one is let through here, never a failed check
    check("offers: the payments lf4 took are invoices of its offer but for those the offer gave no invoice for, each one payment of the buyer's node and in the wallet's ledger",
          seen["paid_to_lf4"] >= 4 and seen["on_buyer_node"] == seen["paid_to_lf4"] and seen["not_in_ledger"] == 0
          and seen["by_offer"] + seen["passed_over"] == seen["paid_to_lf4"] and seen["by_offer"] * 2 >= seen["paid_to_lf4"]
          and all(o["rule"] == "ln_fetch_invoice" for o in over)
          and seen["buyer_node_paid_msat"] <= seen["received_msat"] <= seen["buyer_node_paid_msat"] + seen["buyer_node_fees_msat"], seen)
    offers_policy(on=False)
    before = after
    r = pay(f"{OFFERS}/small.txt")
    stop_sessions()
    new = {h: m for h, m in settled_on(OFFER_NODE).items() if h not in before}
    by_offer = set(offer_invoices(OFFER_NODE))
    seen = {"paid_to_lf4": len(new), "by_offer": sum(1 for h in new if h in by_offer)}
    check("offers: a wallet with tickets.offers false is served the same page with the gateway's BOLT 11 invoice, from /lock",
          call_paid(r) and body_of(r) == PAGE and seen["paid_to_lf4"] >= 1 and seen["by_offer"] == 0, {**seen, "reply": brief(r)})
    offers_policy(on=True)


CHECKS = {"page": page, "latency": latency, "stream": stream, "slots": slots, "liar": liar, "kill": kill, "offers": offers, "pruned": pruned}


def main() -> int:
    # with the pruned node, the pruned check; else every check that runs on the lab's own node
    names = sys.argv[1:] or (["pruned"] if PRUNED else [n for n in CHECKS if n != "pruned"])
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
