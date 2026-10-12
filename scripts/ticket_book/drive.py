#!/usr/bin/env python3
"""The ticket book on a Lightning Fork regtest: the wallet's signer buys with stream tickets.

Run by scripts/ticket_book_regtest.sh, which brings up the chain node and builds the binaries.

    lf1 ---- lf2 ---- s01 ... sNN
   buyer     hop      sellers

Three parties, two of them played here:

  the signer   the real binary (crates/xbt-signer), with the Lightning rail's four-permission macaroon
               for lf1 and its own connection to the chain node. It derives the secrets, checks and
               pays the invoices, books every release, and is the only one that knows a secret before
               it is spent.
  the agent    `Buyer` below: what the wallet's model-facing side does. It calls the signer's socket
               (ticket_open, ticket_offer, ticket_lock, ticket_release, ticket_stop, ticket_status)
               and speaks docs/TICKETS.md over HTTP to the seller.
  the seller   `Seller` below: an HTTP stand-in in front of a seller's node (hold invoices, settle on
               use, cancel), which can also lie in its lock answers.

Channels: lf1->lf2 of 5,000,000 sat from a coin that exists on XBT alone (the rail's funding proof),
lf2->sNN of 2,000,000 sat each. A ticket is 1,000 sat for 40 blocks. Checks, each PASS or FAIL:

  one      402, open, lock 8 through the hop, five paid requests, stop: 5 settled and 3 cancelled on
           both nodes, the book and the buyer's node agree, the ledger holds the tickets and the fees
  liar     lock answers that lie (another payee, amount, life, expiry, a hash that is not ours,
           replayed invoices, garbage) and terms above the owner's bounds: no payment leaves lf1
  kill     the signer is killed with tickets locked and started again
  node     the buyer's node restarts with tickets locked
  silent   a seller that neither settles nor cancels: its tickets come back at their expiry
  restore  the wallet's files are put back from an older copy
  many     NN sellers the owner has not named, 2 tickets each, one paid request each, stop
  surface  the wallet's macaroon; the MCP's ticket tools

Usage: drive.py [check ...]   (all, in this order, when none is named)
Environment: LAB, RUN, OUT, BIN, TICKET_BOOK_PORT_BASE, TICKET_BOOK_SELLERS (see the shell script).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ln_ticket"))
import lab  # noqa: E402  (the node and chain calls of the ticket lab)
from lab import LabError  # noqa: E402

RUN, OUT, BIN = (os.environ[k] for k in ("RUN", "OUT", "BIN"))
BASE = int(os.environ.get("TICKET_BOOK_PORT_BASE", "17911"))
N = int(os.environ.get("TICKET_BOOK_SELLERS", "20"))
SELLERS = [f"s{i:02d}" for i in range(1, N + 1)]
BUYER, HOP = "lf1", "lf2"
ALL = (BUYER, HOP, *SELLERS)
SPLIT = 125  # the regtest stand-in for the height the chains split at
TICKET_MSAT, CLTV = 1_000_000, 40
TAG_RECORD = "1953063787"
SHOP = BASE + 40  # the stand-in sellers' HTTP port
SOCK = f"{RUN}/signer.sock"
WALLET = f"{RUN}/wallet"
REPORT: dict[str, Any] = {"checks": [], "measured": {}}
FAILED: list[str] = []
POOL = ThreadPoolExecutor(32)
RETRIES: list[str] = []  # paid requests sent again because the seller's node did not yet show the ticket ACCEPTED

for i, name in enumerate(SELLERS, start=1):
    lab.PORT[name] = BASE + 10 + i


def check(name: str, ok: bool, saw: Any) -> None:
    REPORT["checks"].append({"check": name, "ok": bool(ok), "saw": saw})
    print(("PASS " if ok else "FAIL ") + name + "  " + json.dumps(saw)[: 240 if ok else 1500], flush=True)
    if not ok:
        FAILED.append(name)


def tick(blocks: int = 1) -> int:
    h = lab.mine(blocks, ALL)
    time.sleep(1.0)
    return h


# --- the signer ---------------------------------------------------------------------------------------


def signer(method: str, params: dict[str, Any] | None = None, timeout: float = 180) -> dict[str, Any]:
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

    def __init__(self) -> None:
        self.proc: subprocess.Popen[bytes] | None = None

    def policy(self) -> dict[str, Any]:
        # s01 is the one seller the owner names; "stream" pays named sellers, "swarm" anyone inside its caps
        return {
            "allowlist": [f"ln:{lab.pubkey(SELLERS[0])}"],
            "max_per_tx_sats": 50_000,
            "daily_budget_sats": 400_000,
            "weekly_budget_sats": 800_000,
            "per_counterparty_cap_sats": 200_000,
            "velocity_max": 100_000,
            "velocity_window_s": 3600,
            "human_threshold_sats": 40_000,
            "split_window_s": 0,
            "regtest_mine": False,
            "anchor_interval_s": 3600,
            "ln": {"enabled": True, "split_height": SPLIT},
            "tickets": {
                "enabled": True,
                "max_new_sellers_per_min": 200,
                "max_locked_tickets": 64,
                "max_locked_sats": 64_000,
                "tasks": {"stream": {"budget_sats": 100_000}, "swarm": {"budget_sats": 100_000, "admit": "any", "max_sellers": 40}},
            },
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
            B2_LN_REST=f"https://127.0.0.1:{lab.PORT[BUYER]}",
            B2_LN_MACAROON=f"{RUN}/rail.macaroon",
            B2_LN_TLS_CERT=f"{RUN}/{BUYER}.tls.cert",
        )
        if os.path.exists(SOCK):
            os.remove(SOCK)
        with open(f"{RUN}/signer.log", "ab") as log:
            self.proc = subprocess.Popen([f"{BIN}/xbt-signer", "--root", WALLET], env=env, stdout=log, stderr=subprocess.STDOUT)
        lab.wait("the signer's socket", 60, lambda: os.path.exists(SOCK) and signer("health")["ok"])

    def kill(self) -> None:
        """As a power cut: no signal the process could act on."""
        assert self.proc is not None
        self.proc.kill()
        self.proc.wait(10)

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

    def spent(self) -> int:
        return sum(int(r["amount_sats"]) for r in self.ledger())


WALLET_PROC = Wallet()


def status(session: str = "") -> dict[str, Any]:
    return signer("ticket_status", {"session": session} if session else {})


def agree(want_htlcs: int | None = None, secs: float = 30) -> dict[str, Any]:
    """Wait until the signer's book and the buyer's node show the same payments in flight."""
    last: dict[str, Any] = {}

    def ok() -> bool:
        nonlocal last
        last = status()
        node = last.get("node") or {}
        return bool(node.get("agree")) and (want_htlcs is None or node.get("htlcs") == want_htlcs)

    try:
        lab.wait("the book and the node to agree", secs, ok, every=0.3)
    except LabError:
        pass
    return last


def buyer_in_flight() -> set[str]:
    """The payment hashes of the HTLCs lf1 has out, from lf1 itself (its admin macaroon, not the wallet's)."""
    return {base64.b64decode(h["hash_lock"]).hex() for c in lab.channels(BUYER) for h in c["pending_htlcs"] if not h["incoming"]}


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


def cost_sats(p: dict[str, Any]) -> int:
    """What a settled payment cost, as the wallet books it: the amount and the fee, rounded up to a sat."""
    return -(-(int(p["value_msat"]) + int(p["fee_msat"])) // 1000)


# --- the seller (a stand-in) ----------------------------------------------------------------------------


def request_digest(method: str, host: str, port: int, target: str, body: bytes) -> str:
    """The channel wire's request digest v2: a tagged hash over the length-prefixed fields."""
    tag = hashlib.sha256(b"xbt402/req/v2").digest()
    h = hashlib.sha256(tag + tag)
    for field in (method.encode(), b"http", host.encode(), str(port).encode(), target.encode(), body):
        h.update(len(field).to_bytes(8, "little") + field)
    return h.hexdigest()


def auth_of(key: bytes, session: str, seq: int, secret: str, digest: str) -> str:
    msg = "|".join(["ticket/auth", session, str(seq), secret, "", digest])
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


class Seller:
    """One seller: a node and, in front of it, the session endpoints of docs/TICKETS.md. `lie` makes
    its lock answers dishonest in one way; `terms_lie` changes its 402."""

    def __init__(self, node: str) -> None:
        self.node = node
        self.pubkey = lab.pubkey(node)
        self.lie = ""
        self.terms_lie: dict[str, Any] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.served = 0
        self.lock = threading.Lock()

    def accepts(self) -> dict[str, Any]:
        net = "lightning:" + lab.chain("getblockhash", "101")[:32]
        extra = {
            "version": "ticket/0",
            "features": [512],
            "ticketMsat": str(TICKET_MSAT),
            "maxTickets": 8,
            "ticketBlocks": CLTV,
            "release": "with-request",
            "settle": "on-use",
            "receiptKey": self.pubkey,
            "session": f"/{self.node}/x402/ticket",
        }
        extra.update(self.terms_lie)
        return {"scheme": "ticket", "network": net, "asset": "XBT:msat", "amount": str(TICKET_MSAT), "payTo": self.pubkey, "extra": extra}

    def hold_invoice(self, hash_hex: str, msat: int = TICKET_MSAT, cltv: int = CLTV, life_s: int = 60, node: str | None = None) -> str:
        body = {"hash": lab.b64(bytes.fromhex(hash_hex)), "value_msat": str(msat), "cltv_expiry": str(cltv), "expiry": str(life_s)}
        return lab.post(node or self.node, "/v2/invoices/hodl", body)["payment_request"]

    def lock_answer(self, req: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            sid = req.get("session") or secrets.token_hex(8)
            first = sid not in self.sessions
            s = self.sessions.setdefault(sid, {"key": secrets.token_bytes(32), "tickets": {}, "balance": 0, "seq": 0, "spent": 0, "released": 0})
        msat = int(req.get("ticketMsat", TICKET_MSAT))
        tickets = []
        for h in req["hashes"]:
            if self.lie == "other_payee":  # an invoice of another node for the buyer's hash
                inv = self.hold_invoice(h, node=SELLERS[1])
            elif self.lie == "amount":
                inv = self.hold_invoice(h, msat=msat + 1)
            elif self.lie == "life":
                inv = self.hold_invoice(h, cltv=CLTV + 1)
            elif self.lie == "expiry":
                inv = self.hold_invoice(h, life_s=86_400)
            elif self.lie == "own_hash":  # a hash whose preimage the seller knows: an ordinary invoice
                mine = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
                inv = self.hold_invoice(mine)
            elif self.lie == "garbage":
                inv = "lnbcrt1" + "q" * 60
            elif self.lie.startswith("replay:"):  # invoices the buyer has already paid
                inv = self.lie.split(":", 1)[1]
            else:
                inv = self.hold_invoice(h, msat=msat)
                s["tickets"][h] = "open"
            tickets.append({"hash": h, "invoice": inv})
        out: dict[str, Any] = {"session": sid, "tickets": tickets}
        if first:
            out["key"] = s["key"].hex()
        return out

    def paid(self, method: str, target: str, body: bytes, header: str) -> tuple[int, dict[str, Any]]:
        """A paid request, in the order of docs/TICKETS.md section 3: auth and seq, the ticket by
        its secret, settle, then serve."""
        payload = json.loads(base64.b64decode(header))["payload"]
        s = self.sessions.get(payload["session"])
        if s is None:
            return 402, {"error": "session_unknown"}
        secret = payload.get("secret", "")
        digest = request_digest(method, "127.0.0.1", SHOP, target, body)
        with self.lock:
            if not hmac.compare_digest(payload["auth"], auth_of(s["key"], payload["session"], payload["seq"], secret, digest)) or payload["seq"] != s["seq"] + 1:
                return 402, {"error": "bad_auth_or_seq"}
            s["seq"] += 1
            if secret:
                h = hashlib.sha256(bytes.fromhex(secret)).hexdigest()
                if s["tickets"].get(h) != "open":
                    return 402, {"error": "ticket_used" if h in s["tickets"] else "ticket_unknown"}
                if lab.get(self.node, "/v2/invoices/lookup?payment_hash=" + lab.url64(bytes.fromhex(h)))["state"] != "ACCEPTED":
                    return 402, {"error": "ticket_not_locked"}
                s["tickets"][h] = "used"
                lab.post(self.node, "/v2/invoices/settle", {"preimage": lab.b64(bytes.fromhex(secret))})
                s["balance"] += TICKET_MSAT
                s["released"] += TICKET_MSAT
            if s["balance"] < TICKET_MSAT:
                return 402, {"error": "balance_short"}
            s["balance"] -= TICKET_MSAT
            s["spent"] += TICKET_MSAT
            self.served += 1
        # unsigned here: checking the seller's receipt belongs to the 402 binding, which is not built
        receipt = {"scheme": "ticket", "session": payload["session"], "seq": s["seq"], "releasedMsat": str(s["released"]), "spentMsat": str(s["spent"])}
        return 200, {"data": "one piece", "receipt": receipt}

    def cancel(self, req: dict[str, Any]) -> dict[str, Any]:
        s = self.sessions[req["session"]]
        hashes = [h for h, st in s["tickets"].items() if st == "open"] if req["hashes"] == "all" else req["hashes"]
        done = []
        for h in hashes:
            if s["tickets"].get(h) == "open":
                lab.post(self.node, "/v2/invoices/cancel", {"payment_hash": lab.b64(bytes.fromhex(h))})
                s["tickets"][h] = "cancelled"
                done.append(h)
        return {"cancelled": done}

    def states(self, hashes: list[str]) -> dict[str, int]:
        return lab.tally_states(lab.get(self.node, "/v2/invoices/lookup?payment_hash=" + lab.url64(bytes.fromhex(h)))["state"] for h in hashes)


SHOPS: dict[str, Seller] = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_: Any) -> None:
        pass

    def answer(self, code: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def route(self, method: str) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        shop = SHOPS.get(self.path.split("/")[1])
        try:
            if shop is None:
                self.answer(404, {"error": "no such seller"})
            elif self.path.endswith("/x402/ticket/lock"):
                self.answer(200, shop.lock_answer(json.loads(body)))
            elif self.path.endswith("/x402/ticket/cancel"):
                self.answer(200, shop.cancel(json.loads(body)))
            elif self.headers.get("PAYMENT-SIGNATURE"):
                self.answer(*shop.paid(method, self.path, body, self.headers["PAYMENT-SIGNATURE"]))
            else:
                self.answer(402, {"x402Version": 2, "accepts": [shop.accepts()]})
        except (LabError, KeyError, ValueError) as e:
            self.answer(500, {"error": f"{type(e).__name__}: {e}"})

    def do_GET(self) -> None:
        self.route("GET")

    def do_POST(self) -> None:
        self.route("POST")


def shop_http(method: str, target: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPConnection("127.0.0.1", SHOP, timeout=120)
    try:
        conn.request(method, target, body=None if body is None else json.dumps(body), headers=headers or {})
        r = conn.getresponse()
        return r.status, json.loads(r.read() or b"{}")
    finally:
        conn.close()


# --- the agent ----------------------------------------------------------------------------------------


class Buyer:
    """One session of the wallet's model-facing side with one seller."""

    def __init__(self, shop: Seller, task: str) -> None:
        self.shop, self.task = shop, task
        self.session = ""  # the signer's
        self.remote = ""  # the seller's
        self.key = b""
        self.seq = 0
        self.hashes: list[str] = []

    def terms(self) -> dict[str, Any]:
        code, body = shop_http("GET", f"/{self.shop.node}/data")
        if code != 402:
            raise LabError(f"an unpaid request answered {code}")
        return body["accepts"][0]

    def open(self, **more: Any) -> dict[str, Any]:
        out = signer("ticket_open", {"terms": self.terms(), "task": self.task, **more})
        self.session = out.get("session", "")
        return out

    def lock(self) -> dict[str, Any]:
        """One lock round: the hashes the pool wants, the seller's invoices for them, the signer's verdict."""
        offer = signer("ticket_offer", {"session": self.session})
        hashes = offer.get("hashes", [])
        if not hashes:
            return {"locked": 0, "tickets": [], "refused": [], "offer": offer}
        req: dict[str, Any] = {"version": "ticket/0", "hashes": hashes, "ticketMsat": offer["ticket_msat"]}
        if self.remote:
            req["session"] = self.remote
        code, ans = shop_http("POST", f"/{self.shop.node}/x402/ticket/lock", req)
        if code != 200:
            raise LabError(f"lock answered {code}: {ans}")
        self.remote = ans["session"]
        if "key" in ans:
            self.key = bytes.fromhex(ans["key"])
        out = signer("ticket_lock", {"session": self.session, "tickets": ans["tickets"]})
        self.hashes += [t["hash"] for t in out.get("tickets", []) if t["state"] == "locked"]
        return out

    def request(self, secret: str = "") -> tuple[int, dict[str, Any]]:
        self.seq += 1
        target = f"/{self.shop.node}/data"
        auth = auth_of(self.key, self.remote, self.seq, secret, request_digest("GET", "127.0.0.1", SHOP, target, b""))
        payload: dict[str, Any] = {"session": self.remote, "seq": self.seq, "auth": auth}
        if secret:
            payload["secret"] = secret
        header = base64.b64encode(json.dumps({"x402Version": 2, "accepted": {"scheme": "ticket"}, "payload": payload}).encode()).decode()
        return shop_http("GET", target, headers={"PAYMENT-SIGNATURE": header})

    def pay(self) -> tuple[dict[str, Any], int]:
        """One paid request: a secret from the signer (booked there before it comes back), then the
        request. The buyer's node shows a ticket in flight a moment before the seller's shows it
        ACCEPTED; a seller that is asked in that moment answers `ticket_not_locked` and has not
        used the ticket, and the same secret, which is spent either way, is sent again."""
        rel = signer("ticket_release", {"session": self.session})
        if rel.get("verdict") != "allow":
            return rel, 0
        for _ in range(50):
            code, body = self.request(rel["ticket_secret"])
            if code != 402 or body.get("error") != "ticket_not_locked":
                break
            RETRIES.append(self.shop.node)
            time.sleep(0.1)
        return rel, code

    def stop(self) -> dict[str, Any]:
        """Stop: the signer names the unreleased tickets, the seller is asked to cancel them."""
        out = signer("ticket_stop", {"session": self.session})
        if out.get("cancel") and self.remote:
            self.seq += 1
            shop_http("POST", f"/{self.shop.node}/x402/ticket/cancel", {"session": self.remote, "seq": self.seq, "hashes": out["cancel"]})
        return out

    def tickets(self) -> dict[str, int]:
        """The book's states of the tickets this session locked. (A lock round before the node knew a
        route leaves tickets whose payment failed at once; they were never locked and are not counted.)"""
        return lab.tally_states(t["state"] for t in status(self.session).get("session_tickets", []) if t["hash"] in self.hashes)


# --- setup --------------------------------------------------------------------------------------------


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
    lab.dc("up", "-d", *ALL)

    def ready(node: str) -> bool:
        lab.load_credentials(node)
        return lab.synced(node)

    for node in ALL:
        lab.wait(f"{node} answering and synced", 180, partial(ready, node))
    send_pinned(lab.lncli(BUYER, "newaddress", "p2wkh")["address"], "0.2")
    # one coin for each channel the hop opens, so that no open waits for another's change
    outs = {lab.lncli(HOP, "newaddress", "p2wkh")["address"]: 0.03 for _ in SELLERS}
    lab.wallet("sendmany", "", json.dumps(outs))
    lab.mine(6, ALL)
    lab.wait("the buyer's coin", 60, partial(lab.wallet_sat, BUYER))
    lab.wait("the hop's coins", 60, lambda: len(lab.lncli(HOP, "listunspent", "--min_confs=1")["utxos"]) >= len(SELLERS))
    open_channel(BUYER, HOP, 5_000_000)
    for s in SELLERS:
        open_channel(HOP, s, 2_000_000)
    lab.mine(8, ALL)
    lab.wait("the buyer's channel active", 180, partial(active, BUYER, 1))
    lab.wait("the hop's channels active", 240, partial(active, HOP, len(SELLERS) + 1))
    lab.wait("the buyer knows every channel", 300, lambda: lab.known_channels(BUYER) >= len(SELLERS) + 1, every=2)
    # the wallet's credentials for lf1: the rail's macaroon and the node's certificate
    os.makedirs(f"{RUN}/keys", exist_ok=True)
    with open(f"{RUN}/rpc.cookie", "w") as f:
        f.write("lab:lab")
    with open(f"{RUN}/rail.macaroon", "wb") as f:
        f.write(bytes.fromhex(lab.bake(BUYER, lab.BUYER_PERMISSIONS)))
    os.chmod(f"{RUN}/rail.macaroon", 0o600)
    for s in SELLERS:
        SHOPS[s] = Seller(s)
    server = ThreadingHTTPServer(("127.0.0.1", SHOP), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    WALLET_PROC.write_policy()
    WALLET_PROC.start()
    st = signer("ln_status")
    check("setup: the Lightning rail is ready on lf1: chain verified, its one channel's funding proven", st.get("ready") is True, {"ready": st.get("ready"), "warnings": st.get("warnings")})


def fresh(shop: Seller, task: str = "stream", **more: Any) -> Buyer:
    """A session with its pool locked: 8 tickets with a seller the owner named, 2 with one it has
    not (a route to a new seller can take a few tries to be found)."""
    b = Buyer(shop, task)
    out = b.open(**more)
    if out.get("verdict") != "allow":
        raise LabError(f"open: {out}")
    count = out["pool"]
    end = time.time() + 120
    while len(b.hashes) < count:
        b.lock()
        if time.time() > end:
            raise LabError(f"only {len(b.hashes)} of {count} tickets locked with {shop.node}")
        if len(b.hashes) < count:
            time.sleep(2)
    return b


def end_session(b: Buyer) -> None:
    b.stop()
    lab.wait("the session to close", 60, lambda: status(b.session)["sessions"][0]["state"] == "closed", every=0.5)


# --- the checks -----------------------------------------------------------------------------------------


def one() -> None:
    shop = SHOPS[SELLERS[0]]
    b = Buyer(shop, "stream")
    opened = b.open()
    check("one: the seller's 402 opens a session of 8 tickets of 1,000 sat with a seller the owner named",
          opened.get("verdict") == "allow" and opened.get("pool") == 8 and opened.get("ticket_msat") == str(TICKET_MSAT) and opened.get("listed") is True, opened)
    spent0 = WALLET_PROC.spent()
    lab.wait("a route to the seller", 240, lambda: b.lock()["locked"] > 0 or len(b.hashes) > 0, every=3)
    t0 = time.perf_counter()
    while len(b.hashes) < 8:
        b.lock()
    hashes = list(b.hashes)
    st = agree(8)
    check("one: 8 tickets locked through the hop: ACCEPTED on the seller's node, in flight on the buyer's, nothing spent",
          shop.states(hashes) == {"ACCEPTED": 8} and buyer_in_flight() == set(hashes) and st["locked"] == {"tickets": 8, "sats": 8000} and WALLET_PROC.spent() == spent0,
          {"seller": shop.states(hashes), "buyer_htlcs": len(buyer_in_flight()), "book": st["locked"], "agree": st["node"], "ledger": WALLET_PROC.spent() - spent0})
    inv = lab.get(shop.node, "/v2/invoices/lookup?payment_hash=" + lab.url64(bytes.fromhex(hashes[0])))
    check("one: the payment carries the wallet's tag to the seller's node and nothing else of the wallet's",
          TAG_RECORD in inv["htlcs"][0]["custom_records"] and len(base64.b64decode(inv["htlcs"][0]["custom_records"][TAG_RECORD])) == 32,
          {"custom_records": list(inv["htlcs"][0]["custom_records"])})
    codes, booked = [], []
    for _ in range(5):
        rel, code = b.pay()
        codes.append(code)
        booked.append(rel.get("charged_sats"))
    check("one: five paid requests, each with a secret the signer booked before returning it, each served",
          codes == [200] * 5 and shop.served == 5 and all(c and c >= 1000 for c in booked), {"http": codes, "booked_at_release": booked})
    cancel = b.stop().get("cancel", [])
    lab.wait("the session to close", 60, lambda: status(b.session)["sessions"][0]["state"] == "closed", every=0.5)
    st = agree(0)
    pays = buyer_payments()
    ours = [pays[h] for h in hashes]
    cost = sum(cost_sats(p) for p in ours if p["status"] == "SUCCEEDED")
    fees = sum(int(p["fee_msat"]) for p in ours if p["status"] == "SUCCEEDED")
    check("one: stop: 5 settled and 3 cancelled on both nodes, the book and the buyer's node agree, no HTLC left",
          len(cancel) == 3 and b.tickets() == {"failed": 3, "settled": 5} and shop.states(hashes) == {"CANCELED": 3, "SETTLED": 5}
          and lab.tally_states(p["status"] for p in ours) == {"FAILED": 3, "SUCCEEDED": 5} and st["node"]["agree"] and not buyer_in_flight(),
          {"book": b.tickets(), "seller": shop.states(hashes), "buyer": lab.tally_states(p["status"] for p in ours), "node": st["node"]})
    check("one: the ledger holds what lf1 paid for the five, routing fees included, and nothing for the three that came back",
          WALLET_PROC.spent() - spent0 == cost and fees > 0, {"ledger_sats": WALLET_PROC.spent() - spent0, "node_cost_sats": cost, "fees_msat": fees})
    REPORT["measured"]["one_lock_8_s"] = round(time.perf_counter() - t0, 3)
    REPORT["paid_invoices"] = [p["payment_request"] for p in ours if p["status"] == "SUCCEEDED"]


def liar() -> None:
    shop = SHOPS[SELLERS[0]]
    before = (len(buyer_payments()), WALLET_PROC.spent())
    replay = REPORT.get("paid_invoices") or [""]
    saw: dict[str, Any] = {}
    b = Buyer(shop, "stream")
    b.open()
    for lie, rule in (("other_payee", "ticket_payee"), ("amount", "ticket_amount"), ("life", "ticket_blocks"), ("expiry", "ticket_expiry"),
                      ("own_hash", "ticket_hash"), ("garbage", "ticket_invoice"), (f"replay:{replay[0]}", "ticket_hash")):
        shop.lie = lie
        try:
            out = b.lock()
        finally:
            shop.lie = ""
        rules = sorted({r["rule"] for r in out.get("refused", [])})
        saw[lie.split(":")[0]] = {"locked": out.get("locked"), "rules": rules}
        if out.get("locked") != 0 or rules != [rule]:
            FAILED.append(f"liar: {lie}")
        # the hashes of a refused round lapse; the next round needs fresh ones
        signer("ticket_stop", {"session": b.session})
        b = Buyer(shop, "stream")
        b.open()
    signer("ticket_stop", {"session": b.session})
    after = (len(buyer_payments()), WALLET_PROC.spent())
    check("liar: lock answers with another payee, amount, life, expiry, a hash of the seller's own, garbage, replayed invoices: nothing is paid",
          all(v["locked"] == 0 and len(v["rules"]) == 1 for v in saw.values()) and after == before and status()["locked"]["tickets"] == 0,
          {"refusals": saw, "lf1_payments_before_after": [before[0], after[0]], "ledger_before_after": [before[1], after[1]]})
    terms: dict[str, Any] = {}
    for name, lie, rule in (("ticket of 5,000 sat", {"ticketMsat": "5000000"}, "ticket_size"), ("life of 2,016 blocks", {"ticketBlocks": 2016}, "ticket_blocks"),
                            ("no feature bit 512", {"features": []}, "ticket_feature_512"), ("a prepaid balance", {"settle": "on-arrival"}, "ticket_terms")):
        shop.terms_lie = lie
        try:
            terms[name] = Buyer(shop, "stream").open().get("rule")
        finally:
            shop.terms_lie = {}
        if terms[name] != rule:
            FAILED.append(f"liar terms: {name}")
    shop.terms_lie = {"maxTickets": 400}
    greedy = Buyer(shop, "stream").open()
    shop.terms_lie = {}
    signer("ticket_stop", {"session": greedy.get("session", "")})
    check("liar: terms above the owner's bounds refuse the seller; a seller that asks for 400 tickets gets the owner's 8",
          list(terms.values()) == ["ticket_size", "ticket_blocks", "ticket_feature_512", "ticket_terms"] and greedy.get("pool") == 8, {"terms": terms, "pool_for_400": greedy.get("pool")})
    other = Buyer(SHOPS[SELLERS[1]], "stream").open()
    check("liar: a seller the owner has not named is refused under a task for named sellers", other.get("rule") == "ticket_admission", other.get("reason"))


def kill() -> None:
    shop = SHOPS[SELLERS[0]]
    spent0 = WALLET_PROC.spent()
    b = fresh(shop)
    used = [b.pay() for _ in range(2)]
    held = signer("ticket_release", {"session": b.session})  # a secret that left the signer and never reached the seller
    WALLET_PROC.kill()
    WALLET_PROC.start()
    st = agree(6)
    tickets = b.tickets()
    again = signer("ticket_release", {"session": b.session})
    check("kill: after a kill of the signer the book is the node (6 in flight), 5 tickets it cannot vouch for are retired, and no secret is released again",
          st["node"]["agree"] and st["node"]["htlcs"] == 6 and buyer_in_flight() == {t for t in b.hashes if t not in {u[0]["hash"] for u in used}}
          and tickets == {"released": 1, "retired": 5, "settled": 2} and again.get("verdict") == "deny" and "ticket_secret" not in again,
          {"node": st["node"], "book": tickets, "release_after": again.get("rule"), "used": [u[1] for u in used]})
    pays = buyer_payments()
    settled = sum(cost_sats(pays[u[0]["hash"]]) for u in used)
    booked = WALLET_PROC.spent() - spent0
    check("kill: the ledger never under-counts: the two used at what lf1 paid, the six still locked at their worst case",
          booked == settled + 6 * held["charged_sats"], {"ledger_sats": booked, "settled_sats": settled, "worst_case_each": held["charged_sats"]})
    b.seq += 1
    shop_http("POST", f"/{shop.node}/x402/ticket/cancel", {"session": b.remote, "seq": b.seq, "hashes": "all"})
    lab.wait("the session to close", 60, lambda: status(b.session)["sessions"][0]["state"] == "closed", every=0.5)
    st = agree(0)
    check("kill: the seller cancels what is left: the bookings of the six go, the two that were used stay",
          WALLET_PROC.spent() - spent0 == settled and b.tickets() == {"failed": 6, "settled": 2} and st["node"]["agree"],
          {"ledger_sats": WALLET_PROC.spent() - spent0, "book": b.tickets()})


def node() -> None:
    shop = SHOPS[SELLERS[0]]
    b = fresh(shop)
    secs = lab.start(BUYER)
    lab.wait("lf1's channel active again", 120, partial(active, BUYER, 1))
    st = agree(8, secs=60)
    check("node: after a restart of the buyer's node its 8 tickets are still locked there and in the book",
          st["node"]["agree"] and st["node"]["htlcs"] == 8 and b.tickets() == {"locked": 8} and shop.states(b.hashes) == {"ACCEPTED": 8},
          {"node": st["node"], "book": b.tickets(), "seller": shop.states(b.hashes), "restart_s": round(secs, 1)})
    rel, code = b.pay()
    end_session(b)
    st = agree(0)
    check("node: a ticket locked before the restart pays a request after it; stop returns the other seven",
          code == 200 and b.tickets() == {"failed": 7, "settled": 1} and st["node"]["agree"], {"http": code, "book": b.tickets(), "node": st["node"]})


def silent() -> None:
    shop = SHOPS[SELLERS[0]]
    spent0 = WALLET_PROC.spent()
    b = fresh(shop)
    held = signer("ticket_release", {"session": b.session})  # released, and the seller never hears of it
    h0 = lab.height()
    booked = WALLET_PROC.spent() - spent0
    signer("ticket_stop", {"session": b.session})
    mined = 0
    while buyer_in_flight() and mined < 60:
        tick()
        mined += 1
    lab.wait("the session to close", 60, lambda: status(b.session)["sessions"][0]["state"] == "closed", every=0.5)
    st = agree(0)
    check("silent: a seller that neither settles nor cancels: its node gives the tickets up before their expiry, and the released one's booking goes",
          booked == held["charged_sats"] and b.tickets() == {"failed": 8} and WALLET_PROC.spent() == spent0 and st["node"]["agree"] and mined <= CLTV,
          {"booked_while_out": booked, "blocks_until_free": mined, "locked_at": h0, "book": b.tickets(), "ledger_after": WALLET_PROC.spent() - spent0})
    REPORT["measured"]["silent_blocks_until_free"] = mined


def restore() -> None:
    first, second = SHOPS[SELLERS[0]], SHOPS[SELLERS[1]]
    spent0 = WALLET_PROC.spent()
    a = fresh(first)
    WALLET_PROC.kill()
    shutil.copytree(f"{WALLET}/.run", f"{RUN}/backup")
    WALLET_PROC.start()
    # after the copy: a new session with the same seller (the start stopped the old one) and one with another
    a2 = fresh(first)
    used_a, _ = a2.pay()
    held_a = signer("ticket_release", {"session": a2.session})
    c = fresh(second, task="swarm")
    used_c, _ = c.pay()
    lab.wait("lf1 to see both settled", 30, lambda: all(buyer_payments()[h]["status"] == "SUCCEEDED" for h in (used_a["hash"], used_c["hash"])))
    time.sleep(3)
    truth = WALLET_PROC.spent() - spent0
    WALLET_PROC.kill()
    shutil.rmtree(f"{WALLET}/.run")
    shutil.copytree(f"{RUN}/backup", f"{WALLET}/.run")
    WALLET_PROC.start()
    # in flight on lf1: the 8 of the first session, 7 of the second, 1 of the other seller's
    st = agree(16)
    pays = buyer_payments()
    counts = st["tickets"]
    after = WALLET_PROC.spent() - spent0
    settled = cost_sats(pays[used_a["hash"]]) + cost_sats(pays[used_c["hash"]])
    events = [e for e in signer("history", {"limit": 5000})["events"] if e.get("type") == "ticket_recovered"]
    check("restore: a wallet put back from an older copy finds on lf1 the 10 tickets its book has never held, and its book is the node again",
          len(events) == 10 and st["node"]["agree"] and st["node"]["htlcs"] == 16 and st["synced"] is True,
          {"recovered": len(events), "node": st["node"], "book": counts})
    check("restore: nothing spent is missing from the ledger: the two settled at what lf1 paid, the sixteen in flight at their worst case",
          after >= truth and after == settled + 16 * held_a["charged_sats"], {"ledger_before_restore": truth, "ledger_after": after, "settled_sats": settled})
    old = signer("ticket_release", {"session": a.session})
    check("restore: no ticket of the old book is released by the restored wallet", old.get("verdict") == "deny" and "ticket_secret" not in old, old.get("rule"))
    # the secret that was out before the restore is still good: the seller settles it, the rest is cancelled
    a2.request(held_a["ticket_secret"])
    for shop in (first, second):
        for sid in list(shop.sessions):
            shop.cancel({"session": sid, "hashes": "all"})
    lab.wait("no HTLC on lf1", 60, lambda: not buyer_in_flight())
    st = agree(0)
    pays = buyer_payments()
    exact = sum(cost_sats(pays[h]) for h in (used_a["hash"], used_c["hash"], held_a["hash"]))
    lab.wait("the ledger to settle", 30, lambda: WALLET_PROC.spent() - spent0 == exact)
    check("restore: once every ticket is settled or cancelled the ledger is exactly what lf1 paid", WALLET_PROC.spent() - spent0 == exact and st["node"]["agree"],
          {"ledger_sats": WALLET_PROC.spent() - spent0, "node_cost_sats": exact})


def many() -> None:
    spent0 = WALLET_PROC.spent()
    # the sellers the owner has not named first, the one it has named last: by then the task has many sellers
    buyers = [Buyer(SHOPS[s], "swarm") for s in SELLERS[1:] + SELLERS[:1]]
    opened = [b.open() for b in buyers]
    # an unnamed seller gets 2 tickets whatever the task; a named one 8 among a few sellers and 2 among more than 8
    want = [(2, False)] * (N - 1) + [(2 if N > 8 else 8, True)]
    pools = [int(o.get("pool", 0)) for o in opened]
    total = sum(pools)
    check(f"many: {N} sellers open under the swarm task, {N - 1} the owner has not named and one it has, with a pool of 2 each",
          [(o.get("pool"), o.get("listed")) for o in opened] == want,
          lab.tally_states(f"{o.get('verdict')}/pool {o.get('pool')}/named {o.get('listed')}{o.get('rule', '')}" for o in opened))

    def fill(pair: tuple[Buyer, int]) -> int:
        b, pool = pair
        end = time.time() + 180
        while len(b.hashes) < pool and time.time() < end:
            b.lock()
            if len(b.hashes) < pool:
                time.sleep(2)
        return len(b.hashes)

    t0 = time.perf_counter()
    locked = list(POOL.map(fill, zip(buyers, pools)))
    secs = time.perf_counter() - t0
    st = agree(total, secs=60)
    check(f"many: {total} tickets locked with {N} sellers at once, the book and lf1 agree",
          locked == pools and st["node"]["agree"] and st["node"]["htlcs"] == total and st["locked"]["tickets"] == total,
          {"locked": sum(locked), "seconds": round(secs, 2), "node": st["node"], "book": st["locked"]})
    REPORT["measured"]["many_lock_s"] = round(secs, 2)
    REPORT["measured"]["many_tickets"] = total
    codes = list(POOL.map(lambda b: b.pay()[1], buyers))
    list(POOL.map(lambda b: b.stop(), buyers))
    lab.wait("no HTLC on lf1", 120, lambda: not buyer_in_flight())
    st = agree(0, secs=60)
    pays = buyer_payments()
    ours = [pays[h] for b in buyers for h in b.hashes]
    cost = sum(cost_sats(p) for p in ours if p["status"] == "SUCCEEDED")
    lab.wait("the ledger to settle", 30, lambda: WALLET_PROC.spent() - spent0 == cost)
    check(f"many: one paid request to each of {N} sellers, then stop: {N} settled, {total - N} cancelled, the book and lf1 agree, fees booked",
          codes == [200] * N and lab.tally_states(p["status"] for p in ours) == {"FAILED": total - N, "SUCCEEDED": N} and st["node"]["agree"]
          and st["locked"]["tickets"] == 0 and WALLET_PROC.spent() - spent0 == cost,
          {"http": lab.tally_states(str(c) for c in codes), "buyer": lab.tally_states(p["status"] for p in ours), "ledger_sats": WALLET_PROC.spent() - spent0,
           "node_cost_sats": cost, "node": st["node"]})


def surface() -> None:
    mac = signer("ln_status").get("macaroon", {})
    check("surface: the wallet's macaroon for lf1 is the Lightning rail's four permissions and nothing more",
          mac.get("ops") == sorted(lab.BUYER_PERMISSIONS) and mac.get("only_needed") is True, mac.get("ops"))

    def tools(env: dict[str, str]) -> list[str]:
        p = subprocess.Popen([f"{BIN}/xbt-wallet-mcp", "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                             env=dict(os.environ, B2_SIGNER_SOCK=SOCK, **env))
        assert p.stdin and p.stdout
        try:
            for i, (method, params) in enumerate((("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
                                                  ("tools/list", {})), start=1):
                p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}) + "\n")
                p.stdin.flush()
                reply = json.loads(p.stdout.readline())
                if i == 1:
                    p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            return [t["name"] for t in reply["result"]["tools"]]
        finally:
            p.stdin.close()
            p.wait(10)

    plain, with_tickets = tools({}), tools({"XBT_MCP_TICKETS": "1"})
    ticket_tools = sorted(t for t in with_tickets if t.startswith("ticket_"))
    check("surface: the MCP offers ticket_status and ticket_stop only when the operator turns them on, and never a tool that locks or releases",
          ticket_tools == ["ticket_status", "ticket_stop"] and not any(t.startswith("ticket_") for t in plain), {"with": ticket_tools, "without": len(plain)})


CHECKS = {"one": one, "liar": liar, "kill": kill, "node": node, "silent": silent, "restore": restore, "many": many, "surface": surface}


def main() -> int:
    names = sys.argv[1:] or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        print(f"unknown check {unknown}; the checks are {' '.join(CHECKS)}", file=sys.stderr)
        return 2
    t0 = time.time()
    try:
        setup()
        print(f"lab up in {time.time() - t0:.0f} s: {BUYER} (buyer) - {HOP} (hop) - {N} sellers, height {lab.height()}", flush=True)
        for name in names:
            try:
                CHECKS[name]()
            except (LabError, OSError, http.client.HTTPException, KeyError, IndexError, ValueError, AssertionError) as e:
                check(f"{name}: ran to its end", False, f"{type(e).__name__}: {e}")
                break  # the lab is in an unknown state: later checks would report that, not themselves
    finally:
        if WALLET_PROC.proc is not None:
            WALLET_PROC.proc.terminate()
    REPORT["measured"]["requests_sent_again_ticket_not_locked"] = len(RETRIES)
    REPORT["failed"] = FAILED
    REPORT["seconds"] = round(time.time() - t0)
    with open(os.path.join(OUT, "ticket_book_regtest.json"), "w") as f:
        json.dump(REPORT, f, indent=1)
    passed = sum(1 for c in REPORT["checks"] if c["ok"])
    print(f"ticket_book: {passed} of {len(REPORT['checks'])} checks passed, {REPORT['seconds']} s", flush=True)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
