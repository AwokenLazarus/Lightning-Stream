#!/usr/bin/env python3
"""The seller gateway on a Lightning Fork regtest: the shipped binary, an unchanged file server
behind it, and a test buyer that speaks the wire draft (docs/TICKETS.md) through a routing hop.

Run by scripts/gateway_regtest.sh, which brings up the chain node and builds the binary.

    lf1 ---- lf2 ---- lf3 ==== xbt-gateway ---- python3 -m http.server
    buyer    hop     seller    (on the host)    (a 100 MB file, a small one)

Channels lf1->lf2 and lf2->lf3 of 5,000,000 sat (1,000,000 pushed). The seller's node accepts 30
pending payments from a peer, so its inbound channel carries 30: the slot count of a channel with a
Core Lightning node at its default. The gateway runs with its shipped ticket terms and caps (2
tickets a session, 15 held for all sessions together, held and prepaid tickets) and holds two baked
macaroons of lf3: invoices:read + invoices:write, and info:read. Tickets are 1,000 sat with a final
CLTV delta of 40. The big file costs 200,000 msat per MiB (about 19 tickets); the small one 2,500
msat per request. Every check prints PASS or FAIL and what it saw.

  terms       the 402 names lf3, the ticket size, count and life, the price rule and the session path
  macaroons   the two macaroons cannot send coins, pay, open a channel or bake; --check refuses a
              wider one on mainnet and takes the two narrow ones
  fetch       the big file priced per byte: tickets locked through the hop and released as the body
              arrives; the buyer stops releasing half way: what came back is what was paid for, to
              the byte, the rest of its tickets are cancelled and its node shows them failed
  whole       a 10 MB file end to end: the bytes are the file's, the last receipt has their hash
  latency     the same small request direct, through a free route, paid from the balance, and paid
              with a secret (a settle on the node); medians and the difference
  locked      a secret for an unpaid ticket, a replayed request, a replayed secret, another buyer's
              secret: none is served, and the other buyer's ticket stays locked
  margin      a ticket is used with 25 blocks left and refused with 24; nothing is settled inside 24
  flood       2,000 lock requests: 15 tickets are issued, half of the channel's 30 slots, and every
              other buyer is told slots_short and when to come back; a buyer that locks and never
              releases has its tickets cancelled, and its node shows them failed
  paidfirst   the gateway as shipped: 2,000 locks for held tickets from buyers that paid nothing get
              prepaid_first and no hold invoice; a buyer that pays a prepaid ticket first (an invoice
              payable for 20 s) then holds its 2
  prepaid     a ticket settled on arrival: an ordinary invoice, paid, credited once when its
              preimage is presented, with nothing held on any channel; bought while the held cap is full
  slots       the gateway given a third macaroon (offchain:read) reads its node's channels: half of
              the smallest is its cap, and it issues no held ticket while a channel is half full
  upstream    the file server stopped: 502, nothing charged; back: served
  restart     the gateway restarted, then the seller's node restarted, with tickets locked: the
              tickets are still good, and a request while the node is away is 503 and not served

Usage: drive.py [--no-setup] [check ...]   (all checks, in the order above, when none is named)
Environment: LAB, RUN (see scripts/ln_ticket/lab.py), OUT (where gateway_regtest.json goes), GATEWAY_BIN,
GATEWAY_PORT (17834), GATEWAY_UPSTREAM_PORT (17835).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import signal
import subprocess
import sys
import threading
import time
from functools import partial
from typing import Any, NamedTuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ln_ticket"))
import lab
from lab import LabError, Ticket

BUYER, HOP, SELLER = "lf1", "lf2", "lf3"
NODES = (BUYER, HOP, SELLER)
RUN = os.environ["RUN"]
BIN = os.environ["GATEWAY_BIN"]
PORT = int(os.environ.get("GATEWAY_PORT", "17834"))
UP_PORT = int(os.environ.get("GATEWAY_UPSTREAM_PORT", "17835"))
ORIGIN = f"http://127.0.0.1:{PORT}"
TICKET_MSAT = 1_000_000
CLTV = 40
MARGIN = 24
BIG = 100_000_000
MID = 10_000_000
BYTE_MSAT, PER_BYTES = 200_000, 1_048_576
REQUEST_MSAT = 2_500
FIRST_USE_S = 15
POOL = 2  # tickets a session holds, as the gateway ships
SLOTS = 30  # pending payments the seller's inbound channel carries
HELD_CAP = SLOTS // 2  # held tickets for all sessions together: half of them
REPORT: dict[str, Any] = {"checks": [], "measured": {}}
FAILED: list[str] = []
PROCS: dict[str, subprocess.Popen[bytes]] = {}
MAC: dict[str, str] = {}
NETWORK = ""


def check(name: str, ok: bool, saw: Any) -> None:
    print(("PASS " if ok else "FAIL ") + name + ": " + json.dumps(saw, default=str)[:600], flush=True)
    REPORT["checks"].append({"check": name, "ok": bool(ok), "saw": saw})
    if not ok:
        FAILED.append(name)


def measured(key: str, value: Any) -> None:
    REPORT["measured"][key] = value
    print(f"  {key} = {json.dumps(value)}", flush=True)


# --- the wire, as a buyer computes it -------------------------------------------------------------


def tagged(tag: str) -> Any:
    t = hashlib.sha256(tag.encode()).digest()
    h = hashlib.sha256()
    h.update(t + t)
    return h


def put(h: Any, x: bytes) -> None:
    h.update(len(x).to_bytes(8, "little") + x)


def request_digest(method: str, target: str, body: bytes) -> str:
    h = tagged("xbt402/req/v2")
    for f in (method.encode(), b"http", b"127.0.0.1", str(PORT).encode(), target.encode(), body):
        put(h, f)
    return h.hexdigest()


RECEIPT_FIELDS = ("scheme", "session", "seq", "releasedMsat", "spentMsat", "charged", "req", "status", "bodyHash")
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


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


def ecdsa_ok(pub_hex: str, msg32: bytes, der: bytes) -> bool:
    """ECDSA over secp256k1, to check a receipt's signature against the receipt key of the terms."""
    pub = bytes.fromhex(pub_hex)
    x = int.from_bytes(pub[1:], "big")
    y = pow(x**3 + 7, (P + 1) // 4, P)
    if (y & 1) != (pub[0] & 1):
        y = P - y
    if der[0] != 0x30 or der[2] != 0x02:
        return False
    rl = der[3]
    r = int.from_bytes(der[4 : 4 + rl], "big")
    s = int.from_bytes(der[6 + rl : 6 + rl + der[5 + rl]], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, -1, N)
    pt = _add(_mul(int.from_bytes(msg32, "big") * w % N, G), _mul(r * w % N, (x, y)))
    return pt is not None and pt[0] % N == r


def receipt_ok(r: dict[str, Any], key: str) -> bool:
    h = tagged("xbt402/ticket-receipt/v0")
    for k in RECEIPT_FIELDS:
        put(h, str(r[k]).encode())
    return ecdsa_ok(key, h.digest(), bytes.fromhex(r["sig"]))


class Answer:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status, self.headers, self.body = status, headers, body

    def json(self) -> dict[str, Any]:
        return json.loads(self.body)

    def error(self) -> str:
        try:
            return str(self.json().get("error", ""))
        except ValueError:
            return ""

    def receipt(self) -> dict[str, Any] | None:
        raw = self.headers.get("payment-response")
        return json.loads(base64.b64decode(raw))["extra"]["receipt"] if raw else None


def send(method: str, target: str, headers: dict[str, str] | None = None, body: bytes = b"", port: int = PORT) -> Answer:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        conn.request(method, target, body=body or None, headers=headers or {})
        r = conn.getresponse()
        try:
            data = r.read()
        except http.client.IncompleteRead as e:
            data = e.partial
        return Answer(r.status, {k.lower(): v for k, v in r.getheaders()}, data)
    finally:
        conn.close()


class Buyer:
    """A test buyer: secrets of its own, every invoice checked before it is paid, every receipt checked."""

    def __init__(self) -> None:
        self.session = ""
        self.key = b""
        self.seq = 0
        self.terms: dict[str, Any] = {}
        self.secrets: dict[str, bytes] = {}  # hash -> secret, unreleased
        self.released = 0
        self.tickets: dict[str, Ticket] = {}
        self.bad_receipts = 0
        self.offers: list[dict[str, Any]] = []

    def learn(self, target: str) -> dict[str, Any]:
        a = send("GET", target)
        pr = json.loads(base64.b64decode(a.headers["payment-required"]))
        self.terms = pr["accepts"][0]
        self.offers = pr["accepts"]
        return {"status": a.status, "required": pr}

    def header(self, method: str, target: str, body: bytes, secret: bytes | None = None, seq: int | None = None) -> str:
        n = self.seq if seq is None else seq
        s = secret.hex() if secret else ""
        msg = "|".join(["ticket/auth", self.session, str(n), s, "", request_digest(method, target, body)])
        payload: dict[str, Any] = {"session": self.session, "seq": n, "auth": hmac.new(self.key, msg.encode(), hashlib.sha256).hexdigest()}
        if secret:
            payload["secret"] = s
        if seq is None:
            self.seq += 1
        accepted = {"scheme": "ticket", "network": NETWORK, "extra": {"layer": "lightning"}}
        return base64.b64encode(json.dumps({"x402Version": 2, "accepted": accepted, "payload": payload}).encode()).decode()

    def took(self, a: Answer, secret: bytes | None) -> Answer:
        """Book an answer: a request that was not authenticated used up no seq; a receipt is checked."""
        r = a.receipt()
        if r is None:
            # not authenticated: the seq is still to be used; a seller that says which one it expects is believed
            self.seq = a.json()["nextSeq"] if a.error() == "bad_seq" else self.seq - 1
            return a
        said = int(r["releasedMsat"])
        if secret is not None and said == (self.released + 1) * TICKET_MSAT:
            self.released += 1
            self.secrets.pop(hashlib.sha256(secret).hexdigest(), None)
        # the released sum is the buyer's own count, never the seller's
        if not receipt_ok(r, self.terms["extra"]["receiptKey"]) or said != self.released * TICKET_MSAT:
            self.bad_receipts += 1
        return a

    def call(self, what: str, body: dict[str, Any], releasing: bytes | None = None) -> Answer:
        raw = json.dumps(body).encode()
        target = f"/x402/ticket/{what}"
        return self.took(send("POST", target, {"PAYMENT-SIGNATURE": self.header("POST", target, raw), "Content-Type": "application/json"}, raw), releasing)

    def status(self) -> dict[str, Any]:
        return self.call("status", {}).json()

    def balance(self) -> int:
        return int(self.status()["session"]["balanceMsat"])

    def get(self, target: str, secret: bytes | None = None) -> Answer:
        return self.took(self.get_only(target, secret), secret)

    def get_only(self, target: str, secret: bytes | None = None) -> Answer:
        """The request alone, for timing: its answer still has to go through `took`."""
        return send("GET", target, {"PAYMENT-SIGNATURE": self.header("GET", target, b"", secret)})

    def release(self, secret: bytes) -> Answer:
        return self.call("release", {"secrets": [secret.hex()]}, secret)

    def ask(self, count: int) -> tuple[Answer, list[bytes]]:
        """The lock request alone: hashes out, invoices back. Nothing is paid."""
        secrets = [os.urandom(32) for _ in range(count)]
        body: dict[str, Any] = {"version": "ticket/0", "hashes": [hashlib.sha256(s).hexdigest() for s in secrets]}
        headers = {"Content-Type": "application/json"}
        if self.session:
            body["session"] = self.session
            raw = json.dumps(body).encode()
            headers["PAYMENT-SIGNATURE"] = self.header("POST", "/x402/ticket/lock", raw)
            a = self.took(send("POST", "/x402/ticket/lock", headers, raw), None)
        else:
            raw = json.dumps(body).encode()
            a = send("POST", "/x402/ticket/lock", headers, raw)
            if a.status == 200 and a.json().get("session"):
                self.session, self.key = a.json()["session"], bytes.fromhex(a.json()["key"])
        return a, secrets

    def ask_prepaid(self, count: int = 1) -> Answer:
        """The lock request for tickets settled on arrival: a count out, the seller's invoices back."""
        body: dict[str, Any] = {"version": "ticket/0", "settle": "on-arrival", "count": count}
        headers = {"Content-Type": "application/json"}
        if self.session:
            body["session"] = self.session
            raw = json.dumps(body).encode()
            headers["PAYMENT-SIGNATURE"] = self.header("POST", "/x402/ticket/lock", raw)
            return self.took(send("POST", "/x402/ticket/lock", headers, raw), None)
        a = send("POST", "/x402/ticket/lock", headers, json.dumps(body).encode())
        if a.status == 200 and a.json().get("session"):
            self.session, self.key = a.json()["session"], bytes.fromhex(a.json()["key"])
        return a

    def buy_prepaid(self) -> tuple[bytes, float]:
        """Buy one prepaid ticket: the invoice checked against the terms, paid by the buyer's node,
        and its preimage, which that node has once the payment succeeded. The seconds it took."""
        t0 = time.perf_counter()
        a = self.ask_prepaid(1)
        if a.status != 200 or len(a.json()["tickets"]) != 1:
            raise LabError(f"prepaid lock: HTTP {a.status} {a.body[:200]!r}")
        t = a.json()["tickets"][0]
        d = lab.get(BUYER, "/v1/payreq/" + t["invoice"], MAC["buyer"])
        x = next(o for o in self.offers if o["extra"]["settle"] == "on-arrival")["extra"]
        good = (d["destination"] == self.terms["payTo"] and d["payment_hash"] == t["hash"] and int(d["num_msat"]) == int(x["ticketMsat"])
                and int(d["cltv_expiry"]) == int(x["ticketBlocks"]) and d["features"].get("512", {}).get("is_required") is True)
        if not good:
            raise LabError(f"a prepaid invoice that does not match the terms: {json.dumps(d)[:300]}")
        body = {"timeout_seconds": 30, "fee_limit_msat": "100000", "payment_request": t["invoice"]}
        final = lab.stream(BUYER, "POST", "/v2/router/send", body, lambda u: u["status"] in ("SUCCEEDED", "FAILED"), MAC["buyer"])
        if final.get("status") != "SUCCEEDED":
            raise LabError(f"the prepaid ticket's payment did not succeed: {json.dumps(final)[:300]}")
        preimage = bytes.fromhex(final["payment_preimage"])
        if hashlib.sha256(preimage).hexdigest() != t["hash"]:
            raise LabError("the node's preimage is not the invoice's")
        self.tickets[t["hash"]] = Ticket(preimage, t["invoice"])
        return preimage, time.perf_counter() - t0

    def lock(self, count: int) -> list[bytes]:
        """Lock `count` tickets: every invoice is checked against the terms before the buyer's node pays it."""
        a, secrets = self.ask(count)
        if a.status != 200:
            raise LabError(f"lock: HTTP {a.status} {a.body[:200]!r}")
        by_hash = {hashlib.sha256(s).hexdigest(): s for s in secrets}
        tickets = []
        for t in a.json()["tickets"]:
            d = lab.get(BUYER, "/v1/payreq/" + t["invoice"], MAC["buyer"])
            x = self.terms["extra"]
            good = (
                t["hash"] in by_hash
                and d["destination"] == self.terms["payTo"]
                and d["payment_hash"] == t["hash"]
                and int(d["num_msat"]) == int(x["ticketMsat"])
                and int(d["cltv_expiry"]) == int(x["ticketBlocks"])
                and d["features"].get("512", {}).get("is_required") is True
            )
            if not good:
                raise LabError(f"an invoice that does not match the terms: {json.dumps(d)[:300]}")
            tickets.append(Ticket(by_hash[t["hash"]], t["invoice"]))
        first = lab.pay(BUYER, tickets, MAC["buyer"])
        if any(u.get("status") != "IN_FLIGHT" for u in first):
            raise LabError(f"a ticket payment did not start: {json.dumps(first)[:300]}")
        for t in tickets:
            self.secrets[t.hash.hex()] = t.secret
            self.tickets[t.hash.hex()] = t
        want = {t.hash.hex() for t in tickets}
        lab.wait("the gateway to see the tickets ACCEPTED", 30, lambda: want <= {t["hash"] for t in self.status()["tickets"] if t["state"] == "ACCEPTED"}, every=0.02)
        return [t.secret for t in tickets]

    def payments(self) -> dict[str, int]:
        return lab.tally(lab.payments(BUYER, list(self.tickets.values())))


# --- the processes on the host --------------------------------------------------------------------


def start_upstream() -> None:
    with open(f"{RUN}/upstream.log", "ab") as log:
        PROCS["upstream"] = subprocess.Popen([sys.executable, "-m", "http.server", str(UP_PORT), "--bind", "127.0.0.1", "--directory", f"{RUN}/www"], stdout=log, stderr=log)
    lab.wait("the file server", 20, lambda: send("GET", "/small.txt", port=UP_PORT).status == 200, every=0.1)


def upstream_requests(path: str) -> int:
    """How often the file server was asked for `path`. Counted per path: on a shared host other
    programs may ask a freshly opened port for `/`, and they are neither the buyer nor the gateway."""
    want = (f'"GET {path} '.encode(), f'"HEAD {path} '.encode())
    with open(f"{RUN}/upstream.log", "rb") as f:
        return sum(1 for line in f if any(w in line for w in want))


def start_gateway(config: str = "gateway.json") -> float:
    t0 = time.monotonic()
    with open(f"{RUN}/gateway.log", "ab") as log:
        PROCS["gateway"] = subprocess.Popen([BIN, f"{RUN}/{config}"], stdout=log, stderr=log)
    lab.wait("the gateway", 60, lambda: health()["height"] is not None, every=0.05)
    return time.monotonic() - t0


def stop(name: str) -> None:
    p = PROCS.pop(name, None)
    if p is not None:
        p.send_signal(signal.SIGTERM)
        p.wait(20)


def health() -> dict[str, Any]:
    return send("GET", "/x402/ticket/health").json()


def gateway_at(height: int) -> None:
    lab.wait(f"the gateway at height {height}", 30, lambda: health()["height"] == height, every=0.05)


def seller_state(secret: bytes) -> str:
    return lab.state(SELLER, Ticket(secret, ""))


def write_config(path: str, chain: str, macaroon: str, info_macaroon: str, channels_macaroon: str = "", caps: dict[str, Any] | None = None) -> None:
    cfg: dict[str, Any] = {
        "listen": f"127.0.0.1:{PORT}",
        "public_url": ORIGIN,
        "upstream": f"http://127.0.0.1:{UP_PORT}",
        "state_dir": f"{RUN}/state",
        "node": {"rest": f"https://127.0.0.1:{lab.PORT[SELLER]}", "tls_cert": f"{RUN}/{SELLER}.tls.cert", "macaroon": macaroon, "info_macaroon": info_macaroon},
        # the shipped ticket terms and the shipped cap on held tickets (15: half of a 30-slot channel). A shorter
        # time to first use than the default 60 s, so that an unused session is closed within the run; every
        # buyer here comes from one address. The checks of the ticket mechanics lock held tickets at once: the
        # shipped rule that a session's first ticket is a prepaid one has a check of its own (paidfirst)
        "caps": {"sessions_per_address": 0, "first_use_secs": FIRST_USE_S, "held_after_paid": False, "unpaid_per_address": 0},
        "times": {"height_max_age_secs": 5},
        "routes": [
            {"path": "/big.bin", "price": {"byte_msat": BYTE_MSAT, "per_bytes": PER_BYTES}},
            {"path": "/mid.bin", "price": {"byte_msat": BYTE_MSAT, "per_bytes": PER_BYTES}},
            {"path": "/small.txt", "price": {"request_msat": REQUEST_MSAT}},
            {"path": "/free/", "free": True},
        ],
    }
    if chain != "main":
        cfg["chain"], cfg["network"] = chain, NETWORK
    else:
        # mainnet is asked for twice: without the second key no config for it is read at all
        cfg["chain"], cfg["mainnet_ack"] = "main", "real funds, software that has run on regtest only"
    if channels_macaroon:
        cfg["node"]["channels_macaroon"] = channels_macaroon
    cfg["caps"].update(caps or {})
    with open(path, "w") as f:
        json.dump(cfg, f, indent=1)


# --- setup ------------------------------------------------------------------------------------------


def active(node: str, count: int) -> bool:
    return sum(1 for c in lab.channels(node) if c["active"]) == count


def connect() -> None:
    def ready(node: str) -> bool:
        lab.load_credentials(node)
        return lab.synced(node)

    for node in NODES:
        lab.wait(f"{node} answering with its macaroon and certificate, and synced", 120, partial(ready, node))


def setup() -> None:
    lab.wait("the chain node", 120, lambda: lab.chain("getblockchaininfo"))
    lab.chain("createwallet", "lab")
    lab.wallet("generatetoaddress", "130", lab.wallet("getnewaddress"))
    lab.dc("up", "-d", *NODES)
    connect()
    for node, btc in ((BUYER, "1"), (HOP, "2"), (SELLER, "0.1")):
        lab.fund(node, btc)
    lab.mine(6, NODES)
    for node in NODES:
        lab.wait(f"{node}'s coins", 60, partial(lab.wallet_sat, node))
    lab.open_channel(BUYER, HOP, 5_000_000, 1_000_000)
    lab.open_channel(HOP, SELLER, 5_000_000, 1_000_000)
    lab.mine(8, NODES)
    for node, count in ((BUYER, 1), (HOP, 2), (SELLER, 1)):
        lab.wait(f"{node}'s channels active", 120, partial(active, node, count))

    def probe() -> bool:
        tickets, _ = lab.lock(BUYER, SELLER, 1, secs=10)
        lab.cancel_all(SELLER, tickets)
        return True

    lab.wait("a route from the buyer to the seller", 240, probe, every=2)


def prepare() -> None:
    """Macaroons, files, the config; then the file server and the gateway."""
    global NETWORK
    NETWORK = "bip122:" + lab.chain("getblockhash", "101")[:32]
    MAC["buyer"] = lab.bake(BUYER, lab.BUYER_PERMISSIONS)
    MAC["invoices"] = lab.bake(SELLER, lab.SELLER_PERMISSIONS)
    MAC["info"] = lab.bake(SELLER, ("info:read",))
    MAC["wide"] = lab.bake(SELLER, (*lab.SELLER_PERMISSIONS, "onchain:write"))
    MAC["channels"] = lab.bake(SELLER, ("offchain:read",))
    MAC["wide_channels"] = lab.bake(SELLER, ("offchain:read", "offchain:write"))
    for name in ("invoices", "info", "wide", "channels", "wide_channels"):
        with open(f"{RUN}/{name}.macaroon", "wb") as f:
            f.write(bytes.fromhex(MAC[name]))
    os.makedirs(f"{RUN}/www/free", exist_ok=True)
    block = os.urandom(1 << 20)
    for name, size in (("big.bin", BIG), ("mid.bin", MID)):
        with open(f"{RUN}/www/{name}", "wb") as f:
            # every MiB differs, so a body that repeats or skips one has another hash
            f.writelines((hashlib.sha256(block[:64] + i.to_bytes(8, "big")).digest() + block)[: min(len(block), size - i)] for i in range(0, size, len(block)))
    for name in ("small.txt", "free/small.txt"):
        with open(f"{RUN}/www/{name}", "w") as f:
            f.write("a small file\n" * 20)
    write_config(f"{RUN}/gateway.json", "regtest", f"{RUN}/invoices.macaroon", f"{RUN}/info.macaroon")
    start_upstream()
    measured("gateway_start_s", round(start_gateway(), 2))


# --- the checks -------------------------------------------------------------------------------------


def terms() -> None:
    b = Buyer()
    saw = b.learn("/big.bin")
    a, x = b.terms, b.terms["extra"]
    ok = (
        saw["status"] == 402
        and a["scheme"] == "ticket"
        and a["network"] == NETWORK
        and x.get("layer") == "lightning"
        and a["payTo"] == lab.pubkey(SELLER)
        and (x["ticketMsat"], x["maxTickets"], x["ticketBlocks"], x["release"], x["settle"], x["session"]) == ("1000000", POOL, 40, "with-request", "on-use", "/x402/ticket")
        and [o["extra"]["settle"] for o in b.offers] == ["on-use", "on-arrival"]
        and x["price"] == {"requestMsat": "0", "byteMsat": str(BYTE_MSAT), "perBytes": str(PER_BYTES), "secondMsat": "0"}
        and len(x["receiptKey"]) == 66
    )
    check("terms: the 402 names the seller's node, the ticket terms (2 a session; held tickets first, prepaid ones second) and the price rule", ok, b.offers)
    services = send("GET", "/services").json()
    check("terms: /services lists the routes, unsigned", services["signed"] is False and len(services["routes"]) == 4 and services["payTo"] == a["payTo"], services)
    nothing = send("GET", "/elsewhere")
    check("terms: a path with no route is 404 from the gateway", nothing.status == 404 and nothing.error() == "no_route", nothing.status)


class Checked(NamedTuple):
    """How `xbt-gateway --check` ended: its exit code and the last line it wrote."""

    code: int
    said: str


def macaroons() -> None:
    cannot = {}
    address = lab.wallet("getnewaddress")
    invoice = lab.issue(HOP, [os.urandom(32)])[0]
    for name in ("invoices", "info"):
        m = MAC[name]
        tries = {
            "send coins": lab.ask(SELLER, "POST", "/v1/transactions", {"addr": address, "amount": "1000"}, m),
            "pay": lab.stream(SELLER, "POST", "/v2/router/send", {"payment_request": invoice.invoice, "timeout_seconds": 5}, lambda u: True, m),
            "open a channel": lab.ask(SELLER, "POST", "/v1/channels", {"node_pubkey_string": lab.pubkey(HOP), "local_funding_amount": "20000"}, m),
            "bake a macaroon": lab.ask(SELLER, "POST", "/v1/macaroon", {"permissions": [{"entity": "onchain", "action": "write"}]}, m),
            "read the wallet": lab.ask(SELLER, "GET", "/v1/balance/blockchain", None, m),
        }
        cannot[name] = {k: lab.refused(v) for k, v in tries.items()}
    cross = {"invoices cannot read the height": lab.refused(lab.ask(SELLER, "GET", "/v1/getinfo", None, MAC["invoices"])), "info cannot make an invoice": lab.refused(lab.ask(SELLER, "POST", "/v2/invoices/hodl", {"hash": lab.b64(os.urandom(32)), "value_msat": "1000"}, MAC["info"]))}
    lab.cancel(HOP, invoice)
    check("macaroons: neither of the gateway's two can send coins, pay, open a channel, bake or read the wallet", all(all(v.values()) for v in cannot.values()) and all(cross.values()), {**cannot, **cross})

    def run_check(config: str) -> Checked:
        r = subprocess.run([BIN, "--check", config], capture_output=True, text=True, check=False)
        return Checked(r.returncode, r.stderr.strip().splitlines()[-1][:300] if r.stderr.strip() else "")

    write_config(f"{RUN}/main-wide.json", "main", f"{RUN}/wide.macaroon", f"{RUN}/info.macaroon")
    write_config(f"{RUN}/main-wide-info.json", "main", f"{RUN}/invoices.macaroon", f"{RUN}/wide.macaroon")
    write_config(f"{RUN}/main-narrow.json", "main", f"{RUN}/invoices.macaroon", f"{RUN}/info.macaroon")
    write_config(f"{RUN}/regtest-wide.json", "regtest", f"{RUN}/wide.macaroon", f"{RUN}/info.macaroon")
    wide, wide_info, narrow, off_main = (run_check(f"{RUN}/{n}.json") for n in ("main-wide", "main-wide-info", "main-narrow", "regtest-wide"))
    ok = wide.code != 0 and "refused on mainnet" in wide.said and "onchain:write" in wide.said and wide_info.code != 0 and narrow.code == 0 and off_main.code == 0
    check("macaroons: a wider macaroon is refused on mainnet, in either place; the two narrow ones are taken", ok, {"wide": wide, "wide as the height macaroon": wide_info, "narrow": narrow, "wide off mainnet": off_main})
    # the third macaroon is optional: offchain:read and nothing more
    m = MAC["channels"]
    third = {
        "pay": lab.refused(lab.stream(SELLER, "POST", "/v2/router/send", {"payment_request": invoice.invoice, "timeout_seconds": 5}, lambda u: True, m)),
        "open a channel": lab.refused(lab.ask(SELLER, "POST", "/v1/channels", {"node_pubkey_string": lab.pubkey(HOP), "local_funding_amount": "20000"}, m)),
        "make an invoice": lab.refused(lab.ask(SELLER, "POST", "/v2/invoices/hodl", {"hash": lab.b64(os.urandom(32)), "value_msat": "1000"}, m)),
        "read the on-chain wallet": lab.refused(lab.ask(SELLER, "GET", "/v1/balance/blockchain", None, m)),
    }
    # what it does show beside the channel list: stated in the gateway's README and in docs/LIMITS.md
    shows = {"the channel balances": "local_balance" in lab.ask(SELLER, "GET", "/v1/balance/channels", None, m),
             "the node's payments": "payments" in lab.ask(SELLER, "GET", "/v1/payments", None, m),
             "the channel list": "channels" in lab.ask(SELLER, "GET", "/v1/channels", None, m)}
    write_config(f"{RUN}/main-channels.json", "main", f"{RUN}/invoices.macaroon", f"{RUN}/info.macaroon", f"{RUN}/channels.macaroon")
    write_config(f"{RUN}/main-wide-channels.json", "main", f"{RUN}/invoices.macaroon", f"{RUN}/info.macaroon", f"{RUN}/wide_channels.macaroon")
    write_config(f"{RUN}/main-dust.json", "main", f"{RUN}/invoices.macaroon", f"{RUN}/info.macaroon")
    with open(f"{RUN}/main-dust.json") as f:
        dusty = json.load(f)
    dusty["tickets"] = {"ticket_msat": 500_000}
    with open(f"{RUN}/main-dust.json", "w") as f:
        json.dump(dusty, f)
    with_channels, wide_channels, dust = (run_check(f"{RUN}/{n}.json") for n in ("main-channels", "main-wide-channels", "main-dust"))
    ok = all(third.values()) and all(shows.values()) and with_channels.code == 0 and wide_channels.code != 0 and "offchain:write" in wide_channels.said
    check("macaroons: the optional channels macaroon (offchain:read) cannot pay, open a channel, make an invoice or read the wallet; it does show balances and payments; a wider one is refused on mainnet",
          ok, {"cannot": third, "shows": shows, "narrow": with_channels, "wide": wide_channels})
    check("macaroons: a config that offers held tickets of 500 sat is refused: below 546 sat a held ticket is dust", dust.code != 0 and "546" in dust.said, dust)


def fetch() -> None:
    b = Buyer()
    b.learn("/big.bin")
    with open(f"{RUN}/www/big.bin", "rb") as f:
        whole = f.read()
    requests_before = upstream_requests("/big.bin")
    pool = b.lock(POOL)
    stop_at = 10  # tickets: about half of the 19.07 the whole file costs
    target = "/big.bin"
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    t0 = time.monotonic()
    first = pool.pop(0)
    conn.request("GET", target, headers={"PAYMENT-SIGNATURE": b.header("GET", target, b"", first)})
    r = conn.getresponse()
    head = json.loads(base64.b64decode(r.getheader("PAYMENT-RESPONSE")))
    b.took(Answer(r.status, {"payment-response": r.getheader("PAYMENT-RESPONSE")}, b""), first)
    got = bytearray()
    done = threading.Event()

    def read() -> None:
        try:
            while chunk := r.read(1 << 16):
                got.extend(chunk)
        except (http.client.IncompleteRead, OSError) as e:
            got.extend(getattr(e, "partial", b""))
        done.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    locks = 1
    # release one ticket when the last is used up (the body waits for it); with one left, lock the next behind
    # it, so that two are never both gone; stop at ten
    while not done.is_set() and b.released < stop_at:
        if b.balance() == 0:
            b.release(pool.pop(0))
            if len(pool) < POOL:
                pool += b.lock(1)
                locks += 1
        else:
            time.sleep(0.002)
    stopped = time.monotonic()
    done.wait(30)
    ended_after = time.monotonic() - stopped
    conn.close()
    lab.wait("the last receipt", 10, lambda: b.status()["responses"], every=0.05)
    st = b.status()
    last = st["responses"][-1]
    paid = b.released * TICKET_MSAT
    want_bytes = paid * PER_BYTES // BYTE_MSAT
    measured("fetch", {"tickets_released": b.released, "locks": locks, "bytes": len(got), "seconds": round(stopped - t0, 2), "ended_after_last_release_s": round(ended_after, 2), "spent_msat": int(st["session"]["spentMsat"])})
    check("fetch: the head's receipt is signed and says the body is a stream", head["extra"].get("stream") is True and receipt_ok(head["extra"]["receipt"], b.terms["extra"]["receiptKey"]), head["extra"]["receipt"])
    check("fetch: what came back is what ten tickets pay for, to the byte, and is the file's", len(got) == want_bytes and bytes(got) == whole[:want_bytes], {"bytes": len(got), "paid_for": want_bytes})
    ok = receipt_ok(last, b.terms["extra"]["receiptKey"]) and int(last["charged"]) == paid and last["bytes"] == want_bytes and last["complete"] is False and last["bodyHash"] == hashlib.sha256(bytes(got)).hexdigest()
    check("fetch: the last receipt is signed, and has the bytes sent, their hash and their price", ok, last)
    check("fetch: nothing was served beyond what was released (spent equals released, balance 0)", (int(st["session"]["releasedMsat"]), int(st["session"]["spentMsat"]), int(st["session"]["balanceMsat"])) == (paid, paid, 0), st["session"])
    check("fetch: the body stopped within the refill wait of the buyer's last release", ended_after < 5, round(ended_after, 2))
    left = len(b.secrets)
    cancelled = b.call("cancel", {"hashes": "all"}).json()["cancelled"]
    finals = lab.tally(lab.POOL.map(lambda t: lab.payment(BUYER, t, final=True), list(b.tickets.values())))
    fees = sum(p.fee_msat for p in lab.payments(BUYER, list(b.tickets.values())) if p.status == "SUCCEEDED")
    ok = len(cancelled) == left and finals == {"FAILED:INCORRECT_PAYMENT_DETAILS": left, "SUCCEEDED": b.released}
    check("fetch: the tickets it did not release were cancelled and its node shows them failed; the released ones succeeded", ok, {"unreleased": left, "cancelled": len(cancelled), "buyer_node": finals})
    measured("fetch_routing_fee_msat", fees)
    check("fetch: every receipt the buyer got was signed and agreed with its own count of what it released", b.bad_receipts == 0, b.bad_receipts)
    check("fetch: the file server was asked once", upstream_requests("/big.bin") == requests_before + 1, upstream_requests("/big.bin") - requests_before)


def whole() -> None:
    b = Buyer()
    b.learn("/mid.bin")
    with open(f"{RUN}/www/mid.bin", "rb") as f:
        data = f.read()
    pool = b.lock(POOL)
    target = "/mid.bin"
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    first = pool.pop(0)
    conn.request("GET", target, headers={"PAYMENT-SIGNATURE": b.header("GET", target, b"", first)})
    r = conn.getresponse()
    b.took(Answer(r.status, {"payment-response": r.getheader("PAYMENT-RESPONSE")}, b""), first)
    got = bytearray()
    done = threading.Event()

    def read() -> None:
        try:
            while chunk := r.read(1 << 16):
                got.extend(chunk)
        except (http.client.IncompleteRead, OSError) as e:
            got.extend(getattr(e, "partial", b""))
        done.set()

    threading.Thread(target=read, daemon=True).start()
    while not done.is_set():
        if pool and b.balance() == 0:
            b.release(pool.pop(0))
        else:
            time.sleep(0.002)
    conn.close()
    lab.wait("the last receipt", 10, lambda: b.status()["responses"], every=0.05)
    st = b.status()
    last = st["responses"][-1]
    price = -(-MID * BYTE_MSAT // PER_BYTES)
    ok = bytes(got) == data and last["complete"] is True and int(last["charged"]) == price and last["bodyHash"] == hashlib.sha256(data).hexdigest() and receipt_ok(last, b.terms["extra"]["receiptKey"])
    check("whole: 10 MB end to end: the file's bytes, and a signed last receipt with their hash and price", ok, {"bytes": len(got), "price_msat": price, "receipt": last})
    check("whole: the buyer released two tickets for 1,907,349 msat and keeps the rest as balance; every receipt agreed with its own count", (b.released, int(st["session"]["balanceMsat"]), b.bad_receipts) == (2, 2 * TICKET_MSAT - price, 0), {"released": b.released, "session": st["session"], "bad_receipts": b.bad_receipts})
    b.call("cancel", {"hashes": "all"})


def timed(fn: Any, n: int) -> list[float]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t0)
    return out


def latency() -> None:
    b = Buyer()
    b.learn("/small.txt")
    secrets = b.lock(POOL)
    if b.get("/small.txt", secrets[0]).status != 200:
        raise LabError("the first paid request was not served")
    n = 300

    def expect(a: Answer) -> None:
        if a.status != 200:
            raise LabError(f"HTTP {a.status} in the latency run")

    # Interleaved, so that the host's other load falls on all alike. Only the request is timed:
    # the buyer's own work on the answer (checking the receipt's signature) is done after the clock stops.
    direct: list[float] = []
    free: list[float] = []
    paid: list[float] = []
    for _ in range(n):
        direct += timed(lambda: expect(send("GET", "/small.txt", port=UP_PORT)), 1)
        free += timed(lambda: expect(send("GET", "/free/small.txt")), 1)
        t0 = time.perf_counter()
        a = b.get_only("/small.txt")
        paid.append(time.perf_counter() - t0)
        expect(b.took(a, None))
    settle: list[float] = []
    more = secrets[1:] + b.lock(1)
    for round_ in range(16):
        for s in more:
            t0 = time.perf_counter()
            a = b.get_only("/small.txt", s)
            settle.append(time.perf_counter() - t0)
            expect(b.took(a, s))
        b.call("cancel", {"hashes": "all"})
        more = b.lock(POOL) if round_ < 15 else []
    spreads = {"direct": lab.spread(direct), "through_a_free_route": lab.spread(free), "paid_from_the_balance": lab.spread(paid), "paid_with_a_secret": lab.spread(settle)}
    measured("latency_ms", spreads)
    per_ticket = TICKET_MSAT // REQUEST_MSAT
    added = round(spreads["paid_from_the_balance"]["p50_ms"] - spreads["through_a_free_route"]["p50_ms"], 2)
    added_settle = round(spreads["paid_with_a_secret"]["p50_ms"] - spreads["through_a_free_route"]["p50_ms"], 2)
    measured("paid_minus_unpaid_p50_ms", added)
    measured("paid_with_a_secret_minus_unpaid_p50_ms", added_settle)
    check(f"latency: a paid request adds at most 5 ms at the median over the same request unpaid ({per_ticket - 1} of {per_ticket} requests at this price carry no secret)", added <= 5, {"added_ms": added})
    # measured, not a pass line of its own: the settle call is the node's, and one request in a ticket's worth makes it
    measured("note_secret", f"one request in {per_ticket} carries a secret and waits for the node's settle call: {added_settle} ms more than unpaid at the median")
    check("latency: no secret was refused and no receipt disagreed", b.bad_receipts == 0 and b.released == 1 + len(settle), {"released": b.released, "with_a_secret": len(settle), "bad_receipts": b.bad_receipts})
    h = health()
    measured("settle_max_ms", round(h["settleMaxUs"] / 1000, 2))
    check("latency: every used ticket was settled within 1 s of its secret arriving (the gateway's own worst case so far)", h["settleMaxUs"] < 1_000_000, {"settled": h["settled"], "worst_ms": round(h["settleMaxUs"] / 1000, 2)})
    b.call("cancel", {"hashes": "all"})


def locked() -> None:
    a, b = Buyer(), Buyer()
    a.learn("/small.txt")
    b.learn("/small.txt")
    served = upstream_requests("/small.txt")
    # issued, never paid
    _, unpaid = a.ask(1)
    got = a.get("/small.txt", unpaid[0])
    check("locked: a secret for a ticket that was never paid buys nothing", (got.status, got.error()) == (402, "ticket_not_locked") and seller_state(unpaid[0]) == "OPEN", {"http": got.status, "error": got.error(), "node": seller_state(unpaid[0])})
    # (the unpaid one still has one of the session's two places)
    sa, sb = a.lock(1), b.lock(POOL)
    ok1 = a.get("/small.txt", sa[0]).status == 200
    # the same request again, byte for byte
    header = a.header("GET", "/small.txt", b"")
    first = send("GET", "/small.txt", {"PAYMENT-SIGNATURE": header})
    again = send("GET", "/small.txt", {"PAYMENT-SIGNATURE": header})
    check("locked: a replayed request is refused", ok1 and first.status == 200 and (again.status, again.error()) == (402, "bad_seq"), {"first": first.status, "again": again.error()})
    used = a.get("/small.txt", sa[0])
    check("locked: a replayed secret is refused", (used.status, used.error()) == (402, "ticket_used"), used.error())
    other = a.get("/small.txt", sb[0])
    check("locked: another buyer's secret is refused, and that buyer's ticket is still locked", (other.status, other.error()) == (402, "ticket_unknown") and seller_state(sb[0]) == "ACCEPTED", {"error": other.error(), "node": seller_state(sb[0])})
    moved = send("GET", "/small.txt?x=1", {"PAYMENT-SIGNATURE": a.header("GET", "/small.txt", b"", seq=a.seq)})
    check("locked: a payment made for one target does not pay another", (moved.status, moved.error()) == (401, "bad_auth"), moved.error())
    check("locked: the file server saw the two paid requests and nothing else", upstream_requests("/small.txt") == served + 2, upstream_requests("/small.txt") - served)
    check("locked: the buyer was charged for what it was served and no more", a.balance() == TICKET_MSAT - 2 * REQUEST_MSAT, a.balance())
    for x in (a, b):
        x.call("cancel", {"hashes": "all"})


def margin() -> None:
    b = Buyer()
    b.learn("/small.txt")
    secrets = b.lock(POOL)
    inv = lab.invoice(SELLER, Ticket(secrets[0], ""))
    expiry = int(inv["htlcs"][0]["expiry_height"])
    h = lab.height()
    measured("margin", {"locked_at": h, "htlc_expiry": expiry})
    lab.mine(expiry - (MARGIN + 1) - h, NODES)
    gateway_at(expiry - MARGIN - 1)
    early = b.get("/small.txt", secrets[0])
    check("margin: a ticket with 25 blocks left is settled and served", early.status == 200 and seller_state(secrets[0]) == "SETTLED", {"http": early.status, "blocks_left": expiry - lab.height()})
    lab.mine(1, NODES)
    gateway_at(expiry - MARGIN)
    late = b.get("/small.txt", secrets[1])
    time.sleep(1.5)
    states = [seller_state(s) for s in secrets[1:]]
    ok = late.status == 402 and late.error() in ("ticket_expiring", "ticket_unknown") and states == ["CANCELED"]
    check("margin: with 24 blocks left a secret is refused, nothing is settled, and the gateway gives the ticket back", ok, {"http": late.status, "error": late.error(), "blocks_left": expiry - lab.height(), "node": states})
    final = lab.tally(lab.POOL.map(lambda t: lab.payment(BUYER, t, final=True), list(b.tickets.values())))
    check("margin: the buyer's node shows one ticket paid and one failed, 6 blocks before the node's own cancel", final == {"FAILED:INCORRECT_PAYMENT_DETAILS": 1, "SUCCEEDED": 1}, final)


def flood() -> None:
    before = health()
    pending_before = len(lab.get(SELLER, "/v1/invoices?pending_only=true&num_max_invoices=5000")["invoices"])
    tallies: dict[str, int] = {}
    retry: set[Any] = set()
    t0 = time.monotonic()
    for _ in range(2000):
        a, _ = Buyer().ask(POOL)
        key = f"{a.status} {a.error()}".strip()
        tallies[key] = tallies.get(key, 0) + 1
        if a.error() == "slots_short":
            retry.add(a.json().get("retryAfter"))
    took = time.monotonic() - t0
    h = health()
    pending = len(lab.get(SELLER, "/v1/invoices?pending_only=true&num_max_invoices=5000")["invoices"]) - pending_before
    measured("flood", {"requests": 2000, "seconds": round(took, 1), "answers": tallies, "active_sessions": h["activeSessions"], "held_tickets": h["heldTickets"], "max_held": h["maxHeld"],
                       "held_msat": h["heldMsat"], "unpaid_invoices_on_the_node": pending, "retry_after": sorted(retry)})
    room = HELD_CAP - before["heldTickets"]
    served = -(-room // POOL)  # the last session to be served gets the one place that is left
    ok = (tallies.get("200", 0) == served and tallies.get("402 slots_short", 0) == 2000 - served and h["heldTickets"] == HELD_CAP == h["maxHeld"] and pending == room
          and retry == {30})
    check(f"flood: of 2,000 lock requests {HELD_CAP} tickets were issued, half of the channel's {SLOTS} slots; every other buyer was told slots_short and to come back in 30 s, has no session, and the node was asked for nothing more",
          ok, {"answers": tallies, "held_tickets": h["heldTickets"], "unpaid_invoices": pending, "sessions_made": h["sessions"] - before["sessions"], "retry_after": sorted(retry)})
    lab.wait("the unused sessions to be closed and forgotten", FIRST_USE_S + 20, lambda: health()["activeSessions"] == 0 and health()["sessions"] <= before["sessions"], every=0.5)
    gone = len(lab.get(SELLER, "/v1/invoices?pending_only=true&num_max_invoices=5000")["invoices"]) - pending_before
    after = health()
    # (sessions of earlier checks that had used up their balance are forgotten in the same sweep)
    ok = gone <= 0 and after["heldTickets"] == 0 and after["sessions"] <= before["sessions"]
    check(f"flood: sessions that never paid were closed after {FIRST_USE_S} s, their invoices cancelled on the node, and nothing of them is kept", ok, {"unpaid_invoices_left": gone, "sessions_before": before["sessions"], "sessions_after": after["sessions"]})
    # a buyer that pays for its tickets and never releases one
    b = Buyer()
    b.learn("/small.txt")
    t0 = time.monotonic()
    idle = lab.pending_htlcs(SELLER)
    b.lock(POOL)
    held = lab.pending_htlcs(SELLER) - idle
    lab.wait("the silent buyer's tickets to be cancelled", FIRST_USE_S + 20, lambda: lab.pending_htlcs(SELLER) == idle, every=0.2)
    secs = time.monotonic() - t0
    final = lab.tally(lab.POOL.map(lambda t: lab.payment(BUYER, t, final=True), list(b.tickets.values())))
    measured("silent_buyer_locked_s", round(secs, 1))
    check("flood: a buyer that locks 2 tickets and releases none held 2,000 sat of the seller's inbound capacity until the gateway cancelled them; its node shows them failed", held == POOL and final == {"FAILED:INCORRECT_PAYMENT_DETAILS": POOL}, {"held_htlcs": held, "seconds": round(secs, 1), "buyer_node": final})
    served = upstream_requests("/small.txt")
    got = b.get("/small.txt")
    check("flood: and it was served nothing", got.status == 402 and upstream_requests("/small.txt") == served, {"http": got.status, "error": got.error()})


def upstream() -> None:
    b = Buyer()
    b.learn("/small.txt")
    s = b.lock(2)
    ok = b.get("/small.txt", s[0]).status == 200
    spent = int(b.status()["session"]["spentMsat"])
    stop("upstream")
    down = b.get("/small.txt")
    r = down.receipt()
    after = int(b.status()["session"]["spentMsat"])
    check("upstream: with the file server stopped a paid request is 502 and nothing is charged", ok and (down.status, down.error()) == (502, "upstream_unavailable") and r is not None and r["charged"] == "0" and after == spent, {"http": down.status, "charged": r and r["charged"], "spent_before": spent, "spent_after": after})
    start_upstream()
    back = b.get("/small.txt")
    check("upstream: with the file server back the same session is served", back.status == 200, back.status)
    b.call("cancel", {"hashes": "all"})


def restart() -> None:
    b = Buyer()
    b.learn("/small.txt")
    s = b.lock(POOL)
    if b.get("/small.txt", s[0]).status != 200:
        raise LabError("the first paid request was not served")
    before = b.status()["session"]
    stop("gateway")
    secs = start_gateway()
    after = b.status()
    kept = (after["session"]["releasedMsat"], after["session"]["spentMsat"]) == (before["releasedMsat"], before["spentMsat"]) and len(after["tickets"]) == POOL - 1
    lab.wait("the tickets ACCEPTED again", 30, lambda: all(t["state"] == "ACCEPTED" for t in b.status()["tickets"]), every=0.05)
    got = b.get("/small.txt", s[1])
    check("restart: after the gateway restarts, the session, its balance and its locked ticket are there and the ticket is used", kept and got.status == 200 and seller_state(s[1]) == "SETTLED", {"restart_s": round(secs, 2), "before": before, "after": after["session"], "http": got.status})
    old = b.get("/small.txt", s[0])
    check("restart: a secret used before the restart is not good again", old.status == 402 and old.error() in ("ticket_used", "ticket_unknown"), old.error())

    s += b.lock(POOL)
    lab.stop(SELLER)
    served = upstream_requests("/small.txt")
    away = b.get("/small.txt", s[2])
    paid = b.get("/small.txt")
    check("restart: with the seller's node stopped a secret is not taken (503) and the balance still pays", (away.status, away.error()) == (503, "node_unavailable") and paid.status == 200 and upstream_requests("/small.txt") == served + 1, {"secret": away.status, "balance": paid.status})
    secs = lab.start(SELLER)
    lab.wait("the gateway to have the node's height again", 60, lambda: health()["height"] is not None, every=0.1)
    lab.wait("the hop to reach the seller again", 60, lambda: active(SELLER, 1), every=0.2)
    again = b.get("/small.txt", s[2])
    last = b.get("/small.txt", s[3])
    states = [seller_state(x) for x in s[2:]]
    check("restart: after the seller's node restarts, tickets locked before it are settled and served", (again.status, last.status) == (200, 200) and states == ["SETTLED", "SETTLED"], {"node_restart_s": round(secs, 1), "http": [again.status, last.status], "node": states})
    final = lab.tally(lab.POOL.map(lambda t: lab.payment(BUYER, t, final=True), list(b.tickets.values())))
    check("restart: the buyer's node shows all four tickets paid", final == {"SUCCEEDED": 4}, final)
    check("restart: every receipt was signed by the same key, before and after", b.bad_receipts == 0, b.bad_receipts)


def prepaid() -> None:
    idle = lab.pending_htlcs(SELLER)
    # the held cap is full of other buyers' unpaid tickets: a held ticket is refused, a prepaid one is not
    crowd = []
    while health()["heldTickets"] < HELD_CAP:
        c = Buyer()
        c.ask(POOL)
        crowd.append(c)
    b = Buyer()
    b.learn("/small.txt")
    refused, _ = b.ask(POOL)
    served = upstream_requests("/small.txt")
    secret, secs = b.buy_prepaid()
    # the payment is settled before its HTLC is off the channel: a moment, not a hold
    gone = lab.wait("the prepaid ticket's payment to be off the seller's channel", 10, lambda: lab.pending_htlcs(SELLER) == idle, every=0.02)
    measured("prepaid_off_the_channel_after_s", round(gone, 3))
    h = health()
    check("prepaid: with the held cap full a held ticket is refused (slots_short) and a prepaid one is issued and paid; nothing is pending on the seller's channel",
          (refused.status, refused.error()) == (402, "slots_short") and h["heldTickets"] == HELD_CAP and h["prepaidTickets"] == 1 and lab.pending_htlcs(SELLER) == idle and seller_state(secret) == "SETTLED",
          {"held_lock": refused.error(), "held": h["heldTickets"], "prepaid_open": h["prepaidTickets"], "pending_htlcs": lab.pending_htlcs(SELLER) - idle, "node": seller_state(secret)})
    unpaid = b.get("/small.txt")
    wrong = b.release(os.urandom(32))
    t0 = time.perf_counter()
    took = b.release(secret)
    credit_s = time.perf_counter() - t0
    again = b.release(secret)
    st = b.status()
    ok = ((unpaid.status, unpaid.error()) == (402, "balance_short") and wrong.json()["refused"][0]["error"] == "ticket_unknown" and took.json()["released"] == [hashlib.sha256(secret).hexdigest()]
          and again.json()["refused"][0]["error"] == "ticket_used" and st["session"]["releasedMsat"] == str(TICKET_MSAT) and b.bad_receipts == 0)
    check("prepaid: nothing is credited before the preimage is presented; the node's own preimage credits one ticket, once; a made-up one credits nothing",
          ok, {"before": unpaid.error(), "made_up": wrong.json()["refused"], "released": took.json(), "again": again.json()["refused"], "session": st["session"]})
    got = b.get("/small.txt")
    check("prepaid: the balance pays requests like any released ticket's", got.status == 200 and upstream_requests("/small.txt") == served + 1 and b.balance() == TICKET_MSAT - REQUEST_MSAT, {"http": got.status, "balance": b.balance()})
    times = [secs + credit_s]
    for _ in range(9):
        s2, t2 = b.buy_prepaid()
        t0 = time.perf_counter()
        if b.release(s2).json()["released"] != [hashlib.sha256(s2).hexdigest()]:
            raise LabError("a paid prepaid ticket was not credited")
        times.append(t2 + time.perf_counter() - t0)
    measured("prepaid_ticket_ms", lab.spread(times))
    lab.wait("the last payment to be off the seller's channel", 10, lambda: lab.pending_htlcs(SELLER) == idle, every=0.02)
    fees = sum(p.fee_msat for p in lab.payments(BUYER, list(b.tickets.values())) if p.status == "SUCCEEDED")
    check("prepaid: ten prepaid tickets bought one at a time through the hop: each from the lock request to the seller's signed credit, all credited, none held",
          int(b.status()["session"]["releasedMsat"]) == 10 * TICKET_MSAT and b.bad_receipts == 0 and lab.pending_htlcs(SELLER) == idle,
          {"per_ticket_ms": lab.spread(times), "routing_fee_msat": fees})
    # one that is paid and never presented is credited all the same when the gateway's sweep finds it
    c = Buyer()
    c.learn("/small.txt")
    c.buy_prepaid()
    lab.wait("the gateway's sweep to credit the paid ticket nobody presented", 120, lambda: c.status()["session"]["releasedMsat"] == str(TICKET_MSAT), every=1)
    check("prepaid: a paid ticket whose preimage was never presented is credited by the gateway's own sweep", c.balance() == TICKET_MSAT, c.balance())
    lab.wait("the crowd's unpaid tickets to lapse", FIRST_USE_S + 100, lambda: health()["heldTickets"] == 0, every=1)


def paidfirst() -> None:
    """The gateway as it ships: hold invoices only to a session that has paid a ticket."""
    stop("gateway")
    write_config(f"{RUN}/paidfirst.json", "regtest", f"{RUN}/invoices.macaroon", f"{RUN}/info.macaroon", caps={"held_after_paid": True, "unpaid_per_address": 2})
    with open(f"{RUN}/paidfirst.json") as f:
        cfg = json.load(f)
    # as shipped, but for the address cap on sessions (every buyer here has one address)
    for k in ("held_after_paid", "unpaid_per_address"):
        cfg["caps"].pop(k)
    with open(f"{RUN}/paidfirst.json", "w") as f:
        json.dump(cfg, f, indent=1)
    start_gateway("paidfirst.json")
    before = health()
    pending_before = len(lab.get(SELLER, "/v1/invoices?pending_only=true&num_max_invoices=5000")["invoices"])
    tallies: dict[str, int] = {}
    t0 = time.monotonic()
    for _ in range(2000):
        a, _ = Buyer().ask(POOL)
        key = f"{a.status} {a.error()}".strip()
        tallies[key] = tallies.get(key, 0) + 1
    took = time.monotonic() - t0
    h = health()
    pending = len(lab.get(SELLER, "/v1/invoices?pending_only=true&num_max_invoices=5000")["invoices"]) - pending_before
    measured("paidfirst_flood", {"requests": 2000, "seconds": round(took, 1), "answers": tallies, "held_tickets": h["heldTickets"], "unpaid_invoices_on_the_node": pending,
                                 "sessions_made": h["sessions"] - before["sessions"]})
    check("paidfirst: of 2,000 locks for held tickets from buyers that have paid nothing, none is issued a hold invoice: each is told prepaid_first, has no session, and the node is asked for nothing",
          tallies == {"402 prepaid_first": 2000} and pending == 0 and h["heldTickets"] == 0 and h["sessions"] == before["sessions"], {"answers": tallies, "unpaid_invoices": pending})
    # a buyer that pays a prepaid ticket first, and then holds
    b = Buyer()
    b.learn("/small.txt")
    secret, _ = b.buy_prepaid()
    inv = b.tickets[hashlib.sha256(secret).hexdigest()].invoice
    expiry = int(lab.get(BUYER, "/v1/payreq/" + inv, MAC["buyer"]).get("expiry", 0))
    check("paidfirst: a first lock buys a prepaid ticket, whose invoice is payable for 20 s", expiry == 20, {"expiry": expiry})
    early, _ = b.ask(POOL)
    released = b.release(secret).json().get("released")
    s = b.lock(POOL)
    check("paidfirst: before its prepaid ticket is presented the session is told prepaid_first; once it is credited the session holds its 2 tickets",
          (early.status, early.error()) == (402, "prepaid_first") and released == [hashlib.sha256(secret).hexdigest()] and len(s) == POOL and health()["heldTickets"] == POOL,
          {"early": [early.status, early.error()], "released": released, "held": health()["heldTickets"]})
    b.call("cancel", {"hashes": "all"})
    stop("gateway")
    start_gateway()


def slots() -> None:
    # a config that assumes every inbound channel carries 483 (a cap of 241), and the channels macaroon: the gateway
    # reads its node and finds 30
    stop("gateway")
    write_config(f"{RUN}/sized.json", "regtest", f"{RUN}/invoices.macaroon", f"{RUN}/info.macaroon", f"{RUN}/channels.macaroon", {"inbound_slots": 483})
    start_gateway("sized.json")
    chan = lab.channels(SELLER)[0]
    listed = {k: chan[k]["max_accepted_htlcs"] for k in ("local_constraints", "remote_constraints")}
    measured("seller_channel", dict(listed, commitment_type=chan.get("commitment_type"), dust_limit_sat={k: chan[k]["dust_limit_sat"] for k in ("local_constraints", "remote_constraints")}))
    h = health()
    check(f"slots: a gateway given the channels macaroon takes half of its smallest channel as its cap: {HELD_CAP} of {SLOTS}, whatever its config assumed",
          h["maxHeld"] == HELD_CAP and min(int(v) for v in listed.values()) == SLOTS, {"max_held": h["maxHeld"], "node_lists": listed})
    # 15 payments that are no ticket of the gateway's are pending towards the seller (another program's invoices on
    # the same node): the channel is half full, and no held ticket is issued
    idle = lab.pending_htlcs(SELLER)
    others, _ = lab.lock(BUYER, SELLER, HELD_CAP, secs=60)
    b = Buyer()
    b.learn("/small.txt")
    refused, _ = b.ask(POOL)
    check("slots: with its inbound channel half full of payments it did not issue, the gateway issues no held ticket and says slots_short",
          (refused.status, refused.error()) == (402, "slots_short") and health()["heldTickets"] == 0 and lab.pending_htlcs(SELLER) - idle == HELD_CAP,
          {"http": refused.status, "error": refused.error(), "pending_towards_the_seller": lab.pending_htlcs(SELLER) - idle, "held_by_the_gateway": health()["heldTickets"]})
    secret, _ = b.buy_prepaid()
    check("slots: a prepaid ticket is sold all the same", b.release(secret).json()["released"] == [hashlib.sha256(secret).hexdigest()], b.status()["session"])
    lab.cancel_all(SELLER, others)
    lab.wait("the seller's channel to empty", 60, lambda: lab.pending_htlcs(SELLER) == idle, every=0.2)
    s = b.lock(POOL)
    check("slots: once the channel has room the same buyer holds its two tickets", len(s) == POOL and health()["heldTickets"] == POOL, health())
    b.call("cancel", {"hashes": "all"})
    stop("gateway")
    start_gateway()


CHECKS = {"terms": terms, "macaroons": macaroons, "fetch": fetch, "whole": whole, "latency": latency, "locked": locked, "margin": margin, "flood": flood, "paidfirst": paidfirst, "prepaid": prepaid,
          "slots": slots, "upstream": upstream, "restart": restart}


def main() -> int:
    args = sys.argv[1:]
    no_setup = "--no-setup" in args
    names = [a for a in args if a != "--no-setup"] or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        print(f"unknown checks: {', '.join(unknown)} (known: {', '.join(CHECKS)})", file=sys.stderr)
        return 2
    try:
        if no_setup:
            connect()
        else:
            setup()
        prepare()
        for n in names:
            print(f"--- {n}", flush=True)
            CHECKS[n]()
    except (LabError, OSError, http.client.HTTPException, KeyError, ValueError, subprocess.SubprocessError) as e:
        check("the run finished", False, f"{type(e).__name__}: {e}")
    finally:
        for name in list(PROCS):
            try:
                stop(name)
            except (OSError, subprocess.SubprocessError) as e:
                print(f"note: {name} did not stop cleanly: {e}", file=sys.stderr)
    REPORT["failed"] = FAILED
    with open(os.path.join(os.environ.get("OUT", RUN), "gateway_regtest.json"), "w") as f:
        json.dump(REPORT, f, indent=1, default=str)
    passed = sum(1 for c in REPORT["checks"] if c["ok"])
    print(f"gateway: {passed} passed, {len(FAILED)} failed" + ("" if not FAILED else ": " + "; ".join(FAILED)), flush=True)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
