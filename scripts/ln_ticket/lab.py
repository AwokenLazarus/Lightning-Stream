"""The stream-ticket regtest lab: docker compose, the chain node, the Lightning nodes' REST interface
and the ticket calls, for scripts/ln_ticket/drive.py.

A ticket is a hold invoice on the seller's node for a hash whose secret only the buyer knows
(docs/TICKETS.md). Everything a buyer or a seller does to one goes through the node's REST
interface, as a wallet or a seller component would do it:

    seller  POST /v2/invoices/hodl     {hash, value_msat, cltv_expiry, expiry}  -> a BOLT 11 invoice
    buyer   POST /v2/router/send       {payment_request, ...}                   -> the ticket is locked
    seller  GET  /v2/invoices/lookup   ?payment_hash=                           -> ACCEPTED
    seller  POST /v2/invoices/settle   {preimage}                               -> the seller is paid
    seller  POST /v2/invoices/cancel   {payment_hash}                           -> the buyer's funds are free
    buyer   GET  /v2/router/track/<h>                                           -> SUCCEEDED or FAILED

Setup (addresses, peers, opening channels) uses lncli inside the containers. Each node's own
tls.cert is the only certificate trusted for its connection.

Environment: LAB (the lightning-fork-lab checkout; COMPOSE_PROJECT_NAME and COMPOSE_FILE are the
caller's), RUN (a scratch directory for the certificates).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from typing import Any

LAB = os.environ["LAB"]
RUN = os.environ["RUN"]
NODES = ("lf1", "lf2", "lf3", "lf4")
PORT = {n: int(os.environ.get(f"LN_TICKET_PORT_{n.upper()}", 17790 + i)) for i, n in enumerate(NODES, start=1)}
MACAROON_PATH = "/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"
#: The rail macaroon of the agent wallet (crates/xbt-signer, rail=ln), and the least a seller needs.
BUYER_PERMISSIONS = ("info:read", "offchain:read", "offchain:write", "onchain:read")
SELLER_PERMISSIONS = ("invoices:read", "invoices:write")

_admin: dict[str, str] = {}
_ctx: dict[str, ssl.SSLContext] = {}
_local = threading.local()
_generation = 0  # raised when a node restarts: every kept connection is opened again
POOL = ThreadPoolExecutor(64)


class LabError(RuntimeError):
    pass


# --- docker compose, the chain node, lncli --------------------------------------------------------


def dc(*args: str, check: bool = True) -> str:
    r = subprocess.run(["docker", "compose", *args], cwd=LAB, capture_output=True, text=True, check=False)
    if check and r.returncode != 0:
        raise LabError(f"docker compose {' '.join(args)}: {r.stderr.strip()[:400]}")
    return r.stdout.strip()


def chain(*args: str) -> str:
    return dc("exec", "-T", "knots-b2b", "bitcoin-cli", "-datadir=/data", "-rpcuser=lab", "-rpcpassword=lab", *args)


def wallet(*args: str) -> str:
    return chain("-rpcwallet=lab", *args)


def height() -> int:
    return int(chain("getblockcount"))


def lncli(node: str, *args: str) -> Any:
    out = dc("exec", "-T", node, "lncli", "--network=regtest", "--rpcserver=127.0.0.1:10009", *args)
    return json.loads(out) if out.startswith(("{", "[")) else out


def wait(what: str, secs: float, fn: Callable[[], Any], every: float = 0.5) -> float:
    """Poll `fn` until it returns something true; the seconds it took. An exception counts as "not
    yet" (a node that is starting refuses connections), and the last one is named if time runs out."""
    t0 = time.monotonic()
    last: Exception | None = None
    while time.monotonic() - t0 < secs:
        try:
            if fn():
                return time.monotonic() - t0
        except (LabError, OSError, http.client.HTTPException, KeyError, ValueError) as e:
            last = e
        time.sleep(every)
    raise LabError(f"timed out after {secs:.0f} s waiting for {what}" + (f" (last error: {last})" if last else ""))


# --- REST -------------------------------------------------------------------------------------------


def forget_connections() -> None:
    global _generation
    _generation += 1


def load_credentials(node: str) -> None:
    """The node's admin macaroon and TLS certificate, read out of its container."""
    mac = subprocess.run(["docker", "compose", "exec", "-T", node, "cat", MACAROON_PATH], cwd=LAB, capture_output=True, check=False)
    if mac.returncode != 0 or not mac.stdout:
        raise LabError(f"{node} has no admin macaroon yet")
    _admin[node] = mac.stdout.hex()
    cert = f"{RUN}/{node}.tls.cert"
    with open(cert, "w") as f:
        f.write(dc("exec", "-T", node, "cat", "/root/.lnd/tls.cert") + "\n")
    ctx = ssl.create_default_context(cafile=cert)
    ctx.check_hostname = False  # the certificate is pinned; its names are the container's
    _ctx[node] = ctx


def _connect(node: str, timeout: float) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection("127.0.0.1", PORT[node], context=_ctx[node], timeout=timeout)


def _kept(node: str) -> tuple[http.client.HTTPSConnection, bool]:
    """This thread's kept-open connection to `node`, and whether it is a new one."""
    if getattr(_local, "generation", None) != _generation:
        _local.generation, _local.conns = _generation, {}
    fresh = node not in _local.conns
    if fresh:
        _local.conns[node] = _connect(node, 30)
    return _local.conns[node], fresh


def ask(node: str, method: str, path: str, body: dict[str, Any] | None = None, macaroon: str | None = None) -> dict[str, Any]:
    """One REST call on a kept-open connection; the node's answer, which for a refusal is {"code", "message"}.
    A kept connection the node has closed is opened again once; a new one that fails is an error."""
    data = None if body is None else json.dumps(body)
    headers = {"Grpc-Metadata-macaroon": macaroon or _admin[node]}
    for _ in range(2):
        conn, fresh = _kept(node)
        try:
            conn.request(method, path, body=data, headers=headers)
            reply = conn.getresponse().read()
            return json.loads(reply or b"{}")
        except (OSError, http.client.HTTPException):
            conn.close()
            del _local.conns[node]
            if fresh:
                raise
    raise LabError(f"{node} {method} {path}: the connection failed twice")


def answer(node: str, method: str, path: str, body: dict[str, Any] | None, macaroon: str | None) -> dict[str, Any]:
    """`ask`, for a call that must succeed: a refusal is an error here, never an empty result."""
    reply = ask(node, method, path, body, macaroon)
    if "code" in reply and "message" in reply:
        raise LabError(f"{node} {method} {path.split('?')[0]}: {reply['message']}")
    return reply


def get(node: str, path: str, macaroon: str | None = None) -> dict[str, Any]:
    return answer(node, "GET", path, None, macaroon)


def post(node: str, path: str, body: dict[str, Any], macaroon: str | None = None) -> dict[str, Any]:
    return answer(node, "POST", path, body, macaroon)


def stream(
    node: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    until: Callable[[dict[str, Any]], bool],
    macaroon: str | None = None,
    timeout: float = 120,
) -> dict[str, Any]:
    """A streaming call (one JSON object per line) on its own connection: the first update for which
    `until` is true, or the node's error. Closing the stream does not stop the payment on the node."""
    conn = _connect(node, timeout)
    try:
        conn.request(method, path, body=None if body is None else json.dumps(body), headers={"Grpc-Metadata-macaroon": macaroon or _admin[node]})
        r = conn.getresponse()
        while line := r.readline():
            j = json.loads(line)
            if "result" not in j:
                return j.get("error", j)
            if until(j["result"]):
                return j["result"]
        return {"code": -1, "message": "the stream ended"}
    finally:
        conn.close()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def url64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode()


def bake(node: str, permissions: Iterable[str]) -> str:
    perms = [dict(zip(("entity", "action"), p.split(":"))) for p in permissions]
    return post(node, "/v1/macaroon", {"permissions": perms})["macaroon"]


def refused(reply: dict[str, Any]) -> bool:
    return reply.get("message") == "permission denied"


# --- nodes and channels ---------------------------------------------------------------------------


def info(node: str) -> dict[str, Any]:
    return get(node, "/v1/getinfo")


def pubkey(node: str) -> str:
    return info(node)["identity_pubkey"]


def synced(node: str, at: int | None = None) -> bool:
    i = info(node)
    return bool(i.get("synced_to_chain")) and (at is None or int(i["block_height"]) >= at)


def mine(blocks: int, nodes: Iterable[str]) -> int:
    """Mine and wait until every node named has the new tip. Returns the height."""
    wallet("generatetoaddress", str(blocks), wallet("getnewaddress"))
    h = height()
    for n in nodes:
        wait(f"{n} at height {h}", 120, partial(synced, n, h), every=0.1)
    return h


def channels(node: str) -> list[dict[str, Any]]:
    return get(node, "/v1/channels")["channels"]


def channel(node: str, peer: str) -> dict[str, Any]:
    """`node`'s one open channel with `peer`."""
    pk = pubkey(peer)
    found = [c for c in channels(node) if c["remote_pubkey"] == pk]
    if len(found) != 1:
        raise LabError(f"{node} has {len(found)} channels with {peer}, expected 1")
    return found[0]


def pending_htlcs(node: str) -> int:
    return sum(len(c["pending_htlcs"]) for c in channels(node))


def wallet_sat(node: str) -> int:
    return int(get(node, "/v1/balance/blockchain")["total_balance"])


def known_channels(node: str) -> int:
    return int(get(node, "/v1/graph/info")["num_channels"])


def pending_channels(node: str) -> dict[str, Any]:
    return get(node, "/v1/channels/pending")


def fund(node: str, btc: str) -> None:
    wallet("sendtoaddress", lncli(node, "newaddress", "p2wkh")["address"], btc)


def open_channel(opener: str, peer: str, sats: int, push: int) -> None:
    pk = pubkey(peer)
    # unchecked: "already connected" is as good as connected, and the wait below fails if neither holds
    dc("exec", "-T", opener, "lncli", "--network=regtest", "--rpcserver=127.0.0.1:10009", "connect", f"{pk}@{peer}:9735", check=False)
    wait(f"{opener} connected to {peer}", 30, lambda: any(p["pub_key"] == pk for p in get(opener, "/v1/peers")["peers"]))
    lncli(opener, "openchannel", f"--node_key={pk}", f"--local_amt={sats}", f"--push_amt={push}")


def stop(node: str) -> None:
    dc("stop", node)
    forget_connections()


def start(node: str) -> float:
    """Start (or restart) a node; the seconds until it answers and is synced."""
    dc("restart", node)
    forget_connections()
    return wait(f"{node} back and synced", 120, lambda: synced(node), every=0.1)


# --- tickets ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Ticket:
    secret: bytes  # known to the buyer only, until it pays a request with it
    invoice: str  # the seller's BOLT 11 hold invoice for sha256(secret)

    @property
    def hash(self) -> bytes:
        return hashlib.sha256(self.secret).digest()


@dataclass(frozen=True)
class Payment:
    status: str  # IN_FLIGHT, SUCCEEDED, FAILED, or UNKNOWN (the node has no such payment)
    reason: str
    preimage: str
    fee_msat: int


def issue(seller: str, secrets: list[bytes], msat: int = 1_000_000, cltv: int = 40, macaroon: str | None = None, life_s: int = 3600) -> list[Ticket]:
    """The seller's half of a lock: one hold invoice per hash. It is given hashes, never secrets.
    `life_s` is how long the invoice may wait to be paid."""

    def one(secret: bytes) -> Ticket:
        body = {"hash": b64(hashlib.sha256(secret).digest()), "value_msat": str(msat), "cltv_expiry": str(cltv), "expiry": str(life_s)}
        return Ticket(secret, post(seller, "/v2/invoices/hodl", body, macaroon)["payment_request"])

    return list(POOL.map(one, secrets))


def pay(buyer: str, tickets: list[Ticket], macaroon: str | None = None, timeout_s: int = 30) -> list[dict[str, Any]]:
    """The buyer's half: pay each invoice. Returns each payment's first update (IN_FLIGHT, or
    FAILED at once)."""
    body: dict[str, Any] = {"timeout_seconds": timeout_s, "fee_limit_msat": "100000"}
    return list(
        POOL.map(
            lambda t: stream(
                buyer,
                "POST",
                "/v2/router/send",
                dict(body, payment_request=t.invoice),
                lambda u: u["status"] in ("IN_FLIGHT", "SUCCEEDED", "FAILED"),
                macaroon,
            ),
            tickets,
        )
    )


def state(seller: str, ticket: Ticket, macaroon: str | None = None) -> str:
    return get(seller, "/v2/invoices/lookup?payment_hash=" + url64(ticket.hash), macaroon)["state"]


def invoice(seller: str, ticket: Ticket) -> dict[str, Any]:
    return get(seller, "/v2/invoices/lookup?payment_hash=" + url64(ticket.hash))


def accepted(seller: str, tickets: list[Ticket], macaroon: str | None = None) -> int:
    """How many of `tickets` the seller's node holds as ACCEPTED (one listing call)."""
    ours = {b64(t.hash) for t in tickets}
    listing = get(seller, "/v1/invoices?pending_only=true&num_max_invoices=5000", macaroon)["invoices"]
    return sum(1 for i in listing if i["state"] == "ACCEPTED" and i["r_hash"] in ours)


def lock(
    buyer: str,
    seller: str,
    count: int,
    msat: int = 1_000_000,
    cltv: int = 40,
    buyer_macaroon: str | None = None,
    seller_macaroon: str | None = None,
    secs: float = 60,
) -> tuple[list[Ticket], float]:
    """Lock `count` tickets: hashes to the seller, invoices back, all paid, all ACCEPTED on the
    seller's node. Returns the tickets and the seconds from the first call to the last ACCEPTED."""
    secrets = [os.urandom(32) for _ in range(count)]
    t0 = time.perf_counter()
    tickets = issue(seller, secrets, msat, cltv, seller_macaroon)
    first = pay(buyer, tickets, buyer_macaroon)
    failed = [u for u in first if u.get("status") != "IN_FLIGHT"]
    if failed:
        raise LabError(f"{len(failed)} of {count} payments did not start: {json.dumps(failed[0])[:300]}")
    end = time.perf_counter() + secs
    while (have := accepted(seller, tickets, seller_macaroon)) < count:
        if time.perf_counter() > end:
            raise LabError(f"{have} of {count} tickets ACCEPTED on {seller} after {secs:.0f} s")
        time.sleep(0.01)
    return tickets, time.perf_counter() - t0


def settle(seller: str, ticket: Ticket, macaroon: str | None = None) -> dict[str, Any]:
    return post(seller, "/v2/invoices/settle", {"preimage": b64(ticket.secret)}, macaroon)


def cancel(seller: str, ticket: Ticket, macaroon: str | None = None) -> dict[str, Any]:
    return post(seller, "/v2/invoices/cancel", {"payment_hash": b64(ticket.hash)}, macaroon)


def cancel_all(seller: str, tickets: list[Ticket]) -> None:
    list(POOL.map(lambda t: cancel(seller, t), tickets))


def payment(buyer: str, ticket: Ticket, macaroon: str | None = None, final: bool = False) -> Payment:
    """The payment as the buyer's node has it now; with `final`, wait for SUCCEEDED or FAILED."""
    path = "/v2/router/track/" + url64(ticket.hash) + ("?no_inflight_updates=true" if final else "")
    u = stream(buyer, "GET", path, None, lambda u: True, macaroon)
    if "status" not in u:
        return Payment("UNKNOWN", str(u.get("message", u)), "", 0)
    return Payment(u["status"], u.get("failure_reason", ""), u.get("payment_preimage", ""), int(u.get("fee_msat", 0)))


def payments(buyer: str, tickets: list[Ticket]) -> list[Payment]:
    return list(POOL.map(lambda t: payment(buyer, t), tickets))


def tally(ps: Iterable[Payment]) -> dict[str, int]:
    out: dict[str, int] = {}
    for p in ps:
        key = p.status if p.status != "FAILED" else f"FAILED:{p.reason.removeprefix('FAILURE_REASON_')}"
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def spread(seconds: list[float]) -> dict[str, float]:
    """Median, 90th percentile and maximum of a list of durations, in milliseconds."""
    xs = sorted(seconds)
    return {
        "n": len(xs),
        "p50_ms": round(xs[len(xs) // 2] * 1e3, 2),
        "p90_ms": round(xs[min(len(xs) - 1, len(xs) * 9 // 10)] * 1e3, 2),
        "max_ms": round(xs[-1] * 1e3, 2),
    }


def tally_states(states: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in states:
        out[s] = out.get(s, 0) + 1
    return dict(sorted(out.items()))
