#!/usr/bin/env python3
"""The lottery, end to end on regtest: an agent's ordinary `xbt402_pay` call, through the shipped
binaries, to URLs behind seller gateways, paid by draws through a routing hop. docs/TICKETS.md,
section 9, is the wire.

    agent ---- xbt-wallet-mcp ---- xbt-signer ==== lf1 ---- lf2 ---- lf3 ==== xbt-gateway x 102 ---- file server
    (this file)   (MCP, stdio)    (the wallet)   buyer     hop     seller    (one a seller each)    (python3 -m http.server)

Run by scripts/lottery_regtest.sh, which builds the binaries and brings up the chain node. The
nodes, the channels (the buyer's and the seller's inbound one carry 30 pending payments each) and
the credentials are those of scripts/ticket_e2e/drive.py, whose helpers this file uses. What is
new here: the gateways offer the lottery; 100 of them stand for 100 sellers (they share the one
seller node, so the buyer's channel, the hop and the seller's inbound channel carry what 100
sellers' wins would, and the seller side is one node's worth of work); a buyer written in Python
(draw.py, the draw a second time) that sends values and never pays; and a proxy that makes one
gateway lie about wins.

  terms     the 402 lists the lottery entry beside the ticket entries; the MCP tool says what a
            call paid by draws can and cannot cause
  file      a 100 MB file priced at a quarter of a sat a piece, bought by draws, five times: every
            byte arrives, what the buyer's node paid is the wins the wallet booked, to the millisat,
            inside the luck cap; nothing is pending on the buyer's channel except while a win is in
            flight
  page      a page priced per request, 200 times: one draw each, the latency a draw adds
  swarm     20 sellers, then 100, paid at once by draws from the one 30-slot channel: no payment
            fails, at most 8 are with the router at once, and an ordinary payment over the same
            channel succeeds meanwhile
  cheat     a buyer that sends values and never pays a win, and one that sends no values: what
            each is served before it is cut off, measured over 30 sessions
  liar      a seller that claims a win for a draw that lost, sends an invoice for another payee,
            for another amount, and two invoices for one win: paid nothing for the lie, and the
            wallet's ledger is what its node paid
  kill      the signer, the gateway, the buyer's node and the seller's node each killed between
            two calls and again in the middle of a download with wins being paid: no win paid
            twice, none booked without being paid or paid without being booked, and the next call
            pays or says why not

Usage: drive.py [check ...]   (all checks, in the order above, when none is named)
Environment: as scripts/ticket_e2e/drive.py (LAB, RUN, OUT, BIN, TICKET_E2E_PORT_BASE), and
LOTTERY_SELLERS (100).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import math
import os
import signal
import statistics
import subprocess
import sys
import threading
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "ticket_e2e"))
import draw  # noqa: E402  (the draw, written a second time)
import drive as e2e  # noqa: E402  (the end-to-end ticket lab: the wallet, the MCP client, the nodes)
from drive import BIN, BUYER, HOP, NODES, OUT, PROCS, RUN, SELLER, LabError, Mcp, agent, brief, check, lab, measured, send, signer, status  # noqa: E402

BASE = e2e.BASE
GW_PORT, UP_PORT, GW2_PORT, PROXY_PORT = e2e.GW_PORT, e2e.UP_PORT, e2e.GW2_PORT, e2e.PROXY_PORT
ORIGIN, LIAR = e2e.ORIGIN, e2e.LIAR
SELLERS = int(os.environ.get("LOTTERY_SELLERS", "100"))
SWARM_PORT = BASE + 10  # the first of SELLERS gateways
PIECE = 65_536
WIN_MSAT = 64_000
BIG = 100_000_000
# a quarter of a sat for a piece of 64 KiB: 1,526 pieces, 381,470 msat for the file, 1 win in 256 pieces
BIG_BYTE_MSAT = 250
# the swarm's file: 64 pieces of 1 sat, so one win expected from each seller in each call
MID = 64 * PIECE
MID_BYTE_MSAT = 1_000
# for the cheat, the liar and the kills: a piece of 16 sat, so that one piece in four wins. A call on it may use
# 3,900 sat: below four tickets' worth, so the wallet's rule pays it by draws, and it stops there by its own count
HOT_BYTE_MSAT = 16_000
HOT_MAX_SATS = 3_900
PAGE_MSAT = 2_500
#: Payments on the buyer's node that are not the wallet's (the ordinary payment of the swarm check), by hash.
FOREIGN: set[str] = set()
#: Every session a call of this run was paid in.
SESSIONS: set[str] = set()


def swarm_origin(i: int) -> str:
    return f"http://127.0.0.1:{SWARM_PORT + i}"


# --- the wallet and the sellers -----------------------------------------------------------------------------


class Wallet(e2e.Wallet):
    def policy(self) -> dict[str, Any]:
        pk = lab.pubkey(SELLER)
        origins = [ORIGIN, LIAR] + [swarm_origin(i) for i in range(SELLERS)]
        return {
            # every origin is the one seller node's: 102 services beside one node
            "allowlist": origins,
            "counterparties": {o: {"ln_node": pk} for o in origins},
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
            "ln": {"enabled": True, "split_height": e2e.SPLIT},
            # the lottery as shipped (wins of 64 sat through a hop, 1 in 4 at the most, 8 values ahead). What the owner
            # raised: the sellers a task may pay at once, and how many may be new in a minute
            "tickets": {"enabled": True, "max_sellers": SELLERS + 8, "max_new_sellers_per_min": 4 * SELLERS, "max_sends_per_hour": 100_000, "max_answer_s": 120,
                        "tasks": {"film": {"budget_sats": 3_000_000, "max_sellers": SELLERS + 8}}},
        }


def gateway_config(name: str, port: int, public: str, tick_ms: int = 500, idle: int = 300) -> str:
    cfg = {
        "listen": f"127.0.0.1:{port}",
        "public_url": public,
        "upstream": f"http://127.0.0.1:{UP_PORT}",
        "state_dir": f"{RUN}/state-{name}",
        "chain": "regtest",
        "network": e2e.NETWORK[0],
        "node": {"rest": f"https://127.0.0.1:{lab.PORT[SELLER]}", "tls_cert": f"{RUN}/{SELLER}.tls.cert", "macaroon": f"{RUN}/invoices.macaroon",
                 "info_macaroon": f"{RUN}/info.macaroon"},
        "caps": {"sessions_per_address": 0},
        # the lottery as the gateway ships it, but for the piece size and the cap on sessions from one address (every
        # buyer of this lab comes from 127.0.0.1)
        "lottery": {"piece_bytes": PIECE, "sessions_per_address": 0, "idle_secs": idle},
        "times": {"height_max_age_secs": 30, "tick_ms": tick_ms},
        "routes": [
            {"path": "/big.bin", "price": {"byte_msat": BIG_BYTE_MSAT, "per_bytes": PIECE}},
            {"path": "/mid.bin", "price": {"byte_msat": MID_BYTE_MSAT, "per_bytes": PIECE}},
            {"path": "/hot.bin", "price": {"byte_msat": HOT_BYTE_MSAT, "per_bytes": PIECE}},
            {"path": "/small.txt", "price": {"request_msat": PAGE_MSAT}},
            {"path": "/free/", "free": True},
        ],
    }
    path = f"{RUN}/{name}.json"
    with open(path, "w") as f:
        json.dump(cfg, f, indent=1)
    return path


def start_gateway(name: str, port: int) -> None:
    with open(f"{RUN}/{name}.log", "ab") as log:
        PROCS[name] = subprocess.Popen([f"{BIN}/xbt-gateway", f"{RUN}/{name}.json"], stdout=log, stderr=log)


def gateway_up(port: int) -> bool:
    try:
        return json.loads(send("GET", "/x402/ticket/health", port)[2])["height"] is not None
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        return False


def health(port: int = GW_PORT) -> dict[str, Any]:
    return json.loads(send("GET", "/x402/ticket/health", port)[2])["lottery"]


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
    e2e.send_pinned(lab.lncli(BUYER, "newaddress", "p2wkh")["address"], "0.2")
    lab.fund(HOP, "0.2")
    lab.mine(6, NODES)
    for node in (BUYER, HOP):
        lab.wait(f"{node}'s coin", 60, partial(lab.wallet_sat, node))
    e2e.open_channel(BUYER, HOP, 5_000_000)
    e2e.open_channel(HOP, SELLER, 5_000_000)
    lab.mine(8, NODES)
    for node, count in ((BUYER, 1), (HOP, 2), (SELLER, 1)):
        lab.wait(f"{node}'s channels active", 240, partial(e2e.active, node, count))
    lab.wait("the buyer knows both channels", 300, lambda: lab.known_channels(BUYER) >= 2, every=2)
    slots = {n: min(int(c[k]["max_accepted_htlcs"]) for c in lab.channels(n) for k in ("local_constraints", "remote_constraints")) for n in (BUYER, SELLER)}
    check("setup: the buyer's channel and the seller's inbound channel carry 30 pending payments", slots == {BUYER: 30, SELLER: 30}, slots)
    os.makedirs(f"{RUN}/keys", exist_ok=True)
    with open(f"{RUN}/rpc.cookie", "w") as f:
        f.write("lab:lab")
    for name, node, perms in (("rail", BUYER, lab.BUYER_PERMISSIONS), ("invoices", SELLER, lab.SELLER_PERMISSIONS), ("info", SELLER, ("info:read",))):
        with open(f"{RUN}/{name}.macaroon", "wb") as f:
            f.write(bytes.fromhex(lab.bake(node, perms)))
        os.chmod(f"{RUN}/{name}.macaroon", 0o600)
    e2e.NETWORK[0] = "lightning:" + lab.chain("getblockhash", "101")[:32]
    # the service: a stock file server; every piece of each file differs
    os.makedirs(f"{RUN}/www/free", exist_ok=True)
    block = os.urandom(1 << 20)
    for name, size in (("big.bin", BIG), ("hot.bin", BIG), ("mid.bin", MID)):
        with open(f"{RUN}/www/{name}", "wb") as f:
            f.writelines((hashlib.sha256(block[:64] + i.to_bytes(8, "big")).digest() + block)[: min(len(block), size - i)] for i in range(0, size, len(block)))
    for name in ("small.txt", "free/small.txt"):
        with open(f"{RUN}/www/{name}", "w") as f:
            f.write(e2e.PAGE)
    with open(f"{RUN}/upstream.log", "ab") as log:
        PROCS["upstream"] = subprocess.Popen([sys.executable, "-m", "http.server", str(UP_PORT), "--bind", "127.0.0.1", "--directory", f"{RUN}/www"], stdout=log, stderr=log)
    lab.wait("the file server", 20, lambda: send("GET", "/small.txt", UP_PORT)[0] == 200, every=0.1)
    # the sellers: the one the file is bought from, the one behind the lying proxy, and the swarm (a slower janitor
    # each, since 100 of them ask the one node for its height)
    gateway_config("gateway", GW_PORT, ORIGIN)
    gateway_config("gateway2", GW2_PORT, LIAR)
    for name, port in (("gateway", GW_PORT), ("gateway2", GW2_PORT)):
        start_gateway(name, port)
    for i in range(SELLERS):
        gateway_config(f"swarm{i}", SWARM_PORT + i, swarm_origin(i), tick_ms=5000)
        start_gateway(f"swarm{i}", SWARM_PORT + i)
    lab.wait("every gateway", 120, lambda: all(gateway_up(p) for p in [GW_PORT, GW2_PORT] + [SWARM_PORT + i for i in range(SELLERS)]), every=0.5)
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), Proxy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    e2e.WALLET_PROC = Wallet()
    e2e.WALLET_PROC.write_policy()
    e2e.WALLET_PROC.start()
    st = signer("ln_status")
    check("setup: the Lightning rail is ready on lf1: chain verified, its one channel's funding proven", st.get("ready") is True, {"ready": st.get("ready"), "warnings": st.get("warnings")})


# --- what the agent does, and what the nodes then say --------------------------------------------------------


def pay(url: str, max_sats: int, who: Mcp | None = None) -> dict[str, Any]:
    """The agent's call: one tool, one URL."""
    r = (who or agent()).tool("xbt402_pay", {"url": url, "max_sats": max_sats, "task": "film"})
    if r.get("session"):
        SESSIONS.add(r["session"])
    return r


def ok_draws(r: dict[str, Any]) -> bool:
    return r.get("verdict") == "allow" and r.get("rail") == "lottery" and r.get("status") == 200


def luck_cap_sats(max_sats: int) -> int:
    return draw.luck_cap_msat(max_sats * 1000, WIN_MSAT) // 1000


def money() -> dict[str, Any]:
    """The counts that must be one: what the buyer's node paid, what the seller's node received, what
    the wallet's book holds as settled wins, and what the wallet's ledger holds (each win and its fee)."""
    pays = {h: p for h, p in e2e.buyer_payments().items() if h not in FOREIGN}
    done = [p for p in pays.values() if p["status"] == "SUCCEEDED"]
    invs = [i for h, i in e2e.seller_invoices().items() if i["state"] == "SETTLED" and h not in FOREIGN]
    st = status()
    rows = e2e.WALLET_PROC.ledger()
    return {
        "buyer_node_paid_msat": sum(int(p["value_msat"]) for p in done),
        "seller_node_received_msat": sum(int(i["amt_paid_msat"]) for i in invs),
        "wallet_book_settled": st["tickets"].get("settled", 0),
        "wallet_ledger_sats": sum(int(r["amount_sats"]) for r in rows),
        "buyer_node_cost_sats": sum(e2e.cost_sats(p) for p in done),
        "fees_msat": sum(int(p["fee_msat"]) for p in done),
        "payments": len(done),
        "failed_payments": sum(1 for p in pays.values() if p["status"] == "FAILED"),
        "in_flight": sum(1 for p in pays.values() if p["status"] == "IN_FLIGHT"),
        "booked_not_settled_sats": int(st.get("booked_sats") or 0),
        "node_agrees": (st.get("node") or {}).get("agree"),
    }


def orphans() -> set[str]:
    """Payments the buyer's node calls in flight with nothing on its channel. A node that is killed
    in the instant it sends a payment can go on saying so, also after a restart (docs/LIMITS.md):
    such a payment moved no money and holds no slot, and the wallet keeps it booked until its node
    drops it."""
    on_channel = {base64.b64decode(h["hash_lock"]).hex() for c in lab.channels(BUYER) for h in c["pending_htlcs"]}
    return {h for h, p in e2e.buyer_payments().items() if p["status"] == "IN_FLIGHT" and h not in on_channel and h not in FOREIGN}


def agrees(m: dict[str, Any]) -> bool:
    """To the millisat: the buyer's node paid what the seller's node received; every payment is a
    settled win in the wallet's book; and the ledger is each payment's amount and fee, with nothing
    booked that the node has not paid, but for a payment the node itself left in flight with
    nothing on its channel."""
    left = orphans()
    return (m["buyer_node_paid_msat"] == m["seller_node_received_msat"] and m["wallet_book_settled"] == m["payments"]
            and m["wallet_ledger_sats"] == m["buyer_node_cost_sats"] + m["booked_not_settled_sats"] and m["in_flight"] == len(left)
            and (m["booked_not_settled_sats"] == 0) == (not left) and m["booked_not_settled_sats"] <= 80 * len(left))


def once() -> dict[str, Any]:
    """Nothing the seller took that the wallet has not booked, nothing booked that was not paid, and
    nothing paid twice: the invoices the seller's node settled, the payments the buyer's node made
    and the wallet's ledger rows are the same hashes; and no draw of a session has two payments."""
    rows = {r["txid"] for r in e2e.WALLET_PROC.ledger()}
    settled = {h for h, i in e2e.seller_invoices().items() if i["state"] == "SETTLED"} - FOREIGN
    paid = {h for h, p in e2e.buyer_payments().items() if p["status"] == "SUCCEEDED"} - FOREIGN
    twice = []
    for sid in sorted(SESSIONS):
        wins = [t["win"] for t in status(sid).get("session_tickets", []) if t.get("win") and t["state"] != "failed"]
        if len(wins) != len(set(wins)):
            twice.append(sid)
    return {"settled_on_seller": len(settled), "paid_on_buyer": len(paid), "same_hashes": settled == paid, "paid_not_booked": sorted(h for h in paid if f"ticket:{h}" not in rows)[:3],
            "booked_not_paid": sorted(t for t in rows if t.startswith("ticket:") and t[7:] not in paid and t[7:] not in orphans())[:3], "a_win_paid_twice": twice,
            "payments_the_node_left_in_flight_with_nothing_on_its_channel": len(orphans())}


def stop_sessions() -> None:
    for s in status().get("sessions", []):
        if s["state"] == "open":
            agent().tool("ticket_stop", {"session": s["session"]})


def quiet(secs: float = 60) -> None:
    """Nothing pending on the buyer's channel and nothing booked that is not settled."""
    lab.wait("nothing pending on the buyer's channel", secs, lambda: lab.pending_htlcs(BUYER) == 0 and int(status().get("booked_sats") or 0) == 0, every=0.25)


class Sampler:
    """The payments pending on the buyer's channel, asked every 20 ms while something runs: how many,
    and which (by payment hash)."""

    def __init__(self) -> None:
        self.samples: list[int] = []
        self.hashes: set[str] = set()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                pending = [base64.b64decode(h["hash_lock"]).hex() for c in lab.channels(BUYER) for h in c["pending_htlcs"]]
                self.samples.append(len(pending))
                self.hashes.update(pending)
            except (LabError, OSError, http.client.HTTPException):
                pass
            time.sleep(0.02)

    def __enter__(self) -> "Sampler":
        self.thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop.set()
        self.thread.join(5)

    def report(self) -> dict[str, Any]:
        """What was pending, and whether all of it was a win on its way: every payment that was ever
        seen pending is one the buyer's node made for exactly one win and that succeeded."""
        n = max(len(self.samples), 1)
        pays = e2e.buyer_payments()
        wins = {h for h, p in pays.items() if p["status"] == "SUCCEEDED" and int(p["value_msat"]) == WIN_MSAT}
        return {"samples": len(self.samples), "nothing_pending_share": round(sum(1 for x in self.samples if x == 0) / n, 3), "most_pending": max(self.samples or [0]),
                "payments_seen_pending": len(self.hashes), "not_a_win_in_flight": sorted(self.hashes - wins - FOREIGN)[:3]}


def in_flight_ms(since: set[str]) -> dict[str, Any]:
    """How long each win of the wallet's was in flight on the buyer's node, from the payment's
    creation to the settle of its HTLC, for the payments not in `since`."""
    took = []
    for h, p in e2e.buyer_payments().items():
        if h in since or h in FOREIGN or p["status"] != "SUCCEEDED":
            continue
        done = max((int(x.get("resolve_time_ns") or 0) for x in p.get("htlcs", [])), default=0)
        if done:
            took.append((done - int(p["creation_time_ns"])) / 1e6)
    took.sort()
    if not took:
        return {"payments": 0}
    return {"payments": len(took), "median": round(statistics.median(took)), "p90": round(took[int(0.9 * (len(took) - 1))]), "longest": round(took[-1])}


# --- the checks -----------------------------------------------------------------------------------------------


def terms() -> None:
    status_code, headers, _ = send("GET", "/big.bin", GW_PORT)
    pr = json.loads(base64.b64decode(headers["payment-required"]))
    schemes = [a["scheme"] for a in pr["accepts"]]
    entry = pr["accepts"][-1]
    x = entry.get("extra", {})
    check("terms: the 402 lists held tickets, prepaid tickets and, last, the lottery: a win of 64 sat (16 at the least), paid after it by an invoice, the window of 8, the grace of 30 s and 64 pieces, and the piece size",
          status_code == 402 and schemes == ["ticket", "ticket", "lottery"] and entry["payTo"] == lab.pubkey(SELLER)
          and (x.get("winMsat"), x.get("minWinMsat"), x.get("pay"), x.get("window"), x.get("graceSeconds"), x.get("gracePieces"), x.get("maxUnpaidWins"), x.get("pieceBytes"))
          == ("64000", "16000", "on-win", 8, 30, 64, 2, str(PIECE)),
          {"schemes": schemes, "lottery": {k: x.get(k) for k in ("winMsat", "minWinMsat", "pay", "release", "window", "graceSeconds", "gracePieces", "maxUnpaidWins", "chainDraws", "pieceBytes")}})
    tools = {t["name"]: t for t in agent().tools()}
    desc = tools["xbt402_pay"]["description"]
    check("terms: the MCP's xbt402_pay says a call may be paid by draws, that what it pays is uneven, and what such a call cannot cause",
          all(w in desc for w in ("pays by draws", "cannot make the wallet pay for a draw that did not win", "uneven")), [w for w in ("pays by draws", "uneven") if w in desc])


def file() -> None:
    url = f"{ORIGIN}/big.bin"
    with open(f"{RUN}/www/big.bin", "rb") as f:
        want = hashlib.sha256(f.read()).hexdigest()
    pieces = math.ceil(BIG / PIECE)
    price_msat = math.ceil(BIG * BIG_BYTE_MSAT / PIECE)
    max_sats = 800
    cap = luck_cap_sats(max_sats)
    before = money()
    paid_already = set(e2e.buyer_payments())
    runs = []
    with Sampler() as sampler:
        for _ in range(5):
            t0 = time.monotonic()
            r = pay(url, max_sats)
            secs = time.monotonic() - t0
            if r.get("saved_to"):
                os.remove(r["saved_to"])
            runs.append({"ok": ok_draws(r) and r.get("complete") is True and r.get("bytes") == BIG and r.get("body_digest") == want, "draws": r.get("draws"),
                         "price_msat": r.get("price_msat"), "wins": r.get("wins"), "wins_paid": r.get("wins_paid"), "charged_sats": r.get("charged_sats"),
                         "fee_msat": r.get("fee_msat"), "seconds": round(secs, 2), "ended": r.get("ended"), "unpaid": r.get("wins_unpaid")})
    quiet()
    m = money()
    wins = sum(int(x["wins"] or 0) for x in runs)
    paid_msat = m["buyer_node_paid_msat"] - before["buyer_node_paid_msat"]
    check("file: a 100 MB file priced at a quarter of a sat a piece arrives whole, five times, bought by draws: 1,526 pieces and as many draws each time, and a price that is the pieces' own",
          all(x["ok"] and x["draws"] == pieces and x["price_msat"] == str(price_msat) for x in runs), runs)
    check("file: what the buyer's node paid is the wins the wallet found and booked, to the millisat: each win 64,000 msat, each paid once, and the ledger is each win and its routing fee",
          agrees(m) and paid_msat == wins * WIN_MSAT and all(x["wins"] == x["wins_paid"] and not x["unpaid"] for x in runs) and m["failed_payments"] == before["failed_payments"],
          {"wins": wins, "paid_msat": paid_msat, "expected_wins": round(5 * price_msat / WIN_MSAT, 1), **m})
    check(f"file: each download paid inside its band: at most the luck cap of a call of max_sats {max_sats} ({cap} sat), whatever the draws did",
          all(int(x["charged_sats"] or 0) <= cap * 1.02 for x in runs), [x["charged_sats"] for x in runs])
    s = sampler.report()
    check("file: nothing is held between wins: everything that was ever pending on the buyer's channel was a win on its way, never more than 8 at once, and nothing was pending when the downloads were over",
          s["most_pending"] <= 8 and not s["not_a_win_in_flight"] and s["payments_seen_pending"] <= wins and lab.pending_htlcs(BUYER) == 0 and e2e.held() == 0, s)
    measured("file_win_in_flight_ms", in_flight_ms(paid_already))
    measured("file_download_s", [x["seconds"] for x in runs])
    measured("file_price_sats", round(price_msat / 1000, 1))
    measured("file_paid_sats_each", [x["charged_sats"] for x in runs])
    measured("file_wins_each", [x["wins"] for x in runs])
    measured("file_pending_on_buyer_channel", s)
    stop_sessions()


def page() -> None:
    url = f"{ORIGIN}/small.txt"
    free, paid, wins = [], [], 0
    first = pay(url, 10)
    for _ in range(200):
        t0 = time.monotonic()
        r = agent().tool("xbt402_pay", {"url": f"{ORIGIN}/free/small.txt", "max_sats": 10, "task": "film"})
        free.append(time.monotonic() - t0)
        t0 = time.monotonic()
        r = pay(url, 10)
        took = time.monotonic() - t0
        if not ok_draws(r) or r.get("draws") != 1 or e2e.body_of(r) != e2e.PAGE:
            raise LabError(f"a page: {brief(r)}")
        wins += int(r["wins"])
        # a call in which a win was paid waits for that payment: counted apart
        if not r["wins"]:
            paid.append(took)
    quiet()
    m = money()
    check("page: a page priced at 2.5 sat a request is one draw a request, 200 times, in one session; a win is paid before its call returns",
          ok_draws(first) and agrees(m) and len(paid) + wins >= 200, {"wins": wins, "expected_wins": round(200 * PAGE_MSAT / WIN_MSAT, 1), "calls_without_a_win": len(paid)})
    measured("page_free_ms_median", round(statistics.median(free) * 1000, 2))
    measured("page_by_draw_ms_median", round(statistics.median(paid) * 1000, 2))
    measured("page_draw_adds_ms", round((statistics.median(paid) - statistics.median(free)) * 1000, 2))
    stop_sessions()


def swarm_of(n: int) -> None:
    agents = [Mcp() for _ in range(n)]
    try:
        before = money()
        results: list[dict[str, Any]] = [{} for _ in range(n)]
        ordinary: dict[str, Any] = {}

        def one(i: int, rounds: int) -> None:
            got = {"wins": 0, "wins_paid": 0, "draws": 0, "bad": []}
            for _ in range(rounds):
                try:
                    r = pay(f"{swarm_origin(i)}/mid.bin", 200, who=agents[i])
                except (LabError, OSError, ValueError) as e:
                    got["bad"].append(str(e)[:160])
                    continue
                if not (ok_draws(r) and r.get("complete") is True and r.get("bytes") == MID and not r.get("wins_unpaid")):
                    got["bad"].append(brief(r))
                for k in ("wins", "wins_paid", "draws"):
                    got[k] += int(r.get(k) or 0)
            results[i] = got

        def ordinary_payment() -> None:
            # someone else's payment over the same channel while the swarm is being paid: 5,000 sat to the seller's node
            time.sleep(1.0)
            made = lab.post(SELLER, "/v1/invoices", {"value": "5000"})
            inv, h = made["payment_request"], base64.b64decode(made["r_hash"]).hex()
            FOREIGN.add(h)
            t0 = time.monotonic()
            lab.pay_invoice(BUYER, inv, 30)
            lab.wait("the ordinary payment", 30, lambda: e2e.seller_invoices().get(h, {}).get("state") == "SETTLED", every=0.1)
            ordinary.update({"paid": True, "seconds": round(time.monotonic() - t0, 2)})

        rounds = 3
        paid_already = set(e2e.buyer_payments())
        t0 = time.monotonic()
        with Sampler() as sampler:
            threads = [threading.Thread(target=one, args=(i, rounds)) for i in range(n)] + [threading.Thread(target=ordinary_payment)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(600)
        secs = time.monotonic() - t0
        quiet(120)
        m = money()
        wins = sum(r.get("wins", 0) for r in results)
        bad = [b for r in results for b in r.get("bad", ["no result"])]
        s = sampler.report()
        paid_msat = m["buyer_node_paid_msat"] - before["buyer_node_paid_msat"]
        sessions = sum(1 for x in status().get("sessions", []) if x["state"] == "open" and x.get("draws"))
        check(f"swarm: {n} sellers paid at once by draws from one 30-slot channel, {rounds} files of 64 pieces from each: every file whole, every win paid, no payment failed",
              not bad and m["failed_payments"] == before["failed_payments"] and sum(r.get("wins_paid", 0) for r in results) == wins and paid_msat == wins * WIN_MSAT
              and sum(r.get("draws", 0) for r in results) == n * rounds * 64,
              {"sellers": n, "sessions_open": sessions, "wins": wins, "expected_wins": n * rounds, "paid_msat": paid_msat, "failed_payments": m["failed_payments"] - before["failed_payments"],
               "seconds": round(secs, 1), "bad": bad[:3]})
        check(f"swarm: with {n} sellers the wallet never had more than 8 payments on its channel at once (30 slots), held nothing between wins, and an ordinary payment over that channel succeeded meanwhile",
              s["most_pending"] <= 9 and not s["not_a_win_in_flight"] and ordinary.get("paid") is True and lab.pending_htlcs(BUYER) == 0 and e2e.held() == 0,
              {**s, "ordinary_payment": ordinary})
        check(f"swarm: after {n} sellers the buyer's node, the seller's node, the wallet's book and its ledger agree to the millisat", agrees(m) and paid_msat == wins * WIN_MSAT, m)
        measured(f"swarm{n}_seconds", round(secs, 1))
        measured(f"swarm{n}_wins", wins)
        measured(f"swarm{n}_pending_on_buyer_channel", s)
        measured(f"swarm{n}_win_in_flight_ms", in_flight_ms(paid_already))
    finally:
        stop_sessions()
        for a in agents:
            a.close()


def swarm() -> None:
    swarm_of(min(20, SELLERS))
    if SELLERS > 20:
        swarm_of(SELLERS)


# --- a buyer written a second time: it speaks the wire, checks every reveal, and does not pay ----------------


class Cheat:
    """A buyer on the wire of docs/TICKETS.md, section 9, with draw.py's draw. It gives a value for
    every piece it received, checks every reveal and works out every draw; it pays no win."""

    def __init__(self, port: int = GW_PORT, origin: str = ORIGIN) -> None:
        self.port, self.origin = port, origin
        status_code, _, body = send("POST", "/x402/lottery/open", port, {"Content-Type": "application/json"}, json.dumps({"version": "lottery/0"}).encode())
        if status_code != 200:
            raise LabError(f"open: {status_code} {body[:100]!r}")
        o = json.loads(body)
        self.sid, self.key, self.win = o["session"], bytes.fromhex(o["key"]), int(o["winMsat"])
        self.view = draw.BuyerView(bytes.fromhex(o["anchor"]))
        self.seq, self.draws, self.wins, self.agree = 0, 0, 0, True
        self.accepted = {"scheme": "lottery", "network": e2e.NETWORK[0]}

    def header(self, method: str, target: str, body: bytes) -> tuple[dict[str, str], str]:
        req = request_digest(method, self.origin, target, body)
        auth = draw.request_auth(self.key, self.sid, self.seq, req)
        payload = {"x402Version": 2, "accepted": self.accepted, "payload": {"session": self.sid, "seq": self.seq, "auth": auth}}
        self.seq += 1
        return {"PAYMENT-SIGNATURE": base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()}, req

    def value(self, seq: int, req: str, kind: str, k: int, amount: int) -> dict[str, Any]:
        """Give a value for one piece; the seller's answer. Checks the reveal and the seller's wins."""
        self.draws += 1
        v = os.urandom(32)
        body = json.dumps({"values": [{"draw": self.draws, "seq": seq, "kind": kind, "k": k, "amountMsat": str(amount), "value": v.hex()}]}).encode()
        headers, _ = self.header("POST", "/x402/lottery/draw", body)
        status_code, _, raw = send("POST", "/x402/lottery/draw", self.port, {**headers, "Content-Type": "application/json"}, body)
        a = json.loads(raw)
        if status_code != 200 or a.get("refused"):
            raise LabError(f"draw {self.draws}: {status_code} {a.get('refused') or a.get('error')}")
        chain = self.view.accept(bytes.fromhex(a["reveal"]), a["drawn"])
        if chain is None:
            raise LabError("the seller's reveal is not on its chain")
        p = draw.piece_digest(seq, bytes.fromhex(req), kind, k, amount, self.win)
        won = draw.wins(draw.draw_digest(self.sid, self.draws, chain[-1], v, p), amount, self.win)
        self.wins += won
        listed = {w["draw"] for w in a.get("wins", [])}
        # the seller lists a draw as an unpaid win exactly when this buyer's own draw says it won
        self.agree = self.agree and ((self.draws in listed) == won)
        return a

    def fetch(self, target: str, piece_msat: int, give_values: bool) -> dict[str, Any]:
        """Fetch a body priced per piece, giving values as pieces arrive (or none), and never paying.
        What arrived before the seller stopped."""
        headers, req = self.header("GET", target, b"")
        seq = self.seq - 1
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        got, k = 0, 0
        try:
            conn.request("GET", target, headers=headers)
            r = conn.getresponse()
            if r.status != 200:
                return {"status": r.status, "error": json.loads(r.read() or b"{}").get("error"), "bytes": 0}
            while True:
                try:
                    chunk = r.read(PIECE - got % PIECE)
                except (http.client.IncompleteRead, OSError) as e:
                    chunk = getattr(e, "partial", b"")
                if not chunk:
                    break
                got += len(chunk)
                if give_values and got % PIECE == 0:
                    self.value(seq, req, "bytes", k, piece_msat)
                    k += 1
        finally:
            conn.close()
        return {"status": 200, "bytes": got}


def request_digest(method: str, origin: str, target: str, body: bytes) -> str:
    host, port = origin.split("//")[1].split(":")
    t = hashlib.sha256(b"xbt402/req/v2").digest()
    h = hashlib.sha256(t + t)
    for f in (method.encode(), b"http", host.encode(), port.encode(), target.encode(), body):
        h.update(len(f).to_bytes(8, "little") + f)
    return h.hexdigest()


def free_service(target: str, piece_msat: int) -> tuple[float, int, bool]:
    """One session of a buyer that gives values and never pays: what it was served before the seller
    stopped it, in units of one win; the wins it left unpaid; and whether the seller's wins were
    the ones this buyer's own draw worked out and its next request was refused `win_unpaid`."""
    c = Cheat()
    total = 0
    for _ in range(40):
        got = c.fetch(target, piece_msat, give_values=True)
        total += got["bytes"]
        if got.get("error") or got["bytes"] < BIG:
            break
    refused = c.fetch(target, piece_msat, give_values=True)
    return total // PIECE * piece_msat / c.win, c.wins, c.agree and refused.get("error") == "win_unpaid"


def cheat() -> None:
    before = health()
    piece_msat = HOT_BYTE_MSAT  # a piece of 16 sat on a win of 64: one in four wins, so a cheat is found out soon
    # no values at all: the window, and then nothing
    quiet_buyer = Cheat()
    got = quiet_buyer.fetch("/hot.bin", piece_msat, give_values=False)
    again = quiet_buyer.fetch("/hot.bin", piece_msat, give_values=False)
    check("cheat: a buyer that sends no values is served the window (8 pieces) and no more: its answer is cut, and its next request is refused value_missing",
          got["bytes"] == 8 * PIECE and again.get("error") == "value_missing", {"first": got, "then": again})
    # values, and no payment, where one piece in four wins: served until a third win is unpaid (the seller bears two)
    runs = [free_service("/hot.bin", piece_msat) for _ in range(20)]
    after = health()
    served = sorted(r[0] for r in runs)
    check("cheat: a buyer that gives values and never pays a win is cut off: its next request is refused win_unpaid, the seller's node was paid nothing, and the seller's wins are exactly the ones a second implementation of the draw works out",
          all(r[2] for r in runs) and after["paidWins"] == before["paidWins"], {"sessions": len(runs), "wins_unpaid_each_mean": round(statistics.mean(r[1] for r in runs), 2)})
    measured("cheat_free_service_in_wins_at_a_quarter_win_a_piece", {"mean": round(statistics.mean(served), 2), "median": round(statistics.median(served), 2), "most": round(served[-1], 2),
                                                                    "sessions": len(runs), "note": "pieces of 16 sat on wins of 64 sat: the seller stops at the third unpaid win"})
    # at a torrent's price: pieces of a quarter of a sat. Served up to the first win, and the grace of 64 pieces after it
    runs = [free_service("/big.bin", BIG_BYTE_MSAT) for _ in range(10)]
    cheap = sorted(r[0] for r in runs)
    measured("cheat_free_service_in_wins_at_a_quarter_sat_a_piece", {"mean": round(statistics.mean(cheap), 2), "median": round(statistics.median(cheap), 2), "most": round(cheap[-1], 2),
                                                                    "sessions": len(runs), "wins_unpaid_each_mean": round(statistics.mean(r[1] for r in runs), 2),
                                                                    "note": "what a buyer that never pays was served before it was stopped, in units of one win (64 sat)"})
    check("cheat: at a quarter of a sat a piece a buyer that never pays is served about one win's worth and the grace of 64 pieces (a quarter of a win) before it is stopped",
          all(r[2] for r in runs) and statistics.mean(cheap) < 4, {"mean_wins_worth": round(statistics.mean(cheap), 2), "each": [round(x, 2) for x in cheap]})


# --- a seller that lies: a proxy in front of the second gateway ----------------------------------------------


class Lies:
    mode = ""
    done = 0
    extra: dict[int, str] = {}


def lie_draw(raw: bytes) -> bytes:
    a = json.loads(raw)
    wins = a.get("wins") or []
    if Lies.mode == "false_win" and not wins and a.get("drawn") and not Lies.done:
        # a real invoice of the seller's own node for the win size, for a draw that lost
        inv = lab.post(SELLER, "/v1/invoices", {"value_msat": str(WIN_MSAT), "expiry": "60", "cltv_expiry": "40"})["payment_request"]
        a["wins"] = [{"draw": a["drawn"], "invoice": inv}]
        Lies.done += 1
    elif Lies.mode in ("other_payee", "other_amount") and wins:
        node, msat = (HOP, WIN_MSAT) if Lies.mode == "other_payee" else (SELLER, WIN_MSAT + 1000)
        for w in wins:
            if w.get("invoice"):
                w["invoice"] = lab.post(node, "/v1/invoices", {"value_msat": str(msat), "expiry": "60", "cltv_expiry": "40"})["payment_request"]
                Lies.done += 1
    elif Lies.mode == "two_invoices":
        more = []
        for w in wins:
            if w.get("invoice") and w["draw"] not in Lies.extra:
                Lies.extra[w["draw"]] = lab.post(SELLER, "/v1/invoices", {"value_msat": str(WIN_MSAT), "expiry": "600", "cltv_expiry": "40"})["payment_request"]
                Lies.done += 1
        # the second invoice of every win so far, in this answer and in every later one
        for d, inv in Lies.extra.items():
            more.append({"draw": d, "invoice": inv})
        a["wins"] = wins + more
    return json.dumps(a).encode()


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_: Any) -> None:
        pass

    def pass_on(self, method: str) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        fwd = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "accept-encoding")}
        conn = http.client.HTTPConnection("127.0.0.1", GW2_PORT, timeout=60)
        try:
            conn.request(method, self.path, body=body or None, headers=fwd)
            r = conn.getresponse()
            data = lie_draw(r.read()) if (self.path == "/x402/lottery/draw" and r.status == 200 and Lies.mode) else None
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in ("content-length", "transfer-encoding", "connection", "date", "server"):
                    self.send_header(k, v)
            self.send_header("Connection", "close")
            length = str(len(data)) if data is not None else r.getheader("Content-Length")
            if length is not None:
                self.send_header("Content-Length", length)
            self.end_headers()
            if data is not None:
                self.wfile.write(data)
                return
            while True:
                chunk = r.read(64 << 10)
                if not chunk:
                    break
                self.wfile.write(chunk)
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


def events(kind: str) -> list[dict[str, Any]]:
    return [e for e in signer("history", {"limit": 5000}).get("events", []) if e.get("type") == kind]


def liar() -> None:
    url = f"{LIAR}/hot.bin"
    for mode, what, rule in (("false_win", "claims a win for a draw that lost, with a real invoice of its own node", "lottery_win"),
                             ("other_payee", "sends, for a real win, an invoice that pays another node", "ticket_payee"),
                             ("other_amount", "sends, for a real win, an invoice for one sat more", "ticket_amount")):
        stop_sessions()
        quiet()
        before, refused_before = money(), len(events("lottery_win_refused")) + len(events("ticket_refused"))
        Lies.mode, Lies.done, Lies.extra = mode, 0, {}
        r = pay(url, HOT_MAX_SATS)
        Lies.mode = ""
        if r.get("saved_to"):
            os.remove(r["saved_to"])
        quiet()
        m = money()
        refused = len(events("lottery_win_refused")) + len(events("ticket_refused")) - refused_before
        honest_before_lie = int(r.get("wins_paid") or 0) if mode == "false_win" else 0
        check(f"liar: a seller that {what} is paid nothing for it: the wallet's own check refuses it ({rule}), books the refusal, and its ledger is what its node paid",
              Lies.done > 0 and refused >= 1 and m["buyer_node_paid_msat"] - before["buyer_node_paid_msat"] == honest_before_lie * WIN_MSAT and agrees(m)
              and (mode != "false_win" or "lottery_seller_fault" in str(r.get("ended"))) and (mode == "false_win" or all(w.get("rule") == rule for w in r.get("wins_unpaid") or [{}])),
              {"lies": Lies.done, "refusals_booked": refused, "paid_msat": m["buyer_node_paid_msat"] - before["buyer_node_paid_msat"], "ended": str(r.get("ended"))[:140],
               "wins_unpaid": (r.get("wins_unpaid") or [])[:2]})
    stop_sessions()
    quiet()
    before = money()
    Lies.mode, Lies.done, Lies.extra = "two_invoices", 0, {}
    r = pay(f"{LIAR}/mid.bin", 200)
    r2 = pay(f"{LIAR}/hot.bin", HOT_MAX_SATS)
    Lies.mode = ""
    if r2.get("saved_to"):
        os.remove(r2["saved_to"])
    quiet()
    m = money()
    wins = int(r.get("wins") or 0) + int(r2.get("wins") or 0)
    seconds = [i for i in e2e.seller_invoices().values() if i["payment_request"] in Lies.extra.values()]
    check("liar: a seller that sends two invoices for every win is paid each win once: the second invoices are open on its node and unpaid, and the ledger is what the node paid",
          Lies.done >= 1 and wins >= 1 and m["buyer_node_paid_msat"] - before["buyer_node_paid_msat"] == wins * WIN_MSAT and agrees(m) and not once()["a_win_paid_twice"]
          and all(i["state"] != "SETTLED" for i in seconds),
          {"wins": wins, "second_invoices": len(Lies.extra), "second_invoices_paid": sum(1 for i in seconds if i["state"] == "SETTLED"), "paid_msat": m["buyer_node_paid_msat"] - before["buyer_node_paid_msat"]})
    stop_sessions()


# --- kills ---------------------------------------------------------------------------------------------------


def next_call_pays(what: str) -> dict[str, Any]:
    """After a kill and a restart: the next call is served by draws, or says plainly why not and a
    later one is. (A win whose payment failed as a node died is paid with the seller's next invoice,
    which comes when the first has lapsed, a minute at the gateway's default.)"""
    said = []
    end = time.time() + 300
    while time.time() < end:
        try:
            r = pay(f"{ORIGIN}/small.txt", 10)
        except LabError as e:
            said.append(str(e)[:120])
            time.sleep(2)
            continue
        if ok_draws(r):
            return {"calls": len(said) + 1, "said_first": sorted(set(x.split(":")[0] for x in said))}
        said.append(f"{r.get('rule')}: {str(r.get('reason'))[:100]}")
        time.sleep(5)
    raise LabError(f"{what}: no call was served after the restart: {said[-3:]}")


def killed(victim: str) -> None:
    if victim == "signer":
        PROCS["signer"].kill()
        PROCS["signer"].wait(10)
        e2e.WALLET_PROC.start()
    elif victim == "gateway":
        PROCS["gateway"].kill()
        PROCS["gateway"].wait(10)
        start_gateway("gateway", GW_PORT)
        lab.wait("the gateway", 60, lambda: gateway_up(GW_PORT), every=0.05)
    else:
        lab.dc("kill", victim)
        lab.forget_connections()
        lab.dc("start", victim)
        lab.wait(f"{victim} back and synced", 180, lambda: lab.synced(victim), every=0.2)
        lab.wait(f"{victim}'s channel active again", 180, partial(e2e.active, victim, 1), every=0.5)
        if victim == BUYER:
            lab.wait("the wallet's Lightning rail ready again", 120, lambda: signer("ln_status").get("ready") is True, every=1)
    print(f"     killed and restarted: {victim}", flush=True)


def settle_down() -> None:
    """After a kill: wait until every payment the wallet booked is final on its node, or is one the
    node never had (the wallet gives those up 90 s after they were sent)."""
    def final() -> bool:
        st = status()
        # every payment the book holds that is not final is one the node left in flight with nothing on its channel
        open_in_book = sum(int(st.get("tickets", {}).get(k, 0)) for k in ("sending", "locked", "released", "retired"))
        return lab.pending_htlcs(BUYER) == 0 and st.get("synced") is True and open_in_book <= len(orphans())

    lab.wait("every booked payment final", 300, final, every=2)


def kill() -> None:
    for victim in ("signer", "gateway", BUYER, SELLER):
        # between two calls, with a session of draws open
        stop_sessions()
        r = pay(f"{ORIGIN}/small.txt", 10)
        if not ok_draws(r):
            raise LabError(f"kill {victim}: the page before: {brief(r)}")
        killed(victim)
        resumed = next_call_pays(f"kill {victim} between two calls")
        settle_down()
        inv, m = once(), money()
        check(f"kill: {victim}, between two calls of a session of draws: no win paid twice, none booked and not paid, none paid and not booked, and the next call is served",
              inv["same_hashes"] and not inv["paid_not_booked"] and not inv["booked_not_paid"] and not inv["a_win_paid_twice"] and agrees(m),
              {"next": resumed, **inv, "ledger_sats": m["wallet_ledger_sats"], "node_cost_sats": m["buyer_node_cost_sats"]})
        # in the middle of a download in which a piece in four wins: payments are in flight when the kill comes
        other = Mcp()
        result: dict[str, Any] = {}

        def run(who: Mcp = other, into: dict[str, Any] = result) -> None:
            try:
                into.update(pay(f"{ORIGIN}/hot.bin", HOT_MAX_SATS, who=who))
            except (LabError, OSError, ValueError) as e:
                into["error"] = str(e)[:200]

        def paid_now() -> int:
            return sum(1 for p in e2e.buyer_payments().values() if p["status"] == "SUCCEEDED")

        paid_before = paid_now()
        t = threading.Thread(target=run)
        t.start()
        lab.wait("wins being paid", 60, lambda: paid_now() >= paid_before + 3, every=0.05)
        killed(victim)
        t.join(200)
        other.close()
        if result.get("saved_to"):
            os.remove(result["saved_to"])
        resumed = next_call_pays(f"kill {victim} in the middle of a download")
        settle_down()
        inv, m = once(), money()
        how = result.get("error") or result.get("ended") or ("complete" if result.get("complete") else brief(result))
        check(f"kill: {victim}, in the middle of a download with wins being paid: no win paid twice, none booked and not paid, none paid and not booked, and the next call is served",
              inv["same_hashes"] and not inv["paid_not_booked"] and not inv["booked_not_paid"] and not inv["a_win_paid_twice"] and agrees(m),
              {"the_call_ended": str(how)[:160], "bytes": result.get("bytes"), "wins": result.get("wins"), "wins_paid": result.get("wins_paid"), "next": resumed, **inv,
               "ledger_sats": m["wallet_ledger_sats"], "node_cost_sats": m["buyer_node_cost_sats"]})
    stop_sessions()


CHECKS = {"terms": terms, "file": file, "page": page, "swarm": swarm, "cheat": cheat, "liar": liar, "kill": kill}


def main() -> int:
    names = sys.argv[1:] or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        print(f"unknown check {unknown}; the checks are {' '.join(CHECKS)}", file=sys.stderr)
        return 2
    t0 = time.time()
    try:
        setup()
        print(f"lab up in {time.time() - t0:.0f} s: {BUYER} (buyer) - {HOP} (hop) - {SELLER} (seller, {SELLERS + 2} gateways), height {lab.height()}", flush=True)
        for name in names:
            try:
                CHECKS[name]()
            except (LabError, OSError, http.client.HTTPException, KeyError, IndexError, ValueError, AssertionError) as e:
                check(f"{name}: ran to its end", False, f"{type(e).__name__}: {e}")
                break  # the lab is in an unknown state: later checks would report that, not themselves
    finally:
        for m in e2e.AGENT:
            if m.proc.poll() is None:
                m.proc.kill()
        for p in PROCS.values():
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
    e2e.REPORT["failed"] = e2e.FAILED
    e2e.REPORT["seconds"] = round(time.time() - t0)
    with open(os.path.join(OUT, "lottery_regtest.json"), "w") as f:
        json.dump(e2e.REPORT, f, indent=1)
    passed = sum(1 for c in e2e.REPORT["checks"] if c["ok"])
    print(f"lottery: {passed} of {len(e2e.REPORT['checks'])} checks passed, {e2e.REPORT['seconds']} s", flush=True)
    return 1 if e2e.FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
