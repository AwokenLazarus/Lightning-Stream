#!/usr/bin/env python3
"""Stream tickets on a Lightning Fork regtest: the checks behind docs/TICKETS.md.

Run by scripts/ln_ticket_regtest.sh, which brings up the chain node. Four nodes, default settings:

    lf4 ---- lf1 ---- lf2 ---- lf3
    far     buyer     hop     seller

Channels lf1->lf2 and lf2->lf3 of 5,000,000 sat (1,000,000 pushed), lf4->lf1 of 2,000,000. A ticket
is 1,000 sat with a final CLTV delta of 40 unless a check says otherwise. Every check prints PASS or
FAIL and what it saw. Numbers that the first lab run of this design reported are
compared, and the ones that differ are listed at the end.

  accept      tickets for hashes only the buyer knows are ACCEPTED through the hop; the invoice
              names the seller, the amount, bit 512 and the CLTV delta; settle gives the buyer's
              node the buyer's own secret; a wrong secret and an unpaid ticket cannot be settled
  fees        10 locked, 5 settled, 5 cancelled: a routing fee on the settled ones only
  dust        which ticket sizes get an output of their own in the commitment transaction
  smallest    the smallest ticket a hop forwards, and what it costs
  direct      tickets over one channel (lf2 buys from lf3): no fee
  two_hops    tickets over three channels (lf4 buys from lf3): two routing fees
  latency     seconds to lock 1 to 400 tickets; per paid request, the seller's check, its
              settle call, and the buyer's node seeing SUCCEEDED; seconds for a stop to free funds
  macaroons   the wallet rail's four permissions pay a ticket; invoices:read and invoices:write
              make, look up, settle and cancel one, and cannot send coins or pay
  min_cltv    the smallest final CLTV delta the seller's node takes for a hold invoice
  slots       520 tickets offered at once through one channel: how many lock, how the rest fail
  restart     with 4 tickets locked, restart the seller, the hop, the buyer: still ACCEPTED, then
              two settle and two cancel
  hop_down    settle while the hop is stopped; the buyer's node learns it when the hop is back
  expiry      a seller that neither settles nor cancels: its node cancels 18 blocks before expiry
  claim       the seller settles while the hop is down and the hop stays down: the seller's node
              closes the channel and claims on chain before expiry; the buyer's node learns the
              secret from the chain once the hop is back
  offline     the seller's node goes away with 3 tickets locked and stays away past their expiry
  offline_100 the same with 100 tickets: the force close and what it costs

Usage: drive.py [--no-setup] [check ...]   (all checks, in the order above, when none is named;
--no-setup is for a lab that an earlier run left up with LN_TICKET_KEEP=1)
Environment: LAB, RUN (see lab.py), OUT (where ln_ticket_regtest.json goes).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import sys
import time
from collections.abc import Callable
from functools import partial
from typing import Any

import lab
from lab import LabError, Ticket

FAR, BUYER, HOP, SELLER = "lf4", "lf1", "lf2", "lf3"
TICKET_MSAT = 1_000_000
CLTV = 40
HOLD_EXPIRY_DELTA = 18  # lncfg/invoices.go in the fork: a held invoice is cancelled this far before expiry
REPORT: dict[str, Any] = {"checks": [], "measured": {}, "against_earlier_run": []}
FAILED: list[str] = []
UP = set(lab.NODES)


def check(name: str, ok: bool, saw: Any) -> None:
    REPORT["checks"].append({"check": name, "ok": bool(ok), "saw": saw})
    print(f"{'PASS' if ok else 'FAIL'} {name} | saw: {saw if isinstance(saw, str) else json.dumps(saw)}", flush=True)
    if not ok:
        FAILED.append(name)


def measured(key: str, value: Any, earlier: Any = None, exact: bool = True) -> None:
    """Record a number. `earlier` is what the first lab run reported for it; with `exact` a different
    value is listed as a difference (latencies and fee estimates are only shown side by side)."""
    REPORT["measured"][key] = value
    if earlier is not None:
        REPORT["against_earlier_run"].append(
            {"what": key, "measured": value, "earlier": earlier, "differs": bool(exact and value != earlier), "exact": exact}
        )


def tick(blocks: int = 1) -> int:
    """Mine, wait for the running nodes to have the tip, and give them a second to act on it."""
    h = lab.mine(blocks, UP)
    time.sleep(1.0)
    return h


def stop(node: str) -> None:
    lab.stop(node)
    UP.discard(node)


def start(node: str) -> float:
    secs = lab.start(node)
    UP.add(node)
    return secs


def clear(nodes: tuple[str, ...] = (BUYER, HOP, SELLER), secs: float = 120) -> float:
    """Wait until no HTLC is pending on any channel of `nodes`."""
    return lab.wait("no HTLC pending on " + ", ".join(nodes), secs, lambda: all(lab.pending_htlcs(n) == 0 for n in nodes), every=0.02)


def active(node: str, count: int) -> bool:
    return sum(1 for c in lab.channels(node) if c["active"]) == count


def finals(buyer: str, tickets: list[Ticket]) -> list[lab.Payment]:
    return list(lab.POOL.map(lambda t: lab.payment(buyer, t, final=True), tickets))


# --- setup ------------------------------------------------------------------------------------------


def setup() -> None:
    lab.wait("the chain node", 120, lambda: lab.chain("getblockchaininfo"))
    lab.chain("createwallet", "lab")
    lab.wallet("generatetoaddress", "130", lab.wallet("getnewaddress"))
    lab.dc("up", "-d", *lab.NODES)
    connect()
    for node, btc in ((BUYER, "1"), (HOP, "2"), (SELLER, "0.1"), (FAR, "0.5")):
        lab.fund(node, btc)
    lab.mine(6, lab.NODES)
    for node in lab.NODES:
        lab.wait(f"{node}'s coins", 60, partial(lab.wallet_sat, node))
    lab.open_channel(BUYER, HOP, 5_000_000, 1_000_000)
    lab.open_channel(HOP, SELLER, 5_000_000, 1_000_000)
    lab.open_channel(FAR, BUYER, 2_000_000, 0)
    lab.mine(8, lab.NODES)
    for node, count in ((BUYER, 2), (HOP, 2), (SELLER, 1), (FAR, 1)):
        lab.wait(f"{node}'s channels active", 120, partial(active, node, count))
    lab.wait("the buyers know all three channels", 120, lambda: all(lab.known_channels(n) >= 3 for n in (BUYER, FAR)))
    route(FAR)
    route(BUYER)


def connect() -> None:
    def ready(node: str) -> bool:
        lab.load_credentials(node)
        return lab.synced(node)

    for node in lab.NODES:
        lab.wait(f"{node} answering with its macaroon and certificate, and synced", 120, partial(ready, node))


def route(buyer: str) -> None:
    """Wait until `buyer` can lock a ticket with the seller (a new channel takes a while to be known)."""

    def probe() -> bool:
        tickets, _ = lab.lock(buyer, SELLER, 1, secs=10)
        lab.cancel_all(SELLER, tickets)
        return True

    lab.wait(f"a route from {buyer} to {SELLER}", 240, probe, every=2)
    clear((FAR, BUYER, HOP, SELLER))


def reopen() -> None:
    """A new lf2->lf3 channel after a check that closed it on chain."""
    lab.open_channel(HOP, SELLER, 5_000_000, 1_000_000)
    lab.mine(8, UP)
    lab.wait("the new channel active", 120, lambda: active(SELLER, 1) and active(HOP, 2))
    route(BUYER)


# --- the checks -------------------------------------------------------------------------------------


def accept() -> None:
    tickets, secs = lab.lock(BUYER, SELLER, 8)
    seller_id = lab.pubkey(SELLER)
    decoded = lab.get(BUYER, "/v1/payreq/" + tickets[0].invoice)
    wanted = {"destination": seller_id, "payment_hash": tickets[0].hash.hex(), "num_msat": str(TICKET_MSAT), "cltv_expiry": str(CLTV)}
    check(
        "accept: the hold invoice names the seller, the buyer's hash, the amount and the CLTV delta, and carries feature bit 512",
        all(decoded.get(k) == v for k, v in wanted.items()) and "512" in decoded.get("features", {}),
        {k: decoded.get(k) for k in wanted} | {"feature_512": decoded.get("features", {}).get("512")},
    )
    states = [lab.state(SELLER, t) for t in tickets]
    before = lab.payments(BUYER, tickets)
    check(
        "accept: 8 tickets for hashes only the buyer knows are ACCEPTED on the seller's node, through the hop",
        states == ["ACCEPTED"] * 8
        and lab.pending_htlcs(HOP) == 16
        and all(p.status == "IN_FLIGHT" and not int(p.preimage or "0", 16) for p in before),
        {"seller": lab.tally_states(states), "buyer": lab.tally(before), "htlcs_on_hop": lab.pending_htlcs(HOP), "lock_s": round(secs, 3)},
    )
    wrong = lab.ask(SELLER, "POST", "/v2/invoices/settle", {"preimage": lab.b64(os.urandom(32))})
    check("accept: the seller's node refuses to settle with a secret that is not a ticket's", "message" in wrong, wrong.get("message"))
    unpaid = lab.issue(SELLER, [os.urandom(32)])[0]
    early = lab.ask(SELLER, "POST", "/v2/invoices/settle", {"preimage": lab.b64(unpaid.secret)})
    check(
        "accept: a ticket that is not locked (OPEN) cannot be settled",
        "message" in early and lab.state(SELLER, unpaid) == "OPEN",
        early.get("message"),
    )
    lab.cancel(SELLER, unpaid)
    short = lab.issue(SELLER, [os.urandom(32)], life_s=2)[0]
    gone = lab.wait("the unpaid invoice to lapse", 30, lambda: lab.state(SELLER, short) == "CANCELED", every=0.2)
    late = lab.pay(BUYER, [short], timeout_s=5)[0]
    check(
        "accept: an invoice nobody paid within its life (2 s here) is cancelled by the seller's node and can no longer be paid",
        late.get("status") != "IN_FLIGHT" or lab.payment(BUYER, short, final=True).status == "FAILED",
        {"cancelled_after_s": round(gone, 1), "late_payment": late.get("status", late.get("message"))},
    )
    reply = lab.settle(SELLER, tickets[0])
    paid = lab.payment(BUYER, tickets[0], final=True)
    check(
        "accept: settle returns the buyer's own secret to the buyer's node as the payment preimage",
        reply == {} and paid.status == "SUCCEEDED" and paid.preimage == tickets[0].secret.hex() and lab.state(SELLER, tickets[0]) == "SETTLED",
        {"buyer": paid.status, "preimage_is_the_secret": paid.preimage == tickets[0].secret.hex(), "seller": lab.state(SELLER, tickets[0])},
    )
    lab.cancel_all(SELLER, tickets[1:])
    rest = finals(BUYER, tickets[1:])
    clear()
    check(
        "accept: the 7 cancelled tickets fail on the buyer's node and nothing stays pending", all(p.status == "FAILED" for p in rest), lab.tally(rest)
    )


def fees() -> None:
    def balances() -> tuple[int, int]:
        return int(lab.channel(BUYER, HOP)["local_balance"]), int(lab.channel(SELLER, HOP)["local_balance"])

    clear()
    b0, s0 = balances()
    tickets, _ = lab.lock(BUYER, SELLER, 10)
    for t in tickets[:5]:
        lab.settle(SELLER, t)
    lab.cancel_all(SELLER, tickets[5:])
    ps = finals(BUYER, tickets)
    clear()
    b1, s1 = balances()
    settled_fees = [p.fee_msat for p in ps[:5]]
    cancelled_fees = [p.fee_msat for p in ps[5:]]
    check(
        "fees: 10 locked, 5 settled, 5 cancelled: the buyer pays a routing fee on the settled tickets only",
        [p.status for p in ps] == ["SUCCEEDED"] * 5 + ["FAILED"] * 5
        and all(f > 0 for f in settled_fees)
        and cancelled_fees == [0] * 5
        and s1 - s0 == 5000
        and 5000 < b0 - b1 <= 5000 + sum(settled_fees) // 1000 + 1,
        {"buyer_paid_sat": b0 - b1, "seller_got_sat": s1 - s0, "fee_msat_settled": settled_fees, "fee_msat_cancelled": cancelled_fees},
    )
    measured("fee_msat_per_settled_ticket_one_hop", settled_fees[0], 1001)
    measured("buyer_paid_sat_for_5_of_10", b0 - b1, 5005)


def dust() -> None:
    clear()
    idle = int(lab.channel(BUYER, HOP)["commit_weight"]), int(lab.channel(SELLER, HOP)["commit_weight"])
    added: dict[str, list[int]] = {}
    for sat in (200, 353, 354, 1000):
        tickets, _ = lab.lock(BUYER, SELLER, 1, msat=sat * 1000)
        added[str(sat)] = [int(lab.channel(BUYER, HOP)["commit_weight"]) - idle[0], int(lab.channel(SELLER, HOP)["commit_weight"]) - idle[1]]
        lab.cancel_all(SELLER, tickets)
        clear()
    smallest = min((int(sat) for sat, w in added.items() if min(w) > 0), default=None)
    check(
        "dust: a 1,000-sat ticket has its own output in the commitment transactions of both channels on the route and a 200-sat ticket has none",
        min(added["1000"]) > 0 and added["200"] == [0, 0],
        {"weight_added_by_one_ticket_of_sat": added},
    )
    measured("smallest_ticket_sat_with_an_output", smallest, 354)
    measured("weight_units_per_ticket_output", added["1000"][0], 172)


def smallest() -> None:
    def buy(buyer: str, msat: int) -> lab.Payment:
        """Offer one ticket of `msat`; settle it if it locks. The payment as the buyer's node ends it."""
        ticket = lab.issue(SELLER, [os.urandom(32)], msat=msat)[0]
        lab.pay(buyer, [ticket], timeout_s=5)
        lab.wait(
            "the ticket locked or failed",
            30,
            lambda: lab.state(SELLER, ticket) == "ACCEPTED" or lab.payment(buyer, ticket).status == "FAILED",
            every=0.1,
        )
        if lab.state(SELLER, ticket) == "ACCEPTED":
            lab.settle(SELLER, ticket)
        else:
            lab.cancel(SELLER, ticket)
        return lab.payment(buyer, ticket, final=True)

    clear()
    hop_999, hop_1000 = buy(BUYER, 999), buy(BUYER, 1000)
    direct_999, direct_1000 = buy(HOP, 999), buy(HOP, 1000)
    clear()
    check(
        "smallest: a ticket of 1 sat locks and settles, through a hop (at a fee as large as the ticket) and on one channel; one of 999 msat does not",
        [p.status for p in (hop_999, hop_1000, direct_999, direct_1000)] == ["FAILED", "SUCCEEDED", "FAILED", "SUCCEEDED"]
        and hop_1000.fee_msat >= 1000,
        {
            "through_a_hop": {"999_msat": lab.tally([hop_999]), "1_sat": lab.tally([hop_1000]), "1_sat_fee_msat": hop_1000.fee_msat},
            "one_channel": {"999_msat": lab.tally([direct_999]), "1_sat": lab.tally([direct_1000]), "1_sat_fee_msat": direct_1000.fee_msat},
        },
    )
    measured("smallest_ticket_msat_through_a_hop", 1000 if hop_999.status == "FAILED" else 999, 1000)
    measured("fee_msat_on_a_1_sat_ticket", hop_1000.fee_msat, 1000)


def direct() -> None:
    clear()
    s0 = int(lab.channel(SELLER, HOP)["local_balance"])
    b0 = int(lab.channel(HOP, SELLER)["local_balance"])
    tickets, secs = lab.lock(HOP, SELLER, 8)
    one, one_secs = lab.lock(HOP, SELLER, 1)
    for t in tickets[:4]:
        lab.settle(SELLER, t)
    lab.cancel_all(SELLER, tickets[4:] + one)
    ps = finals(HOP, tickets)
    clear()
    paid = b0 - int(lab.channel(HOP, SELLER)["local_balance"])
    got = int(lab.channel(SELLER, HOP)["local_balance"]) - s0
    check(
        "direct: tickets over one channel lock, settle with the buyer's secret and cancel, at no fee",
        [p.status for p in ps] == ["SUCCEEDED"] * 4 + ["FAILED"] * 4
        and all(p.fee_msat == 0 for p in ps)
        and all(p.preimage == t.secret.hex() for p, t in zip(ps[:4], tickets))
        and paid == got == 4000,
        {"buyer": lab.tally(ps), "buyer_paid_sat": paid, "seller_got_sat": got, "lock_8_s": round(secs, 3), "lock_1_s": round(one_secs, 3)},
    )
    measured("direct_lock_s", {"1": round(one_secs, 3), "8": round(secs, 3)})
    measured("direct_fee_msat", ps[0].fee_msat, 0)


def two_hops() -> None:
    clear((FAR, BUYER, HOP, SELLER))
    b0 = int(lab.channel(FAR, BUYER)["local_balance"])
    tickets, secs = lab.lock(FAR, SELLER, 8)
    one, one_secs = lab.lock(FAR, SELLER, 1)
    carried = (lab.pending_htlcs(BUYER), lab.pending_htlcs(HOP))
    for t in tickets[:4]:
        lab.settle(SELLER, t)
    lab.cancel_all(SELLER, tickets[4:] + one)
    ps = finals(FAR, tickets)
    clear((FAR, BUYER, HOP, SELLER))
    paid = b0 - int(lab.channel(FAR, BUYER)["local_balance"])
    check(
        "two_hops: tickets through two routing nodes lock, settle with the buyer's secret and cancel; each hop takes its fee on settled tickets only",
        [p.status for p in ps] == ["SUCCEEDED"] * 4 + ["FAILED"] * 4
        and all(p.preimage == t.secret.hex() for p, t in zip(ps[:4], tickets))
        and all(p.fee_msat == 0 for p in ps[4:])
        and carried == (18, 18),
        {
            "buyer": lab.tally(ps),
            "fee_msat_settled": [p.fee_msat for p in ps[:4]],
            "buyer_paid_sat": paid,
            "htlcs_on_each_hop_while_locked": carried,
            "lock_8_s": round(secs, 3),
            "lock_1_s": round(one_secs, 3),
        },
    )
    measured("two_hops_lock_s", {"1": round(one_secs, 3), "8": round(secs, 3)})
    measured("fee_msat_per_settled_ticket_two_hops", ps[0].fee_msat)


def seen_final(ticket: Ticket) -> tuple[lab.Payment, float]:
    """The payment's final state on the buyer's node, and the clock when the node reported it."""
    return lab.payment(BUYER, ticket, final=True), time.perf_counter()


def latency() -> None:
    clear()
    locks: dict[str, float] = {}
    for count in (1, 8, 10, 50, 100, 200, 400):
        tickets, secs = lab.lock(BUYER, SELLER, count)
        locks[str(count)] = round(secs, 3)
        if count == 8:
            t0 = time.perf_counter()
            lab.cancel_all(SELLER, tickets)
            freed = time.perf_counter() - t0 + clear((BUYER,))
        else:
            lab.cancel_all(SELLER, tickets)
        clear()
    measured("lock_s_one_hop", locks, {"1": 0.27, "10": 0.59, "50": 1.9, "100": 3.0, "200": 5.0, "400": 9.6}, exact=False)
    measured("stop_8_tickets_freed_s", round(freed, 3))
    tickets, _ = lab.lock(BUYER, SELLER, 30)
    verify, settle_call, buyer_sees = [], [], []
    good = 0
    for t in tickets:
        watch = lab.POOL.submit(seen_final, t)
        time.sleep(0.05)  # the buyer's node is being watched before the request "arrives"
        t0 = time.perf_counter()
        # a request arrives with a secret: the seller hashes it and asks its node for that ticket
        looked = lab.get(SELLER, "/v2/invoices/lookup?payment_hash=" + lab.url64(hashlib.sha256(t.secret).digest()))["state"]
        t1 = time.perf_counter()
        lab.settle(SELLER, t)
        t2 = time.perf_counter()
        paid, t3 = watch.result()
        good += looked == "ACCEPTED" and paid.status == "SUCCEEDED"
        verify.append(t1 - t0)
        settle_call.append(t2 - t0)
        buyer_sees.append(t3 - t0)
    clear()
    per_request = {
        "seller_hashes_and_looks_up": lab.spread(verify),
        "seller_settle_returns": lab.spread(settle_call),
        "buyer_node_SUCCEEDED": lab.spread(buyer_sees),
    }
    check(
        "latency: 30 paid requests, each ticket looked up ACCEPTED, settled, and SUCCEEDED on the buyer's node; and the locks",
        good == 30,
        {"per_request_ms": per_request, "lock_s": locks, "stop_8_tickets_freed_s": round(freed, 3)},
    )
    measured(
        "per_request_ms", per_request, {"seller_hashes_and_looks_up": 0.93, "seller_settle_returns": 3.5, "buyer_node_SUCCEEDED": 11}, exact=False
    )


def macaroons() -> None:
    buyer_mac = lab.bake(BUYER, lab.BUYER_PERMISSIONS)
    seller_mac = lab.bake(SELLER, lab.SELLER_PERMISSIONS)
    tickets, _ = lab.lock(BUYER, SELLER, 2, buyer_macaroon=buyer_mac, seller_macaroon=seller_mac)
    looked = [lab.state(SELLER, t, seller_mac) for t in tickets]
    settled = lab.settle(SELLER, tickets[0], seller_mac)
    cancelled = lab.cancel(SELLER, tickets[1], seller_mac)
    ps = [lab.payment(BUYER, t, buyer_mac, final=True) for t in tickets]
    check(
        "macaroons: the wallet rail's macaroon (info:read, offchain:read, offchain:write, onchain:read) locks tickets and follows them",
        [p.status for p in ps] == ["SUCCEEDED", "FAILED"] and ps[0].preimage == tickets[0].secret.hex(),
        lab.tally(ps),
    )
    check(
        "macaroons: invoices:read and invoices:write are enough to make, look up, settle and cancel tickets",
        looked == ["ACCEPTED"] * 2 and settled == {} and cancelled == {},
        {"looked_up": looked, "settle": settled, "cancel": cancelled},
    )
    address = lab.wallet("getnewaddress")
    invoice = lab.issue(HOP, [os.urandom(32)])[0]
    seller_tries = {
        "send coins": lab.ask(SELLER, "POST", "/v1/transactions", {"addr": address, "amount": "1000"}, seller_mac),
        "pay an invoice": lab.stream(
            SELLER, "POST", "/v2/router/send", {"payment_request": invoice.invoice, "timeout_seconds": 5}, lambda u: True, seller_mac
        ),
        "open a channel": lab.ask(
            SELLER, "POST", "/v1/channels", {"node_pubkey_string": lab.pubkey(BUYER), "local_funding_amount": "100000"}, seller_mac
        ),
        "read the on-chain balance": lab.ask(SELLER, "GET", "/v1/balance/blockchain", None, seller_mac),
        "bake a macaroon": lab.ask(SELLER, "POST", "/v1/macaroon", {"permissions": [{"entity": "onchain", "action": "write"}]}, seller_mac),
    }
    check(
        "macaroons: the seller's macaroon cannot send coins, pay, open a channel, read the wallet or bake a macaroon",
        all(lab.refused(r) for r in seller_tries.values()),
        {k: r.get("message", r) for k, r in seller_tries.items()},
    )
    buyer_tries = {
        "send coins": lab.ask(BUYER, "POST", "/v1/transactions", {"addr": address, "amount": "1000"}, buyer_mac),
        "make a hold invoice": lab.ask(BUYER, "POST", "/v2/invoices/hodl", {"hash": lab.b64(os.urandom(32)), "value_msat": "1000"}, buyer_mac),
        "bake a macaroon": lab.ask(BUYER, "POST", "/v1/macaroon", {"permissions": [{"entity": "onchain", "action": "write"}]}, buyer_mac),
    }
    check(
        "macaroons: the buyer's macaroon cannot send coins on chain, make invoices or bake a macaroon",
        all(lab.refused(r) for r in buyer_tries.values()),
        {k: r.get("message", r) for k, r in buyer_tries.items()},
    )
    lab.cancel(HOP, invoice)
    clear()


def min_cltv() -> None:
    saw: dict[str, str] = {}
    for delta in (18, 23, 24, 25, 30):
        try:
            tickets, _ = lab.lock(BUYER, SELLER, 1, cltv=delta, secs=15)
        except LabError as e:
            saw[str(delta)] = str(e)[-90:]
            continue
        saw[str(delta)] = "ACCEPTED"
        lab.cancel_all(SELLER, tickets)
    clear()
    smallest = min((int(d) for d, s in saw.items() if s == "ACCEPTED"), default=None)
    check(
        "min_cltv: the seller's node refuses a hold invoice with a final CLTV delta of 18 and takes 30",
        saw["18"] != "ACCEPTED" and saw["30"] == "ACCEPTED",
        saw,
    )
    measured("smallest_final_cltv_delta_accepted", smallest, 25)  # reported as "more than 24"


def slots() -> None:
    clear()
    idle = lab.channel(BUYER, HOP)
    tickets = lab.issue(SELLER, [os.urandom(32) for _ in range(520)])
    t0 = time.perf_counter()
    first = lab.tally_states([u.get("status", "error") for u in lab.pay(BUYER, tickets, timeout_s=20)])

    def settled_down() -> bool:
        tally = lab.tally(lab.payments(BUYER, tickets))
        return tally.get("IN_FLIGHT", 0) == lab.accepted(SELLER, tickets) and sum(tally.values()) == 520 and "UNKNOWN" not in tally

    lab.wait("every one of the 520 payments locked or failed", 120, settled_down, every=1)
    secs = time.perf_counter() - t0
    locked = lab.accepted(SELLER, tickets)
    tally = lab.tally(lab.payments(BUYER, tickets))
    full = lab.channel(BUYER, HOP)
    on_channels = {n: [len(c["pending_htlcs"]) for c in lab.channels(n) if c["pending_htlcs"]] for n in (BUYER, HOP, SELLER)}
    check(
        "slots: of 520 tickets offered at once through one channel, 483 lock and the other 37 fail on the buyer's node with nothing held",
        locked == 483
        and tally.get("IN_FLIGHT") == 483
        and sum(v for k, v in tally.items() if k.startswith("FAILED")) == 37
        and on_channels == {BUYER: [483], HOP: [483, 483], SELLER: [483]},
        {"accepted_on_seller": locked, "buyer": tally, "first_update": first, "htlcs_per_channel": on_channels, "seconds": round(secs, 1)},
    )
    measured("tickets_in_flight_per_channel", locked, 483)
    measured("buyer_failures_of_the_37", {k: v for k, v in tally.items() if k.startswith("FAILED")}, {"FAILED:INSUFFICIENT_BALANCE": 37})
    measured("commitment_weight", {"idle": int(idle["commit_weight"]), "with_483": int(full["commit_weight"])}, {"idle": 1116, "with_483": 84200})
    measured(
        "commitment_fee_sat", {"idle": int(idle["commit_fee"]), "with_483": int(full["commit_fee"])}, {"idle": 285, "with_483": 21304}, exact=False
    )
    t0 = time.perf_counter()
    lab.cancel_all(SELLER, tickets)
    freed = time.perf_counter() - t0 + clear()
    # the buyer's node reports a payment FAILED a little after its HTLC is gone from the channel
    booked = lab.wait("every payment final on the buyer's node", 120, lambda: "IN_FLIGHT" not in lab.tally(lab.payments(BUYER, tickets)), every=1)
    after = lab.tally(lab.payments(BUYER, tickets))
    check(
        "slots: cancelling all 520 frees every HTLC and the channels stay open",
        after.keys() <= {"FAILED:INCORRECT_PAYMENT_DETAILS", "FAILED:INSUFFICIENT_BALANCE", "FAILED:TIMEOUT", "FAILED:NO_ROUTE"}
        and sum(after.values()) == 520
        and active(BUYER, 2)
        and active(HOP, 2)
        and active(SELLER, 1),
        {"buyer": after, "htlcs_gone_s": round(freed, 1), "then_all_payments_final_s": round(booked, 1)},
    )


def restart() -> None:
    saw: dict[str, Any] = {}
    ok = True
    for node, count in ((SELLER, 1), (HOP, 2), (BUYER, 2)):
        tickets, _ = lab.lock(BUYER, SELLER, 4)
        back = start(node)
        up = lab.wait(f"{node}'s channels active", 120, partial(active, node, count), every=0.1)
        lab.wait("the channels active on both ends", 120, lambda: active(BUYER, 2) and active(HOP, 2) and active(SELLER, 1))
        states = [lab.state(SELLER, t) for t in tickets]
        held = [lab.pending_htlcs(n) for n in (BUYER, HOP, SELLER)]
        for t in tickets[:2]:
            lab.settle(SELLER, t)
        lab.cancel_all(SELLER, tickets[2:])
        ps = finals(BUYER, tickets)
        clear()
        good = (
            states == ["ACCEPTED"] * 4
            and held == [4, 8, 4]
            and [p.status for p in ps] == ["SUCCEEDED"] * 2 + ["FAILED"] * 2
            and all(p.preimage == t.secret.hex() for p, t in zip(ps[:2], tickets))
        )
        ok = ok and good
        saw[node] = {
            "back_s": round(back, 1),
            "channels_active_s": round(up, 1),
            "seller": lab.tally_states(states),
            "htlcs": held,
            "buyer": lab.tally(ps),
        }
    check(
        "restart: with 4 tickets locked, a restart of the seller, of the hop and of the buyer leaves them ACCEPTED; then 2 settle and 2 cancel",
        ok,
        saw,
    )
    measured("restart_back_s", {n: saw[n]["back_s"] for n in saw}, {SELLER: 1.0, HOP: 1.0, BUYER: 1.5}, exact=False)


def hop_down() -> None:
    tickets, _ = lab.lock(BUYER, SELLER, 4)
    stop(HOP)
    t0 = time.perf_counter()
    reply = lab.settle(SELLER, tickets[0])
    call_ms = round((time.perf_counter() - t0) * 1e3, 1)
    lab.cancel(SELLER, tickets[1])
    time.sleep(2)
    states = [lab.state(SELLER, t) for t in tickets]
    while_down = lab.tally(lab.payments(BUYER, tickets))
    check(
        "hop_down: with the hop stopped the seller's settle and cancel return at once and its node records them; the buyer's node still shows 4 in flight",
        reply == {} and states == ["SETTLED", "CANCELED", "ACCEPTED", "ACCEPTED"] and while_down == {"IN_FLIGHT": 4},
        {"settle_ms": call_ms, "seller": states, "buyer": while_down},
    )
    back = start(HOP)
    t0 = time.perf_counter()
    ps = finals(BUYER, tickets[:2])
    learned = time.perf_counter() - t0
    lab.cancel_all(SELLER, tickets[2:])
    clear()
    check(
        "hop_down: once the hop is back the buyer's node has the settled ticket as SUCCEEDED with its secret and the cancelled one as FAILED",
        [p.status for p in ps] == ["SUCCEEDED", "FAILED"] and ps[0].preimage == tickets[0].secret.hex(),
        {"buyer": lab.tally(ps), "hop_back_s": round(back, 1), "then_s": round(learned, 1)},
    )
    measured("settle_call_with_hop_down_ms", call_ms, 4.2, exact=False)


def expiry() -> None:
    locked_at = lab.height()
    tickets, _ = lab.lock(BUYER, SELLER, 3)
    htlc = lab.invoice(SELLER, tickets[0])["htlcs"][0]
    expires = int(htlc["expiry_height"])
    buyer_expires = max(int(h["expiration_height"]) for h in lab.channel(BUYER, HOP)["pending_htlcs"])
    h = locked_at
    states = {"ACCEPTED"}
    while states == {"ACCEPTED"} and h < expires:
        h = tick()
        states = {lab.state(SELLER, t) for t in tickets}
    ps = finals(BUYER, tickets)
    clear()
    open_still = active(BUYER, 2) and active(HOP, 2) and active(SELLER, 1)
    check(
        "expiry: a seller that neither settles nor cancels has its tickets cancelled by its own node 18 blocks before their expiry, with every channel still open",
        states == {"CANCELED"} and h == expires - HOLD_EXPIRY_DELTA and all(p.status == "FAILED" for p in ps) and open_still,
        {
            "locked_at": locked_at,
            "seller_htlc_expiry": expires,
            "buyer_htlc_expiry": buyer_expires,
            "cancelled_at": h,
            "blocks_before_expiry": expires - h,
            "blocks_held": h - locked_at,
            "buyer": lab.tally(ps),
            "channels_open": open_still,
        },
    )
    measured("blocks_held_by_a_silent_seller", h - locked_at, 25)
    measured("seller_htlc_expiry_minus_lock_height", expires - locked_at, 43)
    measured("buyer_htlc_expiry_minus_lock_height", buyer_expires - locked_at, 123)


def on_chain(secrets: list[str], block_height: int) -> list[str]:
    """Which of `secrets` (hex) appear in a witness of a transaction in the block at `block_height`."""
    block = json.loads(lab.chain("getblock", lab.chain("getblockhash", str(block_height)), "2"))
    witness = {w for tx in block["tx"] for vin in tx["vin"] for w in vin.get("txinwitness", [])}
    return [s for s in secrets if s in witness]


def closing(node: str, point: str, kind: str) -> list[dict[str, Any]]:
    """`node`'s pending-close entries of `kind` for the channel whose funding outpoint is `point`."""
    return [c for c in lab.pending_channels(node)[kind] if c["channel"]["channel_point"] == point]


def close_heights(node: str, point: str, until: Callable[[int], bool], limit: int) -> dict[str, int]:
    """Mine block by block until `until(height)`; the heights at which `node` first showed the
    channel waiting to close (its commitment is broadcast) and force-closing (the commitment is mined)."""
    seen: dict[str, int] = {}
    for _ in range(limit):
        h = tick()
        mined = closing(node, point, "pending_force_closing_channels")
        if mined or closing(node, point, "waiting_close_channels"):
            seen.setdefault("commitment_broadcast_by", h)
        if mined:
            seen.setdefault("commitment_mined_by", h)
        if until(h):
            return seen
    raise LabError(f"{limit} blocks mined and still waiting; saw {seen}")


def swept(nodes: tuple[str, ...]) -> None:
    """Mine until the nodes named have nothing left in a closing channel (the delays are hundreds of blocks)."""

    def busy() -> bool:
        return any(
            int(lab.pending_channels(n)["total_limbo_balance"]) > 0 or lab.pending_channels(n)["pending_force_closing_channels"] for n in nodes
        )

    for _ in range(50):
        if not busy():
            tick()  # the last sweep is confirmed in the wallet
            return
        tick(50)
    raise LabError("2,500 blocks mined and a closing channel still holds funds on " + ", ".join(nodes))


def claim() -> None:
    clear()
    locked_at = lab.height()
    point = lab.channel(SELLER, HOP)["channel_point"]
    in_channel = int(lab.channel(SELLER, HOP)["local_balance"])
    in_wallet = lab.wallet_sat(SELLER)
    tickets, _ = lab.lock(BUYER, SELLER, 3)
    expires = int(lab.invoice(SELLER, tickets[0])["htlcs"][0]["expiry_height"])
    buyer_expires = max(int(h["expiration_height"]) for h in lab.channel(BUYER, HOP)["pending_htlcs"])
    stop(HOP)
    replies = [lab.settle(SELLER, t) for t in tickets]
    secrets = [t.secret.hex() for t in tickets]
    revealed: dict[str, int] = {}

    def all_claimed(h: int) -> bool:
        for s in on_chain(secrets, h):
            revealed.setdefault(s, h)
        return len(revealed) == 3

    heights = close_heights(SELLER, point, all_claimed, expires - locked_at + 20)
    claimed_at = max(revealed.values())
    check(
        "claim: the seller settled with the hop down and the hop stayed down: the seller's node closed the channel and put all 3 secrets on chain before the tickets' expiry",
        replies == [{}] * 3 and claimed_at < expires,
        {
            "locked_at": locked_at,
            "seller_htlc_expiry": expires,
            **heights,
            "secrets_on_chain_at": sorted(revealed.values()),
            "blocks_before_expiry": expires - claimed_at,
        },
    )
    measured("seller_closes_blocks_before_expiry", expires - heights["commitment_broadcast_by"])
    measured("seller_claim_on_chain_blocks_before_expiry", expires - claimed_at)
    while_down = lab.tally(lab.payments(BUYER, tickets))
    start(HOP)
    h = lab.height()
    for _ in range(30):
        if all(p.status == "SUCCEEDED" for p in lab.payments(BUYER, tickets)):
            break
        h = tick()
    ps = lab.payments(BUYER, tickets)
    check(
        "claim: once the hop is back it reads the secrets from the chain and the buyer's node has all 3 tickets SUCCEEDED, before the buyer's own HTLCs expire, its channel open",
        while_down == {"IN_FLIGHT": 3}
        and all(p.status == "SUCCEEDED" and p.preimage == t.secret.hex() for p, t in zip(ps, tickets))
        and h < buyer_expires
        and active(BUYER, 2),
        {"buyer_while_hop_down": while_down, "buyer": lab.tally(ps), "at_height": h, "buyer_htlc_expiry": buyer_expires},
    )
    # the seller's coins: its channel balance and the 3 tickets come back to its wallet after the delays
    swept((SELLER, HOP))
    now_in_wallet = lab.wallet_sat(SELLER)
    cost = in_wallet + in_channel + 3000 - now_in_wallet
    check(
        "claim: the seller's wallet ends with its channel balance and the 3 tickets, less the fees of its own sweeps",
        0 <= cost < 3000,
        {
            "channel_balance_before": in_channel,
            "tickets_sat": 3000,
            "wallet_gained": now_in_wallet - in_wallet,
            "cost_sat": cost,
            "blocks_from_claim_to_wallet": lab.height() - claimed_at,
        },
    )
    measured("seller_on_chain_claim_cost_sat", cost)
    reopen()


def offline(count: int) -> None:
    name = "offline" if count == 3 else f"offline_{count}"
    clear()
    locked_at = lab.height()
    hop_channel = lab.channel(HOP, SELLER)
    hop_had = lab.wallet_sat(HOP) + int(hop_channel["local_balance"])
    buyer_had = int(lab.channel(BUYER, HOP)["local_balance"])
    tickets, secs = lab.lock(BUYER, SELLER, count)
    hop_expires = max(int(h["expiration_height"]) for h in lab.channel(HOP, SELLER)["pending_htlcs"])
    buyer_expires = max(int(h["expiration_height"]) for h in lab.channel(BUYER, HOP)["pending_htlcs"])
    stop(SELLER)
    heights = close_heights(HOP, hop_channel["channel_point"], lambda h: lab.pending_htlcs(BUYER) == 0, 160)
    freed_at = lab.height()
    ps = lab.payments(BUYER, tickets)
    txid = closing(HOP, hop_channel["channel_point"], "pending_force_closing_channels")[0]["closing_txid"]
    tx = json.loads(lab.chain("getrawtransaction", txid, "2"))
    commitment = {
        "weight": tx["weight"],
        "outputs": len(tx["vout"]),
        "fee_sat": int(hop_channel["capacity"]) - round(sum(o["value"] for o in tx["vout"]) * 100_000_000),
    }
    buyer_has = int(lab.channel(BUYER, HOP)["local_balance"])
    check(
        f"{name}: the seller's node gone with {count} tickets locked: the hop closes its channel to the seller at the tickets' expiry; every ticket fails on the buyer's node long before the buyer's own HTLCs expire, and the buyer has its whole balance and its channel",
        all(p.status == "FAILED" for p in ps)
        and heights.get("commitment_broadcast_by", 0) >= hop_expires
        and freed_at < buyer_expires
        and buyer_has == buyer_had
        and active(BUYER, 2),
        {
            "locked_at": locked_at,
            "hop_htlc_expiry": hop_expires,
            "buyer_htlc_expiry": buyer_expires,
            **heights,
            "buyer_free_at": freed_at,
            "blocks_locked": freed_at - locked_at,
            "buyer": lab.tally(ps),
            "buyer_balance_change_sat": buyer_has - buyer_had,
            "commitment": commitment,
            "lock_s": round(secs, 2),
        },
    )
    start(SELLER)
    swept((HOP,))
    cost = hop_had - lab.wallet_sat(HOP)
    check(
        f"{name}: the hop gets its side of the closed channel back on chain, {count} tickets included, less the fees of the close",
        0 < cost < 1000 + 500 * count,
        {"hop_cost_sat": cost, "blocks_from_lock_to_wallet": lab.height() - locked_at},
    )
    if count == 3:
        measured("offline_force_close_blocks_after_lock", heights["commitment_broadcast_by"] - locked_at, 43)
        measured("offline_buyer_funds_back_blocks_after_lock", freed_at - locked_at, 51)
    else:
        measured(f"{name}_buyer_funds_back_blocks_after_lock", freed_at - locked_at)
    measured(f"{name}_commitment", commitment)
    measured(f"{name}_hop_cost_sat", cost)
    reopen()


CHECKS: dict[str, Callable[[], None]] = {
    "accept": accept,
    "fees": fees,
    "dust": dust,
    "smallest": smallest,
    "direct": direct,
    "two_hops": two_hops,
    "latency": latency,
    "macaroons": macaroons,
    "min_cltv": min_cltv,
    "slots": slots,
    "restart": restart,
    "hop_down": hop_down,
    "expiry": expiry,
    "claim": claim,
    "offline": lambda: offline(3),
    "offline_100": lambda: offline(100),
}


def main() -> int:
    args = sys.argv[1:]
    names = [a for a in args if a != "--no-setup"] or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        print(f"unknown check {unknown}; the checks are {' '.join(CHECKS)}", file=sys.stderr)
        return 2
    t0 = time.time()
    if "--no-setup" in args:
        connect()
    else:
        setup()
    print(f"lab up in {time.time() - t0:.0f} s: {FAR} - {BUYER} (buyer) - {HOP} (hop) - {SELLER} (seller), height {lab.height()}", flush=True)
    for name in names:
        try:
            CHECKS[name]()
        except (LabError, OSError, http.client.HTTPException, KeyError, IndexError, ValueError) as e:
            check(f"{name}: ran to its end", False, f"{type(e).__name__}: {e}")
            break  # the lab is in an unknown state: later checks would report that, not themselves
    differs = [d for d in REPORT["against_earlier_run"] if d["differs"]]
    for d in REPORT["against_earlier_run"]:
        word = "DIFFERS from" if d["differs"] else ("beside" if not d["exact"] else "same as")
        print(f"NOTE {d['what']}: {json.dumps(d['measured'])} {word} the earlier run's {json.dumps(d['earlier'])}", flush=True)
    REPORT["failed"] = FAILED
    REPORT["seconds"] = round(time.time() - t0)
    with open(os.path.join(os.environ["OUT"], "ln_ticket_regtest.json"), "w") as f:
        json.dump(REPORT, f, indent=1)
    passed = len(REPORT["checks"]) - len(FAILED)
    print(
        f"ln_ticket: {passed} of {len(REPORT['checks'])} checks passed, {len(differs)} numbers differ from the earlier run, {REPORT['seconds']} s",
        flush=True,
    )
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
