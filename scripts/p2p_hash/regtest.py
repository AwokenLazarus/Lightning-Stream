"""p2p-hash on regtest with real tickets (scripts/p2p_hash_regtest.sh).

The ticket lab's three Lightning Fork nodes (lf1 the hashtaker, lf2 a hop, lf3 the hashmaker's node), the
wallet's signer on lf1 with a "hashrate" task, the hashmaker's gateway beside lf3 with one route,
/hashrate/, passed to the hashmaker's paid-slice endpoint, a stand-in Nostr relay, a stand-in pool as
the hashtaker's gateway and stand-in miners. The hashmaker publishes its listing to the relay; the hashtaker
finds it there, opens the link to the endpoint it names, and pays each finished slice through the
wallet: one paid request per slice, on the gateway's tickets (prepaid first, then held).

Checks:
  listing   found on the relay, its link key the hashmaker's, the link opened to the address it names
  paid      every finished slice paid once through the wallet, each signed receipt equal to the
            hashmaker's count, the gateway charging exactly slices x price, both meters equal; held
            tickets used; the seller's node settled what the hashtaker's node paid
  no-hash   the miners stop: no payment after that, the wallet's session stopped, nothing left held
  unpaid    the hashtaker stops paying after slice 3: the hashmaker stops within one slice past the
            unpaid slice, and the gateway charges nothing more
  small     a rental whose budget (500 sat) is under the shop's ticket (1,000 sat), from no credit at a
            second gateway on the same node, with the app's caps (rail::pay_caps: 2,000 sat may leave a
            slice, the budget is the most it is charged): the old caps (max_sats = the budget) are
            refused with nothing paid; the app's buy one whole ticket and pay every slice of the budget
            from it; slices x price = the wallet's spent = the seller's signed spent, the credit left
            = the ticket - spent, and the seller's node settled exactly the one ticket the wallet's
            node paid; the rental's report says what left and what stays with the seller
Report: run/p2p_hash_regtest.json.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ticket_e2e"))
import drive as d  # noqa: E402  (the ticket lab's setup, nodes, wallet and helpers)
from drive import lab  # noqa: E402

RUN, OUT, BIN = d.RUN, d.OUT, d.BIN
B = d.BASE
GW, SLICES, RELAY, POOL, LINK, MINERS = B + 4, B + 5, B + 6, B + 7, B + 8, B + 9
ORIGIN = f"http://127.0.0.1:{GW}"
# a second gateway on the same seller node and slice route: a shop the wallet has no credit with
GW2 = B + 10
ORIGIN2 = f"http://127.0.0.1:{GW2}"
SMALL_BUDGET_SATS = 500
RELAY_URL = f"ws://127.0.0.1:{RELAY}"
DIFF = 4
SHARE = DIFF * 2**32
SLICE_WORK = 10 * SHARE
PRICE_MSAT = 100_000
TICKET_MSAT = 1_000_000  # above the wallet's floor for a held ticket on these channels (no anchors), at its default most
GRACE_MS = 8000
REPORT: dict[str, Any] = {"checks": []}
PROCS: list[subprocess.Popen[bytes]] = []


def check(name: str, ok: bool, saw: Any) -> None:
    REPORT["checks"].append({"check": name, "ok": bool(ok), "saw": saw})
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {json.dumps(saw)[:400]}", flush=True)


def policy() -> dict[str, Any]:
    pk = lab.pubkey(d.SELLER)
    return {
        "allowlist": [ORIGIN, ORIGIN2],
        "counterparties": {ORIGIN: {"ln_node": pk}, ORIGIN2: {"ln_node": pk}},
        "max_per_tx_sats": 10_000,
        "daily_budget_sats": 100_000,
        "weekly_budget_sats": 200_000,
        "per_counterparty_cap_sats": 100_000,
        "velocity_max": 1_000,
        "velocity_window_s": 3600,
        "human_threshold_sats": 50_000,
        "split_window_s": 0,
        "regtest_mine": False,
        "anchor_interval_s": 3600,
        "ln": {"enabled": True, "split_height": d.SPLIT},
        "tickets": {"enabled": True, "tasks": {"hashrate": {"budget_sats": 50_000}}},
    }


def setup() -> None:
    lab.wait("the chain node", 120, lambda: lab.chain("getblockchaininfo"))
    lab.chain("createwallet", "lab")
    lab.chain("createwallet", "agent")
    lab.wallet("generatetoaddress", "130", lab.wallet("getnewaddress"))
    lab.dc("up", "-d", *d.NODES)
    for node in d.NODES:
        lab.wait(f"{node} answering and synced", 180, lambda n=node: (lab.load_credentials(n), lab.synced(n))[1])
    d.send_pinned(lab.lncli(d.BUYER, "newaddress", "p2wkh")["address"], "0.2")
    lab.fund(d.HOP, "0.2")
    lab.mine(6, d.NODES)
    for node in (d.BUYER, d.HOP):
        lab.wait(f"{node}'s coin", 60, lambda n=node: lab.wallet_sat(n))
    d.open_channel(d.BUYER, d.HOP, 5_000_000)
    d.open_channel(d.HOP, d.SELLER, 5_000_000)
    lab.mine(8, d.NODES)
    for node, count in ((d.BUYER, 1), (d.HOP, 2), (d.SELLER, 1)):
        lab.wait(f"{node}'s channels active", 240, lambda n=node, c=count: d.active(n, c))
    lab.wait("the hashtaker knows both channels", 300, lambda: lab.known_channels(d.BUYER) >= 2, every=2)
    os.makedirs(f"{RUN}/keys", exist_ok=True)
    with open(f"{RUN}/rpc.cookie", "w") as f:
        f.write("lab:lab")
    for name, node, perms in (("rail", d.BUYER, lab.BUYER_PERMISSIONS), ("invoices", d.SELLER, lab.SELLER_PERMISSIONS), ("info", d.SELLER, ("info:read",))):
        with open(f"{RUN}/{name}.macaroon", "wb") as f:
            f.write(bytes.fromhex(lab.bake(node, perms)))
        os.chmod(f"{RUN}/{name}.macaroon", 0o600)
    network = "bip122:" + lab.chain("getblockhash", "101")[:32]
    cfg = {
        "listen": f"127.0.0.1:{GW}",
        "public_url": ORIGIN,
        "state_dir": f"{RUN}/state-gateway",
        "chain": "regtest",
        "network": network,
        "node": {"rest": f"https://127.0.0.1:{lab.PORT[d.SELLER]}", "tls_cert": f"{RUN}/{d.SELLER}.tls.cert",
                 "macaroon": f"{RUN}/invoices.macaroon", "info_macaroon": f"{RUN}/info.macaroon"},
        "caps": {"sessions_per_address": 0, "unpaid_per_address": 0, "first_use_secs": 20, "idle_secs": 120},
        "times": {"height_max_age_secs": 5},
        "tickets": {"ticket_msat": TICKET_MSAT, "max_tickets": 2, "ticket_blocks": 40, "settle": ["on-use", "on-arrival"]},
        "routes": [{"path": "/hashrate/", "upstream": f"http://127.0.0.1:{SLICES}", "methods": ["POST"], "max_body": 8192,
                    "price": {"request_msat": PRICE_MSAT}}],
    }
    cfg2 = {**cfg, "listen": f"127.0.0.1:{GW2}", "public_url": ORIGIN2, "state_dir": f"{RUN}/state-gateway2"}
    for name, c in (("gateway", cfg), ("gateway2", cfg2)):
        with open(f"{RUN}/{name}.json", "w") as f:
            json.dump(c, f, indent=1)
        with open(f"{RUN}/{name}.log", "ab") as log:
            PROCS.append(subprocess.Popen([f"{BIN}/xbt-gateway", f"{RUN}/{name}.json"], stdout=log, stderr=log))
    for port in (GW, GW2):
        lab.wait(f"the gateway at {port}", 60, lambda p=port: json.loads(d.send("GET", "/x402/ticket/health", p)[2])["height"] is not None, every=0.2)
    status, headers, _ = d.send("POST", "/hashrate/probe/1", GW, body=b"{}")
    REPORT["terms_402"] = {"status": status, "accepts": json.loads(base64.b64decode(headers.get("payment-required", "e30="))).get("accepts")}
    d.Wallet.policy = lambda self: policy()  # the lab's wallet, with this lab's one seller and task
    d.WALLET_PROC.write_policy()
    d.WALLET_PROC.start()
    st = d.signer("ln_status")
    check("setup: the wallet's Lightning rail is ready", st.get("ready") is True, {"ready": st.get("ready"), "warnings": st.get("warnings")})
    with open(f"{RUN}/relay.log", "ab") as log:
        PROCS.append(subprocess.Popen([f"{BIN}/xbt-hashlink", "relay", "--listen", f"127.0.0.1:{RELAY}"], stdout=log, stderr=log))
    for who in ("hasher", "nostr", "buyer"):
        subprocess.run([f"{BIN}/xbt-hashlink", "keygen", f"{RUN}/keys/{who}.key"], check=True, stdout=subprocess.DEVNULL)


def spawn(name: str, args: list[str]) -> subprocess.Popen[bytes]:
    log = open(f"{RUN}/{name}.log", "ab")
    p = subprocess.Popen([f"{BIN}/xbt-hashlink", *args], stdout=log, stderr=log)
    PROCS.append(p)
    return p


def rental(name: str, stop_after: int | None, miner_secs: int, rate: float, origin: str = ORIGIN,
           caps: tuple[str, ...] = ("--max-sats", "1500")) -> dict[str, Any]:
    pool = spawn(f"{name}-pool", ["standin-pool", "--listen", f"127.0.0.1:{POOL}", "--diff", str(DIFF), "--job-ms", "1000", "--report", f"{RUN}/{name}-pool.json"])
    t = ["--slice-work", str(SLICE_WORK), "--price-msat", str(PRICE_MSAT), "--grace-ms", str(GRACE_MS)]
    hashmaker = spawn(f"{name}-hashmaker", ["hashmaker", "--key", f"{RUN}/keys/hasher.key", "--miners", f"127.0.0.1:{MINERS}", "--link", f"127.0.0.1:{LINK}",
                                      "--slices", f"127.0.0.1:{SLICES}", *t, "--report", f"{RUN}/{name}-hasher.json",
                                      "--relays", RELAY_URL, "--nostr-key", f"{RUN}/keys/nostr.key", "--name", "regtest hashmaker",
                                      "--link-public", f"127.0.0.1:{LINK}", "--pay-url", f"{origin}/hashrate", "--pay-node", lab.pubkey(d.SELLER),
                                      "--hashrate-hs", "4000000000000", "--listing-out", f"{RUN}/{name}-listing.json"])
    lab.wait("the hashmaker's listing", 30, lambda: os.path.exists(f"{RUN}/{name}-listing.json"), every=0.2)
    time.sleep(0.5)
    extra = ["--stop-paying-after", str(stop_after)] if stop_after is not None else []
    hashtaker = spawn(f"{name}-hashtaker", ["hashtaker", "--key", f"{RUN}/keys/buyer.key", "--find", RELAY_URL, "--expect-node", lab.pubkey(d.SELLER),
                                    "--found-out", f"{RUN}/{name}-found.json", "--upstream", f"127.0.0.1:{POOL}", "--user", "buyer.rented",
                                    "--signer", d.SOCK, "--task", "hashrate", *caps, "--rental", f"rt-{name}",
                                    "--idle-s", "15", "--report", f"{RUN}/{name}-buyer.json", *extra])
    time.sleep(2)
    miners = [spawn(f"{name}-miner{i}", ["standin-miner", "--pool", f"127.0.0.1:{MINERS}", "--user", f"hasher.m{i}", "--rate", str(rate),
                                         "--bad-every", "9", "--duration-s", str(miner_secs)]) for i in (1, 2)]
    for m in miners:
        m.wait()
    done_ms = int(time.time() * 1000)
    hashtaker.wait(240)
    hashmaker.wait(60)
    time.sleep(1)
    pool.terminate()
    pool.wait(10)

    def load(who: str) -> dict[str, Any]:
        with open(f"{RUN}/{name}-{who}.json") as f:
            return json.load(f)

    return {"hasher": load("hasher"), "buyer": load("buyer"), "pool": load("pool"), "found": load("found"), "listing": load("listing"), "done_ms": done_ms}


def main() -> int:
    t0 = time.time()
    try:
        setup()
        print(f"lab up in {time.time() - t0:.0f} s", flush=True)
        inv0 = d.seller_invoices()
        pay0 = d.buyer_payments()
        r = rental("paid", None, 70, 1.5)
        hz, bz = r["hasher"], r["buyer"]
        lk = r["found"]["listing"]
        hashmaker_pub = subprocess.run([f"{BIN}/xbt-hashlink", "pubkey", f"{RUN}/keys/hasher.key"], check=True, capture_output=True, text=True).stdout.strip()
        check("listing: found on the relay, the hashmaker's link key, the link opened to the address it names",
              lk["link"]["key"] == hashmaker_pub and lk["link"]["addr"] == f"127.0.0.1:{LINK}" and hz["rental"] == "rt-paid"
              and r["found"]["event"] == r["listing"]["event"]["id"],
              {"found": r["found"]["event"], "author": r["found"]["author"], "link": lk["link"], "refused": r["found"]["refused"]})
        paid = hz["paid"]
        oks = [p for p in bz["pays"] if p.get("ok")]
        REPORT["paid_pays"] = bz["pays"]
        check("paid: every finished slice paid once through the wallet", paid >= 6 and len(oks) == paid == len(hz["slicesDone"]) and not bz["payFailed"],
              {"hashmaker paid": paid, "wallet ok": len(oks), "slices done": len(hz["slicesDone"]), "pay ms": [p["ms"] for p in bz["pays"]]})
        check("paid: each receipt equals the hashmaker's count, meters equal", hz["receiptsAgree"] == paid and hz["receiptsDisagree"] == 0 and hz["meter"] == bz["meter"],
              {"agree": hz["receiptsAgree"], "meter": hz["meter"]})
        priced = sum(int(p["wallet"].get("price_msat", 0)) for p in oks)
        last_w = oks[-1]["wallet"] if oks else {}
        spent = int(last_w.get("credited_msat", 0)) - int(last_w.get("balance_msat", 0))
        rails = sorted({p["wallet"].get("rail") for p in oks})
        held_used = [p["slice"] for p in oks if int(p["wallet"].get("tickets_released", 0)) > 0 and int(p["wallet"].get("tickets_prepaid", 0)) == 0]
        prepaid_used = [p["slice"] for p in oks if int(p["wallet"].get("tickets_prepaid", 0)) > 0]
        check("paid: the gateway spent exactly slices x price, on a prepaid ticket and then held ones",
              priced == spent == paid * PRICE_MSAT and rails == ["ticket"] and prepaid_used == [1] and held_used,
              {"priced_msat": priced, "spent_msat": spent, "expected_msat": paid * PRICE_MSAT, "rails": rails,
               "prepaid ticket at slice": prepaid_used, "held ticket released at slices": held_used,
               "moved_sats": sum(int(p["wallet"].get("charged_sats", 0)) for p in oks)})
        inv1 = d.seller_invoices()
        pay1 = d.buyer_payments()
        new_inv = {h: i for h, i in inv1.items() if h not in inv0}
        new_pay = {h: p for h, p in pay1.items() if h not in pay0}
        settled = [i for i in new_inv.values() if i["state"] == "SETTLED"]
        REPORT["paid_tickets"] = [{"hash": h, "state": i["state"], "value_msat": i.get("value_msat"), "paid_msat": i.get("amt_paid_msat")} for h, i in new_inv.items()]
        REPORT["paid_payments"] = [{"hash": h, "status": p["status"], "value_msat": p["value_msat"], "fee_msat": p["fee_msat"]} for h, p in new_pay.items()]
        settled_hashes = [h for h, i in new_inv.items() if i["state"] == "SETTLED"]
        check("paid: the seller's node settled what the hashtaker's node paid (more than one ticket)",
              len(settled) >= 2 and all(new_pay.get(h, {}).get("status") == "SUCCEEDED" for h in settled_hashes),
              {"tickets": REPORT["paid_tickets"], "fees_msat": sum(int(p["fee_msat"]) for p in new_pay.values())})
        REPORT["wallet_status"] = d.signer("ticket_status")
        # how the wallet sized the session (its pool of held tickets, and why none, if none)
        opened = []
        for name in sorted(os.listdir(f"{d.WALLET}/.run")):
            try:
                with open(f"{d.WALLET}/.run/{name}", errors="replace") as f:
                    opened += [line.strip()[:600] for line in f if "ticket_open" in line]
            except (IsADirectoryError, OSError):
                pass
        REPORT["wallet_ticket_open"] = opened
        last = max(p["atMs"] for p in bz["pays"])
        stopped = [e for e in bz["events"] if e["ev"] == "wallet session stopped"]
        check("no-hash: nothing paid after the miners stopped, the wallet's session stopped, nothing held",
              last <= r["done_ms"] + 5000 and bz["closed"] == "no accepted work" and stopped and d.held() == 0,
              {"last pay before miners stopped ms": r["done_ms"] - last, "closed": bz["closed"], "stop": stopped[:1], "held": d.held()})

        r = rental("unpaid", 3, 90, 1.5)
        hz, bz = r["hasher"], r["buyer"]
        st = hz["stopped"] or {}
        past = int(st.get("work", "0")) - 4 * SLICE_WORK
        REPORT["unpaid_pays"] = bz["pays"]
        check("unpaid: the hashmaker stops within one slice past the unpaid slice",
              st.get("reason") == "unpaid" and hz["paid"] == 3 and past <= SLICE_WORK,
              {"stopped": st.get("reason"), "paid": hz["paid"], "slices past": max(past, 0) / SLICE_WORK,
               "stop after slice 4 done ms": st.get("atMs", 0) - (hz["slicesDone"][3]["atMs"] if len(hz["slicesDone"]) > 3 else 0)})
        oks = [p for p in bz["pays"] if p.get("ok")]
        check("unpaid: the wallet paid 3 slices and no more", len(oks) == 3 and sum(int(p["wallet"].get("price_msat", 0)) for p in oks) == 3 * PRICE_MSAT,
              {"pays": [(p["slice"], p.get("ok")) for p in bz["pays"]]})

        # a rental smaller than the shop's ticket, from no credit at the second gateway
        inv0, pay0 = d.seller_invoices(), d.buyer_payments()
        # the hashtaker's own call with the old caps (max_sats = the budget, no charge cap): no ticket fits
        old = d.signer("xbt402_pay", {"url": f"{ORIGIN2}/hashrate/rt-old/1", "method": "POST", "body": "{}",
                                      "max_sats": SMALL_BUDGET_SATS, "task": "hashrate"})
        old.pop("untrusted_provider_response", None)
        moved = {h: p["status"] for h, p in d.buyer_payments().items() if h not in pay0}
        check("small: with the old caps (max_sats = the 500-sat budget) a slice from no credit is refused, nothing paid",
              old.get("verdict") != "allow" and int(old.get("charged_sats", 0)) == 0 and not moved and d.held() == 0,
              {"verdict": old.get("verdict"), "rule": old.get("rule"), "reason": str(old.get("reason"))[:200],
               "charged_sats": old.get("charged_sats"), "payments": moved})
        expect = SMALL_BUDGET_SATS * 1000 // PRICE_MSAT
        r = rental("small", None, 70, 1.5, origin=ORIGIN2, caps=("--budget-sats", str(SMALL_BUDGET_SATS)))
        hz, bz = r["hasher"], r["buyer"]
        oks = [p for p in bz["pays"] if p.get("ok")]
        REPORT["small_pays"] = bz["pays"]
        paid = hz["paid"]
        check("small: every slice of the budget paid once through the wallet, then the rental stopped at its budget",
              paid == len(oks) == expect and not bz["payFailed"] and bz["closed"] == "budget used up"
              and hz["receiptsAgree"] == paid and hz["receiptsDisagree"] == 0 and hz["meter"] == bz["meter"],
              {"hashmaker paid": paid, "wallet ok": len(oks), "expected": expect, "closed": bz["closed"],
               "agree": hz["receiptsAgree"], "meter": hz["meter"]})
        priced = sum(int(p["wallet"].get("price_msat", 0)) for p in oks)
        last_w = oks[-1]["wallet"] if oks else {}
        credited, balance = int(last_w.get("credited_msat", 0)), int(last_w.get("balance_msat", 0))
        spent = credited - balance
        moved_sats = sum(int(p["wallet"].get("charged_sats", 0)) for p in oks)
        inv1, pay1 = d.seller_invoices(), d.buyer_payments()
        new_inv = {h: i for h, i in inv1.items() if h not in inv0}
        new_pay = {h: p for h, p in pay1.items() if h not in pay0}
        settled = {h: i for h, i in new_inv.items() if i["state"] == "SETTLED"}
        succeeded = {h: p for h, p in new_pay.items() if p["status"] == "SUCCEEDED"}
        node_out_msat = sum(int(p["value_msat"]) + int(p["fee_msat"]) for p in succeeded.values())
        REPORT["small_tickets"] = [{"hash": h, "state": i["state"], "value_msat": i.get("value_msat"), "paid_msat": i.get("amt_paid_msat")} for h, i in new_inv.items()]
        REPORT["small_payments"] = [{"hash": h, "status": p["status"], "value_msat": p["value_msat"], "fee_msat": p["fee_msat"]} for h, p in new_pay.items()]
        check("small: slices x price = the wallet's spent = the seller's signed spent; one whole ticket bought at slice 1, "
              "the credit left = the ticket - spent",
              priced == spent == paid * PRICE_MSAT and credited == TICKET_MSAT and balance == TICKET_MSAT - spent
              and [p["slice"] for p in oks if int(p["wallet"].get("tickets_prepaid", 0)) > 0] == [1]
              and all(int(p["wallet"].get("price_msat", 0)) <= SMALL_BUDGET_SATS * 1000 for p in oks),
              {"slices x price msat": paid * PRICE_MSAT, "wallet priced msat": priced, "seller's signed spent msat": spent,
               "credited msat": credited, "credit left msat": balance, "ticket msat": TICKET_MSAT})
        check("small: the seller's node settled exactly the one ticket the wallet's node paid; what left the wallet is that "
              "ticket and its fee, within the 2,000 sat a slice may move; nothing held",
              len(settled) == 1 and list(settled) == list(succeeded) and int(next(iter(settled.values()))["amt_paid_msat"]) == TICKET_MSAT
              and node_out_msat <= moved_sats * 1000 < node_out_msat + 1000 and moved_sats <= 2_000 and d.held() == 0,
              {"settled": len(settled), "succeeded": len(succeeded), "node out msat": node_out_msat, "wallet booked sats": moved_sats,
               "other tickets": sorted({i["state"] for h, i in new_inv.items() if h not in settled}), "held": d.held()})
        check("small: the rental's report (the wallet app's card) says what left the wallet and what stays with the seller as credit",
              bz.get("walletMovedSats") == moved_sats and bz.get("leftWithSellerMsat") == balance,
              {"walletMovedSats": bz.get("walletMovedSats"), "leftWithSellerMsat": bz.get("leftWithSellerMsat"),
               "wallet booked sats": moved_sats, "credit left msat": balance})
    except (lab.LabError, OSError, KeyError, IndexError, ValueError, subprocess.TimeoutExpired) as e:
        check("ran to its end", False, f"{type(e).__name__}: {e}")
    finally:
        for p in PROCS + list(d.PROCS.values()):
            if p.poll() is None:
                p.terminate()
    REPORT["seconds"] = round(time.time() - t0)
    with open(os.path.join(OUT, "p2p_hash_regtest.json"), "w") as f:
        json.dump(REPORT, f, indent=1)
    ok = all(c["ok"] for c in REPORT["checks"])
    print(f"p2p_hash_regtest: {sum(c['ok'] for c in REPORT['checks'])} of {len(REPORT['checks'])} checks passed, {REPORT['seconds']} s", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
