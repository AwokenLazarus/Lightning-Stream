"""p2p-hash on regtest with real tickets (scripts/p2p_hash_regtest.sh).

The ticket lab's three Lightning Fork nodes (lf1 the hashtaker, lf2 a hop, lf3 the hashmaker's node), the
wallet's signer on lf1 with a "hashrate" task, the hashmaker's gateway beside lf3 with one route,
/hashrate/, passed to the hashmaker's paid-slice endpoint, a stand-in Nostr relay, a stand-in pool as
the hashtaker's gateway and stand-in miners. The hashmaker publishes its listing to the relay; the hashtaker
finds it there, opens the link to the endpoint it names, and pays slice by slice through the
wallet, ahead of the work: one paid request per slice, on prepaid tickets sized to the step the rental has
earned (the hashrate task is a rental task, as the starter rules make it on mainnet). The stand-ins hash the chain's real share format at a tiny difficulty, and both sides prove each share.

Checks:
  listing   found on the relay, its link key the hashmaker's, the link opened to the address it names
  paid      every slice paid once through the wallet, ahead of its work; proven work never past what's paid;
            the gateway charging exactly slices x price; both sides' proven counts equal; held tickets used;
            the seller's node settled what the hashtaker's node paid
  no-hash   the miners stop: no payment after that, the wallet's session stopped, nothing left held
  unpaid    the hashtaker stops paying after slice 3: the next share waits on the clock and goes no further, the
            hashmaker stops, and the gateway charges nothing more
  small     a direct call with max_sats 500 from no credit is refused, nothing paid; and a rental whose budget
            (500 sat) is under the smallest ticket (546 sat) is refused before any work, nothing paid, the
            renter told why
  drop      a rental at a third gateway, from no credit, whose link loses what the hashmaker sends for a
            stretch, then is down for 4 s, with a slice paid while it's down. At the resume the hashmaker sends
            its recent shares again, and the hashtaker counts those it never read, once each: both proven
            counts equal; every slice paid once; slices x price = the wallet's spent = what the hashmaker earned;
            the seller's node settled what the wallet's node paid, and what left the wallet is that and its
            fees; nothing held
  reprice   a new price while a rental goes on, with the hashmaker's real app: the wallet app (its Sell page and
            Sell -> Hashrate, which re-prices every minute), the shop's gateway under xbt-supervise as the images run
            it, and the hashmaker service on its settings file. The owner's new price waits while the rental goes on:
            the rental pays the old price, no new rental starts, the gateway's route keeps the old price and the
            gateway does not restart. Once the rental ends, the app writes the new terms and route, the gateway
            restarts with the new price, and the next rental pays it. (P2P_HASH_ONLY=reprice runs only this.)
            The price is the owner's fixed one (regtest's difficulty is not a market), and the settings file is
            written as the Save button writes it but with the lab's small slice (Save refuses one under 2^32).
  slow      issue #64: a fourth gateway, behind a road that holds each ticket buy after the first for
            P2P_HASH_SLOW_BUY_S (11 s, so a buy takes about 12 s, as over several Lightning hops), a rental at 400 sat a
            slice from a miner whose 30 s of output (480 sat) is under the 546 sat step, for P2P_HASH_SLOW_SECS (960 s).
            Before 0.2.13 the renter bought only once under 142 sat was ahead and the hashmaker waited 10 s for it, so
            the rental ended unpaid within minutes; now it runs to its end, buys started ahead and the slices after them
            paid from credit, each slice paid once, the money exact, inside its task's budget.
            (P2P_HASH_ONLY=slow runs only this.)
  solo, pool  real money as above, on real work: a real DATUM gateway on a real Knots regtest of its own, real
            stratum-grind through the hashmaker. Every share wins on regtest, so each block is a real masked
            one: its key isn't null, its clear_bits equal the share's bits, and its id is the raw hash XOR
            the mask, recomputed here from the header. The hashtaker holds each job to what the gateway
            opens on its local API. Pool mode goes through `primed` too. These need binaries the repo doesn't
            carry (P2P_HASH_GATEWAYS, default ~/xbt-rnd/hash-gateways: datum_gateway-blind, bitcoind,
            bitcoin-cli, stratum-grind, primed-main; P2P_HASH_PRIMED for a `primed` that takes gateway-held keys,
            P2P_HASH_PRIMED_KEYS=1 once it does). Without them they are reported as skipped, and not passed.
"""
from __future__ import annotations

import base64
import glob
import hashlib
import http.client
import json
import os
import re
import secrets
import subprocess
import socket
import urllib.parse
import sys
import threading
import time
from typing import Any, Callable

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
# a third, for the rental whose link drops, and the road its link takes
GW3, ROAD = B + 11, B + 12
ORIGIN3 = f"http://127.0.0.1:{GW3}"
# the reprice check: the hashmaker's app, its gateway (under xbt-supervise), the hashmaker service, its miners' fallback
# pool and the rentals' pool
RP_GW, RP_SLICES, RP_LINK, RP_MINERS, RP_CONTROL, RP_UI, RP_FALLBACK, RP_POOL = (B + 29 + i for i in range(8))
RP_ORIGIN = f"http://127.0.0.1:{RP_GW}"
RP_PRICES = (100, 150)  # sats a slice: the price in force, and the owner's new one
SMALL_BUDGET_SATS = 500
RELAY_URL = f"ws://127.0.0.1:{RELAY}"
DIFF = 2**-20  # about 4096 tries a share, in the chain's real share format
SHARE = 4096
SLICE_WORK = 10 * SHARE
PRICE_MSAT = 100_000
TICKET_MSAT = 1_000_000  # above the wallet's floor for a held ticket on these channels (no anchors), at its default most
GRACE_MS = 8000
# the Lightning rail's fee limit on a ticket of TICKET_MSAT, as the wallet books it on a held one (1,015 sat)
HELD_FEE_LIMIT_MSAT = 15_000
HG = os.environ.get("P2P_HASH_GATEWAYS", os.path.expanduser("~/xbt-rnd/hash-gateways"))
# the Stream Gateway the image ships (scripts/datum_gateway_build.sh), else the lab's own build of the same patch
DATUM_GATEWAY = os.environ.get("P2P_HASH_DATUM_GATEWAY") or next(
    (p for p in (os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../dist/datum/x86_64-linux-musl/xbt-datum-gateway"),)
     if os.path.exists(p)), f"{HG}/datum_gateway-blind")
REAL_SECS = int(os.environ.get("P2P_HASH_REAL_SECS", "360"))
# the longest coinbase tag Your gateway takes (60 printable ASCII characters), written as the app writes it
OWNER_TAG = os.environ.get("P2P_HASH_OWNER_TAG", "Owner's own tag: 60 chars, ASCII /solo/ ~!@#$%^&*()_+{}|:<>?")
REAL_BASE = B + 13
# issue #64's check: a fourth gateway, and the road in front of it that holds its ticket buys (its public address)
GW4, SLOW_ROAD = B + 37, B + 38
ORIGIN4 = f"http://127.0.0.1:{SLOW_ROAD}"
SLOW_BUY_S = float(os.environ.get("P2P_HASH_SLOW_BUY_S", "11"))
SLOW_SECS = int(os.environ.get("P2P_HASH_SLOW_SECS", "960"))
SLOW_PRICE_MSAT = 400_000
# two miners at 0.2 shares a second: 0.04 slices a second, 16 sat a second at 400 sat, 480 sat in 30 s (under 546)
SLOW_RATE = 0.2
SLOW_BUDGET_SATS = 40_000
# the top-up check: the renter's own service (the app's renter, with its control page), and the task whose signed budget
# a rental's top-up can't pass
TOPUP_CONTROL = B + 39
TOPUP_TASK_SATS = 1_200
REPORT: dict[str, Any] = {"checks": []}
PROCS: list[subprocess.Popen[bytes]] = []


def check(name: str, ok: bool, saw: Any) -> None:
    REPORT["checks"].append({"check": name, "ok": bool(ok), "saw": saw})
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {json.dumps(saw)[:400]}", flush=True)


def policy() -> dict[str, Any]:
    pk = lab.pubkey(d.SELLER)
    return {
        "allowlist": [ORIGIN, ORIGIN2, ORIGIN3, RP_ORIGIN, ORIGIN4],
        "counterparties": {ORIGIN: {"ln_node": pk}, ORIGIN2: {"ln_node": pk}, ORIGIN3: {"ln_node": pk}, RP_ORIGIN: {"ln_node": pk}, ORIGIN4: {"ln_node": pk}},
        "max_per_tx_sats": 10_000,
        "daily_budget_sats": 200_000,
        "weekly_budget_sats": 400_000,
        "per_counterparty_cap_sats": 100_000,
        "velocity_max": 1_000,
        "velocity_window_s": 3600,
        "human_threshold_sats": 50_000,
        "split_window_s": 0,
        "regtest_mine": False,
        "anchor_interval_s": 3600,
        "ln": {"enabled": True, "split_height": d.SPLIT},
        # the hashrate task as the starter rules sign it on mainnet: a rental task, prepaid tickets of at most 10,000 sat
        "tickets": {"enabled": True, "tasks": {"hashrate": {"budget_sats": 50_000, "rental": {"max_ticket_sats": 10_000, "max_sends_per_hour": 600}},
                                               # issue #64's long rental, on a budget of its own
                                               "hashrate-slow": {"budget_sats": SLOW_BUDGET_SATS, "rental": {"max_ticket_sats": 10_000, "max_sends_per_hour": 600}},
                                               # the top-up check's second rental: its owner's budget is below what its top-up asks
                                               "hashrate-topup": {"budget_sats": TOPUP_TASK_SATS, "rental": {"max_ticket_sats": 10_000, "max_sends_per_hour": 600}}}},
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
        # as the app writes a hashmaker's shop: tickets down to the dust floor, and a larger top ticket on the hashrate route
        "tickets": {"ticket_msat": TICKET_MSAT, "min_ticket_msat": 546_000, "max_tickets": 2, "ticket_blocks": 40, "settle": ["on-use", "on-arrival"]},
        "routes": [{"path": "/hashrate/", "upstream": f"http://127.0.0.1:{SLICES}", "methods": ["POST"], "max_body": 8192,
                    "price": {"request_msat": PRICE_MSAT}, "top_ticket_msat": 100_000_000}],
    }
    cfg2 = {**cfg, "listen": f"127.0.0.1:{GW2}", "public_url": ORIGIN2, "state_dir": f"{RUN}/state-gateway2"}
    cfg3 = {**cfg, "listen": f"127.0.0.1:{GW3}", "public_url": ORIGIN3, "state_dir": f"{RUN}/state-gateway3"}
    # issue #64's: reached through the road that holds its ticket buys, at issue #64's price a slice
    cfg4 = {**cfg, "listen": f"127.0.0.1:{GW4}", "public_url": ORIGIN4, "state_dir": f"{RUN}/state-gateway4",
            "routes": [{**cfg["routes"][0], "price": {"request_msat": SLOW_PRICE_MSAT}}]}
    for name, c in (("gateway", cfg), ("gateway2", cfg2), ("gateway3", cfg3), ("gateway4", cfg4)):
        with open(f"{RUN}/{name}.json", "w") as f:
            json.dump(c, f, indent=1)
        with open(f"{RUN}/{name}.log", "ab") as log:
            PROCS.append(subprocess.Popen([f"{BIN}/xbt-gateway", f"{RUN}/{name}.json"], stdout=log, stderr=log))
    for port in (GW, GW2, GW3, GW4):
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


def spawn(name: str, args: list[str], env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
    log = open(f"{RUN}/{name}.log", "ab")
    p = subprocess.Popen([f"{BIN}/xbt-hashlink", *args], stdout=log, stderr=log, env=env)
    PROCS.append(p)
    return p


class LatePool:
    """Between the gateway and primed: holds what the pool sends for LATE seconds after each new block, so the
    gateway's coinbaser (5 s timeout) is late and its first full jobs go out on coinbase[0]; the late coinbaser then
    rewrites the job's coinbases in place (P2P_HASH_LATE_COINBASER=1)."""

    LATE = 7.0

    def __init__(self, listen: int, to: int, height: Any) -> None:
        self.to, self.height, self.changed, self.held = to, height, 0.0, 0
        self.server = socket.create_server(("127.0.0.1", listen))
        threading.Thread(target=self.watch, daemon=True).start()
        threading.Thread(target=self.serve, daemon=True).start()

    def watch(self) -> None:
        last = None
        while True:
            try:
                h = self.height()
            except Exception:  # noqa: BLE001  (the node stopping at the end)
                return
            if last is not None and h != last:
                self.changed = time.time()
            last = h
            time.sleep(0.3)

    def serve(self) -> None:
        while True:
            a, _ = self.server.accept()
            b = socket.create_connection(("127.0.0.1", self.to))
            threading.Thread(target=self.pump, args=(a, b, False), daemon=True).start()
            threading.Thread(target=self.pump, args=(b, a, True), daemon=True).start()

    def pump(self, x: socket.socket, y: socket.socket, from_pool: bool) -> None:
        try:
            while data := x.recv(65536):
                wait = self.changed + self.LATE - time.time()
                if from_pool and wait > 0:
                    self.held += 1
                    time.sleep(wait)
                y.sendall(data)
        except OSError:
            pass
        for z in (x, y):
            try:
                z.close()
            except OSError:
                pass


class Road:
    """A TCP relay on the hashtaker's way to the link: it can lose what the hashmaker sends, close what
    it carries, and refuse what comes next."""

    def __init__(self, listen: int, to: int) -> None:
        self.to, self.lose, self.refuse, self.open = to, False, False, []
        self.server = socket.create_server(("127.0.0.1", listen))
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self) -> None:
        while True:
            a, _ = self.server.accept()
            if self.refuse:
                a.close()
                continue
            b = socket.create_connection(("127.0.0.1", self.to))
            self.open += [a, b]
            threading.Thread(target=self.pump, args=(a, b, False), daemon=True).start()
            threading.Thread(target=self.pump, args=(b, a, True), daemon=True).start()

    def pump(self, x: socket.socket, y: socket.socket, losable: bool) -> None:
        try:
            while data := x.recv(65536):
                if not (losable and self.lose):
                    y.sendall(data)
        except OSError:
            pass
        for s in (x, y):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def cut(self) -> None:
        for s in self.open:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.open, self.lose = [], False


def rental(name: str, stop_after: int | None, miner_secs: int, rate: float, origin: str = ORIGIN,
           caps: tuple[str, ...] = ("--max-sats", "1500"), link_public: int = LINK, job_ms: int = 1000,
           reconnect: bool = False, during: Callable[[], None] | None = None, price_msat: int = PRICE_MSAT, task: str = "hashrate",
           idle_s: int = 15) -> dict[str, Any]:
    pool = spawn(f"{name}-pool", ["standin-pool", "--listen", f"127.0.0.1:{POOL}", "--diff", str(DIFF), "--job-ms", str(job_ms), "--report", f"{RUN}/{name}-pool.json"])
    t = ["--slice-work", str(SLICE_WORK), "--price-msat", str(price_msat), "--grace-ms", str(GRACE_MS)]
    hashmaker = spawn(f"{name}-hashmaker", ["hashmaker", "--key", f"{RUN}/keys/hasher.key", "--miners", f"127.0.0.1:{MINERS}", "--link", f"127.0.0.1:{LINK}",
                                      "--slices", f"127.0.0.1:{SLICES}", *t, "--report", f"{RUN}/{name}-hasher.json",
                                      "--relays", RELAY_URL, "--nostr-key", f"{RUN}/keys/nostr.key", "--name", "regtest hashmaker",
                                      "--link-public", f"127.0.0.1:{link_public}", "--pay-url", f"{origin}/hashrate", "--pay-node", lab.pubkey(d.SELLER),
                                      "--hashrate-hs", "4000000000000", "--listing-out", f"{RUN}/{name}-listing.json"])
    lab.wait("the hashmaker's listing", 30, lambda: os.path.exists(f"{RUN}/{name}-listing.json"), every=0.2)
    time.sleep(0.5)
    extra = ["--stop-paying-after", str(stop_after)] if stop_after is not None else []
    hashtaker = spawn(f"{name}-hashtaker", ["hashtaker", "--key", f"{RUN}/keys/buyer.key", "--find", RELAY_URL, "--expect-node", lab.pubkey(d.SELLER),
                                    "--found-out", f"{RUN}/{name}-found.json", "--upstream", f"127.0.0.1:{POOL}", "--user", "buyer.rented", "--allow-unblinded", "1",
                                    "--signer", d.RENTER_SOCK, "--task", task, *caps, "--rental", f"rt-{name}",
                                    "--idle-s", str(idle_s), "--report", f"{RUN}/{name}-buyer.json", *extra])
    time.sleep(2)
    miners = [spawn(f"{name}-miner{i}", ["standin-miner", "--pool", f"127.0.0.1:{MINERS}", "--user", f"hasher.m{i}", "--rate", str(rate),
                                         "--bad-every", "9", "--duration-s", str(miner_secs), *(["--reconnect", "1"] if reconnect else [])]) for i in (1, 2)]
    if during is not None:
        during()
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


def topup_check() -> None:
    n = len(PROCS)
    try:
        topup_run()
    finally:
        # whatever it left running (a check that stopped early), so the next check has its ports
        for q in PROCS[n:]:
            if q.poll() is None:
                q.terminate()
        for q in PROCS[n:]:
            try:
                q.wait(10)
            except subprocess.TimeoutExpired:
                q.kill()
        for src in sorted(glob.glob(f"{RUN}/topup*")):
            base = os.path.basename(src)
            if base.endswith((".log", ".json")):
                try:
                    with open(src, "rb") as f, open(f"{OUT}/p2p_hash_{base}", "wb") as g:
                        g.write(f.read())
                except OSError:
                    pass


def topup_run() -> None:
    """Budget and time added to a rental going on (POST /topup, the app's Add to this rental), through the app's own renter
    service and the wallet's signer: the rental pays on past its first budget and never past the sum, a top-up sent again
    adds nothing, none is taken once it ended, and the owner's signed budget for the task still stops it."""
    token_path = f"{RUN}/topup-token"
    with open(token_path, "w") as f:
        f.write(secrets.token_hex(32))
    with open(token_path) as f:
        token = f.read().strip()

    def renter(method: str, path: str, body: dict[str, Any] | None = None, auth: bool = True) -> tuple[int, dict[str, Any]]:
        c = http.client.HTTPConnection("127.0.0.1", TOPUP_CONTROL, timeout=120)
        try:
            headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if auth else {})}
            c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def live(rid: str) -> dict[str, Any]:
        _, st = renter("GET", "/status")
        return next((x for x in st.get("rentals", []) if x.get("rental") == rid), {})

    pool = spawn("topup-pool", ["standin-pool", "--listen", f"127.0.0.1:{POOL}", "--diff", str(DIFF), "--job-ms", "1000", "--report", f"{RUN}/topup-pool.json"])
    hashmaker_pub = subprocess.run([f"{BIN}/xbt-hashlink", "pubkey", f"{RUN}/keys/hasher.key"], check=True, capture_output=True, text=True).stdout.strip()

    def market(tag: str) -> list[subprocess.Popen[bytes]]:
        """The lab's hashmaker (it serves one rental, then ends) and its two miners, its listing fresh on the relay."""
        if os.path.exists(f"{RUN}/topup-{tag}-listing.json"):
            os.remove(f"{RUN}/topup-{tag}-listing.json")
        t = ["--slice-work", str(SLICE_WORK), "--price-msat", str(PRICE_MSAT), "--grace-ms", str(GRACE_MS)]
        hm = spawn(f"topup-{tag}-hashmaker", ["hashmaker", "--key", f"{RUN}/keys/hasher.key", "--miners", f"127.0.0.1:{MINERS}", "--link", f"127.0.0.1:{LINK}",
                                              "--slices", f"127.0.0.1:{SLICES}", *t, "--report", f"{RUN}/topup-{tag}-hasher.json",
                                              "--relays", RELAY_URL, "--nostr-key", f"{RUN}/keys/nostr.key", "--name", "regtest hashmaker",
                                              "--link-public", f"127.0.0.1:{LINK}", "--pay-url", f"{ORIGIN2}/hashrate", "--pay-node", lab.pubkey(d.SELLER),
                                              "--hashrate-hs", "4000000000000", "--listing-out", f"{RUN}/topup-{tag}-listing.json"])
        lab.wait("the hashmaker's listing", 30, lambda: os.path.exists(f"{RUN}/topup-{tag}-listing.json"), every=0.2)
        time.sleep(0.5)
        return [hm, *(spawn(f"topup-{tag}-miner{i}", ["standin-miner", "--pool", f"127.0.0.1:{MINERS}", "--user", f"hasher.m{i}", "--rate", "1.5",
                                                      "--bad-every", "9", "--duration-s", "300"]) for i in (1, 2))]

    def stop(ps: list[subprocess.Popen[bytes]]) -> None:
        for q in ps:
            if q.poll() is None:
                q.terminate()
        for q in ps:
            try:
                q.wait(10)
            except subprocess.TimeoutExpired:
                q.kill()

    def service(task: str) -> subprocess.Popen[bytes]:
        p = spawn(f"topup-renter-{task}", ["renter", "--key", f"{RUN}/keys/buyer.key", "--control", f"127.0.0.1:{TOPUP_CONTROL}",
                                           "--control-token-file", token_path, "--upstream", f"127.0.0.1:{POOL}", "--allow-unblinded", "1",
                                           "--relays", RELAY_URL, "--signer", d.RENTER_SOCK, "--task", task, "--expect-node", lab.pubkey(d.SELLER),
                                           "--iroh", "off", "--user", "buyer.rented"])
        lab.wait("the renter's control page", 30, lambda: renter("GET", "/status")[1].get("role") == "renter", every=0.5)
        lab.wait("the renter finds the hashmaker's offer", 60,
                 lambda: any(o.get("linkKey") == hashmaker_pub for o in renter("GET", "/offers?fresh=1")[1].get("offers", [])), every=2)
        return p

    def wait_ended(rid: str, secs: int) -> dict[str, Any]:
        lab.wait("the rental ended", secs, lambda: live(rid).get("ended") is True, every=1)
        return live(rid)

    def wallet_moved(x: dict[str, Any]) -> int:
        return sum(int(p.get("wallet", {}).get("charged_sats", 0)) for p in x.get("live", {}).get("pays", []) if p.get("ok"))

    # 1. a rental of six slices' budget, topped up after its second: it pays on past six, never past the sum
    m1 = market("a")
    p1 = service("hashrate")
    no_token = renter("POST", "/topup", {"rental": "x", "addSats": 1}, auth=False)
    check("topup: the control page takes no top-up without its token", no_token[0] == 401, no_token)
    first = 6 * PRICE_MSAT // 1000
    code, v = renter("POST", "/rent", {"linkKey": hashmaker_pub, "miners": 2, "budgetSats": first, "minutes": 10, "once": secrets.token_hex(8)})
    if code != 200:
        check("topup: the rental starts", False, v)
        return
    rid = v["rental"]
    lab.wait("two slices paid", 120, lambda: int(live(rid).get("live", {}).get("paidSlices") or 0) >= 2, every=1)
    mark = secrets.token_hex(8)
    added = 10 * PRICE_MSAT // 1000
    code, v = renter("POST", "/topup", {"rental": rid, "addSats": added, "addMinutes": 5, "once": mark})
    again = renter("POST", "/topup", {"rental": rid, "addSats": added, "addMinutes": 5, "once": mark})
    paid_at = int(live(rid).get("live", {}).get("paidSlices") or 0)
    check("topup: added to the rental going on, once for the form sent twice",
          code == 200 and v.get("budgetSats") == first + added and v.get("minutes") == 15 and again == (200, v) and live(rid).get("budgetSats") == first + added,
          {"answer": v, "again": again, "status budget": live(rid).get("budgetSats"), "paid when added": paid_at})
    lab.wait("paid past the first budget", 180, lambda: int(live(rid).get("live", {}).get("paidSlices") or 0) > 7
             or live(rid).get("ended") is True, every=1)
    renter("POST", "/cut", {"rental": rid})
    x = wait_ended(rid, 60)
    lv = x.get("live", {})
    oks = [p for p in lv.get("pays", []) if p.get("ok")]
    priced = sum(int(p["wallet"].get("price_msat", 0)) for p in oks)
    after = renter("POST", "/topup", {"rental": rid, "addSats": added})
    check("topup: the rental paid on past its first budget, each slice once, never past the sum, no payment refused",
          len(oks) > 6 and priced == len(oks) * PRICE_MSAT <= (first + added) * 1000 and not lv.get("payFailed")
          and wallet_moved(x) <= first + added and lv.get("budgetMsat") == (first + added) * 1000,
          {"paid": len(oks), "priced_msat": priced, "budget_sats": first + added, "wallet moved sats": wallet_moved(x),
           "closed": lv.get("closed"), "payFailed": lv.get("payFailed"), "budgetMsat": lv.get("budgetMsat")})
    check("topup: none taken once the rental ended", after[0] == 409, after)
    stop([p1, *m1])

    # 2. the owner's signed budget for the task (TOPUP_TASK_SATS) is below what the rental and its top-up ask: the wallet
    # stops it there, whatever the rental's own budget says
    m2 = market("b")
    p2 = service("hashrate-topup")
    code, v = renter("POST", "/rent", {"linkKey": hashmaker_pub, "miners": 2, "budgetSats": first, "minutes": 10, "once": secrets.token_hex(8)})
    if code != 200:
        check("topup: the second rental starts", False, v)
        return
    rid = v["rental"]
    lab.wait("a slice paid", 120, lambda: int(live(rid).get("live", {}).get("paidSlices") or 0) >= 1 or live(rid).get("ended") is True, every=1)
    if live(rid).get("ended") is True:
        lv = live(rid).get("live", {})
        check("topup: the second rental pays its first slice", False, {"closed": lv.get("closed"), "pays": lv.get("pays"), "events": lv.get("events", [])[-5:]})
        return
    code, v = renter("POST", "/topup", {"rental": rid, "addSats": 50 * PRICE_MSAT // 1000, "once": secrets.token_hex(8)})
    x = wait_ended(rid, 300)
    lv = x.get("live", {})
    REPORT["topup_task_rental"] = lv
    oks = [p for p in lv.get("pays", []) if p.get("ok")]
    why = " ".join(str(p.get("why", "")) for p in lv.get("pays", []) if p.get("ok") is False)
    check("topup: the owner's signed task budget still stops a topped-up rental: the wallet refuses past it, said as its rules",
          code == 200 and wallet_moved(x) <= TOPUP_TASK_SATS and len(oks) * PRICE_MSAT <= TOPUP_TASK_SATS * 1000 and lv.get("payFailed") is True
          and "wallet" in why.lower(),
          {"topup": v, "paid": len(oks), "wallet moved sats": wallet_moved(x), "task budget": TOPUP_TASK_SATS, "closed": lv.get("closed"), "why": why[:300]})
    stop([p2, *m2, pool])


def drop_check() -> None:
    try:
        drop_run()
    finally:
        # its reports and logs, beside the report (the lab copies only run/*.log and run/*.json back)
        for src in sorted(glob.glob(f"{RUN}/drop*")):
            base = os.path.basename(src)
            if base.endswith((".log", ".json")):
                try:
                    with open(src, "rb") as f, open(f"{OUT}/p2p_hash_{base}", "wb") as g:
                        g.write(f.read())
                except OSError:
                    pass


def drop_run() -> None:
    """The rental whose link drops: real tickets, the real gateway's wait, money on every side."""
    road = Road(ROAD, LINK)
    outage: dict[str, Any] = {"at": 0.0, "lost_from_ms": 0}

    def report(who: str) -> dict[str, Any]:
        for _ in range(100):
            try:
                with open(f"{RUN}/drop-{who}.json") as f:
                    return json.load(f)
            except (OSError, ValueError):
                time.sleep(0.1)
        raise ValueError(f"no report from the {who}")

    def paid_slices() -> int:
        return sum(p.get("ok") is True for p in report("buyer")["pays"])

    def during() -> None:
        # the renter pays its whole step ahead (5 slices at 100 sat) before any miner is on: work proven, not slices
        # paid, says the rental is under way. A loss from the start leaves the hashtaker never hearing of its miners
        lab.wait("two slices' worth proven before the drop", 120,
                 lambda: paid_slices() >= 3 and int(report("buyer")["meter"]["work"]) >= 2 * SLICE_WORK, every=0.2)
        # what the hashmaker sends is lost for a stretch: shares its side counted and the hashtaker's never read. The
        # link is cut only once the hashmaker has sent a share into the loss, so the drop always lands with one in flight
        road.lose = True
        outage["lost_from_ms"] = int(time.time() * 1000)

        def sent_into_the_loss() -> int:
            h = report("hasher")
            shares = (h.get("rentals") or [h])[0].get("provenShares", [])
            return sum(1 for x in shares if int(x["atMs"]) >= outage["lost_from_ms"])

        lab.wait("a share sent into the loss", 30, lambda: sent_into_the_loss() >= 1, every=0.2)
        outage["sent_into_the_loss"] = sent_into_the_loss()
        road.refuse = True
        outage["at"] = time.time()
        road.cut()
        time.sleep(4)
        road.refuse = False

    inv0, pay0 = d.seller_invoices(), d.buyer_payments()
    r = rental("drop", None, 70, 1.5, origin=ORIGIN3, link_public=ROAD, job_ms=5000, reconnect=True, during=during)
    hz, bz = r["hasher"], r["buyer"]
    oks = [p for p in bz["pays"] if p.get("ok")]
    REPORT["drop_pays"] = bz["pays"]
    REPORT["drop_events"] = [e for e in hz["events"] if e["ev"] not in ("locked", "paid slice", "miner", "miner taken")]
    paid = hz["paid"]
    evs = hz["events"]
    backs = [e["atMs"] for e in evs if e["ev"] == "hashtaker back, rental resumed"]
    after = [e["slice"] for e in evs if e["ev"] == "paid slice" and backs and e["atMs"] > backs[0]]
    check("drop: the link dropped with shares lost, the hashtaker counted them when they were sent again, once each, and the rental carried on",
          len(backs) == 1 and bz["resentCounted"] >= 1 and bz["meter"]["repeats"] == 0 and len(after) >= 2 and bz["closed"] == "no proven work",
          {"resumed": len(backs), "shares sent into the loss": outage.get("sent_into_the_loss"), "shares counted from a resend": bz["resentCounted"],
           "the hashtaker's repeats": bz["meter"]["repeats"], "slices paid after the resume": after, "closed": bz["closed"], "stopped": (hz.get("stopped") or {}).get("reason")})
    slices = [p["slice"] for p in oks]
    proven = lambda m: (m["work"], m["proven"])  # noqa: E731
    check("drop: every slice paid once, both proven counts equal, none past what's paid",
          paid == len(oks) == len(set(slices)) and slices == list(range(1, paid + 1)) and proven(hz["meter"]) == proven(bz["meter"])
          and int(hz["meter"]["work"]) <= paid * SLICE_WORK and not bz["payFailed"],
          {"hashmaker paid": paid, "wallet ok": len(oks), "meter": hz["meter"], "the hashtaker's meter": bz["meter"], "paid work": paid * SLICE_WORK})
    priced = sum(int(p["wallet"].get("price_msat", 0)) for p in oks)
    last_w = oks[-1]["wallet"] if oks else {}
    credited, balance = int(last_w.get("credited_msat", 0)), int(last_w.get("balance_msat", 0))
    moved_sats = sum(int(p["wallet"].get("charged_sats", 0)) for p in oks)
    check("drop: slices x price = the wallet's spent = what the hashmaker earned",
          priced == credited - balance == paid * PRICE_MSAT == hz["earnedMsat"],
          {"slices x price msat": paid * PRICE_MSAT, "wallet priced msat": priced, "seller's signed spent msat": credited - balance,
           "hashmaker earned msat": hz["earnedMsat"], "credited msat": credited, "credit left msat": balance})
    inv1, pay1 = d.seller_invoices(), d.buyer_payments()
    new_inv = {h: i for h, i in inv1.items() if h not in inv0}
    new_pay = {h: p for h, p in pay1.items() if h not in pay0}
    settled = {h: i for h, i in new_inv.items() if i["state"] == "SETTLED"}
    succeeded = {h: p for h, p in new_pay.items() if p["status"] == "SUCCEEDED"}
    node_out_msat = sum(int(p["value_msat"]) + int(p["fee_msat"]) for p in succeeded.values())
    node_in_msat = sum(int(i["amt_paid_msat"]) for i in settled.values())
    REPORT["drop_tickets"] = [{"hash": h, "state": i["state"], "value_msat": i.get("value_msat"), "paid_msat": i.get("amt_paid_msat")} for h, i in new_inv.items()]
    REPORT["drop_payments"] = [{"hash": h, "status": p["status"], "value_msat": p["value_msat"], "fee_msat": p["fee_msat"]} for h, p in new_pay.items()]
    # the wallet books a released held ticket at its fee limit, not its fee (docs/LIMITS.md): what it booked over what
    # its node paid is at most the rail's limit for each, the same as in the rental with no drop
    held_released = sum(1 for p in oks if int(p["wallet"].get("tickets_released", 0)) > 0 and int(p["wallet"].get("tickets_prepaid", 0)) == 0)
    over_msat = moved_sats * 1000 - node_out_msat
    check("drop: the seller's node settled what the wallet's node paid and what the seller credited; what left the wallet is that and its fees, "
          "booked within the fee limit of each held ticket; nothing held",
          settled and set(settled) == set(succeeded) and node_in_msat == credited and node_out_msat == node_in_msat + sum(int(p["fee_msat"]) for p in succeeded.values())
          and 0 <= over_msat <= 1000 + held_released * HELD_FEE_LIMIT_MSAT and d.held() == 0,
          {"settled": len(settled), "succeeded": len(succeeded), "seller's node in msat": node_in_msat, "credited msat": credited, "wallet's node out msat": node_out_msat,
           "wallet booked sats": moved_sats, "booked over the node msat": over_msat, "held tickets released": held_released, "held": d.held(),
           "stopped": [e for e in bz["events"] if e["ev"] == "wallet session stopped"][:1]})


class SlowBuys:
    """In front of a gateway: holds the answer to each request that buys a ticket (`POST <session>/lock`, whose answer
    carries the ticket's invoice) after the first for `hold` seconds, so a ticket buy takes as long as one over several
    Lightning hops. (The request itself goes on at once: the gateway gives up on one that arrives that slowly, 408.)
    Anything else, a slice paid from credit among it, goes through at once."""

    def __init__(self, listen: int, to: int, hold: float) -> None:
        self.to, self.hold, self.locks, self.held_at = to, hold, 0, []
        self.server = socket.create_server(("127.0.0.1", listen))
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self) -> None:
        while True:
            a, _ = self.server.accept()
            b = socket.create_connection(("127.0.0.1", self.to))
            # the connection's next answer is held: one request at a time on each
            hold = {"next": False}
            threading.Thread(target=self.pump, args=(a, b, True, hold), daemon=True).start()
            threading.Thread(target=self.pump, args=(b, a, False, hold), daemon=True).start()

    def pump(self, x: socket.socket, y: socket.socket, asks: bool, hold: dict[str, bool]) -> None:
        try:
            while data := x.recv(65536):
                # a request's head arrives at the start of a read on these short calls
                if asks and data.startswith(b"POST ") and b"/x402/ticket/lock" in data.split(b"\r\n", 1)[0]:
                    self.locks += 1
                    hold["next"] = self.locks > 1
                elif not asks and hold["next"]:
                    hold["next"] = False
                    self.held_at.append(int(time.time() * 1000))
                    time.sleep(self.hold)
                y.sendall(data)
        except OSError:
            pass
        for z in (x, y):
            try:
                z.close()
            except OSError:
                pass


def slow_check() -> None:
    """Issue #64: ticket buys of about 12 s, a miner whose 30 s of output is under the 546 sat step, a long rental."""
    road = SlowBuys(SLOW_ROAD, GW4, SLOW_BUY_S)
    inv0, pay0 = d.seller_invoices(), d.buyer_payments()
    t0 = time.time()
    r = rental("slow", None, SLOW_SECS, SLOW_RATE, origin=ORIGIN4, price_msat=SLOW_PRICE_MSAT, task="hashrate-slow",
               caps=("--budget-sats", str(SLOW_BUDGET_SATS)), idle_s=60,
               # a share every 5 s from each miner: a new job every second would leave most of them stale
               job_ms=60_000)
    hz, bz = r["hasher"], r["buyer"]
    for who in ("hasher", "buyer"):
        try:
            with open(f"{RUN}/slow-{who}.json", "rb") as f, open(f"{OUT}/p2p_hash_slow-{who}.json", "wb") as g:
                g.write(f.read())
        except OSError:
            pass
    pays = bz["pays"]
    oks = [p for p in pays if p.get("ok")]
    bought = [p for p in oks if int(p["wallet"].get("charged_sats", 0)) > 0]
    slow_buys = [p["ms"] for p in bought[1:]]
    ahead = [p["slice"] for p in bought if p.get("ahead")]
    from_credit = [p["slice"] for p in oks if int(p["wallet"].get("charged_sats", 0)) == 0]
    stopped = (hz.get("stopped") or {}).get("reason")
    served_s = hz.get("servedMs", 0) / 1000
    REPORT["slow"] = {"buy ms": [p["ms"] for p in bought], "pay ms": [p["ms"] for p in pays], "held locks": len(road.held_at), "bought ahead at slices": ahead,
                      "from credit at slices": from_credit, "buySecs": bz.get("buySecs"), "buyLeadSecs": bz.get("buyLeadSecs"), "dues": bz.get("dues"),
                      "paymentWaits": hz.get("paymentWaits"), "rampWaits": hz.get("rampWaits"), "stopped": stopped, "closed": bz.get("closed"),
                      "servedS": served_s, "ran s": round(time.time() - t0)}
    print(f"slow: {json.dumps(REPORT['slow'])[:1500]}", flush=True)
    check(f"slow: ticket buys of about {SLOW_BUY_S + 1:.0f} s (each held {SLOW_BUY_S:.0f} s on its way), and the rental runs to its end "
          f"({SLOW_SECS} s of miners), not \"hashmaker closed: unpaid\"",
          len(slow_buys) >= 5 and min(slow_buys) >= SLOW_BUY_S * 1000 and stopped != "unpaid" and bz.get("closed") == "no proven work"
          and served_s >= SLOW_SECS - 120 and not bz["payFailed"],
          {"slow buys ms": slow_buys[:12], "stopped": stopped, "closed": bz.get("closed"), "served s": served_s, "pay failed": bz["payFailed"]})
    check("slow: each ticket buy after the first two starts ahead, while what's paid still lasts it, and slices are paid from the credit it "
          "bought; the hashmaker waited for a payment on its way at most once",
          len(ahead) >= len(bought) - 3 and from_credit and (hz.get("paymentWaits", 0) + hz.get("rampWaits", 0)) <= 1,
          {"buys": len(bought), "bought ahead": len(ahead), "from credit": len(from_credit), "payment waits": hz.get("paymentWaits"),
           "ramp waits": hz.get("rampWaits"), "dues": bz.get("dues"), "lead s": bz.get("buyLeadSecs")})
    paid = hz["paid"]
    slices = [p["slice"] for p in oks]
    proven = lambda m: (m["work"], m["proven"])  # noqa: E731
    priced = sum(int(p["wallet"].get("price_msat", 0)) for p in oks)
    last_w = oks[-1]["wallet"] if oks else {}
    credited, balance = int(last_w.get("credited_msat", 0)), int(last_w.get("balance_msat", 0))
    moved_sats = sum(int(p["wallet"].get("charged_sats", 0)) for p in oks)
    check("slow: every slice paid once and in turn, both proven counts equal, none past what's paid; slices x price = the wallet's spent = what the "
          "hashmaker earned; what left the wallet within the rental's budget",
          paid == len(oks) == len(set(slices)) and slices == list(range(1, paid + 1)) and proven(hz["meter"]) == proven(bz["meter"])
          and int(hz["meter"]["work"]) <= paid * SLICE_WORK and priced == credited - balance == paid * SLOW_PRICE_MSAT == hz["earnedMsat"]
          and moved_sats <= SLOW_BUDGET_SATS,
          {"hashmaker paid": paid, "wallet ok": len(oks), "meter": hz["meter"], "the hashtaker's meter": bz["meter"], "slices x price msat": paid * SLOW_PRICE_MSAT,
           "wallet priced msat": priced, "seller's spent msat": credited - balance, "earned msat": hz["earnedMsat"], "moved sats": moved_sats,
           "budget sats": SLOW_BUDGET_SATS})
    inv1, pay1 = d.seller_invoices(), d.buyer_payments()
    settled = {h: i for h, i in inv1.items() if h not in inv0 and i["state"] == "SETTLED"}
    succeeded = {h: p for h, p in pay1.items() if h not in pay0 and p["status"] == "SUCCEEDED"}
    node_in = sum(int(i["amt_paid_msat"]) for i in settled.values())
    check("slow: the seller's node settled what the wallet's node paid and what the seller credited; nothing held",
          settled and set(settled) == set(succeeded) and node_in == credited and d.held() == 0,
          {"settled": len(settled), "succeeded": len(succeeded), "seller's node in msat": node_in, "credited msat": credited, "held": d.held()})


class UI:
    """The hashmaker's wallet app over HTTP, as its owner's browser uses it: logged in, each form with its csrf."""

    def __init__(self, port: int, password: str) -> None:
        self.port, self.cookie = port, ""
        st, h, _ = self.req("POST", "/login", {"password": password})
        self.cookie = h.get("set-cookie", "").split(";")[0]
        if st != 303 or not self.cookie:
            raise lab.LabError(f"the hashmaker's app login: {st}")

    def req(self, method: str, path: str, form: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            headers = {"Cookie": self.cookie} if self.cookie else {}
            body = None
            if form is not None:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = urllib.parse.urlencode(form).encode()
            c.request(method, path, body=body, headers=headers)
            r = c.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read().decode(errors="replace")
        finally:
            c.close()

    def act(self, path: str, form: dict[str, str]) -> str:
        page = self.req("GET", path)[2]
        csrf = page.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        st, h, body = self.req("POST", path, {"csrf": csrf, **form})
        if st == 303:
            body = self.req("GET", urllib.parse.urljoin(path, h.get("location", path)))[2]
        return body


def reprice_check() -> None:
    try:
        reprice_run()
    finally:
        # the logs, beside the report (the lab copies only run/*.log and run/*.json back)
        for name in ("rp-ui", "rp-gateway", "rp-hashmaker", "rp-rp1", "rp-rp2", "rp-rp3"):
            try:
                with open(f"{RUN}/{name}.log", "rb") as f, open(f"{OUT}/p2p_hash_reprice-{name}.log", "wb") as g:
                    g.write(f.read())
            except OSError:
                pass


def reprice_run() -> None:
    """A new price while a rental goes on, with the hashmaker's real app, its gateway under xbt-supervise and the
    hashmaker service: the old price is charged during the rental, no new rental starts, the gateway restarts with
    the new price once the rental has ended, and the next rental pays that."""
    rp = f"{RUN}/reprice"
    os.makedirs(f"{rp}/gw", exist_ok=True)
    settings_path, token_path, gw_config = f"{rp}/hashrate-settings.json", f"{rp}/hasher-token", f"{rp}/gw/config.json"
    t0 = time.time()
    timeline: list[dict[str, Any]] = []
    REPORT["reprice_timeline"] = timeline

    def note(what: str, **kw: Any) -> None:
        timeline.append({"s": round(time.time() - t0, 1), "what": what, **kw})
        print(f"      reprice +{time.time() - t0:.0f}s {what} {json.dumps(kw)[:300]}", flush=True)

    def settings() -> dict[str, Any]:
        with open(settings_path) as f:
            return json.load(f)

    def write_settings(v: dict[str, Any]) -> None:
        with open(settings_path + ".new", "w") as f:
            json.dump(v, f, indent=1)
        os.replace(settings_path + ".new", settings_path)

    with open(token_path, "w") as f:
        f.write(secrets.token_hex(32))
    with open(token_path) as f:
        token = f.read().strip()

    def hasher(method: str = "GET", path: str = "/status") -> dict[str, Any]:
        c = http.client.HTTPConnection("127.0.0.1", RP_CONTROL, timeout=10)
        try:
            c.request(method, path, headers={"Authorization": f"Bearer {token}"})
            return json.loads(c.getresponse().read())
        finally:
            c.close()

    def charged() -> int | None:
        """What the gateway charges a slice now (its /services), None while it is not up."""
        try:
            code, _, body = d.send("GET", "/services", RP_GW)
        except OSError:
            return None
        if code != 200:
            return None
        routes = [r for r in json.loads(body).get("routes", []) if r.get("path") == "/hashrate/"]
        return int(routes[0]["price"]["requestMsat"]) if routes else None

    def route_in_config() -> int | None:
        try:
            with open(gw_config) as f:
                routes = [r for r in json.load(f).get("routes", []) if r.get("path") == "/hashrate/"]
        except (OSError, ValueError):
            return None
        return int(routes[0]["price"]["request_msat"]) if routes else None

    def gateway_pid() -> int | None:
        kids = subprocess.run(["pgrep", "-P", str(supervise.pid)], capture_output=True, text=True).stdout.split()
        return int(kids[0]) if kids else None

    # the owner's settings, as a Save at a fixed price leaves them, with the lab's slice and no price worked out yet
    write_settings({"enabled": True, "fallback": f"127.0.0.1:{RP_FALLBACK}", "priceMode": "fixed", "fixedPriceSat": RP_PRICES[0],
                    "fixedSliceWork": str(SLICE_WORK), "sliceFixed": True, "sliceWork": str(SLICE_WORK), "rentable": None,
                    "graceMs": GRACE_MS, "name": "reprice hashmaker", "linkPublic": f"127.0.0.1:{RP_LINK}", "payUrl": f"{RP_ORIGIN}/hashrate"})
    for who in ("rp1", "rp2", "rp3"):
        subprocess.run([f"{BIN}/xbt-hashlink", "keygen", f"{RUN}/keys/{who}.key"], check=True, stdout=subprocess.DEVNULL)
    spawn("rp-fallback", ["standin-pool", "--listen", f"127.0.0.1:{RP_FALLBACK}", "--diff", str(DIFF), "--job-ms", "1000", "--report", f"{rp}/fallback.json"])
    spawn("rp-pool", ["standin-pool", "--listen", f"127.0.0.1:{RP_POOL}", "--diff", str(DIFF), "--job-ms", "1000", "--report", f"{rp}/pool.json"])
    spawn("rp-hashmaker", ["hashmaker", "--key", f"{RUN}/keys/hasher.key", "--config", settings_path, "--control", f"127.0.0.1:{RP_CONTROL}",
                           "--control-token-file", token_path, "--gateway", RP_ORIGIN, "--miners", f"127.0.0.1:{RP_MINERS}", "--link", f"127.0.0.1:{RP_LINK}",
                           "--slices", f"127.0.0.1:{RP_SLICES}", "--report", f"{rp}/hasher.json", "--iroh", "off", "--pay-node", lab.pubkey(d.SELLER)])
    lab.wait("the hashmaker service", 30, lambda: hasher().get("role") == "hasher", every=0.5)
    # three miners; a rental takes two, so one stays free: only the new price's wait can turn a renter away
    for i in (1, 2, 3):
        spawn(f"rp-miner{i}", ["standin-miner", "--pool", f"127.0.0.1:{RP_MINERS}", "--user", f"hasher.m{i}", "--rate", "0.5", "--duration-s", "3000",
                                         # as a real miner does: it follows client.reconnect, which moves it to a rental and back
                                         "--reconnect", "1"])
    # measured before the app prices: the start fee is sized to their speed
    lab.wait("the three miners measured", 180,
             lambda: sum(1 for m in hasher().get("miners", []) if m.get("connected") and float(m.get("hashrateHs") or 0) > 0) == 3, every=2)

    # the shop's gateway as the images run it: started once the app writes its config, and again when it changes
    log = open(f"{RUN}/rp-gateway.log", "ab")
    supervise = subprocess.Popen([f"{BIN}/xbt-supervise", "--wait", gw_config, "--", f"{BIN}/xbt-gateway", gw_config], stdout=log, stderr=log)
    PROCS.append(supervise)
    password = secrets.token_hex(12)
    env = dict(os.environ, XBT_UI_BIND=f"127.0.0.1:{RP_UI}", XBT_UI_SIGNER_SOCK=d.SOCK, XBT_DATA_DIR=f"{rp}/data", XBT_UI_DATA_DIR=f"{rp}/ui",
               XBT_UI_PASSWORD=password, XBT_UI_SELL="1", XBT_UI_GW_DIR=f"{rp}/gw", XBT_UI_GW_NODE_REST=f"https://127.0.0.1:{lab.PORT[d.SELLER]}",
               XBT_UI_GW_NODE_TLS_CERT=f"{RUN}/{d.SELLER}.tls.cert", XBT_UI_GW_STATE_DIR=f"{rp}/state-gateway", XBT_UI_GW_PORT=str(RP_GW),
               XBT_UI_GW_HEALTH_URL=f"{RP_ORIGIN}/x402/ticket/health", XBT_UI_HASHER=f"http://127.0.0.1:{RP_CONTROL}",
               XBT_UI_HASHER_SETTINGS=settings_path, XBT_UI_HASHER_SLICES=f"http://127.0.0.1:{RP_SLICES}", XBT_UI_HASHER_TOKEN_FILE=token_path)
    log = open(f"{RUN}/rp-ui.log", "ab")
    PROCS.append(subprocess.Popen([f"{BIN}/xbt-wallet-ui"], env=env, cwd=rp, stdout=log, stderr=log))
    lab.wait("the hashmaker's app", 60, lambda: d.send("GET", "/login", RP_UI)[0] == 200, every=0.5)
    ui = UI(RP_UI, password)
    # the owner sets up the shop on the Sell page: the node's keys, the shop's address, the chain
    with open(f"{RUN}/invoices.macaroon", "rb") as f:
        inv = f.read().hex()
    with open(f"{RUN}/info.macaroon", "rb") as f:
        info = f.read().hex()
    said = [ui.act("/sell", {"action": "connect", "invoices_macaroon": inv, "info_macaroon": info}),
            ui.act("/sell", {"action": "shop", "name": "reprice hashmaker", "reach": "web", "public_url": RP_ORIGIN}),
            ui.act("/sell", {"action": "advanced", "max_sessions": "30", "sessions_per_address": "0", "max_held_tickets": "15", "proxies": "",
                             "network": "bip122:" + lab.chain("getblockhash", "101")[:32]})]
    note("shop set up on the Sell page", flash=[re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", b.split('class="flash', 1)[-1][:400]))[:200] for b in said])
    # the app prices within a minute or two: its terms, the route, the gateway started on it, then rentals taken
    lab.wait("the first price in force, charged by the gateway, rentals taken", 240,
             lambda: settings().get("priceSat") == RP_PRICES[0] and settings().get("holdNew") is False and charged() == RP_PRICES[0] * 1000
             and hasher().get("paused") is None and hasher()["terms"]["priceMsat"] == RP_PRICES[0] * 1000, every=2)
    st = hasher()
    terms0 = st["terms"]
    pid0 = gateway_pid()
    note("price in force", settings={k: settings().get(k) for k in ("priceSat", "sliceWork", "startSlices", "holdNew")}, charged=charged(), terms=terms0, gateway_pid=pid0)
    pub = subprocess.run([f"{BIN}/xbt-hashlink", "pubkey", f"{RUN}/keys/hasher.key"], check=True, capture_output=True, text=True).stdout.strip()

    def hashtaker(name: str, terms: dict[str, Any], miners: int, secs: int) -> subprocess.Popen[bytes]:
        return spawn(f"rp-{name}", ["hashtaker", "--key", f"{RUN}/keys/{name}.key", "--hashmaker", f"127.0.0.1:{RP_LINK}", "--hashmaker-key", pub,
                                    "--price-msat", str(terms["priceMsat"]), "--slice-work", str(terms["sliceWork"]), "--grace-ms", str(terms["graceMs"]),
                                    "--start-slices", str(terms["startSlices"]), "--upstream", f"127.0.0.1:{RP_POOL}", "--user", "buyer.rented",
                                    "--allow-unblinded", "1", "--signer", d.RENTER_SOCK, "--task", "hashrate", "--pay-url", f"{RP_ORIGIN}/hashrate",
                                    "--max-sats", "1500", "--miners", str(miners), "--rental", f"rt-{name}", "--idle-s", "15", "--duration-s", str(secs),
                                    "--report", f"{rp}/{name}-buyer.json"])

    def buyer(name: str) -> dict[str, Any]:
        for _ in range(100):
            try:
                with open(f"{rp}/{name}-buyer.json") as f:
                    return json.load(f)
            except (OSError, ValueError):
                time.sleep(0.1)
        return {}

    def oks(name: str) -> list[dict[str, Any]]:
        return [p for p in buyer(name).get("pays", []) if p.get("ok")]

    def rental_now(rid: str) -> dict[str, Any] | None:
        return next((r for r in hasher().get("rentals", []) if r.get("rental") == rid), None)

    # 1. a rental of two miners at the price in force
    r1 = hashtaker("rp1", terms0, 2, 240)
    lab.wait("three slices paid in the first rental", 120, lambda: len(oks("rp1")) >= 3, every=1)
    free_before = [m["name"] for m in hasher()["miners"] if m.get("connected") and m.get("rentedTo") is None]
    before = settings()
    # the owner changes the price, as Save writes it (Save then re-prices at once; the app's minute does it here)
    write_settings({**before, "fixedPriceSat": RP_PRICES[1]})
    changed_ms = int(time.time() * 1000)
    note("new price saved", fixedPriceSat=RP_PRICES[1], paid_so_far=len(oks("rp1")), free_miners=free_before)
    lab.wait("the app holding the new price", 90, lambda: settings().get("holdNew") is True and (settings().get("pending") or {}).get("priceSat") == RP_PRICES[1], every=1)
    lab.wait("the hashmaker taking no new rental", 10, lambda: hasher().get("paused") is not None, every=0.5)
    held_ms = int(time.time() * 1000)
    s_held, st_held = settings(), hasher()
    note("held", priceSat=s_held.get("priceSat"), pending=s_held.get("pending"), holdNew=s_held.get("holdNew"), paused=st_held.get("paused"),
         route_in_config=route_in_config(), charged=charged(), gateway_pid=gateway_pid())
    # 2. a new renter, for the miner still free, at the terms in force: turned away
    r2 = hashtaker("rp2", st_held["terms"], 1, 60)
    try:
        r2.wait(60)
    except subprocess.TimeoutExpired:
        r2.terminate()
        r2.wait(10)
    b2 = buyer("rp2")
    with open(f"{RUN}/rp-rp2.log", errors="replace") as f:
        log2 = f.read()
    free_during = [m["name"] for m in hasher()["miners"] if m.get("connected") and m.get("rentedTo") is None]
    rentals_during = [r["rental"] for r in hasher().get("rentals", [])]
    check("reprice: while the rental goes on, a new renter is turned away (a miner is free, the new price waits), nothing paid",
          len(free_before) == 1 and free_during == free_before and rentals_during == ["rt-rp1"] and not [p for p in b2.get("pays") or [] if p.get("ok")]
          and int((b2.get("meter") or {}).get("work", "0")) == 0 and "no miners free now" in log2,
          {"free miners before": free_before, "free miners now": free_during, "rentals": rentals_during, "paused": st_held.get("paused"),
           "the renter": {k: b2.get(k) for k in ("closed", "payFailed")}, "renter's pays": b2.get("pays"), "renter's log": log2[-400:]})
    # a few more slices of the first rental, after the hold
    lab.wait("two more slices paid in the first rental after the hold", 120, lambda: sum(1 for p in oks("rp1") if p["atMs"] > held_ms) >= 2, every=1)
    during = {"route in the config": route_in_config(), "charged": charged(), "gateway pid": gateway_pid(), "terms": hasher()["terms"]["priceMsat"],
              "settings priceSat": settings().get("priceSat")}
    note("rental going on after the hold", **during)
    r1.wait(300)
    ended_ms = int(time.time() * 1000)
    lab.wait("the first rental gone from the hashmaker", 60, lambda: rental_now("rt-rp1") is None, every=1)
    b1 = buyer("rp1")
    p1 = oks("rp1")
    after_change = [p for p in p1 if p["atMs"] > changed_ms]
    h1 = next((r for r in hasher().get("finished", []) if r.get("rental") == "rt-rp1"), None) or {}
    REPORT["reprice_rental1_pays"] = b1.get("pays")
    note("first rental ended", paid=len(p1), after_change=len(after_change), closed=b1.get("closed"))
    check("reprice: the rental going on is charged the old price to its end, slices paid after the change included",
          len(after_change) >= 2 and all(int(p["wallet"].get("price_msat", 0)) == RP_PRICES[0] * 1000 for p in p1)
          and during["route in the config"] == during["charged"] == during["terms"] == RP_PRICES[0] * 1000 and during["gateway pid"] == pid0
          and during["settings priceSat"] == RP_PRICES[0] and not b1.get("payFailed"),
          {"slices paid": len(p1), "paid after the change": len(after_change), "price_msat each": sorted({int(p["wallet"].get("price_msat", 0)) for p in p1}),
           "during the hold": during, "gateway pid at first": pid0, "the hashmaker's record": {k: h1.get(k) for k in ("paid", "earnedMsat", "terms")}})
    # 3. ended: the app writes the new terms and route, the gateway restarts on them, rentals are taken again
    lab.wait("the new price in the route", 150, lambda: route_in_config() == RP_PRICES[1] * 1000, every=1)
    routed_ms = int(time.time() * 1000)
    lab.wait("the gateway charging the new price", 60, lambda: charged() == RP_PRICES[1] * 1000, every=0.5)
    charging_ms = int(time.time() * 1000)
    lab.wait("rentals taken again", 150, lambda: settings().get("holdNew") is False and hasher().get("paused") is None, every=1)
    open_ms = int(time.time() * 1000)
    pid1 = gateway_pid()
    with open(f"{RUN}/rp-gateway.log", errors="replace") as f:
        restarts = [line.strip() for line in f if "changed: restarting" in line]
    terms1 = hasher()["terms"]
    note("new price in force", route=route_in_config(), charged=charged(), terms=terms1, gateway_pid=pid1, restarts=restarts)
    check("reprice: after the rental ends the app writes the new terms and route, the gateway restarts with the new price, and rentals are taken again",
          route_in_config() == charged() == terms1["priceMsat"] == RP_PRICES[1] * 1000 and settings().get("priceSat") == RP_PRICES[1]
          and pid1 not in (None, pid0) and restarts and ended_ms <= routed_ms <= charging_ms <= open_ms,
          {"gateway pid before/after": [pid0, pid1], "supervisor": restarts[-2:], "seconds from the end to the route": round((routed_ms - ended_ms) / 1000),
           "to the gateway charging it": round((charging_ms - ended_ms) / 1000), "to rentals taken": round((open_ms - ended_ms) / 1000),
           "settings": {k: settings().get(k) for k in ("priceSat", "holdNew", "pending")}})
    # 4. the next rental pays the new price
    r3 = hashtaker("rp3", terms1, 2, 60)
    r3.wait(240)
    b3 = buyer("rp3")
    p3 = oks("rp3")
    REPORT["reprice_rental3_pays"] = b3.get("pays")
    last = p3[-1]["wallet"] if p3 else {}
    h3 = next((r for r in hasher().get("finished", []) if r.get("rental") == "rt-rp3"), None) or {}
    check("reprice: the next rental pays the new price, each slice, and the hashmaker earns that",
          len(p3) >= 2 and all(int(p["wallet"].get("price_msat", 0)) == RP_PRICES[1] * 1000 for p in p3) and not b3.get("payFailed"),
          {"slices paid": len(p3), "price_msat each": sorted({int(p["wallet"].get("price_msat", 0)) for p in p3}),
           "the hashmaker's record": {k: h3.get(k) for k in ("paid", "earnedMsat", "terms")},
           "seller's signed spent msat at the last slice": int(last.get("credited_msat", 0)) - int(last.get("balance_msat", 0))})
    REPORT["reprice_status"] = hasher()
    for name in ("hashrate-settings.json", "gw/config.json", "hasher.json"):
        try:
            with open(f"{rp}/{name}") as f:
                REPORT.setdefault("reprice_files", {})[name] = json.load(f)
        except (OSError, ValueError):
            pass


def tagged(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def masked_block(header: bytes) -> dict[str, Any]:
    """From a 164-byte v2 header, as the node's own stages: the raw hash, the mask and the block id they make."""
    key, flags, clear = header[112:128], header[110], header[111]
    prev = header[4:36][::-1]
    mask = bytearray(tagged("Bitcoin block hash PoW XOR mask", key))
    whole = clear // 8
    mask[:whole] = bytes(whole)
    if whole < 32:
        mask[whole] &= 0xFF >> (clear % 8)
    if not any(key):
        mask = bytearray(32)
    h1 = tagged("Bitcoin block header 1", header[:4] + prev + header[128:132] + header[36:68] + header[68:72] + b"\0" + header[72:76]
                + header[108:110] + bytes(2) + bytes((flags, clear)) + tagged("Bitcoin block hash PoW XOR key", key))
    h2 = tagged("Merge-mining hook", h1 + bytes(32) + header[132:164])
    root = hashlib.blake2b(bytes(4) + h2 + header[88:104], digest_size=32).digest()
    hidden = bytearray(tagged("Bitcoin prevblock header, hashed", prev))
    hidden[:6] = bytes(6)
    raw = hashlib.blake2b(bytes(hidden) + header[76:84] + header[104:108] + header[84:88] + root, digest_size=32).digest()
    return {"key_null": not any(key), "clear_bits": clear, "raw": raw.hex(), "mask": bytes(mask).hex(), "id": bytes(a ^ b for a, b in zip(raw, mask)).hex()}


_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    g = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= g[i] if (top >> i) & 1 else 0
    return chk


def with_hrp(addr: str, hrp: str) -> str:
    """The same bech32 (v0) address under another prefix: the same output script, as a mainnet wallet writes it."""
    old, data = addr.rsplit("1", 1)
    values = [_B32.index(c) for c in data[:-6]]
    expand = lambda h: [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]  # noqa: E731
    assert _polymod(expand(old) + values + [_B32.index(c) for c in data[-6:]]) == 1, "not a bech32 address"
    mod = _polymod(expand(hrp) + values + [0] * 6) ^ 1
    return hrp + "1" + "".join(_B32[v] for v in values) + "".join(_B32[(mod >> 5 * (5 - i)) & 31] for i in range(6))


def real_gateway(mode: str) -> None:
    try:
        real_gateway_run(mode)
    finally:
        # its reports and logs, beside the report (the lab copies only run/*.log and run/*.json back)
        for src in sorted(glob.glob(f"{RUN}/{mode}-*")):
            base = os.path.basename(src)
            if base.endswith((".log", ".json")):
                try:
                    with open(src, "rb") as f, open(f"{OUT}/p2p_hash_{base}", "wb") as g:
                        g.write(f.read())
                except OSError:
                    pass


# the bundled gateway's own pages the app passes on read-only (xbt-hashlink hashtaker_service GATEWAY_PAGES)
GATEWAY_PAGES = ["", "threads", "coinbaser", "clients", "config", "assets/style.css", "assets/icons/datum_logo.svg", "assets/icons/favicon.ico"]


def gateway_pages_check(mode: str, api: int, rpc: int, home: str) -> None:
    """Every page the app passes on from the gateway, asked as the renter asks it (GET, no login): with the admin
    password empty, none shows the node's RPC address, its cookie or a credential, and Clients and Config say they
    need admin access."""
    import http.client
    cookie = open(f"{home}/node/regtest/.cookie").read().strip()
    secrets = {"cookie": cookie, "cookie password": cookie.split(":", 1)[-1], "rpc url": f"127.0.0.1:{rpc}", "rpc port": f":{rpc}",
               "cookie path": ".cookie", "lab dir": home, "rpcuser": "rpcuser", "rpcpassword": "rpcpassword", "rpcurl": "rpcurl"}
    pages, leaks = {}, {}
    for page in GATEWAY_PAGES:
        c = http.client.HTTPConnection("127.0.0.1", api, timeout=5)
        c.request("GET", f"/{page}", headers={"Connection": "close"})
        r = c.getresponse()
        body = r.read()
        c.close()
        text = body.decode("utf-8", "replace")
        pages[page or "/"] = {"status": r.status, "type": r.getheader("Content-Type"), "bytes": len(body), "chunked": r.getheader("Transfer-Encoding"),
                              "admin": "requires admin" in text.lower() or "admin access" in text.lower()}
        found = [k for k, v in secrets.items() if v and v in text]
        if found:
            leaks[page or "/"] = found
        with open(f"{RUN}/{mode}-gateway-page-{(page or 'status').replace('/', '_')}", "wb") as f:
            f.write(body)
    REPORT[f"{mode}_gateway_pages"] = {"pages": pages, "leaks": leaks}
    check(f"{mode}: the gateway's status pages the app shows, as the renter asks them: each answers, none shows the node's RPC address, cookie or a credential, "
          "and Clients and Config need admin access",
          not leaks and all(v["status"] in (200, 401, 403) and v["bytes"] <= 1 << 20 and not v["chunked"] for v in pages.values())
          and pages["clients"]["admin"] and pages["config"]["admin"],
          {"pages": pages, "leaks": leaks})


# P2P_HASH_BUSY_SIGNER=1: the renter's writes to the wallet's signer socket fail now and then as a busy socket's do
# (EAGAIN, nothing sent), from an LD_PRELOAD shim: each failure counted down from the number in its file
BUSY_SHIM_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
/* whether this write to fd fails as a busy socket's: an AF_UNIX socket while the count in BUSY_SHIM_FILE is above 0 */
static int busy(int fd) {
    const char *f = getenv("BUSY_SHIM_FILE");
    int dom = 0, hit = 0;
    socklen_t l = sizeof dom;
    if (!f || getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &l) != 0 || dom != AF_UNIX) return 0;
    int h = open(f, O_RDWR);
    if (h < 0) return 0;
    char b[32] = {0};
    long left = pread(h, b, sizeof b - 1, 0) > 0 ? strtol(b, 0, 10) : 0;
    if (left > 0) {
        char o[32];
        int k = snprintf(o, sizeof o, "%ld\n", left - 1);
        hit = ftruncate(h, 0) == 0 && pwrite(h, o, k, 0) == k;
    }
    close(h);
    return hit;
}
ssize_t write(int fd, const void *buf, size_t n) {
    static ssize_t (*real)(int, const void *, size_t);
    if (!real) real = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
    if (busy(fd)) { errno = EAGAIN; return -1; }
    return real(fd, buf, n);
}
ssize_t send(int fd, const void *buf, size_t n, int flags) {
    static ssize_t (*real)(int, const void *, size_t, int);
    if (!real) real = (ssize_t (*)(int, const void *, size_t, int))dlsym(RTLD_NEXT, "send");
    if (busy(fd)) { errno = EAGAIN; return -1; }
    return real(fd, buf, n, flags);
}
ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *a, socklen_t al) {
    static ssize_t (*real)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
    if (!real) real = (ssize_t (*)(int, const void *, size_t, int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "sendto");
    if (busy(fd)) { errno = EAGAIN; return -1; }
    return real(fd, buf, n, flags, a, al);
}
"""


def busy_shim() -> tuple[dict[str, str], str] | None:
    """The renter's environment with the busy-socket shim, and its countdown file; None when it can't be built."""
    so, src, count = f"{RUN}/busy_shim.so", f"{RUN}/busy_shim.c", f"{RUN}/busy_shim.count"
    with open(src, "w") as f:
        f.write(BUSY_SHIM_C)
    built = subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-o", so, src, "-ldl"], capture_output=True, text=True)
    if built.returncode != 0:
        REPORT.setdefault("skipped", []).append({"check": "busy signer socket", "missing": built.stderr[-400:]})
        return None
    with open(count, "w") as f:
        f.write("0\n")
    return {**os.environ, "LD_PRELOAD": so, "BUSY_SHIM_FILE": count}, count


def real_gateway_run(mode: str) -> None:
    """A rental paid with real money through the wallet, of real work for a real gateway on a chain of its own."""
    keys = mode == "solo" or os.environ.get("P2P_HASH_PRIMED_KEYS") == "1"
    primed = os.environ.get("P2P_HASH_PRIMED", f"{HG}/primed-main")
    need = [f"{HG}/{b}" for b in ("bitcoind", "bitcoin-cli", "stratum-grind")] + [DATUM_GATEWAY] + ([primed] if mode == "pool" else [])
    missing = [n for n in need if not os.path.exists(n)]
    if missing:
        REPORT.setdefault("skipped", []).append({"check": mode, "missing": missing})
        print(f"SKIP  {mode}: missing {missing}", flush=True)
        return
    base = REAL_BASE + (0 if mode == "solo" else 10)
    rpc, p2p, st, api, prime, stats = base, base + 1, base + 2, base + 3, base + 4, base + 5
    home = f"{RUN}/{mode}"
    os.makedirs(f"{home}/node", exist_ok=True)
    with open(f"{home}/node/bitcoin.conf", "w") as f:
        f.write("regtest=1\nserver=1\nlistenonion=0\ndiscover=0\ndnsseed=0\nfixedseeds=0\nfallbackfee=0.0002\ntxindex=1\nblake2b_headline=Lazarus\n"
                f"[regtest]\nlisten=1\nbind=127.0.0.1\nport={p2p}\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport={rpc}\n"
                f"testactivationheight=blake2b@101\nmaxtipage=315360000\nblocknotify=/usr/bin/curl -fsS -m 2 -o /dev/null http://127.0.0.1:{api}/NOTIFY\n")
    env = {**os.environ, "LD_LIBRARY_PATH": f"{HG}/lib"}
    subprocess.run([f"{HG}/bitcoind", f"-datadir={home}/node", "-daemon"], check=True, env=env, stdout=subprocess.DEVNULL)

    def cli(*a: str) -> str:
        return subprocess.run([f"{HG}/bitcoin-cli", f"-datadir={home}/node", *a], check=True, env=env, capture_output=True, text=True).stdout.strip()

    try:
        def answers() -> bool:
            try:
                return cli("getblockcount") != ""
            except subprocess.CalledProcessError:
                return False

        lab.wait(f"{mode}'s own node", 60, answers, every=0.5)
        cli("createwallet", "w")
        address = cli("-rpcwallet=w", "getnewaddress", "", "bech32")
        cli("-rpcwallet=w", "generatetoaddress", "220", address)
        height0 = int(cli("getblockcount"))
        datum: dict[str, Any] = {"pool_host": "", "pooled_mining_only": False}
        # the gateway reads a bech32 address only under the mainnet and testnet prefixes (datum_utils.c
        # addr_2_output_script), not regtest's "bcrt". A solo block pays a legacy address, or with
        # P2P_HASH_SOLO_BECH32=1 the wallet's own bech32 address written as a mainnet wallet writes it ("bc1q..."):
        # the same output script
        bech32 = os.environ.get("P2P_HASH_SOLO_BECH32") == "1"
        own = cli("-rpcwallet=w", "getnewaddress", "", "bech32" if bech32 else "legacy")
        pool_address = with_hrp(own, "bc") if bech32 else own
        payout_script = json.loads(cli("-rpcwallet=w", "getaddressinfo", own))["scriptPubKey"]
        REPORT[f"{mode}_payout"] = {"address": pool_address, "wallet's own form": own, "script": payout_script}
        if mode == "pool":
            os.makedirs(f"{home}/prime", exist_ok=True)
            with open(f"{home}/prime/seed.json", "w") as f:
                json.dump({"credits": [{"ts": int(time.time()) - 120, "identity": address, "work": 1_000_000_000, "source": 2}]}, f)
            with open(f"{home}/prime/prime.toml", "w") as f:
                f.write(f'listen = "127.0.0.1:{prime}"\nstats-listen = "127.0.0.1:{stats}"\nadvertise-address = "127.0.0.1:{prime}"\ndata-dir = "{home}/prime/data"\n'
                        f'motd = "rental"\nheadline = "Lazarus"\npayout-address = "{address}"\ncoinbase-tag = "Lazarus"\nprime-id = 134\nnetwork = "regtest"\nwindow = 8\n'
                        f'window-min-work = 50000000\nmin-payout = 546\nmin-diff = 1\nfee-bps = 0\nhouse-loopback = false\nrpc = "http://127.0.0.1:{rpc}"\n'
                        f'rpc-cookie = "{home}/node/regtest/.cookie"\npoll = 0.5\nimport-ledger = "{home}/prime/seed.json"\n' + ("gateway-key = true\n" if keys else ""))
            pub = subprocess.run([primed, "-c", f"{home}/prime/prime.toml", "pubkey"], check=True, capture_output=True, text=True).stdout.strip()
            log = open(f"{RUN}/{mode}-primed.log", "ab")
            PROCS.append(subprocess.Popen([primed, "-c", f"{home}/prime/prime.toml", "run"], stdout=log, stderr=log))
            lab.wait("primed", 30, lambda: socket.create_connection(("127.0.0.1", prime), 1).close() or True, every=0.5)
            late = None
            if os.environ.get("P2P_HASH_LATE_COINBASER") == "1":
                late = LatePool(base + 6, prime, lambda: int(cli("getblockcount")))
            datum = {"pool_host": "127.0.0.1", "pool_port": base + 6 if late else prime, "pool_pubkey": pub, "pool_pass_workers": True, "pool_pass_full_users": True,
                     "pooled_mining_only": True, "protocol_global_timeout": 60}
            pool_address = "bc1qt5praystcdle0nq04e3h02yjszha82uzhww85x6972lcy40k4eyqz9jfaq"
        # solo, the tags the app writes with an owner's own coinbase tag (Your gateway's Coinbase tag): the primary
        # "Lightning Stream" and the owner's, as long as the app takes (60 characters) and with punctuation, so a found
        # block shows DATUM fits it in the coinbase and the node accepts it. With a pool, the pool's primary replaces ours
        tags = {"coinbase_tag_primary": "Lightning Stream", "coinbase_tag_secondary": OWNER_TAG} if mode == "solo" \
            else {"coinbase_tag_primary": "Lazarus", "coinbase_tag_secondary": "rental"}
        with open(f"{home}/gw.json", "w") as f:
            json.dump({"bitcoind": {"rpccookiefile": f"{home}/node/regtest/.cookie", "rpcurl": f"http://127.0.0.1:{rpc}", "work_update_seconds": 5, "notify_fallback": True},
                       "stratum": {"listen_addr": "127.0.0.1", "listen_port": st, "vardiff_min": 1, "fingerprint_miners": False},
                       "mining": {"pool_address": pool_address, **tags},
                       "api": {"listen_addr": "127.0.0.1", "listen_port": api, "admin_password": ""},
                       "logger": {"log_to_console": True, "log_to_file": False, "log_level_console": 1}, "datum": datum}, f)
        log = open(f"{RUN}/{mode}-gateway.log", "ab")
        PROCS.append(subprocess.Popen([DATUM_GATEWAY, "-c", f"{home}/gw.json"], stdout=log, stderr=log, env=env))
        with open(DATUM_GATEWAY, "rb") as f:
            REPORT[f"{mode}_gateway_binary"] = {"path": DATUM_GATEWAY, "sha256": hashlib.sha256(f.read()).hexdigest()}
        lab.wait(f"{mode}'s gateway", 60, lambda: socket.create_connection(("127.0.0.1", st), 1).close() or True, every=0.5)
        slice_work = 2**33
        t = ["--slice-work", str(slice_work), "--price-msat", str(PRICE_MSAT), "--grace-ms", "60000"]
        hashmaker = spawn(f"{mode}-hashmaker", ["hashmaker", "--key", f"{RUN}/keys/hasher.key", "--miners", f"127.0.0.1:{MINERS}", "--link", f"127.0.0.1:{LINK}", "--slices", f"127.0.0.1:{SLICES}",
                                                 *t, "--min-slice-s", "1800", "--report", f"{RUN}/{mode}-hasher.json", "--relays", RELAY_URL, "--nostr-key", f"{RUN}/keys/nostr.key",
                                                 "--name", "regtest hashmaker", "--link-public", f"127.0.0.1:{LINK}", "--pay-url", f"{ORIGIN}/hashrate", "--pay-node", lab.pubkey(d.SELLER),
                                                 "--hashrate-hs", "60000000", "--listing-out", f"{RUN}/{mode}-listing.json"])
        lab.wait("the hashmaker's listing", 30, lambda: os.path.exists(f"{RUN}/{mode}-listing.json"), every=0.2)
        time.sleep(0.5)
        # Mike's rule: no rental runs unmasked, pool or solo. Every rental holds each job to the gateway's API, so a
        # pool that doesn't take gateway keys gives jobs the renter must refuse
        check_flags = ["--gateway-api", f"127.0.0.1:{api}"]
        busy = busy_shim() if os.environ.get("P2P_HASH_BUSY_SIGNER") == "1" and keys else None
        hashtaker = spawn(f"{mode}-hashtaker", ["hashtaker", "--key", f"{RUN}/keys/buyer.key", "--find", RELAY_URL, "--expect-node", lab.pubkey(d.SELLER), "--found-out", f"{RUN}/{mode}-found.json",
                                                 "--upstream", f"127.0.0.1:{st}", "--user", address, "--signer", d.RENTER_SOCK, "--task", "hashrate", "--max-sats", "1500", "--rental", f"rt-{mode}",
                                                 "--idle-s", str(REAL_SECS), "--duration-s", str(REAL_SECS), "--report", f"{RUN}/{mode}-buyer.json", *check_flags],
                          env=busy[0] if busy else None)
        time.sleep(2)
        log = open(f"{RUN}/{mode}-miner.log", "ab")
        grind = subprocess.Popen(["nice", "-n", "15", f"{HG}/stratum-grind", "--host", "127.0.0.1", "--port", str(MINERS), "--user", "hasher.m1"], stdout=log, stderr=log, env=env)
        PROCS.append(grind)
        injected: list[dict[str, Any]] = []
        if busy:
            # mid-rental, a few bursts of busy-socket failures on the renter's payments (each burst: that many writes
            # in a row fail with nothing sent); each payment hit is asked again within the grace
            def bursts() -> None:
                # each burst waits for the one before to be used up by payments, so none is written over
                for at, n in ((0.2, 1), (0.4, 3), (0.6, 2)):
                    time.sleep(max(0.0, t_rent + at * REAL_SECS - time.time()))
                    while injected and "usedAtS" not in injected[-1]:
                        time.sleep(1)
                    with open(busy[1], "w") as f:
                        f.write(f"{n}\n")
                    injected.append({"atS": round(time.time() - t_rent), "writes": n})
                    while open(busy[1]).read().strip() != "0":
                        time.sleep(0.5)
                    injected[-1]["usedAtS"] = round(time.time() - t_rent)
            t_rent = time.time()
            threading.Thread(target=bursts, daemon=True).start()
        if mode == "solo":
            time.sleep(30)
            gateway_pages_check(mode, api, rpc, home)
        # the rental's time counts from its first accepted share, which can come minutes in on a loaded box
        hashtaker.wait(REAL_SECS + 300)
        if not keys:
            # the renter refuses the pool's first job and pays nothing, so the hashmaker never opens a rental and
            # never ends one by itself: stop it here rather than wait for an exit that doesn't come
            hashmaker.terminate()
            hashmaker.wait(30)
        else:
            hashmaker.wait(60)
        grind.terminate()
        height1 = int(cli("getblockcount"))
        if not keys:
            # a pool on the null key: the gateway opens its jobs as pool-null, and the renter refuses at its first job,
            # before any rental: it exits with the reason and writes no rental report, and the hashmaker is paid nothing
            with open(f"{RUN}/{mode}-hashtaker.log", errors="replace") as f:
                said = [ln.strip() for ln in f if "Not blinded" in ln]
            bz = {}
            if os.path.exists(f"{RUN}/{mode}-buyer.json"):
                with open(f"{RUN}/{mode}-buyer.json") as f:
                    bz = json.load(f)
            paid = len([p for p in bz.get("pays", []) if p.get("ok")])
            check(f"{mode}: a pool without gateway keys is refused: the renter stops at its first job, pays nothing, and no share reaches the gateway",
                  bool(said) and "null" in said[0] and "Nothing was paid" in said[0] and hashtaker.returncode not in (0, None) and paid == 0
                  and bz.get("jobsShownBlinded", 0) == 0 and (bz.get("meter") or {}).get("accepted", 0) == 0,
                  {"said": said[:1], "exit": hashtaker.returncode, "paid": paid, "report": {k: bz.get(k) for k in ("closed", "jobsShownBlinded", "meter")} if bz else None})
            return
        with open(f"{RUN}/{mode}-buyer.json") as f:
            bz = json.load(f)
        with open(f"{RUN}/{mode}-hasher.json") as f:
            hz = json.load(f)
        blocks = []
        for h in range(height0 + 1, height1 + 1):
            block_id = cli("getblockhash", str(h))
            m = masked_block(bytes.fromhex(cli("getblockheader", block_id, "false")))
            hdr = bytes.fromhex(cli("getblockheader", block_id, "false"))
            blocks.append({"height": h, "block": block_id, **m, "id_is_raw_xor_mask": m["id"] == block_id,
                           # what an ASIC hashes after the previous block: the nonce's 8 bytes (76..84), and ntime's (104..108, 84..88)
                           "header": {"nonce8": hdr[76:84].hex(), "ntime8": (hdr[104:108] + hdr[84:88]).hex(), "extranonce": hdr[88:104].hex()}})
        REPORT[f"{mode}_blocks"] = blocks
        if keys:
            # a found block publishes its key, and a hashmaker knows its own raw hash for it: so it can work out that
            # key's mask. No job after the block may commit to that key, or the hashmaker could spot wins on it
            seen = bz.get("keysSeen", [])
            reuse, later = [], 0
            for b in blocks:
                key = bytes.fromhex(cli("getblockheader", b["block"], "false"))[112:128]
                h = tagged("Bitcoin block hash PoW XOR key", key).hex()
                after = {x["block"] for x in blocks if x["height"] >= b["height"]}
                on_later = [k for k in seen if k["prevblock"] in after]
                later += len(on_later)
                reuse += [{"block": b["height"], "on a job after it": k} for k in on_later if k["keyHash"] == h]
            spans: dict[str, set[str]] = {}
            for k in seen:
                spans.setdefault(k["keyHash"], set()).add(k["prevblock"])
            spanning = {k: sorted(p) for k, p in spans.items() if len(p) > 1}
            REPORT[f"{mode}_key_reuse"] = {"jobs after a found block checked": later, "reused": reuse, "keys on two previous blocks": spanning}
            check(f"{mode}: no job after a found block commits to that block's key, and no key spans two previous blocks",
                  later > 0 and not reuse and not spanning,
                  {"jobs after a found block checked": later, "keys seen": len(seen), "reused": reuse, "keys on two previous blocks": spanning})
        if mode == "solo":
            pays = [any(o["scriptPubKey"]["hex"] == payout_script for o in json.loads(cli("getblock", b["block"], "2"))["tx"][0]["vout"]) for b in blocks]
            check(f"solo: every block's coinbase pays the renter's address ({pool_address[:6]}...)", blocks and all(pays),
                  {"address": pool_address, "script": payout_script, "paid by block": pays})
            # the owner's coinbase tag in every block the node took: "Lightning Stream", 0x0f, the owner's tag, 0x00
            want = b"Lightning Stream\x0f" + OWNER_TAG.encode() + b"\x00"
            sigs = [json.loads(cli("getblock", b["block"], "2"))["tx"][0]["vin"][0]["coinbase"] for b in blocks]
            check(f"solo: every block the node accepted carries the owner's {len(OWNER_TAG)}-character coinbase tag after the app's own",
                  bool(blocks) and all(want.hex() in c for c in sigs),
                  {"tag": OWNER_TAG, "coinbase scriptSigs": sigs})
        if keys:
            check(f"{mode}: real masked blocks reached the node through the rental, each with a key, the share's clear_bits, and its id the raw hash XOR the mask",
                  len(blocks) >= 1 and all(not b["key_null"] and b["clear_bits"] == 32 and b["id_is_raw_xor_mask"] and b["raw"].startswith("00000000") for b in blocks),
                  {"height": [height0, height1], "blocks": blocks})
            check(f"{mode}: the hashtaker held every job to what the gateway opened on its API", bz["jobsShownBlinded"] >= 1 and bz["closed"] == "rental time over",
                  {"jobs shown blinded": bz["jobsShownBlinded"], "closed": bz["closed"]})
            # a rental keeps its miners across block changes: every new block's first (empty) job, and the jobs sent
            # while a coinbaser is late, are opened on the API, so no block change ends it
            prevs = {k["prevblock"] for k in bz.get("keysSeen", [])}
            how = " with a late coinbaser" if mode == "pool" and os.environ.get("P2P_HASH_LATE_COINBASER") == "1" else ""
            check(f"{mode}: the rental kept its miners across {len(blocks)} block changes{how}, to the end of its time",
                  len(blocks) >= 2 and len(prevs) >= len(blocks) and bz["closed"] == "rental time over"
                  and not [e for e in bz.get("events", []) if e.get("ev") == "a job not shown to be blinded"],
                  {"blocks": len(blocks), "previous blocks its jobs were on": len(prevs), "closed": bz["closed"],
                   "refused": [e for e in bz.get("events", []) if e.get("ev") == "a job not shown to be blinded"][:2],
                   **({"pool replies held": late.held} if mode == "pool" and late else {})})
        else:
            REPORT.setdefault("skipped", []).append({"check": f"{mode}: masked blocks", "missing": "a primed that takes gateway-held keys"})
            print(f"SKIP  {mode}: masked blocks: no primed that takes gateway-held keys; this run's blocks are unblinded", flush=True)
            check(f"{mode}: real blocks reached the node through the rental", len(blocks) >= 1, {"height": [height0, height1], "blocks": blocks})
        # each block's share, among those the hashmaker proved: by its raw hash, and by the fields the header carries
        proven = {p["hash"]: p for p in hz.get("provenShares", [])}
        matched = []
        for b in blocks:
            p = proven.get(b["raw"])
            eight = lambda x: x if len(x) == 16 else bytes.fromhex(x)[::-1].hex() + "00000000"  # noqa: E731  (as a gateway reads it)
            matched.append({"height": b["height"], "block": b["block"][:16], "proven share": p and {k: p[k] for k in ("job", "en2", "ntime", "nonce", "atMs")},
                            "header": b["header"],
                            "nonce matches": bool(p) and eight(p["nonce"]) == b["header"]["nonce8"], "ntime matches": bool(p) and eight(p["ntime"]) == b["header"]["ntime8"],
                            "en2 in extranonce": bool(p) and p["en2"] in b["header"]["extranonce"]})
        REPORT[f"{mode}_share_to_block"] = matched
        check(f"{mode}: each block's share is one the hashmaker proved, matched by raw hash, nonce, ntime and extranonce", blocks and all(x["proven share"] and x["nonce matches"] and x["ntime matches"] and x["en2 in extranonce"] for x in matched), matched)
        same = (hz["meter"]["work"], hz["meter"]["proven"]) == (bz["meter"]["work"], bz["meter"]["proven"])
        # a share on its way when a found block moved the gateway to a new job is turned down as stale, by the gateway
        # and in both counts alike: no more of those than blocks found, and no rejection of any other kind
        stale_only = bz["meter"]["rejected"] == bz["meter"]["stale"] <= len(blocks) and hz["meter"]["rejected"] == bz["meter"]["rejected"]
        check(f"{mode}: both sides proved the same real shares, the gateway accepted them (but shares a found block made stale), none refused, none past what's paid",
              same and hz["meter"]["proven"] >= 1 and bz["meter"]["accepted"] >= 1 and stale_only and hz["meter"]["refused"] == 0 and bz["meter"]["refused"] == 0
              and int(hz["meter"]["work"]) <= hz["paid"] * slice_work,
              {"hashmaker": hz["meter"], "hashtaker": bz["meter"], "paid": hz["paid"], "blocks found": len(blocks)})
        oks = [p for p in bz["pays"] if p.get("ok")]
        if busy:
            left = open(busy[1]).read().strip()
            check(f"{mode}: the wallet's socket busy {sum(i['writes'] for i in injected if 'usedAtS' in i)} times mid-rental (EAGAIN, nothing sent): each payment asked again "
                  "and paid once, none failed or left unknown, and the rental ran to its end",
                  sum(i["writes"] for i in injected if "usedAtS" in i) >= 3 and any(i["writes"] >= 2 and "usedAtS" in i for i in injected) and not bz["payFailed"] and all(p.get("ok") is True for p in bz["pays"]) and bz["closed"] == "rental time over"
                  and len(oks) == hz["paid"],
                  {"injected": injected, "left": left, "pays": len(bz["pays"]), "ok": len(oks), "hashmaker paid": hz["paid"], "closed": bz["closed"],
                   "slowest pay ms": max([p.get("ms", 0) for p in bz["pays"]] or [0])})
        priced = sum(int(p["wallet"].get("price_msat", 0)) for p in oks)
        check(f"{mode}: the wallet's real payments = what the hashmaker earned", priced == hz["earnedMsat"] == hz["paid"] * PRICE_MSAT and hz["paid"] == len(oks) and not bz["payFailed"],
              {"priced": priced, "earned": hz["earnedMsat"], "paid": hz["paid"], "wallet ok": len(oks)})
        if mode == "pool":
            try:
                import urllib.request
                seen = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{stats}/stats.json", timeout=5).read())
            except (OSError, ValueError) as e:
                seen = {"error": str(e)}
            REPORT["pool_primed"] = seen
            totals = seen.get("totals", seen)
            keyed = int(totals.get("gateway_key_blocks", 0)) >= 1 and int(totals.get("gateway_key_refused", 0)) == 0 and int(totals.get("gateway_key_false_blocks", 0)) == 0
            check("pool: primed took the rental's shares and submitted its blocks" + (", each on the gateway's key" if keys else ""),
                  int(totals.get("shares_accepted", 0)) >= 1 and int(totals.get("blocks_submitted", 0)) >= 1 and (keyed or not keys),
                  {k: v for k, v in totals.items() if "share" in k or "block" in k or "gateway_key" in k})
    finally:
        for p in PROCS:
            if p.poll() is None and p.args and any(x in str(p.args[0]) for x in ("datum_gateway", "stratum-grind", "primed", "nice")):
                p.terminate()
        subprocess.run([f"{HG}/bitcoin-cli", f"-datadir={home}/node", "stop"], env=env, capture_output=True)


def main() -> int:
    t0 = time.time()
    try:
        setup()
        print(f"lab up in {time.time() - t0:.0f} s", flush=True)
        inv0 = d.seller_invoices()
        pay0 = d.buyer_payments()
        if os.environ.get("P2P_HASH_ONLY") == "reprice":
            reprice_check()
            raise StopIteration
        if os.environ.get("P2P_HASH_ONLY") == "slow":
            slow_check()
            raise StopIteration
        if os.environ.get("P2P_HASH_ONLY") == "topup":
            topup_check()
            raise StopIteration
        only_real = os.environ.get("P2P_HASH_ONLY") == "real"
        if only_real:
            for mode in os.environ.get("P2P_HASH_REAL_MODES", "solo,pool").split(","):
                real_gateway(mode)
            raise StopIteration
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
        check("paid: every slice paid once through the wallet, each ahead of its work", paid >= 6 and len(oks) == paid and paid >= len(hz["slicesDone"]) and not bz["payFailed"],
              {"hashmaker paid": paid, "wallet ok": len(oks), "slices' worth proven": len(hz["slicesDone"]), "pay ms": [p["ms"] for p in bz["pays"]]})
        same = (hz["meter"]["work"], hz["meter"]["proven"]) == (bz["meter"]["work"], bz["meter"]["proven"])
        check("paid: both sides' proven counts equal, none past what's paid, shares nobody hashed refused",
              same and int(hz["meter"]["work"]) <= paid * SLICE_WORK and hz["meter"]["refused"] > 0 and bz["meter"]["refused"] == 0,
              {"meter": hz["meter"], "the hashtaker's meter": bz["meter"], "paid work": paid * SLICE_WORK})
        priced = sum(int(p["wallet"].get("price_msat", 0)) for p in oks)
        last_w = oks[-1]["wallet"] if oks else {}
        spent = int(last_w.get("credited_msat", 0)) - int(last_w.get("balance_msat", 0))
        rails = sorted({p["wallet"].get("rail") for p in oks})
        held_used = [p["slice"] for p in oks if int(p["wallet"].get("tickets_released", 0)) > 0 and int(p["wallet"].get("tickets_prepaid", 0)) == 0]
        prepaid_used = [p["slice"] for p in oks if int(p["wallet"].get("tickets_prepaid", 0)) > 0]
        check("paid: the gateway spent exactly slices x price, on prepaid tickets only (a rental task holds nothing)",
              priced == spent == paid * PRICE_MSAT and rails == ["ticket"] and prepaid_used and not held_used,
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
              last <= r["done_ms"] + 5000 and bz["closed"] == "no proven work" and stopped and d.held() == 0,
              {"last pay before miners stopped ms": r["done_ms"] - last, "closed": bz["closed"], "stop": stopped[:1], "held": d.held()})

        r = rental("unpaid", 3, 90, 1.5)
        hz, bz = r["hasher"], r["buyer"]
        st = hz["stopped"] or {}
        past = int(st.get("work", "0")) - 3 * SLICE_WORK
        REPORT["unpaid_pays"] = bz["pays"]
        check("unpaid: the hashmaker stops with no share past what's paid",
              st.get("reason") == "unpaid" and hz["paid"] == 3 and past <= 0,
              {"stopped": st.get("reason"), "paid": hz["paid"], "work past what's paid": past, "a share": SHARE, "unpaid": st.get("unpaidWork")})
        oks = [p for p in bz["pays"] if p.get("ok")]
        check("unpaid: the wallet paid 3 slices and no more", len(oks) == 3 and sum(int(p["wallet"].get("price_msat", 0)) for p in oks) == 3 * PRICE_MSAT,
              {"pays": [(p["slice"], p.get("ok")) for p in bz["pays"]]})

        # a rental smaller than the shop's ticket, from no credit at the second gateway
        inv0, pay0 = d.seller_invoices(), d.buyer_payments()
        # the hashtaker's own call with the old caps (max_sats = the budget, no charge cap), on its socket: no ticket fits
        old = d.signer("xbt402_pay", {"url": f"{ORIGIN2}/hashrate/rt-old/1", "method": "POST", "body": "{}",
                                      "max_sats": SMALL_BUDGET_SATS, "task": "hashrate"}, sock=d.RENTER_SOCK)
        old.pop("untrusted_provider_response", None)
        moved = {h: p["status"] for h, p in d.buyer_payments().items() if h not in pay0}
        check("small: with the old caps (max_sats = the 500-sat budget) a slice from no credit is refused, nothing paid",
              old.get("verdict") != "allow" and int(old.get("charged_sats", 0)) == 0 and not moved and d.held() == 0,
              {"verdict": old.get("verdict"), "rule": old.get("rule"), "reason": str(old.get("reason"))[:200],
               "charged_sats": old.get("charged_sats"), "payments": moved})
        # a rental whose budget is under the smallest ticket any seller sells (546 sat): refused before any work, nothing paid,
        # and the renter told why
        r = rental("small", None, 20, 1.5, origin=ORIGIN2, caps=("--budget-sats", str(SMALL_BUDGET_SATS)))
        hz, bz = r["hasher"], r["buyer"]
        REPORT["small_pays"] = bz["pays"]
        moved = {h: p["status"] for h, p in d.buyer_payments().items() if h not in pay0}
        why = " ".join(str(p.get("why", "")) for p in bz["pays"])
        check("small: a budget under the smallest ticket is refused before any work, with nothing paid and the reason said",
              hz["paid"] == 0 and int(hz["meter"]["work"]) == 0 and bz["payFailed"] and not moved and d.held() == 0 and "smallest ticket" in why,
              {"hashmaker paid": hz["paid"], "work": hz["meter"]["work"], "closed": bz["closed"], "why": why[:300], "payments": moved, "held": d.held()})

        topup_check()
        drop_check()
        slow_check()
        real_gateway("solo")
        real_gateway("pool")
    except StopIteration:
        pass
    except (lab.LabError, OSError, KeyError, IndexError, ValueError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        check("ran to its end", False, f"{type(e).__name__}: {e}")
    finally:
        for p in PROCS + list(d.PROCS.values()):
            if p.poll() is None:
                p.terminate()
    REPORT["seconds"] = round(time.time() - t0)
    with open(os.path.join(OUT, "p2p_hash_regtest.json"), "w") as f:
        json.dump(REPORT, f, indent=1)
    ok = all(c["ok"] for c in REPORT["checks"])
    skipped = REPORT.get("skipped", [])
    print(f"p2p_hash_regtest: {sum(c['ok'] for c in REPORT['checks'])} of {len(REPORT['checks'])} checks passed, {len(skipped)} skipped, {REPORT['seconds']} s", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
