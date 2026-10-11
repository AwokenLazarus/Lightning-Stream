#!/usr/bin/env python3
"""Failure paths through the real binaries on regtest, driven by scripts/failure_interop.sh.

Every other interop script runs the happy path. This one breaks something on purpose and checks what
the shipped binaries, at their shipped defaults, do about it. The binaries are the release ones; what
is ours is the wire between them (scripts/interop/faults.py), the signals we send them, and the
regtest node that is faucet, miner and oracle.

  A  an answer lost on a direct channel: the next call resyncs and the lost call is paid once
       A1 the signer's own pay rail (xbt-signer, `xbt402_pay`)
       A2 the library client (xbt-wallet-mcp, XBT_MCP_PAYER=local, keys in the signer)
       A3 two answers lost in a row, on the signer's rail
  B  a provider that stops answering (SIGSTOP: the connection opens, nothing comes back)
       B1 direct: the call ends, nothing more is signed, the channel is refunded at its expiry
       B2 behind a hub: the hub sets that provider aside, the other provider keeps being paid, and
          the first is routed to again once it answers
  C  one hostile Electrum server among two honest ones; the light wallet still refunds at expiry
       C1 it holds its answers   C2 it hides the wallet's transactions   C3 it sends malformed numbers
  D  SIGKILL and restart in the middle of a payment: nothing signed unbooked, nothing lost
       D1 the provider   D2 the signer, with its signed request on the wire   D3 the hub
  E  a seller that says yes to the open's preflight and refuses the funded open: funded once,
     refunded at expiry
       E1 the signer's rail   E2 the library client

  S  the shipped defaults against each other: a signer policy that is the default plus an allowlist

Each check prints PASS or FAIL with what it observed. A FAIL listed in KNOWN_OPEN is a recorded
defect (docs/LIMITS.md, "Open items") and does not fail the run; any other FAIL does.

Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT, RS_BIN, FAIL_PB, FAIL_RUN; FAIL_ONLY (e.g. "A1,C2,D");
ELECTRS (the electrs binary, for C; without it C is reported as not run).
"""
import base64
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
B1 = os.environ["XBT402_B1"]
sys.path.insert(0, B1)
sys.path.insert(0, HERE)
from faults import ElectrumFaultProxy, HttpFaultProxy
from xbt402.rpc import RPC
from xbt402.x402_channel import network_id

RS = os.environ["RS_BIN"]
PB = int(os.environ["FAIL_PB"])
RUN = os.environ["FAIL_RUN"]
COOKIE = os.path.join(os.environ["XBT402_DATADIR"], "regtest", ".cookie")
RPCPORT = os.environ["XBT402_RPCPORT"]
ONLY = [x for x in os.environ.get("FAIL_ONLY", "").split(",") if x]
SAT = 100_000_000
PRICE = 150            # xbt402-rust-provider's shipped price per call, sat
DUST = 546
CAP = 100_000          # the signer's per_counterparty_cap_sats here: the capacity of each channel it funds

# Checks the code is known to fail: "id" -> where it is recorded. A check listed here that fails is
# printed as FAIL (open item) and does not fail the run; when it passes, take it off this list.
KNOWN_OPEN = {
    "S1": "open: AGP-111 item 2",       # a policy without per_counterparty_cap_sats cannot pay the shipped provider
    "A1.2": "open: AGP-111 item 1",     # the signer's rail: a call whose answer was lost is not paid at the close
    "A3.2": "open: AGP-111 item 1",
    "D2.4": "open: AGP-111 item 1",
}

node = RPC.from_env()
W = node.wallet("w")
ADDR = W.getnewaddress()
NET = network_id(node.getblockhash(101))
LOG = open(os.path.join(RUN, "failure_interop.log"), "a")  # noqa: SIM115 (open for the life of the run: every child writes to it)
results, procs, proxies = [], [], []
group = {"id": ""}


def say(*a):
    print(*a, flush=True)


def check(cid, what, ok, observed=""):
    ok = bool(ok)
    known = KNOWN_OPEN.get(cid)
    results.append({"id": cid, "check": what, "ok": ok, "observed": str(observed), "open_item": known})
    tag = "PASS" if ok else (f"FAIL (open item: {known})" if known else "FAIL")
    if ok and known:
        tag = "PASS (listed as open: take it off KNOWN_OPEN)"
    say(f"{tag}  {cid}  {what}" + (f"\n        observed: {observed}" if observed != "" else ""))
    return ok


def note(cid, what, observed):
    results.append({"id": cid, "note": what, "observed": str(observed)})
    say(f"NOTE  {cid}  {what}: {observed}")


def mine(n=1):
    left = n
    while left > 0:
        k = min(left, 200)
        node.generatetoaddress(k, ADDR)
        left -= k


def mine_to(height):
    mine(max(0, height - node.getblockcount()))


class Mining:
    """A block every `every` seconds while a payment needs its funding confirmed."""

    def __init__(self, every=0.5):
        self.every, self.stop = every, threading.Event()

    def __enter__(self):
        def run():
            while not self.stop.wait(self.every):
                try:
                    mine()
                except Exception as e:  # noqa: BLE001
                    LOG.write(f"miner: {e}\n")
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.thread.join(10)


NICE = ["nice", "-n", "19"]      # nice execs the program: the pid we signal is the binary's own


def spawn(cmd, env=None, cwd=None, stdin=None, stdout=None):
    LOG.flush()
    p = subprocess.Popen(NICE + cmd, stdout=stdout or LOG, stderr=LOG, stdin=stdin, env=env, cwd=cwd)
    procs.append(p)
    return p


def stop(p, sig=signal.SIGTERM):
    if p and p.poll() is None:
        try:
            p.send_signal(signal.SIGCONT)
            p.send_signal(sig)
            p.wait(10)
        except (subprocess.TimeoutExpired, ProcessLookupError):
            p.kill()
            p.wait(10)


def kill9(p):
    p.send_signal(signal.SIGKILL)
    p.wait(10)


def wait_http(url, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except OSError:
            time.sleep(0.2)
    return False


def http_json(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def tx_outputs(txid):
    """(confirmations, {spk hex: sats}) of a transaction, from the node."""
    tx = node.getrawtransaction(txid, True)
    outs = {}
    for o in tx["vout"]:
        outs[o["scriptPubKey"]["hex"]] = outs.get(o["scriptPubKey"]["hex"], 0) + round(o["value"] * SAT)
    return tx.get("confirmations", 0), outs


def spends_of(txid, vout):
    """The txid that spends an outpoint (mined or in the mempool), or None."""
    r = node.gettxspendingprevout([{"txid": txid, "vout": vout}])[0]
    if r.get("spendingtxid"):
        return r["spendingtxid"]
    if node.gettxout(txid, vout, True) is not None:
        return None
    # spent and mined: find it in the blocks since the funding
    h = node.getrawtransaction(txid, True).get("blockhash")
    height = node.getblock(h)["height"] if h else node.getblockcount()
    for i in range(height, node.getblockcount() + 1):
        for tx in node.getblock(node.getblockhash(i), 2)["tx"]:
            if any(v.get("txid") == txid and v.get("vout") == vout for v in tx["vin"]):
                return tx["txid"]
    return "spent"


# --- the provider, the signer, the wallet MCP ------------------------------------------------------

def start_provider(name, port, extra=()):
    d = os.path.join(RUN, name)
    p = spawn([f"{RS}/xbt402-rust-provider", "--port", str(port), "--rpc-port", RPCPORT, "--cookie", COOKIE, "--data-dir", d, *extra])
    assert wait_http(f"http://127.0.0.1:{port}/x402/supported"), f"provider {name} did not come up"
    return p


class Signer:
    """xbt-signer on a Unix socket. The policy is the shipped default with the seller on the
    allowlist and two more lines: `per_counterparty_cap_sats` (check S1 is why) and
    `regtest_mine: false`, so that the signer waits for a funding's confirmation as it does on a real
    network and does not mine it itself. Every other budget, wait and margin is the shipped one."""

    def __init__(self, name, allow, fund_sats=2_000_000, policy=None, cap=CAP):
        self.dir = os.path.join(RUN, name)
        self.root = os.path.join(self.dir, "signer")
        os.makedirs(self.root, exist_ok=True)
        self.key = os.path.join(self.dir, "signer.key")
        with open(self.key, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(self.key, 0o600)
        self.policy = {"allowlist": list(allow), "regtest_mine": False}
        if cap:
            self.policy["per_counterparty_cap_sats"] = cap
        self.policy.update(policy or {})
        with open(os.path.join(self.root, "policy.json"), "w") as f:
            json.dump(self.policy, f, indent=1)
        self.sock = os.path.join(self.root, "signer.sock")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("B2_", "XBT_MCP_"))}
        self.env.update({"B2_ROOT": self.root, "B2_DATADIR": os.environ["XBT402_DATADIR"], "B2_RPCPORT": RPCPORT, "B2_WALLET": "agent",
                         "B2_CHAIN": "regtest", "B2_SIGNER_SOCK": self.sock, "B2_CONF": "/dev/null", "B2_HOT_KEYFILE": self.key})
        self.proc = None
        self.start()
        hot = self.call("hot_address")
        self.hot_spk, self.hot_address = hot["hot_spk"], hot["hot_address"]
        txid = W.sendtoaddress(self.hot_address, fund_sats / SAT)
        mine()
        self.call("notice_hot_txid", txid=txid)
        self.funded = fund_sats

    def start(self):
        if os.path.exists(self.sock):
            os.unlink(self.sock)
        self.proc = spawn([f"{RS}/xbt-signer", "--root", self.root], env=self.env)
        end = time.time() + 30
        while time.time() < end and not os.path.exists(self.sock):
            time.sleep(0.1)
        h = self.call("health")
        assert h.get("implementation") == "xbt-signer (Rust)", h

    def raw(self, rpc, timeout=2400, **params):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.settimeout(timeout)
            c.connect(self.sock)
            c.sendall((json.dumps({"id": 1, "method": rpc, "params": params}) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
        if not buf:
            raise ConnectionError(f"signer closed the socket on {rpc}")
        return json.loads(buf)

    def call(self, rpc, timeout=2400, **params):
        r = self.raw(rpc, timeout, **params)
        if r.get("error"):
            raise RuntimeError(f"signer {rpc}: {r['error']}")
        return r["result"]

    def pay(self, url, max_sats=1000, method="POST", body="{}"):
        t0 = time.time()
        try:
            r = self.call("xbt402_pay", url=url, method=method, body=body, max_sats=max_sats)
        except (RuntimeError, OSError, ValueError) as e:
            r = {"verdict": "error", "reason": f"{type(e).__name__}: {e}"}
        r["_secs"] = round(time.time() - t0, 1)
        return r

    def channel(self, origin):
        for c in self.call("channels")["channels"]:
            if c.get("dest") == origin or c.get("origin") == origin:
                return c
        return None

    def signatures(self):
        s = self.call("signatures", limit=100000)
        return s.get("signatures") or [], s.get("chain_ok")


class WalletMcp:
    """xbt-wallet-mcp on stdio, paying with the library client (XBT_MCP_PAYER=local): xbt402's
    Client in that process, its keys and its funding in the signer, its book in a ledger file."""

    def __init__(self, signer, name):
        self.signer, self.ledger, self.id = signer, os.path.join(signer.dir, f"{name}.jsonl"), 0
        self.env = dict(signer.env)
        self.env.update({"XBT_MCP_PAYER": "local", "XBT_MCP_NETWORK": NET, "XBT_MCP_LEDGER": self.ledger})
        self.start()

    def start(self):
        self.proc = spawn([f"{RS}/xbt-wallet-mcp", "--stdio"], env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        r = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "failure-interop", "version": "0"}})
        assert "result" in r, r
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def send(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def rpc(self, method, params):
        self.id += 1
        self.send({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise ConnectionError("xbt-wallet-mcp closed its stdout")
            msg = json.loads(line)
            if msg.get("id") == self.id:
                return msg

    def tool(self, name, **args):
        t0 = time.time()
        try:
            r = self.rpc("tools/call", {"name": name, "arguments": args})
            res = r.get("result") or {}
            sc = res.get("structuredContent") or {}
            text = sc.get("result") if isinstance(sc.get("result"), str) else (res.get("content") or [{}])[0].get("text", "")
            try:
                out = json.loads(text)
            except ValueError:
                out = {"verdict": "error", "reason": text or json.dumps(r)[:300]}
        except (OSError, ValueError) as e:
            out = {"verdict": "error", "reason": f"{type(e).__name__}: {e}"}
        if not isinstance(out, dict):
            out = {"value": out}
        out["_secs"] = round(time.time() - t0, 1)
        return out

    def pay(self, url, max_sats=1000, method="POST", body="{}"):
        return self.tool("xbt402_pay", url=url, method=method, body=body, max_sats=max_sats)


def brief(r):
    keep = ("verdict", "rule", "status", "charged_sats", "booked_sats", "cum", "owed_sats", "reason", "_secs")
    out = {k: r[k] for k in keep if k in r}
    if isinstance(out.get("reason"), str):
        out["reason"] = out["reason"][:160]
    return out


def ensure_agent_wallet():
    if "agent" not in node.listwallets():
        try:
            node.loadwallet("agent")
        except Exception:  # noqa: BLE001
            node.createwallet("agent", True, True, "", False, True)   # the signer's watch-only wallet


def lose_served(proxy, which, then=None):
    """The answers to the paid calls the seller served (answered 200) whose 1-based number among
    those is in `which` are lost on the way back. `then(req)` runs first, with the answer still
    unsent. A paid request the seller answers with a 402 is passed on: it served nothing."""
    state = {"served": 0, "lock": threading.Lock()}

    def after(req):
        if not req["paid"] or req["path"].startswith("/x402/") or req["status"] != 200:
            return
        with state["lock"]:
            state["served"] += 1
            k = state["served"]
        if k in which:
            req["action"] = "lose"
            if then:
                then(req)
    proxy.after = after


def served_calls(proxy):
    """Paid requests the seller answered 200 (it served them and charged them), and how many of
    those answers we threw away."""
    paid = [r for r in proxy.paid() if not r["path"].startswith("/x402/")]
    served = [r for r in paid if r["status"] == 200]
    return len(served), sum(1 for r in served if r["action"] == "lose"), [(r["action"], r["status"]) for r in paid]


def close_amounts(close_txid, hot_spk):
    """(confirmations, the close's outputs that are not the payer's change to its hot key)."""
    conf, outs = tx_outputs(close_txid)
    return conf, {k: v for k, v in outs.items() if k != hot_spk}


# --- A: a lost answer on a direct channel ----------------------------------------------------------

def lost_answer(cid, rail, lose, calls):
    """`calls` paid calls through a proxy that loses the answers numbered in `lose`."""
    i = {"A1": 0, "A2": 1, "A3": 2, "A4": 3}[cid]
    pport, xport = PB + 10 + 2 * i, PB + 11 + 2 * i
    start_provider(f"{cid}-provider", pport)
    proxy = HttpFaultProxy(xport, pport)
    lose_served(proxy, set(lose))
    proxies.append(proxy)
    s = Signer(f"{cid}-signer", [proxy.url])
    payer = s if rail == "signer" else WalletMcp(s, "mcp-payer")
    outs = []
    with Mining():
        for k in range(calls):
            r = payer.pay(f"{proxy.url}/v1/infer?i={k}", body=json.dumps({"q": k}))
            outs.append(r)
            LOG.write(f"{cid} call {k}: {json.dumps(r)[:600]}\n")
    served, lost, trace = served_calls(proxy)
    got = [r for r in outs if r.get("status") == 200 and r.get("verdict") != "deny"]
    failed = [(k, brief(r)) for k, r in enumerate(outs) if not (r.get("status") == 200 and r.get("verdict") != "deny")]
    check(f"{cid}.1", f"{len(lose)} answer(s) lost on the way: the call(s) fail, every other call is answered 200",
          lost == len(lose) and len(got) == calls - len(lose) and len(failed) == len(lose),
          f"{calls} calls: {len(got)} answered, {len(failed)} failed {failed}; the seller served {served}; wire {trace}")
    # what the seller is owed: one price for each call it served, the lost ones among them, once
    owed = served * PRICE
    close = payer.tool("close_channel", counterparty=proxy.url) if rail != "signer" else s.call("close_channel", counterparty=proxy.url)
    LOG.write(f"{cid} close: {json.dumps(close)[:800]}\n")
    txid = close.get("txid")
    mine()
    if not txid:
        check(f"{cid}.2", "the channel closes cooperatively after the lost answer(s)", False, json.dumps(close)[:300])
        return
    conf, others = close_amounts(txid, s.hot_spk)
    payee = sum(others.values())
    check(f"{cid}.2", "the lost call is paid once: the close pays the seller one price per call it served, no more and no less",
          conf >= 1 and len(others) == 1 and payee == max(owed, DUST),
          f"seller's output {payee} sat; it served {served} calls x {PRICE} = {owed}; {len(got)} answers received; close report "
          f"{close.get('close_report')}; close {txid[:16]} confirmed {conf}")
    time.sleep(1.0)
    rec2 = s.channel(proxy.url) or {}
    sigs, chain_ok = s.signatures()
    check(f"{cid}.3", "the signer's book is the chain: its channel is closed at what the close paid, one funding, its signature log intact",
          rec2.get("state") == "closed" and rec2.get("used_sats") == payee and chain_ok is True
          and sum(1 for x in sigs if x.get("kind") == "funding") == 1,
          f"signer record state {rec2.get('state')}, used_sats {rec2.get('used_sats')}, closed_txid {str(rec2.get('closed_txid'))[:16]}, "
          f"fundings signed {sum(1 for x in sigs if x.get('kind') == 'funding')}, log chain_ok {chain_ok}")


def group_s():
    """the shipped defaults against each other"""
    start_provider("S1-provider", PB + 8)
    url = f"http://127.0.0.1:{PB + 8}"
    s = Signer("S1-signer", [url], fund_sats=40_000_000, cap=None)
    before = set(node.getrawmempool())
    with Mining(every=5):
        r = s.pay(f"{url}/v1/infer", body="{}")
        sent = len(set(node.getrawmempool()) - before)
    check("S1", "a signer whose policy is the built-in default plus an allowlist pays the shipped provider",
          r.get("status") == 200 and r.get("verdict") != "deny",
          f"{brief(r)}; fundings sent: {sent}; channel record {s.channel(url)}")


def group_a():
    """an answer lost on a direct channel"""
    # the 5th call on: the channel's first state is its 546 sat floor, which covers the first three
    # calls, so an answer lost before the 4th costs nobody anything and shows nothing
    for cid, rail, lose, calls in (("A1", "signer", [5], 7), ("A2", "client", [5], 7), ("A3", "signer", [5, 6], 8), ("A4", "client", [5, 6], 8)):
        if selected(cid):
            lost_answer(cid, rail, lose, calls)


def wire_cum(req):
    """The cumulative amount the paid request `req` carried (PAYMENT-SIGNATURE), or None."""
    try:
        raw = req["headers"]["payment-signature"]
        pl = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))["payload"]
        return int(pl["cum"])
    except (KeyError, ValueError, TypeError):
        return None


def refund_at_expiry(cid, n, s, origin, funding_txid, what):
    """Mine to the channel's expiry and let the signer's own watcher refund it; check the coins."""
    rec = s.channel(origin) or {}
    expiry = rec.get("expiry")
    if not expiry:
        return check(f"{cid}.{n}", what, False, f"no channel record with an expiry: {rec}")
    fund = node.getrawtransaction(funding_txid, True)
    chan_out = max(fund["vout"], key=lambda o: 0 if o["scriptPubKey"]["hex"] == s.hot_spk else 1)
    vout, funded = chan_out["n"], round(chan_out["value"] * SAT)
    mine_to(expiry - 1)
    early = spends_of(funding_txid, vout)
    mine_to(expiry + 1)
    end, spender = time.time() + 180, None
    while time.time() < end and not spender:      # the watcher's own tick; nobody asks it
        spender = spends_of(funding_txid, vout)
        if not spender:
            time.sleep(1)
    waited = round(180 - (end - time.time()), 1)
    mine()
    time.sleep(1.5)
    rec2 = s.channel(origin) or {}
    back = fee = None
    if spender and spender != "spent":
        outs = tx_outputs(spender)[1]
        back, fee = outs.get(s.hot_spk, 0), funded - sum(outs.values())
    return check(f"{cid}.{n}", what,
                 early is None and spender and back is not None and back + fee == funded and len(outs) == 1 and 0 < fee <= 2000
                 and rec2.get("state") == "refunded" and rec2.get("refund_txid") == spender,
                 f"channel output {funded} sat unspent one block before expiry {expiry}: {early is None}; the watcher's refund "
                 f"{str(spender)[:16]} came {waited} s after expiry: {back} sat back to the hot key, fee {fee}; signer record "
                 f"state {rec2.get('state')}")


# --- B1: a provider that stops answering, direct -----------------------------------------------------

def stops_answering_direct():
    port = PB + 20
    prov = start_provider("B1-provider", port)
    url = f"http://127.0.0.1:{port}"
    s = Signer("B1-signer", [url])
    with Mining():
        first = [s.pay(f"{url}/v1/infer?i={k}") for k in range(2)]
    rec0 = s.channel(url) or {}
    prov.send_signal(signal.SIGSTOP)          # the kernel still accepts connections; nothing answers
    dead = [s.pay(f"{url}/v1/infer?i={k}") for k in (2, 3)]
    rec1 = s.channel(url) or {}
    check("B1.1", "the provider stops answering: each call ends by itself and is refused, with no answer handed on",
          all(r.get("status") == 200 for r in first) and all(r.get("verdict") in ("deny", "error") for r in dead)
          and all(r["_secs"] < 120 for r in dead),
          f"2 calls answered, then {[brief(r) for r in dead]}")
    check("B1.2", "nothing more is signed while it is silent: at most the one state the first unanswered call carried",
          rec1.get("used_sats", 0) - rec0.get("used_sats", 0) <= PRICE and rec1.get("state") == "open",
          f"signed {rec0.get('used_sats')} sat before the silence, {rec1.get('used_sats')} sat after two unanswered calls")
    close = s.raw("close_channel", counterparty=url).get("result", {})
    note("B1", "a cooperative close while the provider is silent", brief(close))
    refund_at_expiry("B1", 3, s, url, rec0.get("funding_txid"),
                     "at the channel's expiry the signer's watcher refunds it: the whole channel returns to the hot key")
    prov.send_signal(signal.SIGCONT)


# --- D1, D2: SIGKILL and restart mid-payment ---------------------------------------------------------

def kill_provider():
    pport, xport = PB + 22, PB + 23
    name, state = "D1-provider", {"prov": None, "killed": 0}
    state["prov"] = start_provider(name, pport)
    proxy = HttpFaultProxy(xport, pport)
    proxies.append(proxy)

    def die(req):
        # the provider has served this call and booked it; it dies before the answer can leave
        # (the answer is lost), and comes back on the same data directory
        state["killed"] += 1
        kill9(state["prov"])
        state["prov"] = start_provider(name, pport)
    lose_served(proxy, {5}, die)
    s = Signer("D1-signer", [proxy.url])
    payer = WalletMcp(s, "mcp-payer")       # the library client: its lost answers are paid exactly (A2)
    with Mining():
        outs = [payer.pay(f"{proxy.url}/v1/infer?i={k}", body=json.dumps({"q": k})) for k in range(7)]
    served, _, trace = served_calls(proxy)
    got = sum(1 for r in outs if r.get("status") == 200 and r.get("verdict") != "deny")
    check("D1.1", "the provider is SIGKILLed with a served call's answer still unsent and restarted: the next calls are answered on the same channel",
          state["killed"] == 1 and got == 6 and len({r.get("chan") for r in outs if r.get("chan")}) == 1,
          f"7 calls, {got} answered; the provider (restarted from its ledger) served {served}; wire {trace}")
    close = payer.tool("close_channel", counterparty=proxy.url)
    mine()
    txid = close.get("txid")
    if not txid:
        return check("D1.2", "the channel closes after the restart", False, json.dumps(close)[:300])
    conf, others = close_amounts(txid, s.hot_spk)
    time.sleep(1.0)
    rec = s.channel(proxy.url) or {}
    check("D1.2", "nothing lost across the restart: the close pays the provider every call it served, the one from before its death included, once",
          conf >= 1 and sum(others.values()) == max(served * PRICE, DUST) and rec.get("used_sats") == sum(others.values()),
          f"provider's output {sum(others.values())} sat; it served {served} calls x {PRICE} = {served * PRICE}; the signer signed {rec.get('used_sats')}")


def kill_signer():
    pport, xport = PB + 24, PB + 25
    start_provider("D2-provider", pport)
    gate = {"reached": threading.Event(), "release": threading.Event(), "req": None, "armed": False}

    def rule(req):
        if gate["armed"] and req["paid"] and not req["path"].startswith("/x402/") and gate["req"] is None:
            gate["req"] = req
            gate["reached"].set()
            gate["release"].wait(60)      # the signed request sits on the wire while the signer dies
        return "pass"
    proxy = HttpFaultProxy(xport, pport, rule)
    proxies.append(proxy)
    s = Signer("D2-signer", [proxy.url])
    with Mining():
        outs = [s.pay(f"{proxy.url}/v1/infer?i={k}", body=json.dumps({"q": k})) for k in range(5)]
    before = s.channel(proxy.url) or {}
    gate["armed"] = True
    t = threading.Thread(target=lambda: outs.append(s.pay(f"{proxy.url}/v1/infer?i=5", body=json.dumps({"q": 5}))), daemon=True)
    t.start()
    reached = gate["reached"].wait(60)
    cum = wire_cum(gate["req"]) if reached else None
    kill9(s.proc)                 # SIGKILL: no handler runs, nothing is flushed
    gate["release"].set()         # the provider now gets the request and serves it; its answer has nowhere to go
    t.join(30)
    time.sleep(0.5)
    s.start()
    after = s.channel(proxy.url) or {}
    check("D2.1", "the signer is SIGKILLed with a signed request on the wire: the state that request carried is in its book when it comes back",
          reached and cum is not None and cum > before.get("used_sats", 0) and after.get("used_sats") == cum and after.get("state") == "open",
          f"signed before the call {before.get('used_sats')} sat; the request on the wire carried {cum} sat; the restarted signer's "
          f"record says used_sats {after.get('used_sats')}, state {after.get('state')}")
    nxt = s.pay(f"{proxy.url}/v1/infer?i=6", body=json.dumps({"q": 6}))
    booked_before = 50_000_000 - nxt.get("residual_daily_sats", 0) if "residual_daily_sats" in nxt else None
    check("D2.2", "nothing signed unbooked: the restarted signer's daily budget already counts that state before it signs anything new",
          booked_before is not None and cum is not None and booked_before >= cum,
          f"the first call after the restart reports {booked_before} sat booked before it, against {cum} sat signed on the wire; {brief(nxt)}")
    served, _, trace = served_calls(proxy)
    close = s.call("close_channel", counterparty=proxy.url)
    mine()
    txid = close.get("txid")
    if not txid:
        return check("D2.3", "the channel closes after the restart", False, json.dumps(close)[:300])
    conf, others = close_amounts(txid, s.hot_spk)
    sigs, chain_ok = s.signatures()
    check("D2.3", "the signature log is intact across the kill, and the next call is answered on the same channel",
          chain_ok is True and nxt.get("status") == 200 and nxt.get("chan") == before.get("chan"),
          f"{len(sigs)} log entries, chain_ok {chain_ok}; {brief(nxt)}")
    check("D2.4", "nothing lost: the close pays the provider every call it served, the one the dead signer never saw answered included, once",
          conf >= 1 and sum(others.values()) == max(served * PRICE, DUST),
          f"provider's output {sum(others.values())} sat; it served {served} calls x {PRICE} = {served * PRICE}; close report "
          f"{close.get('close_report')}; wire {trace}")


# --- E: a seller that refuses the funded open --------------------------------------------------------

def refuses_open(cid, rail):
    i = {"E1": 0, "E2": 1}[cid]
    pport, xport = PB + 30 + 2 * i, PB + 31 + 2 * i
    start_provider(f"{cid}-provider", pport)
    refused = []

    def rule(req):
        # the open's preflight ("would you open these terms?") goes through and is answered yes;
        # the open itself, which names the funded outpoint, is refused
        if req["method"] == "POST" and req["path"].startswith("/x402/"):
            try:
                body = json.loads(req["body"] or b"{}")
            except ValueError:
                body = {}
            if isinstance(body, dict) and (body.get("channel") or {}).get("txid") and not body.get("preflight"):
                refused.append(body["channel"]["txid"])
                return ("answer", 400, {"error": "bad_channel", "detail": "refused by the test"})
        return "pass"
    proxy = HttpFaultProxy(xport, pport, rule)
    proxies.append(proxy)
    s = Signer(f"{cid}-signer", [proxy.url])
    payer = s if rail == "signer" else WalletMcp(s, "mcp-payer")
    with Mining():
        outs = [payer.pay(f"{proxy.url}/v1/infer?i={k}") for k in range(3)]
    LOG.writelines(f"{cid} call {k}: {json.dumps(r)[:600]}\n" for k, r in enumerate(outs))
    sigs, _ = s.signatures()
    fundings = [x for x in sigs if x.get("kind") == "funding"]
    states = [x for x in sigs if x.get("kind") in ("state", "adaptor_presig")]
    rec = s.channel(proxy.url) or {}
    check(f"{cid}.1", "the seller accepts the preflight and refuses the funded open: no call is paid, no state is signed",
          len(refused) >= 1 and all(r.get("status") != 200 for r in outs) and not states and rec.get("used_sats", 0) == 0,
          f"3 calls: {[brief(r) for r in outs]}; funded opens refused: {len(refused)}; state signatures: {len(states)}")
    check(f"{cid}.2", "funded once: three calls against the refusing seller fund one channel, and every refused open names that one funding",
          len(fundings) == 1 and len(set(refused)) == 1 and rec.get("funding_txid") == refused[0],
          f"funding signatures in the signer's log: {len(fundings)}; outpoints the seller was asked to open: {sorted({x[:16] for x in refused})}; "
          f"signer record state {rec.get('state')}, open_error {rec.get('open_error')}")
    if not refused:
        return
    refund_at_expiry(cid, 3, s, proxy.url, refused[0], "refunded at expiry: the signer's watcher returns the whole channel to the hot key")


# --- the hub: B2 (a provider stops answering) and D3 (the hub is killed) ------------------------------

ROUTE_PRICES = [37 * 10 ** 21, 81 * 10 ** 21 + 300_000_000_000_123_456_789]   # amsat per call: 37 sat; 81.3.. sat


def hub_status(hub_url):
    try:
        return http_json(hub_url + "/status", timeout=15)
    except (OSError, ValueError):
        return None


def seller(status, origin):
    return next((x for x in (status or {}).get("sellers", []) if x.get("origin") == origin), {})


def hub_run(cid, base, seconds, rate, disturb):
    """One buyer, one hub, two sellers, all release binaries at their defaults: `seconds` of paid
    calls to both sellers through the hub while `disturb(ctx)` does its damage, then the buyer closes
    its channel, the hub is stopped, its operator tool closes the sellers' channels, and every close
    is read off the chain. Returns what the checks need."""
    d = os.path.join(RUN, cid)
    os.makedirs(d, exist_ok=True)
    hub_port, ports = base, [base + 1, base + 2]
    urls = [f"http://127.0.0.1:{p}" for p in ports]
    provs = []
    for j, (port, price) in enumerate(zip(ports, ROUTE_PRICES)):
        provs.append(spawn([f"{RS}/xbt402-route-provider", "--port", str(port), "--rpc-port", RPCPORT, "--cookie", COOKIE,
                            "--amsat", str(price), "--data-dir", os.path.join(d, f"seller{j}")]))
    for u in urls:
        assert wait_http(u + "/x402/supported"), f"seller {u} did not come up"
    key = os.path.join(d, "hub.key")
    with open(key, "w") as f:
        f.write(f"{secrets.randbelow(2 ** 255) + 1:064x}")
    os.chmod(key, 0o600)
    # what a hub's operator must write, and nothing else: no reveal_timeout, no watch_interval, no spend_final_depth
    conf = {"node": {"rpcport": int(RPCPORT), "cookie": COOKIE, "wallet": "w", "fee_rate": 2}, "network": NET, "port": hub_port,
            "datadir": os.path.join(d, "hub"), "pay_to_key_file": key, "connect": urls,
            "hub": {"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 144,
                    "ch2_capacity": 50000, "ch2_expiry_blocks": 1100, "close_margin": 144,
                    "policy": {"min_expiry_blocks": 1008, "max_expiry_blocks": 8640}}}
    cpath = os.path.join(d, "hub.json")
    with open(cpath, "w") as f:
        json.dump(conf, f)
    hub_cmd = [f"{RS}/xbt402-hub", "--config", cpath]
    hub_url = f"http://127.0.0.1:{hub_port}"
    ctx = {"hub": spawn(hub_cmd), "hub_cmd": hub_cmd, "hub_url": hub_url, "urls": urls, "provs": provs, "t0": None, "seen": {}}
    out = {"ctx": ctx, "urls": urls, "start_height": node.getblockcount()}
    with Mining():
        end = time.time() + 120
        while time.time() < end and len((hub_status(hub_url) or {}).get("sellers", [])) < 2:
            time.sleep(0.5)
        end = time.time() + 120
        while time.time() < end and not all(seller(hub_status(hub_url), u).get("state") == "open" for u in urls):
            time.sleep(0.5)
        out["opened"] = [seller(hub_status(hub_url), u).get("state") for u in urls]
        shard_urls = ",".join(u + "/v1/chunk" for u in urls)
        ctx["t0"] = time.time()
        payer = subprocess.Popen([*NICE, f"{RS}/xbt402-route-payer", "--hub", hub_url, "--shards", shard_urls, "--rpc-port", RPCPORT,
                                  "--cookie", COOKIE, "--seconds", str(seconds), "--rate", str(rate)], stdout=subprocess.PIPE, stderr=LOG, text=True)
        procs.append(payer)
        try:
            disturb(ctx)
        finally:
            try:
                stdout, _ = payer.communicate(timeout=seconds + 240)
            except subprocess.TimeoutExpired:
                payer.kill()
                stdout, _ = payer.communicate()
        out["status_end"] = hub_status(hub_url)
    try:
        res = json.loads(stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        res = {"error": f"the buyer printed no result (exit {payer.returncode}): {stdout[-300:]!r}"}
    out["res"] = res
    LOG.write(f"{cid} buyer: {json.dumps({k: res.get(k) for k in ('summary', 'close', 'okCalls', 'seconds', 'events', 'error')})}\n")
    LOG.write(f"{cid} hub status at the end: {json.dumps(out['status_end'])}\n")
    stop(ctx["hub"])
    tp = subprocess.run([f"{RS}/xbt402-hub", "--config", cpath, "--close-all"], capture_output=True, text=True, timeout=180, check=False)
    LOG.write(tp.stderr)
    try:
        out["closed"] = json.loads(tp.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        out["closed"] = {"closes": [], "error": tp.stdout[-300:]}
    LOG.write(f"{cid} hub --close-all: {json.dumps(out['closed'])}\n")
    mine()
    return out


def seller_received(chan, close_txid, payee_spk):
    """What the chain paid a seller on its channel `chan` ("txid:vout") and on the channels that
    one was rolled over from: [sats], the close first. A rollover is one transaction that spends the
    old channel, pays the seller what it is owed there and funds the next channel."""
    got = [tx_outputs(close_txid)[1].get(payee_spk, 0)]
    txid, vout = chan.split(":")[0], int(chan.split(":")[1])
    for _ in range(16):
        fund = node.getrawtransaction(txid, True)
        prev = fund["vin"][0]
        if "txid" not in prev:
            break
        parent = node.getrawtransaction(prev["txid"], True)["vout"][prev["vout"]]
        if parent["scriptPubKey"].get("type") != "witness_v0_scripthash" or len(fund["vin"]) != 1:
            break               # funded from a wallet: the first channel
        got.append(sum(round(o["value"] * SAT) for o in fund["vout"] if o["n"] != vout))
        txid, vout = prev["txid"], prev["vout"]
    return got


def hub_money(cid, n, out, what):
    """Every coin where the signed states say, read off the chain. The buyer's channel: the hub's
    output is the buyer's last signed state, the buyer's change the rest less the close fee. Each
    seller: what the chain paid it, plus the close fee it paid on each of its channels (payee-pays;
    a hub rolls a seller's channel over when it needs to, so there may be more than one), is what
    the buyer's locks to it add up to. And the hub's own books: out = in - fees, nothing stuck."""
    res, closed, st = out["res"], out["closed"], out.get("status_end") or {}
    if "summary" not in res or "txid" not in (res.get("close") or {}):
        return check(f"{cid}.{n}", what, False, f"the buyer did not close its channel: {json.dumps(res)[:400]}")
    s, p1, c1 = res["summary"], res["ch1Params"], res["close"]
    cum1 = s["signed"]
    conf1, outs1 = tx_outputs(c1["txid"])
    change1 = p1["capacity"] - p1["close_fee"] - cum1
    ok1 = conf1 >= 1 and outs1.get(p1["payee_spk"]) == cum1 == max(s["routed_sat"], DUST) and outs1.get(p1["payer_spk"], 0) == (change1 if change1 >= DUST else 0)
    locks = {u.rsplit("/v1/chunk", 1)[0]: sh["locked_sat"] for u, sh in s["shards"].items()}
    ok2, rows = len(closed.get("closes", [])) == 2 and all("txid" in (c.get("close") or {}) for c in closed["closes"]), []
    for c in closed.get("closes", []):
        ch2 = c["ch2"]
        p2 = ch2["params"]
        got = seller_received(ch2["chan"], (c.get("close") or {}).get("txid"), p2["payee_spk"]) if "txid" in (c.get("close") or {}) else []
        fees = p2["close_fee"] * len(got)
        good = sum(got) + fees == locks.get(ch2["origin"]) and p2.get("close_fee_payer") == "payee"
        ok2 = ok2 and good
        rows.append(f"seller {ch2['origin'].split(':')[-1]}: the chain paid it {' + '.join(map(str, got))} sat ({len(got)} channel(s)"
                    f"{', the hub rolled one over' if len(got) > 1 else ''}) + {fees} sat of close fees = {sum(got) + fees}; the buyer's locks "
                    f"to it {locks.get(ch2['origin'])}")
    ok3 = (st.get("routedOutSat") == sum(locks.values()) == s["routed_sat"] - s["fee_paid_sat"] and st.get("routedInSat") == s["routed_sat"]
           and st.get("feesEarnedSat") == s["fee_paid_sat"] and st.get("stuckSat") == 0)
    return check(f"{cid}.{n}", what, ok1 and ok2 and ok3,
                 f"buyer's channel: the hub got {outs1.get(p1['payee_spk'])} sat = the buyer's signed state {cum1} (of it fees {s['fee_paid_sat']}), "
                 f"buyer's change {outs1.get(p1['payer_spk'])}; " + "; ".join(rows) + f"; hub's books: in {st.get('routedInSat')}, out "
                 f"{st.get('routedOutSat')}, fees {st.get('feesEarnedSat')}, stuck {st.get('stuckSat')}; buyer: {s['locks']} locks, {s['voided']} voided")


def stops_answering_hub():
    cid, seen = "B2", {}

    def disturb(ctx):
        hub_url, u1 = ctx["hub_url"], ctx["urls"][1]
        time.sleep(6)
        seen["before"] = hub_status(hub_url)
        ctx["provs"][1].send_signal(signal.SIGSTOP)
        t_stop = time.time()
        end = t_stop + 60
        while time.time() < end and not seller(hub_status(hub_url), u1).get("blocked"):
            time.sleep(0.5)
        seen["aside"] = hub_status(hub_url)
        seen["aside_after_s"] = round(time.time() - t_stop, 1)
        time.sleep(8)                                 # the other seller goes on being paid meanwhile
        seen["during"] = hub_status(hub_url)
        ctx["provs"][1].send_signal(signal.SIGCONT)
        t_cont = time.time()
        end = t_cont + 60
        while time.time() < end and seller(hub_status(hub_url), u1).get("blocked"):
            time.sleep(0.5)
        seen["back"] = hub_status(hub_url)
        seen["back_after_s"] = round(time.time() - t_cont, 1)

    out = hub_run(cid, PB + 40, 85, 4, disturb)
    u0, u1 = out["urls"]
    aside = seller(seen.get("aside"), u1)
    check("B2.1", "a seller behind the hub stops answering: the hub sets it aside",
          bool(aside.get("blocked")) and aside.get("state") == "open",
          f"{seen.get('aside_after_s')} s after the seller stopped, GET /status shows it blocked: {aside.get('blocked')!r}")
    p0 = [seller(seen.get(k), u0).get("paidSat") for k in ("before", "aside", "during")]
    p1 = [seller(seen.get(k), u1).get("paidSat") for k in ("aside", "during")]
    check("B2.2", "the other seller keeps being paid while the first is set aside, and nothing more is signed to the silent one",
          None not in p0 and p0[2] > p0[1] >= p0[0] and p1[0] == p1[1],
          f"hub's signed total to the answering seller: {p0[0]} sat before, {p0[1]} when the other was set aside, {p0[2]} eight seconds later; "
          f"to the silent seller: {p1[0]} then {p1[1]}")
    back = seller(seen.get("back"), u1)
    end1 = ((out["res"].get("summary") or {}).get("shards") or {}).get(u1 + "/v1/chunk", {}).get("locked_sat")
    check("B2.3", "the seller answers again: the hub lifts the block by itself and routes to it again",
          back.get("blocked") == "" and end1 is not None and p1[1] is not None and end1 > p1[1],
          f"{seen.get('back_after_s')} s after the seller came back the block was gone; routed to it: {p1[1]} sat while it was silent, {end1} sat by the end")
    hub_money(cid, 4, out, "every coin is where the signed states say: the buyer paid the hub what it signed, each seller got what the buyer's locks to it add up to")


def kill_hub():
    cid, seen = "D3", {}

    def disturb(ctx):
        time.sleep(8)
        seen["before"] = hub_status(ctx["hub_url"])
        kill9(ctx["hub"])                      # mid-stream: locks are in flight on both channels
        ctx["hub"] = spawn(ctx["hub_cmd"])     # the same config, key and data directory
        seen["up"] = wait_http(ctx["hub_url"] + "/x402/supported", 60)
        time.sleep(3)
        seen["after"] = hub_status(ctx["hub_url"])

    out = hub_run(cid, PB + 44, 30, 4, disturb)
    u0, u1 = out["urls"]
    b = [seller(seen.get("before"), u).get("paidSat") for u in (u0, u1)]
    a = [seller(seen.get("after"), u).get("paidSat") for u in (u0, u1)]
    e = [seller(out.get("status_end"), u).get("paidSat") for u in (u0, u1)]
    chans = [[seller(seen.get(k), u).get("chan") for u in (u0, u1)] for k in ("before", "after")]
    check("D3.1", "the hub is SIGKILLed mid-stream and restarted: it comes back with the same channels and what it had signed on them",
          seen.get("up") and None not in b + a and all(x >= y for x, y in zip(a, b)) and chans[0] == chans[1],
          f"signed to the two sellers before the kill {b}, after the restart {a}; same channels: {chans[0] == chans[1]}")
    check("D3.2", "routing goes on after the restart: both sellers are paid more",
          None not in a + e and all(x > y for x, y in zip(e, a)),
          f"signed to the two sellers after the restart {a}, at the end {e}")
    hub_money(cid, 3, out, "nothing lost and nothing signed unbooked: the buyer paid the hub what it signed, each seller got what the buyer's locks to it add up to")



# --- C: one hostile Electrum server among honest ones ------------------------------------------------

ELECTRS = os.environ.get("ELECTRS", "")
TEST_CA = os.path.join(HERE, "..", "..", "crates", "xbt-electrum", "tests", "data", "test-ca.pem")


def hostile_electrum(cid, mode, what, honest, hostile_port, provider_port):
    """The light payer's refund scenario (open, three calls, the provider vanishes, refund at expiry)
    with three servers: two honest electrs and `mode` in front of an honest one."""
    proxy = ElectrumFaultProxy(hostile_port, honest["e1"], mode, hold_from="blockchain.transaction.broadcast" if mode == "hold" else None)
    proxies.append(proxy)
    prov = start_provider(f"{cid}-provider", provider_port)
    hostile = f"tcp://127.0.0.1:{hostile_port}"
    servers = f"tcp://127.0.0.1:{honest['e1']},ssl://localhost:{honest['tls']},{hostile}"
    t0 = time.time()
    try:
        cp = subprocess.run([f"{RS}/xbt-electrum-interop", "refund", "--rpc-port", RPCPORT, "--cookie", COOKIE, "--servers", servers,
                             "--min-servers", "2", "--ca", TEST_CA, "--url", f"http://127.0.0.1:{provider_port}", "--kill-pid", str(prov.pid)],
                            capture_output=True, text=True, timeout=1500, check=False)
        LOG.write(cp.stderr[-4000:])
        r = json.loads(cp.stdout.strip().splitlines()[-1])
    except (subprocess.TimeoutExpired, IndexError, ValueError) as e:
        r = {"error": f"{type(e).__name__}: {str(e)[:200]}"}
    secs = round(time.time() - t0)
    LOG.write(f"{cid} light payer: {json.dumps({k: v for k, v in r.items() if k != 'comparisons'})[:3000]}\n")
    did = {"hold": f"{proxy.held} lines from the server held back", "hide": "; ".join(sorted(set(proxy.tampered)))[:300],
           "malform": f"{len(proxy.tampered)} answers with their numbers replaced"}[mode]
    happened = proxy.held > 0 if mode == "hold" else len(proxy.tampered) > 0
    ck = r.get("checks") or {}
    on_chain = None
    if r.get("refundTxid"):
        try:
            tx = node.getrawtransaction(r["refundTxid"], True)
            on_chain = (tx.get("confirmations", 0), [round(o["value"] * SAT) for o in tx["vout"]])
        except Exception as e:  # noqa: BLE001
            on_chain = str(e)[:100]
    money = ("early_refund_refused_by_the_network", "funding_unspent_at_expiry", "refund_broadcast_via_electrum", "refund_proven_by_merkle",
             "refund_output_exact", "funding_spent")
    check(f"{cid}.1", f"one server of three {what}: the light wallet still refunds at expiry, and proves it",
          happened and all(ck.get(k) is True for k in money) and on_chain and on_chain[0] >= 1 and on_chain[1] == [r.get("refundSats")],
          f"the hostile server: {did}. Refund {str(r.get('refundTxid'))[:16]}: on the node {on_chain}, expected {r.get('refundSats')} sat; "
          f"the payer's own checks { {k: ck.get(k) for k in money} }; {secs} s" + (f"; error {r['error']}" if r.get("error") else ""))
    flags = r.get("flags") or []
    wrong = [f for f in flags if hostile.split("//")[1] not in f]
    check(f"{cid}.2", "no wrong answer got through, and no honest server is blamed",
          ck.get("every_answer_matches_node") is True and not wrong and ck.get("calls_200") is True,
          f"{r.get('comparisons')} answers compared with the node, mismatches {len(r.get('mismatches') or [])}; servers flagged: "
          f"{sorted({f.split(': ')[0] for f in flags}) or 'none'}" + (f"; e.g. {flags[0][:160]}" if flags else ""))
    stop(prov)
    proxy.stop()


def group_c():
    """one hostile Electrum server among honest ones"""
    if not (ELECTRS and os.access(ELECTRS, os.X_OK)):
        note("C", "not run", f"no electrs binary at {ELECTRS or '(XBT_ELECTRS is not set)'}")
        results.append({"id": "C", "check": "the hostile Electrum server checks ran", "ok": False, "observed": "no electrs binary", "open_item": None})
        return
    e1, m1, e2, m2, tls = (PB + 50 + k for k in range(5))
    dd = os.environ["XBT402_DATADIR"]
    for port, mon, db in ((e1, m1, "db1"), (e2, m2, "db2")):
        log = open(os.path.join(RUN, f"electrs-{db}.log"), "a")  # noqa: SIM115 (the child's log, for its life)
        procs.append(subprocess.Popen([*NICE, ELECTRS, "--skip-default-conf-files", "--network", "regtest", "--db-dir", os.path.join(RUN, db), "--daemon-dir", dd,
                                       "--cookie-file", COOKIE, "--daemon-rpc-addr", f"127.0.0.1:{RPCPORT}",
                                       "--daemon-p2p-addr", f"127.0.0.1:{os.environ['XBT402_P2PPORT']}", "--electrum-rpc-addr", f"127.0.0.1:{port}",
                                       "--monitoring-addr", f"127.0.0.1:{mon}"], stdout=log, stderr=log))
    spawn([f"{RS}/xbt-electrum-interop", "tls-proxy", "--listen", f"127.0.0.1:{tls}", "--upstream", f"127.0.0.1:{e2}"])
    honest = {"e1": e1, "tls": tls}
    modes = (("C1", "hold", "holds every answer from the moment the channel's funding is broadcast"),
             ("C2", "hide", "hides the wallet's transactions (the funding and the refund do not exist for it)"),
             ("C3", "malform", "sends numbers no chain can have (negative, above 2^64, a string, a fraction, null, 1e400)"))
    for k, (cid, mode, what) in enumerate(modes):
        if selected(cid):
            hostile_electrum(cid, mode, what, honest, PB + 55 + k, PB + 58 + k)



def group_b():
    """a provider that stops answering"""
    for cid, fn in (("B1", stops_answering_direct), ("B2", stops_answering_hub)):
        if selected(cid):
            fn()


def group_d():
    """SIGKILL and restart in the middle of a payment"""
    for cid, fn in (("D1", kill_provider), ("D2", kill_signer), ("D3", kill_hub)):
        if selected(cid):
            fn()


def group_e():
    """a seller that refuses the funded open"""
    for cid, rail in (("E1", "signer"), ("E2", "client")):
        if selected(cid):
            refuses_open(cid, rail)


GROUPS = [("S", group_s), ("A", group_a), ("B", group_b), ("C", group_c), ("D", group_d), ("E", group_e)]


def selected(cid):
    """FAIL_ONLY names groups ("A") or checks ("A2"): is `cid` (a group or a check) to run?"""
    return not ONLY or any(o.startswith(cid) or cid.startswith(o) for o in ONLY)


def main():
    ensure_agent_wallet()
    for gid, fn in GROUPS:
        if not selected(gid):
            continue
        say(f"== {gid}: {fn.__doc__ or ''}".rstrip(": "))
        group["id"] = gid
        try:
            fn()
        except Exception:  # noqa: BLE001
            check(f"{gid}.run", "the driver ran this group to its end", False, traceback.format_exc()[-900:])
        finally:
            for p in procs:
                stop(p)
            procs.clear()
            for x in proxies:
                x.stop()
            proxies.clear()
    checks = [r for r in results if "check" in r]
    bad = [r for r in checks if not r["ok"] and not r["open_item"]]
    known = [r for r in checks if not r["ok"] and r["open_item"]]
    with open(os.path.join(RUN, "failure_interop_results.json"), "w") as f:
        json.dump({"ok": not bad, "checks": results}, f, indent=1)
    say(f"failure_interop: {sum(r['ok'] for r in checks)} PASS, {len(known)} FAIL listed as open items, {len(bad)} FAIL")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
