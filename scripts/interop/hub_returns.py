#!/usr/bin/env python3
"""AGP-104 on regtest, driven by scripts/hub_returns_regtest.sh (which says what is run and checked).
Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT, XBT_BIN, RS_BIN, PY, RETURNS_PB, RETURNS_RUN,
RETURNS_ONLY (e.g. "RS" or "PY" or "checks")."""
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

B1 = os.environ["XBT402_B1"]
sys.path.insert(0, B1)
from xbt402.rpc import RPC  # noqa: E402
from xbt402.x402_channel import network_id, unb64json  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RS = os.environ["RS_BIN"]
PY = os.environ.get("PY", sys.executable)
PB = int(os.environ.get("RETURNS_PB", "22400"))
RUN = os.environ["RETURNS_RUN"]
ONLY = [x for x in os.environ.get("RETURNS_ONLY", "").split(",") if x]
SOAK = ["systemd-run", "--user", "--scope", "-q", "-p", "CPUQuota=200%", "-p", "MemoryMax=4G", "nice", "-n", "19"]
SAT = 100_000_000
DEPOSIT = 1_000_000
CAP = 50_000                       # one ch2
PRICE = 100_000 * 10 ** 18         # 100 sat a call

node = RPC.from_env()
W = node.wallet("w")
ADDR = W.getnewaddress()
NET = network_id(node.getblockhash(101))
COOKIE = os.path.join(os.environ["XBT402_DATADIR"], "regtest", ".cookie")
RPCPORT = os.environ["XBT402_RPCPORT"]
LOG = open(os.path.join(RUN, "hub_returns.log"), "a")
RESULTS = []


def say(msg):
    print(msg, flush=True)
    LOG.write(msg + "\n")
    LOG.flush()


def mine(n=1):
    return node.generatetoaddress(n, ADDR)


def blocks(n, pause=1.3):
    """n blocks, one at a time, the hub's watcher (0.5 s) looking after each."""
    for _ in range(n):
        mine()
        time.sleep(pause)


def spawn(cmd, log=None, **kw):
    out = open(log, "a") if log else LOG
    return subprocess.Popen(SOAK + cmd, stdout=out, stderr=out, **kw)


def stop(p):
    if p and p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


def get(url, timeout=5):
    """(status, headers, body) of a GET; (0, {}, b"") when nothing answers."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except OSError:
        return 0, {}, b""


def wait(cond, timeout=60, step=0.3):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(step)
    return cond()


def routing(hub_url):
    st, h, _ = get(hub_url + "/x402/route")
    key = next((k for k in h if k.upper() == "PAYMENT-REQUIRED"), None)
    return unb64json(h[key])["accepts"][0]["extra"]["routing"] if st == 402 and key else None


def p2wpkh(pub_hex):
    h = hashlib.new("ripemd160", hashlib.sha256(bytes.fromhex(pub_hex)).digest()).digest()
    return "0014" + h.hex()


def on_script(spk_hex):
    """Sats in confirmed unspent outputs paying this script."""
    r = node.scantxoutset("start", [f"raw({spk_hex})"])
    return round(float(r["total_amount"]) * SAT)


def sats(v):
    return round(float(v) * SAT)


def hub_conf(d, port, wallet, urls, fee_rate=2, network=None, rpcport=None, cookie=None):
    key = os.path.join(d, "hub.key")
    if not os.path.exists(key):
        with open(key, "w") as f:
            f.write(f"{secrets.randbelow(2 ** 255) + 1:064x}")
        os.chmod(key, 0o600)
    n = {"rpcport": int(rpcport or RPCPORT), "cookie": cookie or COOKIE, "wallet": wallet}
    if fee_rate:
        n["fee_rate"] = fee_rate
    conf = {"node": n, "network": network or NET, "port": port, "datadir": os.path.join(d, "hub"), "pay_to_key_file": key,
            "connect": urls, "watch_interval": 0.5,
            "hub": {"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 144,
                    "reveal_timeout": 2.0, "ch2_capacity": CAP, "close_margin": 144,
                    "policy": {"min_expiry_blocks": 1008, "max_expiry_blocks": 8640}}}
    cpath = os.path.join(d, "hub.json")
    with open(cpath, "w") as f:
        json.dump(conf, f)
    return cpath


def cycle(i, impl):
    name = f"cycle-{impl}"
    base = PB + 10 + 10 * i
    hub_port, ports = base, [base + 1, base + 2]
    d = os.path.join(RUN, name)
    os.makedirs(d, exist_ok=True)
    checks, procs = [], []

    def check(what, ok, detail=""):
        checks.append({"check": what, "ok": bool(ok), "detail": str(detail)})
        say(f"  {'ok  ' if ok else 'FAIL'} {what}" + (f"  [{detail}]" if detail != "" else ""))

    say(f"== full cycle, {impl} hub")
    try:
        wname = f"hub{impl.lower()}"
        node.createwallet(wname)
        HW = node.wallet(wname)
        dep = W.sendtoaddress(HW.getnewaddress("", "bech32"), DEPOSIT / SAT)
        mine()
        urls = [f"http://127.0.0.1:{p}" for p in ports]
        for j, port in enumerate(ports):
            procs.append(spawn([f"{RS}/xbt402-route-provider", "--port", str(port), "--rpc-port", RPCPORT, "--cookie", COOKIE,
                                "--secret", f"{secrets.randbelow(2 ** 255) + 1:064x}", "--amsat", str(PRICE),
                                "--ledger", os.path.join(d, f"prov{j}.jsonl")]))
        for u in urls:
            assert wait(lambda u=u: get(u + "/x402/supported")[0]), f"seller {u} did not come up"
        cpath = hub_conf(d, hub_port, wname, urls)
        hub_cmd = [f"{RS}/xbt402-hub", "--config", cpath] if impl == "RS" else [PY, "-m", "xbt402.hub", "--config", cpath]
        hub_log = os.path.join(d, "hub.log")
        hub = spawn(hub_cmd, log=hub_log, cwd=B1)
        hub_url = f"http://127.0.0.1:{hub_port}"

        def status(stage, **want):
            """(Rust) GET /status: the four numbers add up to the deposit plus fees less chain costs."""
            if impl != "RS":
                return {}
            s = json.loads(get(hub_url + "/status")[2])
            four = s["capitalSat"] + s["inChannelsSat"] + s["earnedSat"] + s["stuckSat"]
            held = sats(HW.getbalances()["mine"]["trusted"]) + sats(HW.getbalances()["mine"]["untrusted_pending"])
            ok = (four == s["totalSat"] == DEPOSIT + s["feesEarnedSat"] - s["chainFeesSat"] - s["dustSat"] and s["depositsSat"] == DEPOSIT
                  and s["capitalSat"] == held and not s["estimated"] and not s["unsettled"]
                  and all(s[k] == v for k, v in want.items()))
            check(f"status after {stage}: capital {s['capitalSat']} + in channels {s['inChannelsSat']} + earned {s['earnedSat']} + stuck "
                  f"{s['stuckSat']} = {four} = deposit {DEPOSIT} + fees {s['feesEarnedSat']} - chain {s['chainFeesSat']} - dust {s['dustSat']}",
                  ok, "" if ok else json.dumps({k: v for k, v in s.items() if k not in ("sellers", "stuck")}))
            return s

        def both_open():
            r = routing(hub_url)
            if r and len(r.get("providers", [])) == 2:
                return r
            mine()
            return None
        r = wait(both_open, 90, 0.6)
        check("the hub funded and opened a ch2 to both sellers", r and len(r.get("providers", [])) == 2, r and r.get("providers"))
        time.sleep(1.2)
        status("funding", inChannelsSat=2 * CAP, earnedSat=0, stuckSat=0)
        # --- route: the buyer pays seller 0 only, then closes its ch1 ---------------------------------
        cp = subprocess.run(SOAK + [f"{RS}/xbt402-route-payer", "--hub", hub_url, "--shards", urls[0] + "/v1/chunk", "--rpc-port", RPCPORT,
                                    "--cookie", COOKIE, "--seconds", "6", "--rate", "10"], capture_output=True, text=True, timeout=300)
        LOG.write(cp.stderr)
        res = json.loads(cp.stdout.strip().splitlines()[-1])
        cum1 = int(res["close"]["cum"])
        check("the buyer streamed, paid seller 0 through the hub and closed its ch1", res["summary"]["locks"] >= 3 and cum1 > 3000,
              f"{res['summary']['locks']} locks, ch1 closed at {cum1} sat")
        close1 = res["close"]["txid"]
        hub_out = next(o for o in node.getrawtransaction(close1, True)["vout"] if sats(o["value"]) == cum1)
        ch1_key = hub_out["scriptPubKey"]["hex"]
        mine()
        time.sleep(1.2)
        status("routing and the buyer's close")
        # --- seller close: the hub stopped, its operator tool, the hub started again -----------------
        stop(hub)
        tool = [f"{RS}/xbt402-hub", "--config", cpath, "--close-all"] if impl == "RS" else [PY, os.path.join(HERE, "py_hub_close.py"), cpath]
        tp = subprocess.run(SOAK + tool, capture_output=True, text=True, timeout=120, cwd=B1)
        LOG.write(tp.stderr)
        closed = json.loads(tp.stdout.strip().splitlines()[-1])["closes"]
        paid = [c for c in closed if c.get("close", {}).get("event") == "ch2_close"]
        check("the operator tool had the paid seller close its ch2 (the other has nothing signed)",
              len(paid) == 1 and paid[0]["ch2"]["origin"] == urls[0], [c.get("close", c.get("error")) for c in closed])
        close2 = paid[0]["close"]["txid"]
        hub = spawn(hub_cmd, log=hub_log, cwd=B1)
        assert wait(lambda: routing(hub_url) is not None), "the hub did not start again"
        blocks(8)
        c2 = node.getrawtransaction(close2, True)
        mine_out = [o for o in c2["vout"] if HW.getaddressinfo(o["scriptPubKey"]["address"])["ismine"]]
        check("the seller's close pays the hub's remainder to an address of the hub's wallet",
              len(mine_out) == 1 and sats(mine_out[0]["value"]) == CAP - int(paid[0]["close"]["amount"]),
              f"{sats(mine_out[0]['value']) if mine_out else None} of {CAP}, seller paid {paid[0]['close']['amount']}")
        check("six blocks after the buyer's close, the hub's payout left the ch1's own key",
              wait(lambda: node.gettxout(close1, hub_out["n"], True) is None, 20), f"{close1}:{hub_out['n']}")
        blocks(7)
        status("the seller's close and the sweep", inChannelsSat=CAP, earnedSat=0, stuckSat=0, sweepsPending=0)
        # --- refund: the seller never paid, at its ch2's expiry ----------------------------------------
        book = json.load(open(os.path.join(d, "hub", "ch2.json")))
        recs = list(book["chans"].values()) + list(book.get("next_chans", {}).values()) + list(book["archived"])
        idle = next(r for r in recs if r["origin"] == urls[1])
        left = idle["params"]["expiry"] - node.getblockcount()
        while left > 0:
            mine(min(left, 200))
            left = idle["params"]["expiry"] - node.getblockcount()
            time.sleep(0.4)
        time.sleep(1.5)
        blocks(8)
        funding_spent = node.gettxout(idle["params"]["funding_txid"], idle["params"]["funding_vout"], True) is None
        check(f"the unpaid seller's ch2 was refunded at its expiry ({idle['params']['expiry']})", funding_spent)
        s = status("the refund", inChannelsSat=0, earnedSat=0, stuckSat=0, sweepsPending=0)
        # --- nothing on a per-channel key; the wallet holds it all -----------------------------------
        book = json.load(open(os.path.join(d, "hub", "ch2.json")))
        recs = list(book["chans"].values()) + list(book.get("next_chans", {}).values()) + list(book["archived"])
        on_ch2 = {r["params"]["funding_txid"][:8]: on_script(p2wpkh(r["params"]["payer_pub"])) for r in recs}
        check("no coin on any ch2's own payer key (scantxoutset)", len(recs) >= 2 and not any(on_ch2.values()), on_ch2)
        check("no coin on the ch1's payee key (scantxoutset)", on_script(ch1_key) == 0, on_script(ch1_key))
        check("no ch2 names its own key as its payerSpk", all(r["params"]["payer_spk"] != p2wpkh(r["params"]["payer_pub"]) for r in recs))
        txs = HW.listtransactions("*", 1000)
        fund_fees = sum(-sats(t["fee"]) for t in txs if t["category"] == "send")
        back = sorted(sats(t["amount"]) for t in txs if t["category"] == "receive" and t["txid"] != dep and t["confirmations"] > 0)
        held = sats(HW.getbalances()["mine"]["trusted"])
        want = DEPOSIT - 2 * CAP - fund_fees + sum(back)
        check("the wallet holds the deposit, less two fundings and their fees, plus exactly three returns "
              "(the seller's remainder, the swept payout, the refund)", held == want and len(back) == 3,
              f"{held} = {DEPOSIT} - {2 * CAP} - {fund_fees} + {back}")
        if impl == "RS":
            check("the status says the same: everything is capital again", s.get("capitalSat") == held == s.get("totalSat"), s.get("capitalSat"))
            st, h, body = get(hub_url + "/")
            page = body.decode()
            check("GET / is the status page", st == 200 and "text/html" in h.get("Content-Type", "") and "Capital" in page
                  and f"{held:,}" in page and urls[0] in page, f"HTTP {st}, {len(page)} bytes")
            say("  /status: " + json.dumps({k: v for k, v in s.items() if k not in ("sellers", "stuck", "payTo", "network", "wallet")}))
    except Exception as e:  # noqa: BLE001
        check("the run completed", False, repr(e))
    finally:
        for p in procs + [locals().get("hub")]:
            stop(p)
    RESULTS.append({"scenario": name, "ok": all(c["ok"] for c in checks), "checks": checks})


def startup_checks():
    say("== start-up checks, Rust hub")
    d = os.path.join(RUN, "checks")
    os.makedirs(d, exist_ok=True)
    checks = []

    def check(what, ok, detail=""):
        checks.append({"check": what, "ok": bool(ok), "detail": str(detail)})
        say(f"  {'ok  ' if ok else 'FAIL'} {what}" + (f"  [{detail}]" if detail != "" else ""))

    def run_once(cpath, timeout=20):
        """The hub's exit code and stderr, None if it is still running after `timeout`."""
        p = subprocess.Popen([f"{RS}/xbt402-hub", "--config", cpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            _, err = p.communicate(timeout=timeout)
            return p.returncode, err
        except subprocess.TimeoutExpired:
            p.kill()
            return None, p.communicate()[1]
    procs = []
    try:
        port = PB + 30
        # 1. a configured network that is not the node's
        os.makedirs(os.path.join(d, "net"), exist_ok=True)
        rc, err = run_once(hub_conf(os.path.join(d, "net"), port, "hubnet", [], network="bip122:" + "ab" * 16))
        check("a configured network that is not the node's: refused", rc == 2 and "is configured, and the node is on" in err, err.strip().splitlines()[-1:])
        # 2. a node on the SHA-256 chain: the same binary without the BLAKE2b activation
        sha = os.path.join(RUN, "sha-node")
        os.makedirs(sha, exist_ok=True)
        rp, pp = PB + 3, PB + 4
        args = [f"-regtest", f"-datadir={sha}", f"-rpcport={rp}", f"-port={pp}", "-bind=127.0.0.1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                "-discover=0", "-listenonion=0", "-dnsseed=0", "-fixedseeds=0", "-fallbackfee=0.0002"]
        procs.append(subprocess.Popen([os.path.join(os.environ["XBT_BIN"], "bitcoind")] + args, stdout=LOG, stderr=LOG))
        other = RPC(rp, os.path.join(sha, "regtest", ".cookie"))
        assert wait(lambda: _try(other.getblockcount) is not None, 60), "the SHA-256 node did not start"
        other.createwallet("m")
        other.wallet("m").generatetoaddress(110, other.wallet("m").getnewaddress())
        os.makedirs(os.path.join(d, "sha"), exist_ok=True)
        rc, err = run_once(hub_conf(os.path.join(d, "sha"), port, "hubsha", [], rpcport=rp, cookie=os.path.join(sha, "regtest", ".cookie"),
                                    network=network_id(other.getblockhash(101))))
        check("a node on the SHA-256 chain: refused", rc == 2 and "wrong chain" in err and "SHA-256" in err, err.strip().splitlines()[-1:])
        _try(other.stop)
        # 3. no fee rate and no estimate: nothing is funded, and the hub says why
        node.createwallet("hubfee")
        HW = node.wallet("hubfee")
        W.sendtoaddress(HW.getnewaddress("", "bech32"), 200_000 / SAT)
        mine()
        sport = PB + 31
        procs.append(spawn([f"{RS}/xbt402-route-provider", "--port", str(sport), "--rpc-port", RPCPORT, "--cookie", COOKIE,
                            "--secret", f"{secrets.randbelow(2 ** 255) + 1:064x}", "--amsat", str(PRICE), "--ledger", os.path.join(d, "prov.jsonl")]))
        surl = f"http://127.0.0.1:{sport}"
        assert wait(lambda: get(surl + "/x402/supported")[0]), "the seller did not come up"
        os.makedirs(os.path.join(d, "fee"), exist_ok=True)
        log = os.path.join(d, "fee", "hub.log")
        cpath = hub_conf(os.path.join(d, "fee"), port, "hubfee", [surl], fee_rate=None)
        hub = spawn([f"{RS}/xbt402-hub", "--config", cpath], log=log)
        procs.append(hub)
        url = f"http://127.0.0.1:{port}"
        assert wait(lambda: get(url + "/healthz")[0] == 200), "the hub did not come up"
        text = open(log).read()
        book = os.path.join(d, "fee", "hub", "ch2.json")
        none = not os.path.exists(book) or not json.load(open(book))["chans"]
        check("no fee rate set and no estimate on this node: nothing funded, no record, and the reason is said",
              none and "no fee estimate" in text and "node.fee_rate" in text and sats(HW.getbalances()["mine"]["trusted"]) == 200_000,
              [x for x in text.splitlines() if "fee" in x][:2])
        # (a wallet the hub itself makes: started once more on a name the node has never seen)
        os.makedirs(os.path.join(d, "new"), exist_ok=True)
        extra = spawn([f"{RS}/xbt402-hub", "--config", hub_conf(os.path.join(d, "new"), PB + 32, "hubnew", [])], log=os.path.join(d, "new", "hub.log"))
        procs.append(extra)
        assert wait(lambda: get(f"http://127.0.0.1:{PB + 32}/healthz")[0] == 200), "the second hub did not come up"
        # 4. /readyz follows the wallet
        st, _, body = get(url + "/readyz")
        check("/readyz is ready with the wallet loaded", st == 200 and json.loads(body)["wallet"]["loaded"] is True, f"HTTP {st}")
        node.unloadwallet("hubfee")
        st, _, body = get(url + "/readyz")
        doc = json.loads(body) if body else {}
        check("/readyz is not ready while the wallet is not loaded", st == 503 and doc.get("ok") is False and doc["wallet"]["loaded"] is False
              and doc["node"]["synced"] is True, f"HTTP {st}, wallet {doc.get('wallet')}")
        node.loadwallet("hubfee")
        check("and ready again once it is back", get(url + "/readyz")[0] == 200)
        check("a wallet the hub made is on the node's list of wallets to load when it starts (load_on_startup)",
              _settings_has("hubnew"), _settings_has("hubnew"))
    except Exception as e:  # noqa: BLE001
        check("the run completed", False, repr(e))
    finally:
        for p in procs:
            stop(p)
    RESULTS.append({"scenario": "start-up checks", "ok": all(c["ok"] for c in checks), "checks": checks})


def _try(f):
    try:
        return f()
    except Exception:  # noqa: BLE001
        return None


def _settings_has(wallet):
    """Whether the node's settings.json lists `wallet` to load at start (None: the file is not there)."""
    p = os.path.join(os.environ["XBT402_DATADIR"], "regtest", "settings.json")
    try:
        return wallet in (json.load(open(p)).get("wallet") or [])
    except OSError:
        return None


def main():
    runs = [x for x in ("RS", "PY", "checks") if not ONLY or x in ONLY]
    for i, impl in enumerate(x for x in runs if x != "checks"):
        cycle(i, impl)
    if "checks" in runs:
        startup_checks()
    with open(os.path.join(RUN, "hub_returns_results.json"), "w") as f:
        json.dump(RESULTS, f, indent=1)
    bad = [c for r in RESULTS for c in r["checks"] if not c["ok"]]
    say(f"hub_returns: {sum(len(r['checks']) for r in RESULTS) - len(bad)} checks ok, {len(bad)} failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
