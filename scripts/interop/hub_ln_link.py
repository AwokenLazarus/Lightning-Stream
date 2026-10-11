#!/usr/bin/env python3
"""AGP-109 on regtest, driven by scripts/hub_ln_link_regtest.sh (which says what is run and checked).
Env: LAB (the lab's directory; docker compose is run there), RS_BIN, LINK_RUN, LINK_PB (port base),
HUB_LINK_NODE_PORT, HUB_LINK_LN_PORT, LINK_ONLY (e.g. "macaroon" or "cycle")."""
import base64
import hashlib
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

LAB, RS, RUN = (os.environ[k] for k in ("LAB", "RS_BIN", "LINK_RUN"))
PB = int(os.environ.get("LINK_PB", "22800"))
NODE_PORT = int(os.environ.get("HUB_LINK_NODE_PORT", "17581"))
LN_PORT = int(os.environ.get("HUB_LINK_LN_PORT", "17591"))
ONLY = [x for x in os.environ.get("LINK_ONLY", "").split(",") if x]
SOAK = ["systemd-run", "--user", "--scope", "-q", "-p", "CPUQuota=200%", "-p", "MemoryMax=4G", "nice", "-n", "19"]
SAT = 100_000_000
DEPOSIT = 400_000
CAPITAL = 300_000
CAP = 50_000                       # one ch2
PRICE = 100_000 * 10 ** 18         # 100 sat a call
LN_REST = f"https://127.0.0.1:{LN_PORT}"
LOG = open(os.path.join(RUN, "hub_ln_link.log"), "a")
RESULTS = []
COOKIE = os.path.join(RUN, "rpc.cookie")
CERT = os.path.join(RUN, "lf1.tls.cert")


def say(msg):
    print(msg, flush=True)
    LOG.write(msg + "\n")
    LOG.flush()


def rpc(method, *params, wallet=None):
    url = f"http://127.0.0.1:{NODE_PORT}/" + (f"wallet/{wallet}" if wallet else "")
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
    req = urllib.request.Request(url, body, {"Authorization": "Basic " + base64.b64encode(b"lab:lab").decode(), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            out = json.loads(r.read())
    except urllib.error.HTTPError as e:
        out = json.loads(e.read() or b'{"error": "HTTP %d"}' % e.code)
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def dc(*args, check_rc=True):
    r = subprocess.run(["docker", "compose", *args], cwd=LAB, capture_output=True, text=True)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)}: {r.stderr.strip()[:400]}")
    return r.stdout.strip()


def lncli(*a):
    out = dc("exec", "-T", "lf1", "lncli", "--network=regtest", "--rpcserver=127.0.0.1:10009", *a)
    return json.loads(out) if out.startswith(("{", "[")) else out


def fetch(src, name):
    dst = os.path.join(RUN, name)
    dc("cp", f"lf1:{src}", dst)
    os.chmod(dst, 0o600)
    return dst


def bake(name, *perms):
    lncli("bakemacaroon", f"--save_to=/tmp/{name}", *perms)
    return fetch(f"/tmp/{name}", name)


def mine(n=1):
    return rpc("generatetoaddress", n, MINE_TO)


def blocks(n, pause=1.6):
    """n blocks, one at a time: the hub's watcher (0.5 s) and the link (1 s) look after each."""
    for _ in range(n):
        mine()
        time.sleep(pause)


def spawn(cmd, log=None, env=None, **kw):
    out = open(log, "a") if log else LOG
    return subprocess.Popen(SOAK + cmd, stdout=out, stderr=out, env=dict(os.environ, **(env or {})), **kw)


def stop(p, sig=signal.SIGTERM):
    if p and p.poll() is None:
        p.send_signal(sig)
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


def wait(cond, timeout=60, step=0.4):
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
    if st != 402 or not key:
        return None
    return json.loads(base64.b64decode(h[key]))["accepts"][0]["extra"]["routing"]


def status(hub_url):
    st, _, body = get(hub_url + "/status")
    return json.loads(body) if st == 200 else None


def ln_rest(macaroon_path, method, path, body=None):
    """One REST call to the Lightning node with a macaroon, its certificate pinned: (status, JSON)."""
    ctx = ssl.create_default_context(cafile=CERT)
    ctx.check_hostname = False
    mac = open(macaroon_path, "rb").read().hex()
    req = urllib.request.Request(LN_REST + path, json.dumps(body).encode() if body is not None else None,
                                 {"Grpc-Metadata-macaroon": mac, "Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def sats(v):
    return round(float(v) * SAT)


def p2wpkh(pub_hex):
    h = hashlib.new("ripemd160", hashlib.sha256(bytes.fromhex(pub_hex)).digest()).digest()
    return "0014" + h.hex()


def on_script(spk_hex):
    r = rpc("scantxoutset", "start", [f"raw({spk_hex})"])
    return round(float(r["total_amount"]) * SAT)


def ln_coins():
    """The Lightning node's confirmed on-chain coins: [(address, sats)]."""
    return sorted((u["address"], int(u["amount_sat"])) for u in lncli("listunspent", "--min_confs=1").get("utxos", []))


def ln_synced():
    try:
        i = lncli("getinfo")
        return i.get("synced_to_chain") and int(i["block_height"]) >= rpc("getblockcount") and i
    except Exception:  # noqa: BLE001
        return None


def hub_conf(d, port, wallet, urls, capital=0):
    os.makedirs(d, exist_ok=True)
    key = os.path.join(d, "hub.key")
    if not os.path.exists(key):
        with open(key, "w") as f:
            f.write(f"{secrets.randbelow(2 ** 255) + 1:064x}")
        os.chmod(key, 0o600)
    hub = {"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 144,
           "reveal_timeout": 2.0, "ch2_capacity": CAP, "close_margin": 144,
           "policy": {"min_expiry_blocks": 1008, "max_expiry_blocks": 8640}}
    if capital:
        hub["capital_sat"] = capital
    conf = {"node": {"rpcport": NODE_PORT, "cookie": COOKIE, "wallet": wallet, "fee_rate": 2}, "port": port,
            "datadir": os.path.join(d, "hub"), "pay_to_key_file": key, "connect": urls, "watch_interval": 0.5, "hub": hub}
    cpath = os.path.join(d, "hub.json")
    with open(cpath, "w") as f:
        json.dump(conf, f)
    return cpath


def ln_env(macaroon, port, strict=False):
    env = {"XBT_HUB_LN_REST": LN_REST, "XBT_HUB_LN_TLS_CERT": CERT, "XBT_HUB_LN_MACAROON": macaroon,
           "XBT_PUBLIC_URL": f"http://127.0.0.1:{port}"}
    if strict:
        env["XBT_HUB_LN_STRICT"] = "1"
    return env


class Checks:
    def __init__(self, name):
        self.name, self.checks = name, []
        say(f"== {name}")

    def check(self, what, ok, detail=""):
        self.checks.append({"check": what, "ok": bool(ok), "detail": str(detail)})
        say(f"  {'ok  ' if ok else 'FAIL'} {what}" + (f"  [{detail}]" if detail != "" else ""))
        return bool(ok)

    def done(self):
        RESULTS.append({"scenario": self.name, "ok": all(c["ok"] for c in self.checks), "checks": self.checks})


def macaroon_rule(macs, node_id):
    """Rule M1 through the real binary, with macaroons the real node made."""
    c = Checks("the macaroon rule (M1), real macaroons through xbt402-hub")
    hub = None
    try:
        # what the node itself allows the narrow macaroon: the two calls, and nothing that reads or spends
        st, a = ln_rest(macs["two calls"], "GET", "/v1/newaddress?type=WITNESS_PUBKEY_HASH")
        c.check("the node gives the narrow macaroon a fresh address", st == 200 and a.get("address", "").startswith("bcrt1q"), a)
        st, s = ln_rest(macs["two calls"], "POST", "/v1/signmessage", {"msg": base64.b64encode(b"hello").decode()})
        c.check("the node signs a message for the narrow macaroon", st == 200 and len(s.get("signature", "")) == 104, s)
        refused = {}
        for what, method, path, body in [("send coins", "POST", "/v1/transactions", {"addr": MINE_TO, "amount": "1000"}),
                                         ("send all coins", "POST", "/v1/transactions", {"addr": MINE_TO, "send_all": True}),
                                         ("wallet balance", "GET", "/v1/balance/blockchain", None), ("node info", "GET", "/v1/getinfo", None),
                                         ("list coins", "GET", "/v1/utxos?min_confs=0&max_confs=999", None),
                                         ("bake a macaroon", "POST", "/v1/macaroon", {"permissions": [{"entity": "onchain", "action": "write"}]}),
                                         ("open a channel", "POST", "/v1/channels", {"node_pubkey_string": node_id, "local_funding_amount": "100000"}),
                                         ("make an invoice", "POST", "/v1/invoices", {"value": "1000"}),
                                         ("an address from the wallet kit", "POST", "/v2/wallet/address/next", {}),
                                         ("sign with a wallet key", "POST", "/v2/signer/signmessage", {"msg": "aGVsbG8=", "key_loc": {"key_family": 6, "key_index": 0}}),
                                         ("verify a message", "POST", "/v1/verifymessage", {"msg": "aGVsbG8=", "signature": s.get("signature", "")})]:
            st, a = ln_rest(macs["two calls"], method, path, body)
            refused[what] = (st, a.get("message"))
        c.check("the node refuses the narrow macaroon every other call tried (send coins, balance, info, coins, bake a macaroon, open a channel, "
                "make an invoice, the wallet kit's address, the signer's key, verify)",
                all(st != 200 and "permission denied" in (m or "") for st, m in refused.values()), refused)
        want = [("two calls", True, True, None), ("two calls, pasted as hex text", True, True, None), ("two entity permissions", True, True, None),
                ("two calls and SendCoins", True, False, "uri:/lnrpc.Lightning/SendCoins"), ("the wallet rail's", True, False, "offchain:write"),
                ("readonly.macaroon", True, False, "onchain:read"), ("admin.macaroon", True, False, "onchain:write"),
                ("admin.macaroon", False, True, None)]
        for i, (name, strict, linked, names) in enumerate(want):
            port = PB + 40 + i
            d = os.path.join(RUN, f"mac-{i}")
            cpath = hub_conf(d, port, f"mac{i}", [])
            hub = spawn([f"{RS}/xbt402-hub", "--config", cpath], log=os.path.join(d, "hub.log"), env=ln_env(macs[name], port, strict))
            url = f"http://127.0.0.1:{port}"
            s = wait(lambda url=url, linked=linked: (lambda s: s if s and s.get("lightning") and (not linked or s["lightning"].get("nodeId")) else None)(status(url)), 40)
            ln = (s or {}).get("lightning") or {}
            log = open(os.path.join(d, "hub.log")).read()
            where = "with the mainnet rule" if strict else "on regtest without it"
            if linked:
                ok = ln.get("linked") is True and ln.get("nodeId") == node_id and ln.get("statementServed") is True
                if not strict:
                    ok = ok and "It is used here because this is not mainnet" in log and ln["macaroon"]["onlyTheTwoCalls"] is False
                c.check(f"{name}, {where}: linked, and the node signed the hub's statement", ok, ln if not ok else ln.get("nodeId"))
            else:
                ok = (ln.get("linked") is False and names in ln.get("error", "") and "NOT LINKED" in log and routing(url) is not None
                      and "lightning" not in routing(url))
                c.check(f"{name}, {where}: not used ({names}); the hub runs without the link and serves its 402", ok, ln.get("error") or log[-300:])
            stop(hub)
            hub = None
    except Exception as e:  # noqa: BLE001
        c.check("the run completed", False, repr(e))
    finally:
        stop(hub)
    c.done()


def cycle(macaroon, node_id):
    c = Checks("returns above capital and the node-signed identity, real binaries beside a real Lightning Fork node")
    d = os.path.join(RUN, "cycle")
    os.makedirs(d, exist_ok=True)
    procs, hub, lf1_stopped = [], None, False
    hub_port, seller_port = PB + 10, PB + 11
    hub_url, seller = f"http://127.0.0.1:{hub_port}", f"http://127.0.0.1:{seller_port}"
    named = f"{node_id}@127.0.0.1:{hub_port}"
    try:
        rpc("createwallet", "hublink")
        dep = rpc("sendtoaddress", rpc("getnewaddress", "", "bech32", wallet="hublink"), DEPOSIT / SAT, wallet="lab")
        mine()
        procs.append(spawn([f"{RS}/xbt402-route-provider", "--port", str(seller_port), "--rpc-port", str(NODE_PORT), "--cookie", COOKIE,
                            "--secret", f"{secrets.randbelow(2 ** 255) + 1:064x}", "--amsat", str(PRICE), "--ledger", os.path.join(d, "prov.jsonl")]))
        assert wait(lambda: get(seller + "/x402/supported")[0]), "the seller did not come up"
        cpath = hub_conf(d, hub_port, "hublink", [seller], capital=CAPITAL)
        hub_cmd, hub_log, env = [f"{RS}/xbt402-hub", "--config", cpath], os.path.join(d, "hub.log"), ln_env(macaroon, hub_port, strict=True)
        hub = spawn(hub_cmd, log=hub_log, env=env)

        def ready():
            r = routing(hub_url)
            if r and r.get("providers") and r.get("lightning"):
                return r
            mine()
            return None
        r = wait(ready, 90, 0.8)
        assert r, "the hub did not open its seller channel and show its statement"
        time.sleep(1.5)

        def st():
            return status(hub_url)

        def held():
            b = rpc("getbalances", wallet="hublink")["mine"]
            return sats(b["trusted"]) + sats(b["untrusted_pending"])

        def reconciles(stage):
            s = st()
            ln = s["lightning"]
            four = s["capitalSat"] + s["inChannelsSat"] + s["earnedSat"] + s["stuckSat"]
            out = ln["returnedSat"]
            ok = (four == s["totalSat"] == DEPOSIT - out + s["feesEarnedSat"] - s["chainFeesSat"] - s["dustSat"] and s["depositsSat"] == DEPOSIT - out
                  and s["capitalSat"] == held() and not s["estimated"] and not s["unsettled"] and s["totalSat"] >= CAPITAL)
            c.check(f"status after {stage}: capital {s['capitalSat']} + in channels {s['inChannelsSat']} + earned {s['earnedSat']} + stuck {s['stuckSat']} "
                    f"= {four} = deposit {DEPOSIT} - returned to Lightning {out} + fees {s['feesEarnedSat']} - chain {s['chainFeesSat']} - dust {s['dustSat']}, "
                    f"and at least the capital {CAPITAL}", ok, "" if ok else json.dumps({k: v for k, v in s.items() if k not in ("sellers", "stuck")}))
            return s

        def buyer(hub_name, log_name):
            return subprocess.Popen(SOAK + [f"{RS}/xbt402-route-payer", "--hub", hub_name, "--shards", seller + "/v1/chunk", "--rpc-port", str(NODE_PORT),
                                            "--cookie", COOKIE, "--seconds", "6", "--rate", "10"], stdout=subprocess.PIPE,
                                    stderr=open(os.path.join(d, log_name), "a"), text=True)

        def paid(p):
            out, _ = p.communicate(timeout=300)
            res = json.loads(out.strip().splitlines()[-1])
            return res["summary"]["locks"], int(res["close"]["cum"]), res["close"]["txid"]

        def swept(n, timeout=90):
            """Mine until `n` returns in all are final (nothing earned or on its way), or time runs out."""
            end = time.time() + timeout
            while time.time() < end:
                s = st()
                if s and s["sweepsPending"] == 0 and s["earnedSat"] == 0 and not s["unsettled"] and n():
                    return s
                blocks(1)
            return st()

        # --- I1: the statement, as the real node signs it ---------------------------------------------
        ln = r["lightning"]
        lines = ln["statement"].split("\n")
        s0 = st()
        c.check("the 402 carries the Lightning node's id and a four-line statement naming this hub's key and network, 30 days ahead",
                ln["nodeId"] == node_id and lines[0] == "xbt-stream-hub v1" and lines[1] == f"network={s0['network']}" and lines[2] == f"payto={s0['payTo']}"
                and 29 * 86400 < int(lines[3].split("=")[1]) - time.time() <= 30 * 86400, ln["statement"])
        c.check("the signature is the one `lncli signmessage` gives for that text (the standard signed message, nothing of ours)",
                lncli("signmessage", ln["statement"])["signature"] == ln["signature"], ln["signature"])
        c.check("the status shows the hub's address as <node id>@host:port", s0["lightning"]["hubAddress"] == named, s0["lightning"]["hubAddress"])
        a1 = s0["lightning"]["returnAddress"]
        c.check("the link holds one address of the node's wallet, and about 100,000 sat is above capital",
                a1 and a1.startswith("bcrt1q") and 99_000 < s0["lightning"]["aboveCapitalSat"] <= DEPOSIT - CAPITAL, (a1, s0["lightning"]["aboveCapitalSat"]))
        reconciles("funding")
        # a hub named as another node's: refused before anything is funded
        before = len(rpc("listtransactions", "*", 1000, wallet="w"))
        other = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        bad = subprocess.run(SOAK + [f"{RS}/xbt402-route-payer", "--hub", f"{other}@127.0.0.1:{hub_port}", "--shards", seller + "/v1/chunk",
                                     "--rpc-port", str(NODE_PORT), "--cookie", COOKIE, "--seconds", "1"], capture_output=True, text=True, timeout=60)
        c.check("a buyer told this is the hub of another node opens nothing and funds nothing",
                bad.returncode != 0 and "hub_identity" in bad.stderr and "named as the hub of node" in bad.stderr
                and len(rpc("listtransactions", "*", 1000, wallet="w")) == before, bad.stderr.strip()[-200:])
        # --- L1, L2: two buyers pay the hub named by its node id, and close together -----------------
        pa, pb = buyer(named, "buyer-a.log"), buyer(named, "buyer-b.log")
        (la, ca, _), (lb, cb, _) = paid(pa), paid(pb)
        c.check("two buyers paid the seller through the hub named <node id>@host:port, and closed", la >= 3 and lb >= 3 and ca > 3000 and cb > 3000,
                f"{la} and {lb} locks; closed at {ca} and {cb} sat")
        mine()
        time.sleep(1.5)
        same = []
        for _ in range(4):
            blocks(1)
            same.append(st()["lightning"]["returnAddress"])
        c.check("while nothing is paid to it the address stays the same, block after block", set(same) == {a1} and st()["lightning"]["returnedSat"] == 0, same)
        s = swept(lambda: st()["lightning"]["returnedSat"] > 0)
        ret1 = s["lightning"]["returnedSat"]
        coins = wait(lambda: (lambda x: x if len(x) == 2 else None)(ln_coins()), 30)
        c.check("both payouts were swept to the Lightning node's wallet, to the one address (used again until the chain showed it used)",
                coins and [a for a, _ in coins] == [a1, a1] and sum(v for _, v in coins) == ret1 and ret1 > 6000, coins)
        c.check("what arrived is what the buyers paid less the sweeps' fees (two sweeps, at most 600 sat each)",
                0 < ca + cb - ret1 <= 1200, f"{ca} + {cb} paid, {ret1} arrived")
        a2 = wait(lambda: (lambda a: a if a and a != a1 else None)(st()["lightning"]["returnAddress"]), 20)
        c.check("once the chain showed the address used, the next one was asked for", a2 and st()["lightning"]["addressesUsed"] == 1, (a1, a2))
        reconciles("two buyers' closes")
        # --- L3: the Lightning node stopped -----------------------------------------------------------
        dc("stop", "lf1")
        lf1_stopped = True
        lc, cc, _ = paid(buyer(named, "buyer-c.log"))
        c.check("with the Lightning node stopped a buyer still pays through the hub named by its node, and closes", lc >= 3 and cc > 3000, f"{lc} locks, {cc} sat")
        mine()
        s = swept(lambda: st()["lightning"]["returnedSat"] > ret1)
        ret2 = s["lightning"]["returnedSat"]
        c.check("its payout went to the address the hub had on file from the node (asked for nothing)", ret1 < ret2 <= ret1 + cc, f"{ret2 - ret1} of {cc}")
        gone = wait(lambda: (lambda l: l if l["returnAddress"] is None and "not reachable" in (l.get("addressError") or "") else None)(st()["lightning"]), 30)
        c.check("that address is used now and the node cannot give the next: the status says so", gone, st()["lightning"])
        cap_before = st()["capitalSat"]
        ld, cd, _ = paid(buyer(hub_url, "buyer-d.log"))
        mine()
        s = swept(lambda: st()["capitalSat"] > cap_before)
        c.check("the next payout refilled the hub's own wallet: routing and returns did not wait for the node",
                ld >= 3 and s["lightning"]["returnedSat"] == ret2 and 0 < cd - (s["capitalSat"] - cap_before) <= 600,
                f"{ld} locks; wallet +{s['capitalSat'] - cap_before} of {cd}; returned to Lightning still {s['lightning']['returnedSat']}")
        reconciles("the node stopped")
        # --- the node is back: what was sent while it was away is in its wallet, and returns go on ----
        dc("start", "lf1")
        lf1_stopped = False
        assert wait(ln_synced, 120, 2), "lf1 did not come back"
        a3 = wait(lambda: (lambda a: a if a and a not in (a1, a2) else None)(st()["lightning"]["returnAddress"]), 90, 2)
        coins = wait(lambda: (lambda x: x if len(x) == 3 else None)(ln_coins()), 60, 2)
        c.check("back up, the node's wallet holds the payout sent while it was stopped", coins and sum(v for _, v in coins) == ret2
                and sorted(a for a, _ in coins) == sorted([a1, a1, a2]), coins)
        c.check("and the hub has the next address", a3, st()["lightning"])
        le, ce, _ = paid(buyer(named, "buyer-e.log"))
        mine()
        s = swept(lambda: st()["lightning"]["returnedSat"] > ret2)
        ret3 = s["lightning"]["returnedSat"]
        coins = wait(lambda: (lambda x: x if len(x) == 4 else None)(ln_coins()), 60, 2)
        c.check("a later payout goes to the Lightning wallet again, at the new address", coins and sum(v for _, v in coins) == ret3
                and a3 in [a for a, _ in coins] and int(lncli("walletbalance")["confirmed_balance"]) == ret3, coins)
        s = reconciles("the node back")
        # --- the hub killed and started again: the link is on disk --------------------------------------
        before = s["lightning"]
        signed_at = json.load(open(os.path.join(d, "hub", "ln-link.json")))["statement"]["signedAt"]
        stop(hub, signal.SIGKILL)
        tool = subprocess.run(SOAK + hub_cmd + ["--close-all"], capture_output=True, text=True, timeout=120, env=dict(os.environ, **env))
        LOG.write(tool.stderr)
        closes = [x for x in json.loads(tool.stdout.strip().splitlines()[-1])["closes"] if x.get("close", {}).get("event") == "ch2_close"]
        c.check("the hub killed, its operator tool had the seller close its channel", len(closes) == 1, closes or tool.stdout[-300:])
        hub = spawn(hub_cmd, log=hub_log, env=env)
        assert wait(lambda: routing(hub_url) is not None, 30), "the hub did not start again"
        after = wait(lambda: (lambda l: l if l and l.get("nodeId") else None)((st() or {}).get("lightning")), 30)
        link = json.load(open(os.path.join(d, "hub", "ln-link.json")))
        c.check("started again, the hub has the same node, the same address and the statement it had (nothing was asked of the node again)",
                after and after["nodeId"] == node_id and after["returnAddress"] == before["returnAddress"] and after["addressesUsed"] == before["addressesUsed"]
                and link["statement"]["signedAt"] == signed_at and routing(hub_url).get("lightning", {}).get("nodeId") == node_id, after)
        blocks(8)
        s = swept(lambda: st()["inChannelsSat"] == 0)
        close_tx = rpc("getrawtransaction", closes[0]["close"]["txid"], True)
        mine_out = [o for o in close_tx["vout"] if rpc("getaddressinfo", o["scriptPubKey"]["address"], wallet="hublink")["ismine"]]
        c.check("the seller's close pays the hub's remainder to the hub's own wallet, never to the Lightning wallet (its amount was not known when it was named)",
                len(mine_out) == 1 and s["lightning"]["returnedSat"] == ret3 and int(lncli("walletbalance")["confirmed_balance"]) == ret3,
                f"{sats(mine_out[0]['value']) if mine_out else None} sat to the hub's wallet")
        s = reconciles("the seller's close")
        book = json.load(open(os.path.join(d, "hub", "ch2.json")))
        recs = list(book["chans"].values()) + list(book.get("next_chans", {}).values()) + list(book["archived"])
        on_keys = {r["params"]["funding_txid"][:8]: on_script(p2wpkh(r["params"]["payer_pub"])) for r in recs}
        c.check("no coin on any seller channel's own key, nothing earned and not collected (scantxoutset, status)",
                recs and not any(on_keys.values()) and s["earnedSat"] == 0 and s["stuckSat"] == 0 and s["sweepsPending"] == 0, on_keys)
        total_paid = ca + cb + cc + cd + ce
        ln_holds = int(lncli("walletbalance")["confirmed_balance"])
        c.check("every sat: the hub's wallet, its open seller channel (funded again after the close) and the Lightning wallet together hold the deposit "
                "plus the fees earned less what the chain cost",
                held() + s["inChannelsSat"] + ln_holds == DEPOSIT + s["feesEarnedSat"] - s["chainFeesSat"] - s["dustSat"] and ln_holds == ret3,
                f"{held()} + {s['inChannelsSat']} + {ln_holds} = {DEPOSIT} + {s['feesEarnedSat']} - {s['chainFeesSat']} - {s['dustSat']}; buyers paid {total_paid}")
        page = get(hub_url + "/")[2].decode()
        c.check("the status page shows the Lightning node, the hub's address and what was returned", "Lightning node" in page and named in page and f"{ret3:,}" in page)
        say("  /status lightning: " + json.dumps(s["lightning"]))
        _ = dep
    except Exception as e:  # noqa: BLE001
        c.check("the run completed", False, repr(e))
    finally:
        for p in procs + [hub]:
            stop(p)
        if lf1_stopped:
            dc("start", "lf1", check_rc=False)
    c.done()


def main():
    global MINE_TO
    for port in [PB + 10, PB + 11] + [PB + 40 + i for i in range(8)]:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))        # a port in use stops the run here, before anything is started
    with open(COOKIE, "w") as f:
        f.write("lab:lab")
    assert wait(lambda: _try(lambda: rpc("getblockchaininfo")), 90, 1), "the lab's node does not answer"
    for w in ("lab", "w"):
        if w not in rpc("listwallets"):
            _try(lambda w=w: rpc("createwallet", w)) or rpc("loadwallet", w)
    MINE_TO = rpc("getnewaddress", wallet="lab")
    if rpc("getblockcount") < 130:
        rpc("generatetoaddress", 130 - rpc("getblockcount"), MINE_TO)
    rpc("sendtoaddress", rpc("getnewaddress", wallet="w"), 2.0, wallet="lab")
    mine()
    dc("up", "-d", "lf1")
    info = wait(ln_synced, 180, 2)
    assert info, "lf1 did not sync"
    node_id = info["identity_pubkey"]
    say(f"lab: block {rpc('getblockcount')}, Lightning Fork {info['version'].split()[0]}, node {node_id}")
    fetch("/root/.lnd/tls.cert", "lf1.tls.cert")
    two = bake("two.macaroon", "uri:/lnrpc.Lightning/NewAddress", "uri:/lnrpc.Lightning/SignMessage")
    as_hex = os.path.join(RUN, "two.hex")
    with open(as_hex, "w") as f:
        f.write(open(two, "rb").read().hex() + "\n")
    macs = {"two calls": two, "two calls, pasted as hex text": as_hex,
            "two entity permissions": bake("pairs.macaroon", "address:write", "message:write"),
            "two calls and SendCoins": bake("send.macaroon", "uri:/lnrpc.Lightning/NewAddress", "uri:/lnrpc.Lightning/SignMessage", "uri:/lnrpc.Lightning/SendCoins"),
            "the wallet rail's": bake("rail.macaroon", "info:read", "offchain:read", "offchain:write", "onchain:read"),
            "readonly.macaroon": fetch("/root/.lnd/data/chain/bitcoin/regtest/readonly.macaroon", "readonly.macaroon"),
            "admin.macaroon": fetch("/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon", "admin.macaroon")}
    if not ONLY or "macaroon" in ONLY:
        macaroon_rule(macs, node_id)
    if not ONLY or "cycle" in ONLY:
        cycle(two, node_id)
    with open(os.path.join(RUN, "hub_ln_link_results.json"), "w") as f:
        json.dump({"node": node_id, "lightningFork": info["version"], "results": RESULTS}, f, indent=1)
    bad = [c["check"] for r in RESULTS for c in r["checks"] if not c["ok"]]
    say(f"hub_ln_link: {sum(len(r['checks']) for r in RESULTS)} checks, {len(bad)} failed")
    sys.exit(1 if bad or not RESULTS else 0)


def _try(f):
    try:
        return f() or True
    except Exception:  # noqa: BLE001
        return None


if __name__ == "__main__":
    main()
