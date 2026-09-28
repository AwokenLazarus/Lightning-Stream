#!/usr/bin/env python3
"""Routed cross-implementation runs on regtest (AGP-026), driven by scripts/route_interop.sh.

Every combination of client x hub x provider, each Rust (xbt-rs) or Python (B1 agp-023): 1 client with
ONE channel to the hub, 1 hub funding one ch2 to each of 2 providers, `SECONDS` of streamed calls at
`RATE`/s per provider with per-window adaptor locks, then the client closes ch1 (the hub broadcasts), the
hub is stopped and its operator tool closes every ch2 (the provider broadcasts). A block is mined and
every close is checked on chain to the sat:
  ch1: the hub's output == the client's signed state == max(routed, 546); the client's change ==
       capacity - closeFee - cum1 (payer-pays)
  ch2: the provider's output == state - closeFee (payee-pays, v1.2); the hub's change == capacity - state;
       state == max(routed on that ch2, 546 + closeFee); routed on that ch2 == what the client's locks
       paid that provider == what the provider signed as paid (ROUTE-STATE)
  meters: provider meter == client meter to the amsat; paid <= ceil(accrued); the hub fee carried
       exactly: fees == ceil(units / 1e9); sum over ch2s == routed on ch1 - fees
Ports: base+10*i .. +2 (hub, providers). Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT, RS_BIN, PY,
ROUTE_PB, ROUTE_RUN, ROUTE_ONLY (e.g. "RS-PY-RS,PY-RS-PY"), ROUTE_SECONDS, ROUTE_RATE."""
import itertools
import json
import math
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.request

B1 = os.environ.get("XBT402_B1", os.path.expanduser("~/xbt-rnd/b1-agp-023"))
sys.path.insert(0, B1)
from xbt402.rpc import RPC  # noqa: E402
from xbt402.x402_channel import network_id, unb64json  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RS = os.environ["RS_BIN"]
PY = os.environ.get("PY", sys.executable)
PB = int(os.environ.get("ROUTE_PB", "33100"))
RUN = os.environ["ROUTE_RUN"]
SECONDS = float(os.environ.get("ROUTE_SECONDS", "6"))
RATE = float(os.environ.get("ROUTE_RATE", "10"))
SOAK = ["systemd-run", "--user", "--scope", "-q", "-p", "CPUQuota=200%", "-p", "MemoryMax=4G", "nice", "-n", "19"]
PRICES = [370 * 10 ** 18, 813 * 10 ** 18 + 123_456_789]      # 0.37 sat; 0.813.. sat with an amsat tail (> 2^64)
SAT = 100_000_000

node = RPC.from_env()
W = node.wallet("w")
ADDR = W.getnewaddress()
NET = network_id(node.getblockhash(101))
COOKIE = os.path.join(os.environ["XBT402_DATADIR"], "regtest", ".cookie")
RPCPORT = os.environ["XBT402_RPCPORT"]
LOG = open(os.path.join(RUN, "route_interop.log"), "a")


def mine(n=1):
    return node.generatetoaddress(n, ADDR)


def spawn(cmd, **kw):
    return subprocess.Popen(SOAK + cmd, stdout=LOG, stderr=LOG, **kw)


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


def routing(hub_url):
    try:
        urllib.request.urlopen(hub_url + "/x402/route", timeout=3)
    except urllib.error.HTTPError as e:
        if e.code == 402:
            return unb64json(e.headers["PAYMENT-REQUIRED"])["accepts"][0]["extra"]["routing"]
    except OSError:
        pass
    return None


def outputs(txid):
    tx = node.getrawtransaction(txid, True)
    return tx.get("confirmations", 0), {o["scriptPubKey"]["hex"]: round(o["value"] * SAT) for o in tx["vout"]}


def stop(p):
    if p and p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


def scenario(i, client, hub_impl, prov_impl):
    name = f"{client}-{hub_impl}-{prov_impl}"
    base = PB + 10 + 10 * i
    hub_port, ports = base, [base + 1, base + 2]
    d = os.path.join(RUN, name)
    os.makedirs(d, exist_ok=True)
    checks = []

    def check(what, ok, detail=""):
        checks.append({"check": what, "ok": bool(ok), "detail": detail})

    procs, miner_stop = [], threading.Event()
    try:
        urls = [f"http://127.0.0.1:{p}" for p in ports]
        for j, (port, price) in enumerate(zip(ports, PRICES)):
            sec = f"{secrets.randbelow(2 ** 255) + 1:064x}"
            if prov_impl == "RS":
                cmd = [f"{RS}/xbt402-route-provider", "--port", str(port), "--rpc-port", RPCPORT, "--cookie", COOKIE,
                       "--secret", sec, "--amsat", str(price), "--ledger", os.path.join(d, f"prov{j}.jsonl")]
            else:
                cmd = [PY, os.path.join(HERE, "py_route_provider.py"), str(port), sec, str(price)]
            procs.append(spawn(cmd))
        for u in urls:
            assert wait_http(u + "/x402/supported"), f"provider {u} did not come up"
        key = os.path.join(d, "hub.key")
        with open(key, "w") as f:
            f.write(f"{secrets.randbelow(2 ** 255) + 1:064x}")
        os.chmod(key, 0o600)
        conf = {"node": {"rpcport": int(RPCPORT), "cookie": COOKIE, "wallet": "w"}, "network": NET, "port": hub_port,
                "datadir": os.path.join(d, "hub"), "pay_to_key_file": key, "connect": urls, "watch_interval": 0.5,
                "hub": {"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
                        "delta": 144, "reveal_timeout": 2.0, "ch2_capacity": 50000, "ch2_expiry_blocks": 1100,
                        "close_margin": 144, "policy": {"min_expiry_blocks": 1008, "max_expiry_blocks": 8640}}}
        cpath = os.path.join(d, "hub.json")
        with open(cpath, "w") as f:
            json.dump(conf, f)
        hub_cmd = [f"{RS}/xbt402-hub", "--config", cpath] if hub_impl == "RS" else [PY, "-m", "xbt402.hub", "--config", cpath]
        hub = spawn(hub_cmd, cwd=B1)

        def miner():
            while not miner_stop.wait(0.5):
                try:
                    mine()
                except Exception as e:  # noqa: BLE001
                    LOG.write(f"miner: {e}\n")
        threading.Thread(target=miner, daemon=True).start()
        hub_url = f"http://127.0.0.1:{hub_port}"
        end, r = time.time() + 90, None
        while time.time() < end:
            r = routing(hub_url)
            if r and len(r.get("providers", [])) == 2:
                break
            time.sleep(0.3)
        check("hub-funded ch2 open to both providers", r and len(r.get("providers", [])) == 2, str(r and r.get("providers")))
        check("v1.2: the hub advertises ch1 payer-pays, ch2 payee-pays",
              r and (r.get("ch1CloseFeePayer"), r.get("ch2CloseFeePayer")) == ("payer", "payee"))
        shard_urls = ",".join(u + "/v1/chunk" for u in urls)
        if client == "RS":
            ccmd = [f"{RS}/xbt402-route-payer", "--hub", hub_url, "--shards", shard_urls, "--rpc-port", RPCPORT, "--cookie", COOKIE,
                    "--seconds", str(SECONDS), "--rate", str(RATE)]
        else:
            ccmd = [PY, os.path.join(HERE, "py_route_payer.py"), hub_url, shard_urls, str(SECONDS), str(RATE)]
        cp = subprocess.run(SOAK + ccmd, capture_output=True, text=True, timeout=300)
        LOG.write(cp.stderr)
        res = json.loads(cp.stdout.strip().splitlines()[-1])
        miner_stop.set()
        stop(hub)
        tool = [f"{RS}/xbt402-hub", "--config", cpath, "--close-all"] if hub_impl == "RS" else \
            [PY, os.path.join(HERE, "py_hub_close.py"), cpath]
        tp = subprocess.run(SOAK + tool, capture_output=True, text=True, timeout=120, cwd=B1)
        LOG.write(tp.stderr)
        closed = json.loads(tp.stdout.strip().splitlines()[-1])
        mine()
        s = res["summary"]
        # --- the data path and the meters ------------------------------------------------------------
        rates = [n / res["seconds"] for n in res["okCalls"]]
        check(f"client streamed >= {0.8 * RATE:.0f} paid-route calls/s to each provider", all(x >= 0.8 * RATE for x in rates),
              ", ".join(f"{x:.1f}/s" for x in rates))
        check("locks settled, none voided", s["locks"] >= 4 and s["voided"] == 0, f"{s['locks']} locks, {s['voided']} voided")
        paid_by_payto = {}
        for u, sh in s["shards"].items():
            acc = int(sh["accrued_amsat"])
            # paid_sat is the provider's signed paid total as of the last ROUTE-STATE the client saw (locks
            # that complete after the last call are not in it yet): paid <= locked; locked is checked
            # against the provider's ch2 on chain below
            check(f"{u.split('//')[1].split('/')[0]}: provider meter == client meter (amsat), signed paid <= locks <= ceil",
                  acc == int(sh["seen_amsat"]) and sh["paid_sat"] <= sh["locked_sat"] <= math.ceil(acc / 10 ** 21) and acc > 0,
                  f"{acc} amsat, paid {sh['paid_sat']}, locked {sh['locked_sat']}")
            paid_by_payto[u.rsplit("/v1/chunk", 1)[0]] = sh["locked_sat"]
        check("hub fee carried exactly: fees == ceil(units / 1e9)", s["fee_paid_sat"] == -(-int(s["fee_units"]) // 10 ** 9),
              f"{s['fee_paid_sat']} sat for {s['fee_units']} units")
        # --- ch1 on chain -----------------------------------------------------------------------------
        p1, c1 = res["ch1Params"], res["close"]
        cum1 = s["signed"]
        conf1, outs1 = outputs(c1["txid"])
        change1 = p1["capacity"] - p1["close_fee"] - cum1
        check("ch1 close confirmed: the hub gets the client's signed state, the client its change, fee = closeFee",
              conf1 >= 1 and outs1.get(p1["payee_spk"]) == cum1 == max(s["routed_sat"], 546)
              and outs1.get(p1["payer_spk"], 0) == (change1 if change1 >= 546 else 0) and int(c1["cum"]) == cum1,
              f"hub {outs1.get(p1['payee_spk'])} = cum1 {cum1} (routed {s['routed_sat']}), client {outs1.get(p1['payer_spk'])}")
        # --- ch2s on chain ----------------------------------------------------------------------------
        total2 = 0
        for c in closed["closes"]:
            ch2, ev = c["ch2"], c.get("close") or {}
            p2 = ch2["params"]
            total2 += ch2["routed"]
            if "txid" not in ev:
                check(f"ch2 {ch2['origin']} closed", False, json.dumps(c)[:200])
                continue
            conf2, outs2 = outputs(ev["txid"])
            fee2 = p2["close_fee"]
            check(f"ch2 {ch2['origin'].split('//')[1]} close confirmed: provider gets state - its fee, hub its change",
                  conf2 >= 1 and p2.get("close_fee_payer") == "payee" and outs2.get(p2["payee_spk"]) == ch2["signed"] - fee2
                  and outs2.get(p2["payer_spk"]) == p2["capacity"] - ch2["signed"] and ch2["signed"] == max(ch2["routed"], 546 + fee2),
                  f"provider {outs2.get(p2['payee_spk'])} = {ch2['signed']} - {fee2}, hub {outs2.get(p2['payer_spk'])}, routed {ch2['routed']}")
            check(f"ch2 {ch2['origin'].split('//')[1]}: routed on ch2 == the client's locks to it",
                  ch2["routed"] == paid_by_payto.get(ch2["origin"]), f"{ch2['routed']} == {paid_by_payto.get(ch2['origin'])}")
        check("both ch2s closed", len(closed["closes"]) == 2)
        check("sum over ch2s == routed on ch1 - fees", total2 == s["routed_sat"] - s["fee_paid_sat"],
              f"{total2} == {s['routed_sat']} - {s['fee_paid_sat']}")
        return {"scenario": name, "client": client, "hub": hub_impl, "provider": prov_impl, "ok": all(c["ok"] for c in checks),
                "checks": checks, "lockMs": res["lockMs"], "callMs": res["callMs"], "routed": s["routed_sat"], "fees": s["fee_paid_sat"],
                "ch1": {"txid": c1["txid"], "cum": cum1}, "ch2": [{"txid": (c.get("close") or {}).get("txid"), "state": c["ch2"]["signed"],
                                                                   "routed": c["ch2"]["routed"]} for c in closed["closes"]]}
    except Exception as e:  # noqa: BLE001
        check("scenario ran", False, f"{type(e).__name__}: {e}")
        return {"scenario": name, "ok": False, "checks": checks}
    finally:
        miner_stop.set()
        for p in procs + [locals().get("hub")]:
            stop(p)


def main():
    only = [x for x in os.environ.get("ROUTE_ONLY", "").split(",") if x]
    combos = [c for c in itertools.product(("RS", "PY"), repeat=3) if not only or "-".join(c) in only]
    results = []
    for i, (c, h, p) in enumerate(combos):
        t0 = time.time()
        r = scenario(i, c, h, p)
        r["seconds"] = round(time.time() - t0, 1)
        results.append(r)
        n_ok = sum(x["ok"] for x in r["checks"])
        lk = r.get("lockMs") or {}
        print(f"{r['scenario']:9} client {c} -> hub {h} -> provider {p}: {'PASS' if r['ok'] else 'FAIL'} "
              f"({n_ok}/{len(r['checks'])} checks)  routed {r.get('routed')} sat, fees {r.get('fees')}, "
              f"lock p50 {lk.get('p50', 0):.1f} ms p95 {lk.get('p95', 0):.1f} ms", flush=True)
        for x in r["checks"]:
            if not x["ok"]:
                print(f"   FAIL {x['check']}: {x['detail']}", flush=True)
    with open(os.path.join(RUN, "route_interop_results.json"), "w") as f:
        json.dump(results, f, indent=1)
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
