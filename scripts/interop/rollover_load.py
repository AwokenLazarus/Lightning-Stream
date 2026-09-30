#!/usr/bin/env python3
"""AGP-053 rollover under load on regtest, driven by scripts/rollover_load_regtest.sh.

One hub (Rust or Python), one provider (Rust or Python, settleMultiple 2 so its ch2 is rolled over
every few seconds), and the Rust client (xbt402-rollover-load) paying one lock after every call at
LOAD_RATE locks/s (>= 10) for LOAD_SECONDS. A miner thread mines one block every LOAD_BLOCK_S. A
monitor reads the hub's out book (ch2.json) every 0.2 s: every rollover, and each next ch2's zero-conf
state. Runs (hub-provider):
  <H>-<P>         make-before-break (the default): several rollovers under load, ZERO refused locks
                  (no route_blocked, nothing a client would fail over on), every call 200, lock rate >= 10/s
  <H>-<P>-before  the provider takes no unconfirmed child (--zero-conf-max 0): the pre-AGP-053
                  break-before-make behaviour, measured (route_blocked refusals per rollover, gaps)
  <H>-<P>-stuck   fallback: the first rollover is kept out of blocks (empty blocks, generateblock ADDR []) for
                  LOAD_STUCK_S: locks go on over the unconfirmed child until the provider's zero-conf cap,
                  then the hub refuses (route_blocked) before sending anything (no provider refusal, the
                  child's signed state never above the cap); once it confirms, routing resumes
  <H>-<P>-reorg   a reorg across the switch: once a rollover's child is confirmed, the block holding it
                  is invalidated (the rollover is back in the mempool, the hub sees the child unconfirmed
                  again), the miner pauses LOAD_REORG_S, then the new chain confirms it: ZERO refusals
Money checks for every run: each rollover tx pays the provider signed - closeFee (payee-pays) and the
next ch2 capacity - signed; the next ch2's capacity is that output; routed over all of the provider's
ch2s == what the client paid that shard; no lock pending or written off anywhere.
Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT, RS_BIN, PY, LOAD_PB, LOAD_RUN, LOAD_ONLY (e.g.
"RS-RS,PY-PY-before"), LOAD_SECONDS, LOAD_RATE, LOAD_BLOCK_S, LOAD_STUCK_S, LOAD_REORG_S, LOAD_REPORT."""
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
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
PB = int(os.environ.get("LOAD_PB", "34900"))
RUN = os.environ["LOAD_RUN"]
SECONDS = float(os.environ.get("LOAD_SECONDS", "45"))
RATE = float(os.environ.get("LOAD_RATE", "15"))
BLOCK_S = float(os.environ.get("LOAD_BLOCK_S", "3"))
STUCK_S = float(os.environ.get("LOAD_STUCK_S", "20"))
REORG_S = float(os.environ.get("LOAD_REORG_S", "5"))
SOAK = ["systemd-run", "--user", "--scope", "-q", "-p", "CPUQuota=200%", "-p", "MemoryMax=4G", "nice", "-n", "19"]
PRICE = 24 * 10 ** 21                  # 24 sat a call: ch2 reaches 2 x closeFee net every ~5 s at 15 locks/s
SETTLE, CLOSE_FEE = 2, 600
SAT = 100_000_000

node = RPC.from_env()
W = node.wallet("w")
ADDR = W.getnewaddress()
NET = network_id(node.getblockhash(101))
COOKIE = os.path.join(os.environ["XBT402_DATADIR"], "regtest", ".cookie")
RPCPORT = os.environ["XBT402_RPCPORT"]
LOG = open(os.path.join(RUN, "rollover_load.log"), "a")


def spawn(cmd, **kw):
    return subprocess.Popen(SOAK + cmd, stdout=LOG, stderr=LOG, **kw)


def stop(p):
    if p and p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


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


def book(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def records(b):
    return list((b or {}).get("archived", [])) + list(((b or {}).get("chans") or {}).values())


def mine_one(empty=False):
    """One block to a fresh address (after an invalidateblock the same template would rebuild the very
    block that was invalidated: duplicate-invalid); `empty`: no txs (a fee market that leaves them out)."""
    a = W.getnewaddress()
    return node.generateblock(a, []) if empty else node.generatetoaddress(1, a)


class Miner:
    """One block every BLOCK_S; `hold` pauses it, `empty` mines blocks without txs."""

    def __init__(self):
        self.stop, self.hold, self.empty = threading.Event(), threading.Event(), threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        while not self.stop.wait(BLOCK_S):
            if self.hold.is_set():
                continue
            try:
                mine_one(self.empty.is_set())
            except Exception as e:  # noqa: BLE001
                LOG.write(f"miner: {e}\n")


def scenario(i, name):
    parts = name.split("-")
    hub_impl, prov_impl, kind = parts[0], parts[1], (parts[2] if len(parts) > 2 else "after")
    base = PB + 10 + 8 * i
    hub_port, prov_port = base, base + 1
    d = os.path.join(RUN, name)
    os.makedirs(d, exist_ok=True)
    checks, marks = [], []
    t_start = [None]

    def check(what, ok, detail=""):
        checks.append({"check": what, "ok": bool(ok), "detail": detail})

    def mark(what, **kw):
        marks.append({"t": round(time.time() - (t_start[0] or time.time()), 3), "what": what, **kw})

    procs, miner, client = [], None, None
    zc = "0" if kind == "before" else "default"
    try:
        url = f"http://127.0.0.1:{prov_port}"
        sec = f"{secrets.randbelow(2 ** 255) + 1:064x}"
        if prov_impl == "RS":
            cmd = [f"{RS}/xbt402-route-provider", "--port", str(prov_port), "--rpc-port", RPCPORT, "--cookie", COOKIE, "--secret", sec,
                   "--amsat", str(PRICE), "--settle-multiple", str(SETTLE), "--watch-secs", "1", "--ledger", os.path.join(d, "prov.jsonl")]
            if zc != "default":
                cmd += ["--zero-conf-max", zc]
        else:
            cmd = [PY, os.path.join(HERE, "py_route_provider.py"), str(prov_port), sec, str(PRICE), str(SETTLE), zc, "1"]
        procs.append(spawn(cmd))
        assert wait_http(url + "/x402/supported"), f"provider {url} did not come up"
        key = os.path.join(d, "hub.key")
        with open(key, "w") as f:
            f.write(f"{secrets.randbelow(2 ** 255) + 1:064x}")
        os.chmod(key, 0o600)
        hub_dir = os.path.join(d, "hub")
        conf = {"node": {"rpcport": int(RPCPORT), "cookie": COOKIE, "wallet": "w"}, "network": NET, "port": hub_port,
                "datadir": hub_dir, "pay_to_key_file": key, "connect": [url], "watch_interval": 0.5,
                "hub": {"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
                        "delta": 144, "reveal_timeout": 2.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1100,
                        "close_margin": 144, "policy": {"min_expiry_blocks": 1008, "max_expiry_blocks": 8640}}}
        cpath = os.path.join(d, "hub.json")
        with open(cpath, "w") as f:
            json.dump(conf, f)
        hub_cmd = [f"{RS}/xbt402-hub", "--config", cpath] if hub_impl == "RS" else [PY, "-m", "xbt402.hub", "--config", cpath]
        procs.append(spawn(hub_cmd, cwd=B1))
        miner = Miner()
        hub_url = f"http://127.0.0.1:{hub_port}"
        end, r = time.time() + 90, None
        while time.time() < end:
            r = routing(hub_url)
            if r and r.get("providers"):
                break
            time.sleep(0.3)
        check("hub-funded ch2 open to the provider", r and r.get("providers"), str(r and r.get("providers")))
        ch2_path = os.path.join(hub_dir, "ch2.json")
        progress = os.path.join(d, "progress.json")
        out_path = os.path.join(d, "client.json")
        with open(out_path, "w") as out:
            client = subprocess.Popen(SOAK + [f"{RS}/xbt402-rollover-load", "--hub", hub_url, "--shard", url + "/v1/chunk", "--rpc-port", RPCPORT,
                                              "--cookie", COOKIE, "--seconds", str(SECONDS), "--rate", str(RATE), "--progress", progress],
                                      stdout=out, stderr=LOG)
        t_start[0] = time.time()
        seen, zc_seen, stuck, reorg = set(), {}, None, None
        max_unconf = {}                   # child chan -> (highest signed seen while unconfirmed, its cap)
        while client.poll() is None:
            b = book(ch2_path)
            for rec in records(b):
                chan = f"{rec['params'].get('funding_txid')}:{rec['params'].get('funding_vout')}"
                if rec.get("state") == "rolled" and chan not in seen:
                    seen.add(chan)
                    mark("rollover", parent=chan, txid=rec.get("close_txid"), signed=rec.get("signed"))
                z = rec.get("zero_conf") or {}
                if z:
                    conf_now = bool(z.get("confirmed"))
                    if zc_seen.get(chan) != conf_now:
                        zc_seen[chan] = conf_now
                        mark("zero_conf_confirmed" if conf_now else "zero_conf_unconfirmed", chan=chan)
                    if not conf_now:
                        hi = max(max_unconf.get(chan, (0, 0))[0], int(rec.get("signed", 0)))
                        max_unconf[chan] = (hi, int(z.get("maxCum", 0)))
                if kind == "stuck" and stuck is None and rec.get("rolled_from") and rec.get("state") == "open" and z and not z.get("confirmed"):
                    txid = rec["params"]["funding_txid"]
                    miner.empty.set()
                    stuck = {"txid": txid, "chan": chan, "at": time.time()}
                    mark("stuck", txid=txid)
                if kind == "reorg" and reorg is None and rec.get("rolled_from") and z.get("confirmed") and rec.get("state") == "open":
                    txid = rec["params"]["funding_txid"]
                    miner.hold.set()
                    blk = node.getrawtransaction(txid, True).get("blockhash")
                    node.invalidateblock(blk)
                    reorg = {"txid": txid, "chan": chan, "block": blk, "at": time.time()}
                    mark("invalidateblock", txid=txid, block=blk, inMempool=txid in node.getrawmempool())
            if stuck and not stuck.get("released") and time.time() - stuck["at"] >= STUCK_S:
                miner.empty.clear()
                stuck["released"] = time.time()
                mark("released", txid=stuck["txid"])
            if reorg and not reorg.get("resumed") and time.time() - reorg["at"] >= REORG_S:
                miner.hold.clear()
                reorg["resumed"] = time.time()
                mark("miner_resumed")
            time.sleep(0.2)
        res = json.load(open(out_path))
        miner.stop.set()
        mine_one()                        # the last rollover confirms; the watcher folds the last pass
        time.sleep(2.0)
        b = book(ch2_path)
        recs = records(b)
        miner.stop.set()
        # --- checks ---------------------------------------------------------------------------------
        rolled = [r for r in recs if r.get("state") == "rolled"]
        refused, bad = res.get("refused", {}), res.get("badCalls", {})
        if kind != "stuck":                # a held rollover pauses routing past the cap, by design
            check(f"lock rate >= 10/s ({res.get('lockRate')})", res.get("lockRate", 0) >= 10, "")
        if kind in ("after", "reorg"):
            check(f"rollovers under load ({len(rolled)})", len(rolled) >= (3 if kind == "after" else 1), "")
            check("zero refused locks (no route_blocked, nothing to fail over on)", not refused, json.dumps(refused))
            check("every call 200 (no session stalled)", not bad, json.dumps(bad))
            # a child opens unconfirmed (zeroConf), or plainly if a block confirmed it before the open
            zcs = [bool(r.get("zero_conf")) for r in recs if r.get("rolled_from")]
            check(f"next ch2s taken unconfirmed ({sum(zcs)} of {len(zcs)}; the rest confirmed before the open)", any(zcs), json.dumps(zcs))
        if kind == "before":
            check(f"rollovers under load ({len(rolled)})", len(rolled) >= 2, "")
            check("baseline: the gap is there (route_blocked refusals)", refused.get("route_blocked", 0) > 0, json.dumps(refused))
        if kind == "reorg":
            check("reorg: the hub saw the child unconfirmed again", reorg is not None and any(m["what"] == "zero_conf_unconfirmed" and m["chan"] == reorg["chan"]
                                                                                              and m["t"] >= reorg["at"] - t_start[0] for m in marks),
                  json.dumps(reorg))
            check("reorg: re-confirmed on the new chain", reorg is not None and zc_seen.get(reorg["chan"]) is True, "")
        if kind == "stuck":
            capped = [c for c, (hi, cap) in max_unconf.items() if stuck and c == stuck["chan"]]
            hi, cap = max_unconf.get(stuck["chan"], (0, 0)) if stuck else (0, 0)
            check("stuck: the child was used unconfirmed, never above the provider's cap", stuck is not None and 0 < hi <= cap,
                  f"signed {hi} cap {cap} {capped}")
            check("stuck: only route_blocked (the hub's own cap check), no provider refusal; calls stall (402) only past the cap",
                  set(refused) <= {"route_blocked"} and set(bad) <= {"402"}, json.dumps(refused) + json.dumps(bad))
            bad_t = [x[0] for x in res.get("timeline", []) if x[1] == "call"]
            check("stuck: stalled calls only while the rollover was held out of blocks",
                  stuck is not None and all(stuck["at"] - t_start[0] <= t <= stuck.get("released", time.time()) - t_start[0] + BLOCK_S + 3
                                            for t in bad_t), f"{bad_t[:3]}..{bad_t[-3:]}")
            first_ref = [x[0] for x in res.get("timeline", []) if x[1] == "refused"]
            check("stuck: refusals only while the rollover was held out of blocks",
                  stuck is not None and all(stuck["at"] - t_start[0] <= t <= stuck.get("released", time.time()) - t_start[0] + BLOCK_S + 3
                                            for t in first_ref), f"{first_ref[:3]}..{first_ref[-3:]}")
            check("stuck: routing resumed once it confirmed", stuck is not None and zc_seen.get(stuck["chan"]) is True
                  and any(m["what"] == "rollover" and m["t"] > stuck.get("released", 1e18) - t_start[0] for m in marks), "")
        # money: every rollover tx on chain, routed == paid, nothing pending or written off
        bad_roll = []
        by_txid = {r["params"]["funding_txid"]: r for r in recs}
        for r in rolled:
            p = r["params"]
            tx = node.getrawtransaction(r["close_txid"], True)
            vals = [round(o["value"] * SAT) for o in tx["vout"]]
            want = [r["signed"] - p["close_fee"], p["capacity"] - r["signed"]]
            nxt = by_txid.get(r["close_txid"])
            if vals != want or nxt is None or nxt["params"]["capacity"] != want[1] or not tx.get("confirmations"):
                bad_roll.append({"txid": r["close_txid"], "vals": vals, "want": want, "conf": tx.get("confirmations")})
        check("each rollover tx pays signed - closeFee to the provider and capacity - signed to the next ch2, confirmed",
              rolled and not bad_roll, json.dumps(bad_roll)[:300])
        routed = sum(int(r.get("routed", 0)) for r in recs)
        shards = res["summary"]["shards"]
        paid = sum(int(s["locked_sat"]) for s in shards.values())
        check(f"routed over all ch2s == what the client's locks paid ({routed} == {paid})", routed == paid and paid > 0, "")
        check("no ch2 lock pending or written off", all(not r.get("pending") and not r.get("stale") for r in recs), "")
        return {"run": name, "ok": all(c["ok"] for c in checks), "checks": checks, "rollovers": len(rolled),
                "client": {k: res.get(k) for k in ("seconds", "calls", "locksPaid", "lockRate", "refused", "badCalls", "lockOther",
                                                  "maxGapMs", "gapsOver1s", "gapP50Ms", "lockMs")},
                "refusedPerRollover": round(sum(refused.values()) / max(1, len(rolled)), 2),
                "timeline": res.get("timeline", [])[:200], "marks": marks,
                "book": [{k: r.get(k) for k in ("state", "rolled_from", "zero_conf", "signed", "routed", "opened_at", "blocked", "close_txid")}
                         | {"chan": f"{r['params'].get('funding_txid')}:{r['params'].get('funding_vout')}"} for r in recs]}
    except Exception as e:  # noqa: BLE001
        check("scenario ran", False, f"{type(e).__name__}: {e}")
        return {"run": name, "ok": False, "checks": checks, "marks": marks}
    finally:
        if client is not None and client.poll() is None:
            client.kill()
        if miner:
            miner.stop.set()
        for p in reversed(procs):
            stop(p)


def main():
    runs = ["RS-RS", "PY-PY", "RS-PY", "PY-RS", "RS-RS-before", "PY-PY-before", "RS-RS-stuck", "PY-PY-stuck", "RS-RS-reorg", "PY-PY-reorg"]
    only = [x for x in os.environ.get("LOAD_ONLY", "").split(",") if x]
    results = []
    for i, name in enumerate(runs):
        if only and name not in only:
            continue
        r = scenario(i, name)
        results.append(r)
        c = r.get("client") or {}
        print(f"  {name:13s} {'PASS' if r['ok'] else 'FAIL'}  rollovers {r.get('rollovers')}  locks/s {c.get('lockRate')}  "
              f"refused {c.get('refused')}  badCalls {c.get('badCalls')}  maxGapMs {c.get('maxGapMs')}  "
              f"refused/rollover {r.get('refusedPerRollover')}", flush=True)
        for ch in r["checks"]:
            if not ch["ok"]:
                print(f"      FAIL {ch['check']}: {ch['detail']}", flush=True)
    rep = os.environ.get("LOAD_REPORT", os.path.join(RUN, "rollover_load.json"))
    with open(rep, "w") as f:
        json.dump({"seconds": SECONDS, "rate": RATE, "blockS": BLOCK_S, "stuckS": STUCK_S, "reorgS": REORG_S, "results": results}, f, indent=1)
    sys.exit(0 if results and all(r["ok"] for r in results) else 1)


if __name__ == "__main__":
    main()
