#!/usr/bin/env python3
"""AGP-102 part D, check B: AGP-094 item 1 through the real processes.

One client request with a bad `lockAuth` must not stop the hub routing to a provider. Real processes:
a Knots regtest node, the `xbt402-hub` binary, two `xbt402-route-provider` binaries. The clients are
B1's RoutePayer (Python reference): an honest one in this process and an attacker in a subprocess
whose `lock_auth` is replaced by a wrong MAC (everything else is the honest client's code).

  honest: opens ch1, streams calls to both providers until locks have settled
  attacker (own ch1): streams calls to provider 0 with a wrong lockAuth until N of its locks were refused
  honest: streams again; its locks to provider 0 must still settle, with no `route_blocked`

Env as scripts/route_interop.sh sets it: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT, RS_BIN, PY, PB, RUN.
    agp102_d_hub_lockauth.py            the driver
    agp102_d_hub_lockauth.py attacker HUB SHARD   (internal)
"""
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.request

B1 = os.environ["XBT402_B1"]
sys.path.insert(0, B1)
from xbt402 import route_client  # noqa: E402
from xbt402.route_client import RoutePayer  # noqa: E402
from xbt402.rpc import RPC  # noqa: E402
from xbt402.signer import ChannelSigner  # noqa: E402
from xbt402.x402_channel import network_id, unb64json  # noqa: E402

node = RPC.from_env()
W = node.wallet("w")
ADDR = W.getnewaddress()
NET = network_id(node.getblockhash(101))


def fund(address, sats):
    txid = W.sendtoaddress(address, sats / 1e8)
    raw = W.gettransaction(txid, False, True)["decoded"]
    node.generatetoaddress(1, ADDR)
    return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)


def payer(hub):
    return RoutePayer(hub, NET, node.getblockcount, fund=fund, signer=ChannelSigner(fund=fund), capacity=200_000, expiry_blocks=8_000)


def stream(pay, shards, secs, rate=10.0):
    """Calls to each shard for `secs`; returns per-shard (ok, statuses, errors)."""
    out = [{"ok": 0, "status": {}, "errors": {}} for _ in shards]
    stop = threading.Event()

    def run(i):
        nxt = time.time()
        while not stop.is_set():
            nxt += 1 / rate
            try:
                st, _, _ = pay.call(shards[i], "POST", b'{"tokens":1}')
                out[i]["ok"] += st == 200
                out[i]["status"][st] = out[i]["status"].get(st, 0) + 1
            except Exception as e:  # noqa: BLE001
                k = getattr(e, "code", None) or type(e).__name__
                out[i]["errors"][k] = out[i]["errors"].get(k, 0) + 1
            time.sleep(max(0.0, nxt - time.time()))
    ths = [threading.Thread(target=run, args=(i,)) for i in range(len(shards))]
    [t.start() for t in ths]
    time.sleep(secs)
    stop.set()
    [t.join() for t in ths]
    until = time.time() + 8
    while time.time() < until and (pay.pending or any(s.due_sat() > 0 for s in shards)):
        time.sleep(0.3)
    return out


def events(pay, since=0):
    c = {}
    for e in pay.events[since:]:
        k = e["event"] + (":" + str(e.get("error")) if e.get("error") else "")
        c[k] = c.get(k, 0) + 1
    return c


if len(sys.argv) > 1 and sys.argv[1] == "attacker":
    hub, shard_url = sys.argv[2], sys.argv[3]
    route_client.lock_auth = lambda *a, **k: "5a" * 32          # the one change: a MAC the provider must refuse
    pay = payer(hub)
    pay.open()
    sh = pay.shard(shard_url)
    pay.start(interval=0.5)
    res = stream(pay, [sh], float(sys.argv[4]) if len(sys.argv) > 4 else 8.0)
    pay.stop()
    print(json.dumps({"calls": res[0], "locks_settled": pay.stats["locks"], "events": events(pay),
                      "last_events": pay.events[-6:], "all_events": pay.events}, default=str))
    sys.exit(0)

RS = os.environ["RS_BIN"]
PY = os.environ.get("PY", sys.executable)
PB = int(os.environ["PB"])
RUN = os.environ["RUN"]
COOKIE = os.path.join(os.environ["XBT402_DATADIR"], "regtest", ".cookie")
RPCPORT = os.environ["XBT402_RPCPORT"]
LOG = open(os.path.join(RUN, "check_b.log"), "a")
PRICES = [370 * 10 ** 20, 813 * 10 ** 20]        # 37 and 81.3 sat a call: every lock is past the ch2 floor and needs a pre-signature
procs = []


def spawn(cmd, **kw):
    p = subprocess.Popen(cmd, stdout=LOG, stderr=LOG, **kw)
    procs.append(p)
    return p


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("PAYMENT-REQUIRED") or e.read().decode()
    except OSError as e:
        return 0, str(e)


def routing(hub_url):
    st, body = get(hub_url + "/x402/route")
    if st == 402:
        return unb64json(body)["accepts"][0]["extra"]["routing"]
    return None


report = {"checks": []}


def check(what, ok, detail=""):
    report["checks"].append({"check": what, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + what + (": " + str(detail) if detail else ""), flush=True)


miner_stop = threading.Event()
try:
    hub_port, ports = PB + 10, [PB + 11, PB + 12]
    urls = [f"http://127.0.0.1:{p}" for p in ports]
    for j, (port, price) in enumerate(zip(ports, PRICES)):
        spawn([f"{RS}/xbt402-route-provider", "--port", str(port), "--rpc-port", RPCPORT, "--cookie", COOKIE,
               "--secret", f"{secrets.randbelow(2 ** 255) + 1:064x}", "--amsat", str(price), "--ledger", os.path.join(RUN, f"prov{j}.jsonl")])
    for u in urls:
        end = time.time() + 30
        while time.time() < end and get(u + "/x402/supported")[0] == 0:
            time.sleep(0.2)
    key = os.path.join(RUN, "hub.key")
    with open(key, "w") as f:
        f.write(f"{secrets.randbelow(2 ** 255) + 1:064x}")
    os.chmod(key, 0o600)
    # the hub section is the one route_interop.py uses, WITHOUT spend_final_depth: the shipped default (6) applies
    conf = {"node": {"rpcport": int(RPCPORT), "cookie": COOKIE, "wallet": "w"}, "network": NET, "port": hub_port,
            "datadir": os.path.join(RUN, "hub"), "pay_to_key_file": key, "connect": urls, "watch_interval": 0.5,
            "hub": {"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
                    "delta": 144, **({} if os.environ.get("REVEAL") == "default" else {"reveal_timeout": 2.0}), "ch2_capacity": 50000, "ch2_expiry_blocks": 1100,
                    "close_margin": 144, "policy": {"min_expiry_blocks": 1008, "max_expiry_blocks": 8640}}}
    cpath = os.path.join(RUN, "hub.json")
    with open(cpath, "w") as f:
        json.dump(conf, f)
    spawn([f"{RS}/xbt402-hub", "--config", cpath], cwd=B1)

    def miner():
        while not miner_stop.wait(0.5):
            try:
                node.generatetoaddress(1, ADDR)
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
    check("setup: the hub binary funded a ch2 to both provider binaries", r and len(r.get("providers", [])) == 2)
    def ch2s():
        """The hub's ch2s from its own state file: funding, state, blocked, pending locks, and how many it archived."""
        doc = json.load(open(os.path.join(RUN, "hub", "ch2.json")))
        out = {o: (c["params"]["funding_txid"], c["state"], c["blocked"], len(c["pending"]), c["retired"]) for o, c in doc["chans"].items()}
        out["archived"] = len(doc["archived"])
        out["next_chans"] = len(doc["next_chans"])
        return out
    ch2_before = ch2s()
    report["providers_before"] = r["providers"]

    honest = payer(hub_url)
    honest.open()
    shards = [honest.shard(u + "/v1/chunk") for u in urls]
    honest.start(interval=0.5)
    a = stream(honest, shards, 6.0)
    locks_a = honest.stats["locks"]
    check("phase 1: the honest client's locks settle at both providers", locks_a >= 2 and all(x["ok"] > 0 for x in a),
          f"{locks_a} locks; calls {[x['ok'] for x in a]}; events {events(honest)}")
    n_ev = len(honest.events)

    cp = subprocess.run([PY, os.path.abspath(__file__), "attacker", hub_url, urls[0] + "/v1/chunk", "8"], capture_output=True, text=True, timeout=180)
    LOG.write(cp.stderr)
    att = json.loads(cp.stdout.strip().splitlines()[-1])
    report["attacker"] = att
    refused = sum(1 for e in att["all_events"] if e["event"] == "void" and "route_failed" in str(e.get("why")))
    check("phase 2: the attacker's locks with a wrong lockAuth are refused and none settles",
          att["locks_settled"] == 0 and refused >= 1, f"settled {att['locks_settled']}; events {att['events']}; calls {att['calls']}")

    b = stream(honest, shards, 8.0)
    locks_b = honest.stats["locks"] - locks_a
    ev_b = events(honest, n_ev)
    check("phase 3: after the refused locks the honest client's locks to the SAME provider still settle",
          locks_b >= 2 and b[0]["ok"] > 0, f"{locks_b} more locks; calls {[x['ok'] for x in b]}; statuses {[x['status'] for x in b]}; errors {[x['errors'] for x in b]}")
    check("phase 3: no lock of the honest client was refused, blocked or voided", not any(k.startswith(("lock_error", "void")) for k in ev_b), str(ev_b))
    r2 = routing(hub_url)
    ch2_after = ch2s()
    check("the hub still advertises both providers", sorted((r2 or {}).get("providers", [])) == sorted(r["providers"]), str((r2 or {}).get("providers")))
    report["providers_after"] = (r2 or {}).get("providers")
    check("the hub's state file lists the same ch2s with the same status as before (no close, no new funding)", ch2_after == ch2_before and len(ch2_before) >= 4 and all(v[1] == "open" and v[2] == "" and v[3] == 0 for k, v in ch2_after.items() if k.startswith("http")), f"{ch2_before} -> {ch2_after}")
    st, hz = get(hub_url + "/healthz")
    report["healthz"] = hz
    check("/healthz of the hub binary answers 200 and carries the watcher's counters", st == 200 and "watcher" in hz, hz[:300])
    # the hub's own books: nothing written off, nothing held
    hub_dir = os.path.join(RUN, "hub")
    held = []
    for root, _, files in os.walk(hub_dir):
        for fn in files:
            try:
                txt = open(os.path.join(root, fn)).read()
            except (OSError, UnicodeDecodeError):
                continue
            for word in ("written_off", "route_blocked", '"blocked": true', '"held"'):
                if word in txt:
                    held.append((fn, word, txt.count(word)))
    report["hub_files_mentions"] = held
    honest.stop()
    try:
        report["honest_close"] = honest.close()
    except Exception as e:  # noqa: BLE001
        report["honest_close"] = {"error": str(e)}
    report["honest_summary_locks"] = honest.stats
except Exception:  # noqa: BLE001
    import traceback
    traceback.print_exc()
    report['checks'].append({'check': 'the driver ran to its end', 'ok': False, 'detail': traceback.format_exc()[-800:]})
finally:
    miner_stop.set()
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    report["ok"] = all(c["ok"] for c in report["checks"]) and len(report["checks"]) >= 6
    with open(os.path.join(RUN, "check_b.json"), "w") as f:
        json.dump(report, f, indent=1, default=str)
    print("check B:", "PASS" if report["ok"] else "FAIL", flush=True)
    sys.exit(0 if report["ok"] else 1)
