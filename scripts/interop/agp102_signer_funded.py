#!/usr/bin/env python3
"""AGP-102 part D, check A: AGP-101 item 1 through the real processes.

"A funding the signer carried out is always learnable by the client that asked for it, and a retry
adopts it and never funds twice." Real processes: a Knots regtest node, the `xbt-signer` binary on its
Unix socket, the `xbt-signer-payer` binary (xbt402's Client + RemoteSigner; it keeps no ledger), the
`xbt402-rust-provider` binary at its shipped terms.

  A1  run 1 with no block mined: the payer's 180 s wait gives up (`funding_unconfirmed`), the usual
      case with ten-minute blocks. One block. Run 2 (a new process): adopts, pays, funds nothing more.
  A2  (stated limit 1) the same against a second provider, but 150 blocks pass before run 2:
      what does the payer say, is anything more funded, and when can that seller be paid again.

Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT, RS_BIN, PB, RUN.
"""
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.environ["XBT402_B1"])
from xbt402.rpc import RPC  # noqa: E402
from xbt402.x402_channel import network_id  # noqa: E402

RS = os.environ["RS_BIN"]
PB = int(os.environ["PB"])
RUN = os.environ["RUN"]
COOKIE = os.path.join(os.environ["XBT402_DATADIR"], "regtest", ".cookie")
RPCPORT = os.environ["XBT402_RPCPORT"]
WAIT = int(os.environ.get("PAYER_WAIT", "200"))
SAT = 100_000_000
node = RPC.from_env()
W = node.wallet("w")
ADDR = W.getnewaddress()
NET = network_id(node.getblockhash(101))
LOG = open(os.path.join(RUN, "check_a.log"), "a")
procs = []
report = {"checks": []}


def check(what, ok, detail=""):
    report["checks"].append({"check": what, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + what + (": " + str(detail) if detail else ""), flush=True)


def note(what, detail):
    report.setdefault("notes", []).append({"note": what, "detail": detail})
    print("NOTE " + what + ": " + str(detail), flush=True)


def spawn(cmd, **kw):
    p = subprocess.Popen(cmd, stdout=LOG, stderr=LOG, **kw)
    procs.append(p)
    return p


def up(url):
    end = time.time() + 30
    while time.time() < end:
        try:
            urllib.request.urlopen(url + "/x402/supported", timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except OSError:
            time.sleep(0.2)
    return False


def signer_call(sock, method, **params):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.settimeout(60)
        c.connect(sock)
        c.sendall((json.dumps({"id": 1, "method": method, "params": params}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = c.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)


def payer(sock, url, calls=3, timeout=WAIT + 60):
    t0 = time.time()
    cp = subprocess.run([f"{RS}/xbt-signer-payer", "--sock", sock, "--url", url, "--network", NET, "--calls", str(calls),
                         "--capacity", "10000", "--max-price", "1000", "--min-conf", "1"],
                        capture_output=True, text=True, timeout=timeout)
    LOG.write(cp.stderr)
    try:
        rep = json.loads(cp.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        rep = {"ok": False, "stdout": cp.stdout[-400:], "stderr": cp.stderr[-400:]}
    rep["_secs"] = round(time.time() - t0, 1)
    rep["_rc"] = cp.returncode
    rep["_stderr"] = cp.stderr[-600:]
    return rep


def brief(rep):
    return {k: rep.get(k) for k in ("ok", "error", "chan", "funding_txid", "signed", "_secs", "_rc")} | {
        "calls": [c["status"] for c in rep.get("calls", [])]}


def chans(sock):
    r = signer_call(sock, "channels")
    return r.get("result", r)


def hot_sats(sock):
    r = signer_call(sock, "balance")
    return r.get("result", r)


try:
    urls = [f"http://127.0.0.1:{PB + 10}", f"http://127.0.0.1:{PB + 11}"]
    for j, u in enumerate(urls):
        spawn([f"{RS}/xbt402-rust-provider", "--port", str(PB + 10 + j), "--rpc-port", RPCPORT, "--cookie", COOKIE,
               "--data-dir", os.path.join(RUN, f"provider{j}")])
    for u in urls:
        assert up(u), f"provider {u} did not come up"
    root = os.path.join(RUN, "signer")
    os.makedirs(root, exist_ok=True)
    key = os.path.join(RUN, "signer.key")
    with open(key, "w") as f:
        f.write(secrets.token_hex(32))
    os.chmod(key, 0o600)
    policy = {"allowlist": urls, "max_per_tx_sats": 20000, "daily_budget_sats": 200000, "weekly_budget_sats": 200000,
              "per_counterparty_cap_sats": 200000, "velocity_max": 100000, "velocity_window_s": 3600, "human_threshold_sats": 20001,
              "split_window_s": 0, "refund_enabled": True, "hot_balance_cap_sats": 0, "regtest_mine": False, "anchor_required": False}
    with open(os.path.join(root, "policy.json"), "w") as f:
        json.dump(policy, f, indent=1)
    sock = os.path.join(root, "signer.sock")
    env = {k: v for k, v in os.environ.items() if not k.startswith("B2_")}
    env.update({"B2_ROOT": root, "B2_DATADIR": os.environ["XBT402_DATADIR"], "B2_RPCPORT": RPCPORT, "B2_WALLET": "agent",
                "B2_CHAIN": "regtest", "B2_SIGNER_SOCK": sock, "B2_CONF": "/dev/null", "B2_HOT_KEYFILE": key, "B2_WATCH_INTERVAL": "2"})
    spawn([f"{RS}/xbt-signer", "--root", root], env=env)
    end = time.time() + 30
    while time.time() < end and not os.path.exists(sock):
        time.sleep(0.2)
    h = signer_call(sock, "health")["result"]
    assert h.get("implementation") == "xbt-signer (Rust)", h
    hot = signer_call(sock, "hot_address")["result"]
    txid = W.sendtoaddress(hot["hot_address"], 200_000 / SAT)
    node.generatetoaddress(1, ADDR)
    signer_call(sock, "notice_hot_txid", txid=txid)
    report["health"] = h
    hot_spk = hot["hot_spk"]

    def signer_spends(since):
        """Mempool transactions that are not in `since`."""
        return sorted(set(node.getrawmempool()) - set(since))

    # ---------------- A1: the wait gives up, one block, a new payer process ----------------
    print("== A1", flush=True)
    before = node.getrawmempool()
    r1 = payer(sock, urls[0])
    report["a1_run1"] = r1
    f1 = signer_spends(before)
    check("A1 run 1: no block for 180 s, the payer binary gives up with `funding_unconfirmed` and exit 1",
          r1["_rc"] == 1 and (r1.get("error") or {}).get("code") == "funding_unconfirmed", brief(r1))
    check("A1 run 1: the signer did fund: exactly one new transaction is in the mempool", len(f1) == 1, f1)
    report["a1_channels_after_run1"] = chans(sock)
    fq = signer_call(sock, "xbt402_funded", origin=urls[0])
    report["a1_funded_answer"] = fq
    check("A1: socket `xbt402_funded` answers the funded channel for that origin", bool((fq.get("result") or {})), str(fq)[:300])
    node.generatetoaddress(1, ADDR)
    before = node.getrawmempool()
    r2 = payer(sock, urls[0])
    report["a1_run2"] = r2
    check("A1 run 2 (new process, no ledger): 3 paid calls, all 200", r2.get("ok") and [c["status"] for c in r2.get("calls", [])] == [200, 200, 200], brief(r2))
    check("A1 run 2: it pays on the channel run 1 funded (same funding txid)", f1 and r2.get("funding_txid") == f1[0], f"{r2.get('funding_txid')} vs {f1}")
    check("A1 run 2: nothing more was funded (no new transaction in the mempool)", signer_spends(before) == [], signer_spends(before))
    r3 = payer(sock, urls[0])
    report["a1_run3"] = r3
    note("A1 run 3 (a third process, after the channel was attached; stated limit 2: 'must keep a ledger, or the owner closes the channel')", brief(r3))
    report["a1_channels_end"] = chans(sock)

    # ---------------- A2: the payer comes back 150 blocks later (stated limit 1) ----------------
    print("== A2", flush=True)
    before = node.getrawmempool()
    q1 = payer(sock, urls[1])
    report["a2_run1"] = q1
    f2 = signer_spends(before)
    check("A2 run 1: `funding_unconfirmed`, one funding in the mempool", (q1.get("error") or {}).get("code") == "funding_unconfirmed" and len(f2) == 1, f"{brief(q1)} {f2}")
    h0 = node.getblockcount()
    node.generatetoaddress(150, ADDR)
    before = node.getrawmempool()
    q2 = payer(sock, urls[1], timeout=WAIT + 60)
    report["a2_run2"] = q2
    note("A2 run 2, 150 blocks after the funding: what the payer binary prints", {"brief": brief(q2), "stderr": q2["_stderr"]})
    check("A2 run 2: the seller cannot be paid: the payer fails and nothing more is funded",
          not q2.get("ok") and signer_spends(before) == [], f"{brief(q2)}; new txs {signer_spends(before)}")
    q3 = payer(sock, urls[1])
    report["a2_run3"] = q3
    note("A2 run 3, again at once", brief(q3))
    ch = chans(sock)
    report["a2_channels"] = ch
    # the way out: the signer's refund at expiry. Find the channel's expiry, mine to it, let the watcher refund.
    rec = None
    for c in (ch.get("channels") or []):
        if c.get("origin") == urls[1] or c.get("funding_txid") == (f2[0] if f2 else None):
            rec = c
    report["a2_record"] = rec
    expiry = (rec or {}).get("expiry") or (rec or {}).get("expiry_height")
    note("A2: the signer's record of that channel", rec)
    if expiry:
        tip = node.getblockcount()
        left = int(expiry) - tip
        note("A2: blocks from the payer's return until the refund can be sent", {"expiry": expiry, "tip": tip, "blocks_left": left, "funded_at": h0})
        if left > 0:
            for _ in range(left // 500 + 1):
                node.generatetoaddress(min(500, max(1, int(expiry) - node.getblockcount() + 2)), ADDR)
                if node.getblockcount() >= int(expiry) + 1:
                    break
        end = time.time() + 40
        refund = []
        base = node.getrawmempool()
        while time.time() < end:
            ch = chans(sock)
            rec2 = next((c for c in (ch.get("channels") or []) if c.get("chan") == rec.get("chan")), None)
            mp = node.getrawmempool()
            if mp or (rec2 or {}).get("status") in ("refunded", "refunding", "closed"):
                refund = mp
                break
            time.sleep(1)
        node.generatetoaddress(1, ADDR)
        time.sleep(4)
        ch = chans(sock)
        rec2 = next((c for c in (ch.get("channels") or []) if c.get("chan") == rec.get("chan")), None)
        report["a2_record_after_expiry"] = rec2
        check("A2: at expiry the signer's watcher refunds the channel nobody opened", bool(refund) or (rec2 or {}).get("status") in ("refunded", "closed"),
              f"mempool {refund}; record {rec2}")
        node.generatetoaddress(6, ADDR)
        time.sleep(4)
        before = node.getrawmempool()
        import threading
        stop = threading.Event()

        def miner():
            while not stop.wait(1.0):
                node.generatetoaddress(1, ADDR)
        threading.Thread(target=miner, daemon=True).start()
        q4 = payer(sock, urls[1])
        stop.set()
        report["a2_run4"] = q4
        check("A2: after the refund the same seller is paid on a new channel", q4.get("ok") and q4.get("funding_txid") not in (f2[0] if f2 else None, None), brief(q4))
    else:
        check("A2: found the signer's record and its expiry", False, str(ch)[:600])
    report["balance_end"] = hot_sats(sock)
except Exception:  # noqa: BLE001
    import traceback
    traceback.print_exc()
    report['checks'].append({'check': 'the driver ran to its end', 'ok': False, 'detail': traceback.format_exc()[-800:]})
finally:
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    report["ok"] = all(c["ok"] for c in report["checks"]) and len(report["checks"]) >= 8
    with open(os.path.join(RUN, "check_a.json"), "w") as f:
        json.dump(report, f, indent=1, default=str)
    print("check A:", "PASS" if report["ok"] else "FAIL", flush=True)
    sys.exit(0 if report["ok"] else 1)
