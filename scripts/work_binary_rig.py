#!/usr/bin/env python3
"""AGP-091: the real xbt-work-provider binary against a fake node and a fake Prime.

The binary has no test of its own (its loop, flags and admin check are wiring around the library),
and three findings of the second closure audit were "from a run of the binary". This rig runs the
binary and checks what it does, with no chain, miner or Prime needed:

  S0  `--work-units 1` with no cap flag: the caps printed at start are 100 and 1000 work units
  S1  a stranger's coinbase pays the identity 1 sat, the Prime answers 404: no distrust
  S2  the Prime answers 500 for one height, for ever: the blocks after it are still audited
  S3  300 invoice requests through "a proxy" (loopback peer, any X-Forwarded-For): all 200
  S4  the admin endpoints: 404 for a loopback peer with no token, 200 with the token
  S5  a restart goes on from the kept position (`auditNext`), not from 100 blocks below the tip

  scripts/work_binary_rig.py [PATH-TO-xbt-work-provider]     (default: target/debug/xbt-work-provider)
  WORK_RIG_PORT_BASE (default 25910): the fake node, the fake Prime and the provider take base..base+2.

Exit 0 when every check passes.
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

BASE = int(os.environ.get("WORK_RIG_PORT_BASE", "25910"))
NODE, PRIME, API = BASE, BASE + 1, BASE + 2
IDENTITY = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3"
# any 32-byte Ed25519 key: no statement in this rig is signed
PRIME_PUB = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
BITS = "1a00f0b5"
SUBSIDY = 312_500_000
STATE = {"tip": 300, "paid": {}, "prime": {}, "asked": {}}
LOCK = threading.Lock()


def block_hash(h):
    return f"{h:064x}"


class Node(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        m, p = req["method"], req.get("params", [])
        with LOCK:
            tip, paid = STATE["tip"], dict(STATE["paid"])
        height_of = lambda hx: int(hx, 16)
        err = None
        if m == "getblockcount":
            res = tip
        elif m == "getblockhash":
            res = block_hash(p[0])
        elif m == "getbestblockhash":
            res = block_hash(tip)
        elif m == "getblockheader":
            res = {"bits": BITS, "height": height_of(p[0])}
        elif m == "getblockstats":
            res = {"subsidy": SUBSIDY}
        elif m == "getblock":
            h = height_of(p[0])
            vout = [{"value": (SUBSIDY - paid.get(h, 0)) / 1e8, "scriptPubKey": {"address": "bcrt1qsomeotherminer"}}]
            if paid.get(h):
                vout.append({"value": paid[h] / 1e8, "scriptPubKey": {"address": IDENTITY}})
            res = {"hash": p[0], "height": h, "bits": BITS, "previousblockhash": block_hash(h - 1), "tx": [{"vout": vout}]}
        elif m == "getdeploymentinfo":
            res = {"deployments": {}}
        else:
            res, err = None, {"code": -32601, "message": f"rig: no {m}"}
        body = json.dumps({"result": res, "error": err, "id": req.get("id")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Prime(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        h = int(self.path.split("height=")[1])
        with LOCK:
            STATE["asked"][h] = STATE["asked"].get(h, 0) + 1
            status = STATE["prime"].get(h, 404)
        body = b"no window statement" if status == 404 else b"upstream error"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(port, handler):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def call(path, method="GET", headers=None, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{API}{path}", data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


FAILED = []


def check(ok, what):
    print(("  ok   " if ok else "  FAIL ") + what, flush=True)
    if not ok:
        FAILED.append(what)


class Provider:
    def __init__(self, binary, data, extra):
        self.log = open(os.path.join(data, "provider.log"), "ab")
        self.args = [binary, "--port", str(API), "--rpc-port", str(NODE), "--cookie", os.path.join(data, "cookie"), "--identity", IDENTITY,
                     "--prime-pubkey", PRIME_PUB, "--prime-id", "70", "--receipt-url", f"http://127.0.0.1:{PRIME}/receipt",
                     "--window-url", f"http://127.0.0.1:{PRIME}/window", "--data-dir", os.path.join(data, "data"), "--pull-secs", "0"] + extra
        self.p = subprocess.Popen(self.args, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            if self.p.poll() is not None:
                raise SystemExit(f"provider exited {self.p.returncode}: see {self.log.name}")
            try:
                if call("/health")[0] == 200:
                    return
            except OSError:
                time.sleep(0.1)
        raise SystemExit("provider not ready")

    def stop(self):
        self.p.terminate()
        self.p.wait(timeout=10)

    def text(self):
        self.log.flush()
        return open(self.log.name, "r", errors="replace").read()


def wait_for(cond, secs=40):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.25)
    return False


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "target/debug/xbt-work-provider"
    data = tempfile.mkdtemp(prefix="work-rig-")
    open(os.path.join(data, "cookie"), "w").write("rig:rig\n")
    serve(NODE, Node)
    serve(PRIME, Prime)
    token_file = os.path.join(data, "data", "admin.token")
    state_file = os.path.join(data, "data", "work.json")
    report = lambda: json.loads(call("/admin/xbt-work/report", headers={"Authorization": "Bearer " + open(token_file).read().strip()})[1])
    position = lambda: json.load(open(state_file)).get("auditNext")
    try:
        # the Prime fails one height for ever; a stranger's block pays the identity 1 sat
        with LOCK:
            STATE["prime"][250] = 500
            STATE["paid"][260] = 1
        p = Provider(binary, data, ["--admin", "--work-units", "1"])

        print("== S0: --work-units 1, no cap flag")
        check("CreditCaps { per_invoice: Some(100), total: Some(1000) } work units at this epoch (1 a call)" in p.text(),
              "the caps at start are 100 and 1000 work units, 1 a call")

        print("== S2: the Prime answers 500 for height 250, for ever")
        check(wait_for(lambda: os.path.exists(state_file) and position() == 295), f"the walk passed it and stands at 295 (tip 300, 6 deep): auditNext = {position()}")
        with LOCK:
            asked = dict(STATE["asked"])
        check(asked.get(251, 0) >= 1 and asked.get(294, 0) >= 1, f"the blocks after it were asked for (251: {asked.get(251, 0)}, 294: {asked.get(294, 0)})")
        check("height 250" in p.text() and "asking again" in p.text(), "the log says height 250 has no statement for now and is asked for again")
        time.sleep(6)
        with LOCK:
            again = STATE["asked"].get(250, 0)
        check(2 <= again <= 6, f"height 250 was asked for again, with a growing pause ({again} times in about 8 s of 2 s passes)")

        print("== S1: block 260 pays the identity 1 sat, the Prime has no statement")
        r = report()
        check(r["distrust"] is None, f"no distrust: {r['distrust']}")
        check(not any(a.get("height") == 260 for a in r["audits"]), "no verdict recorded for 260")

        print("== S4: the admin endpoints")
        check(call("/admin/xbt-work/report")[0] == 404, "a loopback peer with no token: 404")
        check(call("/admin/xbt-work/report", headers={"X-Forwarded-For": "198.51.100.7"})[0] == 404, "as a client behind a same-host proxy looks: 404")
        check(call("/admin/xbt-work/report", headers={"Authorization": "Bearer " + "0" * 64})[0] == 404, "a wrong token: 404")
        check(call("/admin/xbt-work/audit", "POST", {"Content-Type": "application/json"}, b'{"from": 299, "to": 300}')[0] == 404, "POST audit with no token: 404")
        check(oct(os.stat(token_file).st_mode & 0o777) == "0o600", "DIR/admin.token is 0600")
        st, body = call("/admin/xbt-work/audit", "POST", {"Authorization": "Bearer " + open(token_file).read().strip()}, b'{"from": 299, "to": 300}')
        check(st == 200 and report()["distrust"] is None, "with the token: an audit of the tip (no statement published yet) runs and distrusts nobody")

        print("== S3: 300 invoice requests, as through a proxy")
        before = os.stat(state_file).st_mtime_ns
        codes = [call("/x402/xbt-work/invoice", "POST", {"X-Forwarded-For": f"198.51.100.{n % 4}"}, b"")[0] for n in range(300)]
        check(codes.count(200) == 300, f"all 300 answered 200 ({sorted(set(codes))})")
        check(os.stat(state_file).st_mtime_ns == before, "the state file was not written")

        print("== S5: a restart after the chain moved 150 blocks")
        p.stop()
        with LOCK:
            STATE["tip"] = 450
            STATE["asked"] = {}
        p = Provider(binary, data, ["--admin", "--work-units", "1"])
        check("audit: starting at height 295" in p.text(), "the walk starts at the kept position, 295")
        check(wait_for(lambda: position() == 445), f"and reaches 445: auditNext = {position()}")
        with LOCK:
            asked = dict(STATE["asked"])
        check(all(asked.get(h, 0) >= 1 for h in range(295, 445)), "every block in between was asked for (before: 344 and up only)")
        p.stop()
    finally:
        try:
            p.stop()
        except Exception:  # noqa: BLE001
            pass
        if FAILED:
            print(f"logs kept in {data}")
        else:
            shutil.rmtree(data, ignore_errors=True)
    print("work binary rig: " + ("OK" if not FAILED else f"{len(FAILED)} FAILED"))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
