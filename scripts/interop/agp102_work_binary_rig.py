#!/usr/bin/env python3
"""AGP-102 area `work`: the real xbt-work-provider binary against a fake node (ports 27810-27812).
A: getblockcount fails for a moment -> the epoch thread prices at the block value of height 0.
B: a coinbase whose outputs to the identity sum past u64 -> the audit walk panics every round;
   /health stays 200; no later block is audited."""
import base64, http.server, json, os, shutil, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error

NODE, PRIME, API = 27810, 27811, 27812
IDENTITY = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3"
PRIME_PUB = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
BITS, TIP = "1a00f0b5", 840300
S = {"count_fails_until": 0.0, "bad": None, "asked": []}
L = threading.Lock()
bh = lambda h: f"{h:064x}"

class Node(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        m, p = req["method"], req.get("params", [])
        err, res, status = None, None, 200
        if m == "getblockcount":
            with L: failing = time.time() < S["count_fails_until"]
            if failing: status, err = 503, {"code": -1, "message": "Work queue depth exceeded"}
            else: res = TIP
        elif m == "getblockhash": res = bh(p[0])
        elif m == "getbestblockhash": res = bh(TIP)
        elif m == "getblockheader": res = {"bits": BITS, "height": int(p[0], 16)}
        elif m == "getblockstats": res = {"subsidy": 5_000_000_000 if p[0] < 210_000 else 312_500_000}
        elif m == "getblock":
            h = int(p[0], 16)
            with L: S["asked"].append(h); bad = S["bad"]
            vout = [{"value": 3.125, "scriptPubKey": {"address": "bcrt1qsomeotherminer"}}]
            if h == bad:
                vout += [{"value": 1.5e11, "scriptPubKey": {"address": IDENTITY}}] * 2
            res = {"hash": p[0], "height": h, "bits": BITS, "previousblockhash": bh(h - 1), "tx": [{"vout": vout}]}
        elif m == "getdeploymentinfo": res = {"deployments": {}}
        else: err = {"code": -32601, "message": f"rig: no {m}"}
        body = json.dumps({"result": res, "error": err, "id": req.get("id")}).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

class Prime(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()

def serve(port, h):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", port), h)
    threading.Thread(target=s.serve_forever, daemon=True).start()

def get(path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{API}{path}", timeout=10) as r: return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e: return e.code, dict(e.headers), e.read()

def quote():
    st, hd, _ = get("/v1/pools?window=7d")
    pr = hd.get("PAYMENT-REQUIRED") or hd.get("Payment-Required") or hd.get("payment-required")
    doc = json.loads(base64.b64decode(pr + "=" * (-len(pr) % 4)))
    w = [a for a in doc["accepts"] if a["scheme"] == "xbt-work"][0]
    return st, w["amount"], w["extra"]["pricing"]["blockValueSats"]

def start(binary, data, extra):
    log = open(os.path.join(data, "provider.log"), "ab")
    args = [binary, "--port", str(API), "--rpc-port", str(NODE), "--cookie", os.path.join(data, "cookie"), "--identity", IDENTITY,
            "--prime-pubkey", PRIME_PUB, "--prime-id", "70", "--receipt-url", f"http://127.0.0.1:{PRIME}/receipt",
            "--data-dir", os.path.join(data, "data"), "--pull-secs", "0"] + extra
    p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        if p.poll() is not None: raise SystemExit(f"provider exited {p.returncode}")
        try:
            if get("/health")[0] == 200: return p, log.name
        except OSError: time.sleep(0.1)
    raise SystemExit("provider not ready")

def main():
    binary = sys.argv[1]
    serve(NODE, Node); serve(PRIME, Prime)
    data = tempfile.mkdtemp(prefix="agp102_work_rig_", dir=os.path.dirname(os.path.abspath(__file__)))
    open(os.path.join(data, "cookie"), "w").write("__cookie__:x")
    try:
        print("== A: getblockcount fails for 2.5 s")
        p, log = start(binary, data, [])
        print("  before:", quote())
        with L: S["count_fails_until"] = time.time() + 2.5
        seen = set()
        for _ in range(16):
            time.sleep(0.25); seen.add(quote()[1:])
        print("  quotes (amount, blockValueSats) seen during and after:", sorted(seen))
        time.sleep(2.5)
        print("  after:", quote())
        p.terminate(); p.wait(timeout=10)
        print("  log:", [l for l in open(log, errors="replace").read().splitlines() if l.startswith("epoch:")])
        shutil.rmtree(os.path.join(data, "data")); os.remove(log)

        print("== B: block", TIP - 50, "pays the identity two outputs that sum past u64")
        with L: S["bad"] = TIP - 50; S["asked"].clear()
        p, log = start(binary, data, ["--window-url", f"http://127.0.0.1:{PRIME}/window"])
        time.sleep(12)
        text = open(log, errors="replace").read()
        panics = [l for l in text.splitlines() if "a round panicked" in l]
        with L: asked = list(S["asked"])
        state = json.load(open(os.path.join(data, "data", "work.json")))
        print("  /health:", get("/health")[0], get("/health")[2][:120])
        print("  rounds that panicked in 12 s:", len(panics), "| last:", panics[-1][:200] if panics else None)
        print("  highest block the walk asked the node for:", max(asked), "(bad block", TIP - 50, ", it should reach", TIP - 6, ")")
        print("  auditNext in the state file:", state.get("auditNext"), "| process alive:", p.poll() is None)
        p.terminate(); p.wait(timeout=10)
        shutil.rmtree(os.path.join(data, "data")); os.remove(log)

        print("== C: xbt-work-payer with BASE spelled http://LOCALHOST:%d" % API)
        with L: S["bad"] = None
        p, log = start(binary, data, [])
        payer = os.path.join(os.path.dirname(binary), "xbt-work-payer")
        for base in (f"http://127.0.0.1:{API}", f"http://LOCALHOST:{API}"):
            st = os.path.join(data, "payer-" + base.split("//")[1].split(":")[0] + ".json")
            a = subprocess.run([payer, "prepare", base, "--state", st], capture_output=True, text=True, timeout=30)
            keys = list(json.load(open(st)).keys()) if os.path.exists(st) else None
            b = subprocess.run([payer, "pay", base, "1", "1", "--state", st, "--rpc-port", str(NODE), "--cookie", os.path.join(data, "cookie"),
                                "--window-url", f"http://127.0.0.1:{PRIME}/window"], capture_output=True, text=True, timeout=60)
            tail = [l for l in b.stderr.splitlines() if "panicked" in l or "session" in l or "FAIL" in l][:3]
            print(f"  BASE {base}: prepare exit {a.returncode}, session saved under {keys}; pay exit {b.returncode}: {tail}")
        p.terminate(); p.wait(timeout=10)
    finally:
        shutil.rmtree(data, ignore_errors=True)

main()
