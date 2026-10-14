#!/usr/bin/env python3
"""AGP-038 container test: the amd64 images on regtest, configured only by env and a data dir.

Stack on a private Docker network (`agp038-net-<pid>`; nothing but the MCP is published, and only on
127.0.0.1, ports 23700-23799):
  knots      Knots 29.4.2 regtest (a test-only image: debian:bookworm-slim + the binary), rpcuser auth
  witness    xbt-anchor-witness:agp038   data volume `witness`, socket volume `run-anchor`
  signer     xbt-signer:agp038           data volume `signer`, socket volumes `run-signer` (rw), `run-anchor` (ro)
  mcp        xbt-wallet-mcp:agp038       data volume `mcp`, `run-signer` (ro); HTTP on 127.0.0.1:23710
Every image container runs read-only, non-root, with /tmp a tmpfs. The data dir is a set of named volumes
that take their owners from the images' /data skeleton. The one provisioning step is the operator's: it
writes the node's RPC credentials into signer/secrets (a root helper container, as an app
installer would). Everything else (the wrapping key, the MCP token) is generated on first run.

Checks (each is PASS/FAIL in results.json):
  S  static: non-root users, read-only root filesystems, HEALTHCHECK passing, generated secrets 0600
  G  /readyz gating: the MCP is up before the signer (healthz 200, readyz 503), then ready; the witness
     stopped / the node stopped make readyz 503 and ready again once they are back
  P  the agent's MCP over HTTP (bearer token): the tool list, the balance, a payment quoted under the
     policy; the hot key funded and counted
  R  docker kill + start of witness, signer and MCP: the keys, the hot key's coins, the token and the
     anchors persist; the witness's check of the signature log passes
(P and R paid a seller over the on-chain channel until 2026-10. That channel was removed, and this stack
has no Lightning node, so no seller is paid here: an agent paying a seller through the MCP is proven on
Lightning by scripts/ticket_e2e_regtest.sh.)
(The H checks ran the hub and are retired with it; the other letters are unchanged. The hub was retired
on 2026-10-11: payments between parties route over ordinary Lightning instead. Its code is in the git
history, last at commit 0911cc0.)
    scripts/container_test.sh   (builds the images, then runs this)
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

OUT = sys.argv[1]
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KNOTS_BIN = os.environ.get("XBT_BIN", os.path.expanduser("~/lazarus-regtest/b1-xbt402/knots-29.4.2"))
PID = os.getpid()
P = f"agp038-{PID}"            # container/volume prefix
NET = f"agp038-net-{PID}"
MCP_PORT = 23710
RPC_PW = os.urandom(16).hex()
RESULTS = []
LOG = open(os.path.join(OUT, "container_test.log"), "a")


def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    LOG.write(s + "\n")
    LOG.flush()


def check(group, name, ok, detail=None):
    RESULTS.append({"group": group, "check": name, "ok": bool(ok), "detail": detail})
    log(f"  [{'PASS' if ok else 'FAIL'}] {group}: {name}" + ("" if ok else f"  -- {json.dumps(detail, default=str)[:600]}"))
    return ok


def sh(*argv, check_rc=True, input=None, timeout=300):
    r = subprocess.run(argv, capture_output=True, text=True, input=input, timeout=timeout)
    LOG.write(f"$ {' '.join(argv)}\n{r.stdout[-4000:]}{r.stderr[-4000:]}\n")
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:4])}... rc={r.returncode}: {r.stderr.strip()[-800:]}")
    return r


def docker(*a, **kw):
    return sh("docker", *a, **kw)


def wait_until(fn, timeout, what, every=1.0):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(every)
    raise RuntimeError(f"timed out after {timeout}s waiting for {what} (last: {last})")


# --- the node ----------------------------------------------------------------------------------------------

def cli(*a, wallet=None):
    args = ["docker", "exec", f"{P}-knots", "bitcoin-cli", "-regtest", "-datadir=/data/node", "-rpcuser=xbt", f"-rpcpassword={RPC_PW}"]
    if wallet:
        args.append(f"-rpcwallet={wallet}")
    r = sh(*args, *[str(x) for x in a])
    out = r.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def mine(n=1):
    return cli("generatetoaddress", n, FAUCET_ADDR)


class Mcp:
    def __init__(self, base, token):
        self.base, self.token, self.sid, self.n = base, token, None, 0

    def post(self, msg):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             "Authorization": f"Bearer {self.token}", "MCP-Protocol-Version": "2025-06-18"}
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        code, hdrs, body = http("POST", self.base + "/mcp", json.dumps(msg).encode(), h)
        self.sid = self.sid or next((v for k, v in hdrs.items() if k.lower() == "mcp-session-id"), None)
        return code, json.loads(body) if body.strip() else None

    def start(self):
        self.sid = None
        code, r = self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agp038", "version": "1"}}})
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return code, r

    def tool(self, name, **args):
        self.n += 1
        code, r = self.post({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"name": name, "arguments": args}})
        if code != 200 or "result" not in (r or {}):
            raise RuntimeError(f"tools/call {name}: HTTP {code} {r}")
        text = r["result"]["content"][0]["text"]
        if r["result"].get("isError"):
            raise RuntimeError(f"{name}: {text}")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_text": text}


# --- the stack ----------------------------------------------------------------------------------------------

# an address of no wallet here: the one destination the policy allows (regtest P2WPKH of the key 1)
PAYEE = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
POLICY = {"allowlist": [PAYEE], "max_per_tx_sats": 1000, "daily_budget_sats": 20000, "weekly_budget_sats": 50000,
          "per_counterparty_cap_sats": 9400, "velocity_max": 50, "velocity_window_s": 3600, "human_threshold_sats": 5000,
          "hot_balance_cap_sats": 100000, "split_window_s": 0, "regtest_mine": False, "anchor_required": True, "anchor_interval_s": 5}
COMMON = ["--read-only", "--tmpfs", "/tmp:rw,size=16m", "--network", NET, "--restart", "no", "--security-opt", "no-new-privileges"]
ENV_NODE = ["-e", f"XBT_NODE_RPC_HOST={P}-knots", "-e", "XBT_NODE_RPC_PORT=18443", "-e", "XBT_CHAIN=regtest"]


def vol(name):
    return f"{P}-{name}"


def run_witness():
    docker("run", "-d", "--name", f"{P}-witness", *COMMON, "-v", f"{vol('witness')}:/data/witness", "-v", f"{vol('run-anchor')}:/data/run/anchor",
           "xbt-anchor-witness:agp038")


def run_signer():
    docker("run", "-d", "--name", f"{P}-signer", *COMMON, *ENV_NODE, "-e", "XBT_READY_INTERVAL=2", "-e", "B2_WATCH_INTERVAL=2",
           "-e", "B2_SIGNER_TIMEOUT=240", "-e", f"XBT_SIGNER_POLICY={json.dumps(POLICY)}",
           "-v", f"{vol('signer')}:/data/signer", "-v", f"{vol('run-signer')}:/data/run/signer", "-v", f"{vol('run-anchor')}:/data/run/anchor:ro",
           "xbt-signer:agp038")


def run_mcp():
    docker("run", "-d", "--name", f"{P}-mcp", *COMMON, "-e", "XBT_READY_INTERVAL=2", "-e", "B2_SIGNER_TIMEOUT=240", "-e", "XBT_BASE_PATH=/wallet",
           "-p", f"127.0.0.1:{MCP_PORT}:33510", "-v", f"{vol('mcp')}:/data/mcp", "-v", f"{vol('run-signer')}:/data/run/signer:ro",
           "xbt-wallet-mcp:agp038")


def health(name):
    return docker("inspect", "-f", "{{.State.Health.Status}}", f"{P}-{name}", check_rc=False).stdout.strip()


def helper(volume, script, mount="/d", ro=False):
    """A root helper container on one volume (the installer/auditor role; the images have no shell)."""
    return docker("run", "--rm", "--network", "none", "-v", f"{vol(volume)}:{mount}" + (":ro" if ro else ""), "debian:bookworm-slim",
                  "sh", "-c", script)


def signer_call(method, params=None):
    r = docker("exec", f"{P}-signer", "/usr/bin/xbt-signer", "call", method, json.dumps(params or {}))
    return json.loads(r.stdout)


def mcp_ready():
    return status(f"http://127.0.0.1:{MCP_PORT}/readyz")


def build_test_images():
    ctx = os.path.join(OUT, "ctx-knots")
    os.makedirs(ctx, exist_ok=True)
    for b in ("bitcoind", "bitcoin-cli"):
        sh("cp", os.path.join(KNOTS_BIN, b), ctx)
    with open(os.path.join(ctx, "Dockerfile"), "w") as f:
        f.write("FROM debian:bookworm-slim\nCOPY bitcoind bitcoin-cli /usr/local/bin/\nENTRYPOINT [\"/usr/local/bin/bitcoind\"]\n")
    docker("build", "-q", "-t", "agp038-test-knots:29.4.2", ctx)


def teardown():
    names = docker("ps", "-aq", "--filter", f"name=^{P}-", check_rc=False).stdout.split()
    for n in ("mcp", "signer", "witness", "knots"):
        with open(os.path.join(OUT, f"{n}.log"), "w") as f:
            r = docker("logs", f"{P}-{n}", check_rc=False)
            f.write(r.stdout + r.stderr)
    if names:
        docker("rm", "-f", *names, check_rc=False)
    if os.environ.get("CONTAINER_TEST_KEEP"):
        log(f"kept volumes {P}-*")
    else:
        vols = docker("volume", "ls", "-q", "--filter", f"name=^{P}-", check_rc=False).stdout.split()
        if vols:
            docker("volume", "rm", *vols, check_rc=False)
    docker("network", "rm", NET, check_rc=False)


FAUCET_ADDR = None


def main():
    global FAUCET_ADDR
    log(f"== AGP-038 container test, prefix {P}, network {NET}, evidence {OUT}")
    build_test_images()
    docker("network", "create", NET)
    for v in ("node", "witness", "signer", "mcp", "run-signer", "run-anchor"):
        docker("volume", "create", vol(v))

    # --- the node ---------------------------------------------------------------------------
    log("== node")
    docker("run", "-d", "--name", f"{P}-knots", "--network", NET, "-v", f"{vol('node')}:/data/node", "agp038-test-knots:29.4.2",
           "-regtest", "-datadir=/data/node", "-server", "-listen=0", "-rpcbind=0.0.0.0", "-rpcallowip=0.0.0.0/0", "-rpcport=18443",
           "-rpcuser=xbt", f"-rpcpassword={RPC_PW}", "-printtoconsole", "-discover=0", "-listenonion=0", "-dnsseed=0", "-fixedseeds=0",
           # the AGP-017 rehearsal's chain rules: the BLAKE2b hardfork at 101, long coinbase maturity; a pruned node like a box's
           "-fallbackfee=0.0002", "-prune=550", "-testactivationheight=blake2b@101", "-blake2b_headline=agp038",
           "-testcoinbasematuritylong=200:200:6680", "-rdtsexpiry=4102444800")
    wait_until(lambda: cli("getblockcount") == 0 or cli("getblockcount"), 60, "knots RPC")
    cli("createwallet", "faucet")
    FAUCET_ADDR = cli("getnewaddress", wallet="faucet")
    mine(120)
    # the faucet's coinbases mature past the long-maturity window (height 6,680): mine to 6,720 as the rehearsal does
    desc = cli("getdescriptorinfo", "raw(51)")["descriptor"]
    while cli("getblockcount") < 6720:
        cli("generatetodescriptor", min(1000, 6720 - cli("getblockcount")), desc)
    cli("-named", "createwallet", "wallet_name=agent", "disable_private_keys=true", "blank=true", "descriptors=true")
    # --- provisioning: the node credentials only ---------------------------------------------------------------
    for v, uid in (("signer", 10001),):
        # the helper mounts the volume first, so Docker does not copy the image's /data/<component> owner into it: set it here
        helper(v, f"umask 077 && mkdir -p /d/secrets && printf 'xbt:{RPC_PW}' > /d/secrets/node-rpc-auth && chown -R {uid}:{uid} /d && chmod 700 /d")

    # --- G1: the MCP first: alive, not ready ------------------------------------------------------------------
    log("== G: MCP before the signer")
    run_mcp()
    wait_until(lambda: status(f"http://127.0.0.1:{MCP_PORT}/healthz") == 200, 30, "MCP /healthz")
    code, _, body = http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")
    check("G", "MCP up, signer absent: /healthz 200, /readyz 503", code == 503, {"readyz": code, "body": body})
    token = helper("mcp", "cat /d/secrets/mcp-http-token", ro=True).stdout.strip()
    code, _, _ = http("POST", f"http://127.0.0.1:{MCP_PORT}/mcp", b"{}", {"Content-Type": "application/json"})
    check("S", "the MCP on 0.0.0.0 generated its bearer token and refuses a request without it (401)", code == 401 and len(token) == 64, code)

    log("== witness + signer")
    run_witness()
    run_signer()
    wait_until(lambda: mcp_ready() == 200, 120, "MCP /readyz 200 (signer ready)")
    rz = json.loads(http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")[2])
    check("G", "signer + witness up: MCP /readyz 200 with node synced, keys unlocked, witness reachable",
          rz["ok"] and rz["signer_ready"]["node"]["synced"] and rz["signer_ready"]["unlocked"] and rz["signer_ready"]["witness"]["reachable"], rz)

    # --- S: static properties ----------------------------------------------------------------------------------
    for n in ("witness", "signer", "mcp"):
        wait_until(lambda: health(n) == "healthy", 90, f"{n} HEALTHCHECK healthy", every=2)
    ins = json.loads(docker("inspect", f"{P}-signer", f"{P}-witness", f"{P}-mcp").stdout)
    check("S", "signer, witness, MCP: non-root, read-only root filesystem, HEALTHCHECK healthy",
          all(i["Config"]["User"] not in ("", "root", "0") and i["HostConfig"]["ReadonlyRootfs"] and i["State"]["Health"]["Status"] == "healthy"
              for i in ins), [(i["Name"], i["Config"]["User"], i["HostConfig"]["ReadonlyRootfs"], i["State"]["Health"]["Status"]) for i in ins])
    perms = helper("signer", "stat -c '%a %u %n' /d /d/secrets /d/secrets/* /d/policy.json /d/.run/hot.json", ro=True).stdout.split("\n")
    perms_mcp = helper("mcp", "stat -c '%a %u %n' /d/secrets /d/secrets/mcp-http-token", ro=True).stdout.split("\n")
    wk = [p for p in perms if p.endswith("signer-wrap-key")]
    check("S", "first run: signer-wrap-key and mcp-http-token generated 0600 in 0700 dirs, owned by the service user",
          wk and wk[0].startswith("600 10001") and any(p.startswith("700 10001 /d/secrets") for p in perms)
          and any(p.startswith("600 10003") for p in perms_mcp), perms + perms_mcp)
    hot = helper("signer", "cat /d/.run/hot.json", ro=True).stdout
    check("S", "the hot key on disk is sealed (aes-256-gcm, kdf keyfile), no plaintext key", '"aes-256-gcm"' in hot and '"keyfile"' in hot, hot[:200])
    socks = docker("run", "--rm", "-v", f"{vol('run-signer')}:/s:ro", "-v", f"{vol('run-anchor')}:/a:ro", "debian:bookworm-slim",
                   "sh", "-c", "stat -c '%a %u:%g %n' /s /s/* /a /a/*").stdout.split("\n")
    check("S", "sockets 0660 in 0750 dirs (signer 10001:10001, witness 10002:10002); readiness file 0640",
          any(s.startswith("660 10001:10001 /s/signer.sock") for s in socks) and any(s.startswith("660 10002:10002 /a/anchor.sock") for s in socks)
          and any(s.startswith("640 10001:10001 /s/ready.json") for s in socks), socks)

    ref = []
    for img, env in (("xbt-wallet-mcp:agp038", "XBT_MCP_HTTP_TOKEN=plain"), ("xbt-signer:agp038", "B2_HOT_PASSPHRASE=plain")):
        r = docker("run", "--rm", "--network", "none", "--read-only", "-e", env, img, check_rc=False)
        ref.append((img, r.returncode, (r.stdout + r.stderr).strip()[-200:]))
    check("S", "production mode (the images' default): a secret as a plain env value is refused at start",
          all(rc != 0 and "refused in production mode" in out for _, rc, out in ref), ref)

    # --- P: the agent's MCP, and the hot key funded and counted ------------------------------------------------
    log("== P: the agent's MCP over HTTP; the hot key funded and counted")
    ha = signer_call("hot_address")
    txid = cli("sendtoaddress", ha["hot_address"], "0.0005", wallet="faucet")
    mine(1)
    signer_call("notice_hot_txid", {"txid": txid})
    hot1 = signer_call("hot_address")
    check("P", "the hot key received 50,000 sat and the wallet counts them", hot1.get("hot_sats") == 50000, hot1)
    mcp = Mcp(f"http://127.0.0.1:{MCP_PORT}/wallet", token)
    code, init = mcp.start()
    check("P", "MCP initialize over HTTP with the bearer token", code == 200 and init["result"]["serverInfo"], init)
    code, listed = mcp.post({"jsonrpc": "2.0", "id": 9000, "method": "tools/list"})
    names = [t.get("name") for t in (listed or {}).get("result", {}).get("tools", [])]
    check("P", "the agent's tools: the six every wallet has, and none of the removed on-chain channel",
          names == ["balance", "quote_payment", "pay", "history", "channels", "xbt402_pay"], names)
    bal1 = mcp.tool("balance")
    check("P", "the agent reads the balance: the hot key's coins, no channel",
          bal1.get("hot", {}).get("hot_sats") == 50000 and bal1.get("channels") == [] and not bal1.get("legacy_channels"), bal1)
    q = mcp.tool("quote_payment", to=PAYEE, amount_xbt=0.00001)
    q_off = mcp.tool("quote_payment", to="bcrt1q9d4ywgfnd8h43da5tpcxcn6ajv590cg6d3tg6axemvljvt2k76zsy4x23f", amount_xbt=0.00001)
    check("P", "a payment the agent asks about is judged by the policy: allowed on the allowlist, refused off it",
          q.get("verdict") == "allow" and q_off.get("verdict") == "deny" and q_off.get("rule") == "allowlist", [q, q_off])

    # --- R: kill and restart: state persists ---------------------------------------------------------------------
    log("== R: docker kill + start")
    time.sleep(6)   # one anchor interval, so the witness holds the latest head
    docker("kill", f"{P}-mcp", f"{P}-signer", f"{P}-witness")
    code_down = status(f"http://127.0.0.1:{MCP_PORT}/healthz")
    docker("start", f"{P}-witness")
    docker("start", f"{P}-signer")
    docker("start", f"{P}-mcp")
    wait_until(lambda: mcp_ready() == 200, 120, "MCP /readyz after the restart")
    token2 = helper("mcp", "cat /d/secrets/mcp-http-token", ro=True).stdout.strip()
    mcp = Mcp(f"http://127.0.0.1:{MCP_PORT}/wallet", token2)
    mcp.start()
    ha2 = signer_call("hot_address")
    bal2 = mcp.tool("balance")
    check("R", "after kill+start: same MCP token, same hot address, the hot key's coins as they were",
          code_down == 0 and token2 == token and ha2["hot_address"] == ha["hot_address"] and ha2.get("hot_sats") == 50000
          and bal2.get("hot", {}).get("hot_sats") == 50000,
          {"healthz_while_down": code_down, "same_token": token2 == token, "hot": [hot1, ha2]})
    slog = docker("logs", f"{P}-signer", check_rc=False)
    check("R", "the signer restarted with anchor_required and its log passed the witness check (no refusal), wrapping key read, not regenerated",
          "refusing" not in (slog.stdout + slog.stderr) and (slog.stdout + slog.stderr).count("generated /data/signer/secrets/signer-wrap-key") == 1,
          (slog.stdout + slog.stderr)[-1500:])
    time.sleep(6)
    wc = docker("run", "--rm", "--user", "0", "--network", "none", "-v", f"{vol('witness')}:/data/witness:ro",
                "-v", f"{vol('signer')}:/data/signer:ro", "xbt-anchor-witness:agp038", "check", "--store", "/data/witness",
                "--log", "/data/signer/.run/signatures.jsonl", check_rc=False)
    check("R", "auditor: xbt-anchor-witness check of the signer's log against the persisted witness store", wc.returncode == 0, wc.stdout + wc.stderr)

    # --- G: readiness follows the witness and the node ----------------------------------------------------------------
    log("== G: /readyz gating")
    docker("stop", f"{P}-witness")
    wait_until(lambda: mcp_ready() == 503, 30, "MCP /readyz 503 with the witness stopped")
    rz = json.loads(http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")[2])
    check("G", "witness stopped: MCP /readyz 503 (witness unreachable), /healthz still 200",
          rz["signer_ready"]["witness"]["reachable"] is False and status(f"http://127.0.0.1:{MCP_PORT}/healthz") == 200, rz)
    docker("start", f"{P}-witness")
    wait_until(lambda: mcp_ready() == 200, 60, "MCP /readyz 200 with the witness back")
    check("G", "witness back: MCP /readyz 200", True)
    docker("stop", f"{P}-knots")
    wait_until(lambda: mcp_ready() == 503, 60, "readyz 503 with the node stopped")
    rz = json.loads(http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")[2])
    check("G", "node stopped: MCP /readyz 503 (signer: node unreachable); /healthz 200",
          rz["signer_ready"]["node"]["reachable"] is False
          and status(f"http://127.0.0.1:{MCP_PORT}/healthz") == 200, {"mcp": rz})
    docker("start", f"{P}-knots")
    wait_until(lambda: mcp_ready() == 200, 90, "readyz 200 with the node back")
    check("G", "node back: MCP /readyz 200", True)
    for n in ("witness", "signer", "mcp"):
        wait_until(lambda: health(n) == "healthy", 120, f"{n} healthy at the end", every=3)
    check("S", "every service HEALTHCHECK healthy at the end", True)
    with open(os.path.join(OUT, "facts.json"), "w") as f:
        json.dump({"hot_before": hot1, "hot_after_restart": ha2, "balance_before": bal1, "balance_after_restart": bal2}, f, indent=1, default=str)


if __name__ == "__main__":
    rc = 0
    try:
        main()
    except Exception as e:  # noqa: BLE001
        check("X", "the run completed", False, repr(e))
    finally:
        teardown()
        with open(os.path.join(OUT, "results.json"), "w") as f:
            json.dump(RESULTS, f, indent=1, default=str)
        n_ok = sum(r["ok"] for r in RESULTS)
        log(f"== {n_ok}/{len(RESULTS)} checks passed")
        rc = 0 if RESULTS and n_ok == len(RESULTS) else 1
    sys.exit(rc)
