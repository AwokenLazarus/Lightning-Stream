#!/usr/bin/env python3
"""The container test: the amd64 images on regtest, configured only by env and a data dir, and a paid buy over
stream tickets from the wallet's images to the gateway's image.

Stack on the network of a Lightning Fork regtest lab (packaging/ln_lab.py: a Knots BLAKE2b regtest, lf1 the
buyer's node, lf2 the seller's, one channel; nothing is published but the MCP and the lab nodes' REST, on
127.0.0.1, ports 23700-23799):
  gateway    xbt-gateway:agp038          state volume `gw-state`, setup volume `gw-setup` (its config and two
                                         macaroons, ro), lf2's tls.cert (ro); in front of a stock file server
  witness    xbt-anchor-witness:agp038   data volume `witness`, socket volume `run-anchor`
  signer     xbt-signer:agp038           data volume `signer`, socket volumes `run-signer` (rw), `run-anchor` (ro),
                                         `ln` (the rail macaroon, ro), lf1's tls.cert (ro); in the gateway's
                                         network namespace, so it reaches the gateway at 127.0.0.1:8402 (the
                                         wallet pays tickets over https or to its own machine only, and a
                                         regtest has no https name with a public certificate)
  mcp        xbt-wallet-mcp:agp038       data volume `mcp`, `run-signer` (ro); HTTP on 127.0.0.1:23710
Every image container runs read-only, non-root, with /tmp a tmpfs. The data dir is a set of named volumes
that take their owners from the images' /data skeleton. The provisioning steps are the operator's (a root
helper container, as an app installer would): the node's RPC credentials into signer/secrets, the rail
macaroon into `ln`, the gateway's config and macaroons into `gw-setup`, each baked with only the
permissions it needs. Everything else (the wrapping key, the MCP token) is generated on first run.

Checks (each is PASS/FAIL in results.json):
  S  static: non-root users, read-only root filesystems, HEALTHCHECK passing, generated secrets 0600
  G  /readyz gating: the MCP is up before the signer (healthz 200, readyz 503), then ready; the witness
     stopped / the node stopped make readyz 503 and ready again once they are back
  P  the agent's MCP over HTTP (bearer token): the tool list, the balance, a payment quoted under the
     policy; the hot key funded and counted
  T  the gateway waits for its config, then takes tickets; the rail is ready; the agent's xbt402_pay buys a
     priced page through the wallet; the seller's node settled the ticket and the buyer's node paid it
  R  docker kill + start of witness, signer and MCP: the keys, the hot key's coins, the token and the
     anchors persist; the witness's check of the signature log passes; the agent buys again
    scripts/container_test.sh   (builds the images, then runs this)
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

OUT = sys.argv[1]
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "packaging"))
from ln_lab import PAGE, Lab  # noqa: E402
from regtest_lib import http, status  # noqa: E402

PID = os.getpid()
P = f"pkgct-{PID}"            # container/volume prefix
MCP_PORT = 23710
LAB = Lab(OUT, "pkgcontainer", (23750, 23751))
NET = LAB.net
ORIGIN = "http://127.0.0.1:8402"
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
    return LAB.cli(*a, wallet=wallet)


def mine(n=1):
    return LAB.mine(n)


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
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "container-test", "version": "1"}}})
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
POLICY = {"allowlist": [PAYEE, ORIGIN], "max_per_tx_sats": 5000, "daily_budget_sats": 20000, "weekly_budget_sats": 50000,
          "per_counterparty_cap_sats": 20000, "velocity_max": 50, "velocity_window_s": 3600, "human_threshold_sats": 10000,
          "hot_balance_cap_sats": 100000, "split_window_s": 0, "regtest_mine": False, "anchor_required": True, "anchor_interval_s": 5,
          "tickets": {"enabled": True, "tasks": {"default": {"budget_sats": 20000}}}}
BASE = ["--read-only", "--tmpfs", "/tmp:rw,size=16m", "--restart", "no", "--security-opt", "no-new-privileges"]
COMMON = [*BASE, "--network", NET]
ENV_NODE = ["-e", "XBT_NODE_RPC_HOST=knots-b2b", "-e", "XBT_NODE_RPC_PORT=18443", "-e", "XBT_CHAIN=regtest"]
CERT = "/data/lightning/tls.cert"


def vol(name):
    return f"{P}-{name}"


def run_witness():
    docker("run", "-d", "--name", f"{P}-witness", *COMMON, "-v", f"{vol('witness')}:/data/witness", "-v", f"{vol('run-anchor')}:/data/run/anchor",
           "xbt-anchor-witness:agp038")


def run_signer():
    # in the gateway's network namespace (see the top); the rail: lf1's REST, its pinned certificate, the rail macaroon
    docker("run", "-d", "--name", f"{P}-signer", *BASE, "--network", f"container:{P}-gateway", *ENV_NODE, "-e", "XBT_READY_INTERVAL=2",
           "-e", "B2_WATCH_INTERVAL=2", "-e", "B2_SIGNER_TIMEOUT=240", "-e", f"XBT_SIGNER_POLICY={json.dumps(policy())}",
           "-e", "B2_LN_REST=https://lf1:8080", "-e", "B2_LN_MACAROON=/data/run/ln/rail.macaroon", "-e", f"B2_LN_TLS_CERT={CERT}",
           "-v", f"{vol('signer')}:/data/signer", "-v", f"{vol('run-signer')}:/data/run/signer", "-v", f"{vol('run-anchor')}:/data/run/anchor:ro",
           "-v", f"{vol('ln')}:/data/run/ln:ro", "--mount", f"type=bind,src={LAB.facts['lf1_cert_dir']}/tls.cert,dst={CERT},readonly",
           "xbt-signer:agp038")


def policy():
    """The operator's policy: the payee address, and the gateway's origin tied to the seller's node; the rail and tickets on."""
    return dict(POLICY, counterparties={ORIGIN: {"ln_node": LAB.facts["lf2_pubkey"]}}, ln={"enabled": True, "split_height": LAB.facts["split"]})


def run_gateway():
    docker("run", "-d", "--name", f"{P}-gateway", *COMMON, "-v", f"{vol('gw-state')}:/data/gateway", "-v", f"{vol('gw-setup')}:/data/run/gateway:ro",
           "--mount", f"type=bind,src={LAB.facts['lf2_cert_dir']}/tls.cert,dst={CERT},readonly", "xbt-gateway:agp038")


def seed(volume, files, uid, gid):
    """The installer's step: files into a volume, owned uid:gid, 0640, the dir 0750."""
    d = os.path.join(OUT, f"seed-{volume}")
    os.makedirs(d, exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
    docker("run", "--rm", "--network", "none", "-v", f"{vol(volume)}:/d", "-v", f"{d}:/s:ro", "debian:bookworm-slim", "sh", "-c",
           f"cp /s/* /d/ && chown -R {uid}:{gid} /d && chmod 640 /d/* && chmod 750 /d")
    sh("rm", "-rf", d)


def gateway_config():
    f = LAB.facts
    return {"listen": "127.0.0.1:8402", "public_url": ORIGIN, "upstream": f["upstream"], "state_dir": "/data/gateway", "chain": "regtest",
            "network": f["network"], "node": {"rest": "https://lf2:8080", "tls_cert": CERT, "macaroon": "/data/run/gateway/invoices.macaroon",
                                              "info_macaroon": "/data/run/gateway/info.macaroon"},
            "routes": [{"path": "/", "price": {"request_msat": 2500}}]}


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


def teardown():
    names = docker("ps", "-aq", "--filter", f"name=^{P}-", check_rc=False).stdout.split()
    for n in ("mcp", "signer", "witness", "gateway"):
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
    LAB.down()
    sh("rm", "-rf", os.path.join(OUT, "lab"), check_rc=False)


def main():
    log(f"== container test, prefix {P}, network {NET}, evidence {OUT}")
    log("== the Lightning lab: a Knots BLAKE2b regtest, lf1 (the buyer's node) and lf2 (the seller's), one channel")
    facts = LAB.up()
    for v in ("witness", "signer", "mcp", "run-signer", "run-anchor", "ln", "gw-state", "gw-setup"):
        docker("volume", "create", vol(v))
    cli("-named", "createwallet", "wallet_name=agent", "disable_private_keys=true", "blank=true", "descriptors=true")
    # --- provisioning: the node credentials, the rail macaroon, the gateway's config and macaroons ----------------
    for v, uid in (("signer", 10001),):
        # the helper mounts the volume first, so Docker does not copy the image's /data/<component> owner into it: set it here
        helper(v, f"umask 077 && mkdir -p /d/secrets && printf 'lab:lab' > /d/secrets/node-rpc-auth && chown -R {uid}:{uid} /d && chmod 700 /d")
    seed("ln", {"rail.macaroon": bytes.fromhex(facts["rail_macaroon"])}, 10005, 10008)
    helper("gw-state", "chown 10007:10007 /d && chmod 700 /d")

    # --- T1: the gateway waits for its config ---------------------------------------------------------------------
    log("== T: the gateway, before and after its config")
    run_gateway()
    time.sleep(5)
    glog = docker("logs", f"{P}-gateway", check_rc=False)
    check("T", "the gateway image with no config: its supervisor waits for /data/run/gateway/config.json and starts nothing",
          "waiting for /data/run/gateway/config.json" in glog.stderr + glog.stdout, (glog.stderr + glog.stdout)[-300:])
    seed("gw-setup", {"invoices.macaroon": bytes.fromhex(facts["invoices_macaroon"]), "info.macaroon": bytes.fromhex(facts["info_macaroon"]),
                      "config.json": json.dumps(gateway_config(), indent=1).encode()}, 10005, 10007)
    t0 = time.time()
    wait_until(lambda: docker("exec", f"{P}-gateway", "/usr/bin/xbt-supervise", "probe", "http://127.0.0.1:8402/x402/ticket/health",
                              check_rc=False).returncode == 0, 90, "the gateway's health")
    check("T", f"the config arrives: the gateway starts within {time.time() - t0:.0f} s and answers its health check", True)

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
    # the signer needs the witness answering before it starts (anchor_required)
    wait_until(lambda: health("witness") in ("healthy", "starting") and docker("exec", f"{P}-witness", "/usr/bin/xbt-anchor-witness", "healthcheck",
                                                                               check_rc=False).returncode == 0, 60, "the witness answering")
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
    txid = cli("sendtoaddress", ha["hot_address"], "0.0005", wallet="lab")
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

    # --- T2: the paid buy --------------------------------------------------------------------------------------
    log("== T: the agent buys from the gateway over stream tickets")
    st = wait_until(lambda: (lambda x: x if x.get("ready") is True else None)(signer_call("ln_status")), 120, "the rail ready", every=3)
    check("T", "the rail is ready on lf1 (configured by env and the rail macaroon file): chain verified, the channel's funding proven",
          st.get("ready") is True, {k: st.get(k) for k in ("ready", "warnings")})
    r = mcp.tool("xbt402_pay", url=f"{ORIGIN}/small.txt", max_sats=10)
    body = str((r.get("untrusted_provider_response") or {}).get("body", ""))
    check("T", "the agent's one xbt402_pay call buys the priced page from the gateway image: a ticket over lf1 -> lf2, 2,500 msat used, receipt signed",
          r.get("verdict") == "allow" and r.get("rail") == "ticket" and r.get("status") == 200 and body == PAGE and r.get("tickets_released") == 1
          and r.get("receipt") == {"signed": True, "body": "as signed"},
          {k: r.get(k) for k in ("verdict", "rail", "status", "tickets_released", "price_msat", "balance_msat", "receipt", "reason", "rails_passed_over")})
    settled = wait_until(lambda: LAB.seller_settled(), 30, "the seller's node settled the ticket")
    h = base64.b64decode(settled[-1]["r_hash"]).hex()
    paid = wait_until(lambda: [p for p in LAB.buyer_payments() if p.get("payment_hash") == h and p.get("status") == "SUCCEEDED"], 30,
                      "the buyer's payment SUCCEEDED")
    check("T", "the seller's node settled one ticket of 1,000 sat and the buyer's node paid it (the same hash)",
          int(settled[-1].get("amt_paid_msat") or 0) == 1_000_000 and len(paid) == 1, {"hash": h, "settled": settled[-1].get("amt_paid_msat")})

    # --- R: kill and restart: state persists ---------------------------------------------------------------------
    log("== R: docker kill + start")
    time.sleep(6)   # one anchor interval, so the witness holds the latest head
    docker("kill", f"{P}-mcp", f"{P}-signer", f"{P}-witness")
    code_down = status(f"http://127.0.0.1:{MCP_PORT}/healthz")
    docker("start", f"{P}-witness")
    wait_until(lambda: docker("exec", f"{P}-witness", "/usr/bin/xbt-anchor-witness", "healthcheck", check_rc=False).returncode == 0, 60, "the witness back")
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
    wait_until(lambda: signer_call("ln_status").get("ready") is True, 120, "the rail ready after the restart", every=3)
    r = mcp.tool("xbt402_pay", url=f"{ORIGIN}/small.txt", max_sats=10)
    check("R", "after kill+start the agent buys from the gateway again", r.get("verdict") == "allow" and r.get("status") == 200,
          {k: r.get(k) for k in ("verdict", "rail", "status", "tickets_released", "balance_msat", "reason")})

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
    LAB.lab.dc("stop", "knots-b2b")
    wait_until(lambda: mcp_ready() == 503, 60, "readyz 503 with the node stopped")
    rz = json.loads(http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")[2])
    check("G", "node stopped: MCP /readyz 503 (signer: node unreachable); /healthz 200",
          rz["signer_ready"]["node"]["reachable"] is False
          and status(f"http://127.0.0.1:{MCP_PORT}/healthz") == 200, {"mcp": rz})
    LAB.lab.dc("start", "knots-b2b")
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
