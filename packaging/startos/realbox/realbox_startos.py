#!/usr/bin/env python3
"""The wallet and the gateway on a real StartOS 0.4 server, on regtest, as far as the platform lets one box
go: side-loaded, the owner's actions and pages, the Lightning dependency (a regtest stand-in with Lightning
Fork's id), the agent's MCP over the LAN, and the paid buy attempted.

    realbox_startos.py OUT PHASE...   PHASE: chain wallet-start owner owner-resume buy restart uninstall

Environment: STARTOS_HOST, STARTOS_ROOT_CA (the server's root CA, which `start-cli setup` prints at the end of
the setup), START_CLI (start-cli 2.1.0), START_CLI_HOME (a HOME whose .startos holds the CLI's identity key and
session: `start-cli init-key`, then `start-cli auth login`), SIGN_BIN.

Before it: side-load lightning-fork-standin (build it like packaging/startos/build.sh does a package; it carries
the regtest chain node and two Lightning Fork nodes, with the real package's id, REST port and tls.cert at the
root of its main volume), start it, and side-load the two packages.

What it found on StartOS 0.4.0.1: a dependency can be mounted only as a directory (StartOS refuses file mounts
of a dependency's volume), so the packages' single-file mount of tls.cert fails and neither starts while
Lightning Fork is installed. The rest of the run used a test profile: tls.cert copied alone into public/ of
the stand-in's volume, and the packages built to mount that directory.
"""
import http.client as hclient
import json
import os
import re
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))  # packaging/
CA = os.environ["STARTOS_ROOT_CA"]
os.environ["SSL_CERT_FILE"] = CA  # urllib (the MCP client) trusts the server's CA
import regtest_lib as rl  # noqa: E402
from regtest_lib import POLICY_BASE, Mcp, Ui, check, http, log, wait_until  # noqa: E402

OUT = os.path.abspath(sys.argv[1])
PHASES = sys.argv[2:]
os.makedirs(OUT, exist_ok=True)
rl.open_log(os.path.join(OUT, "realbox_startos.log"))
HOST = os.environ["STARTOS_HOST"]
SIGN_BIN = os.environ["SIGN_BIN"]
CLI = os.environ.get("START_CLI", os.path.expanduser("~/.local/opt/start-cli/start-cli"))
W, G, LF = "xbt-agent-wallet", "lightning-stream-gateway", "lightning-fork"
STATE = os.path.join(OUT, "state.json")
SPLIT = 125


def load():
    try:
        return json.load(open(STATE))
    except FileNotFoundError:
        return {}


def save():
    fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(S, f, indent=1)


S = load()


def cli(*args, input=None, check_rc=True, timeout=600):
    r = subprocess.run([CLI, "-H", f"https://{HOST}", "--root-ca", CA, *args], input=input, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, "HOME": os.environ["START_CLI_HOME"]})
    if check_rc and r.returncode != 0:
        shown = re.sub(r"(-rpcpassword=)\S+", r"\1<redacted>", " ".join(args)[:200])
        raise RuntimeError(f"start-cli {shown}: rc={r.returncode} {(r.stderr or r.stdout).strip()[-600:]}")
    return r.stdout


def attach(pkg, sub, *cmd, check_rc=True):
    """A command in a service's subcontainer. start-cli's attach exits 0 whatever the command did, so a
    command's error is read from its stderr."""
    r = subprocess.run([CLI, "-H", f"https://{HOST}", "--root-ca", CA, "package", "attach", pkg, "-n", sub, "--", *cmd], input="",
                       capture_output=True, text=True, timeout=600, env={**os.environ, "HOME": os.environ["START_CLI_HOME"]})
    if check_rc and (r.returncode != 0 or re.search(r"error|failed|not found", r.stderr, re.I)):
        shown = re.sub(r"(-rpcpassword=)\S+", r"\1<redacted>", " ".join(cmd)[:200])
        raise RuntimeError(f"attach {pkg}/{sub} {shown}: {(r.stderr or r.stdout).strip()[-600:]}")
    return r.stdout


def db():
    v = json.loads(cli("db", "dump"))
    return v.get("value", v)


def pkg(p):
    return db()["packageData"].get(p)


def health(p):
    s = (pkg(p) or {}).get("statusInfo") or {}
    return {k: (x.get("result"), x.get("message")) for k, x in (s.get("health") or {}).items()}, s.get("desired"), s.get("error")


def action(p, a, inp=None):
    """An action as the UI runs it: its input form first (get-input gives the event id), then the run."""
    if inp is None:
        return cli("package", "action", "run", p, a, input="null")
    ev = json.loads(cli("package", "action", "get-input", p, a, "--format", "json"))["eventId"]
    return cli("package", "action", "run", p, a, "--event-id", ev, input=json.dumps(inp))


def container_ip(p):
    """The package's LXC address on the OS bridge, from the OS's port-forward table (what getContainerIp gives)."""
    t = cli("net", "forward", "dump-table")
    ports = {G: "8402", W: "33510"}
    m = re.search(rf"\|\s*{ports[p]}\s*\|\s*([0-9.]+):", t) if p in ports else None
    return m.group(1) if m else None


# --- the regtest chain and nodes inside the stand-in --------------------------------------------------------
def chain(*a):
    return attach(LF, "knots-sub", "bitcoin-cli", "-datadir=/data", "-rpcuser=lab", "-rpcpassword=lab", *[str(x) for x in a]).strip()


def jchain(*a):
    out = chain(*a)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


NODE = {"lf1": ("lf1-sub", 10009, 8080), "lf2": ("lf2-sub", 10011, 8081)}


def lncli(node, *a):
    sub, grpc, _ = NODE[node]
    out = attach(LF, sub, "lncli", "--lnddir=/data", "--network=regtest", f"--rpcserver=127.0.0.1:{grpc}", *a).strip()
    return json.loads(out) if out.startswith(("{", "[")) else out


def rest(node, path):
    sub, _, port = NODE[node]
    cmd = (f"curl -s --cacert /data/tls.cert -H \"Grpc-Metadata-macaroon: $(od -An -vtx1 /data/data/chain/bitcoin/regtest/admin.macaroon | tr -d ' \\n')\" "
           f"'https://127.0.0.1:{port}{path}'")
    return json.loads(attach(LF, sub, "sh", "-c", cmd) or "{}")


class Lab:
    faucet_wallet = "lab"

    def __init__(self):
        self.facts = S.get("facts", {})

    @property
    def faucet(self):
        return self.facts["faucet"]

    def cli(self, *a, wallet=None):
        return jchain(*(([f"-rpcwallet={wallet}"] if wallet else []) + list(a)))

    def mine(self, n=1):
        chain("-rpcwallet=lab", "generatetoaddress", n, chain("-rpcwallet=lab", "getnewaddress"))
        h = int(chain("getblockcount"))
        for node in NODE:
            wait_until(lambda node=node: (lambda i: i.get("synced_to_chain") and int(i.get("block_height", 0)) >= h)(rest(node, "/v1/getinfo")), 120,
                       f"{node} at {h}", every=1)
        return h

    def seller_settled(self):
        return [i for i in rest("lf2", "/v1/invoices?num_max_invoices=1000").get("invoices", []) if i.get("state") == "SETTLED"]

    def buyer_payments(self):
        return rest("lf1", "/v1/payments?include_incomplete=true&max_payments=1000").get("payments", [])


def phase_chain():
    L = Lab()
    if "lab" not in jchain("listwallets"):
        try:
            chain("loadwallet", "lab")
        except RuntimeError:
            chain("createwallet", "lab")
    L.facts["faucet"] = chain("-rpcwallet=lab", "getnewaddress", "", "bech32")
    if int(chain("getblockcount")) < 130:
        chain("-rpcwallet=lab", "generatetoaddress", 130, L.facts["faucet"])
    for node in NODE:
        wait_until(lambda node=node: rest(node, "/v1/getinfo").get("synced_to_chain"), 240, f"{node} synced", every=3)
    if not any(c.get("active") for c in rest("lf1", "/v1/channels").get("channels", [])):
        addr = lncli("lf1", "newaddress", "p2wkh")["address"]
        legacy = chain("-rpcwallet=lab", "getnewaddress", "", "legacy")
        txid = chain("-rpcwallet=lab", "sendtoaddress", legacy, "0.201")
        chain("-rpcwallet=lab", "generatetoaddress", 1, chain("-rpcwallet=lab", "getnewaddress"))
        tx = json.loads(chain("-rpcwallet=lab", "gettransaction", txid, "true", "true"))["decoded"]
        vout = next(o["n"] for o in tx["vout"] if o["scriptPubKey"].get("address") == legacy)
        sent = json.loads(chain("-rpcwallet=lab", "send", json.dumps({addr: 0.2}), "null", "unset", "2",
                                json.dumps({"inputs": [{"txid": txid, "vout": vout}], "add_inputs": False})))
        assert sent.get("complete"), sent
        L.mine(6)
        wait_until(lambda: int(rest("lf1", "/v1/balance/blockchain").get("total_balance", 0)), 60, "lf1 coin", every=2)
        pk2 = rest("lf2", "/v1/getinfo")["identity_pubkey"]
        attach(LF, "lf1-sub", "lncli", "--lnddir=/data", "--network=regtest", "--rpcserver=127.0.0.1:10009", "connect", f"{pk2}@127.0.0.1:9736",
               check_rc=False)
        for attempt in range(6):
            try:
                lncli("lf1", "openchannel", f"--node_key={pk2}", "--local_amt=5000000", "--push_amt=0")
                break
            except RuntimeError:
                if attempt == 5:
                    raise
                time.sleep(5)
        L.mine(8)
    wait_until(lambda: any(c.get("active") for c in rest("lf1", "/v1/channels").get("channels", [])), 240, "channel active", every=3)
    wait_until(lambda: int(rest("lf1", "/v1/graph/info").get("num_channels", 0)) >= 1, 300, "lf1 knows the channel", every=3)
    bake = lambda node, *p: (lambda o: o["macaroon"] if isinstance(o, dict) else o.split()[-1])(lncli(node, "bakemacaroon", *p))  # noqa: E731
    # one Lightning Fork per box: the gateway and the wallet both get lf1 (the dependency's REST on 8080)
    L.facts.update(rail_macaroon=bake("lf1", "info:read", "offchain:read", "offchain:write", "onchain:read"),
                   invoices_macaroon=bake("lf1", "invoices:read", "invoices:write"), info_macaroon=bake("lf1", "info:read"),
                   lf1_pubkey=rest("lf1", "/v1/getinfo")["identity_pubkey"], lf2_pubkey=pk2 if "pk2" in dir() else rest("lf2", "/v1/getinfo")["identity_pubkey"],
                   network="lightning:" + chain("getblockhash", 101)[:32], split=SPLIT)
    S["facts"] = L.facts
    save()
    ch = rest("lf1", "/v1/channels").get("channels", [])
    check("D", "the stand-in's two regtest nodes: one channel lf1 -> lf2 of 5,000,000 sat, active", len(ch) == 1 and ch[0].get("active"),
          [{k: c.get(k) for k in ("active", "capacity")} for c in ch])


class SUi(Ui):
    """The owner's browser on a StartOS LAN interface (https, the server's own CA)."""

    def req(self, method, path, form=None):
        import urllib.parse
        ctx = ssl.create_default_context(cafile=CA)
        c = hclient.HTTPSConnection(self.host, self.port, timeout=120, context=ctx)
        h = dict(self.headers)
        if self.cookie:
            h["Cookie"] = self.cookie
        body = urllib.parse.urlencode(form) if form is not None else None
        if body is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, self.prefix + path, body, h)
        r = c.getresponse()
        sc = r.getheader("Set-Cookie")
        if sc:
            self.last_set_cookie, self.cookie = sc, sc.split(";")[0]
        return r.status, r.getheader("Location") or "", r.read().decode()


def lan_port(p, host_id, internal):
    b = db()["packageData"][p]["hosts"][host_id]["bindings"][str(internal)]
    return b["net"]["assignedSslPort"]


def enable_lan(p, host_id, internal):
    port = lan_port(p, host_id, internal)
    cli("package", "host", p, "binding", host_id, "set-address-enabled", str(internal), "--address", f"{HOST}:{port}", "--enabled", "true")
    return port


def phase_wallet_start():
    L = Lab()
    lfip = container_ip(LF) or attach(LF, "lf1-sub", "sh", "-c", "hostname -I").split()[0]
    S["lf_ip"] = lfip
    action(W, "node-config", {"host": lfip, "port": 18443, "user": "lab", "password": "lab", "chain": "regtest"})
    tasks = [k for k, t in (pkg(W).get("tasks") or {}).items() if t.get("active")]
    check("I", "wallet: the Node connection action (a critical task) takes the stand-in's chain node; its task is done",
          "xbt-agent-wallet:node-config" not in tasks, tasks)
    cli("package", "start", W)
    try:
        wait_until(lambda: (lambda h: h[0].get("wallet-ready", (None,))[0] == "success")(health(W)), 300, "wallet-ready", every=5)
    except RuntimeError:
        pass
    h = health(W)
    check("I", "wallet: started; its health checks as StartOS shows them", h[0].get("wallet-ready", (None,))[0] == "success", h)
    for p, hid, port in ((W, "ui", 8480), (W, "mcp", 33510), (G, "ui", 8481)):
        S[f"lan_{p}_{hid}"] = enable_lan(p, hid, port)
    save()
    lg = cli("package", "logs", W, "--limit", "200")
    m = re.search(r"setup code ([0-9a-f]+)", lg)
    log("   the wallet's log names its first-run setup code:", bool(m))


def setup_ui(p, host_id, port_key, code, pw):
    ui = SUi(f"https://{HOST}:{S[port_key]}")
    st_bad = ui.req("POST", "/setup-password", {"code": "wrong", "password": pw, "password2": pw})[0]
    st = ui.req("POST", "/setup-password", {"code": code, "password": pw, "password2": pw})[0]
    st_l, _ = ui.login(pw)
    return ui, st_bad, st, st_l


def phase_owner():
    L = Lab()
    pw_w, pw_g = os.urandom(12).hex(), os.urandom(12).hex()
    S.update(ui_pw_w=pw_w, ui_pw_g=pw_g)
    save()
    code = lambda p, a: re.search(r"\b([0-9a-f]{12})\b", action(p, a)).group(1)  # noqa: E731
    gui, b1, s1, l1 = setup_ui(G, "ui", f"lan_{G}_ui", code(G, "ui-setup-code"), pw_g)
    check("U", "gateway: over its LAN https interface (the server's CA), the Setup page code action's code sets the password; a wrong one is refused",
          b1 != 303 and s1 in (200, 303) and l1 == 303 and "Lightning Stream Gateway" in gui.get("/"), [b1, s1, l1])
    ui, b2, s2, l2 = setup_ui(W, "ui", f"lan_{W}_ui", code(W, "ui-setup-code"), pw_w)
    check("U", "wallet: the Web UI setup code action's code sets the UI password over the LAN; login works", b2 != 303 and s2 in (200, 303) and l2 == 303,
          [b2, s2, l2])
    enrol = re.search(r"enrol(?:ment)? code[^0-9A-Za-z]*([0-9A-Za-z-]{6,})", cli("package", "logs", W, "--limit", "400"), re.I)
    ecode = attach(W, "ui-sub", "cat", "/data/signer/.run/enroll-code", check_rc=False).strip() if not enrol else enrol.group(1)
    key = os.path.join(OUT, "device-human.key")
    if not os.path.exists(key):
        fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, os.urandom(32).hex().encode())
        os.close(fd)
    pub, f1, f2 = rl.owner_setup(ui, SIGN_BIN, key, dict(POLICY_BASE, allowlist=[L.faucet]), ecode)
    check("U", "the owner enrols an approval key (the code from the app's log) and signs a policy", "enrolled" in f1.lower() and "applied" in f2.lower(),
          [f1, f2, {"code_in_log": bool(enrol)}])
    S["key"] = key
    save()
    if "restarts" in f2:
        cli("package", "restart", W)
        wait_until(lambda: (lambda h: h[0].get("wallet-ready", (None,))[0] == "success")(health(W)), 300, "wallet-ready", every=5)
        ui = SUi(f"https://{HOST}:{S[f'lan_{W}_ui']}")
        ui.login(pw_w)
    page = ui.get("/lightning")
    check("U", f"Lightning page: the dependency's REST address (https://{S['lf_ip']}:8080, its container address) and the pinned tls.cert",
          f"https://{S['lf_ip']}:8080" in page and "SHA-256" in page and 'name="macaroon"' in page, re.sub(r"<[^>]+>", " ", page)[-600:])
    agents = ui.get("/agents")
    tok = re.search(r'<code id="mcp-token">([0-9a-f]{64})</code>', agents)
    endpoints = re.findall(r"https?://[^<\" ]*/mcp", agents)
    check("U", "Agents page: the token and the MCP addresses", bool(tok), {"endpoints": endpoints})
    S["mcp_token"] = tok.group(1) if tok else None
    save()
    mcp = f"https://{HOST}:{S[f'lan_{W}_mcp']}"
    code_, _, _ = http("POST", f"{mcp}/mcp", b"{}", {"Content-Type": "application/json"})
    check("S", "the MCP on its LAN https interface refuses a request without the token (401)", code_ == 401, code_)
    agent = Mcp(mcp, S["mcp_token"])
    c, init = agent.start()
    check("P", "an agent on the LAN: MCP initialize with the token (https, the server's CA)", c == 200, c)
    sc = lambda m, p=None: json.loads(attach(W, "signer-sub", "/usr/bin/xbt-signer", "call", m, json.dumps(p or {})))  # noqa: E731
    S["custody"] = rl.agent_and_custody("P", agent, ui, SIGN_BIN, key, L, sc, tools="package")
    save()


def phase_owner_resume():
    """The rest of the owner's first run after a failed enrolment: the code from the log, the policy, a quote, the sweep."""
    L = Lab()
    ui = SUi(f"https://{HOST}:{S[f'lan_{W}_ui']}")
    ui.login(S["ui_pw_w"])
    enrol = re.findall(r"enrol(?:ment)? code[^0-9A-Za-z]*([0-9A-Za-z-]{6,})", cli("package", "logs", W, "--limit", "4000"), re.I)
    key = S["key"] if S.get("key") else os.path.join(OUT, "device-human.key")
    if not os.path.exists(key):
        fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, os.urandom(32).hex().encode())
        os.close(fd)
    pub, f1, f2 = rl.owner_setup(ui, SIGN_BIN, key, dict(POLICY_BASE, allowlist=[L.faucet]), enrol[-1] if enrol else "")
    check("U", "the owner enrols an approval key (the one-time code from the service's log) and signs a policy", "enrolled" in f1.lower() and "applied" in f2.lower(),
          [f1, f2, {"code_in_log": bool(enrol)}])
    S["key"] = key
    save()
    if "restarts" in f2:
        cli("package", "restart", W)
        wait_until(lambda: (lambda h: h[0].get("wallet-ready", (None,))[0] == "success")(health(W)), 300, "wallet-ready", every=5)
        ui = SUi(f"https://{HOST}:{S[f'lan_{W}_ui']}")
        ui.login(S["ui_pw_w"])
    agent = Mcp(f"https://{HOST}:{S[f'lan_{W}_mcp']}", S["mcp_token"])
    agent.start()
    q = agent.tool("quote_payment", to=L.faucet, amount_xbt=0.00001)
    check("P", "a payment the agent asks about is judged by the owner's policy (allowed)", q.get("verdict") == "allow", q)
    sc = lambda m, p=None: json.loads(attach(W, "signer-sub", "/usr/bin/xbt-signer", "call", m, json.dumps(p or {})))  # noqa: E731
    ha = sc("hot_address")
    exp = str(int(time.time()) + 600)
    msg = "\n".join(["xbt-agentwallet-hot-sweep-v1", ha["hot_address"], L.faucet, "20000", exp]).encode().hex()
    st, loc, _ = ui.post("/keys", "/sweep", {"to": L.faucet, "amount_sats": "20000", "expiry": exp, "signature": "", "signature_ext": rl.sign(SIGN_BIN, key, msg)})
    f = ui.flash(loc.lstrip(".")) if loc else ""
    L.mine(1)
    left = sc("hot_address").get("hot_sats")
    check("P", "the owner sweeps 20,000 sat of the hot key in the UI, signed on another device", f.startswith("Swept 20000 sats to"), [f, left])
    S["custody"] = {"hot_address": ha["hot_address"], "hot_sats": left}
    save()


def phase_buy():
    L = Lab()
    f = L.facts
    gui = SUi(f"https://{HOST}:{S[f'lan_{G}_ui']}")
    gui.login(S["ui_pw_g"])
    ui = SUi(f"https://{HOST}:{S[f'lan_{W}_ui']}")
    ui.login(S["ui_pw_w"])
    agent = Mcp(f"https://{HOST}:{S[f'lan_{W}_mcp']}", S["mcp_token"])
    agent.start()
    sc = lambda m, p=None: json.loads(attach(W, "signer-sub", "/usr/bin/xbt-signer", "call", m, json.dumps(p or {})))  # noqa: E731
    gip = container_ip(G)
    origin = f"http://{gip}:8402"
    S["gateway_origin"] = origin
    upstream = f"http://{S['lf_ip']}:8090"  # nothing serves there: the buy is refused before any request is passed on
    st, flash = rl.gateway_owner_setup(gui, dict(f, upstream=upstream), origin)
    check("T", "gateway page: the config (service, origin, price, network, two narrow macaroons) is checked by the gateway's parser and saved",
          st == 303 and "Saved" in flash, [st, flash])
    try:
        wait_until(lambda: (lambda h: h[0].get("gateway", (None,))[0] == "success")(health(G)), 120, "gateway health", every=5)
    except RuntimeError:
        pass
    check("T", "the gateway started from that config; its health as StartOS shows it", health(G)[0].get("gateway", (None,))[0] == "success", health(G))
    applied = rl.sign_policy(ui, SIGN_BIN, S["key"], rl.ticket_policy(origin, f["lf1_pubkey"], f["split"]))
    check("T", "the owner signs a policy allowing the gateway (its origin tied to the box's node id), rail and tickets on", "applied" in applied.lower(), applied)
    ui.post("/lightning", "/lightning", {"action": "save", "macaroon": f["rail_macaroon"]})
    fl = ui.flash("/lightning")
    check("T", "Lightning page: the rail macaroon stored", "saved" in fl.lower(), fl)
    last = {}
    try:
        wait_until(lambda: (last.update(sc("ln_status")) or last).get("ready") is True, 180, "rail ready", every=5)
    except RuntimeError:
        pass
    check("T", "the signer restarted with it (xbt-supervise) and the rail is ready over the dependency's REST and pinned certificate",
          last.get("ready") is True, {k: last.get(k) for k in ("ready", "warnings", "backend", "config_error")})
    try:
        r = agent.tool("xbt402_pay", url=f"{origin}/small.txt", max_sats=10)
    except RuntimeError as e:
        r = {"error": str(e)}
    S["buy_attempt"] = r
    save()
    check("T", "the paid buy on one StartOS box: the wallet refuses a seller at a private http address (expected; see the report)",
          r.get("status") != 200, {k: r.get(k) for k in ("verdict", "rail", "status", "reason", "rails_passed_over", "error")})


def phase_restart():
    sc = lambda m, p=None: json.loads(attach(W, "signer-sub", "/usr/bin/xbt-signer", "call", m, json.dumps(p or {})))  # noqa: E731
    hot0 = sc("hot_address")
    for p in (G, W):
        t = time.time()
        cli("package", "restart", p)
        wait_until(lambda p=p: (lambda h: h[1] and h[1].get("main") == "running" and all(v[0] == "success" for v in h[0].values()) and h[0])(health(p)),
                   300, f"{p} back healthy", every=5)
        log(f"   package restart {p}: {time.time() - t:.0f} s to healthy")
    hot = sc("hot_address")
    ui = SUi(f"https://{HOST}:{S[f'lan_{W}_ui']}")
    st, _ = ui.login(S["ui_pw_w"])
    tok = re.search(r'<code id="mcp-token">([0-9a-f]{64})</code>', ui.get("/agents"))
    rail = {}
    try:
        wait_until(lambda: (rail.update(sc("ln_status")) or rail).get("ready") is True, 180, "rail ready", every=5)
    except RuntimeError:
        pass
    check("R", "after a restart of both packages: the UI password, the MCP token, the hot address and coins, and the rail as they were",
          st == 303 and tok and tok.group(1) == S["mcp_token"] and hot["hot_address"] == hot0["hot_address"] and hot.get("hot_sats") == hot0.get("hot_sats")
          and rail.get("ready") is True, {"login": st, "token_same": bool(tok) and tok.group(1) == S["mcp_token"], "hot": [hot0.get("hot_sats"), hot.get("hot_sats")],
                                          "rail": rail.get("ready")})


def phase_uninstall():
    for p in (W, G, LF):
        t = time.time()
        cli("package", "uninstall", p, check_rc=False)
        try:
            wait_until(lambda p=p: pkg(p) is None, 300, f"{p} removed", every=5)
            ok = True
        except RuntimeError:
            ok = False
        check("X", f"package uninstall {p} ({time.time() - t:.0f} s): gone from the server", ok, None)


def main():
    p = None
    try:
        for p in PHASES:
            log(f"### phase {p}")
            {"chain": phase_chain, "wallet-start": phase_wallet_start, "owner": phase_owner, "buy": phase_buy, "restart": phase_restart,
             "uninstall": phase_uninstall, "owner-resume": phase_owner_resume}[p]()
    except Exception as e:  # noqa: BLE001
        check("X", f"phase completed: {p}", False, repr(e)[:800])
    finally:
        try:
            rl.RESULTS[:0] = json.load(open(os.path.join(OUT, "results.json")))
        except FileNotFoundError:
            pass
        ok = rl.write_results(OUT)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
