#!/usr/bin/env python3
"""The wallet and the gateway on a real umbrelOS 2.0 box, on regtest: installed from community stores
through the dashboard's own API, set up on their pages through the box's app gateway, and one paid buy.

    realbox_umbrel.py OUT PHASE...
    PHASE: stores standins apps owner buy restart rebootbuy uninstall standins-down

Environment: BOX_HOST (the box's LAN address), BOX_KNOWN_HOSTS (its SSH host key file), BOX_SSH_PASSWORD
(the box user's password, which is also the dashboard's and sudo's on umbrelOS), STORE_URLS (the two
community store git URLs, space-separated), SIGN_BIN (an xbt-wallet-ui binary, for signing on "another
device"), STORE_REFRESH=1 to make the box fetch the stores again now. Facts later phases need are kept in
OUT/state.json (mode 600: it holds the test macaroons). Nothing secret is logged. Checks go to
OUT/results.json as in the off-box drivers.

Before it, on the build host (a throwaway box on the LAN, regtest only; stop all three afterwards):
    docker run -d -p 127.0.0.1:5000:5000 registry:2       # push the images there as 127.0.0.1:5000/<image>:<tag>
    ssh -N -R 127.0.0.1:5000:127.0.0.1:5000 umbrel@<box>  # the box's Docker reaches it on its own loopback
    make_stores.py OUT_STORES 127.0.0.1:5000 && serve_git.py <LAN ip> <port> OUT_STORES
Docker allows a plain-http registry on loopback, so nothing on the box changes and nothing is exposed.
"""
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))  # packaging/
sys.path.insert(0, HERE)
import regtest_lib as rl  # noqa: E402
from regtest_lib import POLICY_BASE, Mcp, Ui, check, http, log, status, wait_until  # noqa: E402
from remote import Box as Ssh, RemoteLab, b64hex  # noqa: E402
from umbrel_api import Box  # noqa: E402

OUT = os.path.abspath(sys.argv[1])
PHASES = sys.argv[2:]
os.makedirs(OUT, exist_ok=True)
rl.open_log(os.path.join(OUT, "realbox_umbrel.log"))
HOST = os.environ["BOX_HOST"]
PW = os.environ["BOX_SSH_PASSWORD"]
SIGN_BIN = os.environ["SIGN_BIN"]
WALLET, GATEWAY = "lazarus-xbt-agent-wallet", "lazarus-lightning-stream-gateway"
KNOTS_APP, LF_APP, LF_SELLER = "paulscode-knots-blake2b", "paulscode-lightning-fork", "paulscode-lightning-fork-seller"
APPDATA = "/home/umbrel/umbrel/app-data"
ORIGIN = "http://127.0.0.1:8402"  # the seller as the buyer's signer sees it (the test profile: the gateway's namespace)
MCP_BASE = f"http://{HOST}:33510"
STATE = os.path.join(OUT, "state.json")
ssh = Ssh(HOST, "umbrel", PW, os.environ["BOX_KNOWN_HOSTS"], os.environ.get("BOX_SSH_CONTROL_DIR", OUT))
api = Box(f"http://{HOST}")


def load_state():
    try:
        return json.load(open(STATE))
    except FileNotFoundError:
        return {}


def save_state(st):
    fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(st, f, indent=1)


S = load_state()


def cname(app, svc):
    return f"{app}_{svc}_1"


def app_state(app):
    return api.q("apps.state", appId=app)["state"]


def install(app, alternatives=None):
    t = time.time()
    if app_state(app) == "not-installed":
        log(f"== install {app}" + (f" (dependency picker: {alternatives})" if alternatives else ""))
        inp = {"appId": app}
        if alternatives:
            inp["alternatives"] = alternatives
        try:
            api.m("apps.install", inp)
        except Exception as e:  # noqa: BLE001
            check("I", f"{app}: apps.install accepted", False, str(e))
            raise
    st = wait_until(lambda: (lambda s: s if s in ("ready", "running", "stopped", "unknown") else None)(app_state(app)), 900, f"{app} installed", every=3)
    return st, time.time() - t


def stat(paths):
    return [x for x in ssh.ssh("stat -c '%u:%g %a %n' " + " ".join(paths), check=False).stdout.split("\n") if x]


def lab():
    env = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in ssh.inspect(f"{KNOTS_APP}_node_1")[0]["Config"]["Env"] if "=" in e}
    L = RemoteLab(ssh, env["RPC_USER"], env["RPC_PASSWORD"])
    L.facts = S.get("facts", {})
    if L.facts:
        L.load_wallet()
    return L


class GwUi(Ui):
    """The owner's browser on an app's port through umbrelOS's app gateway: the gateway's login cookie
    (from the app-auth handoff) plus the app's own session cookie."""

    def __init__(self, base, gw_cookie):
        super().__init__(base)
        self.gw = gw_cookie

    def req(self, method, path, form=None):
        app_cookie = self.cookie
        self.cookie = "; ".join(x for x in (self.gw, app_cookie) if x)
        try:
            st, loc, body = super().req(method, path, form)
        finally:
            if self.cookie == "; ".join(x for x in (self.gw, app_cookie) if x):
                self.cookie = app_cookie
        return st, loc, body


def gateway_cookie(app, port):
    jar, st, url = api.app_session(app, port, PW)
    c = "; ".join(f"{k.name}={k.value}" for k in jar)
    return c, st


def owner_ui(app, port):
    gwc, st = gateway_cookie(app, port)
    pw = api.q("apps.details", appId=app)["credentials"]["password"]
    ui = GwUi(f"http://{HOST}:{port}", gwc)
    return ui, pw, st


def sc_factory():
    return lambda m, p=None: json.loads(ssh.exec(cname(WALLET, "signer"), "/usr/bin/xbt-signer", "call", m, json.dumps(p or {})))


# --------------------------------------------------------------------------------------------------------
def phase_stores():
    api.login(PW)
    have = [r["url"] for r in api.q("appStore.repositories")]
    for url in os.environ["STORE_URLS"].split():
        if url in have and os.environ.get("STORE_REFRESH"):
            # umbreld pulls its stores every few minutes; removing and adding one fetches it now
            api.m("appStore.removeRepository", url=url)
            have.remove(url)
        if url not in have:
            api.m("appStore.addRepository", url=url)
    reps = api.q("appStore.repositories")
    reg = api.q("appStore.registry")
    ids = sorted(a["id"] for r in reg for a in r.get("apps", []) if r.get("meta", {}).get("id") in ("lazarus", "paulscode"))
    check("A", "both community stores added by git URL (smart HTTP, read-only) and their apps listed",
          {WALLET, GATEWAY, KNOTS_APP, LF_APP, LF_SELLER} <= set(ids), {"repos": [r["meta"] for r in reps], "apps": ids})
    w = next(a for r in reg for a in r.get("apps", []) if a["id"] == WALLET)
    S["registry_wallet"] = {k: w.get(k) for k in ("id", "version", "dependencies", "icon", "gallery", "port", "appStoreId")}
    save_state(S)
    log("   wallet as listed:", json.dumps(S["registry_wallet"]))


def phase_standins():
    api.login(PW)
    st, t = install(KNOTS_APP)
    check("D", f"stand-in {KNOTS_APP} (implements bitcoin) installed: {st}, {t:.0f} s", st in ("ready", "running"), st)
    L = lab()
    wait_until(lambda: L.cli("getblockchaininfo").get("chain") == "regtest", 120, "the chain node answering", every=3)
    L.bootstrap_chain()
    for app in (LF_APP, LF_SELLER):
        st, t = install(app, {"bitcoin": KNOTS_APP})
        check("D", f"stand-in {app} installed with the bitcoin slot set to {KNOTS_APP}: {st}, {t:.0f} s", st in ("ready", "running"), st)
    facts = L.channel_up()
    S["facts"] = facts
    save_state(S)
    ch = L.channels("lf1")
    check("D", "one channel lf1 -> lf2 of 5,000,000 sat, active; macaroons baked as the owner would in the node's dashboard",
          len(ch) == 1 and ch[0].get("active") and int(ch[0].get("capacity", 0)) == 5_000_000,
          [{k: c.get(k) for k in ("active", "capacity", "remote_pubkey")} for c in ch])
    cert = stat([f"{APPDATA}/{LF_APP}/data/lnd/tls.cert", f"{APPDATA}/{LF_SELLER}/data/lnd/tls.cert"])
    check("D", "each node's tls.cert where Lightning Fork's export says (data/lnd), written by uid 1000 (the node's user, as his app runs it)",
          len(cert) == 2 and all(c.startswith("1000:1000") for c in cert), cert)


def phase_apps():
    api.login(PW)
    st, t = install(GATEWAY, {"paulscode-lightning-fork": LF_SELLER})
    check("I", f"gateway installed through apps.install with Lightning Fork's slot set to the seller's node: {st}, {t:.0f} s", st in ("ready", "running"), st)
    settings = ssh.ssh(f"cat {APPDATA}/{GATEWAY}/settings.yml", check=False).stdout
    check("I", "gateway: umbreld recorded the dependency picker's choice", LF_SELLER in settings, settings)
    grep = json.loads(ssh.docker("logs", cname(GATEWAY, "init")).stdout.strip().splitlines()[-1])
    gi = ssh.inspect(cname(GATEWAY, "init"))[0]
    check("I", "gateway app: init ran first and exited 0, only the UI password provisioned",
          gi["State"]["ExitCode"] == 0 and grep["ok"] and {(s["component"], s["name"]) for s in grep["secrets"]} == {("ui", "xbt-ui-password")}, grep)
    gd = f"{APPDATA}/{GATEWAY}/data"
    ls = stat([f"{gd}/gateway", f"{gd}/ui", f"{gd}/run/ui", f"{gd}/run/gateway"])
    check("I", "gateway app: the bind mount has the gateway's owners",
          ls == [f"10007:10007 700 {gd}/gateway", f"10005:10005 700 {gd}/ui", f"10005:10005 750 {gd}/run/ui", f"10005:10007 750 {gd}/run/gateway"], ls)
    time.sleep(5)
    r = ssh.docker("logs", cname(GATEWAY, "gateway"))
    check("I", "gateway app: with no config yet the supervisor waits for the file the page writes",
          "waiting for /data/run/gateway/config.json" in r.stdout + r.stderr, (r.stdout + r.stderr)[-300:])
    env = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in ssh.inspect(cname(GATEWAY, "ui"))[0]["Config"]["Env"] if "=" in e}
    check("I", "gateway UI: the node's REST address from Lightning Fork's export (the seller's node, as selected)",
          env.get("XBT_UI_GW_NODE_REST") == "https://10.21.21.76:8180", env.get("XBT_UI_GW_NODE_REST"))

    t0 = time.time()
    st, t = install(WALLET, {"bitcoin": KNOTS_APP})
    check("I", f"wallet installed through apps.install with the bitcoin slot set to {KNOTS_APP}: {st}, {t:.0f} s", st in ("ready", "running"), st)
    rep = json.loads(ssh.docker("logs", cname(WALLET, "init")).stdout.strip().splitlines()[-1])
    check("I", "wallet app: init ran first and exited 0: node credentials, UI password and MCP token provisioned (names only)",
          rep["ok"] and {(s["component"], s["name"]) for s in rep["secrets"]} >= {("signer", "node-rpc-auth"), ("ui", "xbt-ui-password"), ("ui", "run/ui/mcp-http-token")},
          rep)
    wd = f"{APPDATA}/{WALLET}/data"
    ls = stat([f"{wd}/{p}" for p in ("signer", "witness", "mcp", "ui", "run/signer", "run/anchor", "signer/secrets/node-rpc-auth",
                                       "ui/secrets/xbt-ui-password", "run/ui", "run/ui/mcp-http-token", "run/ln")])
    want = [f"10001:10001 700 {wd}/signer", f"10002:10002 700 {wd}/witness", f"10003:10003 700 {wd}/mcp", f"10005:10005 700 {wd}/ui",
            f"10001:10001 750 {wd}/run/signer", f"10002:10002 750 {wd}/run/anchor", f"10001:10001 600 {wd}/signer/secrets/node-rpc-auth",
            f"10005:10005 600 {wd}/ui/secrets/xbt-ui-password", f"10005:10005 750 {wd}/run/ui", f"10005:10005 640 {wd}/run/ui/mcp-http-token",
            f"10005:10008 750 {wd}/run/ln"]
    check("I", "wallet app: the bind mount (app-data, owned by the box user) has CONTAINER.md's owners", ls == want, ls)
    try:
        wait_until(lambda: status(f"{MCP_BASE}/readyz") == 200, 300, "MCP /readyz 200 over the LAN", every=3)
        ok = True
    except RuntimeError as e:
        ok = str(e)
    S["t_wallet_ready_s"] = round(time.time() - t0, 1)
    check("I", f"wallet ready: MCP /readyz 200 over the LAN, {S['t_wallet_ready_s']} s after apps.install", ok is True, ok)
    names = [cname(WALLET, s) for s in ("witness", "signer", "mcp", "ui")]
    try:
        wait_until(lambda: all(i["State"].get("Health", {}).get("Status") == "healthy" for i in ssh.inspect(*names)), 180, "HEALTHCHECK healthy", every=5)
    except RuntimeError:
        pass
    ins = ssh.inspect(*names)
    rows = [(i["Name"], i["Config"]["User"], i["HostConfig"]["ReadonlyRootfs"], i["HostConfig"]["CapDrop"], i["HostConfig"]["NetworkMode"],
             i["State"].get("Health", {}).get("Status")) for i in ins]
    check("S", "witness, signer, MCP, UI: non-root, read-only, cap_drop ALL; the witness without a network; HEALTHCHECK healthy",
          all(r[1] not in ("", "0", "root") and r[2] and r[3] == ["ALL"] and r[5] == "healthy" for r in rows) and rows[0][4] == "none", rows)
    code, _, _ = http("POST", f"{MCP_BASE}/mcp", b"{}", {"Content-Type": "application/json"})
    check("S", "the MCP on the LAN refuses a request without the bearer token (401)", code == 401, code)
    env = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in ins[1]["Config"]["Env"] if "=" in e}
    check("I", "signer: the XBT node from the bitcoin slot (APP_BITCOIN_*), Lightning Fork's REST from its export",
          env.get("XBT_NODE_RPC_HOST") == "10.21.21.62" and env.get("XBT_NODE_RPC_PORT") == "18443" and env.get("B2_LN_REST") == "https://10.21.21.66:8180",
          {k: env.get(k) for k in ("XBT_NODE_RPC_HOST", "XBT_NODE_RPC_PORT", "XBT_CHAIN", "B2_LN_REST")})
    save_state(S)


def phase_owner():
    api.login(PW)
    L = lab()
    sc = sc_factory()
    # the gateway's page
    gui, gpw, st = owner_ui(GATEWAY, 8481)
    check("U", f"gateway: umbrelOS's app login (app-auth on port 2000, handoff posted to :8481) answers {st}", st in (302, 303), st)
    s0, _, _ = Ui(f"http://{HOST}:8481").req("GET", "/")
    check("U", f"gateway UI without the dashboard login: the app gateway refuses or redirects ({s0})", s0 in (302, 303, 401), s0)
    stl, _ = gui.login(gpw)
    check("U", "gateway UI: login with the password the dashboard shows (apps.details, ${APP_PASSWORD}); its one page",
          stl == 303 and "Lightning Stream Gateway" in gui.get("/") and gui.req("GET", "/policy")[0] == 404, stl)
    # the wallet's pages
    ui, wpw, st = owner_ui(WALLET, 8480)
    bad, _ = ui.login("not the password")
    good, _ = ui.login(wpw)
    check("U", "wallet UI through the app gateway: a wrong password refused (401), the dashboard's password accepted (303)", bad == 401 and good == 303, [bad, good])
    logs = api.q("apps.logs", appId=WALLET)
    m = re.findall(r"enrol(?:ment)? code[^0-9A-Za-z]*([0-9A-Za-z-]{6,})", logs or "", re.I)
    file_code = ssh.ssh(f"cat {APPDATA}/{WALLET}/data/signer/.run/enroll-code", check=False).stdout.strip()
    check("U", "the signer's one-time enrolment code is in the app's log as the dashboard shows it (apps.logs)", bool(m) and m[-1] == file_code,
          {"found_in_log": bool(m), "matches_file": bool(m) and m[-1] == file_code})
    key = os.path.join(OUT, "device-human.key")
    if not os.path.exists(key):
        fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, os.urandom(32).hex().encode())
        os.close(fd)
    policy = dict(POLICY_BASE, allowlist=[L.faucet])
    if not S.get("enrolled"):
        pub, f_enrol, f_apply = rl.owner_setup(ui, SIGN_BIN, key, policy, file_code)
        check("U", "the owner enrols an approval key and signs a policy in the UI", "enrolled" in f_enrol.lower() and "applied" in f_apply.lower(),
              [f_enrol, f_apply])
        S.update(enrolled=True, key=key)
        save_state(S)
        if "restarts" in f_apply:
            log("   the policy asks for a signer restart: restart the app (dashboard: Restart)")
            api.m("apps.restart", appId=WALLET)
    wait_until(lambda: status(f"{MCP_BASE}/readyz") == 200, 240, "MCP ready", every=3)
    wait_until(lambda: status(f"http://{HOST}:8480/healthz") in (200, 302, 303, 401), 120, "the app's port answering again", every=2)
    st_page = ui.req("GET", "/lightning")
    if st_page[0] != 200:
        log(f"   after the app restart the UI session is gone ({st_page[0]} -> {st_page[1]}): log in again")
        ui, wpw, _ = owner_ui(WALLET, 8480)
        ui.login(wpw)
    page = ui.get("/lightning")
    check("U", "Lightning page: the node's REST address and pinned certificate from the platform; asks only for the macaroon",
          "https://10.21.21.66:8180" in page and "SHA-256" in page and 'name="macaroon"' in page, page[-500:])
    agents = ui.get("/agents")
    tok = re.search(r'<code id="mcp-token">([0-9a-f]{64})</code>', agents)
    disk = ssh.ssh(f"cat {APPDATA}/{WALLET}/data/run/ui/mcp-http-token").stdout.strip()
    check("U", "Agents page: the MCP endpoint (http://<box>.local:33510/mcp) and the token the MCP uses",
          bool(tok) and tok.group(1) == disk and ".local:33510/mcp" in agents, {"has_token": bool(tok), "endpoint": re.findall(r"http://[^<\" ]*:33510/mcp", agents)})
    agent = Mcp(MCP_BASE, tok.group(1))
    code, init = agent.start()
    check("P", "an agent on the LAN: MCP initialize with the token", code == 200 and isinstance(init, dict) and "result" in init, code)
    before = rl.agent_and_custody("P", agent, ui, SIGN_BIN, key, L, sc, tools="package")
    S.update(custody=before, key=key)
    save_state(S)


def phase_buy(tag="T"):
    api.login(PW)
    L = lab()
    sc = sc_factory()
    gui, gpw, _ = owner_ui(GATEWAY, 8481)
    gui.login(gpw)
    ui, wpw, _ = owner_ui(WALLET, 8480)
    ui.login(wpw)
    tok = re.search(r'<code id="mcp-token">([0-9a-f]{64})</code>', ui.get("/agents")).group(1)
    agent = Mcp(MCP_BASE, tok)
    agent.start()

    def gateway_up():
        return ssh.docker("exec", cname(GATEWAY, "gateway"), "/usr/bin/xbt-supervise", "probe", "http://127.0.0.1:8402/x402/ticket/health",
                          check=False).returncode == 0
    if tag == "T":
        bought = rl.paid_buy("T", agent, ui, gui, SIGN_BIN, S["key"], L, sc, gateway_up, ORIGIN)
    else:
        wait_until(gateway_up, 180, "the gateway healthy", every=3)
        wait_until(lambda: sc("ln_status").get("ready") is True, 240, "the rail ready", every=3)
        n0 = len(L.seller_settled())
        r = agent.tool("xbt402_pay", url=f"{ORIGIN}/small.txt", max_sats=10)
        check(tag, {"R": "after apps.restart of both apps", "B": "after a reboot of the box"}.get(tag, tag) + ": the agent buys the page again",
              r.get("verdict") == "allow" and r.get("rail") == "ticket" and r.get("status") == 200,
              {k: r.get(k) for k in ("verdict", "rail", "status", "tickets_released", "balance_msat", "reason")})
        bought = {"settled": len(L.seller_settled()), "new_settled": len(L.seller_settled()) - n0, "balance_msat": r.get("balance_msat"),
                  "tickets_released": r.get("tickets_released")}
    settled = L.seller_settled()
    pays = L.buyer_payments()
    ev = [{"hash": b64hex(i.get("r_hash")), "seller_state": i.get("state"), "amt_paid_msat": i.get("amt_paid_msat"),
           "buyer": [{k: p.get(k) for k in ("status", "value_msat", "fee_msat")} for p in pays if p.get("payment_hash") == b64hex(i.get("r_hash"))]}
          for i in settled]
    S.setdefault("buys", {})[tag] = {"bought": bought, "tickets": ev}
    save_state(S)
    log(f"   tickets settled on the seller's node, and the buyer's payment for each: {json.dumps(ev)}")


def phase_restart():
    api.login(PW)
    sc = sc_factory()
    token_before = ssh.ssh(f"cat {APPDATA}/{WALLET}/data/run/ui/mcp-http-token").stdout.strip()
    hot_before = sc("hot_address")
    # the wallet's signer lives in the gateway's network namespace (the test profile): the gateway first
    for app in (GATEWAY, WALLET):
        t = time.time()
        api.m("apps.restart", appId=app)
        wait_until(lambda app=app: app_state(app) in ("ready", "running"), 300, f"{app} back", every=3)
        log(f"   apps.restart {app}: {time.time() - t:.0f} s")
    wait_until(lambda: status(f"{MCP_BASE}/readyz") == 200, 300, "MCP /readyz after the restart", every=3)
    rep = json.loads(ssh.docker("logs", cname(WALLET, "init")).stdout.strip().splitlines()[-1])
    check("R", "init ran again: nothing to fix, every secret unchanged", rep["ok"] and all(s["result"] == "unchanged" for s in rep["secrets"]), rep)
    hot = sc("hot_address")
    tok = ssh.ssh(f"cat {APPDATA}/{WALLET}/data/run/ui/mcp-http-token").stdout.strip()
    check("R", "after apps.restart of both apps: the same MCP token, hot address and hot balance",
          tok == token_before and hot["hot_address"] == hot_before["hot_address"] and hot.get("hot_sats") == hot_before.get("hot_sats"),
          {"token_same": tok == token_before, "hot": [hot_before.get("hot_sats"), hot.get("hot_sats")]})
    phase_buy("R")


def phase_uninstall(apps=(WALLET, GATEWAY)):
    api.login(PW)
    for app in apps:
        t = time.time()
        ok = api.m("apps.uninstall", appId=app)
        left_c = ssh.docker("ps", "-aq", "--filter", f"name=^{app}_").stdout.strip()
        left_d = ssh.ssh(f"ls -d {APPDATA}/{app} 2>/dev/null; true").stdout.strip()
        check("X", f"apps.uninstall {app} ({time.time() - t:.0f} s): no container and no app data left", ok and not left_c and not left_d,
              {"containers": left_c, "data": left_d})
    imgs = ssh.docker("images", "--format", "{{.Repository}}:{{.Tag}}").stdout.split()
    log("   images left on the box after the uninstall:", imgs)
    S.setdefault("images_after_uninstall", {})[",".join(apps)] = imgs
    save_state(S)


def main():
    try:
        for p in PHASES:
            log(f"### phase {p}")
            {"stores": phase_stores, "standins": phase_standins, "apps": phase_apps, "owner": phase_owner, "buy": phase_buy,
             "restart": phase_restart, "uninstall": phase_uninstall, "rebootbuy": lambda: phase_buy("B"),
             "standins-down": lambda: phase_uninstall((LF_APP, LF_SELLER, KNOTS_APP))}[p]()
    except Exception as e:  # noqa: BLE001
        check("X", f"phase completed: {p}", False, repr(e))
    finally:
        prev = []
        try:
            prev = json.load(open(os.path.join(OUT, "results.json")))
        except FileNotFoundError:
            pass
        rl.RESULTS[:0] = prev
        ok = rl.write_results(OUT)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
