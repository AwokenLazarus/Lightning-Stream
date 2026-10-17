#!/usr/bin/env python3
"""The Umbrel apps on regtest, installed the way umbrelOS installs them (run by test-umbrel-apps.sh), and a
paid buy: the packaged wallet pays the packaged gateway with stream tickets over two Lightning Fork nodes.

umbrelOS, simulated on plain Docker (no Umbrel dev environment runs rootless here):
  * each app's data dir is a copy of its folder (umbrelOS copies the app into app-data/<app-id>), owned by the
    box user (here the host user: the bind-mount case CONTAINER.md leaves to packaging);
  * compose runs with --compatibility and the project name = the app id, so containers are <app-id>_<service>_1;
  * every app is on one shared network, the environment has ${APP_DATA_DIR}, ${APP_SEED}, ${APP_PASSWORD} and
    ${DEVICE_DOMAIN_NAME}, and each installed app's exports.sh is sourced with a derive_entropy() like umbrelOS's;
  * the apps this store depends on are played by the Lightning lab (packaging/ln_lab.py), on whose network the
    apps run: the `bitcoin` slot by its Knots BLAKE2b regtest node (APP_BITCOIN_*), Lightning Fork by lf1 for
    the wallet's box and lf2 for the gateway's (APP_LIGHTNING_FORK_*, with a copy of each node's tls.cert as the
    data dir the app mounts it from). Paul's apps themselves are not run;
  * app_proxy is this driver's reverse proxy on 127.0.0.1:24080 (X-Forwarded-*), not a container;
  * a test overlay (regtest/*.yml) publishes the test ports on loopback (24000-24099) and puts the wallet's
    signer in the gateway's network namespace, so the buyer reaches the seller on loopback (the wallet pays
    tickets over https or to its own machine only; see the overlay). Nothing else in the apps changes.

Checks (results.json): I install and layout, S hardening, U the UI (no terminal: password, key, policy, token),
P the agent's MCP surface and custody of the hot key, T the paid buy over tickets (both setup pages, the rail,
the gateway, the agent's call, what the nodes saw), R restart persistence (and a buy after it), W token rotation,
M idle memory after the buy, G /readyz gating, X uninstall.
    umbrel_regtest.py OUT RUN_INDEX
"""
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from ln_lab import Lab  # noqa: E402
from regtest_lib import (agent_and_custody, agent_rotation_attempts, leaks, POLICY_BASE, Mcp, Ui, check, docker, http, log, open_log,  # noqa: E402
                         owner_setup, paid_buy, root_helper, sh, start_proxy, status, image_of, test_compose, wait_until, write_results)

OUT, RUN = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "1"
HERE = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(STORE))
APPS_DIR = os.path.join(OUT, "app-data")
SEED = os.urandom(32).hex()
P_MCP = int(os.environ.get("UMBREL_TEST_MCP_PORT", "24010"))
P_UI = int(os.environ.get("UMBREL_TEST_UI_PORT", "24030"))
P_GW_UI = int(os.environ.get("UMBREL_TEST_GW_UI_PORT", "24031"))
P_PROXY = int(os.environ.get("UMBREL_TEST_PROXY_PORT", "24080"))
P_LF = (int(os.environ.get("UMBREL_TEST_LF1_PORT", "24050")), int(os.environ.get("UMBREL_TEST_LF2_PORT", "24051")))
SIGN_BIN = os.path.join(ROOT, "dist/oci/ctx/bin/amd64/xbt-wallet-ui")
WALLET, GATEWAY = "lazarus-xbt-agent-wallet", "lazarus-lightning-stream-gateway"
ORIGIN = "http://127.0.0.1:8402"
open_log(os.path.join(OUT, "umbrel_regtest.log"))
LAB = Lab(OUT, f"pkgumbrel{RUN}", P_LF)
NET = LAB.net


def derive(label):
    """umbrelOS's derive_entropy: a per-box secret from the box seed and a label."""
    return hmac.new(SEED.encode(), label.encode(), hashlib.sha256).hexdigest()


def app_password(app_id):
    return derive(f"app-{app_id}-password")


def exports_env(installed):
    """Source every installed app's exports.sh with derive_entropy defined, as umbrelOS does."""
    script = "set -a\nderive_entropy() { printf '%s' \"$1\" | openssl dgst -sha256 -hmac \"$UMBREL_SEED_HEX\" -r | cut -d' ' -f1; }\n"
    for a in installed:
        script += f". '{os.path.join(STORE, a, 'exports.sh')}'\n"
    script += "env -0\n"
    r = sh("bash", "-c", script, env={"PATH": os.environ["PATH"], "UMBREL_SEED_HEX": SEED})
    return dict(kv.split("=", 1) for kv in r.stdout.split("\0") if "=" in kv and kv.split("=", 1)[0].startswith("APP_"))


def dependency_exports(app):
    """What the apps of the other store export to a dependent: Paul's knots-blake2b for the `bitcoin` slot
    (here the lab's chain node) and Lightning Fork (lf1 on the wallet's box, lf2 on the gateway's)."""
    node = "lf1" if app == WALLET else "lf2"
    return {"APP_BITCOIN_NODE_IP": "knots-b2b", "APP_BITCOIN_RPC_PORT": "18443", "APP_BITCOIN_RPC_USER": "lab", "APP_BITCOIN_RPC_PASS": "lab",
            "APP_LIGHTNING_FORK_NODE_IP": node, "APP_LIGHTNING_FORK_NODE_REST_PORT": "8080",
            "APP_LIGHTNING_FORK_NODE_DATA_DIR": LAB.facts[f"{node}_cert_dir"]}


INSTALLED = []


def compose(app, *args, check_rc=True):
    data = os.path.join(APPS_DIR, app)
    env = {**os.environ, **exports_env(INSTALLED), **dependency_exports(app), "APP_DATA_DIR": data, "APP_SEED": derive(f"app-{app}-seed"),
           "APP_PASSWORD": app_password(app), "DEVICE_DOMAIN_NAME": "127.0.0.1", "DEVICE_HOSTNAME": "umbrel",
           "APP_HIDDEN_SERVICE": "", "UMBREL_TEST_NET": NET, "UMBREL_TEST_MCP_PORT": str(P_MCP), "UMBREL_TEST_UI_PORT": str(P_UI),
           "UMBREL_TEST_GW_UI_PORT": str(P_GW_UI)}
    for k in ("COMPOSE_FILE", "COMPOSE_PROJECT_NAME"):
        env.pop(k, None)
    return sh("docker", "compose", "--compatibility", "-p", app, "--project-directory", data,
              "-f", os.path.join(data, "docker-compose.yml"), "-f", os.path.join(HERE, "common.yml"), "-f", os.path.join(HERE, f"{app}.yml"),
              *args, env=env, check_rc=check_rc, timeout=900)


def install(app):
    """umbrelOS: copy the app into app-data/<id> (owned by the box user), source exports, compose up."""
    if app not in INSTALLED:
        INSTALLED.append(app)
    dst = os.path.join(APPS_DIR, app)
    if not os.path.exists(dst):
        shutil.copytree(os.path.join(STORE, app), dst)
        test_compose(os.path.join(dst, "docker-compose.yml"))
    compose(app, "up", "-d")


def cname(app, svc):
    return f"{app}_{svc}_1"


def inspect(*names):
    return json.loads(docker("inspect", *names).stdout)


def mcp_token_from_ui(ui):
    page = ui.get("/agents")
    m = re.search(r'<code id="mcp-token">([0-9a-f]{64})</code>', page)
    return (m.group(1) if m else None), page


def gateway_up():
    return inspect(cname(GATEWAY, "gateway"))[0]["State"].get("Health", {}).get("Status") == "healthy" or docker(
        "exec", cname(GATEWAY, "gateway"), "/usr/bin/xbt-supervise", "probe", "http://127.0.0.1:8402/x402/ticket/health", check_rc=False).returncode == 0


def first_run(base, password):
    ui = Ui(base)
    st, _ = ui.login(password)
    return ui if st == 303 else None


def main():
    t_install = time.time()
    os.makedirs(APPS_DIR, exist_ok=True)

    log("== the Lightning lab: a Knots BLAKE2b regtest, lf1 (the buyer's box) and lf2 (the seller's), one channel")
    facts = LAB.up()
    chain = LAB
    chain.cli("-named", "createwallet", "wallet_name=agent", "disable_private_keys=true", "blank=true", "descriptors=true")

    # --- the gateway app ------------------------------------------------------------------------------------
    log("== install lazarus-lightning-stream-gateway (no config yet: the gateway waits for its page)")
    install(GATEWAY)
    gdata = os.path.join(APPS_DIR, GATEWAY, "data")
    ginit = inspect(cname(GATEWAY, "init"))[0]
    grep = json.loads(docker("logs", cname(GATEWAY, "init")).stdout.strip().splitlines()[-1])
    check("I", "gateway app: init ran first and exited 0, the UI password provisioned, no MCP token, no node credentials",
          ginit["State"]["ExitCode"] == 0 and grep["ok"] and {(s["component"], s["name"]) for s in grep["secrets"]} == {("ui", "xbt-ui-password")},
          grep)
    ls = root_helper(gdata, "stat -c '%u:%g %a %n' /d/gateway /d/ui /d/run/ui /d/run/gateway").stdout.split("\n")
    check("I", "gateway app: the bind mount has the gateway's owners: its state 10007, the setup dir owned by the UI with the gateway's group",
          [x for x in ls if x] == ["10007:10007 700 /d/gateway", "10005:10005 700 /d/ui", "10005:10005 750 /d/run/ui", "10005:10007 750 /d/run/gateway"], ls)
    time.sleep(5)
    glog = docker("logs", cname(GATEWAY, "gateway")).stderr + docker("logs", cname(GATEWAY, "gateway")).stdout
    check("I", "gateway app: with no config the gateway is not started; its supervisor waits for the file the page writes",
          "waiting for /data/run/gateway/config.json" in glog and inspect(cname(GATEWAY, "gateway"))[0]["State"]["Running"], glog[-300:])
    gi = inspect(cname(GATEWAY, "gateway"), cname(GATEWAY, "ui"))
    mounts = [m["Source"] for m in gi[0]["Mounts"]] + [m["Source"] for m in gi[1]["Mounts"]]
    check("S", "gateway app: gateway and UI non-root, read-only, cap_drop ALL; of the Lightning node's data only tls.cert is mounted, read-only",
          all(i["Config"]["User"] not in ("", "0", "root") and i["HostConfig"]["ReadonlyRootfs"] and i["HostConfig"]["CapDrop"] == ["ALL"] for i in gi)
          and not any("macaroon" in m for m in mounts)
          and all(m["RW"] is False for i in gi for m in i["Mounts"] if m["Source"].endswith("tls.cert"))
          and sum(m.endswith("tls.cert") for m in mounts) == 2,
          [(i["Name"], i["Config"]["User"], [(m["Source"], m["RW"]) for m in i["Mounts"]]) for i in gi])
    wait_until(lambda: status(f"http://127.0.0.1:{P_GW_UI}/readyz") == 200, 60, "the gateway UI")
    gui = first_run(f"http://127.0.0.1:{P_GW_UI}", app_password(GATEWAY))
    check("U", "gateway UI: login with ${APP_PASSWORD}; one page, the gateway's, and no wallet pages", gui is not None
          and "Lightning Stream Gateway" in gui.get("/") and gui.req("GET", "/policy")[0] == 404)

    # --- the wallet app ---------------------------------------------------------------------------------------
    log("== install lazarus-xbt-agent-wallet")
    t_wallet = time.time()
    install(WALLET)
    wdata = os.path.join(APPS_DIR, WALLET, "data")
    init_c = inspect(cname(WALLET, "init"))[0]
    rep = json.loads(docker("logs", cname(WALLET, "init")).stdout.strip().splitlines()[-1])
    check("I", "wallet app: init (xbt-init) ran first and exited 0: the layout check passed, secrets provisioned (names only in its report)",
          init_c["State"]["ExitCode"] == 0 and rep["ok"] and {(s["component"], s["name"]) for s in rep["secrets"]} >= {
              ("signer", "node-rpc-auth"), ("ui", "xbt-ui-password"), ("ui", "run/ui/mcp-http-token")}
          and app_password(WALLET) not in json.dumps(rep), {"exit": init_c["State"]["ExitCode"], "report": rep})
    ls = root_helper(wdata, "stat -c '%u:%g %a %n' /d/signer /d/witness /d/mcp /d/ui /d/run/signer /d/run/anchor /d/signer/secrets/node-rpc-auth "
                            "/d/ui/secrets/xbt-ui-password /d/run/ui /d/run/ui/mcp-http-token /d/run/ln").stdout.split("\n")
    want = ["10001:10001 700 /d/signer", "10002:10002 700 /d/witness", "10003:10003 700 /d/mcp", "10005:10005 700 /d/ui",
            "10001:10001 750 /d/run/signer", "10002:10002 750 /d/run/anchor", "10001:10001 600 /d/signer/secrets/node-rpc-auth",
            "10005:10005 600 /d/ui/secrets/xbt-ui-password", "10005:10005 750 /d/run/ui", "10005:10005 640 /d/run/ui/mcp-http-token",
            "10005:10008 750 /d/run/ln"]
    check("I", "the bind mount (app-data copied as the box user) now has CONTAINER.md's owners; run/ln is the UI's with the rail group (signer, UI)",
          [x for x in ls if x] == want, ls)
    try:
        os.listdir(os.path.join(wdata, "signer"))
        box_user_reads = True
    except PermissionError:
        box_user_reads = False
    check("I", "the box user can no longer read the signer's directory", not box_user_reads)

    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200 and status(f"http://127.0.0.1:{P_UI}/readyz") == 200, 180,
               "MCP and UI /readyz 200")
    t_ready = time.time() - t_wallet
    check("I", f"wallet ready (MCP and UI /readyz 200) {t_ready:.1f} s after install", True, t_ready)
    for s in ("witness", "signer", "mcp", "ui"):
        wait_until(lambda: inspect(cname(WALLET, s))[0]["State"].get("Health", {}).get("Status") == "healthy", 120, f"{s} healthy", every=2)
    ins = inspect(*[cname(WALLET, s) for s in ("witness", "signer", "mcp", "ui")])
    rows = [(i["Name"], i["Config"]["User"], i["HostConfig"]["ReadonlyRootfs"], i["HostConfig"]["CapDrop"], i["HostConfig"]["SecurityOpt"],
             i["HostConfig"]["NetworkMode"], i["State"]["Health"]["Status"]) for i in ins]
    check("S", "witness, signer, MCP, UI: each its own non-root user, read-only, cap_drop ALL, no-new-privileges, HEALTHCHECK healthy",
          all(r[1] not in ("", "0", "root") and r[2] and r[3] == ["ALL"] and any("no-new-privileges" in x for x in r[4] or []) and r[6] == "healthy"
              for r in rows) and len({r[1] for r in rows}) == 4, rows)
    caps = sorted(c.removeprefix("CAP_") for c in init_c["HostConfig"]["CapAdd"] or [])
    check("S", "the witness has no network; init had none and only CHOWN, FOWNER, DAC_OVERRIDE, as root",
          ins[0]["HostConfig"]["NetworkMode"] == "none" and init_c["HostConfig"]["NetworkMode"] == "none"
          and caps == ["CHOWN", "DAC_OVERRIDE", "FOWNER"] and init_c["HostConfig"]["CapDrop"] == ["ALL"] and init_c["Config"]["User"] in ("0:0", "0"),
          {"witness": ins[0]["HostConfig"]["NetworkMode"], "init": [init_c["HostConfig"]["NetworkMode"], init_c["HostConfig"]["CapAdd"]]})
    mcp_mounts = [m["Source"] for m in ins[2]["Mounts"]]
    check("S", "the MCP mounts neither run/ln (the rail macaroon) nor the Lightning node's certificate; the signer and UI mount only tls.cert of it, read-only",
          not any(m.endswith("/run/ln") or m.endswith("tls.cert") for m in mcp_mounts)
          and all(m["RW"] is False for i in (ins[1], ins[3]) for m in i["Mounts"] if m["Source"].endswith("tls.cert")), mcp_mounts)
    code, _, _ = http("POST", f"http://127.0.0.1:{P_MCP}/mcp", b"{}", {"Content-Type": "application/json"})
    check("S", "the MCP refuses a request without the bearer token (401)", code == 401, code)

    # --- U: the owner, in the UI, through the app_proxy stand-in ----------------------------------------------
    log("== U: the owner's first run in the UI (no terminal)")
    proxy = start_proxy(P_PROXY, P_UI, {"X-Forwarded-Proto": "http", "X-Forwarded-Host": "umbrel.local"})
    base = f"http://127.0.0.1:{P_PROXY}"
    check("U", "through the proxy: UI /healthz 200 and /readyz 200 (the signer answers)",
          status(base + "/healthz") == 200 and status(base + "/readyz") == 200)
    ui = Ui(base)
    st, loc = ui.login("not the password")
    st_ok, loc_ok = ui.login(app_password(WALLET))
    check("U", "login: a wrong password is refused, ${APP_PASSWORD} (the dashboard's password) is accepted",
          st == 401 and st_ok == 303 and ui.cookie.startswith("xbtui="), [st, st_ok, loc_ok])
    sec = Ui(f"http://127.0.0.1:{P_UI}", headers={"X-Forwarded-Proto": "https"})
    sec.login(app_password(WALLET))
    check("U", "behind an https proxy the session cookie is Secure; HttpOnly and SameSite=Strict always",
          "Secure" in sec.last_set_cookie and "HttpOnly" in sec.last_set_cookie and "SameSite=Strict" in sec.last_set_cookie
          and "Secure" not in ui.last_set_cookie, [sec.last_set_cookie, ui.last_set_cookie])
    key = os.path.join(OUT, "device-human.key")
    with open(key, "w") as f:
        f.write(os.urandom(32).hex())
    os.chmod(key, 0o600)
    policy = dict(POLICY_BASE, allowlist=[chain.faucet])
    code = root_helper(wdata, "cat /d/signer/.run/enroll-code").stdout.strip()
    pub, f_enrol, f_apply = owner_setup(ui, SIGN_BIN, key, policy, code)
    check("U", "the owner enrols an approval key and signs a policy in the UI (allowlist: one address)",
          "enrolled" in f_enrol.lower() and "applied" in f_apply.lower(), [f_enrol, f_apply])
    if "restarts" in f_apply:
        log("   the policy asks for a signer restart: restart the app's signer (Umbrel: restart the app)")
        compose(WALLET, "restart", "signer")
        wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 120, "MCP ready after the signer restart")
    page = ui.get("/lightning")
    check("U", "the Lightning page shows the node's REST address and the pinned certificate the platform gave, and asks only for the macaroon",
          "https://lf1:8080" in page and "SHA-256" in page and 'name="macaroon"' in page and "not ready" in page, page[-600:])
    token, agents = mcp_token_from_ui(ui)
    disk_token = root_helper(wdata, "cat /d/run/ui/mcp-http-token").stdout.strip()
    check("U", "the Agents page gives the owner the MCP endpoint and the token the MCP server uses",
          token == disk_token and "http://127.0.0.1:33510/mcp" in agents, {"page_has_token": bool(token)})

    # --- P: the agent's surface and custody of the hot key ---------------------------------------------------
    log("== P: the agent's MCP with the token from the Agents page; the hot key funded, counted and swept by the owner")
    sc = lambda m, p=None: json.loads(docker("exec", cname(WALLET, "signer"), "/usr/bin/xbt-signer", "call", m, json.dumps(p or {})).stdout)  # noqa: E731
    agent = Mcp(f"http://127.0.0.1:{P_MCP}", token)
    code, init = agent.start()
    check("P", "MCP initialize over HTTP with the token", code == 200 and isinstance(init, dict) and init.get("result", {}).get("serverInfo"), init)
    before = agent_and_custody("P", agent, ui, SIGN_BIN, key, chain, sc, tools="package")

    # --- T: the paid buy -------------------------------------------------------------------------------------
    log("== T: the owner sets up both apps on their pages; the agent buys from the gateway over stream tickets")
    bought = paid_buy("T", agent, ui, gui, SIGN_BIN, key, LAB, sc, gateway_up, ORIGIN)
    rail_files = root_helper(wdata, "stat -c '%u:%g %a %n' /d/run/ln/rail.macaroon").stdout.strip()
    gw_files = root_helper(gdata, "stat -c '%u:%g %a %n' /d/run/gateway/config.json /d/run/gateway/invoices.macaroon /d/run/gateway/info.macaroon").stdout.split("\n")
    check("T", "on disk: the rail macaroon 10005:10008 0640 (the signer reads it by group, the MCP cannot); the gateway's files 10005:10007 0640",
          rail_files == "10005:10008 640 /d/run/ln/rail.macaroon"
          and [x for x in gw_files if x] == [f"10005:10007 640 /d/run/gateway/{n}" for n in ("config.json", "invoices.macaroon", "info.macaroon")],
          [rail_files, gw_files])
    mcp_mounts = [m["Destination"] for m in inspect(cname(WALLET, "mcp"))[0]["Mounts"]]
    check("T", "the agent's MCP container has no view of the rail macaroon (run/ln is not mounted there)", "/data/run/ln" not in mcp_mounts, mcp_mounts)

    # --- M: idle memory after the buy (the pass lines are packaging/README.md's) ------------------------------
    time.sleep(60)
    names = [cname(WALLET, x) for x in ("witness", "signer", "mcp", "ui")] + [cname(GATEWAY, x) for x in ("gateway", "ui")]
    out = docker("stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}", *names).stdout.split("\n")
    units = {"B": 1 / 2**20, "KiB": 1 / 1024, "kB": 1 / 1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024}

    def mib(v):
        num = re.match(r"([0-9.]+)\s*([A-Za-z]+)", v)
        return float(num.group(1)) * units.get(num.group(2), 1) if num else 0.0
    mem = {ln.split()[0]: round(mib(ln.split(" ", 1)[1].split("/")[0].strip()), 2) for ln in out if ln.strip()}
    w = round(sum(v for k, v in mem.items() if k.startswith(WALLET)), 2)
    g = round(sum(v for k, v in mem.items() if k.startswith(GATEWAY)), 2)
    with open(os.path.join(OUT, "memory.json"), "w") as f:
        json.dump({"method": "docker stats --no-stream, 60 s after the paid buy", "mib": mem, "wallet_mib": w, "gateway_mib": g}, f, indent=1)
    check("M", f"idle memory 60 s after the buy: the wallet app {w} MiB (pass line 64), the gateway app {g} MiB (pass line 32)", w <= 64 and g <= 32, mem)

    # --- R: restart the app (umbrelOS: stop + start, or a reboot) -----------------------------------------------
    log("== R: restart the wallet app")
    time.sleep(6)  # one anchor interval
    compose(WALLET, "stop")
    compose(WALLET, "up", "-d")
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 180, "MCP /readyz after the restart")
    rep2 = json.loads(docker("logs", cname(WALLET, "init")).stdout.strip().splitlines()[-1])
    check("R", "init ran again: nothing to fix, every secret unchanged (the MCP token and the generated keys are never rewritten)",
          rep2["ok"] and all(s["result"] == "unchanged" for s in rep2["secrets"]) and all(d["chowned"] == 0 for d in rep2["dirs"]), rep2)
    ui2 = Ui(base)
    ui2.login(app_password(WALLET))
    token2, _ = mcp_token_from_ui(ui2)
    agent = Mcp(f"http://127.0.0.1:{P_MCP}", token2)
    agent.start()
    ha2 = sc("hot_address")
    check("R", "after the restart: the same token and hot address, and the hot key's coins as they were left",
          token2 == token and ha2["hot_address"] == before["hot_address"] and ha2.get("hot_sats") == before["hot_sats"]
          and agent.tool("balance").get("hot", {}).get("hot_sats") == before["hot_sats"],
          {"token": token2 == token, "hot": [before, ha2]})
    wait_until(lambda: sc("ln_status").get("ready") is True, 120, "the rail ready after the restart", every=3)
    r = agent.tool("xbt402_pay", url=f"{ORIGIN}/small.txt", max_sats=10)
    check("R", "after the restart the rail is ready again from the stored macaroon and the agent buys the page again",
          r.get("verdict") == "allow" and r.get("rail") == "ticket" and r.get("status") == 200,
          {k: r.get(k) for k in ("verdict", "rail", "status", "tickets_released", "balance_msat", "reason")})

    log("== W: rotate the agent token in the UI (no restart); an agent cannot rotate it")
    mcp_base = f"http://127.0.0.1:{P_MCP}"
    tries = agent_rotation_attempts(mcp_base, [token])
    unchanged = root_helper(wdata, "cat /d/run/ui/mcp-http-token").stdout.strip() == token
    check("W", "an agent holding the token (and the old owner header) cannot rotate it: the MCP has no rotation endpoint",
          all(st in (401, 404, 405) for _, st, _, _ in tries) and unchanged, [(w, st) for w, st, _, _ in tries])
    agent_old = Mcp(mcp_base, token)
    agent_old.start()
    ui2.post("/agents", "/rotate-token", {"confirm": "1"})
    flash_rot = ui2.flash("/agents")
    new_token, _ = mcp_token_from_ui(ui2)
    st_old = Mcp(mcp_base, token).start()[0]
    st_old_session = agent_old.post({"jsonrpc": "2.0", "id": 99, "method": "tools/list"})[0]
    disk = root_helper(wdata, "stat -c '%u:%g %a' /d/run/ui/mcp-http-token; cat /d/run/ui/mcp-http-token; "
                              "ls -A /d/run/ui; ls /d/mcp/secrets /d/ui/secrets").stdout.split("\n")
    agent_new = Mcp(mcp_base, new_token or "")
    st_new = agent_new.start()[0]
    check("W", "Agents page rotate: the old token gets 401 at once (its open session too), the new one works, no restart; "
               "the UI's file is replaced atomically, 10005:10005 0640, no temp file, no stale copies",
          "rotated" in flash_rot.lower() and new_token and new_token != token and st_old == 401 and st_old_session == 401 and st_new == 200
          and disk[:3] == ["10005:10005 640", new_token, "mcp-http-token"] and "mcp-http-token" not in "\n".join(disk[3:]),
          {"flash": flash_rot, "old": st_old, "old_session": st_old_session, "new": st_new, "disk": [d if d != new_token else "<token>" for d in disk]})
    seen = agent_rotation_attempts(mcp_base, [token, new_token or ""])
    seen.append(("tools/list", *http("POST", agent_new.url, json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}).encode(),
                                     {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                      "Authorization": f"Bearer {new_token}", "Mcp-Session-Id": agent_new.sid or ""})))
    for p in ("/healthz", "/readyz"):
        seen.append((p, *http("GET", mcp_base + p)))
    check("W", "after the rotation no MCP response (headers or body) carries the new token, and the file still holds it",
          not leaks(seen, new_token) and all(st in (401, 404, 405) for _, st, _, _ in seen[:8])
          and root_helper(wdata, "cat /d/run/ui/mcp-http-token").stdout.strip() == new_token,
          {"leaks": leaks(seen, new_token), "statuses": [(w, st) for w, st, _, _ in seen]})
    time.sleep(6)
    wc = docker("run", "--rm", "--user", "0", "--network", "none", "-v", f"{wdata}/witness:/data/witness:ro", "-v", f"{wdata}/signer:/data/signer:ro",
                image_of("xbt-anchor-witness"), "check", "--store", "/data/witness", "--log", "/data/signer/.run/signatures.jsonl", check_rc=False)
    check("R", "auditor: the witness's check of the signer's signature log passes", wc.returncode == 0, wc.stdout + wc.stderr)

    # --- G: readiness follows the node ------------------------------------------------------------------------
    log("== G: /readyz follows the XBT node")
    LAB.lab.dc("stop", "knots-b2b")
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 503, 90, "readyz 503 with the node stopped")
    check("G", "XBT node stopped: MCP /readyz 503, /healthz 200", status(f"http://127.0.0.1:{P_MCP}/healthz") == 200)
    LAB.lab.dc("start", "knots-b2b")
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 120, "readyz 200 with the node back")
    check("G", "XBT node back: MCP /readyz 200", True)
    proxy.shutdown()
    with open(os.path.join(OUT, "facts.json"), "w") as f:
        json.dump({"run": RUN, "t_wallet_ready_s": t_ready, "t_total_s": time.time() - t_install, "custody": before, "bought": bought,
                   "init_first": rep, "init_restart": rep2, "lab": {k: v for k, v in facts.items() if "macaroon" not in k}}, f, indent=1, default=str)


def teardown():
    for app in reversed(INSTALLED):
        with open(os.path.join(OUT, f"{app}.log"), "w") as f:
            r = compose(app, "logs", "--no-color", "--timestamps", check_rc=False)
            f.write(r.stdout + r.stderr)
    # the wallet first: its signer lives in the gateway's network namespace
    for app in [WALLET, GATEWAY]:
        if app in INSTALLED:
            compose(app, "down", "--volumes", "--timeout", "10", check_rc=False)
    LAB.down()
    if not os.environ.get("UMBREL_TEST_KEEP"):
        # uninstall: umbrelOS deletes app-data/<id>; the files belong to the service uids, so as root
        root_helper(OUT, "rm -rf /d/app-data /d/lab", ro=False)
        check("X", "uninstall: every container, the lab and the app data removed",
              not docker("ps", "-aq", "--filter", f"name=^{WALLET}_").stdout.strip()
              and not docker("ps", "-aq", "--filter", f"name=^{GATEWAY}_").stdout.strip()
              and not os.path.exists(APPS_DIR))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        check("X", "the run completed", False, repr(e))
    finally:
        try:
            teardown()
        except Exception as e:  # noqa: BLE001
            check("X", "teardown", False, repr(e))
        ok = write_results(OUT)
    sys.exit(0 if ok else 1)
