#!/usr/bin/env python3
"""AGP-100: the xbt402 Hub app beside the node app Lightning Fork uses, on regtest (run by test-umbrel-hub-node.sh).

The hub app depends on umbrelOS's `bitcoin` slot. This driver installs it the way umbrelOS does (umbrel_regtest.py
has the details: app-data copies, `<app-id>_<service>_1` names, one box network, the dependency's exports.sh
sourced under `set -euo pipefail`) beside exactly one node app, and never a second one:

  paul     Paul's `paulscode-knots-blake2b` (the app Lightning Fork's `bitcoin` dependency resolves to), from his
           store at a pinned commit, with his image at the digest his compose pins.
             W  his app as shipped (its own UI backend writes bitcoin.conf and starts bitcoind), on a network with
                no route out, so nothing of the real chain is fetched: the wallet RPCs a dependent would call;
             H  the same image on regtest, with the conf his app generated (only the chain changes), and the hub
                app beside it: /readyz, the wallet named hub, and the four RPCs with real coins.
  standin  our `lazarus-xbt-knots` (it exports only APP_XBT_KNOTS_*): the fallback.
  none     no node app: the hub must not come up, and must not report ready.

    hub_shared_node.py OUT MODE
"""
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import sys
import time

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from regtest_lib import Chain, check, docker, http, log, open_log, root_helper, sh, status, wait_until, write_results  # noqa: E402

OUT, MODE = os.path.abspath(sys.argv[1]), sys.argv[2]
HERE = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.dirname(HERE)
PID = os.getpid()
NET = f"agp100-umbrel-{PID}"
# umbrelOS's app network; Paul's apps pin static addresses in it (10.21.21.62 is his node)
SUBNET = os.environ.get("UMBREL_TEST_SUBNET", "10.21.0.0/16")
APPS_DIR = os.path.join(OUT, "app-data")
SEED = os.urandom(32).hex()
# below the host's ephemeral range (32768-60999), bound once before use
P_HUB = int(os.environ.get("UMBREL_TEST_HUB_PORT", "24020"))
HUB, KNOTS, PAUL = "lazarus-xbt402-hub", "lazarus-xbt-knots", "paulscode-knots-blake2b"
PAUL_REPO = "https://github.com/paulscode/umbrel-store.git"
PAUL_COMMIT = "5eb67a9e498f81753b9c1bc6b6f0feb50dac82dd"
SLOT = "bitcoin"
open_log(os.path.join(OUT, "hub_shared_node.log"))


def derive(label):
    """umbrelOS's derive_entropy: a per-box secret from the box seed and a label."""
    return hmac.new(SEED.encode(), label.encode(), hashlib.sha256).hexdigest()


def exports_env(apps):
    """What umbrelOS's app-script does before compose: source the exports.sh of the app's dependencies (the
    provider selected for a slot stands in for the slot), under `set -euo pipefail`, from their app-data copies."""
    script = ("set -euo pipefail\nset -a\n"
              "derive_entropy() { printf '%s' \"$1\" | openssl dgst -sha256 -hmac \"$UMBREL_SEED_HEX\" -r | cut -d' ' -f1; }\n")
    for a in apps:
        d = os.path.join(APPS_DIR, a)
        if os.path.exists(os.path.join(d, "exports.sh")):
            script += f"EXPORTS_APP_ID='{a}'\nEXPORTS_APP_DIR='{d}'\nEXPORTS_TOR_DATA_DIR='{OUT}/tor/data'\n. '{d}/exports.sh'\n"
    script += "env -0\n"
    r = sh("bash", "-c", script, env={"PATH": os.environ["PATH"], "UMBREL_SEED_HEX": SEED, "UMBREL_ROOT": OUT})
    return dict(kv.split("=", 1) for kv in r.stdout.split("\0") if "=" in kv and kv.split("=", 1)[0].startswith("APP_"))


def manifest(app):
    with open(os.path.join(APPS_DIR, app, "umbrel-app.yml")) as f:
        return yaml.safe_load(f)


def providers(app, installed):
    """umbrelOS: each dependency is the app of that id, or the installed app selected for it, which must list
    the dependency in `implements` (umbreld refuses any other selection)."""
    out = []
    for dep in manifest(app).get("dependencies") or []:
        out += [a for a in installed if a == dep or dep in (manifest(a).get("implements") or [])][:1]
    return out


def compose(app, deps, *args, overlays=(), check_rc=True):
    data = os.path.join(APPS_DIR, app)
    # nothing of this shell's APP_* reaches compose: only what the dependencies export, as on a box
    base = {k: v for k, v in os.environ.items() if not k.startswith("APP_")}
    env = {**base, **exports_env([*deps, app]), "APP_ID": app, "APP_DATA_DIR": data, "APP_SEED": derive(f"app-{app}-seed"),
           "APP_PASSWORD": derive(f"app-{app}-seed-APP_PASSWORD"), "DEVICE_DOMAIN_NAME": "umbrel.local", "DEVICE_HOSTNAME": "umbrel",
           "APP_HIDDEN_SERVICE": "not-enabled.onion", "NETWORK_IP": SUBNET.split("/")[0], "TOR_DATA_DIR": os.path.join(OUT, "tor/data"),
           "UMBREL_TEST_NET": NET, "UMBREL_TEST_CONF": HERE, "UMBREL_TEST_HUB_PORT": str(P_HUB)}
    files = [os.path.join(data, "docker-compose.yml"), os.path.join(HERE, "common.yml"), *[os.path.join(HERE, o) for o in overlays]]
    return sh("docker", "compose", "--compatibility", "-p", app, "--project-directory", data, *[x for f in files for x in ("-f", f)],
              *args, env=env, check_rc=check_rc, timeout=900)


def copy_app(app, src):
    dst = os.path.join(APPS_DIR, app)
    if not os.path.exists(dst):
        shutil.copytree(src, dst)
    return dst


def paul_store():
    """Paul's store at the pinned commit: PAUL_STORE (a checkout) or a fetch of that one commit."""
    d = os.environ.get("PAUL_STORE")
    if not d:
        d = os.path.join(OUT, "paulscode-umbrel-store")
        os.makedirs(d)
        sh("git", "init", "-q", d)
        sh("git", "-C", d, "fetch", "-q", "--depth", "1", PAUL_REPO, PAUL_COMMIT)
        sh("git", "-C", d, "checkout", "-q", "FETCH_HEAD")
    head = sh("git", "-C", d, "rev-parse", "HEAD").stdout.strip()
    if head != PAUL_COMMIT:
        raise RuntimeError(f"Paul's store is at {head}, the test is pinned to {PAUL_COMMIT}")
    return d


class Node:
    """bitcoin-cli against a node app from the box network, with the credentials a dependent app is given."""

    def __init__(self, image, host, port, user, password, chain):
        self.image, self.host, self.port, self.u, self.p, self.chain = image, host, port, user, password, chain

    def cli(self, *a, wallet=None, check_rc=True):
        args = ["run", "--rm", "--network", NET, "--entrypoint", "bitcoin-cli", self.image, f"-chain={self.chain}",
                f"-rpcconnect={self.host}", f"-rpcport={self.port}", f"-rpcuser={self.u}", f"-rpcpassword={self.p}"]
        if wallet:
            args.append(f"-rpcwallet={wallet}")
        r = docker(*args, *[str(x) for x in a], check_rc=check_rc)
        out = (r.stdout if r.returncode == 0 else r.stderr).strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out


def hub_checks(group, want_host, want_port, other_node_prefix):
    """Install the hub app beside the one node app and check what the pass line asks: ready, with no second node."""
    t0 = time.time()
    compose(HUB, providers(HUB, INSTALLED), "up", "-d", overlays=["lazarus-xbt402-hub.yml"])
    wait_until(lambda: status(f"http://127.0.0.1:{P_HUB}/readyz") == 200, 120, "hub /readyz 200")
    t_ready = time.time() - t0
    rz = json.loads(http("GET", f"http://127.0.0.1:{P_HUB}/readyz")[2])
    henv = dict(e.split("=", 1) for e in json.loads(docker("inspect", f"{HUB}_hub_1").stdout)[0]["Config"]["Env"] if "=" in e)
    check(group, f"the hub was given the node app's address ({want_host}:{want_port}) by its dependency's exports",
          henv.get("XBT_NODE_RPC_HOST") == want_host and henv.get("XBT_NODE_RPC_PORT") == str(want_port),
          {k: henv.get(k) for k in ("XBT_NODE_RPC_HOST", "XBT_NODE_RPC_PORT")})
    check(group, f"hub /readyz 200 {t_ready:.1f} s after install: node reachable and synced",
          rz["ok"] and rz["node"]["reachable"] is True and rz["node"]["synced"] is True, rz)
    w = rz.get("wallet") or {}
    check(group, "the hub created and loaded the node wallet named hub and has a receive address (createwallet, getnewaddress)",
          w.get("name") == "hub" and str(w.get("receive_address", "")).startswith("bcrt1"), w)
    names = docker("ps", "--filter", f"network={NET}", "--format", "{{.Names}}").stdout.split()
    check(group, "one node on the box: no container of the other node app exists",
          not [n for n in names if n.startswith(other_node_prefix)] and f"{HUB}_hub_1" in names, names)
    return rz


INSTALLED = []


def run_paul():
    store = paul_store()
    data = copy_app(PAUL, os.path.join(store, PAUL))
    with open(os.path.join(data, "docker-compose.yml")) as f:
        image = yaml.safe_load(f)["services"]["app"]["image"]
    check("I", "Paul's node app: his store at the pinned commit, his image pinned by digest (pulled, never built here)",
          "@sha256:" in image and manifest(PAUL).get("implements") == [SLOT], {"commit": PAUL_COMMIT, "image": image})
    INSTALLED.append(PAUL)
    copy_app(HUB, os.path.join(STORE, HUB))
    check("I", f"the hub depends on the `{SLOT}` slot, Lightning Fork's own dependency, and Paul's node app is what fills it",
          manifest(HUB)["dependencies"] == [SLOT] and providers(HUB, INSTALLED) == [PAUL]
          and yaml.safe_load(open(os.path.join(store, "paulscode-lightning-fork/umbrel-app.yml")))["dependencies"] == [SLOT],
          manifest(HUB)["dependencies"])
    ex = exports_env([PAUL])
    check("I", "his exports.sh (sourced under set -euo pipefail, as umbrelOS does) sets APP_BITCOIN_* and none of our names",
          all(ex.get(f"APP_BITCOIN_{k}") for k in ("NODE_IP", "RPC_PORT", "RPC_USER", "RPC_PASS")) and not [k for k in ex if "XBT_KNOTS" in k],
          sorted(k for k in ex if k.startswith("APP_BITCOIN_")))
    host, port, user, pw = (ex[f"APP_BITCOIN_{k}"] for k in ("NODE_IP", "RPC_PORT", "RPC_USER", "RPC_PASS"))

    # --- W: his app as shipped, with no route out ------------------------------------------------------------
    log("== W: Paul's node app as shipped (mainnet, a network with no route out): the wallet RPCs of a dependent")
    docker("network", "create", "--internal", "--subnet", SUBNET, NET)
    compose(PAUL, [], "up", "-d", "app", overlays=[f"{PAUL}.yml"])
    node = Node(image, host, port, user, pw, "main")
    wait_until(lambda: isinstance(node.cli("getblockchaininfo", check_rc=False), dict), 120, "his node's RPC")
    info = node.cli("getblockchaininfo")
    conf = open(os.path.join(data, "data/umbrel-bitcoin.conf")).read()
    keys = [ln.split("=")[0] for ln in conf.splitlines() if "=" in ln]
    check("W", "the conf his app wrote: one rpcauth user, rpcallowip for the app network, no disablewallet, no rpcwhitelist",
          info["chain"] == "main" and keys.count("rpcauth") == 1 and f"rpcallowip={SUBNET}" in conf
          and not [k for k in keys if k in ("disablewallet", "rpcwhitelist", "rpcwhitelistdefault")],
          {"blocks": info["blocks"], "rpc_keys": sorted({k for k in keys if k.startswith("rpc") or "wallet" in k})})
    made = node.cli("createwallet", "agp100", check_rc=False)
    addr = node.cli("getnewaddress", "funding", "bech32", wallet="agp100", check_rc=False)
    check("W", "createwallet and getnewaddress work for a dependent (its exported user, from the app network)",
          isinstance(made, dict) and made.get("name") == "agp100" and str(addr).startswith("bc1q"), [made, addr])
    spend = node.cli("gettxspendingprevout", json.dumps([{"txid": "00" * 31 + "01", "vout": 0}]), check_rc=False)
    check("W", "gettxspendingprevout is served", isinstance(spend, list) and spend[0].get("vout") == 0 and "spendingtxid" not in spend[0], spend)
    send = str(node.cli("sendtoaddress", addr, "0.001", wallet="agp100", check_rc=False))
    check("W", "sendtoaddress reaches the wallet: it is refused by the wallet itself (no coins, no fee estimate), not by the RPC server",
          "error code: -6" in send or "error code: -4" in send, send)
    compose(PAUL, [], "down", "--timeout", "30", overlays=[f"{PAUL}.yml"])
    docker("network", "rm", NET)

    # --- H: the same image on regtest, the hub beside it ----------------------------------------------------
    log("== H: the same node on regtest (his generated conf, the chain changed), and the hub app beside it")
    lines, changed = [], []
    for ln in conf.splitlines():
        if ln.startswith(("chain=", "blocknotify=")):
            changed.append(f"- {ln}")
        elif ln == "[main]":
            lines.append("[regtest]")
            changed.append("[main] -> [regtest]")
        else:
            lines.append(ln)
    added = ["chain=regtest", "connect=0", "fallbackfee=0.0002", "testactivationheight=blake2b@101", "blake2b_headline=agp100"]
    with open(os.path.join(data, "data/agp100-regtest.conf"), "w") as f:
        f.write("\n".join(added[:1] + lines + added[1:]) + "\n")
    docker("network", "create", "--subnet", SUBNET, NET)
    overlays = [f"{PAUL}.yml", f"{PAUL}.regtest.yml"]
    compose(PAUL, [], "up", "-d", "app", overlays=overlays)
    node = Node(image, host, port, user, pw, "regtest")
    wait_until(lambda: isinstance(node.cli("getblockchaininfo", check_rc=False), dict), 90, "his node's RPC on regtest")
    node.cli("createwallet", "faucet")
    faucet = node.cli("getnewaddress", wallet="faucet")
    node.cli("generatetoaddress", 120, faucet)
    info = node.cli("getblockchaininfo")
    check("H", "his node on regtest with his own RPC and wallet settings (conf diff in detail), past the BLAKE2b activation at 101",
          info["chain"] == "regtest" and info["blocks"] == 120 and not info["initialblockdownload"], {"removed_or_changed": changed, "added": added})
    rz = hub_checks("H", host, port, KNOTS)

    recv = rz["wallet"]["receive_address"]
    node.cli("sendtoaddress", recv, "0.01", wallet="faucet")
    node.cli("generatetoaddress", 1, faucet)
    wait_until(lambda: (json.loads(http("GET", f"http://127.0.0.1:{P_HUB}/readyz")[2]).get("wallet") or {}).get("balance_sats", 0) >= 1_000_000,
               30, "the hub's balance")
    bal = json.loads(http("GET", f"http://127.0.0.1:{P_HUB}/readyz")[2])["wallet"]
    check("H", "coins sent to the hub's receive address show as the hub's balance on /readyz (1,000,000 sat)", bal.get("balance_sats") == 1_000_000, bal)
    # the hub's own fund call (crates/xbt402/src/rpc.rs `fund`): sendtoaddress on wallet hub, then gettransaction
    to = node.cli("getnewaddress", wallet="faucet")
    txid = node.cli("sendtoaddress", to, "0.001", wallet="hub", check_rc=False)
    vin = (node.cli("gettransaction", txid, "true", "true", wallet="hub", check_rc=False) or {}).get("decoded", {}).get("vin", [{}])[0] \
        if re.fullmatch(r"[0-9a-f]{64}", str(txid)) else {}
    sp = node.cli("gettxspendingprevout", json.dumps([{"txid": vin.get("txid", ""), "vout": vin.get("vout", 0)}]), check_rc=False)
    check("H", "with the hub's credentials: sendtoaddress from wallet hub pays, and gettxspendingprevout names that payment as the spender",
          isinstance(sp, list) and sp[0].get("spendingtxid") == txid, {"txid": txid, "spender": sp})

    compose(HUB, [PAUL], "restart", overlays=["lazarus-xbt402-hub.yml"])
    wait_until(lambda: status(f"http://127.0.0.1:{P_HUB}/readyz") == 200, 120, "hub /readyz after restart")
    rz2 = json.loads(http("GET", f"http://127.0.0.1:{P_HUB}/readyz")[2])
    check("H", "hub app restart: the same payTo, the same receive address, the wallet loaded again",
          rz2["pay_to"] == rz["pay_to"] and rz2["wallet"]["receive_address"] == recv, [rz["pay_to"], rz2["pay_to"]])
    compose(PAUL, [], "stop", overlays=overlays)
    wait_until(lambda: status(f"http://127.0.0.1:{P_HUB}/readyz") == 503, 60, "readyz 503 with the node stopped")
    check("H", "node app stopped: hub /readyz 503, /healthz 200", status(f"http://127.0.0.1:{P_HUB}/healthz") == 200)
    return {"mode": MODE, "node_image": image, "paul_commit": PAUL_COMMIT, "readyz": rz2, "conf_changed": changed, "conf_added": added}


def run_standin():
    copy_app(KNOTS, os.path.join(STORE, KNOTS))
    copy_app(HUB, os.path.join(STORE, HUB))
    INSTALLED.append(KNOTS)
    docker("network", "create", NET)
    check("F", "the fallback node: lazarus-xbt-knots implements the `bitcoin` slot, so the owner can select it for the hub",
          manifest(KNOTS).get("implements") == [SLOT] and providers(HUB, INSTALLED) == [KNOTS], manifest(KNOTS).get("implements"))
    ex = exports_env([KNOTS])
    check("F", "its exports.sh sets only our names (APP_XBT_KNOTS_*): no APP_BITCOIN_* reaches the hub's compose",
          not [k for k in ex if k.startswith("APP_BITCOIN_")] and len(ex["APP_XBT_KNOTS_RPC_PASS"]) == 64, sorted(ex))
    compose(KNOTS, [], "up", "-d", overlays=[f"{KNOTS}.yml"])
    chain = Chain(f"{KNOTS}_node_1", ex["APP_XBT_KNOTS_RPC_USER"], ex["APP_XBT_KNOTS_RPC_PASS"])
    wait_until(lambda: chain.cli("getblockcount") is not None, 90, "node RPC")
    chain.cli("createwallet", "faucet")
    chain.cli("generatetoaddress", 120, chain.cli("getnewaddress", wallet="faucet"))
    rz = hub_checks("F", ex["APP_XBT_KNOTS_NODE_HOST"], ex["APP_XBT_KNOTS_RPC_PORT"], PAUL)
    return {"mode": MODE, "readyz": rz}


def run_none():
    copy_app(HUB, os.path.join(STORE, HUB))
    docker("network", "create", NET)
    up = compose(HUB, [], "up", "-d", overlays=["lazarus-xbt402-hub.yml"], check_rc=False)
    time.sleep(15)
    st = json.loads(docker("inspect", f"{HUB}_hub_1").stdout)[0]["State"]
    logs = docker("logs", f"{HUB}_hub_1", check_rc=False)
    henv = dict(e.split("=", 1) for e in json.loads(docker("inspect", f"{HUB}_hub_1").stdout)[0]["Config"]["Env"] if "=" in e)
    check("N", "no node app selected: the hub's node address is empty, not a default",
          henv.get("XBT_NODE_RPC_HOST") == "" and henv.get("XBT_NODE_RPC_PORT") == "", {k: henv.get(k) for k in ("XBT_NODE_RPC_HOST", "XBT_NODE_RPC_PORT")})
    check("N", "the hub does not run and nothing answers /readyz (it exits with the reason; it never reports ready)",
          not st["Running"] and st["ExitCode"] != 0 and status(f"http://127.0.0.1:{P_HUB}/readyz") == 0,
          {"up_rc": up.returncode, "state": {k: st[k] for k in ("Status", "ExitCode")}, "log": (logs.stdout + logs.stderr)[-400:]})
    return {"mode": MODE, "hub_exit": st["ExitCode"], "hub_log": (logs.stdout + logs.stderr)[-400:]}


def teardown():
    for app, overlays in ((HUB, ["lazarus-xbt402-hub.yml"]), (PAUL, [f"{PAUL}.yml"]), (KNOTS, [f"{KNOTS}.yml"])):
        if not os.path.exists(os.path.join(APPS_DIR, app)):
            continue
        with open(os.path.join(OUT, f"{app}.log"), "w") as f:
            r = compose(app, [], "logs", "--no-color", "--timestamps", overlays=overlays, check_rc=False)
            f.write(r.stdout + r.stderr)
        compose(app, [], "down", "--volumes", "--timeout", "10", overlays=overlays, check_rc=False)
    docker("network", "rm", NET, check_rc=False)
    if not os.environ.get("UMBREL_TEST_KEEP"):
        # uninstall: umbrelOS deletes app-data/<id>; the hub's files belong to its uid, so as root
        root_helper(OUT, "rm -rf /d/app-data /d/paulscode-umbrel-store", ro=False)
        left = docker("ps", "-aq", "--filter", f"name=^{HUB}_", "--filter", f"name=^{PAUL}_", "--filter", f"name=^{KNOTS}_").stdout.strip()
        check("X", "uninstall: every container, the network and the app data removed", not left and not os.path.exists(APPS_DIR), left)


if __name__ == "__main__":
    try:
        with socket.socket() as s:  # the one host port this test publishes, on loopback
            s.bind(("127.0.0.1", P_HUB))
        os.makedirs(APPS_DIR)
        facts = {"paul": run_paul, "standin": run_standin, "none": run_none}[MODE]()
        with open(os.path.join(OUT, "facts.json"), "w") as f:
            json.dump(facts, f, indent=1, default=str)
    except Exception as e:  # noqa: BLE001
        check("X", "the run completed", False, repr(e))
    finally:
        try:
            teardown()
        except Exception as e:  # noqa: BLE001
            check("X", "teardown", False, repr(e))
        ok = write_results(OUT)
    sys.exit(0 if ok else 1)
