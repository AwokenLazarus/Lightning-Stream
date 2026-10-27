#!/usr/bin/env python3
"""The Linux package on regtest, installed the way docs/LINUX.md says, twice on one machine:

    stand-in miner --> hashmaker install (B) ==link==> hashtaker install (A) --> A's DATUM Gateway (a stand-in pool)
                       lf2, its gateway sells slices   lf1, its wallet pays each slice
    discovery: B's signed listing on a stand-in Nostr relay on loopback

Each install is packaging/linux/install.sh --yes with the owner's answers in LS_* (the lab plays the
owner's own nodes: lf1/lf2 are their Lightning nodes, knots-b2b their XBT node, on loopback as on an
owner's machine). The admin macaroon goes to node-keys on standard input. Then, in each app's page with
no terminal: the approval key and the rules; on B the shop and Sell -> Hashrate; on A Services ->
Hashrate, one rental, paid slice by slice; then uninstall.sh, which must leave nothing behind.

    linux_regtest.py OUT      (run by packaging/linux/test-linux.sh)
Checks (results.json): I install, K the node's keys, L loopback-only ports, U the owner's pages,
H the hashrate rental, X uninstall.
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(PKG))
sys.path.insert(0, os.path.join(ROOT, "packaging"))
from ln_lab import Lab, LAB_DIR  # noqa: E402
from regtest_lib import (POLICY_BASE, Ui, check, docker, field, log, open_log, owner_setup, root_helper, sh, sign_policy,  # noqa: E402
                         status, unescape, wait_until, write_results)

OUT = os.path.abspath(sys.argv[1])
BASE = int(os.environ.get("LS_TEST_PORT_BASE", "24600"))
P = {"lf1": BASE + 50, "lf2": BASE + 51, "rpc": BASE + 52, "relay": BASE + 53, "fallback": BASE + 54, "datum": BASE + 55}
INSTALLS = {
    # name: (node, hashmaker, ui, mcp, connector, gateway, hashtaker control)
    "taker": ("lf1", False, BASE + 10, BASE + 11, BASE + 12, BASE + 13, BASE + 14),
    "maker": ("lf2", True, BASE + 20, BASE + 21, BASE + 22, BASE + 23, BASE + 24),
}
RELAYS = f"ws://127.0.0.1:{P['relay']}"
SIGN_BIN = os.path.join(ROOT, "dist/oci/ctx/bin/amd64/xbt-wallet-ui")
SHARE = 4 << 32  # a share at the stand-in pools' difficulty 4
SLICE_WORK = 10 * SHARE
PRICE_SAT = 100
IMAGES = os.environ.get("LS_TEST_IMAGES", "local-ui")  # local-ui: the tree's wallet-ui build; pinned: the lock's alone
LOCAL_UI = "xbt-wallet-ui:linux-test"


def lock_ref(name):
    for line in open(os.path.join(ROOT, "packaging/images.lock")):
        p = line.split()
        if len(p) == 2 and p[0] == name:
            return p[1]
    raise RuntimeError(f"no {name} in images.lock")


HASHLINK = lock_ref("xbt-hashlink")


def standin(name, *args):
    """A stand-in of the hashlink image on the host's network (a pool, a miner, the relay)."""
    docker("rm", "-f", name, check_rc=False)
    docker("run", "-d", "--name", name, "--network", "host", "--read-only", "--cap-drop", "ALL", "--entrypoint", "/usr/bin/xbt-hashlink",
           HASHLINK, *args)


def admin_macaroon(node, path):
    """The node's admin macaroon, as the owner has it on disk (0600)."""
    r = subprocess.run(["docker", "compose", "exec", "-T", node, "cat", "/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon"],
                       cwd=LAB_DIR, capture_output=True, check=True)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(r.stdout)
    return r.stdout


def install(name, lab):
    node, maker, ui, mcp, conn, gw, ctl = INSTALLS[name]
    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    if IMAGES == "local-ui":
        with open(os.path.join(d, "docker-compose.override.yml"), "w") as f:
            f.write(f"services:\n  ui:\n    image: {LOCAL_UI}\n  node-keys:\n    image: {LOCAL_UI}\n")
    admin = os.path.join(OUT, f"{node}-admin.macaroon")
    secret = admin_macaroon(node, admin)
    base = {k: v for k, v in os.environ.items() if not k.startswith(("COMPOSE_", "LN_TICKET_", "PKG_LAB_", "LAB", "RUN", "ACTIVATION_"))}
    env = dict(base, LS_UI_PASSWORD=f"pw-{name}-$ x", COMPOSE_PROJECT_NAME=f"lstest-{name}",
               LS_LND_REST=f"https://127.0.0.1:{P[node]}", LS_LND_TLS_CERT=os.path.join(lab.facts[f"{node}_cert_dir"], "tls.cert"),
               LS_ADMIN_MACAROON=admin, LS_BITCOIN_CONF="/nonexistent", LS_CHAIN="regtest", LS_NODE_RPC_HOST="127.0.0.1", LS_NODE_RPC_PORT=str(P["rpc"]),
               LS_NODE_RPC_USER="lab", LS_NODE_RPC_PASS="lab", LS_DATUM=f"127.0.0.1:{P['datum']}", LS_DATUM_USER="rented",
               LS_HASHMAKER="1" if maker else "0", LS_LAN_HOST="127.0.0.1", LS_UI_PORT=str(ui), LS_MCP_PORT=str(mcp),
               LS_CONNECTOR_PORT=str(conn), LS_GW_PORT=str(gw), LS_HASHTAKER_CONTROL_PORT=str(ctl), LS_RELAYS=RELAYS, LS_SKIP_PULL="1")
    t0 = time.time()
    r = subprocess.run([os.path.join(PKG, "install.sh"), "--yes", "--dir", d], env=env, capture_output=True, text=True, timeout=900)
    with open(os.path.join(OUT, f"install-{name}.log"), "w") as f:
        f.write(r.stdout + r.stderr)
    check("I", f"{name}: install.sh --yes installs and starts the app ({time.time() - t0:.0f} s)", r.returncode == 0, (r.stdout + r.stderr)[-1500:])
    check("I", f"{name}: .env is private (0600) and its password survives quoting ($ and a space)",
          oct(os.stat(os.path.join(d, ".env")).st_mode & 0o777) == "0o600" and "pw-" + name + "-$ x" in open(os.path.join(d, ".env")).read())
    envtext = open(os.path.join(d, ".env")).read()
    check("I", f"{name}: a plain value is written as it is, a password with signs in quotes, and the end says which to type",
          "\nLS_CHAIN=regtest\n" in envtext and f"\nLS_UI_PASSWORD='pw-{name}-$ x'\n" in envtext and "without the single quotes" in r.stdout, r.stdout[-600:])
    data = os.path.join(d, "data")
    keys = root_helper(data, "ls /d/run/ln /d/run/gateway 2>&1; cat /d/run/ln/auto-keys.json").stdout
    check("K", f"{name}: node-keys made the narrow keys from the admin macaroon on standard input (rail, invoices, info), each with its own root key",
          all(k in keys for k in ("rail.macaroon", "invoices.macaroon", "info.macaroon", "root_key_id")), keys[-600:])
    found = root_helper(data, f"grep -rl {secret.hex()[:48]} /d 2>/dev/null; od -An -tx1 -v -w100000 $(find /d -type f) 2>/dev/null | tr -d ' \\n' "
                              f"| grep -c {secret.hex()[:64]} || true").stdout.split()
    check("K", f"{name}: the admin macaroon is in no file of the app's data (as bytes or hex)", found in (["0"], []), found)
    return d, env


def rules_on_page(ui, path):
    """The rules a page proposes, as its "edit the rules as a file" box holds them."""
    m = re.search(r'<textarea name="json"[^>]*>(.*?)</textarea>', ui.get(path), re.S)
    return json.loads(unescape(m.group(1)))


def save_logs(installs):
    """Each service's log and the stand-ins', into OUT/logs (evidence; nothing is checked here)."""
    d = os.path.join(OUT, "logs")
    os.makedirs(d, exist_ok=True)
    for name, (idir, env) in installs.items():
        for svc in ("signer", "ui", "gateway", "hashtaker", "hashmaker", "init"):
            r = subprocess.run(["docker", "compose", "logs", "--no-color", svc], cwd=idir, env=env, capture_output=True, text=True)
            with open(os.path.join(d, f"{name}-{svc}.log"), "w") as f:
                f.write(r.stdout + r.stderr)
    for c in ("lstest-relay", "lstest-fallback", "lstest-datum", "lstest-miner"):
        r = subprocess.run(["docker", "logs", c], capture_output=True, text=True)
        with open(os.path.join(d, f"{c}.log"), "w") as f:
            f.write(r.stdout + r.stderr)


def listeners():
    out = sh("ss", "-ltnH").stdout
    return [ln.split()[3] for ln in out.splitlines() if ln.split()]


def main():
    os.makedirs(OUT, exist_ok=True)
    open_log(os.path.join(OUT, "test.log"))
    os.environ["LS_TEST_RPC_PORT"] = str(P["rpc"])
    lab = Lab(OUT, "lstest", rest_ports=(P["lf1"], P["lf2"]))
    os.environ["COMPOSE_FILE"] += ":" + os.path.join(HERE, "lab.compose.yml")
    installs = {}
    try:
        log("== the lab: the owners' own nodes (chain, lf1 -> lf2 channel)")
        f = lab.up()
        log("== the stand-ins: a Nostr relay, the hashmaker's own pool, the hashtaker's DATUM Gateway")
        standin("lstest-relay", "relay", "--listen", f"127.0.0.1:{P['relay']}")
        standin("lstest-fallback", "standin-pool", "--listen", f"127.0.0.1:{P['fallback']}", "--diff", "4", "--job-ms", "1000")
        standin("lstest-datum", "standin-pool", "--listen", f"127.0.0.1:{P['datum']}", "--diff", "4", "--job-ms", "1000",
                )

        log("== I/K: install both, from the README's one step")
        for name in INSTALLS:
            installs[name] = install(name, lab)

        log("== L: what listens beyond loopback")
        ls = listeners()
        taker_ports = [str(p) for p in INSTALLS["taker"][2:]]
        wide = [a for a in ls if a.rsplit(":", 1)[1] in taker_ports + [str(p) for p in INSTALLS["maker"][2:]] and not a.startswith("127.0.0.1")]
        check("L", "the UI, MCP, connector, gateway and hashtaker ports of both installs listen on 127.0.0.1 only", not wide, wide)
        maker_wide = sorted({a for a in ls if a.endswith((":23340", ":23341")) and not a.startswith("127.0.0.1")})
        maker_lo = sorted({a for a in ls if a.endswith((":23342", ":23344"))})
        check("L", "the hashmaker alone listens beyond loopback, on its miners' port 23340 and its link port 23341; its control and slices ports are loopback",
              len(maker_wide) == 2 and all(a.startswith("127.0.0.1") for a in maker_lo) and len(maker_lo) == 2, [maker_wide, maker_lo])

        # --- U: the owners, in their pages --------------------------------------------------------------------
        uis = {}
        for name in INSTALLS:
            d, env = installs[name]
            ui = Ui(f"http://127.0.0.1:{INSTALLS[name][2]}")
            st_bad, _ = ui.login("not the password")
            st_ok, _ = ui.login(env["LS_UI_PASSWORD"])
            check("U", f"{name}: the page refuses a wrong password and takes the one set at install", st_bad == 401 and st_ok == 303, [st_bad, st_ok])
            key = os.path.join(OUT, f"{name}-human.key")
            with open(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
                fh.write(os.urandom(32).hex())
            code = root_helper(os.path.join(d, "data"), "cat /d/signer/.run/enroll-code").stdout.strip()
            # the taker: the safe starter rules as the page offers them (the test chain's split height added);
            # the maker sells only, under the base rules
            if name == "taker":
                pol = rules_on_page(ui, "/policy?template=starter")
                pol["ln"]["split_height"] = f["split"]
                check("U", "taker: the starter rules have a hashrate task with a budget", (pol["tickets"]["tasks"].get("hashrate") or {}).get("budget_sats", 0) > 0,
                      pol["tickets"])
            else:
                pol = dict(POLICY_BASE)
            _, f1, f2 = owner_setup(ui, SIGN_BIN, key, pol, code)
            check("U", f"{name}: the owner enrols an approval key and signs the rules", "enrolled" in f1.lower() and "applied" in f2.lower(), [f1, f2])
            if "restarts" in f2:
                sh("docker", "compose", "restart", "signer", cwd=d)
            page = ui.get("/lightning")
            check("U", f"{name}: the Lightning page says the node is connected by itself (no paste)", "connected" in page.lower(), page[-400:])
            uis[name] = (ui, key)

        maker, _ = uis["maker"]
        mdir = installs["maker"][0]
        gw = INSTALLS["maker"][5]
        maker.post("/sell", "/sell", {"action": "advanced", "max_sessions": "30", "sessions_per_address": "2", "max_held_tickets": "15",
                                      "proxies": "", "network": f["network"]})
        maker.post("/sell", "/sell", {"action": "shop", "name": "Test hashmaker", "public_url": f"http://127.0.0.1:{gw}"})
        st, _, _ = maker.post("/sell-hashrate", "/sell-hashrate", {
            "action": "save", "fallback": f"127.0.0.1:{P['fallback']}", "price": str(PRICE_SAT), "rentable": "", "name": "Test miners",
            "link_public": "127.0.0.1:23341", "enabled": "1", "slice_work": str(SLICE_WORK), "grace_s": "8"})
        flash = maker.flash("/sell-hashrate")
        check("U", "maker: Sell -> Hashrate saves renting on (own pool, price, the address hashtakers use)", st == 303 and "error" not in flash.lower(), flash)
        wait_until(lambda: status(f"http://127.0.0.1:{gw}/x402/ticket/health") == 200, 120, "the maker's gateway selling", every=2)
        check("U", "maker: the gateway started from the shop the page wrote", True)
        standin("lstest-miner", "standin-miner", "--pool", "127.0.0.1:23340", "--user", "maker.m1", "--rate", "20", "--reconnect", "1")
        listed = wait_until(lambda: "Listed" in maker.get("/sell-hashrate") or None, 180, "the maker's offer listed", every=3)
        check("U", "maker: with a miner connected, the offer is on the relay", bool(listed))

        # --- H: the hashtaker rents, pays per slice ------------------------------------------------------------
        taker, _ = uis["taker"]
        page = wait_until(lambda: (lambda p: p if 'name="key"' in p else None)(taker.get("/hashrate")), 180, "the offer on the taker's Rent page", every=3)
        check("H", "taker: Services -> Hashrate shows its DATUM Gateway ready and the maker's offer", "Ready to rent" in page and "Test miners" in page,
              page[-800:])
        allow = re.search(r'href="(\./policy\?allow=[^"]+)"', page)
        check("H", "taker: the offer asks first to allow the seller to be paid (the rules list who the app may pay), Rent waits",
              bool(allow) and "<button disabled>Rent</button>" in page, page[-800:])
        applied = sign_policy(taker, SIGN_BIN, uis["taker"][1], rules_on_page(taker, unescape(allow.group(1))[1:]))
        check("H", "taker: the rules page shows the seller added, tied to its node from the signed listing, and the owner signs it",
              "applied" in applied.lower(), applied)
        page = taker.get("/hashrate")
        check("H", "taker: then Rent is on", "<button>Rent</button>" in page, page[-600:])
        settled0 = len(lab.seller_settled())
        st, _, _ = taker.post("/hashrate", "/hashrate", {"action": "rent", "key": field(page, "key"), "miners": "1", "minutes": "3", "budget": "2000"})
        flash = taker.flash("/hashrate")
        check("H", "taker: Rent starts a rental", "Renting" in flash, flash)
        ctl = INSTALLS["taker"][6]
        token = root_helper(os.path.join(installs["taker"][0], "data"), "cat /d/run/hashrate/control-token").stdout.strip()

        def rental():
            r = json.loads(sh("curl", "-s", "-H", f"Authorization: Bearer {token}", f"http://127.0.0.1:{ctl}/status").stdout)
            x = (r.get("rentals") or [{}])[0]
            live = x.get("live") or {}
            return x if int(live.get("paid") or live.get("released") or 0) >= 2 else None
        try:
            x = wait_until(rental, 240, "two slices paid", every=3)
        except RuntimeError:
            x = json.loads(sh("curl", "-s", "-H", f"Authorization: Bearer {token}", f"http://127.0.0.1:{ctl}/status").stdout)
        check("H", "taker: the rented miner's work is paid slice by slice through the wallet (2 or more slices)", isinstance(x, dict) and "rental" in x, x)
        check("H", "maker's node settled tickets for it (lf1 -> lf2)", len(lab.seller_settled()) > settled0, len(lab.seller_settled()))
        rep = docker("logs", "lstest-datum", check_rc=False)
        log("   the taker's DATUM stand-in: " + (rep.stdout + rep.stderr)[-300:].replace("\n", " | "))
        st, _, _ = taker.post("/hashrate", "/hashrate", {"action": "cut", "rental": x.get("rental", "")})
        check("H", "taker: Cut ends the rental", "Cut" in taker.flash("/hashrate"))

        save_logs(installs)

        # --- X: uninstall ----------------------------------------------------------------------------------------
        for name in INSTALLS:
            d, env = installs[name]
            r = subprocess.run([os.path.join(PKG, "uninstall.sh"), "--yes", "--keep-images", "--dir", d], env=env, capture_output=True, text=True, timeout=300)
            with open(os.path.join(OUT, f"uninstall-{name}.log"), "w") as fh:
                fh.write(r.stdout + r.stderr)
            left = docker("ps", "-a", "-q", "--filter", f"label=com.docker.compose.project=lstest-{name}").stdout.split()
            nets = docker("network", "ls", "-q", "--filter", f"label=com.docker.compose.project=lstest-{name}").stdout.split()
            vols = docker("volume", "ls", "-q", "--filter", f"label=com.docker.compose.project=lstest-{name}").stdout.split()
            check("X", f"{name}: uninstall.sh removes the containers, the data and the files, and names the root keys to revoke",
                  r.returncode == 0 and not left and not nets and not vols and not os.path.exists(d) and "deletemacaroonid" in r.stdout,
                  {"rc": r.returncode, "left": left, "nets": nets, "vols": vols, "dir": os.path.exists(d), "out": (r.stdout + r.stderr)[-600:]})
        installs.clear()
    finally:
        save_logs(installs)
        for name, (d, env) in installs.items():
            subprocess.run(["docker", "compose", "--profile", "setup", "--profile", "hashmaker", "down", "--remove-orphans"], cwd=d, env=env,
                           capture_output=True)
            if os.path.isdir(os.path.join(d, "data")):
                root_helper(os.path.join(d, "data"), "rm -rf /d/* /d/.[!.]*", ro=False)
        for c in ("lstest-relay", "lstest-fallback", "lstest-datum", "lstest-miner"):
            docker("rm", "-f", c, check_rc=False)
        lab.down()
        write_results(OUT)


if __name__ == "__main__":
    main()
