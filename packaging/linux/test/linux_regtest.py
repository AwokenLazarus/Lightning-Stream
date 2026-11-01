#!/usr/bin/env python3
"""The Linux package on regtest, installed the way docs/LINUX.md says, twice on one machine:

    stratum-grind --> hashmaker install (B) ==link==> hashtaker install (A) --> A's Stream Gateway --> knots-b2b
                      lf2, its gateway sells slices   lf1, its wallet pays each slice   (masked, solo)
    discovery: B's signed listing on a stand-in Nostr relay on loopback

Each install is packaging/linux/install.sh --yes with the owner's answers in LS_* (the lab plays the
owner's own nodes: lf1/lf2 are their Lightning nodes, knots-b2b their XBT node, on loopback as on an
owner's machine). B is first installed from the last package before the Stream Gateway (0.1), with its
own stock DATUM gateway, and then updated by this one; A is a first install. The admin macaroon goes to
node-keys on standard input. Then, in each app's page with no terminal: the approval key and the rules;
on B the shop and Sell -> Hashrate; each install's Stream Gateway shown masked to its own hashtaker; on
A Services -> Hashrate, one rental of real work on masked solo jobs, paid slice by slice, whose blocks pay
the solo address; then A switched to its owner's own stock DATUM gateway, where renting is refused in
words; then uninstall.sh, which must leave nothing behind.

The Stream Gateway is set up as the owner does it: init makes run/datum/ (0750 10005:10021), the node
login rpc.cookie (0600 10021, "user:password", no newline) and datum/submitblocks/ (0700 10021), and the
Hashrate page's "Your gateway" (solo) writes config.json (0640 10005:10021, no secret), all checked. The
one change the test makes is the gateway's share difficulty floor (vardiff_min 1, as the p2p_hash regtest's
real gateway), so a CPU miner finds shares. LS_TEST_INIT_DATUM=0 plays init's part, for an init without
the "datum" component. The gateway's image is LS_TEST_DATUM_IMAGE (default the compose file's own,
xbt-datum-gateway:0.1.0, as oci_build.sh --load tags it); its id is in the results.

    linux_regtest.py OUT      (run by packaging/linux/test-linux.sh)
Checks (results.json): I install, G the update from 0.1, K the node's keys, L loopback-only ports, U the
owner's pages, M the Stream Gateway's masked jobs, H the hashrate rental, O the owner's own stock
gateway, X uninstall.
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
P = {"lf1": BASE + 50, "lf2": BASE + 51, "rpc": BASE + 52, "relay": BASE + 53, "fallback": BASE + 54, "own": BASE + 56, "own_api": BASE + 57}
INSTALLS = {
    # name: (node, hashmaker, ui, mcp, connector, gateway, hashtaker control, files, Stream Gateway API)
    "taker": ("lf1", False, BASE + 10, BASE + 11, BASE + 12, BASE + 13, BASE + 14, BASE + 15, BASE + 16),
    "maker": ("lf2", True, BASE + 20, BASE + 21, BASE + 22, BASE + 23, BASE + 24, BASE + 25, BASE + 26),
}
STRATUM = 23339  # the Stream Gateway's stratum, the same on every install (the UI writes it); one gateway at a time has a config here
DATUM_UID, UI_UID = 10021, 10005
INIT_DATUM = os.environ.get("LS_TEST_INIT_DATUM", "1") == "1"  # the init in the images makes run/datum and the cookie
DATUM_IMAGE = os.environ.get("LS_TEST_DATUM_IMAGE", "xbt-datum-gateway:0.1.0")
LOCAL = {"init": "xbt-init:linux-test", "hashtaker": "xbt-hashlink:linux-test", "hashmaker": "xbt-hashlink:linux-test", "datum": DATUM_IMAGE}
OWN_GW = "xbt-datum-gateway:linux-test-stock"
HG = os.environ.get("P2P_HASH_GATEWAYS", os.path.expanduser("~/xbt-rnd/hash-gateways"))  # stratum-grind, a CPU miner of real shares
RELAYS = f"ws://127.0.0.1:{P['relay']}"
SIGN_BIN = next((b for b in (os.path.join(ROOT, "dist/oci/ctx/bin/amd64/xbt-wallet-ui"),
                              os.path.join(ROOT, os.environ.get("CARGO_TARGET_DIR", "target"), "x86_64-unknown-linux-musl/release/xbt-wallet-ui"))
                 if os.path.exists(b)), os.path.join(ROOT, "dist/oci/ctx/bin/amd64/xbt-wallet-ui"))
SLICE_WORK = 2 << 32  # two shares at the gateway's difficulty 1 (vardiff_min 1, as the p2p_hash regtest's real gateway)
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


# The 0.1 package an owner updates from: rel/0119 (12b8182c), the last whose pinned images start. rel/0120's
# Linux compose lists the stream-relay and vpn components, but pins an init (12b8182c) that refuses them
# ("unknown component stream-relay"), so as pinned it does not start; this tree's does with the test's init.
OLD_REF = os.environ.get("LS_TEST_OLD_REF", "12b8182c0bf6")


def old_package():
    """The 0.1 package (OLD_REF's packaging/linux), unpacked into OUT/old-package."""
    ref = sh("git", "-C", ROOT, "rev-parse", OLD_REF).stdout.strip()
    d = os.path.join(OUT, "old-package")
    os.makedirs(d, exist_ok=True)
    subprocess.run(f"git -C {ROOT} archive {ref} packaging/linux | tar -x -C {d}", shell=True, check=True)
    return os.path.join(d, "packaging", "linux"), ref


def override(d):
    """The test's images (build_images.sh): this tree's init, UI and hashlink (the pinned init refuses the components
    this compose lists), the Stream Gateway's stand-in; and, while the init doesn't know the "datum" component, init
    without it (this test then makes run/datum, see datum_files)."""
    svc = dict(LOCAL)
    if IMAGES == "local-ui":
        svc.update(ui=LOCAL_UI, **{"node-keys": LOCAL_UI})
    text = "services:\n"
    for k, v in svc.items():
        text += f"  {k}:\n    image: {v}\n"
        if k == "init" and not INIT_DATUM:
            text += "    environment:\n      XBT_INIT_COMPONENTS: signer,witness,mcp,ui,gateway,hashrate,stream-relay,vpn\n"
    with open(os.path.join(d, "docker-compose.override.yml"), "w") as f:
        f.write(text)


def install(name, lab, package=PKG, extra=None):
    node, maker, ui, mcp, conn, gw, ctl, files, api = INSTALLS[name]
    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    if package == PKG:
        override(d)
    admin = os.path.join(OUT, f"{node}-admin.macaroon")
    secret = admin_macaroon(node, admin)
    base = {k: v for k, v in os.environ.items() if not k.startswith(("COMPOSE_", "LN_TICKET_", "PKG_LAB_", "LAB", "RUN", "ACTIVATION_"))}
    env = dict(base, LS_UI_PASSWORD=f"pw-{name}-$ x", COMPOSE_PROJECT_NAME=f"lstest-{name}",
               LS_LND_REST=f"https://127.0.0.1:{P[node]}", LS_LND_TLS_CERT=os.path.join(lab.facts[f"{node}_cert_dir"], "tls.cert"),
               LS_ADMIN_MACAROON=admin, LS_BITCOIN_CONF="/nonexistent", LS_CHAIN="regtest", LS_NODE_RPC_HOST="127.0.0.1", LS_NODE_RPC_PORT=str(P["rpc"]),
               LS_NODE_RPC_USER="lab", LS_NODE_RPC_PASS="lab", LS_DATUM_USER="rented",
               LS_HASHMAKER="1" if maker else "0", LS_LAN_HOST="127.0.0.1", LS_UI_PORT=str(ui), LS_MCP_PORT=str(mcp),
               LS_CONNECTOR_PORT=str(conn), LS_GW_PORT=str(gw), LS_HASHTAKER_CONTROL_PORT=str(ctl), LS_FILES_PORT=str(files),
               LS_DATUM_API_PORT=str(api), LS_RELAYS=RELAYS, LS_SKIP_PULL="1" if package == PKG else "0", **(extra or {}))
    t0 = time.time()
    r = subprocess.run([os.path.join(package, "install.sh"), "--yes", "--dir", d], env=env, capture_output=True, text=True, timeout=900)
    with open(os.path.join(OUT, f"install-{name}{'-0.1' if package != PKG else ''}.log"), "w") as f:
        f.write(r.stdout + r.stderr)
    check("I", f"{name}: install.sh --yes {'of the 0.1 package ' if package != PKG else ''}installs and starts the app ({time.time() - t0:.0f} s)",
          r.returncode == 0, (r.stdout + r.stderr)[-1500:])
    if package == PKG:
        check("I", f"{name}: its Files folder is served on its own port ({files}), nothing said about it",
              "Files folder" not in r.stdout + r.stderr and f"LS_FILES_PORT={files}\n" in open(os.path.join(d, ".env")).read(), (r.stdout + r.stderr)[-600:])
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
    if package == PKG:
        datum_files(name, d)
    return d, env


def update(name, d, old_env):
    """The owner updates a 0.1 install: `git pull`, then install.sh again, with the answers in .env (the test's ports
    for the Stream Gateway's API given, as two installs share this machine)."""
    before = env_file(d)
    # what a 0.1 owner's page saved when they set their own gateway there (no "chosen": 0.1 had no such word)
    root_helper(os.path.join(d, "data"), f"printf '%s' '{json.dumps({'datum': before.get('LS_DATUM')})}' > /d/hashrate/renter.json "
                                         "&& chown 10010:10010 /d/hashrate/renter.json && chmod 600 /d/hashrate/renter.json", ro=False)
    override(d)
    base = {k: v for k, v in os.environ.items() if not k.startswith(("COMPOSE_", "LN_TICKET_", "PKG_LAB_", "LAB", "RUN", "ACTIVATION_", "LS_"))}
    # settings this version adds, given as an owner gives them to an unattended update: the test's ports
    env = dict(base, LS_SKIP_PULL="1", LS_DATUM_API_PORT=str(INSTALLS[name][8]), LS_FILES_PORT=str(INSTALLS[name][7]))
    t0 = time.time()
    r = subprocess.run([os.path.join(PKG, "install.sh"), "--yes", "--dir", d], env=env, capture_output=True, text=True, timeout=900)
    out = r.stdout + r.stderr
    with open(os.path.join(OUT, f"install-{name}-update.log"), "w") as f:
        f.write(out)
    after = env_file(d)
    check("G", f"{name}: install.sh --yes over the 0.1 install updates and starts it ({time.time() - t0:.0f} s)", r.returncode == 0, out[-1500:])
    lost = {k: v for k, v in before.items() if k != "LS_DATUM" and after.get(k) != v}
    check("G", f"{name}: every setting of the 0.1 install is kept (password, ports, node, hashmaker, relays)", not lost and len(before) > 20, lost)
    own = before.get("LS_DATUM")
    check("G", f"{name}: renting is moved to the Stream Gateway, said so, and the old gateway's address kept as LS_DATUM_OWN",
          after.get("LS_DATUM_GATEWAY") == "bundled" and after.get("LS_DATUM") == f"127.0.0.1:{STRATUM}"
          and after.get("LS_GATEWAY_API") == f"127.0.0.1:{INSTALLS[name][8]}" and after.get("LS_DATUM_OWN") == own
          and f"rented hashrate now goes to the Stream Gateway (yours was {own})" in out, {k: after.get(k) for k in after if "DATUM" in k or "GATEWAY" in k})
    check("G", f"{name}: the app's Lightning keys of the 0.1 install are kept, not made again", "already made; keeping them" in out, out[-600:])
    cmd = json.loads(docker("inspect", "-f", "{{json .Config.Cmd}}", container(d, "hashtaker")).stdout)
    check("G", f"{name}: its hashtaker now opens every job on the Stream Gateway's API, and is never told to allow unmasked jobs",
          cmd[cmd.index("--upstream") + 1] == f"127.0.0.1:{STRATUM}" and cmd[cmd.index("--gateway-api") + 1] == f"127.0.0.1:{INSTALLS[name][8]}"
          and "--allow-unblinded" not in cmd, cmd)
    env = dict(old_env, **{k: v for k, v in after.items()})
    st = waited(lambda: renter_status(name), 60, f"{name}'s hashtaker answering") or {}
    check("G", f"{name}: the hashtaker moved the gateway its 0.1 page saved to the Stream Gateway, and keeps the old one to go back to",
          (st.get("datum") or {}).get("addr") == f"127.0.0.1:{STRATUM}" and (st.get("datum") or {}).get("movedFrom") == own, st.get("datum"))
    datum_files(name, d)
    check("G", f"{name}: the Stream Gateway service is added and healthy (idle: no gateway set yet)",
          waited(lambda: health(d, "datum") == "healthy", 120, "the Stream Gateway's health") is not None, health(d, "datum"))
    return d, env


def env_file(d):
    out = {}
    for line in open(os.path.join(d, ".env")):
        if "=" in line and not line.startswith("#"):
            k, v = line.rstrip("\n").split("=", 1)
            out[k] = v
    return out


def dc_env():
    """The environment for `docker compose` in an install's folder: its own files and .env, not the lab's COMPOSE_*."""
    return {k: v for k, v in os.environ.items() if not k.startswith(("COMPOSE_", "LS_"))}


def container(d, svc):
    return sh("docker", "compose", "ps", "-a", "-q", svc, cwd=d, env=dc_env()).stdout.strip()


def health(d, svc):
    c = container(d, svc)
    return docker("inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{end}}", c, check_rc=False).stdout.strip() if c else ""


def datum_files(name, d):
    """What init makes for the Stream Gateway (W5's contract): with the images' init, checked; without, made here."""
    data = os.path.join(d, "data")
    if INIT_DATUM:
        st = root_helper(data, "stat -c '%n %u:%g %a' /d/run/datum /d/run/datum/rpc.cookie /d/datum /d/datum/submitblocks; "
                               "od -An -c /d/run/datum/rpc.cookie | tr -s ' '").stdout
        check("I", f"{name}: init makes run/datum (0750 10005:10021), the node login rpc.cookie (0600 10021, no newline) and datum/submitblocks",
              "/d/run/datum 10005:10021 750" in st and "/d/run/datum/rpc.cookie 10021:10021 600" in st and "/d/datum/submitblocks 10021:10021 700" in st
              and "l a b : l a b" in st and "\\n" not in st, st)
        return
    root_helper(data, f"mkdir -p /d/run/datum /d/datum/submitblocks && chown {UI_UID}:{DATUM_UID} /d/run/datum && chmod 750 /d/run/datum "
                      f"&& chown -R {DATUM_UID}:{DATUM_UID} /d/datum && chmod 700 /d/datum /d/datum/submitblocks "
                      f"&& printf %s lab:lab > /d/run/datum/rpc.cookie && chown {DATUM_UID}:{DATUM_UID} /d/run/datum/rpc.cookie "
                      f"&& chmod 600 /d/run/datum/rpc.cookie", ro=False)


def gateway_config(api, address, own=False):
    """The Stream Gateway's config as the UI writes it for solo (W5's contract: no secret, admin endpoints off,
    /xbt/job loopback only), with the test's share difficulty. own: the owner's own stock gateway (no xbt keys)."""
    api_cfg = {"listen_addr": "127.0.0.1", "listen_port": api, "admin_password": "", "modify_conf": False}
    if not own:
        api_cfg["xbt_job_allow"] = ""
    return {"bitcoind": {"rpccookiefile": "/data/run/datum/rpc.cookie", "rpcurl": f"http://127.0.0.1:{P['rpc']}", "work_update_seconds": 5,
                         "notify_fallback": True},
            "stratum": {"listen_addr": "127.0.0.1", "listen_port": P["own"] if own else STRATUM, "vardiff_min": 1, "fingerprint_miners": False},
            "mining": {"pool_address": address, "coinbase_tag_primary": "Lightning Stream", "coinbase_tag_secondary": "solo",
                       "save_submitblocks_dir": "/data/datum/submitblocks"},
            "api": api_cfg, "logger": {"log_to_console": True, "log_to_file": False, "log_level_console": 2},
            "datum": {"pool_host": "", "pooled_mining_only": False}}


def page_gateway(name, ui, payout):
    """The owner saves Your gateway on the Hashrate page (solo, their address); the UI writes run/datum/config.json.
    Checked as written, then given the test's share difficulty floor. Returns the config as the page wrote it."""
    d = os.path.join(OUT, name)
    data = os.path.join(d, "data")
    st, _, _ = ui.post("/hashrate", "/hashrate", {"action": "gateway", "mode": "solo", "payout": payout})
    flash = ui.flash("/hashrate")
    check("M", f"{name}: Your gateway (solo, a regtest address) saves on the Hashrate page", st == 303 and "Saved" in flash, flash)
    meta = root_helper(data, "stat -c '%u:%g %a' /d/run/datum/config.json; cat /d/run/datum/config.json", ro=True).stdout
    head, _, body = meta.partition("\n")
    try:
        cfg = json.loads(body)
    except ValueError:
        cfg = {}
    api = INSTALLS[name][8]
    ok = (head.strip() == f"{UI_UID}:{DATUM_UID} 640" and cfg.get("stratum", {}).get("listen_addr") == "127.0.0.1"
          and cfg["stratum"].get("listen_port") == STRATUM and cfg.get("api", {}).get("listen_addr") == "127.0.0.1"
          and cfg["api"].get("listen_port") == api and cfg["api"].get("xbt_job_allow", "") == "" and cfg["api"].get("admin_password") == ""
          and cfg.get("bitcoind", {}).get("rpccookiefile") == "/data/run/datum/rpc.cookie"
          and cfg["bitcoind"].get("rpcurl") == f"http://127.0.0.1:{P['rpc']}" and cfg.get("mining", {}).get("pool_address") == payout
          and cfg.get("datum", {}).get("pool_host") == "" and "lab:lab" not in body and '"lab"' not in body)
    check("M", f"{name}: the page wrote config.json (0640 10005:10021): loopback stratum {STRATUM} and API {api}, /xbt/job loopback only, "
               "no admin password, the node by cookie file, solo to the address, no secret", ok, [head, cfg])
    if cfg:
        cfg["stratum"]["vardiff_min"] = 1
        root_helper(data, f"cat > /d/run/datum/config.json <<'EOF'\n{json.dumps(cfg)}\nEOF", ro=False)
    return cfg


def set_gateway(d, cfg):
    """The UI saving Your gateway (solo): run/datum/config.json, 0640 10005:10021. None: the config removed."""
    data = os.path.join(d, "data")
    if cfg is None:
        root_helper(data, "rm -f /d/run/datum/config.json", ro=False)
        return
    root_helper(data, f"cat > /d/run/datum/config.json <<'EOF'\n{json.dumps(cfg)}\nEOF\n"
                      f"chown {UI_UID}:{DATUM_UID} /d/run/datum/config.json && chmod 640 /d/run/datum/config.json", ro=False)


def renter_status(name):
    ctl = INSTALLS[name][6]
    token = root_helper(os.path.join(OUT, name, "data"), "cat /d/run/hashrate/control-token").stdout.strip()
    return json.loads(sh("curl", "-s", "-m", "30", "-H", f"Authorization: Bearer {token}", f"http://127.0.0.1:{ctl}/status").stdout)


def renter_call(name, method, path, body):
    ctl = INSTALLS[name][6]
    token = root_helper(os.path.join(OUT, name, "data"), "cat /d/run/hashrate/control-token").stdout.strip()
    r = sh("curl", "-s", "-m", "60", "-w", "\n%{http_code}", "-X", method, "-H", f"Authorization: Bearer {token}", "-H", "Content-Type: application/json",
           "-d", json.dumps(body), f"http://127.0.0.1:{ctl}{path}", check_rc=False).stdout
    text, _, code = r.rpartition("\n")
    return int(code or 0), (json.loads(text) if text.strip().startswith("{") else text)


def masked_shown(name):
    """The install's hashtaker looks at its upstream's jobs: blinded (masked), and the gateway's word for whose key."""
    def look():
        b = (renter_status(name).get("blinding") or {})
        return b if b.get("state") == "blinded" else None
    try:
        return wait_until(look, 180, f"{name}'s hashtaker seeing masked jobs", every=5)
    except RuntimeError:
        return renter_status(name).get("blinding")


def job_on_api(api_host, api, stratum=STRATUM):
    """A miner's first job from the gateway's stratum, then that job opened on /xbt/job at api_host: (HTTP code or error, answer)."""
    import socket
    import urllib.request
    s = socket.create_connection(("127.0.0.1", stratum), 10)
    s.settimeout(30)
    s.sendall(b'{"id":1,"method":"mining.subscribe","params":["linux-test/0"]}\n{"id":2,"method":"mining.authorize","params":["rented","x"]}\n')
    buf, d, job = b"", 1.0, None
    t0 = time.time()
    while job is None and time.time() - t0 < 30:
        buf += s.recv(65536)
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("method") == "mining.set_difficulty":
                d = float(m["params"][0])
            elif m.get("method") == "mining.notify":
                job = m["params"][0]
    s.close()
    pdiff = round(d * 65536 / 65535)
    pot = 0 if pdiff < 1 else pdiff.bit_length() - 1
    try:
        with urllib.request.urlopen(f"http://{api_host}:{api}/xbt/job?id={job}&pot={pot}", timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None
    except OSError as e:
        return str(e), None


def rules_on_page(ui, path):
    """The rules a page proposes, as its "edit the rules as a file" box holds them."""
    m = re.search(r'<textarea name="json"[^>]*>(.*?)</textarea>', ui.get(path), re.S)
    return json.loads(unescape(m.group(1)))


def save_logs(installs):
    """Each service's log and the stand-ins', into OUT/logs (evidence; nothing is checked here)."""
    d = os.path.join(OUT, "logs")
    os.makedirs(d, exist_ok=True)
    for name, (idir, env) in installs.items():
        for svc in ("signer", "ui", "gateway", "hashtaker", "hashmaker", "init", "datum"):
            r = subprocess.run(["docker", "compose", "logs", "--no-color", svc], cwd=idir, env=env, capture_output=True, text=True)
            with open(os.path.join(d, f"{name}-{svc}.log"), "w") as f:
                f.write(r.stdout + r.stderr)
    for c in ("lstest-relay", "lstest-fallback", "lstest-owngw"):
        r = subprocess.run(["docker", "logs", c], capture_output=True, text=True)
        with open(os.path.join(d, f"{c}.log"), "w") as f:
            f.write(r.stdout + r.stderr)


def listeners():
    out = sh("ss", "-ltnH").stdout
    return [ln.split()[3] for ln in out.splitlines() if ln.split()]


def waited(fn, timeout, what, every=3):
    try:
        return wait_until(fn, timeout, what, every)
    except RuntimeError:
        return None


def own_gateway(address):
    """The owner's own DATUM gateway, stock (no masking, no /xbt/job), on the host's network: as a 0.1 owner had it."""
    d = os.path.join(OUT, "own-gateway")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "rpc.cookie"), "w") as f:
        f.write("lab:lab")
    with open(os.path.join(d, "config.json"), "w") as f:
        json.dump(gateway_config(P["own_api"], address, own=True), f)
    for x in ("rpc.cookie", "config.json"):
        os.chmod(os.path.join(d, x), 0o644)
    os.chmod(d, 0o755)
    docker("rm", "-f", "lstest-owngw", check_rc=False)
    docker("run", "-d", "--name", "lstest-owngw", "--network", "host", "--read-only", "--cap-drop", "ALL", "--tmpfs", "/data/datum",
           "-v", f"{d}:/data/run/datum:ro", OWN_GW)


def main():
    os.makedirs(OUT, exist_ok=True)
    open_log(os.path.join(OUT, "test.log"))
    os.environ["LS_TEST_RPC_PORT"] = str(P["rpc"])
    lab = Lab(OUT, "lstest", rest_ports=(P["lf1"], P["lf2"]))
    os.environ["COMPOSE_FILE"] += ":" + os.path.join(HERE, "lab.compose.yml")
    installs = {}
    grind = None
    try:
        log("== the lab: the owners' own nodes (chain, lf1 -> lf2 channel)")
        f = lab.up()
        # the solo payout: a legacy address of the lab's wallet (the gateway reads bech32 only under mainnet and testnet prefixes)
        solo = str(lab.cli("getnewaddress", "", "legacy", wallet="lab")).strip()
        solo_script = lab.cli("getaddressinfo", solo, wallet="lab")["scriptPubKey"]
        log("== the stand-ins: a Nostr relay, the hashmaker's own pool, an owner's own stock DATUM gateway")
        standin("lstest-relay", "relay", "--listen", f"127.0.0.1:{P['relay']}")
        standin("lstest-fallback", "standin-pool", "--listen", f"127.0.0.1:{P['fallback']}", "--diff", "4", "--job-ms", "1000")
        own_gateway(solo)
        wait_until(lambda: sh("bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{P['own']}", check_rc=False).returncode == 0, 120, "the own stock gateway's stratum", every=2)

        log("== I/G: the maker from the 0.1 package, then updated; the taker a first install")
        old, ref = old_package()
        log(f"   the 0.1 package: packaging/linux at {ref[:12]}")
        installs["maker"] = install("maker", lab, package=old, extra={"LS_DATUM": f"127.0.0.1:{P['own']}"})
        check("G", "maker: the 0.1 install has no Stream Gateway, and rents into its own gateway",
              not container(installs["maker"][0], "datum") and env_file(installs["maker"][0]).get("LS_DATUM") == f"127.0.0.1:{P['own']}")
        installs["maker"] = update("maker", *installs["maker"])
        installs["taker"] = install("taker", lab)
        e = env_file(installs["taker"][0])
        check("I", "taker: a first install uses the Stream Gateway, its API on the port given, and says nothing of a move",
              e.get("LS_DATUM_GATEWAY") == "bundled" and e.get("LS_DATUM") == f"127.0.0.1:{STRATUM}" and e.get("LS_GATEWAY_API") == f"127.0.0.1:{INSTALLS['taker'][8]}"
              and not e.get("LS_DATUM_OWN"), {k: v for k, v in e.items() if "DATUM" in k or "GATEWAY" in k})
        check("I", "taker: the Stream Gateway is healthy while idle (no gateway set yet), as the page's healthcheck waits for its config",
              waited(lambda: health(installs["taker"][0], "datum") == "healthy", 120, "taker's datum health") is not None, health(installs["taker"][0], "datum"))

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
            st_ok, _ = ui.login(env["LS_UI_PASSWORD"] if name == "taker" else f"pw-{name}-$ x")
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
                sh("docker", "compose", "restart", "signer", cwd=d, env=dc_env())
            page = ui.get("/lightning")
            check("U", f"{name}: the Lightning page says the node is connected by itself (no paste)", "connected" in page.lower(), page[-400:])
            uis[name] = (ui, key)

        # --- M: each install's Stream Gateway, set to solo, shown masked to its own hashtaker -------------------------
        lan = sh("hostname", "-I").stdout.split()[0]
        log(f"   the Stream Gateway's image: {DATUM_IMAGE} {docker('image', 'inspect', '-f', '{{.Id}}', DATUM_IMAGE, check_rc=False).stdout.strip()}")
        for name in ("maker", "taker"):
            d = installs[name][0]
            api = INSTALLS[name][8]
            if INIT_DATUM:
                page_gateway(name, uis[name][0], solo)
            else:
                set_gateway(d, gateway_config(api, solo))
            up = waited(lambda: sh("bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{STRATUM}", check_rc=False).returncode == 0, 120, f"{name}'s Stream Gateway stratum")
            check("M", f"{name}: Your gateway saved (solo), the Stream Gateway starts by itself and is healthy",
                  up is not None and waited(lambda: health(d, "datum") == "healthy", 120, f"{name}'s datum health") is not None,
                  {"health": health(d, "datum"), "log": sh("docker", "compose", "logs", "--tail", "15", "datum", cwd=d, env=dc_env(), check_rc=False).stdout[-1200:]})
            b = masked_shown(name)
            check("M", f"{name}{' (updated from 0.1)' if name == 'maker' else ''}: its hashtaker shows the Stream Gateway masking its jobs (solo: the gateway holds the key)",
                  (b or {}).get("state") == "blinded" and b.get("why") == "solo" and "Your gateway holds the key" in b.get("words", ""), b)
            if INIT_DATUM:
                bst = renter_status(name).get("bundled") or {}
                check("M", f"{name}: the hashtaker's status shows the Stream Gateway in use, running, connected to the node and masking",
                      bst.get("inUse") is True and bst.get("running") is True and bst.get("node") is True and bst.get("masking") is True, bst)
            code, a = job_on_api("127.0.0.1", api)
            check("M", f"{name}: a miner's job, opened on /xbt/job from loopback, is masked: a key that isn't null, solo",
                  code == 200 and a.get("null_key") is False and a.get("mode") == "solo", [code, a])
            code_lan, _ = job_on_api(lan, api)
            ls = listeners()
            wide = [x for x in ls if x.rsplit(":", 1)[1] in (str(STRATUM), str(api)) and not x.startswith("127.0.0.1")]
            check("L", f"{name}: the Stream Gateway's stratum ({STRATUM}) and API ({api}) listen on loopback only; /xbt/job isn't reached on the LAN address",
                  not wide and code_lan != 200 and any(x == f"127.0.0.1:{api}" for x in ls), {"wide": wide, "lan": [lan, code_lan]})
            if name == "maker":
                set_gateway(d, None)
                waited(lambda: sh("bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{STRATUM}", check_rc=False).returncode != 0, 60, "the maker's gateway stopped")
        taker, _ = uis["taker"]
        page = taker.get("/hashrate")
        check("M", "taker: Services -> Hashrate says Ready to rent, not that the gateway isn't masking", "Ready to rent" in page and "isn't masking" not in page,
              page[-800:])

        maker, _ = uis["maker"]
        mdir = installs["maker"][0]
        gw = INSTALLS["maker"][5]
        maker.post("/sell", "/sell", {"action": "advanced", "max_sessions": "30", "sessions_per_address": "2", "max_held_tickets": "15",
                                      "proxies": "", "network": f["network"]})
        maker.post("/sell", "/sell", {"action": "shop", "name": "Test hashmaker", "public_url": f"http://127.0.0.1:{gw}"})
        st, _, _ = maker.post("/sell-hashrate", "/sell-hashrate", {
            "action": "save", "fallback": f"127.0.0.1:{P['fallback']}", "price": str(PRICE_SAT), "rentable": "", "name": "Test miners",
            "link_public": "127.0.0.1:23341", "enabled": "1", "slice_work": str(SLICE_WORK), "grace_s": "60"})
        flash = maker.flash("/sell-hashrate")
        check("U", "maker: Sell -> Hashrate saves renting on (own pool, price, the address hashtakers use)", st == 303 and "error" not in flash.lower(), flash)
        wait_until(lambda: status(f"http://127.0.0.1:{gw}/x402/ticket/health") == 200, 120, "the maker's gateway selling", every=2)
        check("U", "maker: the gateway started from the shop the page wrote", True)
        # the maker's miner: real shares (stratum-grind, a CPU miner), at whatever difficulty it's given
        glog = open(os.path.join(OUT, "stratum-grind.log"), "ab")
        grind = subprocess.Popen(["nice", "-n", "15", os.path.join(HG, "stratum-grind"), "--host", "127.0.0.1", "--port", "23340", "--user", "maker.m1"],
                                 stdout=glog, stderr=glog, env={**os.environ, "LD_LIBRARY_PATH": os.path.join(HG, "lib")})
        listed = wait_until(lambda: "Listed" in maker.get("/sell-hashrate") or None, 180, "the maker's offer listed", every=3)
        check("U", "maker: with a miner connected, the offer is on the relay", bool(listed))

        # --- H: the hashtaker rents, on masked solo jobs, pays per slice ---------------------------------------------
        page = wait_until(lambda: (lambda p: p if 'name="key"' in p else None)(taker.get("/hashrate")), 180, "the offer on the taker's Rent page", every=3)
        check("H", "taker: Services -> Hashrate shows its gateway ready and the maker's offer", "Ready to rent" in page and "Test miners" in page,
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
        height0 = int(lab.cli("getblockcount"))
        st, _, _ = taker.post("/hashrate", "/hashrate", {"action": "rent", "key": field(page, "key"), "miners": "1", "minutes": "8", "budget": "2000"})
        flash = taker.flash("/hashrate")
        check("H", "taker: Rent starts a rental", "Renting" in flash, flash)
        tdata = os.path.join(installs["taker"][0], "data")

        def rental():
            x = (renter_status("taker").get("rentals") or [{}])[0]
            live = x.get("live") or {}
            paid = int(live.get("paid") or live.get("released") or 0)
            blocks = int(lab.cli("getblockcount")) - height0
            return x if paid >= 2 and blocks >= 1 else None
        x = waited(rental, 600, "two slices paid and a block found", every=5) or (renter_status("taker").get("rentals") or [{}])[0]
        check("H", "taker: the rented miner's work on masked jobs is paid slice by slice through the wallet (2 or more slices)",
              int((x.get("live") or {}).get("paid") or (x.get("live") or {}).get("released") or 0) >= 2, x)
        check("H", "maker's node settled tickets for it (lf1 -> lf2)", len(lab.seller_settled()) > settled0, len(lab.seller_settled()))
        height1 = int(lab.cli("getblockcount"))
        found = []
        for h in range(height0 + 1, height1 + 1):
            bh = str(lab.cli("getblockhash", h)).strip()
            blk = lab.cli("getblock", bh, 2)
            hdr = bytes.fromhex(str(lab.cli("getblockheader", bh, "false")).strip())
            found.append({"height": h, "pays": any(o["scriptPubKey"]["hex"] == solo_script for o in blk["tx"][0]["vout"]),
                          "key_null": hdr[112:128] == bytes(16) if len(hdr) >= 128 else None})
        check("H", f"blocks found on the rented work reach the node, each paying the solo address ({solo[:6]}...) and carrying a key (masked)",
              found and all(b["pays"] and b["key_null"] is False for b in found), {"height": [height0, height1], "blocks": found})
        saved = root_helper(tdata, "ls /d/datum/submitblocks | wc -l").stdout.strip()
        check("H", "the Stream Gateway also saved each block it submitted, under data/datum/submitblocks", saved.isdigit() and int(saved) >= len(found) > 0, saved)
        st, _, _ = taker.post("/hashrate", "/hashrate", {"action": "cut", "rental": x.get("rental", "")})
        check("H", "taker: Cut ends the rental", "Cut" in taker.flash("/hashrate"))

        # --- O: the owner chooses their own (stock) DATUM gateway: renting refused, in words --------------------------
        d, env = installs["taker"]
        settled1 = len(lab.seller_settled())
        r = subprocess.run([os.path.join(PKG, "install.sh"), "--yes", "--dir", d], capture_output=True, text=True, timeout=900,
                           env=dict(env, LS_DATUM_GATEWAY="own", LS_DATUM=f"127.0.0.1:{P['own']}", LS_GATEWAY_API=f"127.0.0.1:{P['own_api']}"))
        out = r.stdout + r.stderr
        with open(os.path.join(OUT, "install-taker-own.log"), "w") as fh:
            fh.write(out)
        check("O", "taker: install.sh with the owner's own gateway says plainly that rentals need masked jobs, and a stock gateway's are refused",
              r.returncode == 0 and "Rentals need masked jobs" in out and "A stock DATUM Gateway doesn't mask its jobs" in out, out[-1200:])

        def refused():
            b = renter_status("taker").get("blinding") or {}
            return b if b.get("state") and b.get("state") != "blinded" else None
        b = waited(refused, 180, "the taker's hashtaker looking at the own gateway", every=5) or renter_status("taker").get("blinding")
        st = renter_status("taker")
        check("O", "taker: the hashtaker keeps the owner's own gateway, with its API (not moved to the Stream Gateway)",
              (st.get("datum") or {}).get("addr") == f"127.0.0.1:{P['own']}" and (st.get("datum") or {}).get("api") == f"127.0.0.1:{P['own_api']}",
              st.get("datum"))
        check("O", "taker: its hashtaker says in words that the own gateway's jobs can't be shown masked, and rentals to it are refused",
              (b or {}).get("state") in ("can't be checked", "not blinded") and "rentals to this upstream are refused" in (b or {}).get("words", ""), b)
        page = taker.get("/hashrate")
        check("O", "taker: Services -> Hashrate says the gateway isn't masking its jobs, and renting stays off", "isn't masking its jobs" in page
              and "Renting stays off" in page, page[-1200:])
        key = field(page, "key") or ""
        st, _, _ = taker.post("/hashrate", "/hashrate", {"action": "rent", "key": key, "miners": "1", "minutes": "3", "budget": "2000"})
        flash = taker.flash("/hashrate")
        check("O", "taker: Rent is refused on the page, in words, and nothing is paid", "masks its jobs" in flash and "Nothing was paid" in flash, flash)
        code, ans = renter_call("taker", "POST", "/rent", {"linkKey": key, "miners": 1, "budgetSats": 2000, "minutes": 3})
        check("O", "taker: asked directly, the hashtaker refuses the rental (409) with the reason in words",
              code == 409 and "refused" in str((ans or {}).get("error", "")), [code, ans])
        time.sleep(10)
        check("O", "no ticket was paid for it", len(lab.seller_settled()) == settled1, [settled1, len(lab.seller_settled())])

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
            check("X", f"{name}: uninstall.sh removes the containers (the Stream Gateway's too), the data and the files, and names the root keys to revoke",
                  r.returncode == 0 and not left and not nets and not vols and not os.path.exists(d) and "deletemacaroonid" in r.stdout,
                  {"rc": r.returncode, "left": left, "nets": nets, "vols": vols, "dir": os.path.exists(d), "out": (r.stdout + r.stderr)[-600:]})
        installs.clear()
    finally:
        if grind:
            grind.terminate()
        save_logs(installs)
        for name, (d, env) in installs.items():
            subprocess.run(["docker", "compose", "--profile", "setup", "--profile", "hashmaker", "down", "--remove-orphans"], cwd=d, env=env,
                           capture_output=True)
            if os.path.isdir(os.path.join(d, "data")):
                root_helper(os.path.join(d, "data"), "rm -rf /d/* /d/.[!.]*", ro=False)
        for c in ("lstest-relay", "lstest-fallback", "lstest-owngw"):
            docker("rm", "-f", c, check_rc=False)
        lab.down()
        write_results(OUT)


if __name__ == "__main__":
    main()
