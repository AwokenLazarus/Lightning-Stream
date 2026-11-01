#!/usr/bin/env python3
"""Lightning Stream's Umbrel compose, renting with its Stream Gateway (DATUM-compatible), on regtest
(packaging/umbrel/test-umbrel-datum.sh runs this).

The app's own compose file runs its `renter` and `datum` services the way umbrelOS runs them: a copy of the
app folder as the app's data dir, --compatibility, the project named by the app id, on one shared network
(here a network of this run's, standing in for umbrel_main_network). The `bitcoin` slot is a Knots BLAKE2b
regtest node on this host, reached at that network's gateway address as a node app's container would be
(APP_BITCOIN_*: its RPC user and password; no ZMQ). Everything else comes from the p2p_hash lab
(scripts/p2p_hash/regtest.py): three Lightning Fork nodes, the wallet's signer, the hashmaker's gateway, a
stand-in Nostr relay, a hashmaker with real stratum-grind behind it.

What the test changes in the app, and only that (the overlay this writes, OUT/overlay.yml):
  * the images: this tree's amd64 builds from container/Dockerfile, tagged <image>:0.1.0-umbtest (UMB_HASHLINK_IMAGE,
    UMB_DATUM_IMAGE, UMB_INIT_IMAGE);
  * the renter's --relays: this lab's relay, not the public ones, on the renter's loopback through a forwarder
    container in its namespace (the Nostr client takes plain ws:// to loopback only); the rest of its command
    is the compose's;
  * the renter's run/signer: the lab wallet's socket folder in place of the app's (the signer is the lab's);
  * the network: this run's, as umbrelOS's.
Without UMB_INIT_IMAGE (an xbt-init that knows the `datum` component), the files init would make are laid
out here, as W5's contract says (run/datum 0750 10005:10021, rpc.cookie 0600 10021, datum/ 0700 10021); with
it, the compose's own init makes them and that is checked. The config the Hashrate page writes is written
here (solo, to a regtest address of the node's wallet).

Checks (OUT/umbrel_datum_regtest.json):
  compose     the renter's candidates put 127.0.0.1:23339 first, with no --allow-unblinded; the gateway runs
              in the renter's namespace as its image's user, read-only, with no port
  idle        before the config exists the gateway is not started and the service is healthy
  node        once it exists the gateway starts, takes the cookie, reaches the node: its job is on the node's tip
  masked      the job a miner gets is opened on /xbt/job: not the null key, mode solo, h2 in coinb1
  loopback    /xbt/job and the stratum answer in the renter's namespace only: not from another container on
              the app's network, nor from the host
  status      the renter's page shows its gateway as the bundled one, and its jobs as masked (blinded, solo)
  rental      a masked solo rental through the compose, paid through the wallet: real blocks, each masked,
              each paying the regtest address, every job held to /xbt/job, payments = what the hashmaker earned,
              and the found blocks kept in datum/submitblocks
  restart     after `docker restart` of the renter, is its gateway still on its loopback; and a restart of the
              gateway's container puts it back
    datum_regtest.py
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Any

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(STORE))
sys.path.insert(0, os.path.join(ROOT, "scripts", "p2p_hash"))
import regtest as p  # noqa: E402  (the p2p_hash lab: nodes, wallet, relay, gateway, keys)

d, lab, check, REPORT, RUN, OUT = p.d, p.lab, p.check, p.REPORT, p.RUN, p.OUT
APP = "lazarus-lightning-stream"
HG = p.HG
B = p.B
NODE_RPC, NODE_P2P = B + 29, B + 30
DATUM_UID = int(os.environ.get("UMB_DATUM_UID", "10021"))
UI_UID, HASHRATE_UID = 10005, 10010
IMAGES = {"renter": os.environ["UMB_HASHLINK_IMAGE"], "datum": os.environ["UMB_DATUM_IMAGE"]}
INIT_IMAGE = os.environ.get("UMB_INIT_IMAGE", "")
PROBE_IMAGE = "python:3-alpine"
RENT_MINUTES = int(os.environ.get("UMB_DATUM_RENT_MINUTES", "6"))
NET = f"umbdatum-{os.getpid()}"
FWD = f"umbdatum-relayfwd-{os.getpid()}"
# the run's own files (the app's data dir, the overlay); its report and logs go to OUT/umbrel_datum_* (stream-lab fetches those)
WORK = os.path.join(OUT, "umbrel-datum")
DATA = os.path.join(WORK, "app-data", APP)
STRATUM, API, CONTROL = 23339, 7152, 23343
PASS = secrets.token_hex(16)


def sh(*a: str, check_rc: bool = True, env: dict[str, str] | None = None, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    r = subprocess.run(list(a), capture_output=True, text=True, env=env, timeout=timeout)
    if check_rc and r.returncode != 0:
        raise lab.LabError(f"{' '.join(a[:6])}: rc {r.returncode}: {r.stderr.strip()[-600:]}")
    return r


def root(script: str) -> str:
    """A root shell on the app's data dir (the box's view; the images have no shell)."""
    return sh("docker", "run", "--rm", "--network", "none", "-v", f"{DATA}/data:/d", "debian:bookworm-slim", "sh", "-c", script).stdout


class Forward:
    """A TCP forwarder from the network's gateway address to a lab service on loopback: what the app's
    containers reach the host's relay through."""

    def __init__(self, host: str, port: int, to: int) -> None:
        self.to = to
        self.server = socket.create_server((host, port))
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self) -> None:
        while True:
            a, _ = self.server.accept()
            try:
                b = socket.create_connection(("127.0.0.1", self.to), 5)
            except OSError:
                a.close()
                continue
            for x, y in ((a, b), (b, a)):
                threading.Thread(target=self.pump, args=(x, y), daemon=True).start()

    @staticmethod
    def pump(x: socket.socket, y: socket.socket) -> None:
        try:
            while data := x.recv(65536):
                y.sendall(data)
        except OSError:
            pass
        for s in (x, y):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def env_for(gw: str) -> dict[str, str]:
    """What umbrelOS gives the app: its data dir, seed, password, and the slot's node (here this host's)."""
    e = {k: v for k, v in os.environ.items() if k not in ("COMPOSE_FILE", "COMPOSE_PROJECT_NAME") and not k.startswith("APP_")}
    e.update({"APP_DATA_DIR": DATA, "APP_SEED": "0" * 64, "APP_PASSWORD": "x" * 32, "DEVICE_DOMAIN_NAME": "127.0.0.1", "DEVICE_HOSTNAME": "umbrel",
              "APP_BITCOIN_NODE_IP": gw, "APP_BITCOIN_RPC_PORT": str(NODE_RPC), "APP_BITCOIN_RPC_USER": "umbrel", "APP_BITCOIN_RPC_PASS": PASS,
              "APP_LIGHTNING_FORK_NODE_IP": "127.0.0.1", "APP_LIGHTNING_FORK_NODE_REST_PORT": "8080",
              "APP_LIGHTNING_FORK_NODE_DATA_DIR": os.path.join(WORK, "lf-stub"), "UMBREL_ROOT": os.path.join(WORK, "umbrel-root")})
    return e


def compose(gw: str, *args: str, check_rc: bool = True) -> subprocess.CompletedProcess[str]:
    return sh("docker", "compose", "--compatibility", "-p", APP, "--project-directory", DATA, "-f", f"{DATA}/docker-compose.yml",
              "-f", f"{WORK}/overlay.yml", *args, env=env_for(gw), check_rc=check_rc, timeout=900)


def cname(svc: str) -> str:
    return f"{APP}_{svc}_1"


def inspect(name: str) -> dict[str, Any]:
    return json.loads(sh("docker", "inspect", name).stdout)[0]


def probe(netns: str, *args: str) -> dict[str, Any]:
    r = sh("docker", "run", "--rm", "--network", netns, "-v", f"{HERE}/datum_probe.py:/probe.py:ro", PROBE_IMAGE, "python", "-I", "/probe.py", *args,
           check_rc=False, timeout=120)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stdout + r.stderr)[-400:]}


def health(name: str) -> str:
    return inspect(name)["State"].get("Health", {}).get("Status", "none")


def control(ip: str, token: str, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    req = urllib.request.Request(f"http://{ip}:{CONTROL}{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"httpStatus": e.code, **json.loads(e.read() or b"{}")}


def node_up(gw: str, subnet: str) -> tuple[Any, str]:
    """The `bitcoin` slot's node: Knots BLAKE2b regtest, RPC on loopback and on the app network's gateway."""
    home = f"{RUN}/node"
    os.makedirs(home, exist_ok=True)
    with open(f"{home}/bitcoin.conf", "w") as f:
        f.write("regtest=1\nserver=1\nlistenonion=0\ndiscover=0\ndnsseed=0\nfixedseeds=0\nfallbackfee=0.0002\ntxindex=1\nblake2b_headline=Lazarus\n"
                f"rpcuser=umbrel\nrpcpassword={PASS}\n"
                f"[regtest]\nlisten=1\nbind=127.0.0.1\nport={NODE_P2P}\nrpcbind=127.0.0.1\nrpcbind={gw}\nrpcallowip=127.0.0.1\nrpcallowip={subnet}\n"
                f"rpcport={NODE_RPC}\ntestactivationheight=blake2b@101\nmaxtipage=315360000\n")
    env = {**os.environ, "LD_LIBRARY_PATH": f"{HG}/lib"}
    sh(f"{HG}/bitcoind", f"-datadir={home}", "-daemon", env=env)

    def cli(*a: str) -> str:
        return sh(f"{HG}/bitcoin-cli", f"-datadir={home}", *a, env=env).stdout.strip()

    lab.wait("the slot's node", 60, lambda: sh(f"{HG}/bitcoin-cli", f"-datadir={home}", "getblockcount", env=env, check_rc=False).returncode == 0, every=0.5)
    return cli, home


def layout(cookie_owner_ok: bool) -> dict[str, Any]:
    """What init leaves for the gateway, as root sees it: owner, group and mode of each."""
    out = root("for p in datum datum/submitblocks run/datum run/datum/rpc.cookie; do stat -c '%n %u %g %a' /d/$p 2>&1; done; "
               "printf 'cookie newline: '; tail -c1 /d/run/datum/rpc.cookie | od -An -c | tr -d ' '")
    return {"stat": out.strip().splitlines(), "cookie_owner_ok": cookie_owner_ok}


def main() -> int:
    t0 = time.time()
    gw = ""
    cli = None
    hashmaker = grind = None
    try:
        if os.path.isdir(WORK):
            sh("docker", "run", "--rm", "--network", "none", "-v", f"{WORK}:/a", "debian:bookworm-slim", "rm", "-rf", "/a/app-data")
        os.makedirs(WORK, exist_ok=True)
        p.setup()
        print(f"lab up in {time.time() - t0:.0f} s", flush=True)
        sh("docker", "network", "create", NET)
        net = inspect(NET)
        gw, subnet = net["IPAM"]["Config"][0]["Gateway"], net["IPAM"]["Config"][0]["Subnet"]
        Forward(gw, p.RELAY, p.RELAY)
        relay = f"ws://127.0.0.1:{p.RELAY}"
        cli, home = node_up(gw, subnet)
        cli("createwallet", "w")
        cli("-rpcwallet=w", "generatetoaddress", "220", cli("-rpcwallet=w", "getnewaddress", "", "bech32"))
        # the gateway reads bech32 only under mainnet's and testnet's prefixes; a regtest solo block pays a legacy address
        payout = cli("-rpcwallet=w", "getnewaddress", "", "legacy")
        payout_script = json.loads(cli("-rpcwallet=w", "getaddressinfo", payout))["scriptPubKey"]

        # --- install: umbrelOS copies the app folder into app-data/<id>, owned by the box user
        shutil.copytree(os.path.join(STORE, APP), DATA)
        os.makedirs(f"{WORK}/lf-stub", exist_ok=True)
        open(f"{WORK}/lf-stub/tls.cert", "w").close()
        with open(f"{DATA}/docker-compose.yml") as f:
            c = yaml.safe_load(f)
        svcs = c["services"]
        cmd = [str(x) for x in svcs["renter"]["command"]]
        cand = cmd[cmd.index("--datum-candidates") + 1].split(",") if "--datum-candidates" in cmd else []
        dt = svcs["datum"]
        check("compose: the renter's candidates put the bundled gateway first, with no --allow-unblinded and no other gateway API",
              cand[:1] == [f"127.0.0.1:{STRATUM}"] and "--allow-unblinded" not in cmd and "--gateway-api" not in cmd and cmd[cmd.index("--upstream") + 1] == "auto",
              {"candidates": cand, "command": cmd})
        check("compose: the gateway shares the renter's namespace and publishes nothing",
              dt.get("network_mode") == "service:renter" and not dt.get("ports"), {k: dt.get(k) for k in ("network_mode", "ports", "volumes")})
        cmd[cmd.index("--relays") + 1] = relay
        overlay = {
            "networks": {"default": {"name": NET, "external": True}},
            "services": {
                "app_proxy": {"image": "debian:bookworm-slim", "profiles": ["umbrel-only"]},
                "renter": {"image": IMAGES["renter"], "command": cmd, "volumes": [f"{RUN}:/data/run/signer:ro"]},
                "datum": {"image": IMAGES["datum"]},
                **({"init": {"image": INIT_IMAGE}} if INIT_IMAGE else {}),
            },
        }
        with open(f"{WORK}/overlay.yml", "w") as f:
            yaml.safe_dump(overlay, f, sort_keys=False)
        # the lab wallet's socket, for the renter's user (the image's, xbt-hashrate in the signer's group on a box)
        os.chmod(RUN, 0o711)
        os.chmod(d.SOCK, 0o666)

        # --- init: the compose's own (an xbt-init with the datum component), or its files laid out here
        os.makedirs(f"{DATA}/data/run/hashrate", exist_ok=True)
        if INIT_IMAGE:
            compose(gw, "up", "--no-deps", "init")
            st = layout(True)
        else:
            REPORT.setdefault("skipped", []).append({"check": "init: the datum component", "missing": "an xbt-init that knows `datum` (UMB_INIT_IMAGE)"})
            print("SKIP  init's datum component: laid out here as W5's contract says", flush=True)
            root(f"mkdir -p /d/datum/submitblocks /d/run/datum /d/hashrate && chown {DATUM_UID}:{DATUM_UID} /d/datum /d/datum/submitblocks && chmod 0700 /d/datum /d/datum/submitblocks"
                 f" && chown {UI_UID}:{DATUM_UID} /d/run/datum && chmod 0750 /d/run/datum"
                 f" && printf '%s' 'umbrel:{PASS}' > /d/run/datum/rpc.cookie && chown {DATUM_UID}:{DATUM_UID} /d/run/datum/rpc.cookie && chmod 0600 /d/run/datum/rpc.cookie"
                 f" && chown {HASHRATE_UID}:{HASHRATE_UID} /d/hashrate && chmod 0700 /d/hashrate && chown {UI_UID}:{HASHRATE_UID} /d/run/hashrate && chmod 0750 /d/run/hashrate")
            st = layout(True)
        token = secrets.token_hex(32)
        root(f"printf '%s' '{token}' > /d/run/hashrate/control-token && chown {UI_UID}:{HASHRATE_UID} /d/run/hashrate/control-token && chmod 0640 /d/run/hashrate/control-token")
        want = {f"/d/datum {DATUM_UID} {DATUM_UID} 700", f"/d/datum/submitblocks {DATUM_UID} {DATUM_UID} 700", f"/d/run/datum {UI_UID} {DATUM_UID} 750",
                f"/d/run/datum/rpc.cookie {DATUM_UID} {DATUM_UID} 600"}
        check("init: datum/ and run/datum as the contract says, the cookie the gateway's alone with no newline",
              want <= set(st["stat"]) and not any("\\n" in x for x in st["stat"] if x.startswith("cookie")), st)

        # --- up: the renter, then the gateway in its namespace; no config yet
        compose(gw, "up", "-d", "--no-deps", "renter", "datum")
        rn, dn = cname("renter"), cname("datum")
        ri, di = inspect(rn), inspect(dn)
        rip = next(iter(ri["NetworkSettings"]["Networks"].values()))["IPAddress"]
        # the lab's relay on the renter's loopback (test plumbing; it reaches the host's relay through Forward)
        sh("docker", "run", "-d", "--rm", "--name", FWD, "--network", f"container:{rn}", "-v", f"{HERE}/datum_probe.py:/probe.py:ro", PROBE_IMAGE,
           "python", "-I", "/probe.py", "forward", str(p.RELAY), gw, str(p.RELAY))
        check("compose: the gateway runs in the renter's namespace as its image's user, read-only, no capability, no port",
              di["HostConfig"]["NetworkMode"] == f"container:{ri['Id']}" and di["HostConfig"]["ReadonlyRootfs"] and di["HostConfig"]["CapDrop"] == ["ALL"]
              and not di["HostConfig"].get("PortBindings") and str(di["Config"]["User"]).split(":")[0] in (str(DATUM_UID), "xbt-datum"),
              {"network": di["HostConfig"]["NetworkMode"], "renter": ri["Id"][:12], "user": di["Config"]["User"], "ro": di["HostConfig"]["ReadonlyRootfs"],
               "ports": di["HostConfig"].get("PortBindings")})
        lab.wait("the gateway's first health check", 120, lambda: health(dn) != "starting", every=2)
        idle = probe(f"container:{rn}", "connect", "127.0.0.1", str(STRATUM))
        check("idle: with no config the gateway waits, and the service is healthy", health(dn) == "healthy" and idle.get("open") is False,
              {"health": health(dn), "stratum": idle})

        # --- the Hashrate page's config: solo, to the owner's address (what "Your gateway" writes; no secret)
        rpcurl = env_for(gw)["APP_BITCOIN_NODE_IP"]
        conf = {
            "bitcoind": {"rpcurl": f"http://{rpcurl}:{NODE_RPC}", "rpccookiefile": "/data/run/datum/rpc.cookie", "notify_fallback": True, "work_update_seconds": 5},
            "stratum": {"listen_addr": "127.0.0.1", "listen_port": STRATUM, "fingerprint_miners": False, "vardiff_min": 1},
            "mining": {"pool_address": payout, "coinbase_tag_primary": "Lightning Stream", "coinbase_tag_secondary": "rental",
                       "save_submitblocks_dir": "/data/datum/submitblocks"},
            "api": {"listen_addr": "127.0.0.1", "listen_port": API, "admin_password": "", "xbt_job_allow": "", "modify_conf": False},
            "logger": {"log_to_console": True, "log_to_file": False, "log_level_console": 1},
            "datum": {"pool_host": "", "pooled_mining_only": False},
            "xbt": {"mode": "solo"},
        }
        with open(f"{WORK}/datum-config.json", "w") as f:
            json.dump(conf, f, indent=1)
        sh("docker", "run", "--rm", "--network", "none", "-v", f"{DATA}/data:/d", "-v", f"{WORK}/datum-config.json:/c.json:ro", "debian:bookworm-slim", "sh", "-c",
           f"cp /c.json /d/run/datum/config.json && chown {UI_UID}:{DATUM_UID} /d/run/datum/config.json && chmod 0640 /d/run/datum/config.json")
        lab.wait("the gateway's stratum on the renter's loopback", 120, lambda: probe(f"container:{rn}", "connect", "127.0.0.1", str(STRATUM)).get("open") is True, every=3)

        # --- a miner's job, opened on /xbt/job, in the renter's namespace
        tip = cli("getbestblockhash")
        j = probe(f"container:{rn}", "job", "127.0.0.1", str(STRATUM), str(API))
        REPORT["job_in_namespace"] = j
        o = j.get("opened") if isinstance(j.get("opened"), dict) else {}
        check("node: the gateway took the cookie and reached the node: its job is on the node's tip", o.get("prevblock") == tip,
              {"tip": tip, "job's prevblock": o.get("prevblock"), "error": j.get("error")})
        check("masked: the miner's job is opened on /xbt/job: not the null key, mode solo, clear_bits the share's",
              j.get("code") == 200 and o.get("null_key") is False and o.get("mode") == "solo" and o.get("clear_bits") == 32 + j.get("pot", -99),
              {k: o.get(k) for k in ("mode", "null_key", "clear_bits", "xor_key_hash")} | {"code": j.get("code"), "pot": j.get("pot")})
        # a probe that ran after the gateway started (the health log's last entry, once the interval has passed)
        started = time.time()
        lab.wait("a health check of the running gateway", 120, lambda: time.time() - started > 35 and health(dn) != "starting", every=5)
        last = inspect(dn)["State"]["Health"]["Log"][-1]
        check("node: the healthcheck passes on the running gateway's API", health(dn) == "healthy" and last["ExitCode"] == 0, {"health": health(dn), "last": last})

        # --- loopback only: another container on the app's network, and the host
        other = {port: probe(NET, "connect", rip, str(port)) for port in (API, STRATUM)}
        host = {}
        for port in (API, STRATUM):
            try:
                socket.create_connection((rip, port), 3).close()
                host[port] = {"open": True}
            except OSError as e:
                host[port] = {"open": False, "error": str(e)}
        check("loopback: /xbt/job and the stratum answer in the renter's namespace only (not another container, not the host)",
              j.get("code") == 200 and all(v.get("open") is False for v in [*other.values(), *host.values()]),
              {"in namespace /xbt/job": j.get("code"), "another container": other, "host": host})

        # --- the renter's page
        def status() -> dict[str, Any]:
            return control(rip, token, "GET", "/status")
        s0 = status()
        REPORT["renter_status_first"] = s0
        auto = s0.get("datum", {}).get("addr")
        check("status: --upstream auto settled on the bundled gateway by itself", auto == f"127.0.0.1:{STRATUM}",
              {"datum": s0.get("datum"), "note": "the renter picks its gateway once at its start, before the gateway (which starts after it, in its namespace) listens"})
        if auto != f"127.0.0.1:{STRATUM}":
            # what the owner does on the renter's page ("Found on this box: 127.0.0.1:23339")
            REPORT["renter_datum_set_by_hand"] = control(rip, token, "POST", "/datum", {"addr": f"127.0.0.1:{STRATUM}"})
        lab.wait("the renter's look at its gateway", 90, lambda: (status().get("blinding") or {}).get("state") is not None, every=3)
        s1 = status()
        REPORT["renter_status"] = s1
        check("status: the renter shows its gateway as the bundled one, reachable, its jobs masked (blinded, solo)",
              s1["datum"]["addr"] == f"127.0.0.1:{STRATUM}" and s1["datum"]["reachable"] is True and (s1.get("blinding") or {}).get("state") == "blinded"
              and s1["blinding"].get("why") == "solo" and f"127.0.0.1:{STRATUM}" in s1["datum"]["found"],
              {"datum": s1.get("datum"), "blinding": s1.get("blinding")})

        # --- a masked solo rental through the compose, paid through the wallet
        h0 = int(cli("getblockcount"))
        slice_work = 2**33
        hashmaker = p.spawn("umb-hashmaker", ["hashmaker", "--key", f"{RUN}/keys/hasher.key", "--miners", f"127.0.0.1:{p.MINERS}", "--link", f"{gw}:{p.LINK}",
                                              "--slices", f"127.0.0.1:{p.SLICES}", "--slice-work", str(slice_work), "--price-msat", str(p.PRICE_MSAT), "--grace-ms", "60000",
                                              "--min-slice-s", "1800", "--report", f"{RUN}/umb-hasher.json", "--relays", p.RELAY_URL, "--nostr-key", f"{RUN}/keys/nostr.key",
                                              "--name", "regtest hashmaker", "--link-public", f"{gw}:{p.LINK}", "--pay-url", f"{p.ORIGIN}/hashrate",
                                              "--pay-node", lab.pubkey(d.SELLER), "--hashrate-hs", "60000000", "--listing-out", f"{RUN}/umb-listing.json"])
        lab.wait("the hashmaker's listing", 30, lambda: os.path.exists(f"{RUN}/umb-listing.json"), every=0.2)
        key = subprocess.run([f"{p.BIN}/xbt-hashlink", "pubkey", f"{RUN}/keys/hasher.key"], check=True, capture_output=True, text=True).stdout.strip()

        def offered() -> bool:
            o = control(rip, token, "GET", "/offers?fresh=1").get("offers", [])
            return any(x.get("linkKey") == key for x in o)
        lab.wait("the renter finds the listing on the relay", 90, offered, every=3)
        rent = control(rip, token, "POST", "/rent", {"linkKey": key, "miners": 1, "budgetSats": 1500, "minutes": RENT_MINUTES})
        REPORT["rent"] = rent
        if not rent.get("rental"):
            raise lab.LabError(f"the renter did not rent: {rent}")
        time.sleep(3)
        log = open(f"{RUN}/umb-miner.log", "ab")
        grind = subprocess.Popen(["nice", "-n", "15", f"{HG}/stratum-grind", "--host", "127.0.0.1", "--port", str(p.MINERS), "--user", "hasher.m1"],
                                 stdout=log, stderr=log, env={**os.environ, "LD_LIBRARY_PATH": f"{HG}/lib"})
        p.PROCS.append(grind)

        def rental() -> dict[str, Any]:
            return next((x for x in status().get("rentals", []) if x.get("rental") == rent["rental"]), {})
        lab.wait("the rental to end", RENT_MINUTES * 60 + 300, lambda: rental().get("ended") is True, every=10)
        grind.terminate()
        try:
            hashmaker.wait(120)
        except subprocess.TimeoutExpired:
            hashmaker.terminate()
            hashmaker.wait(30)
        live = rental().get("live", {})
        REPORT["rental_live"] = live
        with open(f"{RUN}/umb-hasher.json") as f:
            hz = json.load(f)
        REPORT["rental_hasher"] = {k: hz.get(k) for k in ("paid", "earnedMsat", "meter", "stopped")}
        h1 = int(cli("getblockcount"))
        blocks = []
        for h in range(h0 + 1, h1 + 1):
            bid = cli("getblockhash", str(h))
            m = p.masked_block(bytes.fromhex(cli("getblockheader", bid, "false")))
            pays = any(v["scriptPubKey"]["hex"] == payout_script for v in json.loads(cli("getblock", bid, "2"))["tx"][0]["vout"])
            blocks.append({"height": h, "block": bid, "pays": pays, "id_is_raw_xor_mask": m["id"] == bid, **{k: m[k] for k in ("key_null", "clear_bits", "raw")}})
        REPORT["rental_blocks"] = blocks
        check("rental: real blocks through the compose, each masked (a key, the share's clear_bits, id = raw XOR mask) and paying the regtest address",
              len(blocks) >= 1 and all(b["pays"] and not b["key_null"] and b["clear_bits"] == 32 and b["id_is_raw_xor_mask"] for b in blocks),
              {"heights": [h0, h1], "payout": payout, "blocks": blocks[:6]})
        meter = live.get("meter", {})
        check("rental: every job held to /xbt/job (solo), shares accepted, none refused",
              int(live.get("jobsShownBlinded", 0)) >= 1 and live.get("blinding") == "solo" and int(meter.get("accepted", 0)) >= 1
              and int(meter.get("rejected", 0)) == 0 and int(meter.get("refused", 0)) == 0,
              {"jobsShownBlinded": live.get("jobsShownBlinded"), "blinding": live.get("blinding"), "meter": meter, "closed": live.get("closed")})
        oks = [x for x in live.get("pays", []) if x.get("ok")]
        priced = sum(int(x["wallet"].get("price_msat", 0)) for x in oks)
        check("rental: paid through the wallet, and the payments = what the hashmaker earned",
              len(oks) >= 1 and not live.get("payFailed") and priced == hz.get("earnedMsat") == hz.get("paid", -1) * p.PRICE_MSAT,
              {"wallet ok": len(oks), "priced": priced, "earned": hz.get("earnedMsat"), "paid": hz.get("paid"), "payFailed": live.get("payFailed")})
        kept = root("ls /d/datum/submitblocks | wc -l").strip()
        check("rental: the found blocks are kept in datum/submitblocks", int(kept or 0) >= len(blocks) >= 1, {"files": kept, "blocks": len(blocks)})

        # --- restart: the renter's container restarted, its gateway still on its loopback?
        sh("docker", "restart", rn)
        lab.wait("the renter's control page after its restart", 60, lambda: bool(status().get("role")), every=2)
        time.sleep(5)
        after = probe(f"container:{rn}", "connect", "127.0.0.1", str(STRATUM))
        s2 = status()
        REPORT["after_renter_restart"] = {"stratum": after, "datum": s2.get("datum"), "blinding": s2.get("blinding"), "gateway state": inspect(dn)["State"]["Status"]}
        check("restart: after a restart of the renter, its gateway is still on its loopback", after.get("open") is True and s2["datum"]["reachable"] is True,
              REPORT["after_renter_restart"])
        # the gateway's container joins the renter's namespace as it is when it starts: a restart of it is the way back
        sh("docker", "restart", dn)
        lab.wait("the gateway after its own restart", 90, lambda: probe(f"container:{rn}", "connect", "127.0.0.1", str(STRATUM)).get("open") is True, every=3)
        # the renter looks again once its last look is a minute old
        until = time.time() + 150
        s3 = status()
        while time.time() < until and (s3.get("blinding") or {}).get("state") != "blinded":
            time.sleep(10)
            s3 = status()
        REPORT["after_gateway_restart"] = {"datum": s3.get("datum"), "blinding": s3.get("blinding")}
        check("restart: a restart of the gateway's container puts it back on the renter's loopback, its jobs masked",
              s3["datum"]["reachable"] is True and (s3.get("blinding") or {}).get("state") == "blinded", REPORT["after_gateway_restart"])
    except (lab.LabError, OSError, KeyError, IndexError, ValueError, TypeError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        check("ran to its end", False, f"{type(e).__name__}: {e}")
    finally:
        for x in (grind, hashmaker):
            if x is not None and x.poll() is None:
                x.terminate()
        if gw:
            sh("docker", "rm", "-f", FWD, check_rc=False)
            for svc in ("renter", "datum", "init"):
                r = sh("docker", "logs", "--timestamps", cname(svc), check_rc=False)
                with open(f"{OUT}/umbrel_datum_{svc}.log", "w") as f:
                    f.write(r.stdout + r.stderr)
            compose(gw, "down", "--volumes", "--timeout", "10", check_rc=False)
            sh("docker", "network", "rm", NET, check_rc=False)
        if cli is not None:
            sh(f"{HG}/bitcoin-cli", f"-datadir={RUN}/node", "stop", env={**os.environ, "LD_LIBRARY_PATH": f"{HG}/lib"}, check_rc=False)
        if os.path.isdir(DATA):
            # the data dir holds files of the services' users: removed as root
            sh("docker", "run", "--rm", "--network", "none", "-v", f"{WORK}:/a", "debian:bookworm-slim", "rm", "-rf", "/a/app-data", check_rc=False)
        for x in p.PROCS + list(d.PROCS.values()):
            if x.poll() is None:
                x.terminate()
    REPORT["seconds"] = round(time.time() - t0)
    with open(os.path.join(OUT, "umbrel_datum_regtest.json"), "w") as f:
        json.dump(REPORT, f, indent=1)
    ok = all(c["ok"] for c in REPORT["checks"])
    print(f"umbrel_datum_regtest: {sum(c['ok'] for c in REPORT['checks'])} of {len(REPORT['checks'])} checks passed, "
          f"{len(REPORT.get('skipped', []))} skipped, {REPORT['seconds']} s", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
