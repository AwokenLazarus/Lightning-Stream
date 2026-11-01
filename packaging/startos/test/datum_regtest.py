#!/usr/bin/env python3
"""The StartOS package's Stream Gateway (the `datum` daemon) and its hashtaker, run the way StartOS runs them, against
a Knots BLAKE2b regtest node, with a masked solo rental to the end (test/datum_regtest.sh builds the images and runs
this).

What is the package's own: the init, datum and hashtaker containers' commands, users, env and mounts, from
lightning-stream/startos/spec.ts (test/spec-json.mjs prints it); one network namespace for them (StartOS runs a
package's subcontainers in one LXC container); the `main` volume root-owned and empty at install; init a oneshot
before the daemons. What stands in for the box:
  * the node is the lab's Knots BLAKE2b (P2P_HASH_GATEWAYS/bitcoind), regtest, on the test network's bridge address:
    the Node connection action's values (host, port, user, password);
  * the Hashrate page's "Your gateway" (W5): this writes run/datum/config.json as the UI does (mg-contract.md:
    0640, 10005:10021, no secret, the node's RPC URL from XBT_UI_DATUM_RPCURL);
  * xbt-init's `datum` component (W5): when this tree's xbt-init doesn't know it yet, init runs without it and this
    makes what the component makes (datum/, datum/submitblocks/, run/datum/ 0750 10005:10021, run/datum/rpc.cookie
    `user:password` 0600 10021), and says so in results.json;
  * the seller: another box, its own namespace, a hashmaker (this tree's, as the regtest drivers run it) publishing its
    listing to a stand-in Nostr relay, and the lab's stratum-grind as its miner;
  * no wallet: the hashtaker runs without --signer (the wallet's rail is the ticket regtests' and the p2p_hash
    regtest's), and the seller's grace is long, so the rental's work flows unpaid. Every other flag is the spec's;
    --relays names the stand-in relay.

Checks (results.json):
  S  the spec: the daemon, its mounts, the hashtaker's candidates and --gateway-api, never --allow-unblinded
  I  init on the root-owned volume; the cookie and folders as the contract says
  D  the gateway: idle (and healthy) before its config; started by the config; reaches the node through the cookie
     (Stratum listens only once the node gave it a template); its readyCommand passes
  L  /xbt/job and Stratum on loopback only: inside the package /xbt/job answers (404 for an unknown job, not 403);
     from the network neither the API nor Stratum can be reached
  N  the renter doesn't wait for the gateway: its page is live and says in words what the gateway is doing, with no
     config yet ("not running") and with the node unreachable ("waiting for the node"; W5's renter)
  R  the renter: --upstream auto picks 127.0.0.1:23339; its status says the jobs are masked ("blinded", solo)
  M  a masked solo rental: real blocks reach the node through the rental, each with a key, its id the raw hash XOR the
     mask; each coinbase pays the regtest payout address; the hashtaker held each job to /xbt/job; the gateway kept
     each submitted block on disk
    datum_regtest.py OUT
"""
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(os.path.dirname(HERE), "lightning-stream")
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from regtest_lib import check, docker, log, open_log, sh, wait_until, write_results  # noqa: E402

OUT = sys.argv[1]
HG = os.environ["HG"]
IMG = {"datum": os.environ["DATUM_IMAGE"], "hashlink": os.environ["HASHLINK_IMAGE"], "init": os.environ["INIT_IMAGE"]}
PROBE = os.environ["PROBE_IMAGE"]
P = f"s9datum-{os.getpid()}"
NET, VOL, SVOL = f"{P}-net", f"{P}-main", f"{P}-seller"
MINERS = int(os.environ.get("STARTOS_DATUM_MINERS_PORT", "24190"))
RPC = int(os.environ.get("STARTOS_DATUM_RPC_PORT", "24191"))
RPC_PASS = secrets.token_hex(16)
UID_UI, UID_DATUM = 10005, 10021
RENT_MINUTES = int(os.environ.get("STARTOS_DATUM_RENT_MINUTES", "4"))
NODE_DIR = os.path.join(OUT, "node")
open_log(os.path.join(OUT, "datum_regtest.log"))
FACTS = {}


def spec(rpc_host):
    cfg = {"node": {"host": rpc_host, "port": RPC, "user": "lab", "password": RPC_PASS, "chain": "regtest"},
           "mcpUrls": [], "lightningRest": "", "proxies": [], "lanHost": ""}
    js = ["node", "--experimental-strip-types", "--no-warnings", "test/spec-json.mjs", json.dumps(cfg)]
    if not shutil.which("node"):
        # no node on the lab: the same command in a node image, on the package's sources read-only
        js = ["docker", "run", "--rm", "--network", "none", "-v", f"{PKG}:/p:ro", "-w", "/p", "node:22-slim", *js]
    r = subprocess.run(js, cwd=PKG, capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def run_service(s, image, command=None, name=None):
    """One subcontainer as StartOS makes it: the image's user (or the spec's), the spec's mounts of `main`."""
    args = ["run", "-d", "--name", name or f"{P}-{s['id']}", "--network", f"container:{P}-ns", "--restart", "no"]
    if s.get("user"):
        args += ["--user", "0:0" if s["user"] == "root" else s["user"]]
    for k, v in s["env"].items():
        args += ["-e", f"{k}={v}"]
    for m in s["mounts"]:
        assert not m.get("dependency"), m
        mnt = f"type=volume,src={VOL},dst={m['mountpoint']},volume-nocopy=true"
        if m["subpath"]:
            mnt += f",volume-subpath={m['subpath']}"
        if m["readonly"]:
            mnt += ",readonly"
        args += ["--mount", mnt]
    cmd = command or s["command"]
    args += ["--entrypoint", cmd[0], image, *cmd[1:]]
    return docker(*args)


def vol(script):
    """Root on the `main` volume (the auditor's view, and the stand-in for what W5's init and UI write)."""
    return docker("run", "--rm", "--network", "none", "--mount", f"type=volume,src={VOL},dst=/v,volume-nocopy=true", PROBE, "sh", "-c", script)


def in_pkg(*cmd, check_rc=False):
    """A command inside the package's network namespace (another of its services would be here)."""
    return docker("run", "--rm", "--network", f"container:{P}-ns", PROBE, *cmd, check_rc=check_rc)


def outside(*cmd, check_rc=False):
    """A command from another container on the network: what a hashmaker, or anything on the LAN, could try."""
    return docker("run", "--rm", "--network", NET, PROBE, *cmd, check_rc=check_rc)


def cli(*a):
    env = {**os.environ, "LD_LIBRARY_PATH": f"{HG}/lib"}
    r = subprocess.run([f"{HG}/bitcoin-cli", f"-datadir={NODE_DIR}", *a], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {a[:2]}: {r.stderr.strip()[-300:]}")
    return r.stdout.strip()


def control(method, path, body=None):
    """The hashtaker's control API, as the UI calls it (its token from run/hashrate/control-token)."""
    tok = FACTS["control_token_mount"]
    args = ["sh", "-c", f'curl -s -m 60 -X {method} -H "Authorization: Bearer $(cat /t/control-token)" '
                        + ("-H 'Content-Type: application/json' --data @/dev/stdin " if body is not None else "") + f"http://127.0.0.1:23343{path}"]
    r = docker("run", "--rm", "-i", "--network", f"container:{P}-ns", "--mount", tok, PROBE, *args,
               input=json.dumps(body) if body is not None else None, check_rc=False)
    try:
        return json.loads(r.stdout)
    except ValueError:
        return {"raw": r.stdout[-500:], "err": r.stderr[-300:]}


def tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def masked_block(header):
    """From a 164-byte v2 header, as the node's own stages (scripts/p2p_hash/regtest.py): raw hash, mask, block id."""
    key, flags, clear = header[112:128], header[110], header[111]
    prev = header[4:36][::-1]
    mask = bytearray(tagged("Bitcoin block hash PoW XOR mask", key))
    whole = clear // 8
    mask[:whole] = bytes(whole)
    if whole < 32:
        mask[whole] &= 0xFF >> (clear % 8)
    if not any(key):
        mask = bytearray(32)
    h1 = tagged("Bitcoin block header 1", header[:4] + prev + header[128:132] + header[36:68] + header[68:72] + b"\0" + header[72:76]
                + header[108:110] + bytes(2) + bytes((flags, clear)) + tagged("Bitcoin block hash PoW XOR key", key))
    h2 = tagged("Merge-mining hook", h1 + bytes(32) + header[132:164])
    root = hashlib.blake2b(bytes(4) + h2 + header[88:104], digest_size=32).digest()
    hidden = bytearray(tagged("Bitcoin prevblock header, hashed", prev))
    hidden[:6] = bytes(6)
    raw = hashlib.blake2b(bytes(hidden) + header[76:84] + header[104:108] + header[84:88] + root, digest_size=32).digest()
    return {"key_null": not any(key), "clear_bits": clear, "raw": raw.hex(), "id": bytes(a ^ b for a, b in zip(raw, mask)).hex()}


def node_up(gw, subnet):
    """The node's RPC on the test network's bridge address (the containers' way in: the host's own connection to that
    address is refused as from outside the subnet) and on 127.0.0.1 for this script's bitcoin-cli."""
    os.makedirs(NODE_DIR, exist_ok=True)
    with open(os.path.join(NODE_DIR, "bitcoin.conf"), "w") as f:
        f.write("regtest=1\nserver=1\nlistenonion=0\ndiscover=0\ndnsseed=0\nfixedseeds=0\nfallbackfee=0.0002\ntxindex=1\nblake2b_headline=Lazarus\n"
                f"[regtest]\nlisten=0\nrpcbind={gw}\nrpcbind=127.0.0.1\nrpcallowip={subnet}\nrpcallowip=127.0.0.1\nrpcport={RPC}\nrpcuser=lab\nrpcpassword={RPC_PASS}\n"
                "testactivationheight=blake2b@101\nmaxtipage=315360000\n")
    os.chmod(os.path.join(NODE_DIR, "bitcoin.conf"), 0o600)
    sh(f"{HG}/bitcoind", f"-datadir={NODE_DIR}", "-daemon", env={**os.environ, "LD_LIBRARY_PATH": f"{HG}/lib"})
    wait_until(lambda: cli("getblockcount") != "", 60, "the node's RPC")


def cleanup():
    for c in ("hashtaker", "datum", "hashmaker", "fwd-ns", "fwd-seller", "relay", "ns", "seller", "init"):
        r = docker("logs", f"{P}-{c}", check_rc=False)
        if r.returncode == 0:
            with open(os.path.join(OUT, f"{c}.log"), "w") as f:
                f.write(r.stdout + r.stderr)
        docker("rm", "-f", f"{P}-{c}", check_rc=False)
    for v in (VOL, SVOL):
        docker("volume", "rm", "-f", v, check_rc=False)
    docker("network", "rm", NET, check_rc=False)
    try:
        cli("stop")
    except Exception:  # noqa: BLE001
        subprocess.run(["pkill", "-f", f"-datadir={NODE_DIR}"], capture_output=True)


def main():
    docker("network", "create", NET)
    ipam = json.loads(docker("network", "inspect", NET).stdout)[0]["IPAM"]["Config"][0]
    gw, subnet = ipam["Gateway"], ipam["Subnet"]
    sp = spec(gw)
    by = {s["id"]: s for s in sp["services"]}
    d, ht = by["datum"], by["hashtaker"]["command"]
    arg = lambda c, f: c[c.index(f) + 1] if f in c else None  # noqa: E731
    check("S", "the spec: the datum daemon on its image's user, its own folder and run/datum read-only, started by the config and "
               "restarted by the cookie; the hashtaker tries 127.0.0.1:23339 first, checks jobs on 127.0.0.1:7152, doesn't wait for "
               "the gateway; nothing runs with --allow-unblinded",
          d["image"] == "datum" and not d.get("user")
          and [(m["subpath"], m["readonly"]) for m in d["mounts"]] == [("datum", False), ("run/datum", True)]
          and d["command"][:6] == ["/usr/bin/xbt-supervise", "--wait", "/data/run/datum/config.json", "--watch", "/data/run/datum/rpc.cookie", "--"]
          and arg(ht, "--datum-candidates").split(",")[0] == "127.0.0.1:23339" and arg(ht, "--gateway-api") == "127.0.0.1:7152"
          and arg(ht, "--upstream") == "auto" and "datum" not in by["hashtaker"]["requires"]
          and not any("--allow-unblinded" in s["command"] for s in sp["services"]),
          {"datum": d, "hashtaker": ht})

    log("== the node: Knots BLAKE2b regtest on the test network's bridge address")
    node_up(gw, subnet)
    cli("createwallet", "w")
    funding = cli("-rpcwallet=w", "getnewaddress", "", "bech32")
    cli("-rpcwallet=w", "generatetoaddress", "220", funding)
    # the gateway reads a bech32 address only under mainnet and testnet prefixes: a solo block pays a legacy one here
    payout = cli("-rpcwallet=w", "getnewaddress", "", "legacy")
    payout_script = json.loads(cli("-rpcwallet=w", "getaddressinfo", payout))["scriptPubKey"]
    FACTS.update(payout=payout, payout_script=payout_script, node=f"{gw}:{RPC}")

    log("== install: main root-owned and empty; init (the spec's), then the gateway")
    docker("volume", "create", VOL)
    docker("run", "-d", "--name", f"{P}-ns", "--network", NET, "debian:bookworm-slim", "sleep", "infinity")
    init = by["init"]
    run_service(init, IMG["init"])
    code = int(docker("wait", f"{P}-init").stdout.strip())
    rep = (docker("logs", f"{P}-init").stdout.strip().splitlines() or ["{}"])[-1]
    # the package's own init makes the datum component's files: never emulated here, so the test covers the package as
    # it ships (an init that doesn't know `datum` fails the check below)
    FACTS["init_datum_component"] = "xbt-init"
    ls = vol("stat -c '%u:%g %a %n' /v/datum /v/datum/submitblocks /v/run/datum /v/run/datum/rpc.cookie; "
             "wc -c < /v/run/datum/rpc.cookie; tail -c1 /v/run/datum/rpc.cookie | od -An -c").stdout.split("\n")
    auth = init["env"]["XBT_INIT_NODE_RPC_AUTH"]
    check("I", f"init exits 0; the datum folders and the cookie as the contract says (user:password, no newline, 0600 xbt-datum); "
               f"datum component: {FACTS['init_datum_component']}",
          code == 0 and ls[:4] == [f"{UID_DATUM}:{UID_DATUM} 700 /v/datum", f"{UID_DATUM}:{UID_DATUM} 700 /v/datum/submitblocks",
                                   f"{UID_UI}:{UID_DATUM} 750 /v/run/datum", f"{UID_DATUM}:{UID_DATUM} 600 /v/run/datum/rpc.cookie"]
          and ls[4].strip() == str(len(auth)) and "\\n" not in ls[5],
          {"rc": code, "stat": ls[:4], "report": rep[-400:]})

    run_service(d, IMG["datum"])
    time.sleep(5)
    ready = lambda: docker("exec", f"{P}-datum", *d["readyCommand"], check_rc=False).returncode == 0  # noqa: E731
    api_open = lambda: in_pkg("bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/7152").returncode == 0  # noqa: E731
    stratum_open = lambda: in_pkg("bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/23339").returncode == 0  # noqa: E731
    running = json.loads(docker("inspect", f"{P}-datum").stdout)[0]["State"]["Running"]
    check("D", "before Services → Hashrate writes its config the gateway waits, idle and healthy (its readyCommand passes; nothing listens)",
          running and ready() and not api_open() and not stratum_open(),
          {"running": running})

    log("== the renter starts at once: it doesn't wait for the gateway (the stand-in relay; no wallet: no --signer)")
    docker("run", "-d", "--name", f"{P}-relay", "--network", NET, "--network-alias", "relay", "--entrypoint", "/usr/bin/xbt-hashlink", IMG["hashlink"],
           "relay", "--listen", "0.0.0.0:7777")
    # a Nostr client takes plain ws:// only to its own machine: each namespace reaches the stand-in relay through a
    # loopback forwarder (test-only; on a box the relays are wss://)
    docker("run", "-d", "--name", f"{P}-fwd-ns", "--network", f"container:{P}-ns", PROBE,
           "socat", "TCP-LISTEN:7777,bind=127.0.0.1,fork,reuseaddr", "TCP:relay:7777")
    cmd = list(ht)
    cmd[cmd.index("--relays") + 1] = "ws://127.0.0.1:7777"
    i = cmd.index("--signer")
    del cmd[i:i + 2]
    FACTS["hashtaker_command"] = cmd
    FACTS["control_token_mount"] = f"type=volume,src={VOL},dst=/t,volume-subpath=run/hashrate,readonly,volume-nocopy=true"
    run_service(by["hashtaker"], IMG["hashlink"], command=cmd)
    wait_until(lambda: control("GET", "/status").get("role") == "renter", 60, "the hashtaker's control API")
    bundled_state = lambda st: (st.get("bundled") or {}).get("state")  # noqa: E731
    st = control("GET", "/status")
    FACTS["status_no_config"] = st
    check("N", "with the gateway not set up yet the renter's page is live, on the bundled gateway, and says it isn't running "
               "(W5's renter: its `bundled` state)",
          st.get("role") == "renter" and st["datum"]["addr"] == "127.0.0.1:23339" and bundled_state(st) == "not running", st)

    def write_config(conf):
        docker("run", "--rm", "-i", "--network", "none", "--mount", f"type=volume,src={VOL},dst=/v,volume-nocopy=true", PROBE, "sh", "-c",
               f"cat > /v/run/datum/config.json.tmp && chown {UID_UI}:{UID_DATUM} /v/run/datum/config.json.tmp && chmod 640 /v/run/datum/config.json.tmp "
               "&& mv /v/run/datum/config.json.tmp /v/run/datum/config.json", input=json.dumps(conf))

    conf = {"bitcoind": {"rpccookiefile": "/data/run/datum/rpc.cookie", "rpcurl": by["ui"]["env"]["XBT_UI_DATUM_RPCURL"], "work_update_seconds": 5,
                         "notify_fallback": True},
            "stratum": {"listen_addr": "127.0.0.1", "listen_port": 23339, "vardiff_min": 1, "fingerprint_miners": False},
            "mining": {"pool_address": payout, "coinbase_tag_primary": "Stream", "coinbase_tag_secondary": "rental",
                       "save_submitblocks_dir": "/data/datum/submitblocks"},
            "api": {"listen_addr": "127.0.0.1", "listen_port": int(by["ui"]["env"]["XBT_UI_DATUM_API_PORT"]), "admin_password": "", "modify_conf": False,
                    "xbt_job_allow": ""},
            "logger": {"log_to_console": True, "log_to_file": False, "log_level_console": 2},
            "datum": {"pool_host": "", "pooled_mining_only": False},
            "xbt": {"mode": "solo"}}
    with open(os.path.join(OUT, "datum-config.json"), "w") as f:
        json.dump(conf, f, indent=1)

    log("== the node can't be reached: the gateway set up with a node address nothing answers on")
    dead = json.loads(json.dumps(conf))
    dead["bitcoind"]["rpcurl"] = f"http://{gw}:{RPC + 7}"
    write_config(dead)
    try:
        wait_until(lambda: bundled_state(control("GET", "/status")) == "waiting for the node", 120, "the renter's page saying the gateway waits for the node")
    except RuntimeError as e:
        log(f"  {e}")
    st = control("GET", "/status")
    FACTS["status_node_unreachable"] = st
    check("N", "with the node unreachable the gateway runs (its API answers, its readyCommand passes) but serves no work (no Stratum: the "
               "dashboard says it waits for a block template), and the renter's page stays live and says in words that it waits for the node",
          api_open() and ready() and not stratum_open() and st.get("role") == "renter" and bundled_state(st) == "waiting for the node"
          and not (st.get("bundled") or {}).get("masking"),
          {"bundled": st.get("bundled"), "datum": st.get("datum"), "blinding": st.get("blinding")})

    log("== the Hashrate page's \"Your gateway\": solo, paid to the regtest address, the Node connection action's node (as the UI writes it)")
    write_config(conf)
    t0 = time.time()
    try:
        wait_until(lambda: stratum_open() and api_open(), 120, "the gateway's Stratum and API")
    except RuntimeError as e:
        log(f"  {e}")
    dt = round(time.time() - t0, 1)
    glog = docker("logs", f"{P}-datum", check_rc=False)
    glog = glog.stdout + glog.stderr
    check("D", "the config (rewritten) restarts it (xbt-supervise); it reaches the node through init's cookie: a block template, then Stratum on "
               "127.0.0.1:23339 and the API on 127.0.0.1:7152; its readyCommand passes",
          stratum_open() and api_open() and ready(),
          {"seconds": dt, "log tail": glog[-1500:]})

    ns_ip = json.loads(docker("inspect", f"{P}-ns").stdout)[0]["NetworkSettings"]["Networks"][NET]["IPAddress"]
    inside = in_pkg("curl", "-s", "-m", "5", "-w", "\n%{http_code}", "http://127.0.0.1:7152/xbt/job?id=nosuchjob&pot=0")
    out_api = outside("curl", "-s", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", f"http://{ns_ip}:7152/xbt/job?id=nosuchjob&pot=0")
    out_st = outside("bash", "-c", f"exec 3<>/dev/tcp/{ns_ip}/23339")
    check("L", "/xbt/job answers inside the package (an unknown job is 404, not 403: loopback is an allowed caller); from the network "
               "neither the API nor Stratum can be reached",
          inside.stdout.strip().endswith("404") and "unknown job" in inside.stdout and out_api.returncode == 7 and out_st.returncode != 0,
          {"inside": inside.stdout[-200:], "outside api rc": out_api.returncode, "outside api code": out_api.stdout, "outside stratum rc": out_st.returncode})

    log("== the seller: a stand-in Nostr relay, a hashmaker in a namespace of its own, stratum-grind as its miner")
    docker("volume", "create", SVOL)
    docker("run", "-d", "--name", f"{P}-seller", "--network", NET, "--network-alias", "seller", "-p", f"127.0.0.1:{MINERS}:23340",
           "debian:bookworm-slim", "sleep", "infinity")
    docker("run", "-d", "--name", f"{P}-fwd-seller", "--network", f"container:{P}-seller", PROBE,
           "socat", "TCP-LISTEN:7777,bind=127.0.0.1,fork,reuseaddr", "TCP:relay:7777")
    for k in ("hasher", "nostr"):
        docker("run", "--rm", "--user", "0:0", "-v", f"{SVOL}:/d", "--entrypoint", "/usr/bin/xbt-hashlink", IMG["hashlink"], "keygen", f"/d/{k}.key")
    docker("run", "-d", "--name", f"{P}-hashmaker", "--network", f"container:{P}-seller", "--user", "0:0", "-v", f"{SVOL}:/d",
           "--entrypoint", "/usr/bin/xbt-hashlink", IMG["hashlink"],
           "hashmaker", "--key", "/d/hasher.key", "--miners", "0.0.0.0:23340", "--link", "0.0.0.0:23341", "--slices", "127.0.0.1:23344",
           "--slice-work", str(2**33), "--price-msat", "100000", "--grace-ms", "900000", "--min-slice-s", "1800", "--report", "/d/hasher.json",
           "--relays", "ws://127.0.0.1:7777", "--nostr-key", "/d/nostr.key", "--name", "regtest hashmaker", "--link-public", "seller:23341",
           "--pay-url", "http://seller:9/hashrate", "--pay-node", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
           "--hashrate-hs", "60000000", "--listing-out", "/d/listing.json")
    wait_until(lambda: docker("run", "--rm", "-v", f"{SVOL}:/d", PROBE, "test", "-s", "/d/listing.json", check_rc=False).returncode == 0, 60,
               "the hashmaker's listing")

    log("== the renter, once the gateway has work")
    # its last look (at the gateway with no node) is redone after a minute
    try:
        wait_until(lambda: (control("GET", "/status").get("blinding") or {}).get("state") == "blinded", 150, "the renter's look at its gateway")
    except RuntimeError as e:
        log(f"  {e}")
    st = control("GET", "/status")
    FACTS["status_before"] = st
    check("R", "the renter is on the bundled gateway (127.0.0.1:23339), and its status says the jobs are masked (blinded, solo; the bundled "
               "gateway's state: masking)",
          st["datum"]["addr"] == "127.0.0.1:23339" and st["datum"]["reachable"] and (st.get("blinding") or {}).get("state") == "blinded"
          and st["blinding"]["why"] == "solo" and bundled_state(st) == "masking", st)

    log("== a masked solo rental")
    offers = wait_until(lambda: control("GET", "/offers?fresh=1").get("offers"), 90, "the hashmaker's listing at the renter")
    h0 = int(cli("getblockcount"))
    rent = control("POST", "/rent", {"linkKey": offers[0]["linkKey"], "budgetSats": 5000, "minutes": RENT_MINUTES, "miners": 1})
    FACTS["rent"] = rent
    grind = None
    try:
        if rent.get("ok"):
            time.sleep(3)
            glog_f = open(os.path.join(OUT, "miner.log"), "ab")
            grind = subprocess.Popen(["nice", "-n", "15", f"{HG}/stratum-grind", "--host", "127.0.0.1", "--port", str(MINERS), "--user", "hasher.m1"],
                                     stdout=glog_f, stderr=glog_f, env={**os.environ, "LD_LIBRARY_PATH": f"{HG}/lib"})
            try:
                wait_until(lambda: int(cli("getblockcount")) >= h0 + 2, 360, "two blocks through the rental")
            except RuntimeError as e:
                log(f"  {e}")
            time.sleep(5)
    finally:
        if grind:
            grind.terminate()
            grind.wait(10)
    status = control("GET", "/status")
    FACTS["status_after"] = status
    live = next((x.get("live") or {} for x in status.get("rentals", []) if x.get("rental") == rent.get("rental")), {})
    if rent.get("ok"):
        control("POST", "/cut", {"rental": rent["rental"]})
    h1 = int(cli("getblockcount"))
    blocks = []
    for h in range(h0 + 1, h1 + 1):
        bid = cli("getblockhash", str(h))
        m = masked_block(bytes.fromhex(cli("getblockheader", bid, "false")))
        cb = json.loads(cli("getblock", bid, "2"))["tx"][0]
        pays = [o for o in cb["vout"] if o["scriptPubKey"]["hex"] == payout_script]
        blocks.append({"height": h, "block": bid, **m, "id_is_raw_xor_mask": m["id"] == bid, "pays_payout_sat": round(sum(o["value"] for o in pays) * 1e8)})
    FACTS["blocks"] = blocks
    check("M", "the rental runs (no --allow-unblinded) and real blocks reach the node through it, each masked: a key, and its id the raw "
               "hash XOR the mask",
          bool(rent.get("ok")) and len(blocks) >= 1 and all(not b["key_null"] and b["id_is_raw_xor_mask"] for b in blocks),
          {"rent": rent, "height": [h0, h1], "blocks": blocks})
    check("M", f"each block's coinbase pays the solo payout address, a regtest address ({payout[:8]}...)",
          bool(blocks) and all(b["pays_payout_sat"] > 0 for b in blocks), {"address": payout, "script": payout_script, "blocks": blocks})
    check("M", "the hashtaker held the rental's jobs to what the gateway opened on /xbt/job (jobs shown masked, none refused)",
          int(live.get("jobsShownBlinded") or 0) >= 1,
          {k: live.get(k) for k in ("jobsShownBlinded", "blinding", "closed", "meter")})
    kept = vol("ls /v/datum/submitblocks | wc -l").stdout.strip()
    check("M", "the gateway kept each block it submitted on the package volume (datum/submitblocks)", blocks and int(kept or 0) >= len(blocks),
          {"files": kept, "blocks": len(blocks)})


if __name__ == "__main__":
    ok = False
    try:
        main()
    except Exception as e:  # noqa: BLE001
        check("X", "the run finished", False, repr(e))
    finally:
        with open(os.path.join(OUT, "facts.json"), "w") as f:
            json.dump(FACTS, f, indent=1, default=str)
        cleanup()
        ok = write_results(OUT)
    sys.exit(0 if ok else 1)
