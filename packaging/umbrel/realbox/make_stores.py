#!/usr/bin/env python3
"""The two community stores a real umbrelOS 2.0 test box adds, for a regtest run of the wallet and the gateway.

    make_stores.py OUT REGISTRY       e.g. make_stores.py run/realbox/stores 127.0.0.1:34850

Writes OUT/lazarus.git and OUT/paulscode.git, bare repositories (`git update-server-info`ed) for umbrelOS's
"add community app store" (serve them with serve_git.py). umbrelOS lists only apps whose id starts with the
store's id, so the apps of another author live in a store of that author's id.

OUT/lazarus: the wallet and the gateway of packaging/umbrel, changed only in this:
  * every image is REGISTRY/<image>:<tag>: umbreld `docker pull`s every image of an app on install, so a
    `docker load`ed image fails ("pull access denied"); the box reaches REGISTRY (a registry on loopback,
    tunnelled). The store pins the published images by digest; here the digest is dropped, because an image
    pushed to REGISTRY one platform at a time has a manifest of its own (packaging/umbrel/bundle.sh);
  * the wallet's signer runs in the gateway's network namespace, as in the off-box test overlay
    (regtest/lazarus-xbt-agent-wallet.yml): the wallet pays tickets over https or to its own machine only,
    and trusts only public certificate authorities, so on one box with no public https name the buyer
    reaches the seller at http://127.0.0.1:8402;
  * the store's name says it is a regtest test profile. The stand-in node app lazarus-xbt-knots is left out:
    it follows mainnet, and the wallet takes the `bitcoin` slot first, which the stand-in below fills.

OUT/paulscode: regtest stand-ins for the apps of Lightning Fork's author the packages depend on (his own
apps follow mainnet only), with the ids, the static addresses, the ports and the export names of his apps:
  * paulscode-knots-blake2b: the Lightning lab's Knots BLAKE2b on regtest (BLAKE2b from height 20), with
    ZMQ and txindex; `implements: [bitcoin]` and exports APP_BITCOIN_* as his Companion does;
  * paulscode-lightning-fork: the lab's Lightning Fork build on regtest: the buyer's node. Exports
    APP_LIGHTNING_FORK_NODE_IP / _NODE_REST_PORT / _NODE_DATA_DIR (tls.cert in data/lnd) as his app does;
  * paulscode-lightning-fork-seller: a second Lightning Fork, the seller's node, which `implements`
    paulscode-lightning-fork with the same export names, so the gateway selects it in umbrelOS's dependency
    picker (one box plays two boxes: the buyer's node pays the seller's over one channel). It also runs the
    seller's service, a stock file server (www) that knows nothing of payments.
None of them has a dashboard (the owner's macaroons are baked with lncli), Tor, or a host port.
"""
import os
import shutil
import subprocess
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
UMBREL = os.path.dirname(HERE)
PAGE = "a small page, sold per request\n" * 8  # packaging/ln_lab.py's PAGE: what the buyer checks it got
LF_IMAGE, KNOTS_IMAGE, WWW_IMAGE = "lightning-fork:dev", "knots-blake2b:final-zmq", "python:3-alpine"
SITE = "https://github.com/AwokenLazarus/Lightning-Stream"


def git(*a, cwd):
    subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)


def dump(path, obj, head=""):
    with open(path, "w") as f:
        f.write(head + yaml.safe_dump(obj, sort_keys=False, width=200))


def edit_compose(path, fn):
    # keep the header comments; umbreld re-serialises the file on install anyway
    head = "".join(ln for ln in open(path) if ln.startswith("#"))
    c = yaml.safe_load(open(path))
    fn(c)
    dump(path, c, head)


def publish(store, out, name):
    git("init", "-q", "-b", "master", cwd=store)
    git("add", "-A", cwd=store)
    git("-c", "user.name=realbox", "-c", "user.email=realbox@localhost", "commit", "-q", "-m", f"{name} store", cwd=store)
    bare = os.path.join(out, f"{name}.git")
    git("clone", "-q", "--bare", store, bare, cwd=out)
    git("update-server-info", cwd=bare)
    return bare


def lazarus(out, reg):
    store = os.path.join(out, "lazarus")
    os.makedirs(store)
    with open(os.path.join(store, "umbrel-app-store.yml"), "w") as f:
        f.write('# regtest test profile of packaging/umbrel (made by realbox/make_stores.py)\nid: "lazarus"\nname: "Lazarus (regtest test profile)"\n')
    for app in ("lazarus-xbt-agent-wallet", "lazarus-lightning-stream-gateway"):
        shutil.copytree(os.path.join(UMBREL, app), os.path.join(store, app))

        def change(c, app=app):
            for s in c["services"].values():
                if "image" in s:
                    # the pinned ghcr.io reference as REGISTRY/<image>:<tag>, the digest dropped as bundle.sh does
                    s["image"] = f"{reg}/{s['image'].split('@')[0].rsplit('/', 1)[-1]}"
            if app == "lazarus-xbt-agent-wallet":
                c["services"]["signer"]["network_mode"] = "container:lazarus-lightning-stream-gateway_gateway_1"
        edit_compose(os.path.join(store, app, "docker-compose.yml"), change)
    return publish(store, out, "lazarus")


def manifest(app_id, name, tagline, port, deps, implements=None):
    m = {"manifestVersion": 1.1, "id": app_id, "category": "bitcoin", "name": name, "version": "0.0.1-regtest", "tagline": tagline,
         "description": f"{tagline}. A regtest stand-in for a package test; not the author's app.", "developer": "Lazarus (stand-in)",
         "website": SITE, "repo": SITE, "support": SITE + "/issues", "port": port, "gallery": [], "path": "",
         "releaseNotes": "", "dependencies": deps, "defaultUsername": "", "defaultPassword": "", "submitter": "Lazarus", "submission": SITE}
    if implements:
        m["implements"] = implements
    return m


def lnd_service(alias, ip_var):
    return {
        "image": None,  # set below
        "user": "1000:1000",
        "restart": "on-failure",
        "stop_grace_period": "1m",
        "entrypoint": ["/usr/local/bin/lnd"],
        "command": ["--lnddir=/data/.lnd", "--noseedbackup", "--bitcoin.regtest", "--bitcoin.node=bitcoind",
                    "--bitcoin.blake2b-activation-height=20",
                    "--bitcoind.rpchost=${APP_BITCOIN_NODE_IP}:${APP_BITCOIN_RPC_PORT}",
                    "--bitcoind.rpcuser=${APP_BITCOIN_RPC_USER}", "--bitcoind.rpcpass=${APP_BITCOIN_RPC_PASS}",
                    "--bitcoind.zmqpubrawblock=tcp://${APP_BITCOIN_NODE_IP}:${APP_BITCOIN_ZMQ_RAWBLOCK_PORT}",
                    "--bitcoind.zmqpubrawtx=tcp://${APP_BITCOIN_NODE_IP}:${APP_BITCOIN_ZMQ_RAWTX_PORT}",
                    "--rpclisten=0.0.0.0:10010", "--restlisten=0.0.0.0:8180", "--listen=0.0.0.0:9737",
                    f"--externalip=${{{ip_var}}}:9737", f"--tlsextraip=${{{ip_var}}}", f"--alias={alias}",
                    "--protocol.simple-taproot-chans", "--accept-keysend", "--debuglevel=info"],
        "volumes": ["${APP_DATA_DIR}/data/lnd:/data/.lnd"],
        "networks": {"default": {"ipv4_address": f"${{{ip_var}}}"}},
    }


def paulscode(out, reg):
    store = os.path.join(out, "paulscode")
    os.makedirs(store)
    with open(os.path.join(store, "umbrel-app-store.yml"), "w") as f:
        f.write('# regtest stand-ins for a package test (made by realbox/make_stores.py); not the author\'s store\n'
                'id: "paulscode"\nname: "Lightning Fork stand-ins (regtest test profile)"\n')

    # --- the chain node: the bitcoin slot ---
    d = os.path.join(store, "paulscode-knots-blake2b")
    os.makedirs(os.path.join(d, "data", "knots"))
    open(os.path.join(d, "data", "knots", ".gitkeep"), "w").close()
    dump(os.path.join(d, "umbrel-app.yml"), manifest("paulscode-knots-blake2b", "Knots (BLAKE2b) stand-in, regtest",
                                                    "A Knots BLAKE2b regtest node for the bitcoin slot", 18999, [], ["bitcoin"]))
    dump(os.path.join(d, "docker-compose.yml"), {"version": "3.7", "services": {"node": {
        "image": f"{reg}/{KNOTS_IMAGE}", "restart": "on-failure", "stop_grace_period": "1m",
        "environment": {"CHAIN": "regtest", "RPC_USER": "${APP_BITCOIN_RPC_USER}", "RPC_PASSWORD": "${APP_BITCOIN_RPC_PASS}",
                        "BLAKE2B_HEADLINE": "Lightning Fork lab", "BLAKE2B_ACTIVATION_HEIGHT": "20", "RPC_ALLOW_IP": "10.21.0.0/16"},
        "command": ["-zmqpubrawblock=tcp://0.0.0.0:${APP_BITCOIN_ZMQ_RAWBLOCK_PORT}", "-zmqpubrawtx=tcp://0.0.0.0:${APP_BITCOIN_ZMQ_RAWTX_PORT}",
                    "-txindex=1"],
        "volumes": ["${APP_DATA_DIR}/data/knots:/data"],
        "networks": {"default": {"ipv4_address": "${APP_BITCOIN_NODE_IP}"}},
        "healthcheck": {"test": ["CMD-SHELL", "bitcoin-cli -datadir=/data -rpcuser=$$RPC_USER -rpcpassword=$$RPC_PASSWORD getblockchaininfo > /dev/null"],
                        "interval": "10s", "timeout": "5s", "retries": 30, "start_period": "10s"}}}},
         "# Regtest stand-in for Knots (BLAKE2b) Companion: the Lightning lab's node image, no peers, no host port.\n")
    with open(os.path.join(d, "exports.sh"), "w") as f:
        f.write("# The export names of Knots (BLAKE2b) Companion, which fills the bitcoin slot; a regtest node here.\n"
                'export APP_KNOTS_BLAKE2B_NODE_IP="10.21.21.62"\n'
                'export APP_KNOTS_BLAKE2B_RPC_PORT="18443"\n'
                'export APP_KNOTS_BLAKE2B_ZMQ_RAWBLOCK_PORT="48342"\n'
                'export APP_KNOTS_BLAKE2B_ZMQ_RAWTX_PORT="48343"\n'
                'export APP_KNOTS_BLAKE2B_NETWORK="regtest"\n'
                'export APP_KNOTS_BLAKE2B_RPC_USER="umbrel"\n'
                'export APP_KNOTS_BLAKE2B_RPC_PASS="$(derive_entropy "paulscode-knots-blake2b-rpc")"\n'
                "for var in NODE_IP RPC_PORT ZMQ_RAWBLOCK_PORT ZMQ_RAWTX_PORT NETWORK RPC_USER RPC_PASS; do\n"
                '  bitcoin_var="APP_BITCOIN_${var}"; blake2b_var="APP_KNOTS_BLAKE2B_${var}"\n'
                '  export "$bitcoin_var"="${!bitcoin_var:=${!blake2b_var}}"\n'
                "done\n")

    # --- the two Lightning Fork nodes ---
    for app_id, alias, ip, name, implements in (
            ("paulscode-lightning-fork", "box-buyer", "10.21.21.66", "Lightning Fork stand-in (buyer), regtest", None),
            ("paulscode-lightning-fork-seller", "box-seller", "10.21.21.76", "Lightning Fork stand-in (seller), regtest", ["paulscode-lightning-fork"])):
        d = os.path.join(store, app_id)
        os.makedirs(os.path.join(d, "data", "lnd"))
        open(os.path.join(d, "data", "lnd", ".gitkeep"), "w").close()
        dump(os.path.join(d, "umbrel-app.yml"), manifest(app_id, name, "A Lightning Fork node on regtest", 18998 if implements else 18997,
                                                         ["bitcoin"], implements))
        lnd = lnd_service(alias, "APP_LIGHTNING_FORK_NODE_IP")
        lnd["image"] = f"{reg}/{LF_IMAGE}"
        services = {"lnd": lnd}
        if implements:
            os.makedirs(os.path.join(d, "www"))
            with open(os.path.join(d, "www", "small.txt"), "w") as f:
                f.write(PAGE)
            services["www"] = {"image": f"{reg}/{WWW_IMAGE}", "user": "1000:1000", "restart": "on-failure", "read_only": True,
                               "command": ["python", "-m", "http.server", "8080", "--directory", "/srv"],
                               "volumes": ["${APP_DATA_DIR}/www:/srv:ro"]}
        dump(os.path.join(d, "docker-compose.yml"), {"version": "3.7", "services": services},
             "# Regtest stand-in for Lightning Fork: the Lightning lab's build, its export names and address; no dashboard, Tor or host port.\n")
        with open(os.path.join(d, "exports.sh"), "w") as f:
            f.write("# The export names of Lightning Fork's Umbrel app (its node's address, REST port and data dir).\n"
                    f'export APP_LIGHTNING_FORK_NODE_IP="{ip}"\n'
                    'export APP_LIGHTNING_FORK_NODE_REST_PORT="8180"\n'
                    'export APP_LIGHTNING_FORK_NODE_DATA_DIR="${EXPORTS_APP_DIR}/data/lnd"\n')
    return publish(store, out, "paulscode")


def main():
    out, reg = os.path.abspath(sys.argv[1]), sys.argv[2]
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    print(lazarus(out, reg))
    print(paulscode(out, reg))


if __name__ == "__main__":
    main()
