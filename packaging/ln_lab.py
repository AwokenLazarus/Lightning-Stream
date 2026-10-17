"""The Lightning side of the package tests: two Lightning Fork nodes on one Knots BLAKE2b regtest, from
the lab scripts/ln_rail_regtest.sh uses (scripts/ln_rail/lab.sh), plus the seller's service.

    packaged wallet ==== lf1 =========== lf2 ==== packaged gateway ---- the service (a stock file server)
                         (the buyer's box)   (the seller's box)

lf1 is the Lightning node of the box the wallet is installed on, lf2 the one of the box the gateway is
installed on; one channel of 5,000,000 sat goes from lf1 to lf2, funded from a coin that exists on XBT
alone (what the rail's funding proof accepts). The chain node is also the wallet's XBT node. Each test
gets its own compose project and network, so the three package tests and the other regtest scripts
do not share containers; nothing is published but the two nodes' REST interfaces, on loopback, for
the driver itself. The macaroons are baked here with the permissions the owner would choose in the
node's dashboard, exactly: the wallet's rail, the gateway's invoices and height.

    lab = Lab(out_dir, project, rest_ports=(p1, p2))
    lab.up()                 # chain, nodes, channel, macaroons, certificates, the file server
    ...                      # lab.net is the docker network the packages join
    lab.down()
Regtest only; no miner runs (blocks come from generatetoaddress).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB_DIR = os.path.join(ROOT, "run", "lightning-fork-lab")
BUYER, SELLER = "lf1", "lf2"
SPLIT = 125  # the regtest stand-in for the height the chains split at
PAGE = "a small page, sold per request\n" * 8
BIG = 3 << 20  # the file sold per MiB


class Lab:
    def __init__(self, out: str, project: str, rest_ports: tuple[int, int]):
        self.out, self.project = out, project
        self.run = os.path.join(out, "lab")
        os.makedirs(self.run, exist_ok=True)
        self.net = f"{project}_lab"
        self.www = f"{project}-www"
        os.environ.update({
            "LAB": LAB_DIR, "RUN": self.run, "COMPOSE_PROJECT_NAME": project, "ACTIVATION_HEIGHT": "20",
            "COMPOSE_FILE": f"{LAB_DIR}/docker-compose.yml:{ROOT}/packaging/ln_lab.compose.yml",
            "LN_TICKET_PORT_LF1": str(rest_ports[0]), "LN_TICKET_PORT_LF2": str(rest_ports[1]),
            "PKG_LAB_PORT_LF1": str(rest_ports[0]), "PKG_LAB_PORT_LF2": str(rest_ports[1]),
        })
        sys.path.insert(0, os.path.join(ROOT, "scripts", "ln_ticket"))
        import lab  # noqa: E402  (reads the environment above at import)

        self.lab = lab
        self.facts: dict = {}

    # --- the chain, as the drivers' Chain helper offers it -----------------------------------------------

    faucet_wallet = "lab"

    def cli(self, *a, wallet=None):
        args = [str(x) for x in a]
        out = self.lab.chain(*(([f"-rpcwallet={wallet}"] if wallet else []) + args))
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def mine(self, n=1):
        return self.lab.mine(n, (BUYER, SELLER))

    @property
    def faucet(self):
        return self.facts["faucet"]

    # --- up and down ---------------------------------------------------------------------------------------

    def build(self) -> None:
        """The lab's checkout and node binaries (cloned and built under run/ when missing), as the
        regtest scripts do it."""
        subprocess.run(["bash", "-c", '. "$ROOT/scripts/ln_rail/lab.sh"'], check=True, env={**os.environ, "ROOT": ROOT})

    def up(self) -> dict:
        lab = self.lab
        self.down(quiet=True)
        self.build()
        lab.dc("up", "-d", "fees", "knots-b2b")
        lab.wait("the chain node", 120, lambda: lab.chain("getblockchaininfo"))
        lab.chain("createwallet", "lab")
        self.facts["faucet"] = lab.wallet("getnewaddress", "", "bech32")
        lab.wallet("generatetoaddress", "130", self.facts["faucet"])
        lab.dc("up", "-d", BUYER, SELLER)

        def ready(node: str) -> bool:
            lab.load_credentials(node)
            return lab.synced(node)

        for node in (BUYER, SELLER):
            lab.wait(f"{node} answering and synced", 180, lambda n=node: ready(n))
        self._send_pinned(lab.lncli(BUYER, "newaddress", "p2wkh")["address"], "0.2")
        lab.mine(6, (BUYER, SELLER))
        lab.wait("the buyer's coin", 60, lambda: lab.wallet_sat(BUYER))
        for attempt in range(6):
            try:
                lab.open_channel(BUYER, SELLER, 5_000_000, 0)
                break
            except lab.LabError:
                if attempt == 5:
                    raise
                time.sleep(5)
        lab.mine(8, (BUYER, SELLER))
        lab.wait("the channel active on both sides", 240,
                 lambda: any(c["active"] for c in lab.channels(BUYER)) and any(c["active"] for c in lab.channels(SELLER)))
        lab.wait("the buyer knows the channel", 300, lambda: lab.known_channels(BUYER) >= 1, every=2)
        # what the owner of each box bakes in Lightning Fork's dashboard, and the one file of the node's the package mounts
        for name, node, perms in (("rail", BUYER, lab.BUYER_PERMISSIONS), ("invoices", SELLER, lab.SELLER_PERMISSIONS),
                                  ("info", SELLER, ("info:read",))):
            self.facts[f"{name}_macaroon"] = lab.bake(node, perms)
        for node in (BUYER, SELLER):
            d = os.path.join(self.run, node)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "tls.cert"), "w") as f:
                f.write(lab.dc("exec", "-T", node, "cat", "/root/.lnd/tls.cert") + "\n")
            self.facts[f"{node}_cert_dir"] = d
            self.facts[f"{node}_pubkey"] = lab.pubkey(node)
        self.facts["network"] = "lightning:" + lab.chain("getblockhash", "101")[:32]
        self.facts["split"] = SPLIT
        self._www()
        return self.facts

    def _send_pinned(self, addr: str, btc: str) -> None:
        """Pay `addr` from a P2PKH coin made after the split: its spending transaction carries an XBT-only
        signature, which the wallet's funding proof accepts (as scripts/ticket_e2e/drive.py does)."""
        lab = self.lab
        legacy = lab.wallet("getnewaddress", "", "legacy")
        txid = lab.wallet("sendtoaddress", legacy, f"{float(btc) + 0.001:.8f}")
        lab.wallet("generatetoaddress", "1", lab.wallet("getnewaddress"))
        tx = json.loads(lab.wallet("gettransaction", txid, "true", "true"))["decoded"]
        vout = next(o["n"] for o in tx["vout"] if o["scriptPubKey"].get("address") == legacy)
        opts = json.dumps({"inputs": [{"txid": txid, "vout": vout}], "add_inputs": False})
        sent = json.loads(lab.wallet("send", json.dumps({addr: float(btc)}), "null", "unset", "2", opts))
        if not sent.get("complete"):
            raise lab.LabError(f"send from the P2PKH coin: {sent}")

    def _www(self) -> None:
        """The seller's service: a stock file server on the lab network, which knows nothing of payments."""
        d = os.path.join(self.run, "www")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "small.txt"), "w") as f:
            f.write(PAGE)
        with open(os.path.join(d, "big.bin"), "wb") as f:
            f.write(os.urandom(BIG))
        os.chmod(d, 0o755)
        subprocess.run(["docker", "rm", "-f", self.www], capture_output=True)
        subprocess.run(["docker", "run", "-d", "--name", self.www, "--network", self.net, "--network-alias", "www", "--read-only", "--cpus", "1",
                        "-v", f"{d}:/srv:ro", "python:3-alpine", "python", "-m", "http.server", "8080", "--directory", "/srv"],
                       check=True, capture_output=True)
        self.facts["upstream"] = "http://www:8080"

    def seller_settled(self) -> list[dict]:
        """The seller node's settled invoices (the tickets it was paid)."""
        r = self.lab.get(SELLER, "/v1/invoices?num_max_invoices=1000")
        return [i for i in r.get("invoices", []) if i.get("state") == "SETTLED"]

    def buyer_payments(self) -> list[dict]:
        """Every payment the buyer's node made or has in flight."""
        return self.lab.get(BUYER, "/v1/payments?include_incomplete=true&index_offset=0&max_payments=1000").get("payments", [])

    def down(self, quiet: bool = False) -> None:
        subprocess.run(["docker", "rm", "-f", self.www], capture_output=True)
        r = subprocess.run(["docker", "compose", "down", "-v", "--remove-orphans"], cwd=LAB_DIR, capture_output=True, text=True)
        if r.returncode != 0 and not quiet:
            print(f"lab down: {r.stderr.strip()[-300:]}", flush=True)
