"""Commands on the test box over SSH, and the regtest chain and Lightning nodes of the stand-in apps on it.

The SSH password (also the box's sudo password) comes from the environment (BOX_SSH_PASSWORD) and goes to
sshpass and to sudo on stdin; it is never put on a command line or logged. Docker on umbrelOS needs root
(the box user is not in the docker group).
"""
import base64
import json
import os
import re
import shlex
import subprocess
import time

from regtest_lib import LOG, wait_until  # noqa: F401  (LOG is set by open_log)


class Box:
    def __init__(self, host, user, password, known_hosts, control_dir):
        self.host, self.user, self.pw = host, user, password
        self.opts = ["-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known_hosts}", "-o", "PubkeyAuthentication=no",
                     "-o", "ControlMaster=auto", "-o", f"ControlPath={control_dir}/cm-%C", "-o", "ControlPersist=900",
                     "-o", "ServerAliveInterval=30"]

    def ssh(self, cmd, root=True, input=None, check=True, timeout=600):
        remote = f"sudo -S -p '' bash -c {shlex.quote(cmd)}" if root else cmd
        stdin = (self.pw + "\n" if root else "") + (input or "")
        r = subprocess.run(["sshpass", "-e", "ssh", *self.opts, f"{self.user}@{self.host}", remote], input=stdin, capture_output=True,
                           text=True, timeout=timeout, env={**os.environ, "SSHPASS": self.pw})
        if check and r.returncode != 0:
            shown = re.sub(r"(-rpcpassword=|password=)\S+", r"\1<redacted>", cmd[:160])
            raise RuntimeError(f"box: {shown}: rc={r.returncode} {(r.stderr or r.stdout).strip()[-600:]}")
        return r

    def docker(self, *args, check=True, timeout=600):
        return self.ssh("docker " + " ".join(shlex.quote(str(a)) for a in args), check=check, timeout=timeout)

    def exec(self, container, *args, check=True):
        return self.docker("exec", container, *args, check=check).stdout

    def inspect(self, *names):
        return json.loads(self.docker("inspect", *names).stdout)


KNOTS = "paulscode-knots-blake2b_node_1"
NODES = {"lf1": "paulscode-lightning-fork_lnd_1", "lf2": "paulscode-lightning-fork-seller_lnd_1"}
IPS = {"lf1": "10.21.21.66", "lf2": "10.21.21.76"}
ADMIN = "/data/.lnd/data/chain/bitcoin/regtest/admin.macaroon"
SPLIT = 125  # the regtest stand-in for the height the chains split at (packaging/ln_lab.py)


class RemoteLab:
    """packaging/ln_lab.py's Lab, for the stand-in apps on the box: the chain (the bitcoin slot), lf1 (the
    buyer's node, paulscode-lightning-fork) and lf2 (the seller's, paulscode-lightning-fork-seller)."""

    faucet_wallet = "lab"

    def __init__(self, box, rpc_user, rpc_pass):
        self.box, self.u, self.p = box, rpc_user, rpc_pass
        self.facts = {}

    # --- the chain ---
    def chain(self, *a):
        return self.box.exec(KNOTS, "bitcoin-cli", "-datadir=/data", f"-rpcuser={self.u}", f"-rpcpassword={self.p}", *[str(x) for x in a]).strip()

    def cli(self, *a, wallet=None):
        out = self.chain(*(([f"-rpcwallet={wallet}"] if wallet else []) + list(a)))
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def wallet(self, *a):
        return self.chain("-rpcwallet=lab", *a)

    def load_wallet(self):
        """The faucet wallet; a restart of the node does not load it again by itself."""
        if "lab" not in self.cli("listwallets"):
            self.chain("loadwallet", "lab")

    @property
    def faucet(self):
        return self.facts["faucet"]

    def mine(self, n=1):
        self.wallet("generatetoaddress", str(n), self.wallet("getnewaddress"))
        h = int(self.chain("getblockcount"))
        for node in NODES:
            wait_until(lambda node=node: self.synced(node, h), 120, f"{node} at height {h}", every=1)
        return h

    # --- the Lightning nodes ---
    def lncli(self, node, *a):
        out = self.box.exec(NODES[node], "lncli", "--lnddir=/data/.lnd", "--network=regtest", "--rpcserver=127.0.0.1:10010", *a).strip()
        return json.loads(out) if out.startswith(("{", "[")) else out

    def rest(self, node, path):
        """A REST GET on the node with its admin macaroon, from inside its own container (nothing is published)."""
        cmd = (f"curl -s --cacert /data/.lnd/tls.cert -H \"Grpc-Metadata-macaroon: $(od -An -vtx1 {ADMIN} | tr -d ' \\n')\" "
               f"'https://127.0.0.1:8180{path}'")
        return json.loads(self.box.exec(NODES[node], "sh", "-c", cmd) or "{}")

    def info(self, node):
        return self.rest(node, "/v1/getinfo")

    def synced(self, node, at=None):
        i = self.info(node)
        return bool(i.get("synced_to_chain")) and (at is None or int(i.get("block_height", 0)) >= at)

    def channels(self, node):
        return self.rest(node, "/v1/channels").get("channels", [])

    def bake(self, node, perms):
        out = self.lncli(node, "bakemacaroon", *perms)
        return out["macaroon"] if isinstance(out, dict) else out.split()[-1]

    def seller_settled(self):
        r = self.rest("lf2", "/v1/invoices?num_max_invoices=1000")
        return [i for i in r.get("invoices", []) if i.get("state") == "SETTLED"]

    def buyer_payments(self):
        return self.rest("lf1", "/v1/payments?include_incomplete=true&index_offset=0&max_payments=1000").get("payments", [])

    # --- the set-up packaging/ln_lab.py's Lab.up does, on the box ---
    def bootstrap_chain(self):
        try:
            self.load_wallet()
        except RuntimeError:
            self.chain("createwallet", "lab")
        self.facts["faucet"] = self.wallet("getnewaddress", "", "bech32")
        if int(self.chain("getblockcount")) < 130:
            self.wallet("generatetoaddress", "130", self.facts["faucet"])

    def channel_up(self):
        for node in NODES:
            wait_until(lambda node=node: self.synced(node), 240, f"{node} answering and synced", every=3)
        if not any(c.get("active") for c in self.channels("lf1")):
            self._send_pinned(self.lncli("lf1", "newaddress", "p2wkh")["address"], "0.2")
            self.mine(6)
            wait_until(lambda: int(self.rest("lf1", "/v1/balance/blockchain").get("total_balance", 0)), 60, "the buyer's coin", every=2)
            pk2 = self.info("lf2")["identity_pubkey"]
            self.box.exec(NODES["lf1"], "lncli", "--lnddir=/data/.lnd", "--network=regtest", "--rpcserver=127.0.0.1:10010", "connect",
                          f"{pk2}@{IPS['lf2']}:9737", check=False)
            wait_until(lambda: any(p["pub_key"] == pk2 for p in self.rest("lf1", "/v1/peers").get("peers", [])), 60, "lf1 connected to lf2", every=2)
            for attempt in range(6):
                try:
                    self.lncli("lf1", "openchannel", f"--node_key={pk2}", "--local_amt=5000000", "--push_amt=0")
                    break
                except RuntimeError:
                    if attempt == 5:
                        raise
                    time.sleep(5)
            self.mine(8)
        wait_until(lambda: any(c.get("active") for c in self.channels("lf1")) and any(c.get("active") for c in self.channels("lf2")), 240,
                   "the channel active on both sides", every=3)
        wait_until(lambda: int(self.rest("lf1", "/v1/graph/info").get("num_channels", 0)) >= 1, 300, "the buyer knows the channel", every=3)
        for name, node, perms in (("rail", "lf1", ("info:read", "offchain:read", "offchain:write", "onchain:read")),
                                  ("invoices", "lf2", ("invoices:read", "invoices:write")), ("info", "lf2", ("info:read",))):
            self.facts[f"{name}_macaroon"] = self.bake(node, perms)
        for node in NODES:
            self.facts[f"{node}_pubkey"] = self.info(node)["identity_pubkey"]
        self.facts["network"] = "lightning:" + self.chain("getblockhash", "101")[:32]
        self.facts["split"] = SPLIT
        self.facts["upstream"] = "http://paulscode-lightning-fork-seller_www_1:8080"
        return self.facts

    def _send_pinned(self, addr, btc):
        """packaging/ln_lab.py's _send_pinned: pay from a P2PKH coin made after the split, so the spending
        transaction carries an XBT-only signature, which the rail's funding proof accepts."""
        legacy = self.wallet("getnewaddress", "", "legacy")
        txid = self.wallet("sendtoaddress", legacy, f"{float(btc) + 0.001:.8f}")
        self.wallet("generatetoaddress", "1", self.wallet("getnewaddress"))
        tx = json.loads(self.wallet("gettransaction", txid, "true", "true"))["decoded"]
        vout = next(o["n"] for o in tx["vout"] if o["scriptPubKey"].get("address") == legacy)
        opts = json.dumps({"inputs": [{"txid": txid, "vout": vout}], "add_inputs": False})
        sent = json.loads(self.wallet("send", json.dumps({addr: float(btc)}), "null", "unset", "2", opts))
        if not sent.get("complete"):
            raise RuntimeError(f"send from the P2PKH coin: {sent}")


def b64hex(b64):
    try:
        return base64.b64decode(b64 or "").hex()
    except ValueError:
        return ""
