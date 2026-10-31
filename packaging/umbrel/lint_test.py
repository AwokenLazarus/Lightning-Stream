#!/usr/bin/env python3
"""The lint's rule on the Lightning node's data, tested: of another app's data a container mounts its
tls.cert only, and the one exception, the node's data folder read-only, is node-keys-bake's alone, by
name, as the Lightning app's user, writing only the hand-over folder. Each case breaks a copy of the
store one way and expects lint.py to refuse it; the store as it is must pass.
    python3 packaging/umbrel/lint_test.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
APP = "lazarus-lightning-stream"
BAKE = "node-keys-bake"
NODE_DIR = {"type": "bind", "source": "${APP_LIGHTNING_FORK_NODE_DATA_DIR}", "target": "/node", "read_only": True,
            "bind": {"create_host_path": False}}


def lint(store: Path) -> tuple[bool, str]:
    r = subprocess.run([sys.executable, str(HERE / "lint.py"), str(store)], capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


class NodeDataRule(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.store = Path(self.t.name) / "umbrel"
        # lint.py finds packaging/images.lock beside its own folder, so the copy only holds the store
        shutil.copytree(HERE, self.store, ignore=shutil.ignore_patterns("regtest", "realbox", "__pycache__", "*.png"))
        for p in HERE.glob("*/*.png"):
            (self.store / p.relative_to(HERE)).write_bytes(b"")
        self.compose = self.store / APP / "docker-compose.yml"

    def tearDown(self):
        self.t.cleanup()

    def fresh(self):
        """A new copy of the store, for the next case."""
        self.tearDown()
        self.setUp()

    def edit(self, change):
        # anchors and merge keys are resolved by the load: the broken copy says each service in full
        c = yaml.safe_load(self.compose.read_text())
        change(c["services"])
        self.compose.write_text(yaml.safe_dump(c, sort_keys=False))

    def refused(self, change, why: str):
        self.edit(change)
        ok, out = lint(self.store)
        self.assertFalse(ok, f"lint passed a store where {why}:\n{out[-1500:]}")

    def test_the_store_as_it_is_passes(self):
        ok, out = lint(self.store)
        self.assertTrue(ok, out[-1500:])
        # and with every anchor resolved (what the broken copies are), it still passes
        self.edit(lambda s: None)
        ok, out = lint(self.store)
        self.assertTrue(ok, out[-1500:])

    def test_no_other_container_may_mount_the_node_data(self):
        names = [n for n in yaml.safe_load(self.compose.read_text())["services"] if n not in ("app_proxy", BAKE)]
        self.assertIn("node-keys", names)
        for name in names:
            with self.subTest(name=name):
                self.fresh()
                self.refused(lambda s: s[name].setdefault("volumes", []).append(dict(NODE_DIR)), f"{name} mounts the node's data folder")

    def test_the_exception_is_by_name(self):
        self.refused(lambda s: s.__setitem__("node-keys-bake2", s.pop(BAKE)), "the baker is renamed")

    def test_the_baker_is_held_to_its_terms(self):
        cases = {
            "the node's data is writable": lambda s: s[BAKE]["volumes"].__setitem__(-1, {**NODE_DIR, "read_only": False}),
            "it runs as root": lambda s: s[BAKE].__setitem__("user", "0:0"),
            "it joins another group": lambda s: s[BAKE]["group_add"].append("10001"),
            "it writes run/ln": lambda s: s[BAKE]["volumes"].__setitem__(0, "${APP_DATA_DIR}/data/run/ln:/data/run/ln"),
            "it mounts the signer's dir": lambda s: s[BAKE]["volumes"].append("${APP_DATA_DIR}/data/signer:/data/signer"),
            "it publishes a port": lambda s: s[BAKE].__setitem__("ports", ["33599:33599"]),
            "it keeps running": lambda s: s[BAKE].__setitem__("restart", "on-failure"),
            "it bakes outside the hand-over": lambda s: s[BAKE]["environment"].pop("XBT_KEYS_BAKE_TO"),
            "it runs another program": lambda s: s[BAKE].__setitem__("command", ["serve"]),
            "the taker joins the Lightning app's group": lambda s: s["node-keys"].__setitem__("group_add", ["1000"]),
            # M2: the exception is the baker's, not its name's: xbt-init (root, CHOWN/DAC_OVERRIDE, /data
            # read-write) under the baker's name with the folder mounted
            "an xbt-init named node-keys-bake": lambda s: s.__setitem__(BAKE, {**s["init"], "volumes": [*s["init"]["volumes"], dict(NODE_DIR)]}),
            "it adds a capability": lambda s: s[BAKE].__setitem__("cap_add", ["DAC_OVERRIDE"]),
            "the taker has a network": lambda s: s["node-keys"].pop("network_mode"),
            "the taker mounts the admin macaroon": lambda s: s["node-keys"]["volumes"].append(
                {"type": "bind", "source": "${APP_LIGHTNING_FORK_NODE_DATA_DIR}/data/chain/bitcoin/mainnet/admin.macaroon",
                 "target": "/node/admin.macaroon", "read_only": True, "bind": {"create_host_path": False}}),
        }
        for why, change in cases.items():
            with self.subTest(why=why):
                self.fresh()
                self.refused(change, why)


    def test_every_container_keeps_to_itself(self):
        """No container reaches into another's processes, files or privileges, umbrelOS's app_proxy included."""
        cases = {
            "volumes_from": lambda s: s["ui"].__setitem__("volumes_from", ["signer"]),
            "pid of another service": lambda s: s["ui"].__setitem__("pid", "service:signer"),
            "ipc of another service": lambda s: s["mcp"].__setitem__("ipc", "service:signer"),
            "privileged": lambda s: s["gateway"].__setitem__("privileged", True),
            "an added capability": lambda s: s["ui"].__setitem__("cap_add", ["NET_ADMIN"]),
            "a looser security_opt": lambda s: s["signer"]["security_opt"].append("seccomp:unconfined"),
            "the host's network": lambda s: s["gateway"].__setitem__("network_mode", "host"),
            "another container's network": lambda s: s["ui"].__setitem__("network_mode", "container:lnd"),
            "app_proxy mounts a volume": lambda s: s["app_proxy"].__setitem__("volumes", ["${APP_DATA_DIR}/data/signer:/data/signer"]),
            "app_proxy with pid": lambda s: s["app_proxy"].__setitem__("pid", "service:signer"),
        }
        for why, change in cases.items():
            with self.subTest(why=why):
                self.fresh()
                self.refused(change, why)

    def test_compose_shapes_that_could_reach_the_node_data(self):
        """Shapes a check of the file as written would miss, each giving a container the Lightning node's
        data, the docker socket or root: lint reads the file strictly and the model compose resolves."""
        c = yaml.safe_load(self.compose.read_text())["services"]
        ui, init = c["ui"]["image"], c["init"]["image"]
        bake_cmd = '    command: ["node-keys"]\n    user: "1000:1000"\n'
        evil = lambda extra: "\n  evil:\n" + extra
        node_mount = "      - ${APP_LIGHTNING_FORK_NODE_DATA_DIR}:/node:ro\n"
        cases = {
            "extends the baker, as xbt-init": (lambda t: t.rstrip() + "\n" + evil(
                f"    extends:\n      service: node-keys-bake\n    image: {init}\n    user: \"0:0\"\n    restart: \"no\"\n    network_mode: none\n"
                "    read_only: true\n    cap_drop: [ALL]\n    cap_add: [DAC_OVERRIDE]\n    volumes:\n      - ${APP_DATA_DIR}/data:/data\n"), None),
            "extends a service of another file": (lambda t: t.rstrip() + "\n" + evil(
                f"    <<: *service\n    extends:\n      file: lf.yml\n      service: lf\n    image: {ui}\n    command: [\"serve\"]\n"),
                ("lf.yml", 'services:\n  lf:\n    user: "1000:1000"\n    volumes:\n' + node_mount)),
            "the taker extends the baker": (lambda t: t.replace("  node-keys:\n    <<: *service\n",
                "  node-keys:\n    <<: *service\n    extends:\n      service: node-keys-bake\n", 1), None),
            "the baker runs the UI server": (lambda t: t.replace(bake_cmd,
                '    command: ["node-keys"]\n    entrypoint: ["/usr/bin/xbt-wallet-ui", "serve"]\n    user: "1000:1000"\n', 1), None),
            "secrets from the node's folder": (lambda t: t.replace("  ui:\n    <<: *service\n", "  ui:\n    <<: *service\n    secrets: [node]\n", 1).rstrip()
                + "\nsecrets:\n  node:\n    file: ${APP_LIGHTNING_FORK_NODE_DATA_DIR}/data/chain/bitcoin/mainnet/wallet.db\n", None),
            "a config of the node's folder": (lambda t: t.replace("  mcp:\n    <<: *service\n", "  mcp:\n    <<: *service\n    configs: [{source: node, target: /node}]\n", 1).rstrip()
                + "\nconfigs:\n  node:\n    file: ${APP_LIGHTNING_FORK_NODE_DATA_DIR}\n", None),
            "include": (lambda t: t.replace('version: "3.7"\n', 'version: "3.7"\ninclude:\n  - extra.yml\n', 1),
                ("extra.yml", f'services:\n  evil:\n    image: {ui}\n    user: "1000:1000"\n    volumes:\n' + node_mount)),
            "a build context of the node's folder": (lambda t: t.replace("    image: xbt-vpn:0.1.0\n",
                "    image: xbt-vpn:0.1.0\n    build:\n      context: ${APP_LIGHTNING_FORK_NODE_DATA_DIR}\n", 1), None),
            "a mount that climbs out with ..": (lambda t: t.rstrip() + "\n" + evil(
                f"    image: {init}\n    restart: \"no\"\n    network_mode: none\n    read_only: true\n    cap_drop: [ALL]\n    cap_add: [DAC_OVERRIDE]\n"
                "    security_opt: [no-new-privileges:true]\n    volumes:\n      - ${APP_DATA_DIR}/../paulscode-lightning-fork/data/lnd:/lnd\n"), None),
            "the docker socket": (lambda t: t.replace("  ui:\n    <<: *service\n", "  ui:\n    <<: *service\n    use_api_socket: true\n", 1), None),
            "a post_start hook in the baker": (lambda t: t.replace(bake_cmd, bake_cmd + "    post_start:\n      - command: [\"/usr/bin/xbt-wallet-ui\", \"serve\"]\n"
                "        user: \"0:0\"\n        privileged: true\n", 1), None),
            "an env_file into the baker": (lambda t: t.replace(bake_cmd, '    command: ["node-keys"]\n    env_file: [bake.env]\n    user: "1000:1000"\n', 1),
                ("bake.env", "XBT_KEYS_GRANT_DIR=/node\n")),
            "the baker written twice": (lambda t: t.replace("  node-keys-bake:\n", f"  node-keys-bake:\n    image: {init}\n    volumes: [*lightning-data]\n  node-keys-bake:\n", 1), None),
            "the baker's user written twice": (lambda t: t.replace('    user: "1000:1000"\n', '    user: "0:0"\n    user: "1000:1000"\n', 1), None),
            "a named volume": (lambda t: t.rstrip() + "\nvolumes:\n  node:\n    driver_opts:\n      type: none\n      o: bind\n"
                "      device: ${APP_LIGHTNING_FORK_NODE_DATA_DIR}\n", None),
        }
        for why, (change, extra) in cases.items():
            with self.subTest(why=why):
                self.fresh()
                text = self.compose.read_text()
                changed = change(text)
                self.assertNotEqual(changed, text, f"{why}: the case did not apply")
                self.compose.write_text(changed)
                if extra:
                    (self.compose.parent / extra[0]).write_text(extra[1])
                ok, out = lint(self.store)
                self.assertFalse(ok, f"lint passed a store with {why}:\n{out[-1500:]}")

if __name__ == "__main__":
    unittest.main()
