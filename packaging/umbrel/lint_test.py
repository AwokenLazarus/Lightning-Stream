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
            "the taker mounts the admin macaroon": lambda s: s["node-keys"]["volumes"].append(
                {"type": "bind", "source": "${APP_LIGHTNING_FORK_NODE_DATA_DIR}/data/chain/bitcoin/mainnet/admin.macaroon",
                 "target": "/node/admin.macaroon", "read_only": True, "bind": {"create_host_path": False}}),
        }
        for why, change in cases.items():
            with self.subTest(why=why):
                self.fresh()
                self.refused(change, why)


if __name__ == "__main__":
    unittest.main()
