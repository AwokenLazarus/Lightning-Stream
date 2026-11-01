#!/usr/bin/env python3
"""The lint's rule on the Lightning node's data, tested: of another app's data a container mounts its
tls.cert only, and the one exception, the node's data folder read-only, is node-keys-bake's alone, by
name, as the Lightning app's user, writing only the hand-over folder. Each case breaks a copy of the
store one way and expects lint.py to refuse it, saying why (the case's text in a FAIL line); the store
as it is must pass.
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

    def says(self, out: str, why: str, says) -> None:
        """lint refused the store, and for the reason the case is about."""
        self.assertNotIn("Traceback", out, f"{why}: lint crashed:\n{out[-1500:]}")
        fails = "\n".join(l for l in out.splitlines() if "FAIL" in l)
        self.assertTrue(fails, f"lint passed a store where {why}:\n{out[-1500:]}")
        for t in (says,) if isinstance(says, str) else says:
            self.assertIn(t, fails, f"{why}: lint refused it, but not with {t!r}:\n{fails[-1500:]}")

    def refused(self, change, why: str, says):
        self.edit(change)
        ok, out = lint(self.store)
        self.assertFalse(ok, f"lint passed a store where {why}:\n{out[-1500:]}")
        self.says(out, why, says)

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
                self.refused(lambda s: s[name].setdefault("volumes", []).append(dict(NODE_DIR)), f"{name} mounts the node's data folder", "a long-form mount is only the Lightning node's tls.cert")

    def test_the_exception_is_by_name(self):
        self.refused(lambda s: s.__setitem__("node-keys-bake2", s.pop(BAKE)), "the baker is renamed", "a long-form mount is only the Lightning node's tls.cert")

    def test_the_baker_is_held_to_its_terms(self):
        user = "as the Lightning app's user"
        mounts = "node-keys-bake mounts the node's data read-only, run/ln and run/gateway read-only"
        env = "its environment is not exactly"
        health = "healthcheck is exactly"
        cases = {
            "the node's data is writable": (lambda s: s[BAKE]["volumes"].__setitem__(-1, {**NODE_DIR, "read_only": False}),
                                            "a long-form mount is only the Lightning node's tls.cert"),
            "it runs as root": (lambda s: s[BAKE].__setitem__("user", "0:0"), user),
            "it joins another group": (lambda s: s[BAKE]["group_add"].append("10001"), "node-keys-bake joins exactly the groups"),
            "it writes run/ln": (lambda s: s[BAKE]["volumes"].__setitem__(0, "${APP_DATA_DIR}/data/run/ln:/data/run/ln"), mounts),
            "it mounts the signer's dir": (lambda s: s[BAKE]["volumes"].append("${APP_DATA_DIR}/data/signer:/data/signer"), mounts),
            "it publishes a port": (lambda s: s[BAKE].__setitem__("ports", ["33599:33599"]), user),
            "it keeps running": (lambda s: s[BAKE].__setitem__("restart", "on-failure"), user),
            "it bakes outside the hand-over": (lambda s: s[BAKE]["environment"].pop("XBT_KEYS_BAKE_TO"), env),
            "it runs another program": (lambda s: s[BAKE].__setitem__("command", ["serve"]), "node-keys-bake is node-keys"),
            "the taker joins the Lightning app's group": (lambda s: s["node-keys"].__setitem__("group_add", ["1000"]), "node-keys joins no other group"),
            # M2: the exception is the baker's, not its name's: xbt-init (root, CHOWN/DAC_OVERRIDE, /data
            # read-write) under the baker's name with the folder mounted
            "an xbt-init named node-keys-bake": (lambda s: s.__setitem__(BAKE, {**s["init"], "volumes": [*s["init"]["volumes"], dict(NODE_DIR)]}),
                                                 "xbt-init runs as one service, named init"),
            "it adds a capability": (lambda s: s[BAKE].__setitem__("cap_add", ["DAC_OVERRIDE"]), "cap_add is xbt-init's alone"),
            "the taker has a network": (lambda s: s["node-keys"].pop("network_mode"), "node-keys only moves files: network_mode none"),
            "the taker mounts the admin macaroon": (lambda s: s["node-keys"]["volumes"].append(
                {"type": "bind", "source": "${APP_LIGHTNING_FORK_NODE_DATA_DIR}/data/chain/bitcoin/mainnet/admin.macaroon",
                 "target": "/node/admin.macaroon", "read_only": True, "bind": {"create_host_path": False}}), "a long-form mount is only the Lightning node's tls.cert"),
            # LOW-1: its node is the one Lightning Fork exports, and no service joins its network
            "it asks a node elsewhere": (lambda s: s[BAKE]["environment"].__setitem__("XBT_KEYS_NODE_REST", "https://203.0.113.9:443"), env),
            "it asks a loopback address": (lambda s: s[BAKE]["environment"].__setitem__("XBT_KEYS_NODE_REST", "http://127.0.0.1:8402"), env),
            "another service joins its network": (lambda s: s["witness"].__setitem__("network_mode", "service:node-keys-bake"), "the namespace pinned for it"),
            "its environment passes a variable through": (lambda s: s[BAKE].__setitem__("environment",
                ["XBT_KEYS_NODE_REST"] + [f"{k}={v}" for k, v in s[BAKE]["environment"].items() if k != "XBT_KEYS_NODE_REST"]),
                "passes a variable through from the host's"),
            # LOW-2: a healthcheck is a command run in the container
            "its healthcheck runs the UI server": (lambda s: s[BAKE].__setitem__("healthcheck", {"test": ["CMD", "/usr/bin/xbt-wallet-ui", "serve"]}), health),
            "the taker's healthcheck runs a command": (lambda s: s["node-keys"].__setitem__("healthcheck", {"test": ["CMD", "/usr/bin/xbt-wallet-ui", "serve"]}), health),
            # xbt-init: one service, its own command, the data dir alone
            "a second xbt-init": (lambda s: s.__setitem__("init2", dict(s["init"])), "xbt-init runs as one service, named init"),
            "init mounts the hand-over too": (lambda s: s["init"]["volumes"].append("${APP_DATA_DIR}/data/run/node-keys:/h"), "and mounts ['${APP_DATA_DIR}/data:/data'] alone"),
            "init runs another command": (lambda s: s["init"].__setitem__("command", ["check", "--data", "/h"]), "xbt-init runs its own command"),
        }
        for why, (change, says) in cases.items():
            with self.subTest(why=why):
                self.fresh()
                self.refused(change, why, says)

    def test_the_stream_gateway_stays_on_the_renters_loopback(self):
        """The Stream Gateway's API opens every job (/xbt/job) to loopback: it stays in the renter's network
        namespace, publishes nothing, mounts its own dirs alone and runs what is pinned for it."""
        ns = "publishes no port and runs in the renter's network namespace"
        cases = {
            "it publishes its API": (lambda s: s["datum"].__setitem__("ports", ["7152:7152"]), ns),
            "it is on the app's network": (lambda s: s["datum"].pop("network_mode"), ns),
            "it joins the UI's namespace": (lambda s: s["datum"].__setitem__("network_mode", "service:ui"), "the namespace pinned for it"),
            "it runs on the host's network": (lambda s: s["datum"].__setitem__("network_mode", "host"), "the namespace pinned for it"),
            "another service joins it": (lambda s: s["witness"].__setitem__("network_mode", "service:datum"), "the namespace pinned for it"),
            "it writes its config": (lambda s: s["datum"]["volumes"].__setitem__(1, "${APP_DATA_DIR}/data/run/datum:/data/run/datum"),
                                     "is outside its own sub-dir and socket dirs"),
            "it mounts the signer's dir": (lambda s: s["datum"]["volumes"].append("${APP_DATA_DIR}/data/run/signer:/data/run/signer:ro"),
                                           "is outside its own sub-dir and socket dirs"),
            "it runs as the box user": (lambda s: s["datum"].__setitem__("user", "1000:1000"), "must run as its image's own user"),
            "it runs something else": (lambda s: s["datum"].__setitem__("entrypoint", ["/usr/bin/xbt-datum-gateway", "-c", "/tmp/x.json"]),
                                       "is not the one pinned for it"),
            "its image is another": (lambda s: s["datum"].__setitem__("image", "ghcr.io/retropex/datum:v1.13"), "is not ghcr.io/awokenlazarus/"),
        }
        for why, (change, says) in cases.items():
            with self.subTest(why=why):
                self.fresh()
                self.refused(change, why, says)

    def test_every_container_keeps_to_itself(self):
        """No container reaches into another's processes, files or privileges, umbrelOS's app_proxy included."""
        cases = {
            "volumes_from": (lambda s: s["ui"].__setitem__("volumes_from", ["signer"]), "'volumes_from' is not allowed"),
            "pid of another service": (lambda s: s["ui"].__setitem__("pid", "service:signer"), "'pid' is not allowed"),
            "ipc of another service": (lambda s: s["mcp"].__setitem__("ipc", "service:signer"), "'ipc' is not allowed"),
            "privileged": (lambda s: s["gateway"].__setitem__("privileged", True), "'privileged' is not allowed"),
            "an added capability": (lambda s: s["ui"].__setitem__("cap_add", ["NET_ADMIN"]), "cap_add is xbt-init's alone"),
            "a looser security_opt": (lambda s: s["signer"]["security_opt"].append("seccomp:unconfined"), "security_opt may only be no-new-privileges:true"),
            "the host's network": (lambda s: s["gateway"].__setitem__("network_mode", "host"), "network_mode 'host'"),
            "another container's network": (lambda s: s["ui"].__setitem__("network_mode", "container:lnd"), "network_mode 'container:lnd'"),
            "app_proxy mounts a volume": (lambda s: s["app_proxy"].__setitem__("volumes", ["${APP_DATA_DIR}/data/signer:/data/signer"]), "'volumes' is not allowed"),
            "app_proxy with pid": (lambda s: s["app_proxy"].__setitem__("pid", "service:signer"), "'pid' is not allowed"),
        }
        for why, (change, says) in cases.items():
            with self.subTest(why=why):
                self.fresh()
                self.refused(change, why, says)

    def test_compose_shapes_that_could_reach_the_node_data(self):
        """Shapes a check of the file as written would miss, each giving a container the Lightning node's
        data, the docker socket or root: lint reads the file strictly and the model compose resolves."""
        c = yaml.safe_load(self.compose.read_text())["services"]
        ui, init = c["ui"]["image"], c["init"]["image"]
        bake_cmd = '    command: ["node-keys"]\n    user: "1000:1000"\n'
        evil = lambda extra: "\n  evil:\n" + extra
        node_mount = "      - ${APP_LIGHTNING_FORK_NODE_DATA_DIR}:/node:ro\n"
        subst = "(no default, no other form)"
        files = "is not one of the app's files"
        exports = 'is not export NAME="literal"'
        ui_mount = "      - ${APP_DATA_DIR}/data/ui:/data/ui\n"
        init_mount = "      - ${APP_DATA_DIR}/data:/data\n"
        ui_env = "    environment:\n      XBT_UI_BIND: 0.0.0.0:8482\n"
        cases = {
            "extends the baker, as xbt-init": (lambda t: t.rstrip() + "\n" + evil(
                f"    extends:\n      service: node-keys-bake\n    image: {init}\n    user: \"0:0\"\n    restart: \"no\"\n    network_mode: none\n"
                "    read_only: true\n    cap_drop: [ALL]\n    cap_add: [DAC_OVERRIDE]\n    volumes:\n      - ${APP_DATA_DIR}/data:/data\n"), {}, "'extends' is not allowed"),
            "extends a service of another file": (lambda t: t.rstrip() + "\n" + evil(
                f"    <<: *service\n    extends:\n      file: lf.yml\n      service: lf\n    image: {ui}\n    command: [\"serve\"]\n"),
                {"lf.yml": 'services:\n  lf:\n    user: "1000:1000"\n    volumes:\n' + node_mount}, ("'extends' is not allowed", "lf.yml " + files)),
            "the taker extends the baker": (lambda t: t.replace("  node-keys:\n    <<: *service\n",
                "  node-keys:\n    <<: *service\n    extends:\n      service: node-keys-bake\n", 1), {}, "'extends' is not allowed"),
            "the baker runs the UI server": (lambda t: t.replace(bake_cmd,
                '    command: ["node-keys"]\n    entrypoint: ["/usr/bin/xbt-wallet-ui", "serve"]\n    user: "1000:1000"\n', 1), {}, "is not the one pinned for it"),
            "secrets from the node's folder": (lambda t: t.replace("  ui:\n    <<: *service\n", "  ui:\n    <<: *service\n    secrets: [node]\n", 1).rstrip()
                + "\nsecrets:\n  node:\n    file: ${APP_LIGHTNING_FORK_NODE_DATA_DIR}/data/chain/bitcoin/mainnet/wallet.db\n", {}, "top-level 'secrets' is not allowed"),
            "a config of the node's folder": (lambda t: t.replace("  mcp:\n    <<: *service\n", "  mcp:\n    <<: *service\n    configs: [{source: node, target: /node}]\n", 1).rstrip()
                + "\nconfigs:\n  node:\n    file: ${APP_LIGHTNING_FORK_NODE_DATA_DIR}\n", {}, "top-level 'configs' is not allowed"),
            "include": (lambda t: t.replace('version: "3.7"\n', 'version: "3.7"\ninclude:\n  - extra.yml\n', 1),
                {"extra.yml": f'services:\n  evil:\n    image: {ui}\n    user: "1000:1000"\n    volumes:\n' + node_mount}, "top-level 'include' is not allowed"),
            "a build context of the node's folder": (lambda t: t.replace("    image: xbt-vpn:0.1.0\n",
                "    image: xbt-vpn:0.1.0\n    build:\n      context: ${APP_LIGHTNING_FORK_NODE_DATA_DIR}\n", 1), {}, "'build' is not allowed"),
            "a mount that climbs out with ..": (lambda t: t.rstrip() + "\n" + evil(
                f"    image: {init}\n    restart: \"no\"\n    network_mode: none\n    read_only: true\n    cap_drop: [ALL]\n    cap_add: [DAC_OVERRIDE]\n"
                "    security_opt: [no-new-privileges:true]\n    volumes:\n      - ${APP_DATA_DIR}/../paulscode-lightning-fork/data/lnd:/lnd\n"), {}, "climbs out with .."),
            "the docker socket": (lambda t: t.replace("  ui:\n    <<: *service\n", "  ui:\n    <<: *service\n    use_api_socket: true\n", 1), {}, "'use_api_socket' is not allowed"),
            "a post_start hook in the baker": (lambda t: t.replace(bake_cmd, bake_cmd + "    post_start:\n      - command: [\"/usr/bin/xbt-wallet-ui\", \"serve\"]\n"
                "        user: \"0:0\"\n        privileged: true\n", 1), {}, "'post_start' is not allowed"),
            "an env_file into the baker": (lambda t: t.replace(bake_cmd, '    command: ["node-keys"]\n    env_file: [bake.env]\n    user: "1000:1000"\n', 1),
                {"bake.env": "XBT_KEYS_GRANT_DIR=/node\n"}, ("'env_file' is not allowed", "bake.env " + files)),
            "the baker written twice": (lambda t: t.replace("  node-keys-bake:\n", f"  node-keys-bake:\n    image: {init}\n    volumes: [*lightning-data]\n  node-keys-bake:\n", 1),
                {}, "is written twice"),
            "the baker's user written twice": (lambda t: t.replace('    user: "1000:1000"\n', '    user: "0:0"\n    user: "1000:1000"\n', 1), {}, "is written twice"),
            "a named volume": (lambda t: t.rstrip() + "\nvolumes:\n  node:\n    driver_opts:\n      type: none\n      o: bind\n"
                "      device: ${APP_LIGHTNING_FORK_NODE_DATA_DIR}\n", {}, "top-level 'volumes' is not allowed"),
            # MEDIUM-A: a default holds whatever a missing variable lets in
            "a default on a variable": (lambda t: t.replace(ui_mount, "      - ${APP_DATA_DIR}/${LS_UI:-data/ui}:/data/ui\n", 1), {}, subst),
            "a slot stand-in's variable with a default": (lambda t: t.replace(init_mount, init_mount
                + "      - ${APP_DATA_DIR}/data/${APP_XBT_KNOTS_CHAIN:-../../paulscode-lightning-fork/data/lnd}:/keys:ro\n", 1), {}, subst),
            "a .env with a default beside it": (lambda t: t.replace(ui_mount, "      - ${APP_DATA_DIR}/${LS_SUB:-../paulscode-lightning-fork/data/lnd}:/data/ui\n", 1),
                {".env": "LS_SUB=data/ui\n"}, (".env " + files, subst)),
            "a variable without braces": (lambda t: t.replace(ui_mount, ui_mount + "      - $APP_LIGHTNING_FORK_NODE_DATA_DIR:/lf:ro\n", 1), {}, subst),
            # MEDIUM-B: what umbrelOS does with the rest of the app's folder
            "a hook": (lambda t: t, {"hooks/pre-start": "#!/bin/sh\ncp \"$APP_DATA_DIR/../paulscode-lightning-fork/data/lnd/tls.key\" /tmp/\n"}, "hooks/pre-start " + files),
            "a template": (lambda t: t, {"docker-compose.yml.template": "services: {}\n"}, "docker-compose.yml.template " + files),
            "an override file": (lambda t: t, {"docker-compose.override.yml": "services:\n  ui:\n    volumes:\n" + node_mount}, "docker-compose.override.yml " + files),
            "a link in the app's folder": (lambda t: t, {"data/run/ln": ("link", "../../../paulscode-lightning-fork/data/lnd/data/chain/bitcoin/mainnet")}, "data/run/ln is a link"),
            "shell in exports.sh": (lambda t: t, {"exports.sh": ("append", 'export APP_LAZARUS_LS_KEYS="data/run/keys"\nAPP_LAZARUS_LS_KEYS="../paulscode-lightning-fork/data/lnd"\n')}, exports),
            "a command in exports.sh": (lambda t: t, {"exports.sh": ("append", 'export APP_LAZARUS_LS_KEYS="$(printf %s ../paulscode-lightning-fork/data/lnd)"\n')}, exports),
            "an escaped dollar": (lambda t: t.replace(ui_mount, ui_mount.replace("data/ui:", "data/ui$$x:", 1), 1), {}, subst),
            # F3: what the loaded file holds, though its text shows no $ or hides it in a "comment"
            "a YAML escape for $ with a default": (lambda t: t.replace(ui_env, ui_env + '      PROBE: "\\x24{APP_XBT_KNOTS_CHAIN:-../../paulscode-lightning-fork}"\n', 1), {},
                ("/services/ui/environment/PROBE", subst)),
            "a YAML escape for $ without braces": (lambda t: t.replace(ui_env, ui_env + '      PROBE: "\\u0024NOPE"\n', 1), {}, ("/services/ui/environment/PROBE", subst)),
            "a block scalar line that looks like a comment": (lambda t: t.replace(ui_env, ui_env + "      PROBE: |\n        # ${NOPE:-default}\n", 1), {},
                ("/services/ui/environment/PROBE", subst)),
            # bytes or a set: compose substitutes inside them, a walk of text values does not see them
            "a !!binary value": (lambda t: t.replace(ui_env, ui_env + "      PROBE: !!binary JHtOT1BFOi1kZWZ9\n", 1), {}, "!!binary is not allowed"),
            "a !!set value": (lambda t: t.replace(ui_env, ui_env + '      PROBE: !!set {"${NOPE:-x}": null}\n', 1), {}, "!!set is not allowed"),
            "a variable passed through to another service": (lambda t: t.replace(ui_env, ui_env + "      LD_PRELOAD:\n", 1), {},
                "ui: its environment passes a variable through from the host's"),
            # F1: exports.sh as bash reads it
            "a vertical tab in exports.sh": (lambda t: t, {"exports.sh": ("append_bytes", b'export APP_LIGHTNING_STREAM_APP_PROBE="x"\x0b# ; echo PWNED\n')},
                "exports.sh holds bytes other than printable ASCII and newline (0x0b)"),
            "a leading \\x1f in exports.sh": (lambda t: t, {"exports.sh": ("append_bytes", b"\x1f# ; echo PWNED\n")},
                "exports.sh holds bytes other than printable ASCII and newline (0x1f)"),
            "a carriage return in exports.sh": (lambda t: t, {"exports.sh": ("append_bytes", b'export APP_LIGHTNING_STREAM_APP_PROBE="x"\r# ; echo PWNED\n')},
                "exports.sh holds bytes other than printable ASCII and newline (0x0d)"),
            # F2: an app's exports set its own names only
            "PATH in exports.sh": (lambda t: t, {"exports.sh": ("append", 'export PATH="/home/umbrel/umbrel/app-data/lazarus-lightning-stream/data/ui:/usr/bin"\n')},
                "sets PATH: this app's names start with APP_LIGHTNING_STREAM_APP_"),
            "the Lightning node's address in this app's exports": (lambda t: t, {"exports.sh": ("append", 'export APP_LIGHTNING_FORK_NODE_IP="203.0.113.9"\n')},
                ("sets APP_LIGHTNING_FORK_NODE_IP", "node-keys-bake's environment is not exactly")),
            # F5: an app folder that is a link to another
            "an app folder that is a link": (lambda t: t, {"../lazarus-link": ("link", "lazarus-lightning-stream")}, "store: lazarus-link is a link"),
            # LOW-5: YAML 1.1 reads `on:` as true
            "a service named on": (lambda t: t.rstrip() + f"\n\n  on:\n    <<: *service\n    image: {ui}\n", {}, "is not a string"),
        }
        for why, (change, extra, says) in cases.items():
            with self.subTest(why=why):
                self.fresh()
                text = self.compose.read_text()
                changed = change(text)
                self.assertTrue(changed != text or extra, f"{why}: the case did not apply")
                self.compose.write_text(changed)
                for rel, content in extra.items():
                    f = self.compose.parent / rel
                    f.parent.mkdir(parents=True, exist_ok=True)
                    if isinstance(content, tuple) and content[0] == "link":
                        f.symlink_to(content[1])
                    elif isinstance(content, tuple) and content[0] == "append":
                        f.write_text(f.read_text() + content[1])
                    elif isinstance(content, tuple) and content[0] == "append_bytes":
                        with open(f, "ab") as fh:
                            fh.write(content[1])
                    else:
                        f.write_text(content)
                ok, out = lint(self.store)
                self.assertFalse(ok, f"lint passed a store with {why}:\n{out[-1500:]}")
                self.says(out, why, says)


if __name__ == "__main__":
    unittest.main()
