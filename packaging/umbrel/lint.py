#!/usr/bin/env python3
"""Lint the local Umbrel store.

Manifest: the keys umbrelOS reads, manifestVersion 1/1.1, a known category, the id prefixed with the store id,
an icon and gallery images given as URLs (umbrelOS shows a community store's `icon` and `gallery` as they are: a
file name or an empty icon shows nothing), each a raw.githubusercontent.com URL on this repository's main branch
of a file in the app's own folder here, the icon a plain SVG (no script, nothing fetched); a gallery for every app
but the stand-in node; `submission` a URL into this repository (a store submission is the project owner's
decision); dependencies in this store, a node slot (`bitcoin`) an app here implements, or an app
of another community store named in OTHER_STORES (Lightning Fork), unique ports, `deterministicPassword` when
${APP_PASSWORD} is used.
Compose: app_proxy's APP_HOST is `<app-id>_<service>_1` of a real service; every volume is under
${APP_DATA_DIR}; every agentpay image is a published one, ghcr.io/awokenlazarus/<image>:<version>-<commit>@sha256:<digest>,
the very reference packaging/images.lock pins (the stand-in node's image is the one local image, amd64-only;
lightning-stream:0.1.0 is the connector, and xbt-hashlink, xbt-vpn and xbt-datum-gateway likewise have no digest until
they are published); every ${VAR} is provided by umbrelOS,
this app's exports or a dependency's exports; a slot's variable (APP_BITCOIN_*, set by whichever node app the
owner selects) is only used as `${APP_BITCOIN_X:-${FALLBACK}}` with a fallback this store's implementing app
exports; `docker compose config` accepts the file with those values, and with the slot's values alone.
Hardening (docs/CONTAINER.md): the agentpay services run read-only, cap_drop ALL, no-new-privileges, under an init
(init: true), as their image's non-root user, and mount only their own sub-dir plus the dirs they need (a peer's read-only); of the
Lightning node's data, only its tls.cert, read-only, as a bind that never creates a missing path; no
admin macaroon. The one exception is the one-shot `node-keys-bake`, node-keys from the UI's image with no
entrypoint and exactly its environment: as the Lightning app's user it mounts that app's data folder read-only,
and writes only the hand-over folder run/node-keys. `init` (xbt-init) is the only root container: no network, at
most CHOWN/FOWNER/DAC_OVERRIDE.
Shape: the compose file is read strictly (a key written twice is refused) and its keys are allowed, not refused
(no extends, include, build, secrets, configs, env_file, hooks, ...); an entrypoint only where one is pinned; no
`..` in a mount; ${NAME}, ${NAME:-} and a slot's ${SLOT:-${FALLBACK}} the only substitutions (no default); a name
is a string; xbt-init is one service, init, mounting the data dir alone; a network namespace is joined only where
pinned (the Stream Gateway always in the renter's, with no port); the node-keys one-shots run no healthcheck, and the baker's environment is exactly its own. Every rule on what
a container reaches is checked again on the model `docker compose config` resolves (no .env read), with the host's
folders marked, in each environment lint resolves (this store's apps, and a slot's node alone), so that nothing
written can hide a mount from it. Package: an app's folder holds its manifest, compose file, exports.sh, the icon and
gallery it names, and named others, and no link (nor is any entry of the store a link); exports.sh is printable ASCII
read line by line as bash reads it, and holds comments and `export NAME="literal"` lines setting the app's own names
(its prefix), the stand-in node's derive_entropy line named as the one exception. The substitution rule holds for
every string of the loaded file as well (a YAML escape or a block scalar's line is what compose reads).
    python3 packaging/umbrel/lint.py [STORE_DIR]
"""
from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pin_images import REF, load_lock  # noqa: E402

REQUIRED = ["manifestVersion", "id", "category", "name", "version", "tagline", "description", "developer", "website",
            "repo", "support", "port", "gallery", "dependencies", "submitter", "submission", "icon"]
# where the icon and the gallery are served from: this repository's main branch, the app's folder in this store
RAW = "https://raw.githubusercontent.com/AwokenLazarus/Lightning-Stream/main/packaging/umbrel"
# what `submission` may point at: this repository (never an app store's pull request)
SUBMISSION = "https://github.com/AwokenLazarus/Lightning-Stream/"
CATEGORIES = {"bitcoin", "lightning", "finance", "networking", "social", "media", "automation", "developer", "ai", "files"}
# what umbrelOS sets for every app's compose
UMBREL_VARS = {"APP_DATA_DIR", "APP_SEED", "APP_PASSWORD", "DEVICE_DOMAIN_NAME", "DEVICE_HOSTNAME", "TOR_PROXY_IP", "TOR_PROXY_PORT",
               "APP_HIDDEN_SERVICE"}
# the agentpay images: published, pinned by digest (packaging/images.lock); the registry is this one
REGISTRY = "ghcr.io/awokenlazarus"
# the one image of this store that is not published: the stand-in XBT node (lazarus-xbt-knots), amd64-only, which
# a box with Paul's Knots BLAKE2b Companion never installs
LOCAL_ONLY = {"lazarus-xbt-knots": re.compile(r"^xbt-a3-knots:29\.4\.2$")}
# the connector, xbt-hashlink, xbt-vpn and the Stream Gateway have no line in images.lock yet. oci_build.sh
# --load tags them <image>:0.1.0. A digest is not invented here. Anything else (a registry name, a made-up
# digest) still fails.
UNPUBLISHED = re.compile(r"^(lightning-stream|xbt-hashlink|xbt-vpn|xbt-datum-gateway):0\.1\.0$")
# Umbrel's shared Downloads (the Files app's Downloads), read-only, for the wallet's Files service only.
# umbrelOS 1.x rewrites this compatibility path to ${UMBREL_ROOT}/home/Downloads; the app must declare
# the STORAGE_DOWNLOADS permission (umbrel-apps .agents/skills/umbrel-package-app/SKILL.md).
DOWNLOADS_MOUNT = "${UMBREL_ROOT}/data/storage/downloads:/downloads:ro"
DOWNLOADS_IMAGES = {"xbt-wallet-ui"}

def base_of(img):
    """An image reference's name: `<registry>/<name>:<tag>@<digest>` or a local `<name>:<tag>`."""
    m = REF.match(img)
    return m["name"] if m else img.split("/")[-1].split(":")[0]

# the stream directory the connector (and the VPN service, for paid tunnels) writes, inside the signer's
# socket dir. Read-write, and the only extra mount either may have. Neither gets the signer's state.
STREAM_MOUNT = "${APP_DATA_DIR}/data/run/signer/streams:/data/run/signer/streams"
# image -> (component sub-dir or None, run/ dirs it writes, run/ dirs it may mount read-only)
AGENTPAY = {
    # run/enroll: the copy of the one-time enrolment code the signer writes for the setup page. run/shops,
    # read-only: the shops reached by key, for callers that hand it no transport document (the AI
    # address, agents)
    # run/rental: the hashrate renter's own socket, which the signer serves
    "xbt-signer": ("signer", {"signer", "enroll", "rental"}, {"anchor", "ln", "shops"}),
    "xbt-anchor-witness": ("witness", {"anchor"}, set()),
    # run/ui holds the UI-owned MCP token; the MCP may only read it. run/shops: the shops without a
    # web address the UI keeps, read by the connector and the MCP to hand to the signer
    "xbt-wallet-mcp": ("mcp", set(), {"signer", "ui", "shops"}),
    # the setup pages write run/ln (the rail macaroon), run/gateway (the gateway's config and macaroons)
    # and run/hashrate (the hasher's settings); the AI page writes run/ai (keys, sellers)
    # and run/vpn (the devices and exit the VPN pages set), reading the VPN service's status; and
    # run/datum (the Stream Gateway's config, from the Hashrate page)
    "xbt-wallet-ui": ("ui", {"ui", "ln", "gateway", "hashrate", "shops", "ai", "vpn", "datum"}, {"signer", "enroll", "vpn-status"}),
    "xbt-gateway": ("gateway", set(), {"gateway"}),
    # no state of its own. The control socket is read-only; the stream sockets are STREAM_MOUNT. The AI
    # endpoint books the keys' spend and the sellers' health in run/ai, shared by group with the UI
    "lightning-stream": (None, {"ai"}, {"signer", "shops"}),
    # the hasher and the renter: their keys and state; the settings and token read-only; the renter
    # also its own socket of the signer's (run/rental), read-only, and not the wallet's
    "xbt-hashlink": ("hashrate", set(), {"hashrate", "rental"}),
    # the VPN service: its keys and lists; the settings read-only; its status for the UI. Priced exits
    # are paid through the owner's wallet: the signer's socket and the shops read-only, and the stream
    # sockets are STREAM_MOUNT (each paid tunnel's socket is made there)
    "xbt-vpn": ("vpn", {"vpn-status"}, {"vpn", "signer", "shops"}),
    # the Stream Gateway (DATUM-compatible): its found blocks; its config and the node's RPC cookie read-only
    "xbt-datum-gateway": ("datum", set(), {"datum"}),
}
# the Lightning node's certificate: the only file of another app's data a service here may mount
CERT_MOUNT = {"type": "bind", "source": "${APP_LIGHTNING_FORK_NODE_DATA_DIR}/tls.cert", "target": "/data/lightning/tls.cert", "read_only": True,
              "bind": {"create_host_path": False}}
# The Lightning node's data folder, read-only, never created: the rule "of another app's data, a file
# only, never a directory" is relaxed for ONE container, named NODE_KEYS_BAKE. Lightning Fork's
# directories are its user's alone (0700), and its admin macaroon appears only when the owner makes the
# wallet, so a mount of that one file stops the install until then (Docker refuses a missing file). The
# baker runs as that user (1000), reads the folder only to have the node bake the app's narrow
# macaroons, writes only the hand-over folder, and exits.
# What the folder exposes beyond the admin macaroon: wallet.db, macaroons.db and tls.key (and the SHA256
# bridge node's wallet and its password file). A compromised baker image could take the wallet's seed
# when the wallet password is known, and Lightning Fork's dashboard uses a fixed default one. Accepted
# for 0.2.0 because the admin macaroon the baker needs anyway already allows draining the node; the
# way out is for Lightning Fork to hand narrow macaroons to apps itself (asked of its author for
# 0.2.1). Every other container: tls.cert only.
NODE_KEYS_BAKE = "node-keys-bake"
NODE_DIR_MOUNT = {"type": "bind", "source": "${APP_LIGHTNING_FORK_NODE_DATA_DIR}", "target": "/node", "read_only": True,
                  "bind": {"create_host_path": False}}
NODE_KEYS_BAKE_MOUNTS = {"${APP_DATA_DIR}/data/run/ln:/data/run/ln:ro", "${APP_DATA_DIR}/data/run/gateway:/data/run/gateway:ro",
                         "${APP_DATA_DIR}/data/run/node-keys:/data/run/node-keys"}
# its user, and its groups: the hand-over's (the UI's), run/gateway's and run/ln's, read only
NODE_KEYS_BAKE_USER = "1000:1000"
NODE_KEYS_BAKE_GROUPS = {"10005", "10007", "10008"}
# node-keys itself (the UI's user) reads nothing of the Lightning app: it moves the baked keys from the
# hand-over into run/ln and run/gateway
NODE_KEYS_MOUNTS = {"${APP_DATA_DIR}/data/run/ln:/data/run/ln", "${APP_DATA_DIR}/data/run/gateway:/data/run/gateway",
                    "${APP_DATA_DIR}/data/run/node-keys:/data/run/node-keys"}

# The compose shape a store app may take, checked twice: as written (anchors and merges applied), and
# as `docker compose config` resolves it (extends, include and env_file applied too). Keys are allowed,
# not refused: one these rules do not know (build, secrets, configs, post_start, use_api_socket, ...)
# cannot carry another app's data or this box's in.
TOP_KEYS = {"version", "services"}  # and x- extension fields
SERVICE_KEYS = {"image", "command", "entrypoint", "user", "restart", "init", "read_only", "tmpfs", "cap_drop", "cap_add",
                "security_opt", "depends_on", "environment", "volumes", "ports", "healthcheck", "stop_grace_period",
                "network_mode", "group_add"}
APP_PROXY_KEYS = {"environment"}
# what `docker compose config` writes of its own: the project name and its default network
RESOLVED_TOP_KEYS = {"name", "networks", "services"}
RESOLVED_SERVICE_KEYS = SERVICE_KEYS | {"networks"}
RESOLVED_APP_PROXY_KEYS = {"image", "environment", "networks"}
# an entrypoint replaces what the image runs: only these, exactly
SIGNER_ENTRYPOINT = ["/usr/bin/xbt-supervise", "--watch", "/data/run/ln/rail.macaroon", "--watch", "/data/lightning/tls.cert", "--",
                     "/usr/bin/xbt-signer"]
# the Stream Gateway: started once its config is written, again when that or the node's cookie changes, and
# gone (to be restarted in the renter's namespace as it is then) when the renter's control port stops answering
DATUM_ENTRYPOINT = ["/usr/bin/xbt-supervise", "--wait", "/data/run/datum/config.json", "--watch", "/data/run/datum/rpc.cookie",
                    "--peer", "127.0.0.1:23343", "--", "/usr/bin/xbt-datum-gateway", "-c", "/data/run/datum/config.json"]
ENTRYPOINTS = {("lazarus-lightning-stream", "signer"): SIGNER_ENTRYPOINT, ("lazarus-xbt-agent-wallet", "signer"): SIGNER_ENTRYPOINT,
               ("lazarus-xbt-knots", "node"): ["bitcoind"], ("lazarus-lightning-stream", "datum"): DATUM_ENTRYPOINT}
# the baker's whole environment, as written (nothing more reaches it: no env_file)
NODE_KEYS_BAKE_ENV = {"XBT_KEYS_NODE_REST": "https://${APP_LIGHTNING_FORK_NODE_IP}:${APP_LIGHTNING_FORK_NODE_REST_PORT}",
                      "XBT_KEYS_TLS_CERT": "/node/tls.cert", "XBT_KEYS_ADMIN": "/node/data/chain", "XBT_KEYS_RAIL_DIR": "/data/run/ln",
                      "XBT_KEYS_GW_DIR": "/data/run/gateway", "XBT_KEYS_BAKE_TO": "/data/run/node-keys", "XBT_KEYS_RETRY_MAX_S": "30"}
# the network namespaces a service may join: the connector shares the UI's, and the Stream Gateway the
# renter's (loopback only: its stratum and its /xbt/job are the renter's alone)
NETNS = {("lazarus-lightning-stream", "connector"): "service:ui", ("lazarus-lightning-stream", "datum"): "service:renter"}
# xbt-init (root, CHOWN/FOWNER/DAC_OVERRIDE): one service, `init`, its own command, the data dir alone
INIT_VOLUMES = ["${APP_DATA_DIR}/data:/data"]
# a one-shot node-keys runs nothing else in its container: no healthcheck command
ONESHOT_HEALTH = {"disable": True}
# ${...} as written: a variable, an empty default, or a slot's variable with its fallback; no default
# value (it would hold whatever path or address a missing variable lets in) and no other form
SUBST = re.compile(r"\$\{[A-Z0-9_]+:-\$\{[A-Z0-9_]+\}\}|\$\{[A-Z0-9_]+(?::-)?\}")
# The files of an app's folder umbrelOS acts on (it copies the folder into the box's app data, runs
# hooks/, renders templates, sources exports.sh as shell): these, the icon and gallery the manifest
# names, and per app the named others; never a link.
APP_FILES = {"umbrel-app.yml", "docker-compose.yml", "exports.sh"}
EXTRA_FILES = {"lazarus-lightning-stream-gateway": {"data/.gitkeep"}, "lazarus-xbt-agent-wallet": {"data/.gitkeep"},
               "lazarus-xbt-knots": {"README.md", "conf/peers.conf", "conf/xbt.conf", "data/knots/.gitkeep"}}
# the names an app's exports.sh may set: its own, under its own prefix (not another app's, umbrelOS's or
# the shell's: PATH, BASH_ENV, LD_PRELOAD, APP_DATA_DIR, a dependency's APP_LIGHTNING_FORK_NODE_IP)
EXPORT_PREFIX = {"lazarus-lightning-stream": "APP_LIGHTNING_STREAM_APP_", "lazarus-lightning-stream-gateway": "APP_LIGHTNING_STREAM_GATEWAY_",
                 "lazarus-xbt-agent-wallet": "APP_XBT_AGENT_WALLET_", "lazarus-xbt-knots": "APP_XBT_KNOTS_"}
# exports.sh: comments and `export NAME="literal"` lines, and this one line of the stand-in node's
# (umbrelOS's derive_entropy: a per-box secret from the box seed and the label)
EXPORTS_EXCEPTIONS = {"lazarus-xbt-knots": {'export APP_XBT_KNOTS_RPC_PASS="$(derive_entropy "lazarus-xbt-knots-rpc-${APP_XBT_KNOTS_RPC_USER}")"'}}
# stand-ins for the host's folders in the resolved model, so that each mount's source says whose it is
MARKS = {"APP_DATA_DIR": "/__app_data__", "APP_LIGHTNING_FORK_NODE_DATA_DIR": "/__lightning_fork_data__", "UMBREL_ROOT": "/__umbrel_root__"}


class StrictLoader(yaml.SafeLoader):
    """yaml.safe_load that refuses a key written twice in one mapping: PyYAML keeps the last, so a second
    `user:` or a second service of the same name would be what lint reads but not what was written.
    Keys a merge (<<) brings in are not the mapping's own and may be overridden, as Compose allows."""

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for k, _ in node.value:
                # a merged pair's key sits in the anchored mapping, outside this one's text
                if k.tag == "tag:yaml.org,2002:merge" or not node.start_mark.index <= k.start_mark.index <= node.end_mark.index:
                    continue
                key = self.construct_object(k, deep=deep)
                if key in seen:
                    raise yaml.constructor.ConstructorError(None, None, f"{key!r} is written twice", k.start_mark)
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _refused_tag(loader, node):
    # bytes, a set or pairs: lint's walk would not see a substitution compose still makes inside them
    raise yaml.constructor.ConstructorError(None, None, f"{node.tag.replace('tag:yaml.org,2002:', '!!')} is not allowed", node.start_mark)


for _tag in ("binary", "set", "omap", "pairs"):
    StrictLoader.add_constructor(f"tag:yaml.org,2002:{_tag}", _refused_tag)


def package_files(folder: str, here: Path, m: dict) -> None:
    """Only the app's own files, and no link: umbrelOS acts on more of the folder than the compose file."""
    allowed = APP_FILES | {Path(str(u)).name for u in [m.get("icon"), *(m.get("gallery") or [])] if u} | EXTRA_FILES.get(folder, set())
    for dirpath, dirs, files in os.walk(here):
        for n in dirs + files:
            p = Path(dirpath) / n
            rel = p.relative_to(here).as_posix()
            if p.is_symlink():
                bad(f"{folder}: {rel} is a link (umbrelOS copies the app's folder as it is)")
            elif p.is_file() and rel not in allowed:
                bad(f"{folder}: {rel} is not one of the app's files ({', '.join(sorted(allowed))})")
    ex = here / "exports.sh"
    if ex.is_file() and not ex.is_symlink():
        # read as bash reads it: printable ASCII and \n only (Python would also break lines at \r, VT, FF,
        # U+2028 ..., and strip \x1f or a no-break space, where bash sees one line and runs what follows)
        raw = ex.read_bytes()
        odd = sorted({b for b in raw if b != 0x0A and not 0x20 <= b <= 0x7E})
        if odd:
            bad(f"{folder}: exports.sh holds bytes other than printable ASCII and newline ({', '.join(f'0x{b:02x}' for b in odd[:8])})")
        prefix = EXPORT_PREFIX.get(folder)
        for i, line in enumerate(raw.decode("ascii", "replace").split("\n"), 1):
            t = line.strip(" \t")
            if not t or t.startswith("#") or t in EXPORTS_EXCEPTIONS.get(folder, set()):
                continue
            mm = re.fullmatch(r'export ([A-Z][A-Z0-9_]*)="[^"$`\\]*"', t)
            if not mm:
                bad(f"{folder}: exports.sh line {i} is not export NAME=\"literal\" (it is sourced as shell): {t[:120]!r}")
            elif not prefix or not mm.group(1).startswith(prefix):
                bad(f"{folder}: exports.sh line {i} sets {mm.group(1)}: this app's names start with {prefix}")


def substitutions(folder: str, text_nc: str) -> None:
    """Every $ in the compose file is ${NAME}, ${NAME:-} or a slot's ${SLOT:-${FALLBACK}}."""
    for mm in re.finditer(r"\$\S{0,60}", SUBST.sub("", text_nc)):
        bad(f"{folder}: {mm.group(0)!r}: only ${{NAME}}, ${{NAME:-}} and a slot's ${{SLOT:-${{FALLBACK}}}} (no default, no other form)")


def bind_of(v):
    """A resolved mount's bind options: a mapping ({} when there are none), or what else is written there."""
    b = v.get("bind")
    return {} if b is None or b == [] else b


def env_of(sv) -> dict:
    """A service's environment as a mapping, whichever form it is written in (an item with no = passes the
    host's value through: it maps to None)."""
    env = sv.get("environment") if isinstance(sv, dict) else None
    if isinstance(env, list):
        return {pr[0]: (pr[1] if len(pr) == 2 else None) for pr in (str(e).split("=", 1) for e in env)}
    return {str(k): v for k, v in env.items()} if isinstance(env, dict) else {}


def loaded_substitutions(folder: str, node, where: str = "") -> None:
    """The same rule on every string of the loaded file, keys too: a YAML escape (\\x24, \\u0024) or a block
    scalar's '#' line is a $ or a line compose reads, though the text shows neither."""
    if isinstance(node, dict):
        for k, v in node.items():
            loaded_substitutions(folder, k, where)
            loaded_substitutions(folder, v, f"{where}/{k}")
    elif isinstance(node, list):
        for v in node:
            loaded_substitutions(folder, v, where)
    elif isinstance(node, str):
        if "$" in SUBST.sub("", node):
            bad(f"{folder}: {where or 'a key'}: {node[:80]!r}: only ${{NAME}}, ${{NAME:-}} and a slot's ${{SLOT:-${{FALLBACK}}}} (no default, no other form)")
    elif not isinstance(node, (int, float, bool, type(None), datetime.date)):
        bad(f"{folder}: {where or 'a key'}: a {type(node).__name__} value (only text, numbers, booleans, null and dates)")


def raw_shape(folder: str, c: dict, svcs: dict) -> None:
    """The compose file as written: only known keys, a pinned entrypoint, and no `..` in a mount."""
    for k in [*c, *svcs]:
        if not isinstance(k, str):
            bad(f"{folder}: the name {k!r} is not a string (YAML 1.1 reads on, yes, no and numbers as other things)")
    for k in c:
        if k not in TOP_KEYS and not str(k).startswith("x-"):
            bad(f"{folder}: top-level {k!r} is not allowed (version, services and x- fields only)")
    inits = [n for n, sv in svcs.items() if base_of(str(sv.get("image", ""))) == "xbt-init"]
    if inits and inits != ["init"]:
        bad(f"{folder}: xbt-init runs as one service, named init, not {inits}")
    for n in inits:
        if svcs[n].get("command") not in (None, ["init"]) or svcs[n].get("volumes") != INIT_VOLUMES:
            bad(f"{folder}/{n}: xbt-init runs its own command (init) and mounts {INIT_VOLUMES} alone")
    if NODE_KEYS_BAKE in svcs:
        env = {k: str(v) for k, v in env_of(svcs[NODE_KEYS_BAKE]).items()}
        if env != NODE_KEYS_BAKE_ENV:
            bad(f"{folder}/{NODE_KEYS_BAKE}: its environment is not exactly {NODE_KEYS_BAKE_ENV}")
    for name, sv in svcs.items():
        if any(v is None for v in env_of(sv).values()):
            bad(f"{folder}/{name}: its environment passes a variable through from the host's (an item with no value)")
        nm = sv.get("network_mode")
        if nm not in (None, "none") and nm != NETNS.get((folder, name)):
            bad(f"{folder}/{name}: network_mode {nm!r}: none, or the namespace pinned for it ({NETNS.get((folder, name))})")
        if sv.get("command") == ["node-keys"] and sv.get("healthcheck") != ONESHOT_HEALTH:
            bad(f"{folder}/{name}: a node-keys one-shot's healthcheck is exactly {ONESHOT_HEALTH}")
        allowed = APP_PROXY_KEYS if name == "app_proxy" else SERVICE_KEYS
        for k in sv:
            if k not in allowed:
                bad(f"{folder}/{name}: {k!r} is not allowed (allowed: {sorted(allowed)})")
        if "entrypoint" in sv and sv["entrypoint"] != ENTRYPOINTS.get((folder, name)):
            bad(f"{folder}/{name}: entrypoint {sv['entrypoint']!r} is not the one pinned for it")
        for v in sv.get("volumes") or []:
            src = str(v.get("source", "")) if isinstance(v, dict) else str(v).split(":")[0]
            if ".." in src.replace("\\", "/").split("/"):
                bad(f"{folder}/{name}: mount {src!r} climbs out with ..")


def resolved_shape(folder: str, cfg: dict, svcs: dict, env: dict) -> None:
    """The model `docker compose config` resolves, with MARKS for the host's folders: every rule on what
    a container may reach is checked again here, where nothing written can hide from it."""
    app, node, umbrel = (MARKS[k] for k in ("APP_DATA_DIR", "APP_LIGHTNING_FORK_NODE_DATA_DIR", "UMBREL_ROOT"))
    for k in cfg:
        if k not in RESOLVED_TOP_KEYS and not str(k).startswith("x-"):
            bad(f"{folder}: resolved, top-level {k!r} is not allowed")
    for n, net in (cfg.get("networks") or {}).items():
        if n != "default" or set(net or {}) - {"name", "ipam"} or (net or {}).get("ipam"):
            bad(f"{folder}: resolved, network {n!r} is not the app's plain default one")
    rs = cfg.get("services") or {}
    if set(rs) != set(svcs):
        bad(f"{folder}: resolved, the services {sorted(set(rs) ^ set(svcs), key=str)} are not the ones written here (include, extends)")
    for name, sv in rs.items():
        allowed = RESOLVED_APP_PROXY_KEYS if name == "app_proxy" else RESOLVED_SERVICE_KEYS
        for k, v in sv.items():
            # compose writes some keys it was not given as null
            if v is not None and k not in allowed:
                bad(f"{folder}/{name}: resolved, {k!r} is not allowed")
        if sv.get("entrypoint") is not None and sv["entrypoint"] != ENTRYPOINTS.get((folder, name)):
            bad(f"{folder}/{name}: resolved, entrypoint {sv['entrypoint']!r} is not the one pinned for it")
        if set(map(str, sv.get("security_opt") or [])) - {"no-new-privileges:true"}:
            bad(f"{folder}/{name}: resolved, security_opt may only be no-new-privileges:true")
        nm = sv.get("network_mode")
        if nm not in (None, "none") and nm != NETNS.get((folder, name)):
            bad(f"{folder}/{name}: resolved, network_mode {nm!r}: none, or the namespace pinned for it")
        if sv.get("command") == ["node-keys"] and sv.get("healthcheck") != ONESHOT_HEALTH:
            bad(f"{folder}/{name}: resolved, a node-keys one-shot's healthcheck is exactly {ONESHOT_HEALTH}")
        img = str(sv.get("image", ""))
        if base_of(img) == "xbt-init":
            plain = ({}, {"create_host_path": True})
            vols = [(v.get("type"), v.get("source"), v.get("target"), v.get("read_only") is True, bind_of(v) in plain) for v in sv.get("volumes") or []]
            if name != "init" or sv.get("command") not in (None, ["init"]) or vols != [("bind", app + "/data", "/data", False, True)]:
                bad(f"{folder}/{name}: resolved, xbt-init is the service init, its own command, the data dir alone")
        for v in sv.get("volumes") or []:
            src, tgt, ro = str(v.get("source") or ""), v.get("target"), v.get("read_only") is True
            b = bind_of(v)
            never = isinstance(b, dict) and b.get("create_host_path") is False
            if v.get("type") != "bind":
                bad(f"{folder}/{name}: resolved, a {v.get('type')} mount (bind mounts only): {v}")
            elif not isinstance(b, dict) or set(b) - {"create_host_path"}:
                bad(f"{folder}/{name}: resolved, bind options {v.get('bind')} (none but create_host_path)")
            elif os.path.normpath(src) != src:
                bad(f"{folder}/{name}: resolved, mount source {src!r} is not a plain path")
            elif src == node or src.startswith(node + "/"):
                cert = src == node + "/tls.cert" and tgt == "/data/lightning/tls.cert" and ro and never
                folder_mount = name == NODE_KEYS_BAKE and src == node and tgt == "/node" and ro and never
                if not (cert or folder_mount):
                    bad(f"{folder}/{name}: resolved, mounts the Lightning node's data ({src} -> {tgt}): its tls.cert only, or node-keys-bake's read-only folder")
            elif src == umbrel or src.startswith(umbrel + "/"):
                if src != umbrel + "/data/storage/downloads" or tgt != "/downloads" or not ro or base_of(img) not in DOWNLOADS_IMAGES:
                    bad(f"{folder}/{name}: resolved, mounts the box's own files ({src}): Umbrel's Downloads only, read-only, for the UI")
            elif not src.startswith(app + "/"):
                bad(f"{folder}/{name}: resolved, mount source {src!r} is not under the app's data")
        if name == NODE_KEYS_BAKE:
            want = {(app + "/data/run/ln", "/data/run/ln", True), (app + "/data/run/gateway", "/data/run/gateway", True),
                    (app + "/data/run/node-keys", "/data/run/node-keys", False), (node, "/node", True)}
            got = {(v.get("source"), v.get("target"), v.get("read_only") is True) for v in sv.get("volumes") or []}
            got_env = {k: str(v) for k, v in (sv.get("environment") or {}).items()}
            # Lightning Fork's own exports, never this app's: the admin macaroon goes nowhere else
            lf = {**OTHER_STORES["paulscode-lightning-fork"], **MARKS}
            want_env = {k: re.sub(r"\$\{([A-Z0-9_]+)\}", lambda mm: str(lf.get(mm.group(1), "")), v) for k, v in NODE_KEYS_BAKE_ENV.items()}
            if base_of(img) != "xbt-wallet-ui" or sv.get("entrypoint") is not None or sv.get("command") != ["node-keys"]:
                bad(f"{folder}/{name}: resolved, node-keys-bake is node-keys from the UI's image, with no entrypoint")
            if str(sv.get("user")) != NODE_KEYS_BAKE_USER or set(map(str, sv.get("group_add") or [])) != NODE_KEYS_BAKE_GROUPS:
                bad(f"{folder}/{name}: resolved, node-keys-bake runs as {NODE_KEYS_BAKE_USER} in exactly the groups {sorted(NODE_KEYS_BAKE_GROUPS)}")
            if got_env != want_env:
                bad(f"{folder}/{name}: resolved, node-keys-bake's environment is not exactly {want_env}: {got_env}")
            if sv.get("restart") != "no" or sv.get("read_only") is not True or sv.get("cap_drop") != ["ALL"] or sv.get("cap_add") \
                    or sv.get("ports") or "network_mode" in sv or got != want:
                bad(f"{folder}/{name}: resolved, node-keys-bake is a read-only one-shot with no capability or port, and exactly its four mounts")

# apps of another community store a dependency may name, and what their exports give a dependent (Paul's
# umbrel-store, paulscode-lightning-fork/exports.sh)
OTHER_STORES = {"paulscode-lightning-fork": {"APP_LIGHTNING_FORK_NODE_IP": "10.21.21.66", "APP_LIGHTNING_FORK_NODE_REST_PORT": "8180",
                                             "APP_LIGHTNING_FORK_NODE_DATA_DIR": "/tmp/lightning-fork-stub/data/lnd"}}
INIT_CAPS = {"CHOWN", "FOWNER", "DAC_OVERRIDE"}
# A dependency slot another store's app may fill (umbrelOS `implements`), and what the selected app
# sets for the dependent (Paul's paulscode-knots-blake2b exports.sh; the names Lightning Fork reads).
SLOTS = {"bitcoin": {"APP_BITCOIN_NODE_IP": "10.21.21.62", "APP_BITCOIN_RPC_PORT": "18443", "APP_BITCOIN_RPC_USER": "umbrel",
                     "APP_BITCOIN_RPC_PASS": "stub"}}

problems: list[str] = []
warnings: list[str] = []


def bad(msg: str) -> None:
    problems.append(msg)
    print(f"  FAIL {msg}")


def served(folder: str, here: Path, what: str, url, kinds: tuple[str, ...]) -> Path | None:
    """`url` is RAW/<folder>/<file> of a file in the app's folder here, of one of `kinds`: what umbrelOS fetches
    once this tree is on main. The file, or None (and a problem)."""
    url = str(url or "")
    prefix = f"{RAW}/{folder}/"
    name = url[len(prefix):] if url.startswith(prefix) else ""
    if not name or "/" in name or name.startswith("."):
        bad(f"{folder}: {what} {url!r} is not {prefix}<file> (a URL: umbrelOS shows a community store's {what} as it is given)")
        return None
    f = here / name
    if not f.is_file():
        bad(f"{folder}: {what} {url!r} names {name}, which is not in {here.name}/")
        return None
    if f.suffix.lower() not in kinds:
        bad(f"{folder}: {what} {name} is not one of {kinds}")
        return None
    return f


def plain_svg(folder: str, f: Path) -> None:
    """An icon drawn here: an <svg> document with no script, no event handler and nothing it fetches."""
    import xml.etree.ElementTree as ET
    text = f.read_text()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        bad(f"{folder}: icon {f.name} is not XML: {e}")
        return
    if root.tag not in ("svg", "{http://www.w3.org/2000/svg}svg"):
        bad(f"{folder}: icon {f.name} is not an <svg> document")
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in ("script", "foreignObject", "image", "use", "style"):
            bad(f"{folder}: icon {f.name} has <{tag}> (a plain drawing only)")
        for k, v in el.attrib.items():
            if k.split("}")[-1].lower().startswith("on") or "href" in k or "url(" in v:
                bad(f"{folder}: icon {f.name}: {k}={v!r} (no handler, link or reference)")


def exports_vars(p: Path) -> dict[str, str]:
    return dict(re.findall(r'^export\s+([A-Z0-9_]+)="?([^"\n]*)"?', p.read_text(), re.M)) if p.exists() else {}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent).resolve()
    # no link anywhere umbrelOS reads: an app folder that is a link is another folder's files
    for e in sorted(root.iterdir()):
        if e.is_symlink():
            bad(f"store: {e.name} is a link")
    store = yaml.safe_load((root / "umbrel-app-store.yml").read_text()) or {}
    if "id" not in store or "name" not in store:
        bad("umbrel-app-store.yml needs id and name")
    sid = str(store.get("id"))
    apps = {}
    for mp in sorted(root.glob("*/umbrel-app.yml")):
        apps[mp.parent.name] = (mp, yaml.safe_load(mp.read_text()))
    if not apps:
        bad("no apps")
    ports: dict[int, str] = {}
    try:
        pins = load_lock()
    except (OSError, ValueError) as e:
        pins = {}
        bad(f"packaging/images.lock: {e}")
    for folder, (mp, m) in apps.items():
        print(f"== {folder}")
        missing = [k for k in REQUIRED if k not in m]
        if missing:
            bad(f"{mp}: missing {missing}")
            continue
        if str(m["manifestVersion"]) not in ("1", "1.1"):
            bad(f"{folder}: manifestVersion {m['manifestVersion']}")
        if m["id"] != folder or not str(m["id"]).startswith(sid + "-"):
            bad(f"{folder}: id {m['id']!r} must equal the folder and start with {sid}-")
        if str(m["category"]).lower() not in CATEGORIES:
            bad(f"{folder}: category {m['category']!r}")
        if not isinstance(m["gallery"], list):
            bad(f"{folder}: gallery must be a list")
        elif not m["gallery"] and folder not in LOCAL_ONLY:
            bad(f"{folder}: empty gallery (umbrelOS shows the app with no pictures)")
        for g in m["gallery"] or []:
            served(folder, mp.parent, "gallery", g, (".png", ".jpg", ".jpeg"))
        icon = served(folder, mp.parent, "icon", m["icon"], (".svg", ".png"))
        package_files(folder, mp.parent, m)
        if icon and icon.suffix == ".svg":
            plain_svg(folder, icon)
        for d in m["dependencies"] or []:
            if d in SLOTS:
                if not any(d in (am.get("implements") or []) for _, am in apps.values()):
                    # a store with this app alone: the owner installs the slot's node from another store
                    warnings.append(f"{folder}: no app in this store implements the slot {d}: the owner installs it from another store")
            elif d not in apps and d not in OTHER_STORES:
                bad(f"{folder}: dependency {d} is not in this store")
        for i in m.get("implements") or []:
            if i not in SLOTS:
                bad(f"{folder}: implements {i!r}, not a known slot")
        if not str(m["submission"]).startswith(SUBMISSION):
            bad(f"{folder}: submission {m['submission']!r} is not a URL into {SUBMISSION} (a store submission is the project owner's decision)")
        compose_p = mp.parent / "docker-compose.yml"
        text = compose_p.read_text()
        try:
            c = yaml.load(text, Loader=StrictLoader)
        except yaml.YAMLError as e:
            bad(f"{folder}: docker-compose.yml: {e}")
            continue
        svcs = c.get("services") or {}
        raw_shape(folder, c, svcs)
        loaded_substitutions(folder, c)
        # --- app_proxy
        env = env_of(svcs.get("app_proxy") or {})
        host, aport = env.get("APP_HOST"), env.get("APP_PORT")
        mh = re.fullmatch(rf"{re.escape(m['id'])}_([a-z0-9-]+)_1", str(host or ""))
        if not mh or mh.group(1) not in svcs:
            bad(f"{folder}: app_proxy APP_HOST {host!r} is not <app-id>_<service>_1 of a service here")
        if not aport:
            bad(f"{folder}: app_proxy APP_PORT unset")
        # --- ports
        for p in [int(m["port"])] + [int(str(x).split(":")[-2]) for s in svcs.values() for x in (s.get("ports") or [])]:
            if p in ports:
                bad(f"{folder}: host port {p} also used by {ports[p]}")
            ports[p] = folder
        # --- variables
        own = exports_vars(mp.parent / "exports.sh")
        # a slot is filled by the app the owner selects: here, the apps of this store that implement it
        providers = [a for d in m["dependencies"] or [] for a, (_, am) in apps.items() if a == d or d in (am.get("implements") or [])]
        dep = {k: v for a in providers for k, v in exports_vars(apps[a][0].parent / "exports.sh").items()}
        dep.update({k: v for d in m["dependencies"] or [] for k, v in OTHER_STORES.get(d, {}).items()})
        slot = {k: v for d in m["dependencies"] or [] for k, v in SLOTS.get(d, {}).items()}
        text_nc = re.sub(r"(?m)^\s*#.*$", "", text)
        substitutions(folder, text_nc)
        used = set(re.findall(r"\$\{([A-Z0-9_]+)\}", text_nc)) | set(re.findall(r"\$\{([A-Z0-9_]+):-\}", text_nc))
        for v, fallback in re.findall(r"\$\{([A-Z0-9_]+):-\$\{([A-Z0-9_]+)\}\}", text_nc):
            if v not in slot:
                bad(f"{folder}: ${{{v}:-...}}: only a slot's variable takes a fallback")
            used.discard(v)
        for v in sorted(set(re.findall(r"\$\{?([A-Z0-9_]+)", text_nc)) & set(slot)):
            if not re.search(r"\$\{" + v + r":-\$\{[A-Z0-9_]+\}\}", text_nc) or re.search(r"\$\{?" + v + r"(?!:-\$\{)\b", text_nc):
                bad(f"{folder}: ${{{v}}} (slot) must be used as ${{{v}:-${{FALLBACK}}}}")
        # with no app of this store filling a slot, its fallbacks are unset and take their defaults: the
        # slot's own values (checked below) are what reach the services
        if slot and not providers:
            used -= {fb for _, fb in re.findall(r"\$\{([A-Z0-9_]+):-\$\{([A-Z0-9_]+)\}\}", text_nc)}
            used -= set(re.findall(r"\$\{([A-Z0-9_]+):-\}", text_nc))
        # ${UMBREL_ROOT} only in the one shared mount the app may have, with its permission
        downloads = DOWNLOADS_MOUNT in text_nc
        if downloads and "STORAGE_DOWNLOADS" not in (m.get("permissions") or []):
            bad(f"{folder}: mounts Umbrel's Downloads without the STORAGE_DOWNLOADS permission")
        if downloads and text_nc.count("${UMBREL_ROOT}") == text_nc.count(DOWNLOADS_MOUNT):
            used.discard("UMBREL_ROOT")
        for v in sorted(used - UMBREL_VARS - set(own) - set(dep)):
            bad(f"{folder}: ${{{v}}} is not set by umbrelOS, this app's exports or a dependency's")
        if "APP_PASSWORD" in used and not m.get("deterministicPassword"):
            bad(f"{folder}: uses ${{APP_PASSWORD}} without deterministicPassword: true")
        # --- services
        for name, s in svcs.items():
            # every container, umbrelOS's app_proxy too (its keys: raw_shape): no looser privileges, no
            # other container's or the host's network
            if set(map(str, s.get("security_opt") or [])) - {"no-new-privileges:true"}:
                bad(f"{folder}/{name}: security_opt may only be no-new-privileges:true")
            if name == "app_proxy":
                continue
            img = str(s.get("image", ""))
            pin = REF.match(img)
            if folder in LOCAL_ONLY and LOCAL_ONLY[folder].match(img):
                pass
            elif UNPUBLISHED.match(img):
                pass
            elif not pin or pin["repo"] != REGISTRY:
                bad(f"{folder}/{name}: image {img!r} is not {REGISTRY}/<image>:<version>-<commit>@sha256:<digest>")
            elif pins.get(pin["name"]) != img:
                bad(f"{folder}/{name}: image {img!r} is not the one packaging/images.lock pins ({pins.get(pin['name'])!r})")
            node_keys = s.get("command") == ["node-keys"]
            base = pin["name"] if pin else img.split(":")[0]
            # a UI that writes the shop's route for paid pieces of work (XBT_UI_HASHER_SLICES) asks the hashmaker
            # (XBT_UI_HASHER) before it moves that route to a new price: with no hashmaker address the route would
            # never follow, and a hashmaker whose gateway charges another price takes no rental
            ui_env = env_of(s)
            if str(ui_env.get("XBT_UI_HASHER_SLICES") or "").startswith("http://") and not str(ui_env.get("XBT_UI_HASHER") or "").startswith("http://"):
                bad(f"{folder}/{name}: XBT_UI_HASHER_SLICES without an http:// XBT_UI_HASHER: the shop's route would never follow a new price")
            # the name alone is not the exception: the baker's checks below decide, before any other
            baker = name == NODE_KEYS_BAKE
            if s.get("cap_add") and (baker or base != "xbt-init"):
                bad(f"{folder}/{name}: cap_add is xbt-init's alone")
            for v in s.get("volumes") or []:
                if isinstance(v, dict):
                    if baker and base == "xbt-wallet-ui" and node_keys and v == NODE_DIR_MOUNT:
                        continue
                    if v != CERT_MOUNT:
                        bad(f"{folder}/{name}: a long-form mount is only the Lightning node's tls.cert, read-only, never created: {v}")
                    continue
                src = str(v).split(":")[0]
                if str(v) == DOWNLOADS_MOUNT and base_of(img) in DOWNLOADS_IMAGES:
                    continue
                if not src.startswith("${APP_DATA_DIR}/"):
                    bad(f"{folder}/{name}: volume {v} is not under ${{APP_DATA_DIR}}")
                if "macaroon" in str(v) or "LIGHTNING" in src:
                    bad(f"{folder}/{name}: mounts the Lightning node's data or a macaroon of it: {v}")
            if baker:
                env = env_of(s)
                if base != "xbt-wallet-ui" or not node_keys:
                    bad(f"{folder}/{name}: node-keys-bake is node-keys (command [\"node-keys\"]) from the UI's image")
                if not s.get("read_only") or s.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in (s.get("security_opt") or []):
                    bad(f"{folder}/{name}: needs read_only, cap_drop ALL, no-new-privileges")
                if str(s.get("user")) != NODE_KEYS_BAKE_USER or s.get("ports") or s.get("restart") != "no" or "network_mode" in s or s.get("privileged"):
                    bad(f"{folder}/{name}: node-keys-bake is a one-shot (restart: \"no\") as the Lightning app's user {NODE_KEYS_BAKE_USER}, on the app's network, with no port")
                if set(map(str, s.get("group_add") or [])) != NODE_KEYS_BAKE_GROUPS:
                    bad(f"{folder}/{name}: node-keys-bake joins exactly the groups {sorted(NODE_KEYS_BAKE_GROUPS)}")
                if env.get("XBT_KEYS_BAKE_TO") != "/data/run/node-keys" or "XBT_KEYS_TAKE_FROM" in env or "XBT_KEYS_GRANT_DIR" in env:
                    bad(f"{folder}/{name}: node-keys-bake bakes into the hand-over (XBT_KEYS_BAKE_TO=/data/run/node-keys) only")
                vols = s.get("volumes") or []
                if NODE_DIR_MOUNT not in vols or [v for v in vols if isinstance(v, dict) and v != NODE_DIR_MOUNT] \
                        or {str(v) for v in vols if not isinstance(v, dict)} != NODE_KEYS_BAKE_MOUNTS:
                    bad(f"{folder}/{name}: node-keys-bake mounts the node's data read-only, run/ln and run/gateway read-only, and writes only run/node-keys")
            elif base == "xbt-init":
                caps = set(s.get("cap_add") or [])
                if s.get("network_mode") != "none" or s.get("cap_drop") != ["ALL"] or not caps <= INIT_CAPS or not s.get("read_only"):
                    bad(f"{folder}/{name}: xbt-init must run with network_mode none, read_only, cap_drop ALL, cap_add within {sorted(INIT_CAPS)}")
                if s.get("restart") != "no":
                    bad(f"{folder}/{name}: xbt-init is a one-shot (restart: \"no\")")
            elif node_keys:
                if base != "xbt-wallet-ui":
                    bad(f"{folder}/{name}: node-keys runs from the UI's image")
                if not s.get("read_only") or s.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in (s.get("security_opt") or []):
                    bad(f"{folder}/{name}: needs read_only, cap_drop ALL, no-new-privileges")
                if "user" in s or s.get("ports") or s.get("restart") != "no":
                    bad(f"{folder}/{name}: node-keys is a one-shot (restart: \"no\") as its image's user, with no port")
                if s.get("group_add"):
                    bad(f"{folder}/{name}: node-keys joins no other group (the Lightning app's data is node-keys-bake's alone)")
                if s.get("network_mode") != "none":
                    bad(f"{folder}/{name}: node-keys only moves files: network_mode none")
                vols = s.get("volumes") or []
                if any(isinstance(v, dict) for v in vols) or {str(v) for v in vols} - NODE_KEYS_MOUNTS:
                    bad(f"{folder}/{name}: node-keys reads nothing of the Lightning app, and writes only run/ln, run/gateway and run/node-keys")
            elif base in AGENTPAY:
                comp, own_runs, peers = AGENTPAY[base]
                if not s.get("read_only") or s.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in (s.get("security_opt") or []):
                    bad(f"{folder}/{name}: needs read_only, cap_drop ALL, no-new-privileges")
                if "user" in s:
                    bad(f"{folder}/{name}: must run as its image's own user (no user: override; CONTAINER.md uid table)")
                if s.get("init") is not True:
                    bad(f"{folder}/{name}: needs init: true (the binaries stop on SIGTERM by themselves; an init still reaps and forwards for anything they start)")
                if (s.get("depends_on") or {}).get("init", {}).get("condition") != "service_completed_successfully":
                    bad(f"{folder}/{name}: must wait for init (service_completed_successfully)")
                if base == "lightning-stream" and s.get("ports"):
                    bad(f"{folder}/{name}: the connector is not published on the LAN")
                if base == "xbt-datum-gateway":
                    # its API opens every job (/xbt/job) and serves it to loopback only: on the app's network it
                    # would be any container's to read, and on a host port the LAN's
                    if s.get("ports") or s.get("network_mode") != "service:renter":
                        bad(f"{folder}/{name}: the Stream Gateway publishes no port and runs in the renter's network namespace (service:renter)")
                allowed = {f"${{APP_DATA_DIR}}/data/{comp}:/data/{comp}"} if comp else set()
                allowed |= {f"${{APP_DATA_DIR}}/data/run/{r}:/data/run/{r}" for r in own_runs}
                allowed |= {f"${{APP_DATA_DIR}}/data/run/{p}:/data/run/{p}:ro" for p in peers}
                if base in ("lightning-stream", "xbt-vpn"):
                    allowed.add(STREAM_MOUNT)
                if base in DOWNLOADS_IMAGES:
                    allowed.add(DOWNLOADS_MOUNT)
                vols = [v for v in (s.get("volumes") or []) if not isinstance(v, dict)]
                for v in vols:
                    if v not in allowed:
                        bad(f"{folder}/{name}: mount {v} is outside its own sub-dir and socket dirs")
                if comp and f"${{APP_DATA_DIR}}/data/{comp}:/data/{comp}" not in vols:
                    bad(f"{folder}/{name}: does not mount its own data sub-dir")
                if base == "lightning-stream":
                    if STREAM_MOUNT not in vols:
                        bad(f"{folder}/{name}: must mount the stream directory read-write")
                    if "${APP_DATA_DIR}/data/run/signer:/data/run/signer:ro" not in vols:
                        bad(f"{folder}/{name}: must mount the signer's socket dir read-only")
                    if any(str(v).startswith("${APP_DATA_DIR}/data/signer:") for v in vols):
                        bad(f"{folder}/{name}: must not mount the signer's state")
        # --- docker compose accepts it (umbrelOS values stubbed)
        envs = {"APP_DATA_DIR": "/tmp/app-data", "APP_SEED": "0" * 64, "APP_PASSWORD": "x" * 32, "DEVICE_DOMAIN_NAME": "umbrel.local",
                "DEVICE_HOSTNAME": "umbrel", **{k: (v if "$(" not in v else "stub") for k, v in {**dep, **own}.items()}}
        with tempfile.TemporaryDirectory() as t:
            # app_proxy is injected by umbrelOS; give it an image so compose validates the file
            ov = Path(t) / "ov.yml"
            ov.write_text("services:\n  app_proxy:\n    image: umbrel-app-proxy-stub\n")
            r = subprocess.run(["docker", "compose", "--env-file", "/dev/null", "-f", str(compose_p), "-f", str(ov), "config", "-q"], capture_output=True, text=True,
                               env={**os.environ, **envs}, cwd=mp.parent)
            if r.returncode != 0:
                bad(f"{folder}: docker compose config: {r.stderr.strip()[-400:]}")
            else:
                # the model compose resolves, the host's folders marked: every rule again, on what would run
                r = subprocess.run(["docker", "compose", "--env-file", "/dev/null", "-f", str(compose_p), "-f", str(ov), "config", "--format", "json"], capture_output=True,
                                   text=True, env={**os.environ, **envs, **MARKS}, cwd=mp.parent)
                try:
                    resolved_shape(folder, json.loads(r.stdout), svcs, {**envs, **MARKS})
                except ValueError:
                    bad(f"{folder}: docker compose config --format json: {r.stderr.strip()[-400:]}")
            if slot:
                # the slot's node alone (no app of this store installed): the slot's values reach the services
                other = {k for d in m["dependencies"] or [] for k in OTHER_STORES.get(d, {})}
                base = {k: v for k, v in envs.items() if k not in dep or k in other}
                r = subprocess.run(["docker", "compose", "--env-file", "/dev/null", "-f", str(compose_p), "-f", str(ov), "config"], capture_output=True, text=True,
                                   env={**{k: v for k, v in os.environ.items() if not k.startswith("APP_")}, **base, **slot}, cwd=mp.parent)
                if r.returncode != 0 or not all(v in r.stdout for v in slot.values()):
                    bad(f"{folder}: with only the slot's node, compose does not get its values: {r.stderr.strip()[-300:]}")
                else:
                    # and every rule again, on what the slot's node alone resolves
                    alone = {**base, **slot, **MARKS}
                    r = subprocess.run(["docker", "compose", "--env-file", "/dev/null", "-f", str(compose_p), "-f", str(ov), "config", "--format", "json"],
                                       capture_output=True, text=True,
                                       env={**{k: v for k, v in os.environ.items() if not k.startswith("APP_")}, **alone}, cwd=mp.parent)
                    try:
                        resolved_shape(folder, json.loads(r.stdout), svcs, alone)
                    except ValueError:
                        bad(f"{folder}: with only the slot's node, docker compose config --format json: {r.stderr.strip()[-300:]}")
        print(f"  manifest + compose checked ({len(svcs)} services)")
    for w in warnings:
        print(f"  warn {w}")
    print("lint PASS" if not problems else f"lint FAIL ({len(problems)})")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
