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
lightning-stream:0.1.0 is the connector, which has no digest until it is published); every ${VAR} is provided by umbrelOS,
this app's exports or a dependency's exports; a slot's variable (APP_BITCOIN_*, set by whichever node app the
owner selects) is only used as `${APP_BITCOIN_X:-${FALLBACK}}` with a fallback this store's implementing app
exports; `docker compose config` accepts the file with those values, and with the slot's values alone.
Hardening (docs/CONTAINER.md): the agentpay services run read-only, cap_drop ALL, no-new-privileges, under an init
(init: true), as their image's non-root user, and mount only their own sub-dir plus the dirs they need (a peer's read-only); of the
Lightning node's data, only its tls.cert, read-only, as a bind that never creates a missing path; no
admin macaroon. The one exception is the one-shot `node-keys-bake`, by name: as the Lightning app's user
it mounts that app's data folder read-only, and writes only the hand-over folder run/node-keys. `init` (xbt-init) is the only root container: no network, at most CHOWN/FOWNER/DAC_OVERRIDE.
    python3 packaging/umbrel/lint.py [STORE_DIR]
"""
from __future__ import annotations

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
# the connector, xbt-hashlink and xbt-vpn have no line in images.lock yet. oci_build.sh --load tags them
# <image>:0.1.0. A digest is not invented here. Anything else (a registry name, a made-up digest) still fails.
UNPUBLISHED = re.compile(r"^(lightning-stream|xbt-hashlink|xbt-vpn):0\.1\.0$")
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
    "xbt-signer": ("signer", {"signer", "enroll"}, {"anchor", "ln", "shops"}),
    "xbt-anchor-witness": ("witness", {"anchor"}, set()),
    # run/ui holds the UI-owned MCP token; the MCP may only read it. run/shops: the shops without a
    # web address the UI keeps, read by the connector and the MCP to hand to the signer
    "xbt-wallet-mcp": ("mcp", set(), {"signer", "ui", "shops"}),
    # the setup pages write run/ln (the rail macaroon), run/gateway (the gateway's config and macaroons)
    # and run/hashrate (the hasher's settings); the AI page writes run/ai (keys, sellers)
    # and run/vpn (the devices and exit the VPN pages set), reading the VPN service's status
    "xbt-wallet-ui": ("ui", {"ui", "ln", "gateway", "hashrate", "shops", "ai", "vpn"}, {"signer", "enroll", "vpn-status"}),
    "xbt-gateway": ("gateway", set(), {"gateway"}),
    # no state of its own. The control socket is read-only; the stream sockets are STREAM_MOUNT. The AI
    # endpoint books the keys' spend and the sellers' health in run/ai, shared by group with the UI
    "lightning-stream": (None, {"ai"}, {"signer", "shops"}),
    # the hasher and the renter: their keys and state; the settings and token read-only; the renter
    # also the signer's socket, read-only
    "xbt-hashlink": ("hashrate", set(), {"hashrate", "signer"}),
    # the VPN service: its keys and lists; the settings read-only; its status for the UI. Priced exits
    # are paid through the owner's wallet: the signer's socket and the shops read-only, and the stream
    # sockets are STREAM_MOUNT (each paid tunnel's socket is made there)
    "xbt-vpn": ("vpn", {"vpn-status"}, {"vpn", "signer", "shops"}),
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
# for 0.1.20 because the admin macaroon the baker needs anyway already allows draining the node; the
# way out is for Lightning Fork to hand narrow macaroons to apps itself (asked of its author for
# 0.1.21). Every other container: tls.cert only.
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
        c = yaml.safe_load(text)
        svcs = c.get("services") or {}
        # --- app_proxy
        env = (svcs.get("app_proxy") or {}).get("environment") or {}
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
            # every container, umbrelOS's app_proxy too: no way into another's processes, files or
            # privileges (each named one is checked below where it is allowed)
            for k in ("volumes_from", "pid", "ipc", "privileged", "devices", "userns_mode"):
                if k in s:
                    bad(f"{folder}/{name}: {k} is not allowed")
            if set(map(str, s.get("security_opt") or [])) - {"no-new-privileges:true"}:
                bad(f"{folder}/{name}: security_opt may only be no-new-privileges:true")
            nm = s.get("network_mode")
            if nm is not None and nm != "none" and not (str(nm).startswith("service:") and str(nm)[8:] in svcs):
                bad(f"{folder}/{name}: network_mode {nm!r}: only none, or another service of this app")
            if name == "app_proxy":
                if s.get("volumes") or s.get("cap_add"):
                    bad(f"{folder}/{name}: umbrelOS's app_proxy mounts nothing and adds no capability")
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
                env = s.get("environment") or {}
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
            r = subprocess.run(["docker", "compose", "-f", str(compose_p), "-f", str(ov), "config", "-q"], capture_output=True, text=True,
                               env={**os.environ, **envs}, cwd=mp.parent)
            if r.returncode != 0:
                bad(f"{folder}: docker compose config: {r.stderr.strip()[-400:]}")
            if slot:
                # the slot's node alone (no app of this store installed): the slot's values reach the services
                other = {k for d in m["dependencies"] or [] for k in OTHER_STORES.get(d, {})}
                base = {k: v for k, v in envs.items() if k not in dep or k in other}
                r = subprocess.run(["docker", "compose", "-f", str(compose_p), "-f", str(ov), "config"], capture_output=True, text=True,
                                   env={**{k: v for k, v in os.environ.items() if not k.startswith("APP_")}, **base, **slot}, cwd=mp.parent)
                if r.returncode != 0 or not all(v in r.stdout for v in slot.values()):
                    bad(f"{folder}: with only the slot's node, compose does not get its values: {r.stderr.strip()[-300:]}")
        print(f"  manifest + compose checked ({len(svcs)} services)")
    for w in warnings:
        print(f"  warn {w}")
    print("lint PASS" if not problems else f"lint FAIL ({len(problems)})")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
