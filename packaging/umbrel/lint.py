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
admin macaroon. `init` (xbt-init) is the only root container: no network, at most CHOWN/FOWNER/DAC_OVERRIDE.
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
# the connector and xbt-hashlink have no line in images.lock yet. oci_build.sh --load tags them
# <image>:0.1.0. A digest is not invented here. Anything else (a registry name, a made-up digest) still fails.
UNPUBLISHED = re.compile(r"^(lightning-stream|xbt-hashlink):0\.1\.0$")
# the stream directory the connector writes, inside the signer's socket dir. Read-write, and the
# only extra mount it may have. It does not get the signer's state.
STREAM_MOUNT = "${APP_DATA_DIR}/data/run/signer/streams:/data/run/signer/streams"
# image -> (component sub-dir or None, run/ dirs it writes, run/ dirs it may mount read-only)
AGENTPAY = {
    "xbt-signer": ("signer", {"signer"}, {"anchor", "ln"}),
    "xbt-anchor-witness": ("witness", {"anchor"}, set()),
    # run/ui holds the UI-owned MCP token; the MCP may only read it
    "xbt-wallet-mcp": ("mcp", set(), {"signer", "ui"}),
    # the setup pages write run/ln (the rail macaroon), run/gateway (the gateway's config and macaroons)
    # and run/hashrate (the hasher's settings)
    "xbt-wallet-ui": ("ui", {"ui", "ln", "gateway", "hashrate"}, {"signer"}),
    "xbt-gateway": ("gateway", set(), {"gateway"}),
    # no state of its own. The control socket is read-only; the stream sockets are STREAM_MOUNT.
    "lightning-stream": (None, set(), {"signer"}),
    # the hasher and the renter: their keys and state; the settings and token read-only; the renter
    # also the signer's socket, read-only
    "xbt-hashlink": ("hashrate", set(), {"hashrate", "signer"}),
}
# the Lightning node's certificate: the only file of another app's data a service here may mount
CERT_MOUNT = {"type": "bind", "source": "${APP_LIGHTNING_FORK_NODE_DATA_DIR}/tls.cert", "target": "/data/lightning/tls.cert", "read_only": True,
              "bind": {"create_host_path": False}}
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
                    bad(f"{folder}: no app in this store implements the slot {d} (the fallback node)")
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
        for v in sorted(used - UMBREL_VARS - set(own) - set(dep)):
            bad(f"{folder}: ${{{v}}} is not set by umbrelOS, this app's exports or a dependency's")
        if "APP_PASSWORD" in used and not m.get("deterministicPassword"):
            bad(f"{folder}: uses ${{APP_PASSWORD}} without deterministicPassword: true")
        # --- services
        for name, s in svcs.items():
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
            for v in s.get("volumes") or []:
                if isinstance(v, dict):
                    if v != CERT_MOUNT:
                        bad(f"{folder}/{name}: a long-form mount is only the Lightning node's tls.cert, read-only, never created: {v}")
                    continue
                src = str(v).split(":")[0]
                if not src.startswith("${APP_DATA_DIR}/"):
                    bad(f"{folder}/{name}: volume {v} is not under ${{APP_DATA_DIR}}")
                if "macaroon" in str(v) or "LIGHTNING" in src:
                    bad(f"{folder}/{name}: mounts the Lightning node's data or a macaroon of it: {v}")
            base = pin["name"] if pin else img.split(":")[0]
            if base == "xbt-init":
                caps = set(s.get("cap_add") or [])
                if s.get("network_mode") != "none" or s.get("cap_drop") != ["ALL"] or not caps <= INIT_CAPS or not s.get("read_only"):
                    bad(f"{folder}/{name}: xbt-init must run with network_mode none, read_only, cap_drop ALL, cap_add within {sorted(INIT_CAPS)}")
                if s.get("restart") != "no":
                    bad(f"{folder}/{name}: xbt-init is a one-shot (restart: \"no\")")
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
                if base == "lightning-stream":
                    allowed.add(STREAM_MOUNT)
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
