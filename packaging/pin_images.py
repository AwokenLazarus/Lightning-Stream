#!/usr/bin/env python3
"""Pin the packages to the published images in packaging/images.lock (scripts/oci_publish.sh writes it).

The lock has one line per image: `<image> <registry>/<image>:<version>-<commit>@sha256:<index digest>`. This
writes each reference into
  * the Umbrel apps' docker-compose.yml (`image:` lines of the agentpay services), as given: tag and digest;
  * the Linux package's docker-compose.yml, the same way;
  * the StartOS packages' startos/spec.ts (the IMAGES table the manifest packs from), as given.
With --check it writes nothing and exits 1 if a file is not pinned to the lock (packaging/umbrel/lint.py runs
it). Other images (the stand-in XBT node) are left alone. An image with no lock line yet is left as
`<image>:0.1.0` (the tag scripts/oci_build.sh --load gives) and any other spelling of it fails --check.
No digest is invented.
With --release it also refuses what may not be released: an image the packages name that has no lock
line (a local tag no box can pull), a lock built from an older commit than the last change to the
images' sources (crates/ but its tests, Cargo.toml, Cargo.lock, container/): the pins would run old code, and a
pinned image that doesn't know what its package asks of it (an init without a component the package lists,
"unknown component datum"; a hashlink without a flag it passes, such as --gateway-api). That last check runs the
images (docker; --uses runs it alone). Run it before a store or a package is published; it passes only after the
images of the commit are published and pinned.
    python3 packaging/pin_images.py [--check] [--release] [--uses]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = HERE / "images.lock"
REF = re.compile(r"^(?P<repo>[a-z0-9.-]+(?::\d+)?(?:/[a-z0-9._-]+)+)/(?P<name>xbt-[a-z0-9-]+|lightning-stream):(?P<tag>[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{12})"
                 r"@(?P<digest>sha256:[0-9a-f]{64})$")
# an image reference of an agentpay service, local tag or pinned. lightning-stream, xbt-hashlink and
# xbt-datum-gateway are included so that once images.lock has their lines, this rewrites their local tags to
# those digests.
ANY = r"(?:[a-z0-9.:/-]+/)?(xbt-(?:init|signer|anchor-witness|wallet-mcp|wallet-ui|gateway|work-relay|hashlink|stream-relay|vpn|datum-gateway)|lightning-stream)(?::[A-Za-z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?"


def load_lock(path: Path = LOCK) -> dict[str, str]:
    """image name -> pinned reference; raises ValueError on a malformed line."""
    pins = {}
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split()
        m = REF.match(parts[1]) if len(parts) == 2 else None
        if not m or m["name"] != parts[0]:
            raise ValueError(f"{path.name}:{n}: not `<image> <registry>/<image>:<version>-<commit>@sha256:<digest>`: {line!r}")
        pins[parts[0]] = parts[1]
    return pins


def targets() -> list[tuple[Path, re.Pattern, str]]:
    """(file, pattern whose group 1 is the image name, replacement template)"""
    out = []
    for p in sorted((HERE / "umbrel").glob("lazarus-*/docker-compose.yml")):
        out.append((p, re.compile(r"(?m)^(    image: )" + ANY + r"$"), "compose"))
    linux = HERE / "linux" / "docker-compose.yml"
    if linux.exists():
        out.append((linux, re.compile(r"(?m)^(    image: )" + ANY + r"$"), "compose"))
    for p in sorted((HERE / "startos").glob("*/startos/spec.ts")):
        out.append((p, re.compile(r"(?m)^(  [a-z]+: ')" + ANY + r"(',?)$"), "spec"))
    return out


def pinned(text: str, pat: re.Pattern, pins: dict[str, str], release: bool = False) -> tuple[str, list[str]]:
    missing = []

    def sub(m: re.Match) -> str:
        name = m.group(2)
        end = m.start(3) if m.lastindex and m.lastindex >= 3 and m.group(3) else m.end(0)
        ref = m.string[m.end(1):end]
        if name not in pins:
            # no digest exists yet. The local tag is the one oci_build.sh --load gives. Anything else
            # (a registry name, a tag we did not build) is reported, and no digest is invented.
            if ref == f"{name}:0.1.0" and not release:
                return m.group(0)
            missing.append(name)
            return m.group(0)
        return m.group(1) + pins[name] + (m.group(3) if m.lastindex and m.lastindex >= 3 else "")

    return pat.sub(sub, text), missing


# what the images are built from: a change here after the lock's commit makes the pins stale. A crate's
# tests/ never go into an image (the images hold release binaries), so a change only there does not.
IMAGE_SOURCES = ["crates", "Cargo.toml", "Cargo.lock", "container", ":(glob,exclude)crates/*/tests/**"]


# sources only some images are built from (no other image's crates depend on them): a change there makes only those
# images' pins stale, so a fix release may rebuild them alone and keep the others' pins (0.2.1: xbt-wallet-ui;
# 0.2.2: xbt-wallet-ui and lightning-stream)
# path -> the images built from it (no other image's crates depend on it)
OWN_SOURCES = {
    "crates/xbt-wallet-ui": {"xbt-wallet-ui"},
    "crates/lightning-stream": {"lightning-stream", "xbt-wallet-ui"},
    # 0.2.3: the VPN service is also linked into the wallet UI; the signer crate into the wallet UI, the
    # wallet MCP (and its xbt-nwc) and the anchor witness, which builds from the same package
    "crates/xbt-vpn": {"xbt-vpn", "xbt-wallet-ui"},
    "crates/xbt-signer": {"xbt-signer", "xbt-anchor-witness", "xbt-wallet-mcp", "xbt-wallet-ui", "xbt-vpn"},
    # 0.2.6: the gateway crate is linked into the signer (and so the anchor witness) and the wallet UI; the wallet MCP
    # crate into the connector, the VPN service and the wallet UI
    "crates/xbt-gateway": {"xbt-gateway", "xbt-signer", "xbt-anchor-witness", "xbt-wallet-ui"},
    "crates/xbt-wallet-mcp": {"xbt-wallet-mcp", "lightning-stream", "xbt-vpn", "xbt-wallet-ui"},
}


def stale(pins: dict[str, str]) -> list[str]:
    """The lock's commits whose images are older than the sources at HEAD (the reasons, one per commit)."""
    import subprocess
    out = []
    for commit in sorted({REF.match(r)["tag"].rsplit("-", 1)[1] for r in pins.values()}):
        at = {img for img, r in pins.items() if REF.match(r)["tag"].rsplit("-", 1)[1] == commit}
        # what only images built from another commit are made of does not make these stale
        others = [f":(exclude){p}" for p, owners in OWN_SOURCES.items() if not owners & at]
        r = subprocess.run(["git", "-C", str(HERE.parent), "diff", "--quiet", commit, "HEAD", "--", *IMAGE_SOURCES, *others])
        if r.returncode == 1:
            out.append(f"images.lock pins images built from {commit}; their sources changed since (git diff {commit} HEAD -- {' '.join(IMAGE_SOURCES)})")
        elif r.returncode != 0:
            out.append(f"images.lock names commit {commit}, which this checkout does not have")
    return out


def _docker(*a: str, check: bool = True) -> "subprocess.CompletedProcess[str]":
    import subprocess
    return subprocess.run(["docker", *a], capture_output=True, text=True, check=check)


def _uses() -> list[tuple[str, str, str, set[str]]]:
    """What each package asks of its images: (where, image ref, kind, wants), kind "init" (the components its
    init lists) or "hashlink" (the flags its hashlink commands pass)."""
    import yaml
    out = []
    composes = sorted((HERE / "umbrel").glob("lazarus-*/docker-compose.yml")) + [HERE / "linux" / "docker-compose.yml"]
    for path in composes:
        if not path.exists():
            continue
        rel = str(path.relative_to(HERE.parent))
        doc = yaml.safe_load(path.read_text()) or {}
        for name, svc in (doc.get("services") or {}).items():
            img = str((svc or {}).get("image", ""))
            if "/xbt-init:" in img or img.startswith("xbt-init:"):
                comps = str(((svc.get("environment") or {}) if isinstance(svc.get("environment"), dict) else {}).get("XBT_INIT_COMPONENTS", ""))
                if comps:
                    out.append((f"{rel} {name}", img, "init", set(comps.split(","))))
            if "/xbt-hashlink:" in img or img.startswith("xbt-hashlink:"):
                cmd = [str(x) for x in (svc.get("command") or [])]
                flags = {x for x in cmd if x.startswith("--")}
                if flags:
                    out.append((f"{rel} {name}", img, "hashlink", flags))
    for path in sorted((HERE / "startos").glob("*/startos/spec.ts")):
        rel, text = str(path.relative_to(HERE.parent)), path.read_text()
        ref = lambda key: (re.search(r"(?m)^  %s: '([^']+)'" % key, text) or [None, ""])[1]  # noqa: E731
        m = re.search(r"const components = \[([^\]]*)\]", text)
        if m:
            out.append((f"{rel} init", ref("init"), "init", set(re.findall(r"'([a-z-]+)'", m.group(1)))))
        flags = set()
        for c in re.finditer(r"command: \[\s*'/usr/bin/xbt-hashlink',(.*?)\]", text, re.S):
            flags |= set(re.findall(r"'(--[a-z0-9-]+)'", c.group(1)))
        if flags:
            out.append((f"{rel} hashlink", ref("hashlink"), "hashlink", flags))
    return out


def _init_report(stdout: str) -> dict | None:
    """xbt-init's report: the last line of its output, a JSON object with "ok"; None when there is none."""
    import json
    for line in reversed(stdout.strip().splitlines()):
        try:
            v = json.loads(line)
        except ValueError:
            continue
        return v if isinstance(v, dict) and "ok" in v else None
    return None


def unknown_to_pins() -> list[str]:
    """Each pinned image against what its package asks of it: an init that doesn't know a component the package
    lists (xbt-init check says \"unknown component\"), a hashlink binary without a flag the package passes. Runs
    the images (pulled by digest if missing): for --release, before a package or a store is published."""
    import tempfile
    bad = []
    for where, ref, kind, wants in _uses():
        if not ref:
            bad.append(f"{where}: no image")
            continue
        if kind == "init":
            r = _docker("run", "--rm", "--network", "none", "--tmpfs", "/x", ref, "check", "--data", "/x", "--components",
                        ",".join(sorted(wants)), check=False)
            # xbt-init check prints its report as JSON and exits 1 on any problem (an empty /x has many): the report
            # is what's read. No report (a pull or run that failed) is a failure, never a pass
            report = _init_report(r.stdout)
            if report is None:
                bad.append(f"{where}: {ref} could not be run to ask it (rc {r.returncode}): {(r.stderr or r.stdout).strip()[-300:]}")
                continue
            unknown = sorted({m for p in report.get("problems", []) for m in re.findall(r"unknown component ([a-z-]+)", str(p))})
            if unknown:
                bad.append(f"{where}: {ref} doesn't know the component{'s' if len(unknown) > 1 else ''} {', '.join(unknown)}")
        else:
            made = _docker("create", ref, check=False)
            c = made.stdout.strip()
            if made.returncode != 0 or not c:
                bad.append(f"{where}: {ref} could not be pulled or created (rc {made.returncode}): {made.stderr.strip()[-300:]}")
                continue
            try:
                with tempfile.TemporaryDirectory() as t:
                    got = _docker("cp", f"{c}:/usr/bin/xbt-hashlink", f"{t}/xbt-hashlink", check=False)
                    data = open(f"{t}/xbt-hashlink", "rb").read() if got.returncode == 0 else b""
            finally:
                _docker("rm", c, check=False)
            if not data:
                bad.append(f"{where}: {ref} has no /usr/bin/xbt-hashlink to read")
                continue
            missing = sorted(f for f in wants if f.encode() not in data and f[2:].encode() not in data)
            if missing:
                bad.append(f"{where}: {ref} doesn't take {', '.join(missing)}")
    return bad


def main() -> int:
    check = "--check" in sys.argv[1:] or "--release" in sys.argv[1:]
    release = "--release" in sys.argv[1:]
    pins = load_lock()
    bad = 0
    if release:
        for why in stale(pins):
            print(f"pin_images: not releasable: {why}")
            bad += 1
        # what the packages ask of the pinned images, asked of the images themselves
        for why in unknown_to_pins():
            print(f"pin_images: not releasable: {why}")
            bad += 1
    if "--uses" in sys.argv[1:]:
        for why in unknown_to_pins():
            print(f"pin_images: {why}")
            bad += 1
    for path, pat, _ in targets():
        text = path.read_text()
        new, missing = pinned(text, pat, pins, release)
        rel = path.relative_to(HERE.parent)
        for name in missing:
            print(f"pin_images: {rel}: {name} has no line in images.lock")
            bad += 1
        if new != text:
            if check:
                print(f"pin_images: {rel} is not pinned to images.lock (python3 packaging/pin_images.py)")
                bad += 1
            else:
                path.write_text(new)
                print(f"pin_images: pinned {rel}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
