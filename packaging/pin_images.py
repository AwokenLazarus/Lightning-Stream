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
line (a local tag no box can pull), and a lock built from an older commit than the last change to the
images' sources (crates/, Cargo.toml, Cargo.lock, container/): the pins would run old code. Run it before
a store or a package is published; it passes only after the images of the commit are published and pinned.
    python3 packaging/pin_images.py [--check] [--release]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = HERE / "images.lock"
REF = re.compile(r"^(?P<repo>[a-z0-9.-]+(?::\d+)?(?:/[a-z0-9._-]+)+)/(?P<name>xbt-[a-z0-9-]+|lightning-stream):(?P<tag>[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{12})"
                 r"@(?P<digest>sha256:[0-9a-f]{64})$")
# an image reference of an agentpay service, local tag or pinned. lightning-stream and xbt-hashlink are
# included so that once images.lock has their lines, this rewrites their local tags to those digests.
ANY = r"(?:[a-z0-9.:/-]+/)?(xbt-(?:init|signer|anchor-witness|wallet-mcp|wallet-ui|gateway|work-relay|hashlink)|lightning-stream)(?::[A-Za-z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?"


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


# what the images are built from: a change here after the lock's commit makes the pins stale
IMAGE_SOURCES = ["crates", "Cargo.toml", "Cargo.lock", "container"]


def stale(pins: dict[str, str]) -> list[str]:
    """The lock's commits whose images are older than the sources at HEAD (the reasons, one per commit)."""
    import subprocess
    out = []
    for commit in sorted({REF.match(r)["tag"].rsplit("-", 1)[1] for r in pins.values()}):
        r = subprocess.run(["git", "-C", str(HERE.parent), "diff", "--quiet", commit, "HEAD", "--", *IMAGE_SOURCES])
        if r.returncode == 1:
            out.append(f"images.lock pins images built from {commit}; their sources changed since (git diff {commit} HEAD -- {' '.join(IMAGE_SOURCES)})")
        elif r.returncode != 0:
            out.append(f"images.lock names commit {commit}, which this checkout does not have")
    return out


def main() -> int:
    check = "--check" in sys.argv[1:] or "--release" in sys.argv[1:]
    release = "--release" in sys.argv[1:]
    pins = load_lock()
    bad = 0
    if release:
        for why in stale(pins):
            print(f"pin_images: not releasable: {why}")
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
