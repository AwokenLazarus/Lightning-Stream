#!/usr/bin/env python3
"""Pin the packages to the published images in packaging/images.lock (scripts/oci_publish.sh writes it).

The lock has one line per image: `<image> <registry>/<image>:<version>-<commit>@sha256:<index digest>`. This
writes each reference into
  * the Umbrel apps' docker-compose.yml (`image:` lines of the agentpay services), as given: tag and digest;
  * the StartOS packages' startos/spec.ts (the IMAGES table the manifest packs from), as given.
With --check it writes nothing and exits 1 if a file is not pinned to the lock (packaging/umbrel/lint.py runs
it). Other images (the stand-in XBT node) are left alone.
    python3 packaging/pin_images.py [--check]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = HERE / "images.lock"
REF = re.compile(r"^(?P<repo>[a-z0-9.-]+(?::\d+)?(?:/[a-z0-9._-]+)+)/(?P<name>xbt-[a-z0-9-]+):(?P<tag>[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{12})"
                 r"@(?P<digest>sha256:[0-9a-f]{64})$")
# an image reference of an agentpay service, local tag or pinned
ANY = r"(?:[a-z0-9.:/-]+/)?(xbt-(?:init|signer|anchor-witness|wallet-mcp|wallet-ui|gateway|work-relay))(?::[A-Za-z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?"


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
    for p in sorted((HERE / "startos").glob("*/startos/spec.ts")):
        out.append((p, re.compile(r"(?m)^(  [a-z]+: ')" + ANY + r"(',?)$"), "spec"))
    return out


def pinned(text: str, pat: re.Pattern, pins: dict[str, str]) -> tuple[str, list[str]]:
    missing = []

    def sub(m: re.Match) -> str:
        name = m.group(2)
        if name not in pins:
            missing.append(name)
            return m.group(0)
        return m.group(1) + pins[name] + (m.group(3) if m.lastindex and m.lastindex >= 3 else "")

    return pat.sub(sub, text), missing


def main() -> int:
    check = "--check" in sys.argv[1:]
    pins = load_lock()
    bad = 0
    for path, pat, _ in targets():
        text = path.read_text()
        new, missing = pinned(text, pat, pins)
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
