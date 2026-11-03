#!/bin/bash
# Each published binary is built on its own (scripts/oci_build.sh: one `cargo build -p ...` per image), while
# the tests, clippy and packaging/linux/test/build_images.sh build many crates in one cargo run. Cargo turns on,
# for a dependency shared by the crates of one run, every feature any of them asks for (feature unification),
# so a crate that uses a feature without declaring it works in every test and not in the published image.
# 0.2.9: xbt-hashlink was published without xbt402's http-client, which only the test builds turned on, and its
# rentals did not start.
#
# This check reads scripts/oci_build.sh's cargo lines, so a new image is covered without an edit here. For each
# line it compares the features of every crate the line builds (cargo tree, the target's normal and build
# dependencies) with the features the same crates get in the workspace build the tests run (--workspace), and
# fails on a difference that scripts/standalone_features.allow does not list. A listed difference has been read:
# the feature only adds API the binary does not use (an impl, a type, a constructor), so leaving it out changes
# nothing the binary does. A difference that is not listed is either declared in the crate's Cargo.toml (what
# the binary needs) or, once read, added to the list with the reason.
#
#   scripts/check_standalone_features.sh [--target TRIPLE] [--print]
#     --target   the target to resolve for (default x86_64-unknown-linux-musl, as the published amd64 images)
#     --print    print every difference, listed or not, in the list's format, and exit 0
#
# Needs only cargo and python3; builds nothing (cargo tree reads Cargo.lock, --locked, offline when the
# dependencies are fetched). Run by .github/workflows/publish-images.yml before the images are built, and by CI.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET=x86_64-unknown-linux-musl
PRINT=0
while [ $# -gt 0 ]; do
  case $1 in
    --target) TARGET=$2; shift ;;
    --print) PRINT=1 ;;
    *) echo "usage: $0 [--target TRIPLE] [--print]" >&2; exit 2 ;;
  esac
  shift
done
exec python3 - "$TARGET" "$PRINT" <<'PY'
import re, subprocess, sys

target, print_all = sys.argv[1], sys.argv[2] == "1"

def tree(pkgs):
    """{(crate, version): set(features)} of what one cargo run over `pkgs` builds for the target."""
    args = ["cargo", "tree", "--locked", "-q", "-e", "features,normal,build", "--target", target,
            "--prefix", "none", "-f", "{p} [{f}]"] + pkgs
    out = subprocess.run(args, capture_output=True, text=True)
    if out.returncode:
        sys.exit(f"check_standalone_features: {' '.join(args)} failed:\n{out.stderr}")
    feats = {}
    for line in out.stdout.splitlines():
        m = re.match(r"(\S+) v(\S+)(?: \([^)]*\))? \[(.*)\]", line.strip())
        if m:
            feats.setdefault(m[1], set()).update(f for f in m[3].split(",") if f)
    return feats

# the published builds: every `cargo build ... -p X [-p Y]` line of oci_build.sh, named by its packages
groups = []
for line in open("scripts/oci_build.sh"):
    if "cargo build" in line and " -p " in line and not line.lstrip().startswith("#"):
        pkgs = re.findall(r"-p ([A-Za-z0-9_-]+)", line)
        if pkgs and pkgs not in groups:
            groups.append(pkgs)
if len(groups) < 8:
    sys.exit(f"check_standalone_features: found only {len(groups)} cargo build lines in scripts/oci_build.sh")

allowed = set()
for line in open("scripts/standalone_features.allow"):
    line = line.split("#", 1)[0].split()
    if line:
        if len(line) != 2 or ":" in line[0] or "/" not in line[1]:
            sys.exit(f"check_standalone_features: bad line in scripts/standalone_features.allow: {' '.join(line)}")
        allowed.add((line[0], line[1]))  # (published build, crate/feature)

unified = tree(["--workspace"])
bad, seen = [], set()
for pkgs in groups:
    name = "+".join(pkgs)
    alone = tree([a for p in pkgs for a in ("-p", p)])
    for crate, feats in sorted(alone.items()):
        for f in sorted(unified.get(crate, set()) - feats):
            seen.add((name, f"{crate}/{f}"))
            if print_all:
                print(f"{name} {crate}/{f}")
            elif (name, f"{crate}/{f}") not in allowed and ("*", f"{crate}/{f}") not in allowed:
                bad.append(f"  {name}: {crate}/{f}")
if print_all:
    sys.exit(0)
stale = sorted(f"  {b} {cf}" for b, cf in allowed if b != "*" and (b, cf) not in seen)
if stale:
    print("check_standalone_features: listed in scripts/standalone_features.allow but no longer a difference "
          "(remove them):\n" + "\n".join(stale))
if bad:
    print(f"check_standalone_features: {len(bad)} feature(s) the tests' workspace build turns on and the published "
          f"build of these crates does not ({target}):\n" + "\n".join(bad) +
          "\nDeclare each one the binary needs in its crate's Cargo.toml; list one that only adds unused API in "
          "scripts/standalone_features.allow, with the reason.")
    sys.exit(1)
print(f"check_standalone_features: {len(groups)} published builds, every feature difference from the workspace "
      f"build is declared or listed ({target})")
PY
