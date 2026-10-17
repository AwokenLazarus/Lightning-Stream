#!/bin/bash
# Publish the images the Umbrel apps and the StartOS packages run to GitHub's container registry, as
# multi-platform images, and record their digests so the packages pin them:
#   xbt-init, xbt-signer, xbt-anchor-witness, xbt-wallet-mcp, xbt-wallet-ui, xbt-gateway
#   -> ghcr.io/awokenlazarus/<image>:<version>-<commit>, for linux/amd64, linux/arm64 and linux/arm/v7
#
# The build is scripts/oci_build.sh's (static musl binaries, cargo --locked, release, FROM scratch, the same
# platforms, labels and SOURCE_DATE_EPOCH): with --push it writes and inspects the OCI archives as always,
# then pushes the same build from the same context and cache. This script checks that the registry serves,
# under each tag, exactly the index of the inspected archive, writes packaging/images.lock and pins the
# packages to it (packaging/pin_images.py).
#
# Tag: <version>-<commit>, the workspace version in Cargo.toml and the 12-hex commit the images are built
# from (for example 0.1.0-0123456789ab), the name oci_build.sh already gives its archives. It names the
# source, it is new for every commit, and it is never moved: a tag that is already in the registry is
# refused. There is no `latest`: the packages pin a digest, and a moving tag would only invite pulling
# something else. The tree must be clean, so no -dirty image is published.
#
# Login: docker must be logged in to the registry with a token that may write packages (on ghcr.io, for a
# personal account: a classic token with write:packages), for example
#   printf '%s' "$TOKEN" | docker login ghcr.io -u USER --password-stdin
# A package GitHub creates on the first push is private: make it public in its settings (packaging/README.md,
# "Images").
#
#   scripts/oci_publish.sh [--skip-cargo] [--registry ghcr.io/OWNER] [--no-pin]
# --skip-cargo reuses the binaries in $CARGO_TARGET_DIR (oci_build.sh refuses any that name a host path).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
REGISTRY=ghcr.io/awokenlazarus
SKIP=()
PIN=1
while [ $# -gt 0 ]; do
  case $1 in
    --skip-cargo) SKIP=(--skip-cargo) ;;
    --registry) REGISTRY=${2%/}; shift ;;
    --no-pin) PIN=0 ;;
    *) echo "usage: $0 [--skip-cargo] [--registry ghcr.io/OWNER] [--no-pin]" >&2; exit 2 ;;
  esac
  shift
done
IMAGES=(xbt-init xbt-signer xbt-anchor-witness xbt-wallet-mcp xbt-wallet-ui xbt-gateway)
if git status --porcelain --untracked-files=no | grep -q .; then
  echo "oci_publish: the tree has uncommitted changes; commit first (a published image names its commit)" >&2; exit 1
fi
REV=$(git rev-parse --short=12 HEAD)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TAG=$VERSION-$REV
OUT=$ROOT/dist/oci
LOCK=$ROOT/packaging/images.lock

for img in "${IMAGES[@]}"; do
  if docker buildx imagetools inspect "$REGISTRY/$img:$TAG" >/dev/null 2>&1; then
    echo "oci_publish: $REGISTRY/$img:$TAG is already published; a tag is never overwritten" >&2; exit 1
  fi
done

scripts/oci_build.sh "${SKIP[@]}" --only "$(IFS=,; echo "${IMAGES[*]}")" --push "$REGISTRY"

# the registry serves, under the tag, the very index of the inspected archive, with the three platforms
python3 - "$OUT" "$REGISTRY" "$TAG" "$LOCK" "$REV" "${IMAGES[@]}" <<'PY'
import hashlib, json, subprocess, sys, tarfile
out, registry, tag, lock, rev, *images = sys.argv[1:]
lines = []
for img in images:
    with tarfile.open(f"{out}/{img}.tar") as t:
        archive = json.load(t.extractfile("index.json"))["manifests"][0]["digest"]
    pushed = json.load(open(f"{out}/{img}.push.json"))["containerimage.digest"]
    ref = f"{registry}/{img}:{tag}"
    raw = subprocess.check_output(["docker", "buildx", "imagetools", "inspect", "--raw", ref])
    served = "sha256:" + hashlib.sha256(raw).hexdigest()
    plats = sorted("/".join(filter(None, (m["platform"]["os"], m["platform"]["architecture"], m["platform"].get("variant"))))
                   for m in json.loads(raw)["manifests"])
    if not (archive == pushed == served) or plats != ["linux/amd64", "linux/arm/v7", "linux/arm64"]:
        sys.exit(f"oci_publish: {ref}: archive {archive}, pushed {pushed}, served {served}, platforms {plats}")
    print(f"   {ref}@{served} {' '.join(plats)}")
    lines.append(f"{img} {ref}@{served}")
with open(lock, "w") as f:
    f.write("# The published images the packages pin, written by scripts/oci_publish.sh. One line per image:\n"
            "#   <image> <registry>/<image>:<version>-<commit>@<index digest>\n"
            f"# Built from commit {rev} for linux/amd64, linux/arm64 and linux/arm/v7. packaging/pin_images.py writes\n"
            "# them into the Umbrel compose files and the StartOS specs; packaging/umbrel/lint.py checks they agree.\n")
    f.write("\n".join(lines) + "\n")
PY
echo "oci_publish: wrote packaging/images.lock"
if [ $PIN = 1 ]; then python3 packaging/pin_images.py; fi
echo "oci_publish: done; check that every package is public (packaging/README.md, \"Images\")"
