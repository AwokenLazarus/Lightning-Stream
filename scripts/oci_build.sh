#!/bin/bash
# AGP-038: multi-arch OCI images of the agentpay services, saved locally (pushed only with --push, which
# scripts/oci_publish.sh drives).
#   xbt-signer, xbt-anchor-witness, xbt-wallet-mcp, xbt-wallet-ui, xbt-init, xbt-work-relay, xbt-gateway,
#   lightning-stream (the connector; not in packaging/images.lock until scripts/oci_publish.sh records it)
#   (xbt-supervise is not an image: it is copied into the signer and gateway images)
#   platforms linux/amd64, linux/arm64, linux/arm/v7, FROM scratch, static musl (zig), docs/CONTAINER.md
#
# Steps: build the static musl binaries for the three targets (release profile, --locked so that the
# dependencies are the ones Cargo.lock names and a lockfile that is out of date stops the build, cargo -j2
# under the soak rules); stage them with the shared base layer (container/mkbase.py); `docker buildx build` each image
# for all three platforms into dist/oci/<image>.tar (an OCI archive with SOURCE_DATE_EPOCH = the commit
# time and rewritten timestamps). With --load, also load the images into the local Docker: the amd64 ones as
# <image>:agp038 (scripts/container_test.sh runs these), and every platform as <image>:<version> (the
# regtest drivers of packaging/ run these in place of the published images). dist/oci/IMAGES.md gets digests and
# sizes. With --push REGISTRY, also push each image, the same build from the same context and cache, as
# REGISTRY/<image>:<version>-<commit> (refused for a dirty tree); the digest the registry returns goes to
# dist/oci/<image>.push.json. The binaries carry no build host path: cargo and the C compiler map the checkout
# to /src and the cargo home to /cargo, and a staged binary that still names either is refused.
#
# The Dockerfile has no RUN, so building the arm images needs no emulator (no binfmt, no qemu). The tool is
# docker buildx through the docker group (no sudo); this host has no rootless Docker, podman or buildah.
#   scripts/oci_build.sh [--load] [--skip-cargo] [--only IMAGE[,IMAGE...]] [--push REGISTRY]
# The binaries come from $CARGO_TARGET_DIR (default target/). --only builds a subset (the base layer is shared,
# so a subset's archives match the others only when built from the same mkbase.py).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
LOAD=0
CARGO=1
ONLY=""
PUSH=""
while [ $# -gt 0 ]; do
  case $1 in
    --load) LOAD=1 ;;
    --skip-cargo) CARGO=0 ;;
    --only) ONLY=$2; shift ;;
    --push) PUSH=${2%/}; shift ;;
    *) echo "usage: $0 [--load] [--skip-cargo] [--only IMAGE[,IMAGE...]] [--push REGISTRY]" >&2; exit 2 ;;
  esac
  shift
done
IMAGES=(xbt-signer xbt-anchor-witness xbt-wallet-mcp xbt-wallet-ui xbt-init xbt-work-relay xbt-gateway lightning-stream)
[ -n "$ONLY" ] && IMAGES=(${ONLY//,/ })
TGT=${CARGO_TARGET_DIR:-target}
want() { [[ " ${IMAGES[*]} " == *" $1 "* ]]; }
# rust target -> buildx TARGETARCH+TARGETVARIANT
declare -A ARCH=([x86_64-unknown-linux-musl]=amd64 [aarch64-unknown-linux-musl]=arm64 [armv7-unknown-linux-musleabihf]=armv7)
PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7
# Paths in the binaries (panic locations, C asserts) name the build host's directories: map the checkout to
# /src and the cargo home to /cargo, so a published image carries no host path. The target's rustflags in
# .cargo/config.toml are kept: cargo appends a --config array to them.
CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
remap() { # TARGET: sets RM (cargo args) and the C flags cc-rs reads for that target
  RM=(--config "target.$1.rustflags=[\"--remap-path-prefix=$CARGO_HOME_DIR=/cargo\",\"--remap-path-prefix=$ROOT=/src\"]")
  export "CFLAGS_${1//-/_}=-ffile-prefix-map=$CARGO_HOME_DIR=/cargo -ffile-prefix-map=$ROOT=/src"
}
SOAK=(nice -n 19)
command -v systemd-run >/dev/null && SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
REV=$(git rev-parse --short=12 HEAD)
DIRTY=$(git status --porcelain --untracked-files=no | grep -q . && echo "-dirty" || true)
EPOCH=$(git log -1 --format=%ct)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
if [ -n "$PUSH" ] && [ -n "$DIRTY" ]; then echo "oci_build: --push needs a clean tree (an image names its commit)" >&2; exit 1; fi
OUT=$ROOT/dist/oci
CTX=$OUT/ctx
mkdir -p "$OUT"
rm -rf "$CTX"
mkdir -p "$CTX"

if [ $CARGO = 1 ]; then
  for t in "${!ARCH[@]}"; do
    echo "== cargo build --release --target $t"
    remap "$t"
    if want xbt-signer || want xbt-anchor-witness; then
      "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-signer --bin xbt-signer --bin xbt-anchor-witness
    fi
    if want xbt-gateway; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-gateway --bin xbt-gateway; fi
    if want xbt-signer || want xbt-gateway; then
      "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-svc --bin xbt-supervise
    fi
    if want xbt-wallet-mcp; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-wallet-mcp; fi
    if want xbt-wallet-ui || want xbt-init; then
      "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-wallet-ui -p xbt-svc --bin xbt-wallet-ui --bin xbt-init
    fi
    if want xbt-work-relay; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-work-relay --bin xbt-work-relay; fi
    if want lightning-stream; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p lightning-stream --bin lightning-stream; fi
  done
fi
for t in "${!ARCH[@]}"; do
  mkdir -p "$CTX/bin/${ARCH[$t]}"
  bins=("${IMAGES[@]}")
  if want xbt-signer || want xbt-gateway; then bins+=(xbt-supervise); fi
  for b in "${bins[@]}"; do
    f=$TGT/$t/release/$b
    [ -x "$f" ] || { echo "oci_build: $f missing (run without --skip-cargo)" >&2; exit 1; }
    file -b "$f" | grep -q "statically linked" || { echo "oci_build: $f is not static: $(file -b "$f")" >&2; exit 1; }
    if grep -q -a -F -e "$ROOT/" -e "$CARGO_HOME_DIR/" "$f"; then
      echo "oci_build: $f names a build host path (rebuild without --skip-cargo: the path remapping)" >&2; exit 1
    fi
    cp "$f" "$CTX/bin/${ARCH[$t]}/$b"
  done
  # the images whose layer holds xbt-supervise beside their own binary
  for b in xbt-signer xbt-gateway; do
    if want "$b"; then
      mkdir -p "$CTX/bin/${ARCH[$t]}/$b.d"
      cp "$CTX/bin/${ARCH[$t]}/$b" "$CTX/bin/${ARCH[$t]}/xbt-supervise" "$CTX/bin/${ARCH[$t]}/$b.d/"
    fi
  done
done
python3 container/mkbase.py "$CTX/base.tar"
cp container/Dockerfile "$CTX/Dockerfile"

SRC=https://github.com/AwokenLazarus/Lightning-Stream
LABELS=(--label "org.opencontainers.image.source=$SRC" --label "org.opencontainers.image.revision=$REV$DIRTY"
        --label "org.opencontainers.image.version=$VERSION" --label "org.opencontainers.image.licenses=MIT OR Apache-2.0")
# the same on the multi-platform index (a registry's package page reads the index's annotations), and no
# provenance or SBOM attestation (they would add manifests of their own to the index)
INDEX=(--annotation "index:org.opencontainers.image.source=$SRC" --annotation "index:org.opencontainers.image.revision=$REV$DIRTY"
       --annotation "index:org.opencontainers.image.version=$VERSION" --annotation "index:org.opencontainers.image.licenses=MIT OR Apache-2.0"
       --provenance=false --sbom=false)
for img in "${IMAGES[@]}"; do
  echo "== buildx $img ($PLATFORMS)"
  ARCHIVE=(--platform "$PLATFORMS" --target "$img" "${LABELS[@]}" --label "org.opencontainers.image.title=$img" "${INDEX[@]}"
           --annotation "index:org.opencontainers.image.title=$img"
           --annotation "index:org.opencontainers.image.description=Lightning Stream: $img, a static binary FROM scratch (docs/CONTAINER.md)"
           --build-arg SOURCE_DATE_EPOCH="$EPOCH")
  docker buildx build -q "${ARCHIVE[@]}" -t "$img:$VERSION-$REV$DIRTY" \
    --output "type=oci,dest=$OUT/$img.tar,rewrite-timestamp=true" "$CTX" >/dev/null
  if [ -n "$PUSH" ]; then
    echo "== push $PUSH/$img:$VERSION-$REV"
    docker buildx build -q "${ARCHIVE[@]}" --metadata-file "$OUT/$img.push.json" \
      --output "type=image,name=$PUSH/$img:$VERSION-$REV,push=true,unpack=false,oci-mediatypes=true,rewrite-timestamp=true" "$CTX" >/dev/null
  fi
  if [ $LOAD = 1 ]; then
    docker buildx build -q --platform linux/amd64 --target "$img" "${LABELS[@]}" --label "org.opencontainers.image.title=$img" \
      --build-arg SOURCE_DATE_EPOCH="$EPOCH" -t "$img:agp038" --load "$CTX" >/dev/null
    # every platform under the version tag (Docker's containerd image store keeps a multi-platform index)
    docker buildx build -q --platform "$PLATFORMS" --target "$img" "${LABELS[@]}" --label "org.opencontainers.image.title=$img" \
      --build-arg SOURCE_DATE_EPOCH="$EPOCH" -t "$img:$VERSION" --load "$CTX" >/dev/null
  fi
done
python3 scripts/oci_inspect.py "$OUT" "${IMAGES[@]}" --md "$OUT/IMAGES.md" --rev "$REV$DIRTY"
echo "oci_build: $OUT/{$(IFS=,; echo "${IMAGES[*]}")}.tar"
