#!/bin/bash
# AGP-038: multi-arch OCI images of the agentpay services, saved locally (pushed only with --push, which
# scripts/oci_publish.sh drives).
#   xbt-signer, xbt-anchor-witness, xbt-wallet-mcp, xbt-wallet-ui, xbt-init, xbt-work-relay, xbt-gateway,
#   lightning-stream (the connector; not in packaging/images.lock until scripts/oci_publish.sh records it),
#   xbt-hashlink (p2p-hash: the hasher's and the renter's services; likewise)
#   xbt-stream-relay (the built-in Stream relay, off until the owner switches it on; likewise)
#   xbt-vpn (the VPN service: the owner's devices' WireGuard endpoint, and an exit if offered)
#   xbt-datum-gateway (the Stream Gateway, DATUM-compatible: the renter's masking gateway; C, built by
#     scripts/datum_gateway_build.sh, or taken from XBT_DATUM_PREBUILT)
#   (xbt-supervise is not an image: it is copied into the signer and gateway images)
#   platforms linux/amd64, linux/arm64, linux/arm/v7, FROM scratch, static musl (zig), docs/CONTAINER.md
#
# Steps: build the static musl binaries for the three targets (release profile, --locked so that the
# dependencies are the ones Cargo.lock names and a lockfile that is out of date stops the build, cargo -j2
# under the soak rules); stage them with the shared base layer (container/mkbase.py); `docker buildx build` each image
# for all three platforms into dist/oci/<image>.tar (an OCI archive with SOURCE_DATE_EPOCH = the commit
# time and rewritten timestamps). With --binaries-only, stop after staging the checked static binaries in
# dist/oci/ctx/bin/<arch>/ (the binary release workflow packs those). With --load, also load the images into the local Docker: the amd64 ones as
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
BIN_ONLY=0
CARGO=1
ONLY=""
PUSH=""
while [ $# -gt 0 ]; do
  case $1 in
    --load) LOAD=1 ;;
    --skip-cargo) CARGO=0 ;;
    --binaries-only) BIN_ONLY=1 ;;
    --only) ONLY=$2; shift ;;
    --push) PUSH=${2%/}; shift ;;
    *) echo "usage: $0 [--load] [--skip-cargo] [--binaries-only] [--only IMAGE[,IMAGE...]] [--push REGISTRY]" >&2; exit 2 ;;
  esac
  shift
done
IMAGES=(xbt-signer xbt-anchor-witness xbt-wallet-mcp xbt-wallet-ui xbt-init xbt-work-relay xbt-gateway lightning-stream xbt-hashlink xbt-stream-relay xbt-vpn xbt-datum-gateway)
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
# a staged image root keeps read-only folders (xbt-vpn's table, 0555): writable again before removal
if [ -d "$CTX" ]; then chmod -R u+w "$CTX"; fi
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
    if want xbt-signer || want xbt-gateway || want xbt-datum-gateway; then
      "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-svc --bin xbt-supervise
    fi
    if want xbt-wallet-mcp; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-wallet-mcp; fi
    if want xbt-wallet-ui || want xbt-init; then
      "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-wallet-ui -p xbt-svc --bin xbt-wallet-ui --bin xbt-init
    fi
    if want xbt-work-relay; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-work-relay --bin xbt-work-relay; fi
    if want lightning-stream; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p lightning-stream --bin lightning-stream; fi
    if want xbt-hashlink; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-hashlink --bin xbt-hashlink; fi
    if want xbt-stream-relay; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-stream-relay --bin xbt-stream-relay; fi
    if want xbt-vpn; then "${SOAK[@]}" cargo build -q -j2 --release --locked "${RM[@]}" --target "$t" -p xbt-vpn --bin xbt-vpn; fi
  done
fi
for t in "${!ARCH[@]}"; do
  mkdir -p "$CTX/bin/${ARCH[$t]}"
  bins=()
  for b in "${IMAGES[@]}"; do [ "$b" = xbt-datum-gateway ] || bins+=("$b"); done
  if want xbt-signer || want xbt-gateway || want xbt-datum-gateway; then bins+=(xbt-supervise); fi
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
# The Stream Gateway (xbt-datum-gateway) is C, not cargo: scripts/datum_gateway_build.sh makes its static
# binaries and the licences it ships (dist/datum; XBT_DATUM_PREBUILT names a directory that already holds
# them, as --skip-cargo does for the Rust ones). One layer, a root staged here with its modes: the binary and
# xbt-supervise 0555, the notice and licences 0444 in a 0555 folder (the base layer makes the folder too).
if want xbt-datum-gateway; then
  declare -A ZIG=([x86_64-unknown-linux-musl]=x86_64-linux-musl [aarch64-unknown-linux-musl]=aarch64-linux-musl
                  [armv7-unknown-linux-musleabihf]=arm-linux-musleabihf)
  DG=${XBT_DATUM_PREBUILT:-}
  if [ -z "$DG" ]; then
    DG=$OUT/datum
    zt=(); for t in "${!ARCH[@]}"; do zt+=("${ZIG[$t]}"); done
    "${SOAK[@]}" scripts/datum_gateway_build.sh --out "$DG" --targets "$(IFS=,; echo "${zt[*]}")" --test
  fi
  for t in "${!ARCH[@]}"; do
    d=$CTX/bin/${ARCH[$t]}
    f=$DG/${ZIG[$t]}/xbt-datum-gateway
    [ -x "$f" ] || { echo "oci_build: $f missing (scripts/datum_gateway_build.sh)" >&2; exit 1; }
    file -b "$f" | grep -q "statically linked" || { echo "oci_build: $f is not static: $(file -b "$f")" >&2; exit 1; }
    if grep -q -a -F -e "$ROOT/" "$f"; then echo "oci_build: $f names a build host path" >&2; exit 1; fi
    r=$d/xbt-datum-gateway.root
    if [ -d "$r" ]; then chmod -R u+w "$r"; fi
    rm -rf "$r" && mkdir -p "$r/usr/bin" "$r/usr/share/xbt-datum-gateway"
    cp "$f" "$r/usr/bin/xbt-datum-gateway" && cp "$d/xbt-supervise" "$r/usr/bin/xbt-supervise"
    chmod 0555 "$r/usr/bin/"*
    cp "$DG"/licenses/* "$r/usr/share/xbt-datum-gateway/" && chmod 0444 "$r/usr/share/xbt-datum-gateway/"*
    chmod 0755 "$r/usr" "$r/usr/bin" "$r/usr/share" && chmod 0555 "$r/usr/share/xbt-datum-gateway"
  done
fi
# --binaries-only: the checked static binaries in dist/oci/ctx/bin/<arch>/ are the result (the binary
# release workflow packs them); no image is built
if [ $BIN_ONLY = 1 ]; then
  echo "== binaries in $CTX/bin"
  exit 0
fi
python3 container/mkbase.py "$CTX/base.tar"
cp container/Dockerfile "$CTX/Dockerfile"
# the VPN service ships the country table exits' regions are checked against (DB-IP's IP to Country Lite,
# CC BY 4.0), so a box needs no download to check them. XBT_GEO_FILE: a copy already fetched (.csv.gz);
# else this month's, or last month's, from DB-IP
mkdir -p "$CTX/geo"
if want xbt-vpn; then
  if [ -n "${XBT_GEO_FILE:-}" ]; then
    cp "$XBT_GEO_FILE" "$CTX/geo/dbip-country-lite.csv.gz"
    month=$(basename "$XBT_GEO_FILE" | grep -oE '[0-9]{4}-[0-9]{2}' || echo "unknown")
  else
    month=
    for m in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 day" +%Y-%m)"; do
      if curl -fsSL --max-time 300 "https://download.db-ip.com/free/dbip-country-lite-$m.csv.gz" -o "$CTX/geo/dbip-country-lite.csv.gz"; then month=$m; break; fi
    done
    [ -n "$month" ] || { echo "oci_build: the DB-IP country table could not be fetched (set XBT_GEO_FILE)" >&2; exit 1; }
  fi
  gzip -t "$CTX/geo/dbip-country-lite.csv.gz" || { echo "oci_build: the country table is not gzip" >&2; exit 1; }
  printf 'IP to Country Lite by DB-IP (https://db-ip.com), %s, licensed under CC BY 4.0\n(https://creativecommons.org/licenses/by/4.0/).\n' "$month" > "$CTX/geo/ATTRIBUTION"
  echo "== country table: DB-IP $month, $(stat -c %s "$CTX/geo/dbip-country-lite.csv.gz") bytes, sha256 $(sha256sum "$CTX/geo/dbip-country-lite.csv.gz" | cut -c1-16)"
  # one layer for the binary and its table (base + one layer, as every image): a root to COPY whole, its
  # modes set here (COPY keeps them), the table's folder 0555 as the base layer makes it
  for d in "$CTX"/bin/*/; do
    [ -x "$d/xbt-vpn" ] || continue
    r="$d/xbt-vpn.root"
    if [ -d "$r" ]; then chmod -R u+w "$r"; fi
    rm -rf "$r" && mkdir -p "$r/usr/bin" "$r/usr/share/xbt-vpn"
    cp "$d/xbt-vpn" "$r/usr/bin/xbt-vpn" && chmod 0555 "$r/usr/bin/xbt-vpn"
    cp "$CTX/geo/dbip-country-lite.csv.gz" "$CTX/geo/ATTRIBUTION" "$r/usr/share/xbt-vpn/"
    chmod 0444 "$r/usr/share/xbt-vpn/"*
    chmod 0755 "$r/usr" "$r/usr/bin" "$r/usr/share" && chmod 0555 "$r/usr/share/xbt-vpn"
  done
fi

SRC=https://github.com/AwokenLazarus/Lightning-Stream
LABELS=(--label "org.opencontainers.image.source=$SRC" --label "org.opencontainers.image.revision=$REV$DIRTY"
        --label "org.opencontainers.image.version=$VERSION")
# the same on the multi-platform index (a registry's package page reads the index's annotations), and no
# provenance or SBOM attestation (they would add manifests of their own to the index)
INDEX=(--annotation "index:org.opencontainers.image.source=$SRC" --annotation "index:org.opencontainers.image.revision=$REV$DIRTY"
       --annotation "index:org.opencontainers.image.version=$VERSION"
       --provenance=false --sbom=false)
for img in "${IMAGES[@]}"; do
  echo "== buildx $img ($PLATFORMS)"
  # each image's own licence (SPDX; scripts/oci_inspect.py's table, which also checks it): ours, or, for the Stream
  # Gateway, with the C libraries it links (two LGPL)
  lic=$(python3 scripts/oci_inspect.py --license "$img")
  LIC=(--label "org.opencontainers.image.licenses=$lic")
  ARCHIVE=(--platform "$PLATFORMS" --target "$img" "${LABELS[@]}" "${LIC[@]}" --label "org.opencontainers.image.title=$img" "${INDEX[@]}"
           --annotation "index:org.opencontainers.image.licenses=$lic"
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
    docker buildx build -q --platform linux/amd64 --target "$img" "${LABELS[@]}" "${LIC[@]}" --label "org.opencontainers.image.title=$img" \
      --build-arg SOURCE_DATE_EPOCH="$EPOCH" -t "$img:agp038" --load "$CTX" >/dev/null
    # every platform under the version tag (Docker's containerd image store keeps a multi-platform index)
    docker buildx build -q --platform "$PLATFORMS" --target "$img" "${LABELS[@]}" "${LIC[@]}" --label "org.opencontainers.image.title=$img" \
      --build-arg SOURCE_DATE_EPOCH="$EPOCH" -t "$img:$VERSION" --load "$CTX" >/dev/null
  fi
done
python3 scripts/oci_inspect.py "$OUT" "${IMAGES[@]}" --md "$OUT/IMAGES.md" --rev "$REV$DIRTY"
echo "oci_build: $OUT/{$(IFS=,; echo "${IMAGES[*]}")}.tar"
