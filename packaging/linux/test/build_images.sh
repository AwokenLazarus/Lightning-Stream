#!/bin/bash
# The Linux package test's images that have no published digest yet, for this machine (amd64) only:
#   xbt-wallet-ui:linux-test, xbt-hashlink:linux-test   the published images with this tree's binaries in
#       them (static musl, as oci_build.sh builds them): the renter's masking check, the Hashrate page;
#   xbt-datum-gateway:linux-test        the Stream Gateway from third_party/datum_gateway at HEAD
#       (stream-gateway.Dockerfile: a stand-in for the gateway lane's image);
#   xbt-datum-gateway:linux-test-stock  the same from the vendor commit, unmodified: an owner's own stock
#       DATUM gateway, which doesn't mask its jobs.
# Run by packaging/linux/test-linux.sh unless LS_TEST_BUILD=0.
set -euo pipefail
cd "$(dirname "$0")/../../.."
ROOT=$PWD
# the vendor commit: CONVOY datum_gateway 971af86 as it came, before the masking patch
STOCK=${LS_TEST_STOCK_REF:-$(git log --format=%H --diff-filter=A -1 -- third_party/datum_gateway/LICENSE)}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
lock() { awk -v n="$1" '$1 == n {print $2}' packaging/images.lock; }

echo "== this tree's xbt-wallet-ui and xbt-hashlink (x86_64 musl)"
TGT=${CARGO_TARGET_DIR:-target}
cargo build -q -j "${CARGO_BUILD_JOBS:-6}" --release --locked --target x86_64-unknown-linux-musl \
  -p xbt-wallet-ui -p xbt-hashlink --bin xbt-wallet-ui --bin xbt-hashlink
for img in xbt-wallet-ui xbt-hashlink; do
  mkdir -p "$T/$img"
  cp "$TGT/x86_64-unknown-linux-musl/release/$img" "$T/$img/$img"
  printf 'FROM %s\nCOPY --chmod=0555 %s /usr/bin/%s\n' "$(lock "$img")" "$img" "$img" > "$T/$img/Dockerfile"
  docker build -q -t "$img:linux-test" "$T/$img" >/dev/null
  echo "   $img:linux-test"
done

echo "== the Stream Gateway (HEAD) and a stock DATUM gateway ($(git rev-parse --short "$STOCK"))"
for v in head stock; do
  ref=HEAD; tag=linux-test
  [ "$v" = stock ] && { ref=$STOCK; tag=linux-test-stock; }
  mkdir -p "$T/gw-$v"
  git archive "$ref" third_party/datum_gateway | tar -x -C "$T/gw-$v"
  docker build -q --build-arg SUPERVISE_FROM="$(lock xbt-gateway)" -f "$ROOT/packaging/linux/test/stream-gateway.Dockerfile" \
    -t "xbt-datum-gateway:$tag" "$T/gw-$v/third_party/datum_gateway" >/dev/null
  echo "   xbt-datum-gateway:$tag"
done
