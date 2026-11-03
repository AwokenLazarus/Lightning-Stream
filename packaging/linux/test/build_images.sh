#!/bin/bash
# The Linux package test's images that have no published digest yet, for this machine (amd64) only:
#   xbt-init:linux-test, xbt-wallet-ui:linux-test, xbt-hashlink:linux-test, xbt-gateway:linux-test   the
#       published images with this tree's binaries in them (static musl, as oci_build.sh builds them): the init
#       that knows the compose's components, the renter's masking check, the Hashrate page, and the seller
#       gateway that reads the config this UI writes (health_token is newer than the published gateway) with
#       this tree's xbt-supervise beside it;
#   xbt-datum-gateway:linux-test-stock  third_party/datum_gateway at the vendor commit, unmodified, built on
#       Debian (stream-gateway.Dockerfile): an owner's own stock DATUM gateway, which doesn't mask its jobs.
# The Stream Gateway itself is the real image (scripts/oci_build.sh --load: xbt-datum-gateway:0.1.0, or
# LS_TEST_DATUM_IMAGE), not built here.
# Run by packaging/linux/test-linux.sh unless LS_TEST_BUILD=0.
set -euo pipefail
cd "$(dirname "$0")/../../.."
ROOT=$PWD
# the vendor commit: CONVOY datum_gateway 971af86 as it came, before the masking patch
STOCK=${LS_TEST_STOCK_REF:-$(git log --format=%H --diff-filter=A -1 -- third_party/datum_gateway/LICENSE)}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
lock() { awk -v n="$1" '$1 == n {print $2}' packaging/images.lock; }

echo "== this tree's xbt-init, xbt-wallet-ui, xbt-hashlink and xbt-gateway (x86_64 musl)"
TGT=${CARGO_TARGET_DIR:-target}
# One cargo run per image, as scripts/oci_build.sh builds them for publishing, not one run for all: cargo turns
# on, for the dependencies the crates of one run share, every feature any of them asks for, and a binary built
# with the others got features its published build lacks (0.2.9: xbt-hashlink without xbt402's http-client
# passed here and failed to start a rental from the published image).
for b in "-p xbt-wallet-ui -p xbt-svc --bin xbt-wallet-ui --bin xbt-init" "-p xbt-hashlink --bin xbt-hashlink" \
         "-p xbt-gateway --bin xbt-gateway" "-p xbt-signer --bin xbt-signer" "-p xbt-svc --bin xbt-supervise"; do
  # shellcheck disable=SC2086 # $b is the list of cargo arguments
  cargo build -q -j "${CARGO_BUILD_JOBS:-6}" --release --locked --target x86_64-unknown-linux-musl $b
done
# and this tree's users and groups (container/mkbase.py): the pinned images' /etc/group predates the Stream
# Gateway's (xbt-datum, 10021, with the UI in it, so the UI can give run/datum/config.json the gateway's group)
python3 container/mkbase.py "$T/base.tar"
mkdir -p "$T/base" && tar -x -C "$T/base" -f "$T/base.tar" etc/passwd etc/group
for img in xbt-init xbt-wallet-ui xbt-hashlink; do
  mkdir -p "$T/$img"
  cp "$TGT/x86_64-unknown-linux-musl/release/$img" "$T/$img/$img"
  cp "$T/base/etc/passwd" "$T/base/etc/group" "$T/$img/"
  printf 'FROM %s\nCOPY --chmod=0555 %s /usr/bin/%s\nCOPY --chmod=0444 passwd group /etc/\n' "$(lock "$img")" "$img" "$img" > "$T/$img/Dockerfile"
  docker build -q -t "$img:linux-test" "$T/$img" >/dev/null
  echo "   $img:linux-test"
done
# the seller gateway and the signer with xbt-supervise beside each, as their images ship them (oci_build.sh). The
# signer is this tree's: the pinned one (12b8182c) serves no renter's socket (run/rental/signer.sock), which the
# compose's hashtaker pays through
for img in xbt-gateway xbt-signer; do
  mkdir -p "$T/$img"
  cp "$TGT/x86_64-unknown-linux-musl/release/$img" "$TGT/x86_64-unknown-linux-musl/release/xbt-supervise" \
    "$T/base/etc/passwd" "$T/base/etc/group" "$T/$img/"
  printf 'FROM %s\nCOPY --chmod=0555 %s xbt-supervise /usr/bin/\nCOPY --chmod=0444 passwd group /etc/\n' "$(lock "$img")" "$img" \
    > "$T/$img/Dockerfile"
  docker build -q -t "$img:linux-test" "$T/$img" >/dev/null
  echo "   $img:linux-test"
done

echo "== a stock DATUM gateway ($(git rev-parse --short "$STOCK"))"
mkdir -p "$T/gw-stock"
git archive "$STOCK" third_party/datum_gateway | tar -x -C "$T/gw-stock"
docker build -q --build-arg SUPERVISE_FROM="$(lock xbt-gateway)" -f "$ROOT/packaging/linux/test/stream-gateway.Dockerfile" \
  -t xbt-datum-gateway:linux-test-stock "$T/gw-stock/third_party/datum_gateway" >/dev/null
echo "   xbt-datum-gateway:linux-test-stock"
