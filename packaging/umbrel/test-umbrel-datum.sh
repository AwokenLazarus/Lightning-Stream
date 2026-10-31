#!/bin/bash
# Lightning Stream's Umbrel compose renting with its Stream Gateway (DATUM-compatible), on regtest: the
# compose's own `renter` and `datum` services against a Knots BLAKE2b regtest node standing in for the
# `bitcoin` slot, and a masked solo rental paid through the wallet (packaging/umbrel/regtest/datum_regtest.py
# has the checks). The p2p_hash lab provides the Lightning side (scripts/p2p_hash_regtest.sh's: lf1-lf3, the
# wallet's signer, the hashmaker's gateway, a relay).
#
# Images (amd64 only, from this tree, tagged :0.1.0-umbtest and removed at the end, so no local tag a package
# names is replaced):
#   xbt-hashlink        container/Dockerfile's stage, on the static musl binary
#   xbt-datum-gateway   UMB_DATUM_IMAGE if given (oci_build.sh's, once container/Dockerfile has the stage);
#                       else a stand-in: the shared base layer, scripts/datum_gateway_build.sh's static gateway
#                       and xbt-supervise, as uid 10021 (xbt-datum)
#   xbt-init            when this tree's xbt-init knows the `datum` component: then the compose's own init
#                       makes the gateway's files; until then the driver lays them out per W5's contract
# Needs P2P_HASH_GATEWAYS (default ~/xbt-rnd/hash-gateways: bitcoind, bitcoin-cli, stratum-grind), the lab
# (run/lightning-fork-lab), python:3-alpine and debian:bookworm-slim. Ports P2P_HASH_PORT_BASE (19961) to +30.
# Report: run/umbrel_datum_regtest.json, run/umbrel_datum_regtest.log, run/umbrel_datum_<service>.log.
#   packaging/umbrel/test-umbrel-datum.sh
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1
ROOT=$PWD
B=${P2P_HASH_PORT_BASE:-19961}
export P2P_HASH_PORT_BASE=$B TICKET_E2E_PORT_BASE=$B TICKET_E2E_PORT_RPC=$B
export LN_TICKET_PORT_LF1=$((B + 1)) LN_TICKET_PORT_LF2=$((B + 2)) LN_TICKET_PORT_LF3=$((B + 3))
export COMPOSE_PROJECT_NAME=umbdatum
export ACTIVATION_HEIGHT=20
HG=${P2P_HASH_GATEWAYS:-$HOME/xbt-rnd/hash-gateways}
export P2P_HASH_GATEWAYS=$HG
for b in bitcoind bitcoin-cli stratum-grind; do
  [ -x "$HG/$b" ] || { echo "test-umbrel-datum: $HG/$b missing" >&2; exit 2; }
done
LAB=${P2P_HASH_LAB:-$ROOT/run/lightning-fork-lab}
if [ ! -x "$LAB/bin/lnd" ]; then
  # shellcheck source=scripts/ln_rail/lab.sh
  . "$ROOT/scripts/ln_rail/lab.sh"
fi
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ticket_e2e/compose.yml
TAG=0.1.0-umbtest
R=
cleanup() {
  if [ -n "$R" ]; then pkill -f "$R/" 2>/dev/null || true; fi
  (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
  docker image rm -f "xbt-hashlink:$TAG" "xbt-datum-gateway:$TAG" "xbt-init:$TAG" >/dev/null 2>&1 || true
  if [ -n "$R" ]; then
    mkdir -p "$ROOT/run/umbrel_datum_regtest"
    cp "$R"/*.log "$R"/*.json "$ROOT/run/umbrel_datum_regtest/" 2>/dev/null || true
    rm -rf "$R"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$ROOT/run"
# a short path: the signer's socket path must fit in sun_path (108 bytes)
R=$(mktemp -d "${TMPDIR:-/tmp}/umbd-XXXXXX")

# the lab's side, as p2p_hash_regtest.sh builds it
nice -n 19 cargo build -q -j4 --release --locked -p xbt-signer --bin xbt-signer -p xbt-wallet-mcp --bin xbt-wallet-mcp \
  -p xbt-gateway --bin xbt-gateway -p xbt-hashlink --bin xbt-hashlink
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

# the app's images, amd64, from this tree
T=x86_64-unknown-linux-musl
MUSL=${CARGO_TARGET_DIR:-$ROOT/target}/$T/release
INIT=0
grep -q '"datum"' crates/xbt-svc/src/lib.rs crates/xbt-svc/src/layout.rs 2>/dev/null && INIT=1
nice -n 19 cargo build -q -j4 --release --locked --target $T -p xbt-hashlink --bin xbt-hashlink -p xbt-svc --bin xbt-supervise
[ $INIT = 1 ] && nice -n 19 cargo build -q -j4 --release --locked --target $T -p xbt-svc --bin xbt-init
CTX=$ROOT/run/umbrel-datum-ctx
rm -rf "$CTX" && mkdir -p "$CTX/bin/amd64"
python3 container/mkbase.py "$CTX/base.tar"
cp container/Dockerfile "$CTX/Dockerfile"
cp "$MUSL/xbt-hashlink" "$CTX/bin/amd64/"
docker buildx build -q --platform linux/amd64 --target xbt-hashlink --load -t "xbt-hashlink:$TAG" "$CTX" >/dev/null
export UMB_HASHLINK_IMAGE=xbt-hashlink:$TAG
if [ $INIT = 1 ]; then
  cp "$MUSL/xbt-init" "$CTX/bin/amd64/"
  docker buildx build -q --platform linux/amd64 --target xbt-init --load -t "xbt-init:$TAG" "$CTX" >/dev/null
  export UMB_INIT_IMAGE=xbt-init:$TAG
fi
if [ -n "${UMB_DATUM_IMAGE:-}" ]; then
  docker image inspect "$UMB_DATUM_IMAGE" >/dev/null || { echo "test-umbrel-datum: $UMB_DATUM_IMAGE is not loaded" >&2; exit 2; }
else
  nice -n 19 scripts/datum_gateway_build.sh --targets x86_64-linux-musl --out "$ROOT/dist/datum"
  D=$CTX/datum && mkdir -p "$D/bin"
  cp "$CTX/base.tar" "$D/"
  cp "$ROOT/dist/datum/x86_64-linux-musl/xbt-datum-gateway" "$MUSL/xbt-supervise" "$D/bin/"
  cat >"$D/Dockerfile" <<'EOF'
# test stand-in for the xbt-datum-gateway image (container/Dockerfile's stage, once it is there)
FROM scratch
ADD base.tar /
ENV XBT_DATA_DIR=/data XBT_MODE=production
COPY --chmod=0555 bin/ /usr/bin/
USER 10021:10021
ENTRYPOINT ["/usr/bin/xbt-supervise", "--wait", "/data/run/datum/config.json", "--watch", "/data/run/datum/rpc.cookie", "--", "/usr/bin/xbt-datum-gateway", "-c", "/data/run/datum/config.json"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/bin/xbt-supervise", "probe", "http://127.0.0.1:7152/", "--waiting-for", "/data/run/datum/config.json"]
EOF
  docker buildx build -q --platform linux/amd64 --load -t "xbt-datum-gateway:$TAG" "$D" >/dev/null
  export UMB_DATUM_IMAGE=xbt-datum-gateway:$TAG
fi
echo "test-umbrel-datum: images $UMB_HASHLINK_IMAGE $UMB_DATUM_IMAGE ${UMB_INIT_IMAGE:-(no init with datum: laid out by the driver)}"

(cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
# shellcheck disable=SC2046 # the port list is meant to split
python3 "$ROOT/scripts/portcheck.py" wait $(seq "$B" $((B + 30)))
(cd "$LAB" && docker compose build -q lf1 && docker compose up -d fees knots-b2b)

export LAB RUN=$R OUT=$ROOT/run BIN
if nice -n 19 python3 "$ROOT/packaging/umbrel/regtest/datum_regtest.py" 2>&1 | tee "$ROOT/run/umbrel_datum_regtest.log"; then
  echo "test-umbrel-datum: OK"
else
  echo "test-umbrel-datum: FAIL (log: run/umbrel_datum_regtest.log)" >&2
  exit 1
fi
