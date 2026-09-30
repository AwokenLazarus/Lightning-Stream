#!/bin/bash
# AGP-048 on regtest: rail=ln. The Rust signer and MCP pay XBT Lightning invoices through a Lightning
# Fork node under B2's policy, with the AGP-047 guards (bit 512, the LN node's chain identity, no
# taproot or non-unified or pre-split channels). Lab: paulscode/lightning-fork-lab a5cadc5 (Knots
# v29.4.1 BLAKE2b regtest, activation at 20; lf1 and lf2 = Lightning Fork dd659b3,
# v0.21.3-beta-blake2b.13; bitcoind-sha + lnd-sha = stock Core and lnd on a SHA-256 regtest), cloned
# read-only under run/. Scenarios: scripts/ln_rail/drive.py (S1-S9); report run/ln_rail_regtest.json.
#
# Regtest only: no mainnet LN node is contacted. Ports 34681, 34691, 34693 (loopback; AGP-048 has 34600-34699), compose project
# agp048ln, container CPU caps (scripts/ln_rail/compose.agp048.yml), host builds at nice 19 -j4. The
# lab's containers and volumes are removed on exit (LN_RAIL_KEEP=1 keeps them).
#
#   scripts/ln_rail_regtest.sh            build what is missing, run S1-S9, tear down
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
LF=$ROOT/run/lightning-fork
LAB_REV=a5cadc5604cd18a0b2f4901ef380cdf4d44ee75a
LF_REV=dd659b383333986d473e430e5d60d642d9e9524c
export COMPOSE_PROJECT_NAME=agp048ln
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ln_rail/compose.agp048.yml
export ACTIVATION_HEIGHT=20
R=$ROOT/run/ln-rail-$$
mkdir -p "$R"

[ -d "$LAB/.git" ] || git clone -q https://github.com/paulscode/lightning-fork-lab.git "$LAB"
git -C "$LAB" checkout -q "$LAB_REV"
[ -d "$LF/.git" ] || git clone -q https://github.com/paulscode/lightning-fork.git "$LF"
git -C "$LF" checkout -q "$LF_REV"
if [ ! -x "$LAB/bin/lnd" ] || [ ! -x "$LAB/bin/lncli" ]; then
  mkdir -p "$LAB/bin" "$ROOT/run/gocache"
  docker run --rm --cpus=4 -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOWORK=off -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
    -e GOFLAGS=-buildvcs=false -v "$LF:/src:ro" -v "$ROOT/run/gocache:/cache" -v "$LAB/bin:/out" -w /src golang:1.25.13 \
    sh -c 'T="autopilotrpc signrpc walletrpc chainrpc invoicesrpc watchtowerrpc peersrpc routerrpc offersrpc";
           go build -tags "$T" -o /out/lnd ./cmd/lnd && go build -tags "$T" -o /out/lncli ./cmd/lncli'
fi
docker image inspect knots-blake2b:final-zmq >/dev/null 2>&1 || \
  (cd "$LAB/knots" && DOCKER_BUILDKIT=0 docker build --cpuset-cpus=0-3 -t knots-blake2b:final-zmq .)
(cd "$LAB" && docker compose build -q lf1)

python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait 34681 34691 34693
nice -n 19 cargo build -q -j4 --release -p xbt-signer --bin xbt-signer -p xbt-wallet-mcp --bin xbt-wallet-mcp
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

cleanup() {
  pkill -f "$R/" 2>/dev/null || true
  if [ "${LN_RAIL_KEEP:-0}" != 1 ]; then
    (cd "$LAB" && docker compose --profile refuse --profile cln down -v >/dev/null 2>&1) || true
  fi
  cp "$R"/*.log "$ROOT/run/" 2>/dev/null || true
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

(cd "$LAB" && docker compose down -v >/dev/null 2>&1 || true)
(cd "$LAB" && docker compose up -d fees knots-b2b bitcoind-sha)
bash "$LAB/scripts/wait-chains.sh"
(cd "$LAB" && docker compose up -d lf1 lf2 lnd-sha)

LAB=$LAB OUT=$ROOT/run BIN=$BIN RUN=$R nice -n 19 python3 "$ROOT/scripts/ln_rail/drive.py"
