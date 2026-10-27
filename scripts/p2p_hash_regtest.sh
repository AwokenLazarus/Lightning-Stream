#!/bin/bash
# p2p-hash on regtest with real tickets: the hashmaker publishes its hashrate listing to a stand-in
# Nostr relay, the hashtaker finds it, opens the link, and pays every finished slice through the
# wallet's signer as one paid request to the hashmaker's gateway, on the gateway's tickets. The
# checks and what each looks at: scripts/p2p_hash/regtest.py.
#
# Lab: the ticket lab's (scripts/ticket_e2e/compose.yml on lightning-fork-lab, three Lightning Fork
# nodes on one Knots BLAKE2b regtest), in its own compose project (p2phash) and on its own ports:
# P2P_HASH_PORT_BASE (default 19961) to BASE+9. P2P_HASH_LAB: a lightning-fork-lab checkout with
# its node binaries built (default run/lightning-fork-lab, cloned and built when missing). The
# lab's containers and volumes are removed on exit. About 10 minutes.
# Report: run/p2p_hash_regtest.json and run/p2p_hash_regtest.log.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
B=${P2P_HASH_PORT_BASE:-19961}
export TICKET_E2E_PORT_BASE=$B TICKET_E2E_PORT_RPC=$B
export LN_TICKET_PORT_LF1=$((B + 1)) LN_TICKET_PORT_LF2=$((B + 2)) LN_TICKET_PORT_LF3=$((B + 3))
export COMPOSE_PROJECT_NAME=p2phash
export ACTIVATION_HEIGHT=20
LAB=${P2P_HASH_LAB:-$ROOT/run/lightning-fork-lab}
if [ ! -x "$LAB/bin/lnd" ]; then
  # shellcheck source=scripts/ln_rail/lab.sh
  . "$ROOT/scripts/ln_rail/lab.sh"
fi
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ticket_e2e/compose.yml
R=
cleanup() {
  if [ -n "$R" ]; then pkill -f "$R/" 2>/dev/null || true; fi
  (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
  if [ -n "$R" ]; then
    mkdir -p "$ROOT/run/p2p_hash_regtest"
    cp "$R"/*.log "$R"/*.json "$ROOT/run/p2p_hash_regtest/" 2>/dev/null || true
    rm -rf "$R"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$ROOT/run"
# a short path: the signer's socket path must fit in sun_path (108 bytes)
R=$(mktemp -d "${TMPDIR:-/tmp}/p2ph-XXXXXX")

nice -n 19 cargo build -q -j4 --release --locked -p xbt-signer --bin xbt-signer -p xbt-wallet-mcp --bin xbt-wallet-mcp \
  -p xbt-gateway --bin xbt-gateway -p xbt-hashlink --bin xbt-hashlink
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

(cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
# shellcheck disable=SC2046 # the port list is meant to split
python3 "$ROOT/scripts/portcheck.py" wait $(seq "$B" $((B + 9)))
(cd "$LAB" && docker compose build -q lf1 && docker compose up -d fees knots-b2b)

export LAB RUN=$R OUT=$ROOT/run BIN
if nice -n 19 python3 "$ROOT/scripts/p2p_hash/regtest.py" 2>&1 | tee "$ROOT/run/p2p_hash_regtest.log"; then
  echo "p2p_hash_regtest: OK"
else
  echo "p2p_hash_regtest: FAIL (log: run/p2p_hash_regtest.log)" >&2
  exit 1
fi
