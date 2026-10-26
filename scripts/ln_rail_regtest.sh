#!/bin/bash
# AGP-048 on regtest: rail=ln. The Rust signer and MCP pay XBT Lightning invoices through a Lightning
# Fork node under B2's policy, with the AGP-047 guards (bit 512, the LN node's chain identity, no
# taproot or non-unified or pre-split channels). Lab: paulscode/lightning-fork-lab a5cadc5 (Knots
# v29.4.1 BLAKE2b regtest, activation at 20; lf1, lf2 and lf3 = Lightning Fork cebc10fe,
# v0.21.3-beta-blake2b.17 (AGP-083; dd659b3, .13, until then); bitcoind-sha + lnd-sha = stock Core and
# lnd on a SHA-256 regtest), cloned read-only under run/. Scenarios: scripts/ln_rail/drive.py (S1-S9 AGP-048, S10-S15 AGP-049: funding
# proven from the transaction, the exposure cap, the macaroon IP caveat, watchtowers, the rate limit,
# HTLC CLTV locks; S16-S18 AGP-066: lookup by payment hash, the macaroon allowlist, plain http only on
# loopback; S19-S24 AGP-083: BOLT 12 offers on the real node: lf1, which holds a taproot and a pre-split
# channel, pays none; lf3, whose one channel is proven, pays lf2's offers, and a failed pay is retried
# from the stored invoice); report run/ln_rail_regtest.json.
#
# Regtest only: no mainnet LN node is contacted. Ports 17481, 17491, 17493, 17495 (loopback; below the
# kernel's ephemeral range since AGP-083, 34781/34791/34793 before), compose project agp049ln, container CPU caps (scripts/ln_rail/compose.ln_rail.yml),
# host builds at nice 19 -j4. The lab's containers and volumes are removed on exit (LN_RAIL_KEEP=1
# keeps them). LN_RAIL_GOCACHE: a Go build cache to reuse (default run/gocache).
#
#   scripts/ln_rail_regtest.sh            build what is missing, run S1-S24, tear down
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
export COMPOSE_PROJECT_NAME=agp049ln
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ln_rail/compose.ln_rail.yml
export ACTIVATION_HEIGHT=20
# LN_RAIL_SCRATCH: where the scratch directory goes (default run/); the signers' sockets are in it,
# and a socket path is at most 107 bytes, so a checkout with a long path names a shorter place here
R=${LN_RAIL_SCRATCH:-$ROOT/run}/ln-rail-$$
mkdir -p "$R"

# the lab and the node binaries: cloned and built when missing (scripts/ln_rail/lab.sh)
. "$ROOT/scripts/ln_rail/lab.sh"

# a lab an earlier LN_RAIL_KEEP=1 run left holds the ports: it goes before they are checked
(cd "$LAB" && docker compose down -v >/dev/null 2>&1 || true)
python3 "$ROOT/scripts/portcheck.py" wait 17481 17491 17493 17495
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

(cd "$LAB" && docker compose up -d fees knots-b2b bitcoind-sha)
bash "$LAB/scripts/wait-chains.sh"
(cd "$LAB" && docker compose up -d lf1 lf2 lf3 lnd-sha)

LAB=$LAB OUT=$ROOT/run BIN=$BIN RUN=$R nice -n 19 python3 "$ROOT/scripts/ln_rail/drive.py"
