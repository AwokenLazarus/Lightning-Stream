#!/bin/bash
# AGP-109 on regtest: the hub beside a real Lightning Fork node, through the real binaries (xbt402-hub,
# and the Rust seller and buyer of route_interop.sh). The lab is the one scripts/ln_rail_regtest.sh uses
# (scripts/ln_rail/lab.sh: paulscode/lightning-fork-lab a5cadc5, Knots v29.4.1 BLAKE2b regtest, Lightning
# Fork cebc10fe, v0.21.3-beta-blake2b.17), with one chain node and one Lightning node, lf1.
# scripts/interop/hub_ln_link.py drives:
#   1. the macaroon rule: macaroons lf1 bakes (for the two calls, per call and per entity, as a file and as
#      pasted hex; with SendCoins added; the wallet rail's; readonly.macaroon; admin.macaroon), each given to
#      xbt402-hub with the mainnet rule on (XBT_HUB_LN_STRICT=1): only the first three give a link, and the
#      hub runs without one otherwise. And what the node itself allows the narrow macaroon: a new address
#      and a signed message, and "permission denied" for sending coins, balances, info, baking, channels.
#   2. one full cycle with a hub that holds 400,000 sat and has a capital of 300,000: its 402 carries lf1's
#      signed statement (the same signature `lncli signmessage` gives); buyers pay the hub named
#      <node id>@host:port, and one told another node id funds nothing; payouts above capital arrive in
#      lf1's on-chain wallet, two of them at one address, and the next address is asked for only once the
#      chain shows the first used; with lf1 stopped a buyer still pays and closes, its payout goes to the
#      address on file, the one after refills the hub's wallet, and after lf1 is started returns go to it
#      again; the hub is killed and started again and has the same link; the seller's close pays the hub's
#      wallet; GET /status reconciles to the sat at each stage.
# Ports (loopback, below the ephemeral range): the lab's node 17581 and lf1's REST 17591
# (HUB_LINK_NODE_PORT, HUB_LINK_LN_PORT), the hub and seller from LINK_PB (default 22600): +10, +11,
# +40..+47. Its own compose project (agp109ln), so it runs beside ln_rail_regtest.sh. Starts NO miners.
# The lab's containers and volumes and every process are removed on exit (HUB_LINK_KEEP=1 keeps the lab).
# Soak rules: container CPU caps, CPUQuota 200%, 4G, nice 19. Report: run/hub_ln_link_results.json.
set -euo pipefail
if command -v lazvault >/dev/null 2>&1; then lazvault hold check --project xbt-agentpay || exit 75; fi   # a heavy entry point: not during a host hold
cd "$(dirname "$0")/.."
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
export COMPOSE_PROJECT_NAME=agp109ln
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ln_rail/compose.hub_link.yml
export ACTIVATION_HEIGHT=20
R=${XBT_RS_RUN:-$ROOT/run}/hub-ln-link-$$
mkdir -p "$R"
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)

# the lab and the node binaries: cloned and built when missing
. "$ROOT/scripts/ln_rail/lab.sh"

cleanup() {
  pkill -f -- "$R/" 2>/dev/null || true
  if [ "${HUB_LINK_KEEP:-0}" != 1 ]; then
    (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
  fi
  mkdir -p "$ROOT/run"
  cp "$R"/hub_ln_link_results.json "$R"/hub_ln_link.log "$ROOT/run/" 2>/dev/null || true
  for f in "$R"/cycle/hub.log "$R"/cycle/buyer-*.log; do [ -f "$f" ] && cp "$f" "$ROOT/run/hub_ln_link.$(basename "$f")"; done
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# a lab an earlier HUB_LINK_KEEP=1 run left holds the ports and an old chain: it goes first
(cd "$LAB" && docker compose down -v >/dev/null 2>&1 || true)
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bins
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402 --all-features --bin xbt402-hub
(cd "$LAB" && docker compose up -d fees knots-b2b)
export LAB RS_BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release LINK_RUN=$R
if python3 scripts/interop/hub_ln_link.py; then echo "hub_ln_link: OK"; else echo "hub_ln_link: FAIL (log: run/hub_ln_link.log)"; exit 1; fi
