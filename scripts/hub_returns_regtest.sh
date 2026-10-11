#!/bin/bash
# AGP-104 on regtest, through the real hub binary: every coin the hub gets back reaches its wallet, and
# its status adds up. scripts/interop/hub_returns.py drives, on a private Knots 29.4.2 node (B1's
# scripts/node.sh flags: BLAKE2b from block 101):
#   1. the full cycle, once with the Rust hub (xbt402-hub) and once with the Python one (B1): a hub wallet
#      with a 1,000,000 sat deposit, two Rust sellers, one Rust buyer. Fund, route, buyer close, the hub
#      stopped and its operator tool asking the paid seller to close, the hub started again, the unpaid
#      seller's ch2 refunded at its expiry. Then: nothing unspent on any per-channel key (scantxoutset),
#      the wallet holds the deposit plus what came back less what the chain cost, and (Rust) GET /status
#      reconciles to the sat at each stage and GET / is the page;
#   2. the Rust hub's start-up checks: a configured network that is not the node's, a node on the SHA-256
#      chain (a second node without the BLAKE2b activation), a funding with no fee rate and no estimate,
#      and /readyz while the wallet is not loaded.
# Ports (below the ephemeral range): base XBT_RS_RETURNS_PORT_BASE (default 22400): node +1/+2, the
# SHA-256 node +3/+4, hubs and sellers +10..+39. Starts NO miners. The nodes and every process are
# stopped and wiped on exit. Soak rules: CPUQuota 200%, 4G, nice 19.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1}
PB=${XBT_RS_RETURNS_PORT_BASE:-22400}
R=${XBT_RS_RUN:-$ROOT/run}/returns-$$
export XBT402_B1=$B1
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node
export XBT402_RPCPORT=$((PB + 1)) XBT402_P2PPORT=$((PB + 2))
export XBT402_MATURITY_PAD=6800
export PY=${XBT402_PYTHON:-$HOME/xbt-rnd/b1/.venv/bin/python}
[ -x "$PY" ] || PY=python3
export RS_BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release RETURNS_PB=$PB RETURNS_RUN=$R
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
mkdir -p "$R"
cleanup() {
  pkill -f -- "$R/" 2>/dev/null || true
  "$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
  mkdir -p "$ROOT/run"
  cp "$R"/hub_returns_results.json "$R"/hub_returns.log "$ROOT/run/" 2>/dev/null || true
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

python3 "$ROOT/scripts/portcheck.py" wait $(seq $((PB + 1)) $((PB + 4))) $(seq $((PB + 10)) $((PB + 39)))
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bins
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402 --all-features --bin xbt402-hub
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
"$B1/scripts/node.sh" up
if "$PY" scripts/interop/hub_returns.py; then echo "hub_returns: OK"; else echo "hub_returns: FAIL (log: run/hub_returns.log)"; exit 1; fi
