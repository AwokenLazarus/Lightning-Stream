#!/bin/bash
# AGP-102 part D: checks through the real processes (Knots regtest node + release binaries).
# usage: scripts/agp102_checks.sh a|b [port base]   (REVEAL=default with b: the hub at its default reveal_timeout, check C)
# a: xbt-signer, xbt-signer-payer, xbt402-rust-provider. b: xbt402-hub, xbt402-route-provider. Build them first (release).
# RS_BIN: another directory of binaries (a control build); TAG: suffix of the run directory. Ports PB+1..PB+12, default 27900.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
which=$1
PB=${2:-27900}
export XBT402_B1=$HOME/xbt-rnd/b1-agp-102
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export RUN=$ROOT/run/agp102_d_$which${TAG:-}
rm -rf "$RUN"; mkdir -p "$RUN"
export XBT402_MATURITY_PAD=6800
export XBT402_DATADIR=$RUN/node XBT402_RPCPORT=$((PB + 1)) XBT402_P2PPORT=$((PB + 2))
export RS_BIN=${RS_BIN:-$ROOT/target/release} PB PY=$HOME/xbt-rnd/b1/.venv/bin/python
cleanup() { "$XBT402_B1/scripts/node.sh" down >/dev/null 2>&1 || true; }
trap cleanup EXIT
"$XBT402_B1/scripts/node.sh" up
case $which in
  a) "$PY" scripts/interop/agp102_signer_funded.py ;;
  b) "$PY" scripts/interop/agp102_hub_lockauth.py ;;
esac
