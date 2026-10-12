#!/bin/bash
# AGP-102 part D: checks through the real processes (Knots regtest node + release binaries).
# usage: scripts/agp102_checks.sh a [port base]
# a: xbt-signer, xbt-signer-payer, xbt402-rust-provider. Build them first (release).
# (Check b ran the hub. The hub was retired on 2026-10-11: payments between parties route over ordinary
# Lightning instead. Its code is in the git history, last at commit a548fb0.)
# RS_BIN: another directory of binaries (a control build); TAG: suffix of the run directory. Ports PB+1..PB+12, default 27900.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
which=${1:-}
[ "$which" = a ] || { echo "usage: $0 a [port base]" >&2; exit 2; }
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
esac
