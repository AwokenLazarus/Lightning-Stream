#!/bin/bash
# Failure paths through the real binaries on regtest. Every other interop script here runs the
# happy path; this one breaks something on purpose (scripts/interop/failure_interop.py has the list)
# and reports, check by check, what the release binaries do at their shipped defaults:
#   A  an answer lost on a direct channel (the signer's pay rail and the library client)
#   B  a provider that stops answering, direct and behind a hub
#   C  one hostile Electrum server among honest ones (holds its answers, hides a transaction, sends
#      malformed numbers): the light wallet still refunds at expiry
#   D  SIGKILL and restart of the provider, the signer and the hub in the middle of a payment
#   E  a seller that refuses the funded open
# Each check prints PASS or FAIL and what it observed. A FAIL that the driver lists as a known open
# item (docs/LIMITS.md, "Open items") is printed as such and does not fail the run.
#
# Needs: the Python reference checkout for its node script and RPC helper (XBT402_B1, default
# ../b1 beside this checkout), a Knots 29.4.2 build (XBT_BIN: the directory of bitcoind and
# bitcoin-cli), and for C a patched electrs (XBT_ELECTRS; without one C is reported as not run).
# Ports: FAIL_PORT_BASE (default 26400) .. +99, all below the kernel's ephemeral range and checked
# free before anything starts. FAIL_ONLY="A1,C,D2" runs a subset; FAIL_KEEP=1 keeps the run directory
# (ledgers, configs) for a look afterwards. Starts no miner but its own
# generatetoaddress calls. The node and every process are stopped and the run directory removed on
# exit; the results and the log are copied to run/.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$(dirname "$ROOT")/b1}
PB=${FAIL_PORT_BASE:-26400}
R=${XBT_RS_RUN:-$ROOT/run}/failure-$$
export XBT402_B1=$B1
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node
export XBT402_RPCPORT=$((PB + 1)) XBT402_P2PPORT=$((PB + 2))
export XBT402_MATURITY_PAD=6800
PY=${XBT402_PYTHON:-$B1/.venv/bin/python}
[ -x "$PY" ] || PY=python3
export RS_BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release FAIL_PB=$PB FAIL_RUN=$R
ELECTRS_DEFAULT=$(dirname "$ROOT")/electrs-agp-024/src/target/release/electrs
export ELECTRS=${XBT_ELECTRS:-$ELECTRS_DEFAULT}
[ -f "$B1/scripts/node.sh" ] || { echo "no Python reference checkout at $B1 (set XBT402_B1)" >&2; exit 2; }
[ -x "$XBT_BIN/bitcoind" ] || { echo "no bitcoind in $XBT_BIN (set XBT_BIN)" >&2; exit 2; }
mkdir -p "$R"
cleanup() {
  pkill -f -- "$R/" 2>/dev/null || true
  "$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
  mkdir -p "$ROOT/run"
  cp "$R"/failure_interop_results.json "$R"/failure_interop.log "$ROOT/run/" 2>/dev/null || true
  [ -n "${FAIL_KEEP:-}" ] && { rm -rf "$R/node"; echo "kept: $R"; } || rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# every port this run binds, checked free first: a port someone else holds would be a false FAIL
python3 - "$PB" <<'EOF'
import socket, sys
pb, busy = int(sys.argv[1]), []
if pb + 99 >= int(open("/proc/sys/net/ipv4/ip_local_port_range").read().split()[0]):
    sys.exit(f"port base {pb}: {pb}..{pb + 99} reaches the kernel's ephemeral range")
for p in range(pb, pb + 100):
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # as the servers bind: a closed run's ports are free
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            busy.append(p)
if busy:
    sys.exit(f"ports in use: {busy} (set FAIL_PORT_BASE)")
EOF
nice -n 19 cargo build -q -j2 --release -p xbt402-interop --bins
nice -n 19 cargo build -q -j2 --release -p xbt402 --all-features --bin xbt402-hub
nice -n 19 cargo build -q -j2 --release -p xbt-signer --bin xbt-signer
nice -n 19 cargo build -q -j2 --release -p xbt-wallet-mcp --bin xbt-wallet-mcp
nice -n 19 cargo build -q -j2 --release -p xbt-electrum --features interop --bins
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
"$B1/scripts/node.sh" up
echo "== failure paths through the release binaries: $ROOT @ $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null) (binaries $RS_BIN), ports $PB+"
if "$PY" scripts/interop/failure_interop.py; then
  echo "failure_interop: OK (results: run/failure_interop_results.json)"
else
  echo "failure_interop: FAIL (log: run/failure_interop.log)"; exit 1
fi
