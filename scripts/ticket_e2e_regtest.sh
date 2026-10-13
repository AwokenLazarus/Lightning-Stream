#!/bin/bash
# The wallet pays a gateway, end to end on regtest: an agent's ordinary `xbt402_pay` call, through
# the shipped binaries, to a URL behind the seller gateway, paid with stream tickets through a
# routing hop. docs/TICKETS.md is the wire.
#
#     agent ---- xbt-wallet-mcp ---- xbt-signer ==== lf1 ---- lf2 ---- lf3 ==== xbt-gateway ---- file server
#     (the driver)   (MCP, stdio)    (the wallet)   buyer     hop     seller                 (python3 -m http.server)
#
# The file server is stock and unchanged; the signer, the MCP server and the gateway are the release
# binaries of this tree, with the wallet's policy and the gateway's caps as they ship (2 tickets a
# session, 15 held in all); the nodes are Lightning Fork nodes, the hop and the seller started with
# --default-remote-max-htlcs=30, so that the buyer's channel and the seller's inbound channel carry
# 30 pending payments each: the slot count of a channel with a Core Lightning node at its default.
# A stand-in for that number only: no Core Lightning node is in this lab. It prints PASS or FAIL
# for each check with what it saw:
#   page     a small priced page; a first request, the pool of 2 tickets locked through the hop
#            included, in 1 s (median of 5 new sessions)
#   latency  what a paid request adds over an unpaid one through the same wallet (medians of 200)
#   stream   a 100 MB file priced per byte, whole; again and stopped half way by the call's
#            max_sats; again and stopped by the agent; the unused tickets cancelled within 5 s; what
#            the buyer's node paid, what the seller's node received, what the wallet booked and what
#            the receipts say, to the millisat
#   slots    half of the buyer's channel taken by payments of others: the wallet holds nothing and
#            pays with prepaid tickets, one at a time; a seller at its cap of 15 says slots_short and
#            is paid with a prepaid ticket; a lock that finds no slot on the way: the session holds
#            less and waits
#   liar     a seller that lies, played by a proxy in front of a second gateway: another node id,
#            tickets for another payee, terms that change, inflated metering signed by the seller's
#            own key, no receipt, a receipt for another request, an answer that stops in the
#            middle: at most one ticket each, booked exactly
#   kill     the signer, the MCP server, the gateway, the buyer's node and the seller's node each
#            killed with a pool locked and again in the middle of an answer, then started again:
#            nothing the seller took that the wallet has not booked, nothing paid twice, and the
#            next call pays or says why not
# The names and what each checks: scripts/ticket_e2e/drive.py.
#
# Lab: the one scripts/ln_rail_regtest.sh uses (scripts/ln_rail/lab.sh: paulscode/lightning-fork-lab
# a5cadc5, Knots v29.4.1 BLAKE2b regtest, Lightning Fork cebc10fe, v0.21.3-beta-blake2b.17), cloned
# and built under run/ when missing. Regtest only: no mainnet node is contacted and no miner starts.
# Ports (loopback, below the kernel's ephemeral range): TICKET_E2E_PORT_BASE (default 17961) to
# BASE+7: the chain node's RPC, the three nodes' REST, the gateway (BASE+4), the file server
# (BASE+5), the second gateway (BASE+6) and the lying proxy in front of it (BASE+7). Its own compose
# project (tickete2e), so it runs beside the other regtest scripts. Each container is capped at 2
# CPUs; host builds run at nice 19 with -j4. The lab's containers and volumes are removed on exit
# (TICKET_E2E_KEEP=1 keeps them and the scratch directory). About 25 minutes.
# Report: run/ticket_e2e_regtest.json and run/ticket_e2e_regtest.log.
#
#   scripts/ticket_e2e_regtest.sh               every check
#   scripts/ticket_e2e_regtest.sh page stream   only these
set -euo pipefail
if command -v lazvault >/dev/null 2>&1; then lazvault hold check --project xbt-agentpay || exit 75; fi # a heavy entry point: not during a host hold
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
B=${TICKET_E2E_PORT_BASE:-17961}
export TICKET_E2E_PORT_BASE=$B TICKET_E2E_PORT_RPC=$B
export LN_TICKET_PORT_LF1=$((B + 1)) LN_TICKET_PORT_LF2=$((B + 2)) LN_TICKET_PORT_LF3=$((B + 3))
export COMPOSE_PROJECT_NAME=tickete2e
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ticket_e2e/compose.yml
export ACTIVATION_HEIGHT=20
R=

cleanup() {
  if [ -n "$R" ]; then pkill -f "$R/" 2>/dev/null || true; fi
  if [ "${TICKET_E2E_KEEP:-0}" != 1 ]; then
    if [ -d "$LAB" ]; then
      # unchecked: on the way out there is nobody to tell, and the next run removes what is left
      (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
    fi
    if [ -n "$R" ]; then
      cp "$R"/*.log "$ROOT/run/" 2>/dev/null || true
      rm -rf "$R"
    fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$ROOT/run"
R=$(mktemp -d "$ROOT/run/ticket-e2e-XXXXXX")

nice -n 19 cargo build -q -j4 --release --offline -p xbt-signer --bin xbt-signer -p xbt-wallet-mcp --bin xbt-wallet-mcp -p xbt-gateway --bin xbt-gateway
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

# the lab and the node binaries: cloned and built when missing
# shellcheck source=scripts/ln_rail/lab.sh
. "$ROOT/scripts/ln_rail/lab.sh"

# a lab an earlier TICKET_E2E_KEEP=1 run left holds the ports and an old chain: it goes first
(cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
# shellcheck disable=SC2046 # the port list is meant to split
python3 "$ROOT/scripts/portcheck.py" wait $(seq "$B" $((B + 7)))
(cd "$LAB" && docker compose up -d fees knots-b2b)

export LAB RUN=$R OUT=$ROOT/run BIN
if nice -n 19 python3 "$ROOT/scripts/ticket_e2e/drive.py" "$@" 2>&1 | tee "$ROOT/run/ticket_e2e_regtest.log"; then
  echo "ticket_e2e: OK"
else
  echo "ticket_e2e: FAIL (log: run/ticket_e2e_regtest.log)" >&2
  exit 1
fi
