#!/bin/bash
# The lottery, end to end on regtest: an agent's ordinary `xbt402_pay` call, through the shipped
# binaries, to URLs behind seller gateways, paid by draws through a routing hop. docs/TICKETS.md,
# section 9, is the wire.
#
#     agent ---- xbt-wallet-mcp ---- xbt-signer ==== lf1 ---- lf2 ---- lf3 ==== xbt-gateway x 102 ---- file server
#     (the driver)   (MCP, stdio)    (the wallet)   buyer     hop     seller    (one a seller each)    (python3 -m http.server)
#
# The file server is stock and unchanged; the signer, the MCP server and the gateways are the
# release binaries of this tree, with the wallet's lottery policy and the gateway's lottery terms
# as they ship (wins of 64 sat, a window of 8 pieces, a grace of 10 s and 64 pieces, 2 unpaid
# wins); the nodes are Lightning Fork nodes, the hop and the seller started with
# --default-remote-max-htlcs=30, so that the buyer's channel and the seller's inbound channel carry
# 30 pending payments each: the slot count of a channel with a Core Lightning node at its default.
# A stand-in for that number only: no Core Lightning node is in this lab. The 100 sellers of the
# swarm are 100 gateways beside the one seller node: the buyer's channel, the hop and the seller's
# inbound channel carry what 100 sellers' wins would, and the seller side is one node's worth of
# work. It prints PASS or FAIL for each check with what it saw:
#   terms    the 402 lists the lottery entry; the MCP tool says what a call paid by draws can cause
#   file     a 100 MB file at a quarter of a sat a piece, bought by draws, five times: whole; what
#            the buyer's node paid is the wins booked, to the millisat, inside the luck cap; nothing
#            pending on the buyer's channel except while a win is in flight
#   page     a page priced per request, 200 times; what a draw adds to a call
#   swarm    20 sellers, then 100, paid at once from the one 30-slot channel: no payment fails, at
#            most 8 at once, and an ordinary payment over that channel succeeds meanwhile
#   cheat    a buyer that never pays a win, and one that sends no values: what each is served before
#            it is cut off (measured), with the draw worked out by a second implementation
#   liar     a seller that claims a win for a draw that lost, or sends an invoice for another payee,
#            for another amount, or two invoices for one win: paid nothing for the lie
#   kill     the signer, the gateway, the buyer's node and the seller's node each killed between two
#            calls and in the middle of a download with wins being paid: no win paid twice, none
#            booked and not paid or paid and not booked, and the next call is served
# The names and what each checks: scripts/lottery/drive.py.
#
# Lab: the one scripts/ln_rail_regtest.sh uses (scripts/ln_rail/lab.sh: paulscode/lightning-fork-lab
# a5cadc5, Knots v29.4.1 BLAKE2b regtest, Lightning Fork cebc10fe, v0.21.3-beta-blake2b.17), cloned
# and built under run/ when missing, with the node overlay of scripts/ticket_e2e/compose.yml.
# Regtest only: no mainnet node is contacted and no miner starts.
# Ports (loopback, below the kernel's ephemeral range): LOTTERY_PORT_BASE (default 18100) to BASE+7
# (the chain node's RPC, the three nodes' REST, the gateway, the file server, the second gateway
# and the lying proxy in front of it) and BASE+10 to BASE+9+LOTTERY_SELLERS (the swarm's gateways,
# 100 by default). Its own compose project (lotterye2e), so it runs beside the other regtest
# scripts. Each container is capped at 2 CPUs; host builds run at nice 19 with -j4. The lab's
# containers and volumes are removed on exit (LOTTERY_KEEP=1 keeps them and the scratch
# directory). About 30 minutes.
# Report: run/lottery_regtest.json and run/lottery_regtest.log.
#
#   scripts/lottery_regtest.sh              every check
#   scripts/lottery_regtest.sh file swarm   only these
set -euo pipefail
if command -v lazvault >/dev/null 2>&1; then lazvault hold check --project xbt-agentpay || exit 75; fi # a heavy entry point: not during a host hold
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
B=${LOTTERY_PORT_BASE:-18100}
export LOTTERY_SELLERS=${LOTTERY_SELLERS:-100}
export TICKET_E2E_PORT_BASE=$B TICKET_E2E_PORT_RPC=$B
export LN_TICKET_PORT_LF1=$((B + 1)) LN_TICKET_PORT_LF2=$((B + 2)) LN_TICKET_PORT_LF3=$((B + 3))
export COMPOSE_PROJECT_NAME=lotterye2e
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ticket_e2e/compose.yml
export ACTIVATION_HEIGHT=20
R=

cleanup() {
  if [ -n "$R" ]; then pkill -f "$R/" 2>/dev/null || true; fi
  if [ "${LOTTERY_KEEP:-0}" != 1 ]; then
    if [ -d "$LAB" ]; then
      # unchecked: on the way out there is nobody to tell, and the next run removes what is left
      (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
    fi
    if [ -n "$R" ]; then
      for f in signer mcp gateway gateway2 upstream; do cp "$R/$f.log" "$ROOT/run/lottery-$f.log" 2>/dev/null || true; done
      rm -rf "$R"
    fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$ROOT/run"
R=$(mktemp -d "$ROOT/run/lottery-XXXXXX")

python3 "$ROOT/scripts/lottery/draw.py" check
nice -n 19 cargo build -q -j4 --release --offline -p xbt-signer --bin xbt-signer -p xbt-wallet-mcp --bin xbt-wallet-mcp -p xbt-gateway --bin xbt-gateway
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

# the lab and the node binaries: cloned and built when missing
# shellcheck source=scripts/ln_rail/lab.sh
. "$ROOT/scripts/ln_rail/lab.sh"

# a lab an earlier LOTTERY_KEEP=1 run left holds the ports and an old chain: it goes first
(cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
# shellcheck disable=SC2046 # the port list is meant to split
python3 "$ROOT/scripts/portcheck.py" wait $(seq "$B" $((B + 7))) $(seq $((B + 10)) $((B + 9 + LOTTERY_SELLERS)))
(cd "$LAB" && docker compose up -d fees knots-b2b)

export LAB RUN=$R OUT=$ROOT/run BIN
if nice -n 19 python3 "$ROOT/scripts/lottery/drive.py" "$@" 2>&1 | tee "$ROOT/run/lottery_regtest.log"; then
  echo "lottery: OK"
else
  echo "lottery: FAIL (log: run/lottery_regtest.log)" >&2
  exit 1
fi
