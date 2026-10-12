#!/bin/bash
# The ticket book on regtest: the wallet's signer (the real binary, crates/xbt-signer) buys with
# stream tickets from stand-in sellers, through real Lightning Fork nodes. docs/TICKETS.md is the
# wire; scripts/ticket_book/drive.py plays the agent (it calls the signer's socket and speaks HTTP
# to the seller) and the sellers (an HTTP stand-in in front of each seller's node, honest or lying).
#
#     lf1 ---- lf2 ---- s01 ... s20
#    buyer     hop      sellers
#
# It prints PASS or FAIL for each check with what it saw:
#   one seller through the hop: 8 tickets locked, 5 released with five paid requests, stop: 5
#     settled, 3 cancelled, the signer's book and the buyer's node agree, the routing fees booked;
#   a seller that lies (another payee, another amount, a longer life, a hash that is not the
#     buyer's, replayed invoices, terms above the owner's bounds): nothing is paid;
#   the book against the node after a kill of the signer, a restart of the buyer's node, a seller
#     that neither settles nor cancels until its tickets expire, a restore of the wallet's files
#     from an older copy;
#   20 sellers the owner has not named, 2 tickets each, under one task's budget;
#   the wallet's macaroon is the Lightning rail's four permissions; the MCP's ticket tools.
#
# Lab: the one scripts/ln_rail_regtest.sh uses (scripts/ln_rail/lab.sh: paulscode/lightning-fork-lab
# a5cadc5, Knots v29.4.1 BLAKE2b regtest, Lightning Fork cebc10fe, v0.21.3-beta-blake2b.17), cloned
# and built under run/ when missing. Regtest only: no mainnet node is contacted and no miner starts.
# Ports (loopback, below the kernel's ephemeral range): TICKET_BOOK_PORT_BASE (default 17911) to
# BASE+40: the chain node's RPC, the nodes' REST (scripts/ticket_book/compose.py) and the stand-in
# seller (BASE+40). Its own compose project (ticketbook), so it runs beside the other regtest
# scripts. Each container is capped at 1 or 2 CPUs; host builds run at nice 19 with -j4. The lab's
# containers and volumes are removed on exit (TICKET_BOOK_KEEP=1 keeps them). About 15 minutes.
# Report: run/ticket_book_regtest.json and run/ticket_book_regtest.log.
#
#   scripts/ticket_book_regtest.sh              every check
#   TICKET_BOOK_SELLERS=4 scripts/ticket_book_regtest.sh    fewer seller nodes (the last check then uses 4)
set -euo pipefail
if command -v lazvault >/dev/null 2>&1; then lazvault hold check --project xbt-agentpay || exit 75; fi # a heavy entry point: not during a host hold
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
export TICKET_BOOK_PORT_BASE=${TICKET_BOOK_PORT_BASE:-17911}
export TICKET_BOOK_SELLERS=${TICKET_BOOK_SELLERS:-20}
export COMPOSE_PROJECT_NAME=ticketbook
export ACTIVATION_HEIGHT=20
R=

cleanup() {
  if [ -n "$R" ]; then pkill -f "$R/" 2>/dev/null || true; fi
  if [ "${TICKET_BOOK_KEEP:-0}" != 1 ] && [ -d "$LAB" ] && [ -n "${COMPOSE_FILE:-}" ]; then
    # unchecked: on the way out there is nobody to tell, and the next run removes what is left
    (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
  fi
  if [ -n "$R" ]; then
    cp "$R"/*.log "$ROOT/run/" 2>/dev/null || true
    rm -rf "$R"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$ROOT/run"
R=$(mktemp -d "$ROOT/run/ticket-book-XXXXXX")
python3 "$ROOT/scripts/ticket_book/compose.py" > "$R/compose.yml"
export COMPOSE_FILE=$LAB/docker-compose.yml:$R/compose.yml

# the lab and the node binaries: cloned and built when missing
# shellcheck source=scripts/ln_rail/lab.sh
. "$ROOT/scripts/ln_rail/lab.sh"

# a lab an earlier TICKET_BOOK_KEEP=1 run left holds the ports and an old chain: it goes first
(cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
B=$TICKET_BOOK_PORT_BASE
# shellcheck disable=SC2046 # the port list is meant to split
python3 "$ROOT/scripts/portcheck.py" wait "$B" $((B + 1)) $((B + 2)) $((B + 40)) $(seq $((B + 11)) $((B + 10 + TICKET_BOOK_SELLERS)))
nice -n 19 cargo build -q -j4 --release --offline -p xbt-signer --bin xbt-signer -p xbt-wallet-mcp --bin xbt-wallet-mcp
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release
(cd "$LAB" && docker compose up -d fees knots-b2b)

export LAB RUN=$R OUT=$ROOT/run BIN
export LN_TICKET_PORT_LF1=$((B + 1)) LN_TICKET_PORT_LF2=$((B + 2))
if nice -n 19 python3 "$ROOT/scripts/ticket_book/drive.py" "$@" 2>&1 | tee "$ROOT/run/ticket_book_regtest.log"; then
  echo "ticket_book: OK"
else
  echo "ticket_book: FAIL (log: run/ticket_book_regtest.log)" >&2
  exit 1
fi
