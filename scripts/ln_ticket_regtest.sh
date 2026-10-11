#!/bin/bash
# Stream tickets on regtest: the measurements behind docs/TICKETS.md, repeatable from this tree.
# A ticket is a small Lightning payment locked to a hash whose secret only the buyer knows (a hold
# invoice on the seller's node); the buyer releases it by putting the secret in a paid request.
# No wallet, signer or seller code runs here: scripts/ln_ticket/drive.py plays both sides against
# the nodes' own REST interface, on four Lightning Fork nodes with default settings:
#
#     lf4 ---- lf1 ---- lf2 ---- lf3
#     far     buyer     hop     seller
#
# It prints PASS or FAIL for each check with what it saw: tickets ACCEPTED through the hop for hashes
# only the buyer knows; settle returns the buyer's secret; a fee on settled tickets only; tickets on
# one channel and over two hops; lock and per-request latencies; what each side's macaroon can and
# cannot do; the smallest final CLTV delta; 483 of 520 in flight; settle after a restart of each
# node and with the hop down; the seller's node cancelling 18 blocks before expiry; the seller's
# claim on chain when the hop stays down; a seller offline past expiry with 3 and with 100 tickets.
# Numbers the first lab run of this design reported are compared and the differences listed (NOTE lines).
#
# Lab: the one scripts/ln_rail_regtest.sh uses (scripts/ln_rail/lab.sh: paulscode/lightning-fork-lab
# a5cadc5, Knots v29.4.1 BLAKE2b regtest, Lightning Fork cebc10fe, v0.21.3-beta-blake2b.17), cloned
# and built under run/ when missing. Regtest only: no mainnet node is contacted and no miner starts.
# Ports (loopback, below the kernel's ephemeral range): 17791-17794, the four nodes' REST
# (LN_TICKET_PORT_LF1..LF4). Its own compose project (lnticket), so it runs beside the other regtest
# scripts. Each container is capped at 2 CPUs. The lab's containers and volumes are removed on exit
# (LN_TICKET_KEEP=1 keeps them, for `scripts/ln_ticket/drive.py --no-setup <check>`; see that file's
# header for the environment it needs). Takes about 20 minutes.
# Report: run/ln_ticket_regtest.json and run/ln_ticket_regtest.log.
#
#   scripts/ln_ticket_regtest.sh              every check
#   scripts/ln_ticket_regtest.sh fees slots   only these (names: scripts/ln_ticket/drive.py)
set -euo pipefail
if command -v lazvault >/dev/null 2>&1; then lazvault hold check --project xbt-agentpay || exit 75; fi # a heavy entry point: not during a host hold
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
export COMPOSE_PROJECT_NAME=lnticket
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ln_ticket/compose.yml
export ACTIVATION_HEIGHT=20
mkdir -p "$ROOT/run"
R=$(mktemp -d "$ROOT/run/ln-ticket-XXXXXX")

cleanup() {
  if [ "${LN_TICKET_KEEP:-0}" != 1 ]; then
    # unchecked: on the way out there is nobody to tell, and the next run removes what is left
    (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
  fi
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# the lab and the node binaries: cloned and built when missing
# shellcheck source=scripts/ln_rail/lab.sh
. "$ROOT/scripts/ln_rail/lab.sh"

# a lab an earlier LN_TICKET_KEEP=1 run left holds the ports and an old chain: it goes first
(cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
python3 "$ROOT/scripts/portcheck.py" wait "${LN_TICKET_PORT_LF1:-17791}" "${LN_TICKET_PORT_LF2:-17792}" "${LN_TICKET_PORT_LF3:-17793}" "${LN_TICKET_PORT_LF4:-17794}"
(cd "$LAB" && docker compose up -d fees knots-b2b)

export LAB RUN=$R OUT=$ROOT/run
if nice -n 19 python3 "$ROOT/scripts/ln_ticket/drive.py" "$@" 2>&1 | tee "$ROOT/run/ln_ticket_regtest.log"; then
  echo "ln_ticket: OK"
else
  echo "ln_ticket: FAIL (log: run/ln_ticket_regtest.log)" >&2
  exit 1
fi
