#!/bin/bash
# The seller gateway on regtest: the shipped binary (target/release/xbt-gateway) beside the
# seller's Lightning Fork node, an unchanged stock HTTP file server behind it (python3 -m
# http.server), and a test buyer that speaks the wire draft (docs/TICKETS.md) through a routing hop:
#
#     lf1 ---- lf2 ---- lf3 ==== xbt-gateway ---- file server
#     buyer    hop     seller
#
# The gateway runs with its shipped ticket terms and caps: 2 tickets a session, 15 held for all
# sessions together, held tickets and prepaid ones. The seller's node is started with
# --default-remote-max-htlcs=30, so its inbound channel carries 30 pending payments: the slot count
# of a channel with a Core Lightning node at its default. A stand-in for that number only: no Core
# Lightning node is in this lab.
#
# It prints PASS or FAIL for each check with what it saw: the 402's terms; what the gateway's
# macaroons cannot do, a wider one refused on mainnet, and a config with held tickets below 546 sat
# refused; a 100 MB file priced per byte, fetched with tickets released as it arrives and stopped
# half way; a 10 MB file end to end; what a paid request adds over an unpaid one; the hostile buyer
# (a secret for an unpaid ticket, replays, another buyer's secret, 2,000 lock requests of which 15
# tickets are issued and the rest told slots_short, tickets locked and never released); the
# 24-block margin; prepaid tickets, bought while the held cap is full; the gateway reading its
# node's channels with a third macaroon and holding nothing while a channel is half full; the file
# server stopped; the gateway restarted and the seller's node restarted with tickets locked. The
# names and what each checks: scripts/gateway/drive.py.
#
# Lab: the one scripts/ln_rail_regtest.sh uses (scripts/ln_rail/lab.sh), cloned and built under run/
# when missing. Regtest only: no mainnet node is contacted and no miner starts.
# Ports (loopback, below the kernel's ephemeral range): 17831-17833, the three nodes' REST
# (GATEWAY_PORT_LF1..LF3); 17834, the gateway (GATEWAY_PORT); 17835, the file server
# (GATEWAY_UPSTREAM_PORT). Its own compose project (lngateway), so it runs beside the other regtest
# scripts. Each container is capped at 2 CPUs. The lab's containers and volumes are removed on exit
# (GATEWAY_KEEP=1 keeps them and the scratch directory, for `scripts/gateway/drive.py --no-setup
# <check>`; see that file's header for the environment it needs). Takes about 12 minutes.
# Report: run/gateway_regtest.json and run/gateway_regtest.log.
#
#   scripts/gateway_regtest.sh               every check
#   scripts/gateway_regtest.sh fetch flood   only these
set -euo pipefail
if command -v lazvault >/dev/null 2>&1; then lazvault hold check --project xbt-agentpay || exit 75; fi # a heavy entry point: not during a host hold
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
export COMPOSE_PROJECT_NAME=lngateway
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/gateway/compose.yml
export ACTIVATION_HEIGHT=20
export LN_TICKET_PORT_LF1=${GATEWAY_PORT_LF1:-17831} LN_TICKET_PORT_LF2=${GATEWAY_PORT_LF2:-17832} LN_TICKET_PORT_LF3=${GATEWAY_PORT_LF3:-17833}
export GATEWAY_PORT=${GATEWAY_PORT:-17834} GATEWAY_UPSTREAM_PORT=${GATEWAY_UPSTREAM_PORT:-17835}
R=

cleanup() {
  if [ "${GATEWAY_KEEP:-0}" != 1 ]; then
    if [ -d "$LAB" ]; then
      # unchecked: on the way out there is nobody to tell, and the next run removes what is left
      (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
    fi
    if [ -n "$R" ]; then rm -rf "$R"; fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$ROOT/run"
R=$(mktemp -d "$ROOT/run/gateway-XXXXXX")

nice -n 19 cargo build -q --release -j4 -p xbt-gateway --offline

# the lab and the node binaries: cloned and built when missing
# shellcheck source=scripts/ln_rail/lab.sh
. "$ROOT/scripts/ln_rail/lab.sh"

# a lab an earlier GATEWAY_KEEP=1 run left holds the ports and an old chain: it goes first
(cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
python3 "$ROOT/scripts/portcheck.py" wait "$LN_TICKET_PORT_LF1" "$LN_TICKET_PORT_LF2" "$LN_TICKET_PORT_LF3" "$GATEWAY_PORT" "$GATEWAY_UPSTREAM_PORT"
(cd "$LAB" && docker compose up -d fees knots-b2b)

export LAB RUN=$R OUT=$ROOT/run GATEWAY_BIN=$ROOT/target/release/xbt-gateway
if nice -n 19 python3 "$ROOT/scripts/gateway/drive.py" "$@" 2>&1 | tee "$ROOT/run/gateway_regtest.log"; then
  echo "gateway: OK"
else
  echo "gateway: FAIL (log: run/gateway_regtest.log)" >&2
  exit 1
fi
