#!/bin/bash
# The demo: a film behind the gateway, paid piece by piece as it plays; a swarm paid by lottery.
# End to end on regtest, with the shipped binaries. docs/DEMO.md is the guide for a node runner.
#
#     player ---- payproxy ---- xbt-wallet-mcp ---- xbt-signer ==== lf1 ---- lf2 ---- lf3 ==== xbt-gateway ---- Jellyfin
#     (ffmpeg, and  (scripts/demo/  (MCP, stdio)    (the wallet)   buyer     hop     seller    (the film)        (stock)
#      a clock)      payproxy.py)                                                     |
#                                                                                     +---- lf4 ==== xbt-gateway ---- the same Jellyfin
#                                                                                     +==== xbt-gateway x 20 ---- a file server
#
# The seller's side is what a node runner would set up: a stock Jellyfin (its official image,
# unchanged, in a container of its own, with a library of one freely licensed film and a user
# without admin rights), and xbt-gateway beside a Lightning node with one priced route: the film's
# paths, by the byte. The buyer's side is the wallet of this tree and a small paying proxy
# (scripts/demo/payproxy.py) that an ordinary player reads from. It prints PASS or FAIL for each
# check with what it saw, and a readout while the film plays:
#   film    through one routing hop, paid with stream tickets: the first frame; a stretch in real
#           time and what it costs a minute; a pause, a seek, a dropped connection, a restart of
#           the seller's gateway, a stop and what comes back; the whole film; the counts of money
#   far     the same film from a seller two routing hops away
#   agent   an agent with only the wallet's MCP tools buys the first part of the film's file
#   swarm   the film's file in pieces of 256 KiB from 20 gateways at once, paid by draws from the
#           buyer's one 30-slot channel
# The names and what each checks: scripts/demo/drive.py.
#
# The film: Big Buck Bunny, (c) 2008 Blender Foundation, www.bigbuckbunny.org, licensed under
# Creative Commons Attribution 3.0 (276 MB, 10:34, 1080p, 3.5 Mbit/s). It is fetched once from a
# mirror of the Blender Foundation's files into run/demo-cache and checked against its SHA-256; it
# is not in this repository. DEMO_FILM=/path/to/a.mp4 uses a file of yours; DEMO_FILM=generate, or
# no mirror answering, makes a test pattern with ffmpeg.
#
# The service: DEMO_SERVICE=jellyfin (the default) starts the image DEMO_JELLYFIN_IMAGE
# (jellyfin/jellyfin:10.11.0) and sets it up over its own API. DEMO_SERVICE=files uses a stock
# `python3 -m http.server` and needs no image. For a Jellyfin that already runs, set
# DEMO_JELLYFIN_URL (http://host:port), DEMO_JELLYFIN_KEY (a key of a user that may play the film)
# and DEMO_JELLYFIN_ITEM (the film's item id): nothing on that server is changed.
#
# Needs: docker with compose, python3, ffmpeg and ffprobe, a Rust toolchain. Lab: the one
# scripts/ln_rail_regtest.sh uses (scripts/ln_rail/lab.sh: paulscode/lightning-fork-lab a5cadc5,
# Knots v29.4.1 BLAKE2b regtest, Lightning Fork cebc10fe, v0.21.3-beta-blake2b.17), cloned and
# built under run/ when missing, with the node overlays of scripts/ticket_e2e/compose.yml and
# scripts/demo/compose.yml. Regtest only: no mainnet node is contacted, no miner starts, and
# nothing listens on an address other than 127.0.0.1.
# Ports (loopback, below the kernel's ephemeral range): DEMO_PORT_BASE (default 18300) to BASE+30:
# the chain node's RPC, the REST of lf1 to lf3, the film's gateway (+4), the file server (+5), the
# gateway two hops away (+6), the relay buyers reach the film's gateway through (+7), lf4's REST
# (+8), Jellyfin (+9), the paying proxy (+10), the swarm's 20 gateways (+11 to +30). Its own
# compose project (demofilm), so it runs beside the other regtest scripts. Each container is capped
# at 2 CPUs; host builds run at nice 19 with -j4. The containers and volumes are removed on exit
# (DEMO_KEEP=1 keeps them and the scratch directory). About 7 minutes once the lab is built.
# Report: run/demo_film.json, run/demo_film.log, and text captures under run/demo-captures.
#
#   scripts/demo_film.sh               every check
#   scripts/demo_film.sh film agent    only these
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
B=${DEMO_PORT_BASE:-18300}
export TICKET_E2E_PORT_BASE=$B TICKET_E2E_PORT_RPC=$B
export LN_TICKET_PORT_LF1=$((B + 1)) LN_TICKET_PORT_LF2=$((B + 2)) LN_TICKET_PORT_LF3=$((B + 3)) LN_TICKET_PORT_LF4=$((B + 8))
export COMPOSE_PROJECT_NAME=demofilm
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ticket_e2e/compose.yml:$ROOT/scripts/demo/compose.yml
export ACTIVATION_HEIGHT=20
R=

cleanup() {
  if [ -n "$R" ]; then pkill -f "$R/" 2>/dev/null || true; fi
  if [ "${DEMO_KEEP:-0}" != 1 ]; then
    docker rm -f "$COMPOSE_PROJECT_NAME-jellyfin" >/dev/null 2>&1 || true
    if [ -d "$LAB" ]; then
      # unchecked: on the way out there is nobody to tell, and the next run removes what is left
      (cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
    fi
    if [ -n "$R" ]; then
      for f in signer gateway-near gateway-far proxy; do cp "$R/$f.log" "$ROOT/run/demo-$f.log" 2>/dev/null || true; done
      rm -rf "$R"
    fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$ROOT/run"
R=$(mktemp -d "$ROOT/run/demo-XXXXXX")

for tool in docker python3 ffmpeg ffprobe; do
  command -v "$tool" >/dev/null 2>&1 || { echo "demo: $tool is needed and is not on the PATH" >&2; exit 1; }
done
nice -n 19 cargo build -q -j4 --release --locked -p xbt-signer --bin xbt-signer -p xbt-wallet-mcp --bin xbt-wallet-mcp -p xbt-gateway --bin xbt-gateway
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

# the lab and the node binaries: cloned and built when missing
# shellcheck source=scripts/ln_rail/lab.sh
. "$ROOT/scripts/ln_rail/lab.sh"

# a lab an earlier DEMO_KEEP=1 run left holds the ports and an old chain: it goes first
docker rm -f "$COMPOSE_PROJECT_NAME-jellyfin" >/dev/null 2>&1 || true
(cd "$LAB" && docker compose down -v >/dev/null 2>&1) || true
# shellcheck disable=SC2046 # the port list is meant to split
python3 "$ROOT/scripts/portcheck.py" wait $(seq "$B" $((B + 30)))
(cd "$LAB" && docker compose up -d fees knots-b2b)

export LAB RUN=$R OUT=$ROOT/run BIN
if nice -n 19 python3 "$ROOT/scripts/demo/drive.py" "$@" 2>&1 | tee "$ROOT/run/demo_film.log"; then
  echo "demo: OK"
else
  echo "demo: FAIL (log: run/demo_film.log)" >&2
  exit 1
fi
