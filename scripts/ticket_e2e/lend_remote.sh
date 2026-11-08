#!/usr/bin/env bash
# A lender's machine in the mesh_lend_real check: only the tool, at ~/mesh-alpha/stream-compute-check. Waits for the operator's
# file server, then one command, `lend`, in a clean directory. Reports its card and report back under its tag, and does as it is
# told. Each lender of a run has its own tag (a, b, ...), so two can share a machine.
#   lend_remote.sh URL BIND_IP TAG
set -u
URL=$1 IP=$2 TAG=$3
BASE=$HOME/mesh-alpha DIR=$BASE/lend-clean-$TAG CFG=$BASE/lend-clean-$TAG.cfg BIN=$BASE/stream-compute-check
rm -rf "$DIR" "$CFG"; mkdir -p "$CFG"
until curl -sf -m 5 "$URL/$TAG/lend-go" -o /dev/null; do sleep 2; done
curl -sf -m 30 "$URL/invite.json" -o "$CFG/invite.json"
for f in lender.macaroon lender.tls.cert lend-args; do curl -sf -m 30 "$URL/$TAG/$f" -o "$CFG/$f"; done
chmod 600 "$CFG/lender.macaroon"
start() {
  # shellcheck disable=SC2046
  nohup "$BIN" lend --invite "$CFG/invite.json" --dir "$DIR" --node-macaroon "$CFG/lender.macaroon" --node-cert "$CFG/lender.tls.cert" \
    --bind-ip "$IP" --yes $(cat "$CFG/lend-args") >> "$CFG/lend.log" 2>&1 < /dev/null &
  echo $! > "$CFG/lend.pid"
}
start
done=""; misses=0
while :; do
  [ -f "$DIR/card.txt" ] && curl -sf -m 5 -X POST --data-binary "@$DIR/card.txt" "$URL/$TAG/card" -o /dev/null
  [ -f "$DIR/report.json" ] && curl -sf -m 5 -X POST --data-binary "@$DIR/report.json" "$URL/$TAG/report" -o /dev/null
  if c=$(curl -sf -m 5 "$URL/$TAG/command"); then misses=0; else misses=$((misses + 1)); fi
  if [ -n "${c:-}" ] && [ "$c" != "$done" ]; then
    case "$c" in
      *kill) kill -9 "$(cat "$CFG/lend.pid")"; sleep 2; start; curl -sf -m 5 -X POST --data-binary "$c" "$URL/$TAG/did" -o /dev/null ;;
      *stop) kill -TERM "$(cat "$CFG/lend.pid")"; sleep 5; exit 0 ;;
    esac
    done=$c
  fi
  # the operator's gone: so is the lab
  if [ "$misses" -gt 40 ]; then kill -TERM "$(cat "$CFG/lend.pid")" 2>/dev/null; sleep 5; exit 0; fi
  sleep 2
done
