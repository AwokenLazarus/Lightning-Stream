#!/usr/bin/env bash
# The shop on this machine, its buyers on another (BUYER_HOST, over ssh), through RELAY: only the
# shop's upload to the relay is on this machine's line, as for buyers anywhere else.
# Copies the measuring tool to BUYER_HOST for the run and removes it after.
# STEPS="1:10 2:10 4:10" (endpoints:buyers), MODES="bulk film", MBIT=8, SECS=60, BULK_SECS=20
set -euo pipefail
here=$(cd "$(dirname "$0")/../.." && pwd)
bin=${BIN:-$here/target/release/examples/relay_scale}
: "${RELAY:?the relay URL}" "${BUYER_HOST:?ssh host for the buyers}"
out=${OUT:-/dev/stdout}
remote=/tmp/relay_scale.$$
scp -q "$bin" "$BUYER_HOST:$remote"
trap 'ssh "$BUYER_HOST" rm -f "$remote"; kill ${seller:-} 2>/dev/null || true' EXIT
for mode in ${MODES:-bulk film}; do
  for step in ${STEPS:-1:10 2:10 4:10}; do
    n=${step%%:*}; k=${step##*:}
    secs=${SECS:-60}; [[ $mode == bulk ]] && secs=${BULK_SECS:-20}
    keys_file=$(mktemp)
    RELAY=$RELAY ENDPOINTS=$n ROLE=seller "$bin" run > "$keys_file" 2>/dev/null & seller=$!
    until [[ -s $keys_file ]]; do sleep 0.5; done
    keys=$(head -1 "$keys_file"); rm -f "$keys_file"
    ssh "$BUYER_HOST" "RELAY=$RELAY ROLE=buyer SHOP_KEYS=$keys BUYERS=$k MODE=$mode MBIT=${MBIT:-8} SECS=$secs $remote run 2>/dev/null | tail -1" >> "$out"
    kill $seller; wait $seller 2>/dev/null || true; seller=
  done
done
