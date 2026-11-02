#!/usr/bin/env bash
# Delivered rate and stalls of a relay-only shop, by how many link keys it serves on.
# RELAY=<url> (default: a local relay started here, with our relay's per-client limit)
# STEPS="1:10 2:10 4:10 1:30 2:30 4:30" (endpoints:buyers), MODES="film bulk", MBIT=8, SECS=60, BULK_SECS=20
set -euo pipefail
here=$(cd "$(dirname "$0")/../.." && pwd)
bin=${BIN:-$here/target/release/examples/relay_scale}
out=${OUT:-/dev/stdout}
relay_pid=
if [[ -z "${RELAY:-}" ]]; then
  port=${RELAY_PORT:-33400}
  "$bin" relay "127.0.0.1:$port" 2>/dev/null & relay_pid=$!
  trap 'kill $relay_pid 2>/dev/null || true' EXIT
  sleep 1
  RELAY="http://127.0.0.1:$port"
fi
for mode in ${MODES:-film bulk}; do
  for step in ${STEPS:-1:10 2:10 4:10 1:30 2:30 4:30}; do
    n=${step%%:*}; k=${step##*:}
    secs=${SECS:-60}; [[ $mode == bulk ]] && secs=${BULK_SECS:-20}
    cpu0=$(awk '{print $1+$2+$3}' /proc/stat)
    line=$(RELAY=$RELAY ENDPOINTS=$n BUYERS=$k MODE=$mode MBIT=${MBIT:-8} SECS=$secs \
           /usr/bin/time -f '%U %S %e' -o /tmp/relay_scale.time "$bin" run 2>/dev/null | tail -1)
    read -r u s e < /tmp/relay_scale.time
    cores=$(awk -v u="$u" -v s="$s" -v e="$e" 'BEGIN{printf "%.2f", (u+s)/e}')
    echo "${line%\}},\"process_cores\":$cores}" >> "$out"
  done
done
