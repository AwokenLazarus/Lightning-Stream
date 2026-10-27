#!/bin/bash
# p2p-hash with a real miner: a short rental from a miner with the DragonMint web UI, through
# this machine's hashmaker and hashtaker, into a real DATUM Gateway, and the miner's pools put back.
#
#     miner ---SV1--- hashmaker (LISTEN) ====link==== hashtaker ---SV1--- GATEWAY (DATUM)
#
# Both apps run here. The hashtaker credits GW_USER at the gateway (default: the user the miner
# already uses there), so the work goes where it went before. Tickets use the lab's stand-in
# rails (no money moves). The hashtaker stops paying after STOP_PAYING_AFTER slices, so the run ends
# with the hashmaker stopping the miner for non-payment; the miner's saved pool is its fallback in
# the meantime.
#
# The miner's pools are saved first (run/p2p-hash/miner/<time>/pools-before.json, mode 600: it
# holds the pool passwords) and restored on every exit, then read back and compared.
#
#   MINER=host GATEWAY=host:port LISTEN=this-machine:port DM_USER=... DM_PASS=... scripts/p2p_hash_miner.sh
#   optional: GW_USER, MINUTES (10), STOP_PAYING_AFTER (4), SHARE_DIFF (4096), SHARES_PER_SLICE (10)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${MINER:?}" "${GATEWAY:?}" "${LISTEN:?}" "${DM_USER:?}" "${DM_PASS:?}"
MINUTES=${MINUTES:-10}
STOP_PAYING_AFTER=${STOP_PAYING_AFTER:-4}
SHARE_DIFF=${SHARE_DIFF:-4096}
SHARES_PER_SLICE=${SHARES_PER_SLICE:-10}
SLICE_WORK=$((SHARES_PER_SLICE * SHARE_DIFF * 4294967296))
D=run/p2p-hash/miner/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$D"
cargo build -q --release -p xbt-hashlink
BIN=target/release/xbt-hashlink
DM="python3 -I scripts/p2p_hash/dragonmint.py $MINER"

$DM save "$D/pools-before.json" | tee "$D/pools-before.redacted.json"
GW_USER=${GW_USER:-$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["user"])' "$D/pools-before.json")}

pids=()
restore() {
  set +e
  echo "restoring the miner's pools"
  $DM restore "$D/pools-before.json" | tee "$D/pools-after.json"
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
}
trap restore EXIT

"$BIN" keygen "$D/hasher.key" > "$D/hasher.pub"
"$BIN" keygen "$D/buyer.key" > /dev/null
"$BIN" hashmaker --key "$D/hasher.key" --miners "$LISTEN" --link 127.0.0.1:34931 --slice-work $SLICE_WORK \
  --price-msat 10000 --grace-ms 30000 --report "$D/hasher.json" 2> "$D/hasher.log" &
pids+=($!)
sleep 0.5
"$BIN" hashtaker --key "$D/buyer.key" --hashmaker 127.0.0.1:34931 --hashmaker-key "$(cat "$D/hasher.pub")" \
  --upstream "$GATEWAY" --user "$GW_USER" --slice-work $SLICE_WORK --price-msat 10000 --grace-ms 30000 \
  --rental "miner-$(date +%s)" --idle-s 180 --duration-s $((MINUTES * 60)) --stop-paying-after "$STOP_PAYING_AFTER" \
  --report "$D/buyer.json" 2> "$D/buyer.log" &
B=$!
pids+=($B)
sleep 1
$DM test "stratum+tcp://$LISTEN" "$GW_USER" "$D/pools-before.json"
echo "miner pointed at $LISTEN; the rental runs up to $MINUTES min"
wait $B || true
sleep 2
trap - EXIT
restore
python3 -I scripts/p2p_hash/miner_summary.py "$D" "$SLICE_WORK" "$STOP_PAYING_AFTER" | tee "$D/summary.json"
