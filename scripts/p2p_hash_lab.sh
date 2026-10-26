#!/bin/bash
# p2p-hash, phase 1 lab: a rental between two apps on one machine, through the shipped binary.
#
#     stand-in miners ---SV1--- hasher ====link (BOLT 8)==== buyer ---SV1--- stand-in pool
#     (the hasher's LAN)        (xbt-hashlink hasher)        (xbt-hashlink buyer)  (the buyer's gateway)
#
# The stand-in pool plays the buyer's DATUM Gateway and the stand-in miners play the hasher's
# miners; their share hash is a toy (see the crate's standin module). Tickets use the lab's
# stand-in rails: the hasher checks each released preimage against the hash the buyer locked, and
# no money moves. It prints PASS or FAIL for each of the plan's pass lines:
#   receipts   every finished slice paid once, each signed receipt equal to the hasher's own count
#              of accepted work at that slice, both meters equal at the end, the gateway crediting
#              only the buyer's user name
#   unpaid     the buyer stops paying after slice 3: the hasher stops within one slice of work
#              past the unpaid slice, by the grace time, and the gateway sees no more work
#   no-hash    the miners stop: no payment after that, the rental ends, the tickets still locked
#              are cancelled
# Report: run/p2p-hash/lab.json. Ports: 127.0.0.1:34920-34925.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=run/p2p-hash
rm -rf "$OUT/lab" && mkdir -p "$OUT/lab"
cargo build -q --release -p xbt-hashlink
BIN=target/release/xbt-hashlink
D="$OUT/lab"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

DIFF=4
WORK_PER_SHARE=$((4 * 4294967296))
SLICE_WORK=$((10 * WORK_PER_SHARE))

"$BIN" keygen "$D/hasher.key" > "$D/hasher.pub"
"$BIN" keygen "$D/buyer.key" > /dev/null

# scenario: name, buyer flags, miner rate (shares/s each), miner seconds, grace ms
scenario() {
  local name=$1 extra=$2 rate=$3 secs=$4 grace=$5 pool=127.0.0.1:34920 link=127.0.0.1:34921 miners=127.0.0.1:34922
  local dir="$D/$name"
  mkdir -p "$dir"
  "$BIN" standin-pool --listen $pool --diff $DIFF --job-ms 1000 --report "$dir/pool.json" 2> "$dir/pool.log" &
  local pool_pid=$!
  pids+=($pool_pid)
  "$BIN" hasher --key "$D/hasher.key" --miners $miners --link $link --slice-work $SLICE_WORK --price-msat 10000 \
    --grace-ms "$grace" --report "$dir/hasher.json" 2> "$dir/hasher.log" &
  local h_pid=$!
  pids+=($h_pid)
  sleep 0.5
  # shellcheck disable=SC2086
  "$BIN" buyer --key "$D/buyer.key" --hasher $link --hasher-key "$(cat "$D/hasher.pub")" --upstream $pool \
    --user buyer.rented --slice-work $SLICE_WORK --price-msat 10000 --grace-ms "$grace" --rental "lab-$name" \
    --idle-s 4 --report "$dir/buyer.json" $extra 2> "$dir/buyer.log" &
  local b_pid=$!
  pids+=($b_pid)
  sleep 0.5
  local m=()
  for i in 1 2; do
    "$BIN" standin-miner --pool $miners --user "hasher.m$i" --rate "$rate" --bad-every 9 --duration-s "$secs" \
      2> "$dir/miner$i.log" &
    m+=($!)
  done
  for p in "${m[@]}"; do wait "$p" || true; done
  date +%s%3N > "$dir/miners_done_ms"
  wait $b_pid || true
  wait $h_pid || true
  sleep 1
  kill $pool_pid 2>/dev/null || true
  wait $pool_pid 2>/dev/null || true
}

scenario paid "" 4 25 3000
scenario unpaid "--stop-paying-after 3" 2 40 1000

python3 -I scripts/p2p_hash/check.py "$D" "$SLICE_WORK" "$WORK_PER_SHARE" "$OUT/lab.json"
