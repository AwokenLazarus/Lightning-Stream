#!/bin/bash
# The fallback with a real miner: the miner hashes for the hasher's own pool (the fallback) through
# the app, is rented by a buyer into the buyer's pool, and goes back to the fallback by itself when
# the rental ends. No money moves: the slices are paid on the lab's rail over the link.
#
#   miner --SV1--> xbt-hashlink hasher (LISTEN) --> FALLBACK              (nobody renting)
#                                     ==link==> xbt-hashlink buyer --> BUYER_POOL   (rented)
#
# The miner's pools are saved first (mode 600: they hold the pool passwords) and restored on every
# exit, then read back and compared. The miner's web login comes from the environment.
#
#   MINER=host DM_USER=... DM_PASS=... FALLBACK=host:port BUYER_POOL=host:port WORKER=name \
#   LISTEN=ip:port scripts/p2p_hash_fallback_miner.sh
# Evidence: run/p2p-hash/fallback/<time>/ (summary.json, the hasher's and the buyer's reports).
set -euo pipefail
cd "$(dirname "$0")/.."
: "${MINER:?}" "${DM_USER:?}" "${DM_PASS:?}" "${FALLBACK:?}" "${BUYER_POOL:?}" "${WORKER:?}" "${LISTEN:?}"
ON_FALLBACK_S=${ON_FALLBACK_S:-60}
RENT_S=${RENT_S:-120}
AFTER_S=${AFTER_S:-60}
# a slice: four shares at difficulty 4096 (about 17 s of a 4 TH/s miner)
SLICE_WORK=${SLICE_WORK:-70368744177664}
TERMS=(--slice-work "$SLICE_WORK" --price-msat 1000 --grace-ms 60000)
LINK=127.0.0.1:24895
CONTROL=127.0.0.1:24896
D=run/p2p-hash/fallback/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$D"
BIN=target/release/xbt-hashlink
cargo build -q --release -p xbt-hashlink
DM="python3 -I scripts/p2p_hash/dragonmint.py $MINER"
status() { curl -s --max-time 5 "http://$CONTROL/status"; }

pids=()
saved=0
finish() {
  set +e
  if [ "$saved" = 1 ]; then
    echo "restoring the miner's pools"
    $DM restore "$D/pools-before.json" | tee "$D/pools-after.json"
  fi
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
}
trap finish EXIT

"$BIN" keygen "$D/hasher.key" > "$D/hasher.pub"
"$BIN" keygen "$D/buyer.key" > /dev/null
"$BIN" hasher --key "$D/hasher.key" --miners "$LISTEN" --link "$LINK" --control "$CONTROL" --fallback "$FALLBACK" --rentable 1 \
  "${TERMS[@]}" --report "$D/hasher.json" 2> "$D/hasher.log" &
pids+=($!)
sleep 1

$DM save "$D/pools-before.json" | tee "$D/pools-before.redacted.json"
saved=1
$DM test "stratum+tcp://$LISTEN" "$WORKER" "$D/pools-before.json"
echo "miner pointed at $LISTEN; waiting for it to hash at the fallback"
for _ in $(seq 120); do
  status | python3 -c 'import json,sys; d=json.load(sys.stdin); m=[x for x in d["miners"] if x["connected"]]; sys.exit(0 if m and m[0]["work"] != "0" else 1)' 2>/dev/null && break
  sleep 2
done
sleep "$ON_FALLBACK_S"
status > "$D/status-fallback.json"

echo "renting it for $RENT_S s into $BUYER_POOL"
"$BIN" buyer --key "$D/buyer.key" --hasher "$LINK" --hasher-key "$(cat "$D/hasher.pub")" "${TERMS[@]}" --upstream "$BUYER_POOL" \
  --user "$WORKER" --miners 1 --rental fallback-test --idle-s 120 --duration-s "$RENT_S" --report "$D/buyer.json" 2> "$D/buyer.log" &
B=$!
pids+=($B)
sleep $((RENT_S / 2))
status > "$D/status-rented.json"
wait "$B" || true

echo "rental over; watching the miner go back to the fallback for $AFTER_S s"
sleep "$AFTER_S"
status > "$D/status-after.json"

python3 -I - "$D" <<'PY' | tee "$D/summary.json"
import json, sys
d = sys.argv[1]
r = lambda n: json.load(open(f"{d}/{n}"))
fb, mid, after, buyer = r("status-fallback.json"), r("status-rented.json"), r("status-after.json"), r("buyer.json")
m = lambda s: (s["miners"] or [{}])[0]
rental = next((f for f in after["finished"] if f["rental"] == "fallback-test"), {})
methods = m(after).get("methods", {})
out = {
    "miner": m(after).get("name"),
    "workAtFallback": m(fb).get("work"), "workWhileRented": m(mid).get("work"), "workAfter": m(after).get("work"),
    "rentedToWhileRented": m(mid).get("rentedTo"), "rentedToAfter": m(after).get("rentedTo"),
    "hashrateHs": m(after).get("hashrateHs"),
    "rental": {k: rental.get(k) for k in ("paid", "receiptsAgree", "receiptsDisagree", "meter", "unitWork")},
    "rentalStopped": (rental.get("stopped") or {}).get("reason"),
    "buyerClosed": buyer.get("closed"), "buyerMeter": buyer.get("meter"),
    "metersEqual": rental.get("meter") == buyer.get("meter"),
    "methods": methods,
    "movedBy": "set_extranonce" if methods.get("mining.extranonce.subscribe") else "client.reconnect",
}
out["pass"] = bool(
    m(mid).get("rentedTo") == "fallback-test" and m(after).get("rentedTo") is None
    and int(m(after).get("work") or 0) > int(m(mid).get("work") or 0) > int(m(fb).get("work") or 0) > 0
    and (rental.get("paid") or 0) >= 1 and rental.get("receiptsDisagree") == 0 and out["metersEqual"]
)
print(json.dumps(out, indent=2))
PY
