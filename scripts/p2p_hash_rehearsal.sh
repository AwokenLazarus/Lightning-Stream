#!/bin/bash
# p2p-hash rehearsal between two machines, with a real miner and real sats.
#
#   miner --SV1--> hasher (HASHER_IP, over ssh)  ==link==>  buyer (this machine) --SV1--> GATEWAY (DATUM)
#                  gateway + TLS front, Lightning node      wallet's signer, Lightning node
#   discovery: the hasher's signed listing on a stand-in Nostr relay on this machine (RELAY_LISTEN)
#
# Every finished slice is paid by this machine's wallet as one paid request to the hasher's gateway,
# on its tickets, over Lightning. The buyer stops paying after STOP_PAYING_AFTER slices, so the run
# ends with the hasher stopping the miner for non-payment (the miner's saved pool is its fallback).
#
# The miner's pools are saved first (mode 600: they hold the pool passwords) and restored on every
# exit, then read back and compared. The hasher's processes and this machine's relay are stopped on
# every exit. The settings (hosts, ports, the hasher's files on its machine, prices) come from
# CONF (default run/p2p-hash/rehearsal/rehearsal.env); the miner's web login from the environment.
#
#   MINER=host DM_USER=... DM_PASS=... scripts/p2p_hash_rehearsal.sh
# Evidence: run/p2p-hash/rehearsal/<time>/ (summary.json, the reports of both sides, the payments
# and invoices of both nodes during the run, the connections seen on both machines).
set -euo pipefail
cd "$(dirname "$0")/.."
CONF=${CONF:-run/p2p-hash/rehearsal/rehearsal.env}
# shellcheck source=/dev/null
. "$CONF"
[ "${CHECK_ONLY:-0}" = 1 ] || : "${MINER:?}" "${DM_USER:?}" "${DM_PASS:?}"
: "${HASHER_SSH:?}" "${HASHER_DIR:?}" "${HASHER_IP:?}" "${GATEWAY:?}" "${GW_USER:?}"
: "${SIGNER_SOCK:?}" "${RELAY_LISTEN:?}" "${PAY_NODE:?}" "${BUYER_LNCLI:?}" "${SELLER_LNCLI:?}"
STOP_PAYING_AFTER=${STOP_PAYING_AFTER:-14}
MINUTES=${MINUTES:-15}
D=run/p2p-hash/rehearsal/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$D/hasher"
T0=$(date +%s)
BIN=target/release/xbt-hashlink
DM="python3 -I scripts/p2p_hash/dragonmint.py ${MINER:-}"
H="$HASHER_DIR"
TERMS="--slice-work $SLICE_WORK --price-msat $PRICE_MSAT --grace-ms $GRACE_MS"
remote() { ssh -o BatchMode=yes "$HASHER_SSH" "$@"; }

pids=()
saved=0
finish() {
  set +e
  if [ "$saved" = 1 ]; then
    echo "restoring the miner's pools"
    $DM restore "$D/pools-before.json" | tee "$D/pools-after.json"
  fi
  # the pattern's first character in brackets: it does not match the remote shell's own command line
  remote "pkill -f '[${H:0:1}]${H:1}/' ; sleep 1; pkill -9 -f '[${H:0:1}]${H:1}/'" 2>/dev/null
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
}
trap finish EXIT

# the relay on this machine, then the hasher's side on its machine
"$BIN" relay --listen "$RELAY_LISTEN" 2> "$D/relay.log" &
pids+=($!)
# the hasher reaches the relay through an ssh tunnel to its own loopback: a relay on another
# machine is spoken to only over TLS, and this stand-in relay has none
ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -N -R "127.0.0.1:${RELAY_LISTEN##*:}:$RELAY_LISTEN" "$HASHER_SSH" &
pids+=($!)
sleep 2
remote "cd $H && rm -f listing.json hasher.json && \
  (nohup python3 $H/tls_front.py $HASHER_IP:$FRONT_PORT 127.0.0.1:$GW_PORT $H/front.crt $H/front.key > front.log 2>&1 &) && \
  (nohup $H/xbt-gateway $H/gateway.json > gateway.log 2>&1 &) && sleep 3 && \
  (nohup $H/xbt-hashlink hasher --key $H/hasher.key --miners $HASHER_IP:$MINERS_PORT --link $HASHER_IP:$LINK_PORT \
     --slices 127.0.0.1:$SLICES_PORT $TERMS --report $H/hasher.json \
     --relays ws://127.0.0.1:${RELAY_LISTEN##*:} --nostr-key $H/nostr.key --name '$LISTING_NAME' --link-public $HASHER_IP:$LINK_PORT \
     --pay-url https://$HASHER_IP:$FRONT_PORT/hashrate --pay-node $PAY_NODE --hashrate-hs $HASHRATE_HS \
     --listing-out $H/listing.json > hasher.log 2>&1 &)"
for _ in $(seq 60); do remote "test -s $H/listing.json" && break; sleep 1; done
remote "test -s $H/listing.json" || { echo "the hasher published no listing; see $H/hasher.log on $HASHER_SSH" >&2; exit 1; }
curl -sk --max-time 10 "https://$HASHER_IP:$FRONT_PORT/x402/ticket/health" > "$D/gateway-health-before.json" || { echo "the hasher's gateway did not answer; see $H/gateway.log and front.log on $HASHER_SSH" >&2; exit 1; }
# the wallet reads the hasher's terms and pays nothing (max_sats 0): the pin, the allowlist and the 402
python3 -I -c 'import json,socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(sys.argv[1])
p={"url": sys.argv[2], "method": "POST", "body": "{}", "max_sats": 0, "task": sys.argv[3]}
s.sendall((json.dumps({"id": 1, "method": "xbt402_pay", "params": p})+"\n").encode())
b=b""
while not b.endswith(b"\n"):
    c=s.recv(65536)
    if not c: break
    b+=c
print(json.dumps(json.loads(b).get("result"), indent=1))' "$SIGNER_SOCK" "https://$HASHER_IP:$FRONT_PORT/hashrate/check/1" "$TASK" | tee "$D/terms-check.json"
if [ "${CHECK_ONLY:-0}" = 1 ]; then
  echo "CHECK_ONLY: the miner was not touched; stopping"
  exit 0
fi

# the miner: pools saved, then pool 1 pointed at the hasher (the saved pool 1 stays as pool 2)
$DM save "$D/pools-before.json" | tee "$D/pools-before.redacted.json"
saved=1
$DM test "stratum+tcp://$HASHER_IP:$MINERS_PORT" "$GW_USER" "$D/pools-before.json"

# the buyer: finds the listing, opens the link, rents the miner into its own gateway, pays per slice
"$BIN" buyer --key "$BUYER_KEY" --find "ws://$RELAY_LISTEN" --expect-node "$PAY_NODE" --found-out "$D/found.json" \
  --upstream "$GATEWAY" --user "$GW_USER" --signer "$SIGNER_SOCK" --task "$TASK" --max-sats "$MAX_SATS" \
  --rental "rehearsal-$T0" --idle-s 180 --duration-s $((MINUTES * 60)) --stop-paying-after "$STOP_PAYING_AFTER" \
  --report "$D/buyer.json" 2> "$D/buyer.log" &
B=$!
pids+=($B)
echo "miner pointed at $HASHER_IP:$MINERS_PORT; the rental runs up to $MINUTES min, paying $STOP_PAYING_AFTER slices"
sleep 120
ss -tnp 2>/dev/null > "$D/connections-buyer.txt" || true
remote "ss -tn" > "$D/connections-hasher.txt" || true
wait $B || true
sleep 5
curl -sk --max-time 10 "https://$HASHER_IP:$FRONT_PORT/x402/ticket/health" > "$D/gateway-health-after.json" || true
finish
trap - EXIT
for f in hasher.json listing.json hasher.log gateway.log front.log; do scp -q -o BatchMode=yes "$HASHER_SSH:$H/$f" "$D/hasher/" || true; done
$BUYER_LNCLI listpayments --include_incomplete > "$D/buyer-payments.json" || true
remote "$SELLER_LNCLI listinvoices --max_invoices 200 --index_offset 0" > "$D/seller-invoices.json" || true
python3 -I scripts/p2p_hash/rehearsal_summary.py "$D" "$T0" "$SLICE_WORK" "$STOP_PAYING_AFTER" "$HASHER_IP" "$MINER" | tee "$D/summary.json"
