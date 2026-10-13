#!/bin/bash
# AGP-039: the web UI on regtest, end to end. A private Knots 29.4.2 regtest node (the node script
# of the Python channel reference, XBT402_B1/scripts/node.sh), xbt-signer with the anchor witness,
# xbt-wallet-mcp over streamable HTTP, and xbt-wallet-ui. Then (regtest_ui.py):
#   an agent asks through the MCP for a payment at the human threshold and is told it needs the human;
#   the human logs in to the UI, sees it, signs the approval (with `xbt-wallet-ui sign`, the "another
#   device" path; the in-browser signing is covered by tests/browser.rs) and submits it in the UI; the
#   payment is made and confirmed on chain; a second one is denied; the human sweeps the hot key;
#   the UI shows an intact, anchored signature log and no channel.
# The payment is an on-chain `pay`. An agent paying a seller's 402 is proven on Lightning by
# scripts/ticket_e2e_regtest.sh; until 2026-10 this script paid over the on-chain channel, which was
# removed.
# Ports 23800-23899 (AGP-039): node RPC 23801, P2P 23802, MCP 23820, UI 23830.
# Soak rules: CPUQuota 200%, MemoryMax 4G, nice 19, cargo -j2. Starts no miners (blocks from
# generatetoaddress / the signer's regtest-only mining). Evidence: run/ui-regtest/<stamp>/.
set -euo pipefail
if [ -z "${UI_REGTEST_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export UI_REGTEST_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/../.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1-agp-050}
[ -d "$B1" ] || B1=$HOME/xbt-rnd/b1
STAMP=$(date +%Y%m%d-%H%M%S)
R=$ROOT/run/ui-regtest/$STAMP
mkdir -p "$R"
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node XBT402_RPCPORT=23801 XBT402_P2PPORT=23802 XBT402_MATURITY_PAD=6800
P_MCP=23820 P_UI=23830
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  "$B1/scripts/node.sh" down >/dev/null 2>&1 || true
  [ -n "${UI_REGTEST_KEEP:-}" ] || rm -rf "$R/node"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

python3 "$ROOT/scripts/portcheck.py" wait --timeout 60 23801 23802 $P_MCP $P_UI
echo "== build (release, -j2)"
cargo build -q -j2 --release --offline -p xbt-signer -p xbt-wallet-mcp -p xbt-wallet-ui --bins
BIN=$ROOT/target/release
"$B1/scripts/node.sh" up
CLI=("$XBT_BIN/bitcoin-cli" -regtest -datadir="$XBT402_DATADIR" -rpcport=$XBT402_RPCPORT)
COOKIE=$XBT402_DATADIR/regtest/.cookie

PAYEE=$("${CLI[@]}" -rpcwallet=w getnewaddress payee bech32)

echo "== the human's key (on 'another device'), the signer's root and policy"
mkdir -p "$R/device" "$R/keys" "$R/wallet/.run" "$R/witness" "$R/ui"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$R/device/human.key"; chmod 600 "$R/device/human.key"
HUMAN_PUB=$("$BIN/xbt-wallet-ui" pubkey --key "$R/device/human.key")
cat >"$R/wallet/policy.json" <<JSON
{"allowlist": ["$PAYEE"], "counterparties": {}, "max_per_tx_sats": 5000, "daily_budget_sats": 100000,
 "weekly_budget_sats": 200000, "per_counterparty_cap_sats": 50000, "velocity_max": 60, "velocity_window_s": 3600,
 "human_threshold_sats": 1000, "split_window_s": 0, "approval_ttl_s": 900,
 "hot_balance_cap_sats": 0, "anchor_interval_s": 60, "anchor_required": true, "human_pubkey": "$HUMAN_PUB"}
JSON

echo "== anchor witness, signer"
"$BIN/xbt-anchor-witness" serve --store "$R/witness" --sock "$R/witness/w.sock" >"$R/witness.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -S "$R/witness/w.sock" ] && break; sleep 0.1; done
export B2_ROOT=$R/wallet B2_DATADIR=$XBT402_DATADIR B2_RPCPORT=$XBT402_RPCPORT B2_WALLET=w B2_HOT_KEYFILE=$R/keys/hot.key \
       B2_ANCHOR_SOCK=$R/witness/w.sock B2_SIGNER_SOCK=$R/wallet/.run/signer.sock B2_WATCH_INTERVAL=5
"$BIN/xbt-signer" --root "$R/wallet" >"$R/signer.log" 2>&1 & PIDS+=($!)
for _ in $(seq 100); do [ -S "$B2_SIGNER_SOCK" ] && break; sleep 0.1; done
[ -S "$B2_SIGNER_SOCK" ] || { echo "signer did not start"; cat "$R/signer.log"; exit 1; }

echo "== MCP (HTTP), UI"
MCP_TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
XBT_MCP_HTTP_TOKEN=$MCP_TOKEN "$BIN/xbt-wallet-mcp" --http 127.0.0.1:$P_MCP >"$R/mcp.log" 2>&1 & PIDS+=($!)
printf 'regtest ui password %s\n' "$STAMP" | head -c -1 >"$R/ui/password"; chmod 600 "$R/ui/password"
XBT_UI_BIND=127.0.0.1:$P_UI XBT_UI_SIGNER_SOCK=$B2_SIGNER_SOCK XBT_UI_DATA_DIR=$R/ui/data XBT_UI_PASSWORD_FILE=$R/ui/password \
  "$BIN/xbt-wallet-ui" >"$R/ui.log" 2>&1 & PIDS+=($!)
for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$P_UI/healthz" && break; sleep 0.1; done

set +e
python3 "$ROOT/scripts/ui/regtest_ui.py" --out "$R" --sock "$B2_SIGNER_SOCK" --mcp "http://127.0.0.1:$P_MCP/mcp" --mcp-token "$MCP_TOKEN" \
  --ui "http://127.0.0.1:$P_UI" --ui-password-file "$R/ui/password" --human-key "$R/device/human.key" --sign-bin "$BIN/xbt-wallet-ui" \
  --payee "$PAYEE" --cli "${CLI[*]}" 2>&1 | tee "$R/regtest_ui.log"
rc=${PIPESTATUS[0]}
set -e
ln -sfn "$STAMP" "$ROOT/run/ui-regtest/latest"
echo "evidence: $R"
[ "$rc" -eq 0 ] && echo "regtest_ui: PASS" || { echo "regtest_ui: FAIL"; tail -20 "$R/signer.log"; exit 1; }
