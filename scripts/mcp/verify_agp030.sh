#!/bin/bash
# The MCP verify: an agent can pay through the wallet's MCP server, at this commit, in one run.
#   scripts/mcp/verify_agp030.sh            every step
#   PARITY=0 scripts/mcp/verify_agp030.sh   without the two comparisons with the Python wallet
#   E2E="page stream" ...                   which checks of the end-to-end run (default: page latency stream)
#
# What it proves, step by step:
#   1. the release binaries build and the workspace's tests pass;
#   2. the MCP server lists the tools it should (six for every wallet, the Lightning and ticket tools
#      where the operator turns them on, and none of the removed on-chain channel);
#   3. the protocol is answered as the Python wallet's MCP answers it, and every tool both wallets
#      have gives the same replies, over stdio and over streamable HTTP (scripts/mcp/mcp_conformance.py,
#      http_sdk_check.py). Needs the Python wallet's tree (B2_TREE, default ~/xbt-rnd/b2) and a Python
#      with the `mcp` SDK 2.2.0 (MCP_PY), and the Python channel reference it imports (B1_ROOT);
#      PARITY=0 skips these two;
#   4. an agent buys over the MCP binary: `xbt402_pay` through xbt-wallet-mcp and xbt-signer, paid
#      with stream tickets through a routing hop to a seller behind xbt-gateway, on regtest
#      (scripts/ticket_e2e_regtest.sh: Docker and the Lightning Fork lab it builds under run/).
#
# Until 2026-10 step 4 bought over the on-chain channel, which was removed; steps of this script
# that compared whole channel runs with the Python wallet went with it.
# Soak rules: CPUQuota 200%, 4G, nice 19, -j2 for the builds and tests of steps 1 to 3.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
PY=${MCP_PY:-$HOME/xbt-rnd/xbt-063/.venv/bin/python}
B2=${B2_TREE:-$HOME/xbt-rnd/b2}
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
declare -a RES=()
step() {   # label, command...
  local label=$1; shift
  echo "==== $label"
  local t0=$SECONDS
  "$@"
  local rc=$?
  RES+=("$( [ $rc -eq 0 ] && echo PASS || echo "FAIL($rc)" )  $label  ($((SECONDS - t0)) s)")
  echo "==== $label: rc=$rc"
}
tools() {   # env..., then the expected names in order
  local -a envs=()
  while [[ ${1:-} == *=* ]]; do envs+=("$1"); shift; done
  local got
  got=$(env "${envs[@]}" target/release/xbt-wallet-mcp --list-tools | python3 -c 'import json,sys; print(" ".join(t["name"] for t in json.load(sys.stdin)["tools"]))')
  echo "  ${envs[*]:-(no rail turned on)}: $got"
  [ "$got" = "$*" ]
}
tool_lists() {
  tools balance quote_payment pay history channels xbt402_pay &&
  tools XBT_MCP_LN=1 balance quote_payment pay history channels xbt402_pay ln_pay ln_status &&
  tools XBT_MCP_LN=1 XBT_MCP_TICKETS=1 balance quote_payment pay history channels xbt402_pay ln_pay ln_status ticket_status ticket_stop
}
mkdir -p run
echo "MCP verify: $(git rev-parse --short HEAD), $(date -u +%FT%TZ)"
step "build (release, -j2)" "${SOAK[@]}" cargo build -q -j2 --release --offline -p xbt-wallet-mcp -p xbt-signer -p xbt-gateway --bins
step "cargo test --workspace" bash -c "${SOAK[*]} cargo test -q -j2 --workspace --offline 2>&1 | grep -E '^test result' | awk '{p+=\$4; f+=\$6} END {print \"tests passed\", p, \"failed\", f; exit f>0}'"
step "no serde_json arbitrary_precision" bash -c "! cargo tree --offline -e features -i serde_json --workspace 2>/dev/null | grep -q arbitrary_precision"
step "the tool lists" tool_lists
if [ "${PARITY:-1}" != 0 ]; then
  # the Python wallet imports the Python channel reference: where its checkout is
  export B1_ROOT=${B1_ROOT:-${XBT402_B1:-$HOME/xbt-rnd/b1}}
  step "protocol and shared tools vs the Python wallet (mock signer, stdio)" python3 scripts/mcp/mcp_conformance.py --py "$PY" --b2 "$B2" --rust target/release/xbt-wallet-mcp --out run/verify-mcp-conformance.json
  step "Python SDK over streamable HTTP vs the Python wallet over stdio" python3 scripts/mcp/http_sdk_check.py --py "$PY" --b2 "$B2" --rust target/release/xbt-wallet-mcp
fi
# shellcheck disable=SC2086
step "an agent buys through the MCP binary, paid with stream tickets (regtest)" scripts/ticket_e2e_regtest.sh ${E2E:-page latency stream}
echo
echo "==== summary"
printf '%s\n' "${RES[@]}"
! printf '%s\n' "${RES[@]}" | grep -q "^FAIL"
