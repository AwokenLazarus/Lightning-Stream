#!/bin/bash
# AGP-042: box packaging gaps. Soak rules (CPUQuota 200%, MemoryMax 4G, nice 19, cargo -j2).
# Ports for packaging runs: 34200-34299 (do not collide with AGP-040 34000 / StartOS 34100).
# Shared CARGO_TARGET_DIR=~/xbt-rnd/xbt-rs-target.
#   1. xbt-svc, xbt-wallet-ui, xbt-wallet-mcp, xbt402-hub tests
#   2. clippy: no warning in those crates / xbt402-hub.rs
#   3. Umbrel store lint
#   4. (PACKAGING=1) images + one Umbrel cold run + StartOS spec run
set -euo pipefail
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/xbt-rnd/xbt-rs-target}"
if [ -z "${VERIFY_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export VERIFY_SCOPED=1
  export UMBREL_TEST_SCOPED=1 STARTOS_TEST_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/.."
step() { echo; echo "== $*"; }
step "1. xbt-svc + xbt-wallet-ui + xbt-wallet-mcp + xbt402-hub"
cargo test -q -j2 -p xbt-svc -p xbt-wallet-ui -p xbt-wallet-mcp --all-targets 2>&1 | grep -E "test result|FAILED|panicked" | grep -v " 0 passed"
cargo test -q -j2 -p xbt402 --features rpc,http-client,http-server --bin xbt402-hub 2>&1 | grep -E "test result|FAILED|panicked"
step "2. clippy (xbt-svc, xbt-wallet-ui, xbt-wallet-mcp, xbt402-hub.rs)"
n=$(cargo clippy -q -j2 -p xbt-svc -p xbt-wallet-ui -p xbt-wallet-mcp --all-targets 2>&1 | grep -cE "^ *--> crates/(xbt-svc|xbt-wallet-ui|xbt-wallet-mcp)/" || true)
m=$(cargo clippy -q -j2 -p xbt402 --features rpc,http-client,http-server --bin xbt402-hub 2>&1 | grep -cE "^ *--> crates/xbt402/src/bin/xbt402-hub.rs" || true)
echo "clippy warnings: crates $n, xbt402-hub.rs $m"; [ "$n" = 0 ] && [ "$m" = 0 ]
step "3. Umbrel lint"
python3 packaging/umbrel/lint.py packaging/umbrel
step "4. Knots CMP-098 contract documented"
grep -q 'APP_XBT_KNOTS_NODE_HOST' packaging/umbrel/lazarus-xbt-knots/README.md
grep -q 'amd64-only' packaging/umbrel/lazarus-xbt-knots/README.md
grep -q 'XBT_HUB_ONION' packaging/umbrel/lazarus-xbt402-hub/docker-compose.yml
grep -q 'XBT_UI_MCP_ROTATE_URL' packaging/umbrel/lazarus-xbt-agent-wallet/docker-compose.yml
echo "docs/compose contract: ok"
if [ "${PACKAGING:-}" = 1 ]; then
  step "5. images + Umbrel (ports 34200) + StartOS"
  mkdir -p run/verify-agp042
  scripts/oci_build.sh --load >run/verify-agp042/oci_build.log 2>&1
  grep -q "^Checks: PASS" dist/oci/IMAGES.md
  export UMBREL_TEST_MCP_PORT=34210 UMBREL_TEST_HUB_PORT=34220 UMBREL_TEST_UI_PORT=34230
  export UMBREL_TEST_PROXY_PORT=34280 UMBREL_TEST_PROV_PORT=34240
  RUNS=1 packaging/umbrel/test-umbrel-apps.sh 2>&1 | grep -E "lint (PASS|FAIL)|refused|RESULT|run [0-9]:|FAIL|evidence"
  packaging/startos/test-startos.sh 2>&1 | grep -E "\"ok\"|bytes|checks passed|RESULT|FAIL|evidence"
fi
echo; echo "verify_agp042: PASS"
