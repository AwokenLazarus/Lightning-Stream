#!/bin/bash
# AGP-038: the container test. Builds the multi-arch images (scripts/oci_build.sh --load: all three platforms
# into dist/oci/*.tar, the amd64 ones loaded as <image>:agp038), checks the arm64 and arm/v7 images with
# scripts/oci_inspect.py, then runs scripts/container/container_test.py: signer + witness + MCP
# composed with a Knots 29.4.2 regtest node, configured only by env and a data dir; the agent's MCP over
# HTTP and the hot key's custody; kill/restart persistence; /readyz gating. Ports 23700-23799 (published
# on 127.0.0.1 only: MCP 23710). Soak rules: cargo under CPUQuota 200%, MemoryMax 4G, nice 19, -j2.
# Evidence: run/container-test/<stamp>/.
#   scripts/container_test.sh [--skip-build]      CONTAINER_TEST_KEEP=1 keeps the volumes
set -euo pipefail
lazvault hold check --project xbt-agentpay || exit 75   # IMP-030: heavy entry point, refuses during a host hold
cd "$(dirname "$0")/.."
ROOT=$PWD
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$ROOT/run/container-test/$STAMP
mkdir -p "$OUT"
busy=$(ss -ltnH | awk '{print $4}' | sed 's/.*://' | awk '$1>=23700 && $1<=23799' | sort -u | tr '\n' ' ')
[ -z "$busy" ] || { echo "container_test: ports busy in 23700-23799: $busy" >&2; exit 1; }
if [ "${1:-}" != "--skip-build" ]; then
  echo "== images (scripts/oci_build.sh --load)"
  ./scripts/oci_build.sh --load | tee "$OUT/oci_build.log"
fi
echo "== inspect: every image, every platform (arm64 and arm/v7 included)"
set +e
python3 scripts/oci_inspect.py dist/oci xbt-signer xbt-anchor-witness xbt-wallet-mcp >"$OUT/oci_inspect.json"
irc=$?
set -e
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('   inspect ok:', d['ok'], d['problems'] or '')" "$OUT/oci_inspect.json"
set +e
python3 scripts/container/container_test.py "$OUT"
rc=$?
set -e
ln -sfn "$STAMP" "$ROOT/run/container-test/latest"
echo "evidence: $OUT"
[ $rc -eq 0 ] && [ $irc -eq 0 ] && echo "container_test: PASS" || { echo "container_test: FAIL"; exit 1; }
