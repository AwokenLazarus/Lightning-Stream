#!/bin/bash
# AGP-100 verify: the xbt402 Hub app uses the node app Lightning Fork uses, and no second node.
# Lints the store, then installs the hub on regtest the way umbrelOS does (regtest/hub_shared_node.py) beside
#   paul     Paul's paulscode-knots-blake2b (his store at a pinned commit, his image by digest),
#   standin  our lazarus-xbt-knots (the fallback, APP_XBT_KNOTS_* only),
#   none     no node app (the hub must not report ready),
# and prints RESULT PASS|FAIL. MODES="paul standin none" chooses.
# Needs xbt402-hub:0.1.0 and xbt-init:0.1.0 loaded (scripts/oci_build.sh --load), xbt-a3-knots:29.4.2 for
# standin, and for paul the network once: his store commit (or PAUL_STORE=<checkout>) and his node image,
# which docker pulls by digest. One host port, 127.0.0.1:24020 (UMBREL_TEST_HUB_PORT), and the docker subnet
# 10.21.0.0/16 (umbrelOS's; Paul's apps pin addresses in it), so one run at a time. Soak rules: CPUQuota 200%,
# MemoryMax 4G, nice 19. Starts no miners. Never pushes, never submits to a store.
# Evidence: run/umbrel-hub-node/<stamp>/<mode>/.
set -euo pipefail
if [ -z "${UMBREL_TEST_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export UMBREL_TEST_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/../.."
ROOT=$PWD
MODES=${MODES:-paul standin none}
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$ROOT/run/umbrel-hub-node/$STAMP
mkdir -p "$OUT"
for i in xbt402-hub xbt-init; do
  docker image inspect "$i:0.1.0" >/dev/null 2>&1 || { echo "test-umbrel-hub-node: image $i:0.1.0 missing (scripts/oci_build.sh --load)" >&2; exit 1; }
done

echo "== lint the store" | tee "$OUT/lint.log"
python3 packaging/umbrel/lint.py packaging/umbrel 2>&1 | tee -a "$OUT/lint.log"
echo "== lint catches a hub that reads the slot's variable with no fallback" | tee -a "$OUT/lint.log"
NEG=$(mktemp -d)
cp -r packaging/umbrel/. "$NEG/"
sed -i 's/\${APP_BITCOIN_NODE_IP:-\${APP_XBT_KNOTS_NODE_HOST}}/${APP_BITCOIN_NODE_IP}/' "$NEG/lazarus-xbt402-hub/docker-compose.yml"
if python3 packaging/umbrel/lint.py "$NEG" >>"$OUT/lint.log" 2>&1; then echo "lint missed it" | tee -a "$OUT/lint.log"; rm -rf "$NEG"; echo "RESULT FAIL"; exit 1; fi
rm -rf "$NEG"
echo "   refused, as it should be" | tee -a "$OUT/lint.log"

rc=0
for m in $MODES; do
  echo "== hub beside: $m"
  mkdir -p "$OUT/$m"
  python3 packaging/umbrel/regtest/hub_shared_node.py "$OUT/$m" "$m" || rc=1
done
ln -sfn "$STAMP" "$ROOT/run/umbrel-hub-node/latest"
echo "evidence: $OUT"
if [ $rc -eq 0 ]; then echo "RESULT PASS"; else echo "RESULT FAIL"; exit 1; fi
