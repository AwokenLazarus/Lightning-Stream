#!/bin/bash
# Verify the Linux package (packaging/linux): install.sh's checks in a bare ubuntu:24.04, then two
# installs on this machine against a regtest lab, a hashmaker (installed from the 0.1 package, then
# updated) and a hashtaker (a first install), each one's Stream Gateway shown masked, one paid rental of
# real work on masked solo jobs between them, the owner's own stock DATUM gateway refused, and
# uninstall.sh (packaging/linux/test/linux_regtest.py). Prints RESULT PASS|FAIL.
# Needs the lab (run/lightning-fork-lab, cloned and built when missing), the pinned images (pulled), the
# test's images (packaging/linux/test/build_images.sh: this tree's wallet-ui and hashlink, the Stream
# Gateway's stand-in and a stock gateway; LS_TEST_BUILD=0 uses the ones already built), and stratum-grind
# in P2P_HASH_GATEWAYS (~/xbt-rnd/hash-gateways, as the p2p_hash regtest's real gateway mode).
# Ports: 127.0.0.1 LS_TEST_PORT_BASE (24600) + 10..57, the Stream Gateway's 23339, and the hashmaker's
# 23340-23344. Evidence: run/linux-test/<stamp>/.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
OUT=$ROOT/run/linux-test/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"

echo "== install.sh's own steps, with a stand-in docker"
packaging/linux/test/install_steps.sh | tee "$OUT/install-steps.txt" | grep -q "RESULT PASS" || { cat "$OUT/install-steps.txt"; echo "RESULT FAIL"; exit 1; }

echo "== install.sh in a bare ubuntu:24.04: it names what is missing, and changes nothing"
docker run --rm -v "$ROOT/packaging/linux:/pkg:ro" ubuntu:24.04 bash -c '/pkg/install.sh --yes --dir /tmp/ls; echo "rc=$?"' > "$OUT/deps-none.txt" 2>&1 || true
grep -q "Docker is not installed" "$OUT/deps-none.txt" && grep -q "rc=1" "$OUT/deps-none.txt" || { cat "$OUT/deps-none.txt"; echo "RESULT FAIL"; exit 1; }
docker run --rm -v "$ROOT/packaging/linux:/pkg:ro" ubuntu:24.04 bash -c \
  'apt-get update -qq >/dev/null && apt-get install -y -qq docker.io >/dev/null 2>&1; /pkg/install.sh --yes --dir /tmp/ls; echo "rc=$?"' > "$OUT/deps-nocompose.txt" 2>&1 || true
grep -q "Compose plugin is missing" "$OUT/deps-nocompose.txt" && grep -q "rc=1" "$OUT/deps-nocompose.txt" || { tail -5 "$OUT/deps-nocompose.txt"; echo "RESULT FAIL"; exit 1; }
echo "   both refused with the right words"

for ref in $(awk '!/^#/ && NF == 2 {print $2}' packaging/images.lock); do
  docker image inspect "$ref" >/dev/null 2>&1 || docker pull -q "$ref" >/dev/null
done
if [ "${LS_TEST_BUILD:-1}" = 1 ]; then
  packaging/linux/test/build_images.sh 2>&1 | tee "$OUT/build-images.txt"
  [ "${PIPESTATUS[0]}" = 0 ] || { echo "RESULT FAIL"; exit 1; }
fi
python3 packaging/linux/test/linux_regtest.py "$OUT"
python3 - "$OUT/results.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
bad = [c for c in r if not c.get("ok")]
print(f"{len(r) - len(bad)}/{len(r)} checks passed")
for c in bad:
    print("FAIL", c.get("group"), c.get("check"))
print("RESULT", "PASS" if not bad and r else "FAIL")
sys.exit(1 if bad else 0)
PY
