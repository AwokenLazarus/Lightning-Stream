#!/bin/bash
# Verify the Linux package (packaging/linux): install.sh's checks in a bare ubuntu:24.04, then two
# installs on this machine against a regtest lab, a hashmaker and a hashtaker, one paid rental between
# them, and uninstall.sh (packaging/linux/test/linux_regtest.py). Prints RESULT PASS|FAIL.
# Needs the lab (run/lightning-fork-lab, cloned and built when missing), the pinned images (pulled), and
# with LS_TEST_IMAGES=local-ui (the default) the tree's wallet-ui as xbt-wallet-ui:linux-test
# (scripts/oci_build.sh --only xbt-wallet-ui --load, then docker tag xbt-wallet-ui:0.1.0 xbt-wallet-ui:linux-test).
# Ports: 127.0.0.1 LS_TEST_PORT_BASE (24600) + 10..55, and the hashmaker's 23340-23344. Evidence: run/linux-test/<stamp>/.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
OUT=$ROOT/run/linux-test/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"

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
