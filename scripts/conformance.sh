#!/bin/bash
# Conformance of xbt-primitives + xbt402 (Rust) with the Python references, both directions.
#   1. the pinned vector copies in vectors/ are the published files (B1 agp-068, B2 agp-next2);
#   2. Rust recomputes every published vector: xbt402 (54), UnifiedSighash (166), BLAKE2b header v2
#      stages (5), the Knots BLAKE2b regtest capture (28) -> N/N byte-identical;
#   3. the Rust emitter rebuilds the whole xbt402 vector file and B1's check_vectors.py checks it
#      (diff against the Python library + its generator-independent checks).
# (A step 4 checked the hub's routing vectors. The hub was retired on 2026-10-11: payments between
# parties route over ordinary Lightning instead. Its code is in the git history, last at commit a548fb0.)
# Runs under the soak rules (CPUQuota 200%, 4G, nice 19). Env: XBT402_B1, XBT402_B2.
set -euo pipefail
cd "$(dirname "$0")/.."
B1=${XBT402_B1:-$HOME/xbt-rnd/b1}
export XBT402_B1=$B1
B2=${XBT402_B2:-$HOME/xbt-rnd/b2}
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

echo "== 1. pinned vectors are the published ones"
for pair in "$B1/docs/x402/vectors.json:vectors/xbt402_vectors.json" \
            "$B1/tests/data/unified_sighash.json:vectors/unified_sighash.json" \
            "$B2/tests/vectors/block_header_v2.json:vectors/block_header_v2.json" \
            "$B2/tests/vectors/blake2b_regtest.json:vectors/blake2b_regtest.json"; do
  src=${pair%%:*}; pin=${pair##*:}
  if cmp -s "$src" "$pin"; then echo "  same  $pin = $src"; else echo "  DIFF  $pin != $src" >&2; exit 1; fi
done

BIN=${CARGO_TARGET_DIR:-./target}/release
echo "== 2. Rust recomputes every published vector"
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bins
"$BIN"/xbt-conformance vectors

echo "== 3. reverse: Python check_vectors.py checks the Rust-emitted vector file"
"$BIN"/xbt402-vectors "$OUT/rust_vectors.json"
python3 scripts/py_check_rust_vectors.py "$OUT/rust_vectors.json"
# and under libsecp256k1 (coincurve), from B1's venv, when there is one
PYCC=${XBT402_PY_COINCURVE:-$HOME/xbt-rnd/b1/.venv/bin/python}
if [ -x "$PYCC" ] && "$PYCC" -c "import coincurve" 2>/dev/null; then
  "$PYCC" scripts/py_check_rust_vectors.py "$OUT/rust_vectors.json"
fi
echo "conformance: OK"
