#!/bin/bash
# The StartOS package's Stream Gateway (the `datum` daemon) and its hashtaker on Docker, StartOS-shaped (one network
# namespace for the package's containers, the `main` volume root-owned), against a Knots BLAKE2b regtest node, with
# a masked solo rental to the end: packaging/startos/test/datum_regtest.py says what it checks.
#
# Images: the package's own commands, mounts and env (spec.ts, through test/spec-json.mjs), on stand-in images
# where the published ones don't exist yet: xbt-hashlink, xbt-init and xbt-supervise from this tree (cargo, glibc,
# on ubuntu:24.04), and the gateway from the lab binary P2P_HASH_GATEWAYS/datum_gateway-blind (CONVOY 971af86 +
# gateway-blind-release.patch) unless DATUM_IMAGE names a built xbt-datum-gateway image, or DATUM_IMAGE_TAR an
# archive of one (scripts/oci_build.sh's dist/oci/xbt-datum-gateway.tar), loaded here. The node, the miner
# (stratum-grind) and the gateway binary come from P2P_HASH_GATEWAYS (default ~/xbt-rnd/hash-gateways).
# Ports: 127.0.0.1:24190 (the seller's miners), 24191 (the node's RPC, on the test network's bridge address only).
# Evidence: run/startos-datum/<stamp>/ (results.json, datum_regtest.log, the containers' logs).
set -euo pipefail
cd "$(dirname "$0")/../../.."
ROOT=$PWD
HG=${P2P_HASH_GATEWAYS:-$HOME/xbt-rnd/hash-gateways}
OUT=$ROOT/run/startos-datum/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
for b in bitcoind bitcoin-cli stratum-grind datum_gateway-blind lib/libmicrohttpd.so.12; do
  [ -e "$HG/$b" ] || { echo "datum_regtest: $HG/$b missing" >&2; exit 1; }
done

echo "== build: xbt-hashlink, xbt-init, xbt-supervise from this tree"
nice -n 19 cargo build -q -j"${JOBS:-6}" --release --locked -p xbt-hashlink --bin xbt-hashlink -p xbt-svc --bin xbt-init --bin xbt-supervise
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

CTX=$(mktemp -d)
LOADED=
# the stand-in images go again at the end: no tag of this run is left on the lab
trap 'rm -rf "$CTX"; docker rmi -f xbt-hashlink:standin-datum-test xbt-init:standin-datum-test xbt-test-probe:datum-test xbt-datum-gateway:standin-datum-test $LOADED >/dev/null 2>&1 || true' EXIT
cp "$BIN/xbt-hashlink" "$BIN/xbt-init" "$BIN/xbt-supervise" "$HG/datum_gateway-blind" "$HG/lib/libmicrohttpd.so.12" "$CTX/"
cat > "$CTX/Dockerfile.hashlink" <<'EOF'
FROM ubuntu:24.04
RUN groupadd -g 10010 xbt-hashrate && useradd -u 10010 -g 10010 -M -s /usr/sbin/nologin xbt-hashrate
COPY xbt-hashlink /usr/bin/xbt-hashlink
ENV XBT_DATA_DIR=/data XBT_MODE=production
USER xbt-hashrate
EOF
cat > "$CTX/Dockerfile.init" <<'EOF'
FROM ubuntu:24.04
COPY xbt-init /usr/bin/xbt-init
ENV XBT_DATA_DIR=/data XBT_MODE=production
EOF
cat > "$CTX/Dockerfile.datum" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libcurl4t64 libjansson4 libsodium23 >/dev/null && rm -rf /var/lib/apt/lists/*
COPY libmicrohttpd.so.12 /usr/local/lib/
RUN ldconfig && groupadd -g 10021 xbt-datum && useradd -u 10021 -g 10021 -M -s /usr/sbin/nologin xbt-datum
COPY datum_gateway-blind /usr/bin/xbt-datum-gateway
COPY xbt-supervise /usr/bin/xbt-supervise
ENV XBT_DATA_DIR=/data XBT_MODE=production
USER xbt-datum
EOF
cat > "$CTX/Dockerfile.probe" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends curl socat >/dev/null && rm -rf /var/lib/apt/lists/*
EOF
echo "== stand-in images"
docker build -q -t xbt-hashlink:standin-datum-test -f "$CTX/Dockerfile.hashlink" "$CTX" >/dev/null
docker build -q -t xbt-init:standin-datum-test -f "$CTX/Dockerfile.init" "$CTX" >/dev/null
docker build -q -t xbt-test-probe:datum-test -f "$CTX/Dockerfile.probe" "$CTX" >/dev/null
if [ -n "${DATUM_IMAGE_TAR:-}" ]; then
  out=$(docker load -i "$DATUM_IMAGE_TAR")
  ref=$(printf '%s\n' "$out" | sed -n 's/^Loaded image: //p' | head -1)
  [ -n "$ref" ] || { id=$(printf '%s\n' "$out" | sed -n 's/^Loaded image ID: //p' | head -1); ref=xbt-datum-gateway:loaded-datum-test; docker tag "$id" "$ref"; }
  export DATUM_IMAGE=$ref
  # what this run loaded goes again at the end
  LOADED=$ref
fi
if [ -z "${DATUM_IMAGE:-}" ]; then
  docker build -q -t xbt-datum-gateway:standin-datum-test -f "$CTX/Dockerfile.datum" "$CTX" >/dev/null
  export DATUM_IMAGE=xbt-datum-gateway:standin-datum-test
fi
export HASHLINK_IMAGE=xbt-hashlink:standin-datum-test INIT_IMAGE=xbt-init:standin-datum-test PROBE_IMAGE=xbt-test-probe:datum-test HG
echo "lab gateway binary (the stand-in's) $(sha256sum "$HG/datum_gateway-blind" | cut -c1-16); image run: $DATUM_IMAGE ($(docker image inspect "$DATUM_IMAGE" --format '{{.Id}}' | cut -c1-19))${DATUM_IMAGE_TAR:+ from $DATUM_IMAGE_TAR}" | tee "$OUT/images.log"

set +e
nice -n 10 python3 packaging/startos/test/datum_regtest.py "$OUT"
rc=$?
set -e
ln -sfn "$(basename "$OUT")" "$ROOT/run/startos-datum/latest"
echo "evidence: $OUT"
[ $rc -eq 0 ] && echo "RESULT PASS" || { echo "RESULT FAIL"; exit 1; }
