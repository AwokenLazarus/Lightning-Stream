#!/bin/bash
# A side-load bundle of the local Umbrel store, for a pilot on a box chosen for it (never a store
# submission, never a registry). Writes dist/umbrel/:
#   lazarus-store/            the store folder to copy to the box (umbrel-app-store.yml + the three apps)
#   images-amd64.tar          `docker save` of the images for an x86_64 box (Umbrel Home, a PC)
#   images-arm64.tar          the same for a Raspberry Pi 4/5 (no XBT node stand-in: its image is amd64-only)
#   SHA256SUMS, IMAGES.txt    checksums; each image's id per platform (compare after `docker load`)
# Needs the images loaded (scripts/oci_build.sh --load) and, for the amd64 stand-in node, xbt-a3-knots:29.4.2.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=dist/umbrel
rm -rf "$OUT"
mkdir -p "$OUT/lazarus-store"
cp packaging/umbrel/umbrel-app-store.yml "$OUT/lazarus-store/"
for app in lazarus-xbt-knots lazarus-xbt-agent-wallet lazarus-lightning-stream-gateway; do
  cp -r "packaging/umbrel/$app" "$OUT/lazarus-store/"
done
IMGS=(xbt-init:0.1.0 xbt-signer:0.1.0 xbt-anchor-witness:0.1.0 xbt-wallet-mcp:0.1.0 xbt-wallet-ui:0.1.0 xbt-gateway:0.1.0)
: >"$OUT/IMAGES.txt"
for plat in amd64 arm64; do
  extra=()
  [ $plat = amd64 ] && extra=(xbt-a3-knots:29.4.2)
  for i in "${IMGS[@]}" "${extra[@]}"; do
    echo "$plat $i $(docker image inspect --platform linux/$plat --format '{{.Id}}' "$i")" >>"$OUT/IMAGES.txt"
  done
  echo "== docker save linux/$plat"
  docker save --platform "linux/$plat" -o "$OUT/images-$plat.tar" "${IMGS[@]}" "${extra[@]}"
done
(cd "$OUT" && sha256sum images-*.tar >SHA256SUMS)
cat >"$OUT/README.txt" <<'TXT'
XBT Agent Wallet and Lightning Stream Gateway for Umbrel: a local side-load bundle. Not in any app store.

On the box (ssh umbrel@umbrel.local):
  1. sha256sum -c SHA256SUMS
  2. docker load -i images-amd64.tar      (a Raspberry Pi: images-arm64.tar; it has no XBT node stand-in)
  3. mkdir -p ~/umbrel/app-stores/lazarus-local && cp -r lazarus-store/. ~/umbrel/app-stores/lazarus-local/
  4. Install Lightning Fork and Knots (BLAKE2b) Companion from their author's community store first.
  5. umbrelOS adds community app stores by git URL: put lazarus-store/ in a private git repo the box can
     reach (a bare repo on the LAN), add it under App Store -> Community App Stores, then install
     "XBT Agent Wallet" (to buy) and/or "Lightning Stream Gateway" (to sell), selecting Knots (BLAKE2b)
     Companion for the wallet's node. This step is unverified until the pilot box: umbrelOS dev tooling
     does not run rootless on the build host.
  6. Wallet: log in with the password the dashboard shows for it; Setup: enrol your approval key, sign a
     policy (the starter template turns Lightning and tickets on); Lightning: paste a macaroon baked in
     Lightning Fork's dashboard with exactly info:read offchain:read offchain:write onchain:read;
     Agents: copy the MCP endpoint and token into your agent.
  7. Gateway: log in the same way; on its page set the service, the price, the https address buyers use
     (a TLS proxy you run, pointed at lazarus-lightning-stream-gateway_gateway_1:8402) and two macaroons
     (invoices:read invoices:write; info:read).
TXT
ls -l "$OUT"
