#!/bin/bash
# A side-load bundle of the local Umbrel store, for a pilot on a box chosen for it (never a store
# submission, never a registry). Writes dist/umbrel/:
#   lazarus-store/            the store folder to copy to the box (umbrel-app-store.yml + the apps)
#   images-amd64.tar          `docker save` of the images for an x86_64 box (Umbrel Home, a PC)
#   images-arm64.tar          the same for a Raspberry Pi 4/5 (no XBT node stand-in: its image is amd64-only)
#   SHA256SUMS, IMAGES.txt    checksums; each image's id per platform (compare after loading)
# The agentpay images are the published ones the store pins (packaging/images.lock,
# ghcr.io/awokenlazarus/<image>:<version>-<commit>@sha256:<digest>): a missing one is pulled by digest and tagged
# <registry>/<image>:<version>-<commit> here, so the saved archives carry a name. The amd64 stand-in node,
# xbt-a3-knots:29.4.2, is the one local image.
# umbrelOS 2.0 pulls every image of an app when it installs it, so a `docker load`ed image alone fails
# ("pull access denied"). Without REGISTRY the store names the published images, which a box with internet
# access pulls from ghcr.io itself (the archives are then a copy, not needed). REGISTRY=host:port names every
# image by a registry the box can pull from instead, as <REGISTRY>/<image>:<tag> (push the saved images
# there first). The digest is dropped then: `docker load` and `docker push` of one platform make a new
# single-platform manifest, whose digest is not the published index's; IMAGES.txt has the ids to compare.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=dist/umbrel
rm -rf "$OUT"
mkdir -p "$OUT/lazarus-store"
cp packaging/umbrel/umbrel-app-store.yml "$OUT/lazarus-store/"
for app in lazarus-xbt-knots lazarus-xbt-agent-wallet lazarus-lightning-stream-gateway lazarus-lightning-stream; do
  cp -r "packaging/umbrel/$app" "$OUT/lazarus-store/"
  if [ -n "${REGISTRY:-}" ]; then
    sed -i -E "s#^(    image: )([a-z0-9.:/-]+/)?(xbt-[a-z0-9-]+:[A-Za-z0-9._-]+)(@sha256:[0-9a-f]{64})?\$#\1$REGISTRY/\3#" \
      "$OUT/lazarus-store/$app/docker-compose.yml"
  fi
done
python3 packaging/pin_images.py --check || { echo "bundle: the store is not pinned to packaging/images.lock" >&2; exit 1; }
IMGS=()
for ref in $(awk '!/^#/ && NF == 2 {print $2}' packaging/images.lock); do
  for plat in amd64 arm64; do
    docker image inspect --platform "linux/$plat" "$ref" >/dev/null 2>&1 || docker pull -q --platform "linux/$plat" "$ref" >/dev/null \
      || { echo "bundle: cannot pull $ref (linux/$plat)" >&2; exit 1; }
  done
  docker tag "$ref" "${ref%@*}"
  IMGS+=("${ref%@*}")
done
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

umbrelOS 2.0 pulls every image of an app from its registry when it installs the app, so `docker load` on
the box is not enough ("pull access denied"). The images must be in a registry the box can pull from, and
the store must name them by it. Built without REGISTRY, the store names the published images on ghcr.io by
digest, and a box with internet access needs nothing more: skip step 2. Built with REGISTRY=host:port, the
store names that registry instead.
  1. sha256sum -c SHA256SUMS
  2. (REGISTRY only) Load images-amd64.tar (a Raspberry Pi: images-arm64.tar; it has no XBT node stand-in)
     on a machine that runs the registry, tag each image REGISTRY/<image>:<tag> (the tag it was saved with,
     IMAGES.txt) and push it. Docker pulls over plain http only from a loopback registry: on the LAN, reach
     it through `ssh -R` to the box's 127.0.0.1, or give it TLS.
  3. Put lazarus-store/ in a git repo the box can reach over http(s) (umbreld's git client speaks smart
     HTTP only; a bare repo served by `git http-backend` will do) and add its URL under App Store ->
     Community App Stores. umbrelOS lists only apps whose id starts with the store's id ("lazarus").
  4. Install Lightning Fork and Knots (BLAKE2b) Companion from their author's community store first.
  5. Install "XBT Agent Wallet" (to buy) and/or "Lightning Stream Gateway" (to sell), or "Lightning
     Stream" (both, plus the connector), selecting Knots (BLAKE2b) Companion for the wallet's node.
     Lightning Stream's connector image is not in these archives until it is published: load
     lightning-stream:0.1.0 from a local build first, or the install cannot pull it.
  6. Wallet: log in with the password the dashboard shows for it; Setup: enrol your approval key, sign a
     policy (the starter template turns Lightning and tickets on); Lightning: paste a macaroon baked in
     Lightning Fork's dashboard with exactly info:read offchain:read offchain:write onchain:read;
     Agents: copy the MCP endpoint and token into your agent.
  7. Gateway: log in the same way; on its page set the service, the price, the https address buyers use
     (a TLS proxy you run, pointed at lazarus-lightning-stream-gateway_gateway_1:8402) and two macaroons
     (invoices:read invoices:write; info:read).
TXT
ls -l "$OUT"
