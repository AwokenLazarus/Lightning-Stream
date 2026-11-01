#!/bin/bash
# The source tarballs of the LGPL libraries the Stream Gateway image (xbt-datum-gateway) links statically,
# libmicrohttpd and argp-standalone, as the release attaches them: the exact files
# scripts/datum_gateway_build.sh built from, each checked against the sha256 that script pins, plus a
# SHA256SUMS of them. The GNU LGPL lets anyone relink the gateway against a modified copy of these
# libraries; the release carries their source so that it is at hand from us, not only from upstream.
#
#   scripts/datum_gateway_sources.sh OUTDIR
#
# The tarballs are taken from XBT_DATUM_DEPS (default ~/.cache/xbt-datum-deps, where the build fetched them)
# when their hash matches, and fetched from the build script's own URLs otherwise. Any mismatch stops it.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${1:?usage: scripts/datum_gateway_sources.sh OUTDIR}
BUILD=scripts/datum_gateway_build.sh
[ -f "$BUILD" ] || { echo "datum_gateway_sources: no $BUILD in this tree (the Stream Gateway is not in it)" >&2; exit 1; }
CACHE=${XBT_DATUM_DEPS:-$HOME/.cache/xbt-datum-deps}
LIBS=(libmicrohttpd argp-standalone)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
names=()
for lib in "${LIBS[@]}"; do
  # the build script's pin line: "<file> <url>[|<mirror>...] <sha256>"
  line=$(grep -E "^ *\"$lib-[0-9][^ ]* [^ ]+ [0-9a-f]{64}\"$" "$BUILD" | tr -d '"' | sed 's/^ *//') || true
  [ "$(printf '%s\n' "$line" | grep -c .)" = 1 ] || { echo "datum_gateway_sources: no single pin for $lib in $BUILD" >&2; exit 1; }
  read -r name url sum <<<"$line"
  f=$OUT/$name
  if [ -f "$CACHE/$name" ] && [ "$(sha256sum "$CACHE/$name" | cut -d' ' -f1)" = "$sum" ]; then
    cp "$CACHE/$name" "$f"
  else
    IFS='|' read -r -a urls <<<"$url"
    got=0
    for u in "${urls[@]}"; do
      if curl -fsSL --retry 3 --retry-delay 5 --max-time 300 -o "$f.part" "$u"; then got=1; break; fi
    done
    [ "$got" = 1 ] || { echo "datum_gateway_sources: could not fetch $name" >&2; exit 1; }
    mv "$f.part" "$f"
  fi
  have=$(sha256sum "$f" | cut -d' ' -f1)
  [ "$have" = "$sum" ] || { echo "datum_gateway_sources: $name has sha256 $have, not the pinned $sum" >&2; rm -f "$f"; exit 1; }
  names+=("$name")
done
(cd "$OUT" && sha256sum "${names[@]}" > SHA256SUMS-datum-gateway-lgpl && cat SHA256SUMS-datum-gateway-lgpl)
