# The Lightning Fork regtest lab, as scripts/ln_rail_regtest.sh and scripts/hub_ln_link_regtest.sh use
# it (sourced; needs ROOT, and COMPOSE_PROJECT_NAME / COMPOSE_FILE set by the caller for the image
# build). Lab: paulscode/lightning-fork-lab a5cadc5 (Knots v29.4.1 BLAKE2b regtest); Lightning Fork
# cebc10fe, v0.21.3-beta-blake2b.17. Both are cloned under run/ (ignored) and never changed. The node
# binaries are built once, in a container, and kept in the lab's bin/ with the revision and tags they
# were built from. LN_RAIL_GOCACHE: a Go build cache to reuse (default run/gocache).
LAB=$ROOT/run/lightning-fork-lab
LF=$ROOT/run/lightning-fork
LAB_REV=a5cadc5604cd18a0b2f4901ef380cdf4d44ee75a
LF_REV=cebc10fe01e811a38c2830c0396bd3c9182e5d62
# wtclientrpc (AGP-049): ln_status lists the wtclient's towers over REST
LF_TAGS="autopilotrpc signrpc walletrpc chainrpc invoicesrpc watchtowerrpc wtclientrpc peersrpc routerrpc offersrpc"

[ -d "$LAB/.git" ] || git clone -q https://github.com/paulscode/lightning-fork-lab.git "$LAB"
git -C "$LAB" checkout -q "$LAB_REV"
if [ ! -x "$LAB/bin/lnd" ] || [ ! -x "$LAB/bin/lncli" ] || [ "$(cat "$LAB/bin/.tags" 2>/dev/null)" != "$LF_REV $LF_TAGS" ]; then
  [ -d "$LF/.git" ] || git clone -q https://github.com/paulscode/lightning-fork.git "$LF"
  git -C "$LF" cat-file -e "$LF_REV^{commit}" 2>/dev/null || git -C "$LF" fetch -q --tags origin
  git -C "$LF" checkout -q "$LF_REV"
  GOCACHE_DIR=${LN_RAIL_GOCACHE:-$ROOT/run/gocache}
  mkdir -p "$LAB/bin" "$GOCACHE_DIR"
  docker run --rm --cpus=4 -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOWORK=off -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
    -e GOFLAGS=-buildvcs=false -e T="$LF_TAGS" -v "$LF:/src:ro" -v "$GOCACHE_DIR:/cache" -v "$LAB/bin:/out" -w /src golang:1.25.13 \
    sh -c 'go build -tags "$T" -o /out/lnd ./cmd/lnd && go build -tags "$T" -o /out/lncli ./cmd/lncli'
  echo "$LF_REV $LF_TAGS" > "$LAB/bin/.tags"
fi
docker image inspect knots-blake2b:final-zmq >/dev/null 2>&1 || \
  (cd "$LAB/knots" && DOCKER_BUILDKIT=0 docker build --cpuset-cpus=0-3 -t knots-blake2b:final-zmq .)
(cd "$LAB" && docker compose build -q lf1)
