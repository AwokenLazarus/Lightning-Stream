#!/bin/bash
# Build the StartOS package (packaging/startos/lightning-stream: the whole app, as the Umbrel app is) into
# dist/startos/: lightning-stream_x86_64.s9pk and lightning-stream_aarch64.s9pk. Publishing to a registry is
# its own step (docs/STARTOS.md): never `make publish`.
#   - packs the published images the specs pin (packaging/images.lock, ghcr.io/awokenlazarus/<image>:<tag>@<digest>):
#     a .s9pk carries its images, so a server installs it without a registry; pack takes each arch from the local
#     Docker, so a pinned image missing there is pulled first (by digest);
#   - start-cli 2.1.0 (START_CLI, default ~/.local/opt/start-cli/start-cli) and the tar2sqfs shim (tools/);
#   - node/npm for the TypeScript (npm ci, tsc, the SDK's eslint, ncc).
# start-cli packs only inside a packaging workspace (a directory with .startos/: its config and the build key
# that signs the package). It lives outside the repo, so no key is committed: STARTOS_WS, default
# ~/.local/share/xbt-startos-ws, made once with `start-cli s9pk init-workspace`. packaging/startos/.startos is a
# git-ignored symlink to it, so the package is packed in place and its manifest records the commit.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PKGS=(lightning-stream)
START_CLI=${START_CLI:-$HOME/.local/opt/start-cli/start-cli}
[ -x "$START_CLI" ] || { echo "build: start-cli missing at $START_CLI (github.com/Start9Labs/start-technologies releases, start-cli/v2.1.0)" >&2; exit 1; }
python3 "$ROOT/packaging/pin_images.py" --check || { echo "build: the specs are not pinned to packaging/images.lock" >&2; exit 1; }
for ref in $(awk '!/^#/ && NF == 2 {print $2}' "$ROOT/packaging/images.lock"); do
  for p in linux/amd64 linux/arm64; do
    docker image inspect --platform "$p" "$ref" >/dev/null 2>&1 || docker pull -q --platform "$p" "$ref" >/dev/null \
      || { echo "build: cannot pull $ref ($p)" >&2; exit 1; }
  done
done
BIN=$(mktemp -d)
trap 'rm -rf "$BIN"' EXIT
ln -s "$START_CLI" "$BIN/start-cli"
export PATH=$BIN:$HERE/tools:$PATH
WS=${STARTOS_WS:-$HOME/.local/share/xbt-startos-ws}
if [ ! -f "$WS/.startos/config.yaml" ]; then
  mkdir -p "$WS"
  (cd "$WS" && start-cli s9pk init-workspace .)
fi
ln -sfn "$WS/.startos" "$HERE/.startos"
mkdir -p "$ROOT/dist/startos"
for pkg in "${PKGS[@]}"; do
  cd "$HERE/$pkg"
  [ -d node_modules ] || npm ci --no-audit --no-fund
  npm run -s check
  node node_modules/@start9labs/start-sdk/lint.mjs
  npm run -s build
  for arch in x86_64 aarch64; do
    echo "== pack $pkg $arch"
    start-cli s9pk pack --arch="$arch" -o "$ROOT/dist/startos/${pkg}_$arch.s9pk"
  done
done
ls -l "$ROOT/dist/startos/"
