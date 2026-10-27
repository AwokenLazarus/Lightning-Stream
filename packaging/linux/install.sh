#!/usr/bin/env bash
# Install (or update) Lightning Stream on this Linux machine, beside your own XBT node, Lightning node
# and DATUM Gateway. The guide is docs/LINUX.md. Run it from a checkout of the repository, as a user
# that can use Docker:
#
#   packaging/linux/install.sh [--dir DIR] [--yes]
#
# It checks Docker and its Compose plugin, asks where your nodes are (an answer already in DIR/.env,
# or an LS_* variable in the environment, is the default), writes DIR/docker-compose.yml and DIR/.env
# (mode 600), has your Lightning node bake the app's narrow macaroons from your admin macaroon (read
# here and passed on standard input: it is never written anywhere), and starts the app. --yes takes
# every default without asking. Nothing is downloaded but the app's pinned images.
set -euo pipefail
# the app's own files only: a COMPOSE_FILE from the caller's shell would name others
unset COMPOSE_FILE

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=${LS_INSTALL_DIR:-$HOME/lightning-stream}
YES=0
while [ $# -gt 0 ]; do
  case $1 in
    --dir) DIR=$2; shift 2 ;;
    --yes) YES=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "install: unknown option $1 (try --help)" >&2; exit 2 ;;
  esac
done
DIR=$(mkdir -p "$DIR" && cd "$DIR" && pwd)

die() { echo "install: $*" >&2; exit 1; }
say() { echo "== $*"; }

# --- 1. what it needs ---------------------------------------------------------------------------------
say "checking Docker"
command -v docker >/dev/null || die "Docker is not installed. On Ubuntu: sudo apt install docker.io docker-compose-v2 (or Docker's own packages: https://docs.docker.com/engine/install/ubuntu/)"
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing. On Ubuntu: sudo apt install docker-compose-v2"
cv=$(docker compose version --short 2>/dev/null | sed 's/^v//')
case $cv in
  1.*|2.[0-9]|2.[0-9].*|2.1[0-9]|2.1[0-9].*) die "Docker Compose $cv is too old: 2.20 or newer is needed" ;;
esac
docker info >/dev/null 2>&1 || die "this user cannot use Docker. Add it to the docker group (sudo usermod -aG docker $USER, then log out and in) or run this with sudo"
case $(uname -m) in
  x86_64|aarch64|arm64|armv7l) ;;
  *) die "this machine is $(uname -m); the app's images are for x86_64, arm64 and armv7" ;;
esac

# --- 2. the settings ----------------------------------------------------------------------------------
# an existing .env is the default for every answer (an update keeps your settings)
if [ -f "$DIR/.env" ]; then
  say "keeping the settings in $DIR/.env as defaults"
  set -a
  # shellcheck source=/dev/null
  . "$DIR/.env"
  set +a
fi

ask() { # VAR "question" default
  local var=$1 q=$2 def=${!1:-$3} a
  if [ "$YES" = 1 ]; then printf -v "$var" %s "$def"; return; fi
  read -r -p "$q [$def]: " a </dev/tty
  printf -v "$var" %s "${a:-$def}"
}
ask_secret() { # VAR "question": an empty answer keeps what is there
  local var=$1 q=$2 a
  if [ "$YES" = 1 ]; then return; fi
  read -r -s -p "$q${!var:+ [keep the one set]}: " a </dev/tty; echo
  [ -z "$a" ] || printf -v "$var" %s "$a"
}
conf_value() { # KEY FILE: a top-level key of a bitcoin.conf, before the first [section]
  [ -r "$2" ] || return 0
  awk -F= -v k="$1" '/^\[/{exit} $1==k{sub(/^[^=]*=/,""); v=$0} END{if (v!="") print v}' "$2"
}

echo
echo "Your Lightning node (lnd-family, such as Lightning Fork). The app talks to its REST interface."
ask LS_LND_REST "Its REST address" "https://127.0.0.1:8080"
ask LND_DIR "Its data folder (with tls.cert and data/chain/...)" "$HOME/.lnd"
ask LS_LND_TLS_CERT "Its TLS certificate" "$LND_DIR/tls.cert"
[ -f "$LS_LND_TLS_CERT" ] || die "no certificate at $LS_LND_TLS_CERT"

echo
echo "Your XBT node (Knots BLAKE2b): its RPC, which the wallet asks about the chain."
ask LS_BITCOIN_CONF "Its config file (read for rpcuser, rpcpassword and rpcport)" "$HOME/.bitcoin/bitcoin.conf"
LS_NODE_RPC_USER=${LS_NODE_RPC_USER:-$(conf_value rpcuser "$LS_BITCOIN_CONF")}
LS_NODE_RPC_PASS=${LS_NODE_RPC_PASS:-$(conf_value rpcpassword "$LS_BITCOIN_CONF")}
LS_NODE_RPC_PORT=${LS_NODE_RPC_PORT:-$(conf_value rpcport "$LS_BITCOIN_CONF")}
ask LS_NODE_RPC_HOST "Its RPC host" "127.0.0.1"
ask LS_NODE_RPC_PORT "Its RPC port" "8332"
ask LS_NODE_RPC_USER "Its RPC user" ""
[ -n "$LS_NODE_RPC_PASS" ] || ask_secret LS_NODE_RPC_PASS "Its RPC password"
{ [ -n "$LS_NODE_RPC_USER" ] && [ -n "$LS_NODE_RPC_PASS" ]; } || die "the XBT node's RPC user and password are needed (rpcuser and rpcpassword in its config; a cookie changes at every restart, so it cannot be used)"

echo
echo "Hashtaker: rented hashrate goes to your own DATUM Gateway."
ask LS_DATUM "Your DATUM Gateway's Stratum address" "127.0.0.1:23334"
ask LS_DATUM_USER "The user name rented miners use on it" "rented"

echo
echo "Hashmaker: rent this machine's miners out to others (you can turn it on later by running this again)."
ask LS_HASHMAKER "Turn it on? 1 for yes, 0 for no" "0"
if [ "$LS_HASHMAKER" = 1 ]; then
  lan=$(hostname -I 2>/dev/null | awk '{print $1}')
  ask LS_LAN_HOST "This machine's LAN address, which your miners point at" "${lan:-127.0.0.1}"
  COMPOSE_PROFILES=hashmaker
  LS_UI_HASHMAKER=http://127.0.0.1:23342
  LS_UI_HASHMAKER_SLICES=http://127.0.0.1:23344
else
  # shellcheck disable=SC2034  # written to .env by name, below
  LS_HASHMAKER=0 COMPOSE_PROFILES='' LS_UI_HASHMAKER='' LS_UI_HASHMAKER_SLICES=''
fi

echo
if [ -z "${LS_UI_PASSWORD:-}" ]; then
  LS_UI_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr '+/' '-_')
  [ "$YES" = 1 ] || ask_secret LS_UI_PASSWORD "A password for the app's page (empty: a random one, saved in $DIR/.env)"
fi
LS_DATA_DIR=${LS_DATA_DIR:-$DIR/data}
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-lightning-stream}
LS_UI_PORT=${LS_UI_PORT:-8482} LS_MCP_PORT=${LS_MCP_PORT:-33511} LS_CONNECTOR_PORT=${LS_CONNECTOR_PORT:-8484}
LS_GW_PORT=${LS_GW_PORT:-8402} LS_HASHTAKER_CONTROL_PORT=${LS_HASHTAKER_CONTROL_PORT:-23343}
LS_RELAYS=${LS_RELAYS:-wss://relay.lazarus-xbt.xyz,wss://relay.kilombino.com,wss://relay.damus.io,wss://nos.lol} LS_LAN_HOST=${LS_LAN_HOST:-}

# --- 3. the files -------------------------------------------------------------------------------------
say "writing $DIR/docker-compose.yml and $DIR/.env"
[ "$HERE" = "$DIR" ] || cp "$HERE/docker-compose.yml" "$DIR/docker-compose.yml"
mkdir -p "$LS_DATA_DIR"
(
  umask 077
  {
    echo "# Lightning Stream: written by install.sh on $(date -u +%Y-%m-%d). It holds passwords: keep it private."
    for k in COMPOSE_PROJECT_NAME LS_DATA_DIR LS_UI_PASSWORD LS_LND_REST LS_LND_TLS_CERT LS_NODE_RPC_HOST LS_NODE_RPC_PORT LS_NODE_RPC_USER \
             LS_NODE_RPC_PASS LS_DATUM LS_DATUM_USER LS_HASHMAKER LS_LAN_HOST COMPOSE_PROFILES LS_UI_HASHMAKER \
             LS_UI_HASHMAKER_SLICES LS_UI_PORT LS_MCP_PORT LS_CONNECTOR_PORT LS_GW_PORT LS_HASHTAKER_CONTROL_PORT LS_RELAYS; do
      v=${!k:-}
      # single quotes: Compose and the shell both take the value as it is ($ and spaces included)
      case $v in *"'"*) die "$k may not contain a single quote" ;; esac
      printf "%s='%s'\n" "$k" "$v"
    done
  } > "$DIR/.env.tmp"
  mv "$DIR/.env.tmp" "$DIR/.env"
)
cd "$DIR"
docker compose config -q || die "the settings do not work together (docker compose config says why, above)"

# --- 4. the images, the keys, the start ---------------------------------------------------------------
if [ "${LS_SKIP_PULL:-0}" != 1 ]; then
  say "downloading the app's images (pinned by digest)"
  docker compose --profile setup --profile hashmaker pull -q
fi

ADMIN=${LS_ADMIN_MACAROON:-$LND_DIR/data/chain/bitcoin/mainnet/admin.macaroon}
if [ -s "$LS_DATA_DIR/run/ln/rail.macaroon" ] 2>/dev/null || sudo -n test -s "$LS_DATA_DIR/run/ln/rail.macaroon" 2>/dev/null; then
  say "the app's Lightning keys are already made; keeping them"
else
  echo
  echo "The app now asks your Lightning node for its own narrow keys (macaroons), made from your admin"
  echo "macaroon. It is read here, handed over once, and never saved. Leave it empty to skip: you can"
  echo "paste narrow macaroons on the app's Lightning and Sell pages instead (docs/LINUX.md)."
  ask ADMIN "Your admin macaroon" "$ADMIN"
  if [ -n "$ADMIN" ]; then
    if [ -r "$ADMIN" ]; then
      reader=(cat -- "$ADMIN")
    elif sudo -n true 2>/dev/null || [ "$YES" != 1 ]; then
      echo "(this user cannot read it; reading it with sudo)"
      reader=(sudo cat -- "$ADMIN")
    else
      die "cannot read $ADMIN"
    fi
    say "making the app's keys through your Lightning node"
    "${reader[@]}" | docker compose --profile setup run --rm -T node-keys || die "your Lightning node did not make the keys (above: why). Is it running and unlocked, and is $LS_LND_REST its REST address?"
  fi
fi

say "starting the app"
docker compose up -d
for _ in $(seq 90); do
  h=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$(docker compose ps -q ui)" 2>/dev/null || true)
  [ "$h" = healthy ] && break
  sleep 2
done
[ "$h" = healthy ] || die "the app's page did not come up; see: docker compose -f $DIR/docker-compose.yml logs ui"

cat <<EOF

Lightning Stream is running.
  Its page:     http://127.0.0.1:${LS_UI_PORT:-8482}/  (from another machine: ssh -L ${LS_UI_PORT:-8482}:127.0.0.1:${LS_UI_PORT:-8482} $(id -un)@this-machine, then open that address)
  Its password: in $DIR/.env (LS_UI_PASSWORD)
  Next:         make your approval key, sign the safe starter rules, then Services → Hashrate (docs/LINUX.md)
  Stop / start: docker compose -f $DIR/docker-compose.yml down / up -d
EOF
