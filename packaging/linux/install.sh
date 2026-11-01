#!/usr/bin/env bash
# Install (or update) Lightning Stream on this Linux machine, beside your own XBT node and Lightning
# node. The guide is docs/LINUX.md. Run it from a checkout of the repository, as a user
# that can use Docker:
#
#   packaging/linux/install.sh [--dir DIR] [--yes]
#
# It checks Docker and its Compose plugin, asks where your nodes are (an LS_* variable in the
# environment, else an answer already in DIR/.env, is the default), writes DIR/docker-compose.yml and DIR/.env
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
# a value .env holds without quotes: nothing in it that Compose or the shell would read otherwise
plain() { [[ $1 =~ ^[A-Za-z0-9_./:,@+-]*$ ]]; }

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
  # an LS_* setting given to this run in the environment wins over the one .env holds (an unattended
  # update that turns something on, or moves a port)
  given=$(for v in $(compgen -e | grep -E '^LS_'); do declare -p "$v"; done)
  kept=$(grep -oE '^LS_[A-Z0-9_]+=' "$DIR/.env" | tr -d =)
  set -a
  # shellcheck source=/dev/null
  . "$DIR/.env"
  set +a
  eval "$given"
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
{ [ -n "$LS_NODE_RPC_USER" ] && [ -n "$LS_NODE_RPC_PASS" ]; } || die "the XBT node's RPC user and password are needed. A cookie changes at every restart, so it cannot be used: if your node has only its cookie, add an rpcauth line for the app (docs/LINUX.md, What you need)"

# the hashtaker's gateway: the Stream Gateway that comes with the app (masking; stratum 127.0.0.1:23339,
# its API on LS_DATUM_API_PORT), or the owner's own. An install from before 0.2.0 has LS_DATUM (its own
# gateway) and no LS_DATUM_GATEWAY: it is moved to the Stream Gateway, since renting refuses jobs that
# aren't masked, and its address is kept as LS_DATUM_OWN to go back to
LS_DATUM_API_PORT=${LS_DATUM_API_PORT:-7153}
BUNDLED_DATUM=127.0.0.1:23339 BUNDLED_API=127.0.0.1:$LS_DATUM_API_PORT
MOVED=0
if [ -z "${LS_DATUM_GATEWAY:-}" ] && [ -n "${LS_DATUM:-}" ] && [ "$LS_DATUM" != "$BUNDLED_DATUM" ]; then
  LS_DATUM_OWN=${LS_DATUM_OWN:-$LS_DATUM}
  # said only to an install being updated: a first install has no "until now"
  [ ! -f "$DIR/.env" ] || MOVED=1
fi
echo
echo "Hashtaker: rented hashrate goes to a DATUM gateway, which builds the blocks. The app comes with one,"
echo "the Stream Gateway (DATUM-compatible), that masks its jobs: a hashmaker can't tell which shares would"
echo "be blocks, so it can't keep those back. Renting needs that: the app checks every job is masked before"
echo "a miner gets it."
if [ "$MOVED" = 1 ]; then
  echo "Until now rented hashrate went to your own DATUM Gateway at $LS_DATUM_OWN. This version moves it to"
  echo "the Stream Gateway (its address is kept in .env as LS_DATUM_OWN; answer 2 to keep yours)."
fi
case ${LS_DATUM_GATEWAY:-} in
  own | 2) gw_def=2 ;;
  bundled | 1 | "") gw_def=1 ;;
  *) die "LS_DATUM_GATEWAY is \"$LS_DATUM_GATEWAY\": use bundled (the Stream Gateway that comes with the app) or own (your own DATUM Gateway)" ;;
esac
LS_DATUM_GATEWAY=''
ask LS_DATUM_GATEWAY "Use the Stream Gateway that comes with the app (1), or your own DATUM Gateway (2)?" "$gw_def"
case $LS_DATUM_GATEWAY in
  1 | bundled) LS_DATUM_GATEWAY=bundled ;;
  2 | own) LS_DATUM_GATEWAY=own ;;
  *) die "answer 1 (the Stream Gateway that comes with the app) or 2 (your own DATUM Gateway), not \"$LS_DATUM_GATEWAY\"" ;;
esac
if [ "$LS_DATUM_GATEWAY" = bundled ]; then
  LS_DATUM=$BUNDLED_DATUM LS_GATEWAY_API=$BUNDLED_API LS_BUNDLED_GATEWAY=$BUNDLED_DATUM
  echo "   The Stream Gateway: once the app is running, choose solo (paid to your own XBT address) or Lazarus"
  echo "   Pool on Services → Hashrate, under Your gateway. It uses your XBT node above."
  if [ "$MOVED" = 1 ]; then say "rented hashrate now goes to the Stream Gateway (yours was $LS_DATUM_OWN)"; fi
else
  echo
  echo "   Rentals need masked jobs. The app opens each job on your gateway's API (/xbt/job) before a miner"
  echo "   gets it, and refuses the rental if the job isn't masked. A stock DATUM Gateway doesn't mask its jobs"
  echo "   and has no /xbt/job, so with one every rental is refused: nothing is paid, and the Hashrate page"
  echo "   says why. Run this again and answer 1 to switch to the Stream Gateway."
  # coming back from the app's gateway: the addresses default to the owner's own again
  if [ "${LS_DATUM:-}" = "$BUNDLED_DATUM" ]; then LS_DATUM=${LS_DATUM_OWN:-}; fi
  if [ "${LS_GATEWAY_API:-}" = "$BUNDLED_API" ]; then LS_GATEWAY_API=''; fi
  ask LS_DATUM "Your DATUM Gateway's Stratum address" "${LS_DATUM_OWN:-127.0.0.1:23334}"
  [[ $LS_DATUM == *:* ]] || die "the Stratum address is host:port, not \"$LS_DATUM\""
  ask LS_GATEWAY_API "Its API address, where the app opens its jobs (/xbt/job)" "${LS_DATUM%:*}:7152"
  [[ $LS_GATEWAY_API == *:* ]] || die "the API address is host:port, not \"$LS_GATEWAY_API\""
  LS_DATUM_OWN=$LS_DATUM
  # the hashtaker would otherwise move a gateway it wasn't given on its page to the Stream Gateway
  LS_BUNDLED_GATEWAY=off
fi
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
echo "VPN: your devices (phone, laptop, TV) send their traffic through VPN exits other people offer,"
echo "paid as you use it, with a WireGuard config the app makes for each one; you can also offer this"
echo "box as an exit. Devices reach it on UDP ${LS_VPN_PORT:-51820} on your LAN (docs/VPN-EXITS.md)."
ask LS_VPN "Install it? 1 for yes, 0 for no" "0"
if [ "$LS_VPN" = 1 ]; then
  COMPOSE_PROFILES=${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}vpn
  LS_VPN_PORT=${LS_VPN_PORT:-51820}
  lan=${LS_LAN_HOST:-$(hostname -I 2>/dev/null | awk '{print $1}')}
  ask LS_VPN_ENDPOINT "The address your devices reach this machine on (LAN address:port)" "${lan:-127.0.0.1}:$LS_VPN_PORT"
  ask LS_VPN_REGION "To offer this box as an exit later, its country (two letters; empty: not announced)" ""
else
  # shellcheck disable=SC2034  # written to .env by name, below
  LS_VPN=0 LS_VPN_ENDPOINT='' LS_VPN_REGION=''
fi

echo
echo "Stream relay: help other people's apps connect when their routers block it (docs/RUN-A-RELAY.md)."
echo "It takes this machine's public port 443, so it suits a server with a public address. You switch it"
echo "on, with your domain name, in the app afterwards (Settings → Stream relays); this only installs it."
ask LS_RELAY "Install it? 1 for yes, 0 for no" "0"
if [ "$LS_RELAY" = 1 ]; then
  COMPOSE_PROFILES=${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}relay
else
  LS_RELAY=0
fi

echo
if [ -z "${LS_UI_PASSWORD:-}" ]; then
  LS_UI_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr '+/' '-_')
  [ "$YES" = 1 ] || ask_secret LS_UI_PASSWORD "A password for the app's page (empty: a random one, saved in $DIR/.env)"
fi
LS_DATA_DIR=${LS_DATA_DIR:-$DIR/data}
LS_CHAIN=${LS_CHAIN:-main}
# the chain's name as the node itself says it (getblockchaininfo), not its common name: "mainnet" here
# would stop the signer at its start with "the node is on main"
case $LS_CHAIN in
  main | test | testnet4 | signet | regtest) ;;
  mainnet) die "LS_CHAIN is \"mainnet\": use \"main\", the name your node gives it" ;;
  *) die "LS_CHAIN is \"$LS_CHAIN\": use main, test, testnet4, signet or regtest, the name your node gives its chain" ;;
esac
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-lightning-stream}
LS_UI_PORT=${LS_UI_PORT:-8482} LS_MCP_PORT=${LS_MCP_PORT:-33511} LS_CONNECTOR_PORT=${LS_CONNECTOR_PORT:-8484} LS_APP_PORTS=${LS_APP_PORTS:-33521,33522,33523,33524}
LS_GW_PORT=${LS_GW_PORT:-8402} LS_HASHTAKER_CONTROL_PORT=${LS_HASHTAKER_CONTROL_PORT:-23343} LS_FILES_PORT=${LS_FILES_PORT:-8486}
LS_RELAYS=${LS_RELAYS:-wss://relay.lazarus-xbt.xyz,wss://relay.kilombino.com,wss://relay.damus.io,wss://nos.lol} LS_LAN_HOST=${LS_LAN_HOST:-}

# --- 3. the files -------------------------------------------------------------------------------------
say "writing $DIR/docker-compose.yml and $DIR/.env"
[ "$HERE" = "$DIR" ] || cp "$HERE/docker-compose.yml" "$DIR/docker-compose.yml"
mkdir -p "$LS_DATA_DIR"
(
  umask 077
  {
    echo "# Lightning Stream: written by install.sh on $(date -u +%Y-%m-%d). It holds passwords: keep it private."
    line() { # KEY: a plain value as it is, so what you read is what you type (the random password is one);
      # any other in single quotes, which Compose and the shell both take as they are ($ and spaces included)
      local v=${!1:-}
      case $v in *"'"*) die "$1 may not contain a single quote" ;; esac
      if plain "$v"; then printf "%s=%s\n" "$1" "$v"; else printf "%s='%s'\n" "$1" "$v"; fi
    }
    asked=" COMPOSE_PROJECT_NAME LS_DATA_DIR LS_CHAIN LS_UI_PASSWORD LS_LND_REST LS_LND_TLS_CERT LS_NODE_RPC_HOST LS_NODE_RPC_PORT
            LS_NODE_RPC_USER LS_NODE_RPC_PASS LS_DATUM_GATEWAY LS_DATUM LS_GATEWAY_API LS_DATUM_OWN LS_DATUM_API_PORT LS_BUNDLED_GATEWAY
            LS_DATUM_USER LS_HASHMAKER LS_RELAY LS_VPN LS_VPN_PORT LS_VPN_ENDPOINT LS_VPN_REGION
            LS_LAN_HOST COMPOSE_PROFILES LS_UI_HASHMAKER LS_UI_HASHMAKER_SLICES LS_UI_PORT LS_MCP_PORT LS_CONNECTOR_PORT LS_APP_PORTS
            LS_GW_PORT LS_HASHTAKER_CONTROL_PORT LS_RELAYS LS_FILES_PORT "
    for k in $asked; do line "$k"; done
    # and every other setting the app's compose file reads, or the old .env held (one added by hand, or by a
    # later version), when it is set: an update keeps it, and one given to this run is written
    for k in $( { grep -oE '\$\{LS_[A-Z0-9_]+' "$HERE/docker-compose.yml" | cut -c3-; echo "${kept:-}"; } | sort -u); do
      case $asked in *[[:space:]]"$k"[[:space:]]*) continue ;; esac
      case $k in LS_SKIP_PULL | LS_ADMIN_MACAROON | LS_BITCOIN_CONF) continue ;; esac
      if [ -n "${!k+x}" ]; then line "$k"; fi
    done
  } > "$DIR/.env.tmp"
  mv "$DIR/.env.tmp" "$DIR/.env"
)
cd "$DIR"
docker compose config -q || die "the settings do not work together (docker compose config says why, above)"

# --- 4. the images, the keys, the start ---------------------------------------------------------------
if [ "${LS_SKIP_PULL:-0}" != 1 ]; then
  say "downloading the app's images (pinned by digest)"
  docker compose --profile setup --profile hashmaker --profile relay --profile vpn pull -q
fi

# the admin macaroon is offered where lnd keeps it; empty skips this step (the app's pages take narrow ones later)
FOUND=$LND_DIR/data/chain/bitcoin/mainnet/admin.macaroon
ADMIN=${LS_ADMIN_MACAROON:-}
if [ -s "$LS_DATA_DIR/run/ln/rail.macaroon" ] 2>/dev/null || sudo -n test -s "$LS_DATA_DIR/run/ln/rail.macaroon" 2>/dev/null; then
  say "the app's Lightning keys are already made; keeping them"
else
  exists() { [ -e "$1" ] || sudo -n test -e "$1" 2>/dev/null; }
  if [ "$YES" = 1 ]; then
    # unattended: the macaroon named in LS_ADMIN_MACAROON, else the one where lnd keeps it, else none
    [ -n "$ADMIN" ] || { exists "$FOUND" && ADMIN=$FOUND; }
  else
    echo
    echo "The app now asks your Lightning node for its own narrow keys (macaroons), made from your admin"
    echo "macaroon. It is read here, handed over once, and never saved. Leave it empty to skip: you can"
    echo "paste narrow macaroons on the app's Lightning and Sell pages instead (docs/LINUX.md)."
    exists "$FOUND" && echo "Yours looks to be at: $FOUND"
    read -r -p "Path to your admin macaroon (empty: skip): " ADMIN </dev/tty
  fi
  if [ -z "$ADMIN" ]; then
    say "no admin macaroon: skipped. Connect your Lightning node on the app's Lightning page"
  else
    exists "$ADMIN" || die "there is no file at $ADMIN. Give the path to your admin macaroon, or leave it empty to skip"
    if [ -r "$ADMIN" ]; then
      reader=(cat -- "$ADMIN")
    elif sudo -n true 2>/dev/null || [ "$YES" != 1 ]; then
      echo "(this user cannot read it; reading it with sudo)"
      reader=(sudo cat -- "$ADMIN")
    else
      die "this user cannot read $ADMIN (and sudo would ask for a password): run install.sh as a user that can, or leave it empty to skip"
    fi
    say "making the app's keys through your Lightning node"
    "${reader[@]}" >/dev/null || die "could not read $ADMIN"
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

# the shared folder of a Files service is served on 127.0.0.1:LS_FILES_PORT, and answers / with 204: another
# program on that port keeps it from the app, and would answer buyers in its place
files=$( { exec 3<>"/dev/tcp/127.0.0.1/$LS_FILES_PORT" && printf 'GET / HTTP/1.0\r\n\r\n' >&3 && timeout 5 head -1 <&3; } 2>/dev/null | tr -d '\r' || true)
case $files in
  "HTTP/1."?" 204"*) ;;
  "") echo "install: warning: nothing serves the Files folder on 127.0.0.1:$LS_FILES_PORT (docker compose -f $DIR/docker-compose.yml logs ui says why)" >&2 ;;
  *) echo "install: warning: another program uses 127.0.0.1:$LS_FILES_PORT, so the app cannot serve the Files folder there. Set LS_FILES_PORT in $DIR/.env to a free port and run install.sh again (or stop that program)" >&2 ;;
esac

cat <<EOF

Lightning Stream is running.
  Its page:     http://127.0.0.1:${LS_UI_PORT:-8482}/  (from another machine: ssh -L ${LS_UI_PORT:-8482}:127.0.0.1:${LS_UI_PORT:-8482} $(id -un)@this-machine, then open that address)
  Its password: $(if plain "$LS_UI_PASSWORD"; then echo "everything after LS_UI_PASSWORD= in $DIR/.env"; else echo "LS_UI_PASSWORD in $DIR/.env, without the single quotes around it"; fi)
                (to see it: grep LS_UI_PASSWORD $DIR/.env)
  Next:         make your approval key, sign the safe starter rules, then Services → Hashrate (docs/LINUX.md)
  Stop / start: docker compose -f $DIR/docker-compose.yml down / up -d
EOF
