#!/bin/bash
# install.sh's own steps, without Docker or nodes: a stand-in `docker` answers what install.sh asks
# and records what it is handed. Checks the admin macaroon step (given, missing, none at all) and
# what .env holds. Prints RESULT PASS|FAIL. Run by packaging/linux/test-linux.sh; needs only bash.
set -uo pipefail
PKG=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
trap '[ -n "${KEEP_T:-}" ] || rm -rf "$T"' EXIT
mkdir -p "$T/bin"
cat > "$T/bin/docker" <<'STUB'
#!/bin/bash
# the stand-in: Compose 2.29, a docker the user may use, every container healthy
case "$*" in
  "compose version --short") echo 2.29.0 ;;
  "compose version"|info) echo ok ;;
  *"run --rm -T node-keys"*) cat > "$STUB_OUT/handed"; echo "node-keys handed $(wc -c < "$STUB_OUT/handed") bytes" ;;
  *"ps -q ui"*) echo c0ffee ;;
  inspect*) echo healthy ;;
  *) : ;;
esac
STUB
chmod +x "$T/bin/docker"
fails=0
run() { # name, then KEY=VALUE settings for install.sh; leaves its output in $T/<name>.out
  local name=$1; shift
  mkdir -p "$T/$name"
  env -i PATH="$T/bin:/usr/bin:/bin" HOME="$T/$name/home" STUB_OUT="$T/$name" LS_SKIP_PULL=1 \
      LS_LND_REST=https://127.0.0.1:8080 LS_LND_TLS_CERT="$T/tls.cert" LS_BITCOIN_CONF=/nonexistent \
      LS_NODE_RPC_PORT=8332 LS_NODE_RPC_USER=u LS_NODE_RPC_PASS=p LS_HASHMAKER=0 "$@" \
      "$PKG/install.sh" --yes --dir "$T/$name/app" > "$T/$name.out" 2>&1
  echo $? > "$T/$name.rc"
}
ok() { # what, condition result
  if [ "$2" = 0 ]; then echo "  ok   $1"; else echo "  FAIL $1"; sed 's/^/       /' "$3" | tail -8; fails=$((fails + 1)); fi
}
printf 'macaroon-bytes' > "$T/admin.macaroon"
echo cert > "$T/tls.cert"
run given LS_ADMIN_MACAROON="$T/admin.macaroon" LS_UI_PASSWORD='with space$'
grep -qx 0 "$T/given.rc" && cmp -s "$T/given/handed" "$T/admin.macaroon"; ok "a macaroon named is handed to the node, and the install goes on" $? "$T/given.out"
run missing LS_ADMIN_MACAROON="$T/nope.macaroon"
grep -qx 1 "$T/missing.rc" && grep -q "there is no file at $T/nope.macaroon" "$T/missing.out" && ! grep -q "Lightning node did not" "$T/missing.out"
ok "a macaroon that is not there is said so, and the node is not blamed" $? "$T/missing.out"
run none
grep -qx 0 "$T/none.rc" && [ ! -e "$T/none/handed" ] && grep -q "no admin macaroon: skipped" "$T/none.out"
ok "with none, the step is skipped and the install goes on" $? "$T/none.out"
grep -q "^LS_UI_PASSWORD='with space\$'$" "$T/given/app/.env" && grep -qx "LS_CHAIN=main" "$T/given/app/.env" \
  && grep -q "without the single quotes" "$T/given.out"
ok ".env: a password with signs in quotes, said so at the end; a plain value as it is" $? "$T/given/app/.env"
pw=$(sed -n 's/^LS_UI_PASSWORD=//p' "$T/none/app/.env")
[[ $pw =~ ^[A-Za-z0-9_-]{24}$ ]] && grep -q "everything after LS_UI_PASSWORD=" "$T/none.out"
ok "a random password is written without quotes, and the end says to type all of it" $? "$T/none/app/.env"

# an update: every setting the old .env holds is kept, the ones install.sh does not ask about included
old_env() { # name, then the lines of the .env an earlier install wrote
  local name=$1; shift
  mkdir -p "$T/$name/app"
  printf '%s\n' "$@" > "$T/$name/app/.env"
}
old_env update LS_UI_PORT=8490 LS_AI_BIND=0.0.0.0:33540 LS_VPN_TUNNEL_PORT=51990 LS_FILES_PORT=8496 \
  LS_SUGGESTED_SELLERS= LS_BY_HAND=kept "LS_UI_PASSWORD='old pass'"
run update LS_COLORS='di=01;34'
e=$T/update/app/.env
grep -qx 0 "$T/update.rc" && grep -qx LS_AI_BIND=0.0.0.0:33540 "$e" && grep -qx LS_VPN_TUNNEL_PORT=51990 "$e" \
  && grep -qx LS_FILES_PORT=8496 "$e" && grep -qx LS_UI_PORT=8490 "$e" && grep -qx LS_SUGGESTED_SELLERS= "$e" \
  && grep -qx LS_BY_HAND=kept "$e" && grep -qx "LS_UI_PASSWORD='old pass'" "$e"
ok "an update keeps every setting the old .env holds (the AI bind, the VPN tunnel port, Files, one added by hand)" $? "$e"
! grep -q '^LS_COLORS' "$e" && [ "$(grep -vc "^#" "$e")" = "$(grep -o '^[A-Z_0-9]*=' "$e" | sort -u | grep -c .)" ]
ok "nothing from the shell that is not the app's, and each setting once" $? "$e"

# --yes over an existing .env: a setting given to the run wins, and is written
old_env given_env LS_UI_PORT=8490 LS_AI_BIND=127.0.0.1:33540 LS_HASHMAKER=0 LS_RELAY=0
run given_env LS_UI_PORT=9001 LS_AI_BIND=0.0.0.0:33541 LS_RELAY=1 LS_VPN_TUNNEL_PORT=52000
e=$T/given_env/app/.env
grep -qx 0 "$T/given_env.rc" && grep -qx LS_UI_PORT=9001 "$e" && grep -qx LS_AI_BIND=0.0.0.0:33541 "$e" \
  && grep -qx LS_RELAY=1 "$e" && grep -qx COMPOSE_PROFILES=relay "$e" && grep -qx LS_VPN_TUNNEL_PORT=52000 "$e" \
  && grep -q "127.0.0.1:9001" "$T/given_env.out"
ok "--yes: settings in the environment win over .env, are written, and are used (the relay turned on, the page's port)" $? "$e"

# the hashtaker's gateway: the Stream Gateway by default, masked jobs checked on its API, never unmasked
e=$T/none/app/.env
grep -qx LS_DATUM_GATEWAY=bundled "$e" && grep -qx LS_DATUM=127.0.0.1:23339 "$e" && grep -qx LS_GATEWAY_API=127.0.0.1:7153 "$e" \
  && grep -qx LS_DATUM_API_PORT=7153 "$e" && ! grep -q "Until now" "$T/none.out"
ok "a first install: the Stream Gateway (stratum 127.0.0.1:23339, API 127.0.0.1:7153), nothing said of a move" $? "$e"
c=$PKG/docker-compose.yml
grep -q '"--upstream", "${LS_DATUM:-127.0.0.1:23339}", "--gateway-api", "${LS_GATEWAY_API:-127.0.0.1:7153}"' "$c" \
  && ! grep -q allow-unblinded "$c" && grep -q '^  datum:$' "$c" && ! sed -n '/^  datum:$/,/^  [a-z]/p' "$c" | grep -q profiles \
  && grep -q 'XBT_INIT_COMPONENTS: .*,datum$' "$c"
ok "compose: the renter opens jobs on the gateway's API, is never told to allow unmasked jobs; the gateway is on by default" $? "$c"

# an update from 0.1: its own gateway's address in .env, no choice yet: moved to the Stream Gateway, the old address kept
old_env from01 LS_DATUM=127.0.0.1:23334 LS_DATUM_USER=renter1 LS_UI_PORT=8490 "LS_UI_PASSWORD='old pass'" LS_HASHMAKER=0
run from01
e=$T/from01/app/.env
grep -qx 0 "$T/from01.rc" && grep -qx LS_DATUM_GATEWAY=bundled "$e" && grep -qx LS_DATUM=127.0.0.1:23339 "$e" \
  && grep -qx LS_GATEWAY_API=127.0.0.1:7153 "$e" && grep -qx LS_DATUM_OWN=127.0.0.1:23334 "$e" && grep -qx LS_DATUM_USER=renter1 "$e" \
  && grep -qx LS_UI_PORT=8490 "$e" && grep -qx "LS_UI_PASSWORD='old pass'" "$e" \
  && grep -q "Until now rented hashrate went to your own DATUM Gateway at 127.0.0.1:23334" "$T/from01.out" \
  && grep -q "rented hashrate now goes to the Stream Gateway (yours was 127.0.0.1:23334)" "$T/from01.out"
ok "an update from 0.1 moves renting to the Stream Gateway, says so, keeps the old address (LS_DATUM_OWN) and every other setting" $? "$T/from01.out"
run from01
grep -qx 0 "$T/from01.rc" && grep -qx LS_DATUM_GATEWAY=bundled "$e" && grep -qx LS_DATUM_OWN=127.0.0.1:23334 "$e" && ! grep -q "Until now" "$T/from01.out"
ok "run again: stays on the Stream Gateway, nothing said again" $? "$T/from01.out"

# the owner's own gateway: chosen, the masking need said plainly, its API asked (default the same host, 7152)
run own LS_DATUM_GATEWAY=own LS_DATUM=192.168.1.5:23334
e=$T/own/app/.env
grep -qx 0 "$T/own.rc" && grep -qx LS_DATUM_GATEWAY=own "$e" && grep -qx LS_DATUM=192.168.1.5:23334 "$e" \
  && grep -qx LS_GATEWAY_API=192.168.1.5:7152 "$e" && grep -q "Rentals need masked jobs" "$T/own.out" \
  && grep -q "A stock DATUM Gateway doesn't mask its jobs" "$T/own.out" && grep -q "every rental is refused" "$T/own.out"
ok "your own gateway: kept with its API (host:7152), and said plainly that rentals need masked jobs" $? "$T/own.out"
cp "$e" "$T/own.env"
mkdir -p "$T/back/app" && cp "$T/own.env" "$T/back/app/.env"
run back LS_DATUM_GATEWAY=bundled
e=$T/back/app/.env
grep -qx 0 "$T/back.rc" && grep -qx LS_DATUM=127.0.0.1:23339 "$e" && grep -qx LS_GATEWAY_API=127.0.0.1:7153 "$e" && grep -qx LS_DATUM_OWN=192.168.1.5:23334 "$e"
ok "and back to the Stream Gateway: its addresses, yours kept" $? "$e"
mkdir -p "$T/again/app" && cp "$e" "$T/again/app/.env"
run again LS_DATUM_GATEWAY=own
e=$T/again/app/.env
grep -qx 0 "$T/again.rc" && grep -qx LS_DATUM=192.168.1.5:23334 "$e" && grep -qx LS_GATEWAY_API=192.168.1.5:7152 "$e"
ok "and to yours again: your address comes back, not the Stream Gateway's" $? "$e"
run badchoice LS_DATUM_GATEWAY=maybe
grep -qx 1 "$T/badchoice.rc" && grep -q 'LS_DATUM_GATEWAY is "maybe": use bundled' "$T/badchoice.out"
ok "a choice that is neither is refused, in words" $? "$T/badchoice.out"

# the Files folder's port: a setting of its own, read by the compose file, said plainly when another program has it
grep -qx LS_FILES_PORT=8486 "$T/none/app/.env" && grep -q 'XBT_UI_FILES_BIND: 127.0.0.1:${LS_FILES_PORT:-8486}' "$PKG/docker-compose.yml"
ok "LS_FILES_PORT is written (8486 by default) and is where the app serves the folder" $? "$T/none/app/.env"
if command -v python3 >/dev/null; then
  stand_in() { # PORTFILE STATUS: a program on a free port that answers every request with STATUS
    python3 -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s): s.send_response(int(sys.argv[2])); s.send_header("Content-Length", "0"); s.end_headers()
    def log_message(s, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1] + ".tmp", "w").write(str(srv.server_port)); __import__("os").rename(sys.argv[1] + ".tmp", sys.argv[1])
srv.serve_forever()' "$1" "$2" &
    for _ in $(seq 50); do [ -s "$1" ] && break; sleep 0.1; done
  }
  stand_in "$T/other.port" 200; other=$!
  stand_in "$T/ours.port" 204; ours=$!
  run clash LS_FILES_PORT="$(cat "$T/other.port")"
  run served LS_FILES_PORT="$(cat "$T/ours.port")"
  kill "$other" "$ours"
  grep -qx 0 "$T/clash.rc" && grep -q "another program uses 127.0.0.1:$(cat "$T/other.port"), so the app cannot serve the Files folder" "$T/clash.out" \
    && grep -q "Set LS_FILES_PORT in $T/clash/app/.env" "$T/clash.out"
  ok "another program on the Files port is said plainly, with the setting that moves it" $? "$T/clash.out"
  ! grep -q "Files folder" "$T/served.out"
  ok "the app's own folder on that port: nothing said" $? "$T/served.out"
else
  echo "  skip the Files port checks: no python3 for the stand-in program"
fi
[ "$fails" = 0 ] && echo "RESULT PASS" || { echo "RESULT FAIL"; exit 1; }
