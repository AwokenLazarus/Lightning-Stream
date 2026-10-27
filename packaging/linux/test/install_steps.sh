#!/bin/bash
# install.sh's own steps, without Docker or nodes: a stand-in `docker` answers what install.sh asks
# and records what it is handed. Checks the admin macaroon step (given, missing, none at all) and
# what .env holds. Prints RESULT PASS|FAIL. Run by packaging/linux/test-linux.sh; needs only bash.
set -uo pipefail
PKG=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
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
[ "$fails" = 0 ] && echo "RESULT PASS" || { echo "RESULT FAIL"; exit 1; }
