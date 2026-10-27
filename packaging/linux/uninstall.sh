#!/usr/bin/env bash
# Remove Lightning Stream from this machine: its containers, its images, and (unless --keep-data) its
# data folder, with the keys, the spending rules and the tickets in it.
#
#   packaging/linux/uninstall.sh [--dir DIR] [--keep-data] [--keep-images] [--yes]
#
# Before you remove the data: spend or move anything left in the app first (an on-chain balance of the
# app's own wallet, if you funded one), and keep your approval-key backup if you may come back. The
# macaroons the app made stay valid on your Lightning node until you revoke them: this prints their
# root key ids for `lncli deletemacaroonid`.
set -euo pipefail
# the app's own files only: a COMPOSE_FILE from the caller's shell would name others
unset COMPOSE_FILE

DIR=${LS_INSTALL_DIR:-$HOME/lightning-stream}
KEEP=0 YES=0 KEEP_IMAGES=0
while [ $# -gt 0 ]; do
  case $1 in
    --dir) DIR=$2; shift 2 ;;
    --keep-data) KEEP=1; shift ;;
    --keep-images) KEEP_IMAGES=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "uninstall: unknown option $1 (try --help)" >&2; exit 2 ;;
  esac
done
[ -f "$DIR/docker-compose.yml" ] && [ -f "$DIR/.env" ] || { echo "uninstall: no Lightning Stream in $DIR" >&2; exit 1; }
cd "$DIR"
DATA=$(set -a; . ./.env; echo "$LS_DATA_DIR")
# the clean-up helper: the app's files belong to its services' users, not to yours
BUSYBOX=busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662

echo "== the macaroons the app made on your Lightning node (revoke each: lncli deletemacaroonid ID)"
for f in run/ln/auto-keys.json run/gateway/auto-keys.json; do
  [ -d "$DATA" ] && docker run --rm --network none -v "$DATA:/d:ro" "$BUSYBOX" cat "/d/$f" 2>/dev/null \
    | grep -o '"root_key_id": *"[0-9]*"' | grep -o '[0-9][0-9]*' | sed 's/^/   /' || true
done

echo "== stopping and removing the app's containers"
images=$(docker compose --profile setup --profile hashmaker config --images 2>/dev/null | sort -u)
docker compose --profile setup --profile hashmaker down --remove-orphans

if [ "$KEEP" = 1 ]; then
  echo "== keeping $DATA (run install.sh again to start from it)"
else
  if [ "$YES" != 1 ]; then
    read -r -p "Delete $DATA: the app's keys, rules and tickets? This cannot be undone. Type yes: " a </dev/tty
    [ "$a" = yes ] || { echo "kept $DATA"; exit 0; }
  fi
  echo "== deleting $DATA"
  docker run --rm --network none -v "$DATA:/d" "$BUSYBOX" sh -c 'rm -rf /d/* /d/.[!.]* /d/..?*'
  rmdir "$DATA"
  rm -f "$DIR/.env" "$DIR/docker-compose.yml" "$DIR/docker-compose.override.yml"
  rmdir "$DIR" 2>/dev/null || true
fi

if [ "$KEEP_IMAGES" != 1 ]; then
  echo "== removing the app's images"
  # shellcheck disable=SC2086
  [ -z "$images" ] || docker image rm $images >/dev/null 2>&1 || true
  docker image rm "$BUSYBOX" >/dev/null 2>&1 || true
fi
echo "Lightning Stream is removed."
