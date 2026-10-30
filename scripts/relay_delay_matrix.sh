#!/bin/bash
# The Jellyfin relay check at several added delays on the relay leg (scripts/relay_delay.sh), each
# judged against the film played straight from Jellyfin on this machine (JF_BASELINE=1). Lab only:
# needs sudo for tc, and what the jellyfin checks need (JELLYFIN_URL, JF_ADMIN_KEY_FILE, JF_LIBRARY,
# JF_ITEM, JF_GUEST_USER). Results per delay in $OUT_ROOT/delay-<ms>/.
#   scripts/relay_delay_matrix.sh [ms ...]       # default: 0 300 800 1500
set -u
cd "$(dirname "$0")/.."
OUT_ROOT=${OUT_ROOT:-$HOME/4k/runs}
trap 'scripts/relay_delay.sh off >/dev/null' EXIT
for d in "${@:-0 300 800 1500}"; do
    for ms in $d; do
        o=$OUT_ROOT/delay-$ms
        rm -rf "$o" && mkdir -p "$o"
        if [ "$ms" -gt 0 ]; then scripts/relay_delay.sh on "$ms"; else scripts/relay_delay.sh off; fi
        XBT_TRACE_WIRE=1 JF_BASELINE=1 TICKET_E2E_SCRATCH=$OUT_ROOT/scr scripts/ticket_e2e_regtest.sh jellyfin_relay > "$o/lab.out" 2>&1
        echo "delay $ms ms: rc=$?"
        cp run/*.log "$o/" 2>/dev/null
        cp -r run/jellyfin_relay run/jellyfin_baseline "$o/" 2>/dev/null
    done
done
