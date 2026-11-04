#!/bin/bash
# Add a fixed delay to traffic leaving this machine for a relay, to see how a shop and its buyers
# behave over a slow path (lab only; needs sudo and tc).
#   scripts/relay_delay.sh on <ms> [relay host]   # default host: relay.lightning-stream.com
#   scripts/relay_delay.sh off
# Both ends of a lab run sit on this machine and reach the relay from here, so a request and its answer
# each cross the delay once: the link's round trip grows by about twice <ms>.
set -euo pipefail
dev=$(ip route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}')
case "${1:-}" in
on)
    ms=${2:?delay in ms}
    host=${3:-relay.lightning-stream.com}
    sudo tc qdisc del dev "$dev" root 2>/dev/null || true
    # a fourth band of its own for the delayed traffic: the three default bands carry the rest unchanged
    sudo tc qdisc add dev "$dev" root handle 1: prio bands 4 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
    sudo tc qdisc add dev "$dev" parent 1:4 handle 40: netem delay "${ms}ms"
    for ip in $(getent ahostsv4 "$host" | awk '{print $1}' | sort -u); do
        sudo tc filter add dev "$dev" protocol ip parent 1:0 prio 3 u32 match ip dst "$ip/32" flowid 1:4
        echo "relay_delay: ${ms} ms to $ip ($host) on $dev"
    done
    ;;
off)
    sudo tc qdisc del dev "$dev" root 2>/dev/null || true
    echo "relay_delay: off on $dev"
    ;;
*)
    echo "usage: $0 on <ms> [relay host] | off" >&2
    exit 2
    ;;
esac
