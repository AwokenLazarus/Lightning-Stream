#!/usr/bin/env python3
"""Are these listen ports free? The regtest scripts ask before they start anything.

    scripts/portcheck.py busy PORT...                 exit 1 and name the ports that cannot be bound
    scripts/portcheck.py wait [--timeout S] PORT...   wait until all can be bound (default 75 s), else exit 1

A port is tried the way a server binds it: SO_REUSEADDR, on every address, IPv4 and IPv6. A port
that a run just closed can stay unbindable for about a minute (a connection in TIME-WAIT), which is
why `wait` exists and why its default is longer than that. Keep test ports below the kernel's
ephemeral range (`/proc/sys/net/ipv4/ip_local_port_range`, 32768-60999 by default): inside it any
outgoing connection can take one between this check and the bind.
"""
import argparse
import socket
import sys
import time


def bindable(port):
    for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            continue                    # this host has no IPv6
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((address, port))
        except OSError:
            return False
        finally:
            s.close()
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["busy", "wait"])
    ap.add_argument("--timeout", type=float, default=75.0)
    ap.add_argument("ports", nargs="+", type=int)
    a = ap.parse_args()
    deadline = time.monotonic() + (a.timeout if a.command == "wait" else 0)
    busy = [p for p in a.ports if not bindable(p)]
    if busy and a.command == "wait":
        print(f"portcheck: waiting up to {a.timeout:.0f} s for {busy}", file=sys.stderr)
    while busy and time.monotonic() < deadline:
        time.sleep(1)
        busy = [p for p in busy if not bindable(p)]
    if busy:
        print(f"portcheck: in use: {' '.join(map(str, busy))}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
