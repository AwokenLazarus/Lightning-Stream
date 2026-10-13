#!/usr/bin/env python3
"""The compose overlay of the ticket book regtest, printed to stdout: on top of lightning-fork-lab
(a5cadc5), the chain node's RPC and each Lightning Fork node's REST interface on loopback, a CPU cap
on every container, and SELLERS seller nodes (s01, s02, ...) with the lab's default node settings.
The hop, lf2, is started with `--default-remote-max-htlcs=30`: it accepts 30 pending payments from
each peer, so the buyer's one channel carries 30 towards it, which is what a channel with a Core
Lightning node at its default carries. (A stand-in for the slot count only: a Core Lightning node
also limits what it sends, and has a dust limit of 546 sat where this node's is 354.)

    knots-b2b RPC  127.0.0.1:BASE         the signer's own chain node
    lf1 REST       127.0.0.1:BASE+1       the buyer: the wallet's Lightning node
    lf2 REST       127.0.0.1:BASE+2       the routing hop
    sNN REST       127.0.0.1:BASE+10+NN   a seller's node

BASE is TICKET_BOOK_PORT_BASE (default 17911): every port is below the kernel's ephemeral range.
"""
import os
import sys

BASE = int(os.environ.get("TICKET_BOOK_PORT_BASE", "17911"))
SELLERS = int(os.environ.get("TICKET_BOOK_SELLERS", "16"))

# lf2 as the lab starts it (lightning-fork-lab a5cadc5, docker-compose.yml), and one setting more
HOP = """  lf2:
    cpus: 2
    ports: ["127.0.0.1:{port}:8080"]
    command:
      - --noseedbackup
      - --bitcoin.regtest
      - --bitcoin.node=bitcoind
      - --bitcoin.blake2b-activation-height=${{ACTIVATION_HEIGHT:-20}}
      - --fee.url=http://fees:8080/fees.json
      - --bitcoind.rpchost=knots-b2b:18443
      - --bitcoind.rpcuser=lab
      - --bitcoind.rpcpass=lab
      - --bitcoind.rpcpolling
      - --bitcoind.blockpollinginterval=2s
      - --bitcoind.txpollinginterval=2s
      - --rpclisten=0.0.0.0:10009
      - --restlisten=0.0.0.0:8080
      - --listen=0.0.0.0:9735
      - --externalip=lf2:9735
      - --tlsextradomain=lf2
      - --alias=lf2
      - --debuglevel=info,PEER=debug,FNDG=debug
      - --protocol.simple-taproot-chans
      - --accept-keysend
      - --default-remote-max-htlcs=30
"""

NODE = """  {name}:
    image: lightning-fork:dev
    restart: "no"
    networks: [lab]
    depends_on:
      knots-b2b:
        condition: service_healthy
    cpus: 1
    ports: ["127.0.0.1:{port}:8080"]
    command:
      - --noseedbackup
      - --bitcoin.regtest
      - --bitcoin.node=bitcoind
      - --bitcoin.blake2b-activation-height=${{ACTIVATION_HEIGHT:-20}}
      - --fee.url=http://fees:8080/fees.json
      - --bitcoind.rpchost=knots-b2b:18443
      - --bitcoind.rpcuser=lab
      - --bitcoind.rpcpass=lab
      - --bitcoind.zmqpubrawblock=tcp://knots-b2b:28332
      - --bitcoind.zmqpubrawtx=tcp://knots-b2b:28333
      - --rpclisten=0.0.0.0:10009
      - --restlisten=0.0.0.0:8080
      - --listen=0.0.0.0:9735
      - --externalip={name}:9735
      - --tlsextradomain={name}
      - --alias={name}
      - --debuglevel=info
    volumes:
      - {name}-data:/root/.lnd
"""


def main() -> int:
    if not 1 <= SELLERS <= 80 or BASE + 10 + SELLERS >= 32768:
        print("TICKET_BOOK_SELLERS is 1 to 80, and every port stays below 32768", file=sys.stderr)
        return 2
    names = [f"s{i:02d}" for i in range(1, SELLERS + 1)]
    out = ["services:", "  knots-b2b:", "    cpus: 2", f'    ports: ["127.0.0.1:{BASE}:18443"]']
    out += ["  lf1:", "    cpus: 2", f'    ports: ["127.0.0.1:{BASE + 1}:8080"]', HOP.format(port=BASE + 2).rstrip("\n")]
    out += [NODE.format(name=n, port=BASE + 10 + i).rstrip("\n") for i, n in enumerate(names, start=1)]
    out += ["volumes:"] + [f"  {n}-data:" for n in names]
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
