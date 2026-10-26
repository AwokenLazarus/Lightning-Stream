# p2p-hash: try it

Rent BLAKE2b hashrate from someone, or rent yours out, paid in sats as accepted work arrives.
The buyer's own DATUM Gateway makes the jobs. Nobody holds anyone's money. How it works:
[P2P-HASH.md](P2P-HASH.md).

```
miners ──SV1──> hasher: xbt-hashlink hasher ══ encrypted link ══> buyer: xbt-hashlink buyer ──SV1──> buyer's DATUM Gateway
                hasher: xbt-gateway (sells slices)  <── one paid request per slice ──  buyer's wallet signer
discovery: the hasher's signed listing on Nostr relays
```

This is command-line software that has run between two machines on one LAN, with a private relay.
There are no app screens for it yet. Use small amounts.

## What happened when we ran it

A BLAKE2b ASIC on stock firmware rented into a real DATUM Gateway, with the hasher and the buyer on
two machines and the payments over the public XBT Lightning network:
- 129 shares accepted, 0 rejected;
- 14 slices paid, and all 14 signed work receipts matched the hasher's own count;
- two 546-sat tickets paid, 4 sats of routing fees in all;
- when the buyer stopped paying, the hasher cut the miner off about 1.1 slices later (41 s), and
  the miner fell back to its own pool.

## What you need

| | Hasher | Buyer |
|---|---|---|
| Lightning | a Lightning Fork (lnd-family) node with inbound capacity | a Lightning Fork node with a route to the hasher's |
| Mining | a BLAKE2b miner that can point at a Stratum V1 address | a DATUM Gateway (or any SV1 pool endpoint) and a user name on it |
| Software | `xbt-hashlink`, `xbt-gateway`, a TLS front | `xbt-hashlink`, the wallet signer (`xbt-signer`) |
| Network | one port for miners (LAN), one for the link and one https port, both reachable by the buyer | reaches the hasher's link and https ports |

Build (Rust 1.90 or newer):

```
cargo build --release -p xbt-hashlink -p xbt-gateway -p xbt-signer
```

Each side makes its keys once:

```
target/release/xbt-hashlink keygen hasher.key     # the hasher's link key; prints its public key
target/release/xbt-hashlink keygen nostr.key      # the hasher's Nostr key
target/release/xbt-hashlink keygen buyer.key      # the buyer's link key
```

## Hasher

1. **A narrow node key.** Bake macaroons that can only make and read invoices, and read node info:

   ```
   lncli bakemacaroon invoices:read invoices:write --save_to invoices.macaroon
   lncli bakemacaroon info:read --save_to info.macaroon
   ```

   Copy the node's `tls.cert` somewhere the gateway can read it.

2. **The gateway** sells one thing: a paid request per slice. A config (`gateway.json`):

   ```json
   {
     "listen": "127.0.0.1:34941",
     "public_url": "https://HASHER_HOST:34942",
     "state_dir": "state",
     "chain": "main",
     "mainnet_ack": "real funds, software that has run on regtest only",
     "node": {
       "rest": "https://127.0.0.1:8080",
       "tls_cert": "tls.cert",
       "macaroon": "invoices.macaroon",
       "info_macaroon": "info.macaroon"
     },
     "tickets": { "ticket_msat": 546000, "max_tickets": 2, "ticket_blocks": 40, "settle": ["on-use", "on-arrival"] },
     "routes": [
       { "path": "/hashrate/", "upstream": "http://127.0.0.1:34943", "methods": ["POST"],
         "max_body": 8192, "price": { "request_msat": 40000 } }
     ]
   }
   ```

   `request_msat` is the price of one slice, and it must equal `--price-msat` below. Check the config
   against the node, then run it:

   ```
   target/release/xbt-gateway --check gateway.json
   target/release/xbt-gateway gateway.json
   ```

3. **TLS in front of the gateway.** The gateway speaks plain HTTP on loopback. Put any reverse
   proxy with a certificate in front of it on `public_url`, or use the small one in this tree:

   ```
   python3 scripts/p2p_hash/tls_front.py HASHER_HOST:34942 127.0.0.1:34941 front.crt front.key
   ```

   With a self-signed certificate, give the buyer its SHA-256 for the pin (step 1 of Buyer).

4. **The hasher's side of the link**, publishing its listing first:

   ```
   target/release/xbt-hashlink hasher --key hasher.key \
     --miners 0.0.0.0:34930 --link 0.0.0.0:34944 --slices 127.0.0.1:34943 \
     --slice-work 140737488355328 --price-msat 40000 --grace-ms 45000 \
     --relays wss://relay.example --nostr-key nostr.key --name "my hashrate" \
     --link-public HASHER_HOST:34944 --pay-url https://HASHER_HOST:34942/hashrate \
     --pay-node YOUR_NODE_ID --hashrate-hs 4100000000000 --report hasher.json
   ```

   - `--slice-work` is the work in a slice, in hashes. A share at difficulty `d` is `d × 2^32`
     hashes, so 140737488355328 is 8 shares at difficulty 4096: about 34 s of a 4.1 TH/s miner.
   - `--slices` is where the gateway's paid requests arrive (the route's upstream above). The
     hasher answers 200 only for a slice its own meter counted, so nothing else is charged.
   - `--relays` takes `wss://` relays. Plain `ws://` is accepted only on loopback.

5. **Point the miners** at `stratum+tcp://HASHER_HOST:34930`. Keep the usual pool as the fallback
   pool: when payments stop, the hasher closes the miners' sessions and they fail over to it.

## Buyer

1. **Allow the hasher in the wallet's policy** (the signer's `policy.json`; see
   [TICKETS.md](TICKETS.md) for the whole policy). Add the hasher's https origin, tie it to its
   node, pin its certificate when it is self-signed, and give the rentals a task budget:

   ```json
   "allowlist": ["https://HASHER_HOST:34942"],
   "counterparties": { "https://HASHER_HOST:34942": { "ln_node": "HASHER_NODE_ID" } },
   "tickets": {
     "enabled": true,
     "tasks": { "hashrate": { "budget_sats": 2000 } },
     "seller_tls": { "https://HASHER_HOST:34942": { "cert_sha256": "CERT_SHA256" } }
   }
   ```

   Merge these into the existing policy and keep its other caps. Restart the signer.

2. **Find the hasher and rent:**

   ```
   target/release/xbt-hashlink buyer --key buyer.key \
     --find wss://relay.example --expect-node HASHER_NODE_ID --max-price-msat 40000 \
     --upstream 127.0.0.1:23334 --user YOUR_GATEWAY_USER \
     --signer /path/to/signer.sock --task hashrate --max-sats 2000 \
     --duration-s 900 --report buyer.json
   ```

   - `--find` reads signed hashrate listings from the relays and keeps one only if its
     signatures and its binding to the hasher's link key hold. `--expect-node` and
     `--max-price-msat` narrow the choice.
   - `--upstream` and `--user` are the buyer's DATUM Gateway and the user it credits.
   - Payment: each finished slice is one paid request to the hasher's gateway, through the
     wallet signer, under the task's budget and the policy's caps.
   - `--stop-paying-after N` stops paying after N slices, to see the hasher stop.

## What each side sees, and stopping

- `buyer.json` and `hasher.json`: accepted and rejected shares, the work counted, each slice and
  its payment, and why the rental ended.
- The hasher stops serving when a finished slice is not paid within `--grace-ms`, or as soon as
  a second slice finishes unpaid. The buyer stops paying when no accepted work arrives (`--idle-s`)
  or at `--duration-s`.

## Known limits

- **Prepaid credit on short rentals.** A ticket is at least 546 sats. A rental shorter than a
  ticket's worth of slices leaves the rest as prepaid credit with the hasher.
- **Command line only.** There are no app screens yet.
- **Tested narrowly.** Two machines on one LAN, a private relay, one miner.
- **One key question is open:** the link is signed with an app key bound to the listing, not
  with the Lightning node key itself.

## Scripts in this tree

- `scripts/p2p_hash_lab.sh`: stand-in pool and miners, no money.
- `scripts/p2p_hash_regtest.sh`: the same with real Lightning Fork nodes and the real wallet on
  regtest.
- `scripts/p2p_hash_miner.sh`: a short rental from a real miner with the DragonMint web UI, which
  saves and restores the miner's pools.
- `scripts/p2p_hash_rehearsal.sh`: the two-machine run above. It reads its settings from an env
  file (`CONF`, default `run/p2p-hash/rehearsal/rehearsal.env`, not in the tree). Its variables:
  - hasher machine: `HASHER_SSH` (ssh target), `HASHER_DIR` (its binaries, keys and gateway
    config), `HASHER_IP`, and the ports `MINERS_PORT`, `LINK_PORT`, `FRONT_PORT`, `GW_PORT`,
    `SLICES_PORT`;
  - discovery: `RELAY_LISTEN` (a stand-in relay on the buyer's loopback, reached by the hasher
    through an ssh tunnel), `LISTING_NAME`, `HASHRATE_HS`;
  - buyer: `GATEWAY` and `GW_USER` (the DATUM Gateway and its user), `SIGNER_SOCK`, `TASK`,
    `MAX_SATS`, `BUYER_KEY`, `PAY_NODE` (the hasher's node id);
  - terms: `SLICE_WORK`, `PRICE_MSAT`, `GRACE_MS`, `STOP_PAYING_AFTER`, `MINUTES`;
  - evidence: `BUYER_LNCLI` and `SELLER_LNCLI` (lncli commands for each node).

  The miner's web login comes from the environment: `MINER`, `DM_USER`, `DM_PASS`.
