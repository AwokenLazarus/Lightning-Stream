# p2p-hash: try it

Rent BLAKE2b hashrate from someone, or rent yours out, paid in sats as you use it, seconds at a time.

**In 0.2.0:** Renting hashrate needs masked jobs (jobs that hide which shares win), solo or through a pool, so a hashmaker can't keep back the shares that would be blocks. The app comes with its own gateway, the **Stream Gateway (DATUM-compatible)**, which masks its jobs, and rents into it. You set it up on the Hashrate page under *Your gateway*: solo to your own XBT address (the default), or through Lazarus Pool. Before each rental, and when the Rent page opens, the app checks the jobs; if they aren't masked (the gateway isn't set up or running, or the app is set to another gateway that doesn't mask), it says so and rents nothing.
The hashtaker's own gateway makes the jobs. Nobody holds anyone's money. How it works:
[P2P-HASH.md](P2P-HASH.md).

```
miners ──SV1──> hashmaker: xbt-hashlink hashmaker ══ encrypted link ══> hashtaker: xbt-hashlink hashtaker ──SV1──> hashtaker's gateway
                hashmaker: xbt-gateway (sells slices)  <── one paid request per slice ──  hashtaker's wallet signer
discovery: the hashmaker's signed listing on Nostr relays
```

This page is the command line, which has run between two machines on one LAN with a private relay.
The Umbrel app has screens for the same thing (Sell → Hashrate, and Rent hashrate). Use small amounts.
On a plain Linux machine (Ubuntu or another distribution with Docker), the same app installs beside your
own nodes with one script: [LINUX.md](LINUX.md).

## What happened when we ran it

A BLAKE2b ASIC on stock firmware rented into a real DATUM-protocol gateway, with the hashmaker and the hashtaker on
two machines and the payments over the public XBT Lightning network:
- 129 shares accepted, 0 rejected;
- 14 slices paid, and all 14 signed work receipts matched the hashmaker's own count;
- two 546-sat tickets paid, 4 sats of routing fees in all;
- when the hashtaker stopped paying, the hashmaker cut the miner off about 1.1 slices later (41 s), and
  the miner fell back to its own pool.

## What you need

| | Hashmaker | Hashtaker |
|---|---|---|
| Lightning | a Lightning Fork (lnd-family) node with inbound capacity | a Lightning Fork node with a route to the hashmaker's |
| Mining | a BLAKE2b miner that can point at a Stratum V1 address | a gateway that masks its jobs: the app's own Stream Gateway (DATUM-compatible), or one of yours that opens its jobs on `/xbt/job` |
| Software | `xbt-hashlink`, `xbt-gateway`, a TLS front | `xbt-hashlink`, the wallet signer (`xbt-signer`) |
| Network | one port for miners (LAN), one for the link and one https port, both reachable by the hashtaker | reaches the hashmaker's link and https ports |

Build (Rust 1.90 or newer):

```
cargo build --release -p xbt-hashlink -p xbt-gateway -p xbt-signer
```

Each side makes its keys once:

```
target/release/xbt-hashlink keygen hashmaker.key     # the hashmaker's link key; prints its public key
target/release/xbt-hashlink keygen nostr.key      # the hashmaker's Nostr key
target/release/xbt-hashlink keygen hashtaker.key      # the hashtaker's link key
```

## Hashmaker

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
     "mainnet_ack": "real funds, software tested on mainnet with small amounts only",
     "node": {
       "rest": "https://127.0.0.1:8080",
       "tls_cert": "tls.cert",
       "macaroon": "invoices.macaroon",
       "info_macaroon": "info.macaroon"
     },
     "tickets": { "ticket_msat": 546000, "min_ticket_msat": 546000, "max_tickets": 2, "ticket_blocks": 40, "settle": ["on-use", "on-arrival"] },
     "routes": [
       { "path": "/hashrate/", "upstream": "http://127.0.0.1:34943", "methods": ["POST"],
         "max_body": 8192, "price": { "request_msat": 40000 }, "top_ticket_msat": 100000000 }
     ]
   }
   ```

   `request_msat` is the price of one slice, and it must equal `--price-msat` below.
   `min_ticket_msat` is the smallest ticket you sell, and a renter's first step: 546 sat. A gateway
   whose smallest is more is refused by renters, with nothing paid. `top_ticket_msat` is the largest
   prepaid ticket this route sells, for a big miner's tickets; it doesn't raise what is held.
   Check the config against the node, then run it:

   ```
   target/release/xbt-gateway --check gateway.json
   target/release/xbt-gateway gateway.json
   ```

3. **TLS in front of the gateway.** The gateway speaks plain HTTP on loopback. Put any reverse
   proxy with a certificate in front of it on `public_url`, or use the small one in this tree:

   ```
   python3 scripts/p2p_hash/tls_front.py HASHER_HOST:34942 127.0.0.1:34941 front.crt front.key
   ```

   With a self-signed certificate, give the hashtaker its SHA-256 for the pin (step 1 of Hashtaker).

4. **The hashmaker's side of the link**, publishing its listing first:

   ```
   target/release/xbt-hashlink hashmaker --key hashmaker.key \
     --miners 0.0.0.0:34930 --link 0.0.0.0:34944 --slices 127.0.0.1:34943 \
     --slice-work 140737488355328 --price-msat 40000 --grace-ms 45000 \
     --relays wss://relay.example --nostr-key nostr.key --name "my hashrate" \
     --link-public HASHER_HOST:34944 --pay-url https://HASHER_HOST:34942/hashrate \
     --pay-node YOUR_NODE_ID --hashrate-hs 4100000000000 --report hasher.json
   ```

   - `--slice-work` is the work in a slice, in hashes. A share at difficulty `d` is `d × 2^32`
     hashes, so 140737488355328 is 8 shares at difficulty 4096: about 34 s of a 4.1 TH/s miner.
   - `--slices` is where the gateway's paid requests arrive (the route's upstream above). Each one
     pays a slice ahead of its work, and the hashmaker sends no share on past what's paid.
   - `--relays` takes `wss://` relays. Plain `ws://` is accepted only on loopback.

5. **Point the miners** at `stratum+tcp://HASHER_HOST:34930`. Keep the usual pool as the fallback
   pool: when payments stop, the hashmaker closes the miners' sessions and they fail over to it.

## Hashtaker

1. **Allow the hashmaker in the wallet's policy** (the signer's `policy.json`; see
   [TICKETS.md](TICKETS.md) for the whole policy). Add the hashmaker's https origin, tie it to its
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

2. **Find the hashmaker and rent:**

   ```
   target/release/xbt-hashlink hashtaker --key hashtaker.key \
     --find wss://relay.example --expect-node HASHER_NODE_ID --max-price-msat 40000 \
     --upstream 127.0.0.1:23334 --user YOUR_GATEWAY_USER \
     --signer /path/to/signer.sock --task hashrate --max-sats 2000 \
     --duration-s 900 --report buyer.json
   ```

   - `--find` reads signed hashrate listings from the relays and keeps one only if its
     signatures and its binding to the hashmaker's link key hold. `--expect-node` and
     `--max-price-msat` narrow the choice.
   - `--upstream` and `--user` are the hashtaker's gateway and the user it credits.
   - Payment: each finished slice is one paid request to the hashmaker's gateway, through the
     wallet signer, under the task's budget and the policy's caps.
   - `--stop-paying-after N` stops paying after N slices, to see the hashmaker stop.

## Your gateway

Rented hashrate goes to the hashtaker's own gateway: it builds the block templates and masks every job, so a
hashmaker can't tell which shares win. The app comes with one, the **Stream Gateway (DATUM-compatible)**. On
the app's Hashrate page, under *Your gateway*:

1. **Choose where its blocks pay.** *Solo* (the default): every block it finds pays your address, whole.
   *Lazarus Pool*: blocks are shared through the pool, which pays you for your share of its work. Lazarus Pool
   masks these jobs once it takes gateway-held keys; until then renting stays off in that mode, and solo works.
   In that mode your gateway holds the key and hands it to the pool with a block, so it could hide a block it
   finds from the pool, the same as any DATUM miner can today.
2. **Enter your XBT address.** On mainnet it starts `bc1q`, `bc1p`, `1` or `3`; the page checks it for your
   node's network before saving.
3. **Save.** The gateway starts a few seconds later. The page then shows it running, connected to your node,
   and masking its jobs; renting opens when all three hold.

It reaches your XBT node by RPC with the credentials the app already has (the one-shot init writes them to a
cookie file only the gateway reads; its config holds no secret), and listens on 127.0.0.1 only. Details:
[P2P-HASH.md](P2P-HASH.md#the-stream-gateway-that-comes-with-the-app).

**Your own gateway instead.** *Use another gateway* takes a host:port. It has to open its jobs the way the
Stream Gateway does (`GET /xbt/job` on its API; give the API's host:port when it isn't the same host's port 7152);
a stock DATUM gateway can't, and renting stays off with it. A choice made there holds until the installer is run again
with another answer, which then wins (the page says so).
Do not point rentals at a pool's public stratum port: you would be paying for work credited to whoever that
port pays. On the command line: `--upstream host:port` and `--gateway-api host:port`.

**Upgrading from 0.1.x.** An app that was set to a stock gateway app is moved to the Stream Gateway once, and
the page offers the old one back. Pools whose server holds the key (CONVOY-style ABW) are a follow-up.

## Renting out several miners, with a fallback

With `--fallback host:port` (or a settings file, `--config`), the hashmaker keeps serving: every miner
nobody rents hashes there, hashtakers rent whole miners (`--miners N` on the hashtaker), and when a rental
ends its miners go back to the fallback by themselves. `--rentable N` caps how many miners are
rented out at once. See [P2P-HASH.md](P2P-HASH.md#the-fallback-pool-and-several-hashtakers).

## What each side sees, and stopping

- `buyer.json` and `hasher.json`: accepted and rejected shares, the work counted, each slice and
  its payment, and why the rental ended.
- The hashmaker sends no share on past what's paid: one that doesn't fit waits 2 s for payment, and
  without it the rental stops and the miners go home. The hashtaker stops paying when no proven work
  arrives (`--idle-s`) or at `--duration-s`.

## Known limits

- **Prepaid credit on short rentals.** A ticket is at least 546 sats. A rental shorter than a
  ticket's worth of slices leaves the rest as prepaid credit with the hashmaker.
- **App screens are in the Umbrel app only, and not released yet.** Elsewhere it is command line.
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
  - hashmaker machine: `HASHER_SSH` (ssh target), `HASHER_DIR` (its binaries, keys and gateway
    config), `HASHER_IP`, and the ports `MINERS_PORT`, `LINK_PORT`, `FRONT_PORT`, `GW_PORT`,
    `SLICES_PORT`;
  - discovery: `RELAY_LISTEN` (a stand-in relay on the hashtaker's loopback, reached by the hashmaker
    through an ssh tunnel), `LISTING_NAME`, `HASHRATE_HS`;
  - hashtaker: `GATEWAY` and `GW_USER` (the gateway and its user), `SIGNER_SOCK`, `TASK`,
    `MAX_SATS`, `BUYER_KEY`, `PAY_NODE` (the hashmaker's node id);
  - terms: `SLICE_WORK`, `PRICE_MSAT`, `GRACE_MS`, `STOP_PAYING_AFTER`, `MINUTES`;
  - evidence: `BUYER_LNCLI` and `SELLER_LNCLI` (lncli commands for each node).

  The miner's web login comes from the environment: `MINER`, `DM_USER`, `DM_PASS`.
