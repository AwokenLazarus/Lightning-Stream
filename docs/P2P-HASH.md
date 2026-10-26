# p2p-hash: rented hashrate over Lightning Stream (phase 1)

Anyone rents hashrate from anyone, paid as the work arrives, pointed at the buyer's own DATUM
Gateway. The buyer makes the jobs; the hasher runs no gateway. Nobody holds anyone's money.

```
miners ──SV1 (LAN)──> hasher's app ══ link (BOLT 8 Noise_XK) ══> buyer's app ──SV1──> buyer's DATUM Gateway ──> pool
                        jobs and verdicts ◄──────────────── shares ────────►
                        meter                                  meter, tickets, receipts
```

Crate: `crates/xbt-hashlink`. Lab: `scripts/p2p_hash_lab.sh`. To run it yourself: [P2P-HASH-TRY-IT.md](P2P-HASH-TRY-IT.md).

## What is built

- **The link**: BOLT 8 (`Noise_XK_secp256k1_ChaChaPoly_SHA256`), byte for byte, checked against
  BOLT 8's published test vectors (the three acts, the keys, the transport messages across two key
  rotations). The prologue is `xbt-hashlink/0`, not `lightning`, so a hashlink handshake never
  completes against a Lightning peer or the other way round. The buyer dials and must know the
  hasher's static key (from the listing); the hasher learns the buyer's key in act three.
- **Messages** (one JSON object per Noise message): `hello` (version, rental, listing, terms),
  `welcome`, `open` (a miner connected), `up` (a line from the miner: subscribe, authorize,
  submit), `down` (a line from the gateway: notify, set_difficulty, and the verdict on each submit),
  `shut`, `lock`, `pay`, `rate`, `ping`/`pong`, `close`. See `src/msg.rs`.
- **Stratum V1 relay**: one upstream session to the buyer's gateway per miner, so extranonces,
  version rolling and other extensions pass through unchanged. The buyer's app puts the buyer's
  user name in `mining.authorize` and `mining.submit` (the gateway credits the buyer). The hasher's
  app never passes `client.reconnect` to its miners.
- **The meter**: work is counted only for shares the gateway accepts, at `difficulty × 2^32`
  hashes each, at the difficulty in force when the share's job was sent. Both apps read the same
  lines in the same order and count the same work at every step.
- **Slices and tickets**: the buyer keeps two tickets locked ahead (their payment hashes), and
  when a slice of work is done releases that slice's preimage with a work receipt signed by its
  link key. The hasher checks the preimage against the locked hash and the receipt against its own
  count, and stops serving (closes its miners' sessions) when a finished slice is not paid within
  the grace time, or as soon as a second slice finishes unpaid, or when no ticket is locked for the
  next slice. At the end the buyer cancels the tickets still locked.

## Lab result

`scripts/p2p_hash_lab.sh`: stand-in pool as the buyer's gateway, two stand-in miners with a toy
share hash, the release binary in three processes, tickets on the lab's stand-in rails (no
money moves). 10 of 10 checks pass: every slice paid once and every receipt equal to the
hasher's own count (18 of 18); both meters equal; the gateway credited the buyer's name only;
rejected shares count no work; no payment after the miners stopped and both locked tickets
cancelled; with payment stopped after slice 3, the hasher stopped 0.40 slice past the unpaid
slice and the gateway saw no work after that.

## With a real miner

`scripts/p2p_hash_miner.sh` runs a short rental from a miner with the DragonMint web UI into a real
DATUM Gateway: it saves the miner's pools, points pool 1 at the hasher (the saved pool stays as
the fallback), lets the buyer pay a few slices and then stop paying, and restores the pools on
every exit and compares them. It credits the same gateway user the miner already uses. It has
run: 58 shares accepted, 4 slices paid, the hasher stopping 0.8 slice after the unpaid one.

## Between two machines, paid in real sats

`scripts/p2p_hash_rehearsal.sh` runs the hasher and the buyer on two machines, the buyer finding
the hasher by its Nostr listing and paying each slice through the hasher's gateway over
Lightning. The result, and a guide to run it yourself: [P2P-HASH-TRY-IT.md](P2P-HASH-TRY-IT.md).

## Choices

### Noise: implement BOLT 8, not the `snow` crate

| | BOLT 8 in-tree (chosen) | `snow` 0.9 (Noise_XK) |
|---|---|---|
| Keys | secp256k1, the same curve as the Lightning node keys and the wallet's keys | 25519 only: no secp256k1 DH, so the link key could never be a Lightning key |
| Wire | exactly Lightning's: the published BOLT 8 vectors pass | generic Noise framing; Lightning's length-prefix encryption and key rotation would be ours anyway |
| Code | about 300 lines over crates already in the tree (secp256k1, sha2, hmac, chacha20poly1305) | a new dependency tree |
| Later | the node's own key can sign the link (open question below), or the link can run over a Lightning peer connection's custom messages | neither |

### One upstream session per miner

The plan allowed one per hasher or one per miner. One per miner needs no extranonce splitting, no
job rewriting and no knowledge of the chain's header: every line passes as it is, and the
gateway's own accounting per session applies.

## What is left

- **Real tickets**: `rail::BuyerRail` and `rail::SellerRail` are where the wallet's held tickets
  plug in (the signer pays the hasher's hold invoice for each locked hash under a "hashrate" task
  budget; the hasher's node makes and settles the hold invoices). The lab uses stand-ins.
- **Which key signs the link**: today a key of the app's own. Open: the Lightning node key (a
  signing path to the node) or the app key bound to the node key by a signature in the listing.
- **Listings** (`hashrate` kind on Nostr and directories), reconnect with resume, the Tor
  transport, several rentals at once, the UI (Sell: hashrate, Buy: hashrate).
- **Stale and reject thresholds**: rejected shares cost the hasher (no work counted); a rule to
  end a rental on a high reject rate is not yet there.
