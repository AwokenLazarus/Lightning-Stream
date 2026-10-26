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

## The fallback pool and several renters

The hasher's side keeps serving instead of ending with one rental (`xbt-hashlink hasher --fallback`
or `--config`, the service the app runs):

- **Every miner is a unit**, named by its worker name (`mining.authorize`); a connection that does
  not authorize within ten seconds is let go. A miner nobody rents hashes for the hasher's own pool
  or DATUM Gateway, the **fallback**, so a hasher points each miner at the app once.
- **A rental takes whole miners.** The buyer's `hello` says how many (0: as many as are free), up
  to a cap the hasher sets (`--rentable`). Any split works: one miner each to several buyers, or
  three to one buyer while the fourth stays on the fallback. Each rental has its own link, meter,
  receipts and tickets, and when one ends, only its miners go back.
- **Moving a miner**, either way, without a gap longer than one job:
  - a miner that asked for `mining.set_extranonce` keeps its connection: the app opens the new
    upstream session itself (the miner's own subscribe and authorize, replayed), hands the miner
    the new extranonce and sends the new jobs with `clean_jobs`. Shares for the old upstream's
    jobs still go there during a ten-second drain;
  - any other miner is sent `client.reconnect` to the app's own address and is placed by its
    worker name when it comes back.
- **The listing says what is free** (`capacity`: miners, free miners, free hashrate) and is
  published again when that changes.
- **The end of a rental.** Both sides let a channel's meter go at the same point: after the buyer's
  upstream session for it has ended and its last verdict was sent, the buyer says `shut`, and the
  hasher lets the channel go there too. This removed the case where the hasher counted one more
  finished slice than the buyer. The buyer's `close` also says how many slices it counted; only
  slices both sides counted are billed, and their payments may still arrive until the grace time
  ends. A buyer with a budget ends the rental as soon as the next slice could not be paid.
- **The renter's service** (`xbt-hashlink renter`) finds offers on Nostr and runs several rentals
  at once into the buyer's own DATUM Gateway, each with a budget and a cut switch, paying through
  the wallet's signer.
- **Control pages** for the app (`GET /status`, `POST /stop/RENTAL`; `GET /offers`, `POST /rent`,
  `POST /cut`, `POST /datum`) answer only with the control token (`--control-token-file`).

Tests (`crates/xbt-hashlink/tests/several.rs`, stand-in pools and miners that connect again when
asked or take a new extranonce, as real firmware does): four miners with three renters taking one
each; one renter taking three while the fourth stays on the fallback; a renter that stops paying
losing only its own miner, which goes back to the fallback while the other rental goes on; and no
gap between accepted shares longer than one job (2 s in the test) when a miner moves, either way.

With a real miner (`scripts/p2p_hash_fallback_miner.sh`, no money: the lab's rail): a BLAKE2b
ASIC on stock firmware, pointed once at the hasher, hashed for the fallback (a DATUM Gateway) for a
minute, was rented by a buyer for two minutes (6 slices paid, 25 shares accepted, receipts and both
meters equal) and went back to the fallback by itself when the rental ended. It does not ask for
`mining.set_extranonce`, so it was moved by `client.reconnect`. Real firmware waits for the answer to
its subscribe before it authorizes, so a miner is placed as soon as it connects and named when it
authorizes; the stand-in miner now does the same.

The app (Umbrel) has a page for each side: Sell → Hashrate (the fallback, the price, how many
miners to rent out, each miner and each rental, a Stop button) and Services → Hashrate (the offers,
a budget and a duration, each rental with a Cut button, the buyer's DATUM Gateway). Rentals also
show on Live connections.

## What is left

- **Real tickets**: done for the wallet path. Each finished slice is one paid request to the
  hasher's gateway through the wallet's signer (`--signer`, a "hashrate" task budget);
  `scripts/p2p_hash_regtest.sh` runs it with Lightning Fork nodes. The stand-in rails remain for
  the lab.
- **The meters at the end of a rental**: fixed (above). A rental cut mid-slice still leaves the
  part of a slice done since the last payment unpaid: the hasher's exposure, by design, is under
  one slice.
- **Which key signs the link**: today a key of the app's own. Open: the Lightning node key (a
  signing path to the node) or the app key bound to the node key by a signature in the listing.
- **Listings** on public relays and directories (the signed `hashrate/0` listing on Nostr is
  built and used by `--find` and the renter's service), reconnect with resume, the Tor transport.
- **Miners behind one address with one worker name** count as one miner per live connection
  (`name #2`, …); give each miner its own worker name.
- **Stale and reject thresholds**: rejected shares cost the hasher (no work counted); a rule to
  end a rental on a high reject rate is not yet there.
