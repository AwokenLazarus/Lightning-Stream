# p2p-hash: rented hashrate over Lightning Stream (phase 1)

Anyone rents hashrate from anyone, paid as the work arrives, pointed at the hashtaker's own DATUM
Gateway. The hashtaker makes the jobs; the hashmaker runs no gateway. Nobody holds anyone's money.

```
miners ──SV1 (LAN)──> hashmaker's app ══ link (BOLT 8 Noise_XK) ══> hashtaker's app ──SV1──> hashtaker's DATUM Gateway ──> pool
                           jobs and verdicts ◄──────────────── shares ────────►
                           meter                                  meter, tickets, receipts
```

**The two roles** are named after the direction of the hash, not after who publishes:

- the **hashmaker** produces the hash: it brings the miners and publishes the signed listing;
- the **hashtaker** receives it: it takes a listing and points the work at its own DATUM Gateway.

Earlier versions called them the hasher and the buyer (or renter). Those names stay where changing
them would break something already running: the Umbrel app's `hasher` and `renter` services, their
data folders and settings, and the `role` and peer-key fields of the JSON reports and status pages.
The command line takes both, so `xbt-hashlink hasher` and `xbt-hashlink buyer` still work.

Crate: `crates/xbt-hashlink`. Lab: `scripts/p2p_hash_lab.sh`. To run it yourself: [P2P-HASH-TRY-IT.md](P2P-HASH-TRY-IT.md).

## What is built

- **The link**: BOLT 8 (`Noise_XK_secp256k1_ChaChaPoly_SHA256`), byte for byte, checked against
  BOLT 8's published test vectors (the three acts, the keys, the transport messages across two key
  rotations). The prologue is `xbt-hashlink/0`, not `lightning`, so a hashlink handshake never
  completes against a Lightning peer or the other way round. The hashtaker dials and must know the
  hashmaker's static key (from the listing); the hashmaker learns the hashtaker's key in act three.
- **Messages** (one JSON object per Noise message): `hello` (version, rental, listing, terms),
  `welcome`, `open` (a miner connected), `up` (a line from the miner: subscribe, authorize,
  submit), `down` (a line from the gateway: notify, set_difficulty, and the verdict on each submit),
  `shut`, `lock`, `pay`, `rate`, `ping`/`pong`, `close`. See `src/msg.rs`.
- **Stratum V1 relay**: one upstream session to the hashtaker's gateway per miner, so extranonces,
  version rolling and other extensions pass through unchanged. The hashtaker's app puts the hashtaker's
  user name in `mining.authorize` and `mining.submit` (the gateway credits the hashtaker). The hashmaker's
  app never passes `client.reconnect` to its miners.
- **The meter**: work is counted only for shares the gateway accepts, at `difficulty × 2^32`
  hashes each, at the difficulty in force when the share's job was sent. Both apps read the same
  lines in the same order and count the same work at every step.
- **Slices and tickets**: the hashtaker keeps two tickets locked ahead (their payment hashes), and
  when a slice of work is done releases that slice's preimage with a work receipt signed by its
  link key. The hashmaker checks the preimage against the locked hash and the receipt against its own
  count, and stops serving (closes its miners' sessions) when a finished slice is not paid within
  the grace time, or as soon as a second slice finishes unpaid, or when no ticket is locked for the
  next slice. At the end the hashtaker cancels the tickets still locked.

## Lab result

`scripts/p2p_hash_lab.sh`: stand-in pool as the hashtaker's gateway, two stand-in miners with a toy
share hash, the release binary in three processes, tickets on the lab's stand-in rails (no
money moves). 10 of 10 checks pass: every slice paid once and every receipt equal to the
hashmaker's own count (18 of 18); both meters equal; the gateway credited the hashtaker's name only;
rejected shares count no work; no payment after the miners stopped and both locked tickets
cancelled; with payment stopped after slice 3, the hashmaker stopped 0.40 slice past the unpaid
slice and the gateway saw no work after that.

## With a real miner

`scripts/p2p_hash_miner.sh` runs a short rental from a miner with the DragonMint web UI into a real
DATUM Gateway: it saves the miner's pools, points pool 1 at the hashmaker (the saved pool stays as
the fallback), lets the hashtaker pay a few slices and then stop paying, and restores the pools on
every exit and compares them. It credits the same gateway user the miner already uses. It has
run: 58 shares accepted, 4 slices paid, the hashmaker stopping 0.8 slice after the unpaid one.

## Between two machines, paid in real sats

`scripts/p2p_hash_rehearsal.sh` runs the hashmaker and the hashtaker on two machines, the hashtaker finding
the hashmaker by its Nostr listing and paying each slice through the hashmaker's gateway over
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

The plan allowed one per hashmaker or one per miner. One per miner needs no extranonce splitting, no
job rewriting and no knowledge of the chain's header: every line passes as it is, and the
gateway's own accounting per session applies.

## The fallback pool and several hashtakers

The hashmaker's side keeps serving instead of ending with one rental (`xbt-hashlink hashmaker --fallback`
or `--config`, the service the app runs):

- **Every miner is a unit**, named by its worker name (`mining.authorize`); a connection that does
  not authorize within ten seconds is let go. A miner nobody rents hashes for the hashmaker's own pool
  or DATUM Gateway, the **fallback**, so a hashmaker points each miner at the app once.
- **A rental takes whole miners.** The hashtaker's `hello` says how many (0: as many as are free), up
  to a cap the hashmaker sets (`--rentable`). Any split works: one miner each to several hashtakers, or
  three to one hashtaker while the fourth stays on the fallback. Each rental has its own link, meter,
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
- **The end of a rental.** Both sides let a channel's meter go at the same point: after the hashtaker's
  upstream session for it has ended and its last verdict was sent, the hashtaker says `shut`, and the
  hashmaker lets the channel go there too. This removed the case where the hashmaker counted one more
  finished slice than the hashtaker. The hashtaker's `close` also says how many slices it counted; only
  slices both sides counted are billed, and their payments may still arrive until the grace time
  ends. A hashtaker with a budget ends the rental as soon as the next slice could not be paid.
- **The hashtaker's service** (`xbt-hashlink hashtaker`) finds offers on Nostr and runs several rentals
  at once into the hashtaker's own DATUM Gateway, each with a budget and a cut switch, paying through
  the wallet's signer.
- **Control pages** for the app (`GET /status`, `POST /stop/RENTAL`; `GET /offers`, `POST /rent`,
  `POST /cut`, `POST /datum`) answer only with the control token (`--control-token-file`).

Tests (`crates/xbt-hashlink/tests/several.rs`, stand-in pools and miners that connect again when
asked or take a new extranonce, as real firmware does): four miners with three hashtakers taking one
each; one hashtaker taking three while the fourth stays on the fallback; a hashtaker that stops paying
losing only its own miner, which goes back to the fallback while the other rental goes on; and no
gap between accepted shares longer than one job (2 s in the test) when a miner moves, either way.

With a real miner (`scripts/p2p_hash_fallback_miner.sh`, no money: the lab's rail): a BLAKE2b
ASIC on stock firmware, pointed once at the hashmaker, hashed for the fallback (a DATUM Gateway) for a
minute, was rented by a hashtaker for two minutes (6 slices paid, 25 shares accepted, receipts and both
meters equal) and went back to the fallback by itself when the rental ended. It does not ask for
`mining.set_extranonce`, so it was moved by `client.reconnect`. Real firmware waits for the answer to
its subscribe before it authorizes, so a miner is placed as soon as it connects and named when it
authorizes; the stand-in miner now does the same.

The app (Umbrel) has a page for each side: Sell → Hashrate (the fallback, the price, how many
miners to rent out, each miner and each rental, a Stop button) and Services → Hashrate (the offers,
a budget and a duration, each rental with a Cut button, the hashtaker's DATUM Gateway). Rentals also
show on Live connections.

## Trust before renting: a test slice and a delivery history

A hashtaker has two ways to judge a hashmaker before committing a budget
(`crates/xbt-hashlink/src/trust.rs`).

**A test slice.** Services → Hashrate → *Try one slice first* rents one machine for one slice:
its budget is one slice's price, and its time limit is three slices' worth at the advertised speed,
between 5 and 60 minutes. It is an ordinary rental, paid the ordinary way, and the hashtaker's own
DATUM Gateway checks every share. When it ends, the rental shows what it delivered: the speed
(accepted work over the time from the start to the finished slice, so it includes the first seconds
of connecting) against the speed the listing advertised, the share of stale shares (Stratum V1
error 21, or an error that says stale) and of rejected shares, and the share round trip (submit to
verdict, median and 95th percentile, as the hashtaker's app sees it).

**A delivery record.** After any rental that paid at least one slice, the hashtaker may choose to
publish a signed record of it (*Publish a delivery record*). It is a Nostr event of kind 30078
(NIP-78 application data), signed by the hashtaker's link key used as a Nostr key, so the hashmaker,
who saw that key on the link, can tell it is the hashtaker it served:

- tags: `d` = `lightning-stream-hash-attest:<commitment>`, `t` = `lightning-stream-hash-attest`,
  `p` = the hashmaker's link key (x-only), and nothing else;
- content (at most 2 KiB): the hashmaker's and the hashtaker's link keys, the commitment
  `SHA-256("xbt-hashlink/rental/0|<rental>|<hashtaker key>|<hashmaker key>")`, the slices and
  millisatoshis paid, the slice size, the work the gateway accepted, the duration, accepted,
  rejected and stale shares, the advertised and delivered speed, the median share round trip, a
  hash of the signed work receipts behind the paid slices, whether it was a test slice, and when
  it ended, rounded down to the hour.

It names no pool, payout address, user name, rental name or IP address.

**A hashmaker's summary.** A hashmaker with relays and a Nostr key set publishes, at most every ten
minutes after a rental ends, its own signed list of the rentals it served: kind 30078, `d` =
`lightning-stream-hash-summary:<link key>`, `t` = `lightning-stream-hash-summary`, `p` = its link
key (x-only), content at most 16 KiB with its newest 40 rentals (the commitment, the hashtaker's
key, slices and millisatoshis paid, work, the receipts hash, the hour it ended). It is signed by the
Nostr key the hashmaker's listing is bound to; a summary by any other key is ignored. The hashmaker
keeps it in `hash-summary.json` beside its settings, so it survives a restart.

**What the offer shows.** Each offer on Services → Hashrate carries a delivery history built from
the records and the summary on the app's relays: TH-hours confirmed by both sides, the records and
how many the hashmaker confirmed, the speed delivered against the speed advertised (a weighted
average), disputes, and the most recent rentals. A record is **confirmed** when the hashmaker's
summary has the same commitment, hashtaker, slices paid and receipts hash; it is **disputed** when
the summary has the rental but disagrees.

**What it does not prove.** Lightning payments are private, so nobody but the two sides can check
that a payment happened. The history is made hard to fake rather than impossible to fake:

- a hashmaker's records about itself (its own link key, or its listing's Nostr key) are dropped;
- a record the hashmaker did not confirm counts for 0.3 of one it did;
- a record from a key with no record for any other hashmaker counts for half;
- each key counts for at most its 3 most recent rentals with a hashmaker.

A hashmaker can still make keys that rent from it and from others; the strongest evidence remains
the hashtaker's own test slice.

**Relays.** The relay at relay.lazarus-xbt.xyz accepts kind 30078 only in shapes it knows; these
two shapes need its write policy updated (the change and its test are prepared with this work).
Other relays take them as ordinary NIP-78 events.

## What is left

- **Real tickets**: done for the wallet path. Each finished slice is one paid request to the
  hashmaker's gateway through the wallet's signer (`--signer`, a "hashrate" task budget);
  `scripts/p2p_hash_regtest.sh` runs it with Lightning Fork nodes. The stand-in rails remain for
  the lab.
- **The meters at the end of a rental**: fixed (above). A rental cut mid-slice still leaves the
  part of a slice done since the last payment unpaid: the hashmaker's exposure, by design, is under
  one slice.
- **Which key signs the link**: today a key of the app's own. Open: the Lightning node key (a
  signing path to the node) or the app key bound to the node key by a signature in the listing.
- **Listings** on public relays and directories (the signed `hashrate/0` listing on Nostr is
  built and used by `--find` and the hashtaker's service), reconnect with resume, the Tor transport.
- **Miners behind one address with one worker name** count as one miner per live connection
  (`name #2`, …); give each miner its own worker name.
- **Stale and reject thresholds**: rejected shares cost the hashmaker (no work counted); a rule to
  end a rental on a high reject rate is not yet there.
