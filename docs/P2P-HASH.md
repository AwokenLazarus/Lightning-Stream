# p2p-hash: rented hashrate over Lightning Stream (phase 1)

**In 0.2.0:** Renting hashrate needs masked jobs (jobs that hide which shares win), solo or through a pool, so a hashmaker can't keep back the shares that would be blocks. The app comes with a DATUM Gateway that masks its jobs, and rents into it. Before each rental, and when the Rent page opens, the app checks the jobs; if they aren't masked (the gateway isn't running, or the app is set to another gateway that doesn't mask), it says so and rents nothing.

Anyone rents hashrate from anyone, paid as it is used, seconds at a time, pointed at the hashtaker's own DATUM
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
- **A link that drops.** The hashmaker's miners go to the fallback and the rental waits the grace time
  for the hashtaker, who dials again and says `resume`. The hashtaker counts a verdict before sending
  it, so verdicts on their way when the link dropped are counted on its side only, and the hashmaker
  would then finish every later slice a share late and refuse its payment as not done. So `resume`
  carries the hashtaker's count, and the hashmaker takes the difference before anything else on the new
  link, no more than the shares it sent up and heard nothing about. The last payments and their locks
  are sent again; the hashmaker takes each slice once. A hashtaker back before the hashmaker noticed the
  drop is taken back the same way: its key says it is the same hashtaker.
- **A link that goes silent**, with no close and no end of stream, ends the rental on both sides: see
  "What a stalled link can cost" below.
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

## How each side is protected

Both apps rebuild every share's hash from the Stratum lines alone (`crates/xbt-hashlink/src/proof.rs`) and count
only the work it proves. Neither takes the other's word: the gateway's verdicts set no work. The order of paying
is in `crates/xbt-hashlink/src/order.rs`.

**The hashmaker.** A renter gets no work it hasn't paid for.
- Miners don't move until the start fee and a first step have been paid. A `hello` with no payment reserves no
  miner, and ends at the grace time (`no first payment`).
- No share is forwarded past what's paid. One that doesn't fit waits, the hashmaker says `due`, and if no payment
  comes within 2 s the rental stops and the miners go home (`unpaid`). Measured on the real-money regtest: stopped
  with 0 work past what was paid.
- A share nobody hashed, a repeat, or one too old goes no further; the miner gets a rejection from the hashmaker.
- A renter that keeps the miners idle (no jobs, or jobs too fast to finish) uses up the paid time: four times what
  the paid slices should take at the miners' best measured speed (`paid time used up`).
- A renter flooding jobs or shares, asking for a share worth more than 4 slices, or sending a job the check can't
  follow ends the rental. So does looping `resume`.
- Walking away after the first step, with a new key each time, buys no work that wasn't paid for: each rental
  pays its start fee and first step, gets that much work, and stops.

**The hashtaker.** It never has more paid for and not yet received than a minute of the miner's hashing or 546
sat, whichever is more, plus any start fee shown on the offer.
- Steps are earned: what's paid and unused never passes the largest of 546 sat, one share, or what has been
  delivered, up to 30 s of the miner's output. Steps ignore reputation, so fake history pays nothing.
- A hashmaker that takes a payment and vanishes keeps that step, and the app won't pay a seller a third time after
  two first steps that delivered little.
- Shares that don't prove are not paid for, and many of them end the rental (`shares that don't prove`).
- **Withholding blocks.** The renter's gateway blinds every job with an `xor_key` whose `clear_bits` equal the
  share's own bits, so a hashmaker can't tell which shares win. The app checks each job through the gateway's
  local `/xbt/job` and refuses an upstream it can't show to be blinded. The renter's page says, per upstream, which
  it is. No list of pools: a pool that adds a key passes by itself. Solo on a gateway that blinds, and a pool whose
  gateway holds the key, qualify. So would a pool-held key (ABW) through such a gateway, though no such pool has been
  run. A miner pointed straight at a pool, with no gateway of the renter's, can't be checked, so it's refused.
- **Delay.** Blinding doesn't stop a hashmaker holding shares until a winner goes stale, or sitting on the job
  before a new block. The app ends a rental at the second share late on a superseded job, when a window of shares
  all arrive older than a quarter of a job's life, on 8 rejections in a row or under 75% accepted over 64, and
  when shares look harder than the difficulty said.

**A dropped link.** At `resume` the hashmaker sends its recent shares again; the hashtaker checks each and counts
it once, so the two counts come back level. Measured on the real-money regtest: 10 shares counted from the
resend, both proven counts equal, every slice paid once.

**Follow-up, not built: refuse a key a block has revealed.** A found block publishes its key, so a hashmaker can
work out that key's mask, and spot wins on any later job that commits to the same key. A gateway's own key changes
with every template, and the app refuses a gateway key seen on two previous blocks. A key the pool holds (ABW) can
rightly outlast blocks other miners found, so for those the app relies on the pool changing its key after a block
it finds, and says so on the renter's page. The check that would end the reliance: keep the key hashes revealed in
the blocks the renter's node follows, read from each new header, and refuse any job, in any mode, that commits to
one. The renter's app reads no block headers today (its gateway's API gives a job's previous block by hash only),
so it waits for that plumbing.

## A stalled link

A link can stall with neither side told. Since no share goes past what's paid, a stall costs the hashmaker
nothing it wasn't paid for, and the hashtaker at most its unused step.
- A hashtaker silent for 60 s ends the rental on the hashmaker's side (`QUIET_LIMIT`); the hashtaker ends on its
  own limit for no proven work.
- A send that makes no progress for 5 s closes the link (`WRITE_TIMEOUT`), and the rental waits its grace time
  for a `resume`.
- **Not fixed:** writes to a miner and to the hashtaker's gateway have no time limit (from reading the code, not
  measured). A link over iroh's direct path once stopped carrying anything after a resume, in 500 runs under
  load, cause unknown. With no fallback (the lab), a miner coming back after a drop waits up to 10 s.

## What is left

- **Real tickets**: done for the wallet path. Each slice is one paid request to the
  hashmaker's gateway through the wallet's signer, paid ahead of its work (`--signer`, a "hashrate" task budget);
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
- **Stale and reject thresholds**: rejected shares cost the hashmaker (no work counted); a rental with
  none accepted ends (above), and a rule to end one on a high reject rate is not yet there.
