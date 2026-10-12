# xbt-signer

B2's agent-wallet signer in Rust (AGP-027). One process holds every key. The model-facing process
(B2's Python MCP server, or a Rust payer through `client::RemoteSigner`) only calls its socket. The
signer carries:

- B2's policy engine;
- sealed hot and channel keys;
- the write-ahead channel open (P1) and the minConf wait (P2);
- refund custody at expiry (the watcher);
- the AGP-022 close-change retry;
- the hash-chained signature log, anchored with B2's witness.

It uses B2's socket protocol (`b2/docs/B2_SIGNER_API.md`) and B2's on-disk formats, so either signer
runs behind either client and opens the other's files.

Reference: B2 `agp-next2` `04c3f56` (`agentwallet/signer.py`, `channels.py`, `hot.py`, `keystore.py`,
`sigaudit.py`, `anchor.py`, `policy.py`, `xbt402.py`, `stream.py`, `netparams.py`).

## Run

```bash
cargo build -j2 --release -p xbt-signer --bins
B2_HOT_KEYFILE=/secure/hot.key B2_ANCHOR_SOCK=/run/witness/w.sock B2_RPCPORT=8332 B2_DATADIR=~/.bitcoin \
  target/release/xbt-signer --root ~/wallet          # policy.json in ~/wallet, state in ~/wallet/.run
target/release/xbt-signer --root ~/wallet --check    # every start-up check (chain, P3, keys, anchor), then exit
target/release/xbt-anchor-witness serve --store /var/lib/witness --sock /run/witness/w.sock   # its own user
target/release/xbt-anchor-witness check --store /var/lib/witness --log ~/wallet/.run/signatures.jsonl
```

The environment is B2's:

- `B2_ROOT`, `B2_DATADIR`, `B2_RPCPORT`, `B2_WALLET`;
- `B2_CHAIN` (must agree with the node);
- `B2_SIGNER_SOCK`: a path, or `tcp://127.0.0.1:PORT` (see Portability);
- `B2_HOT_KEYFILE` or `B2_HOT_PASSPHRASE`: exactly one; the passphrase is removed from the environment once read;
- `B2_HOT_ALLOW_PLAINTEXT=1`: tests only;
- `B2_ANCHOR_SOCK`, `B2_WATCH_INTERVAL`, `B2_HOT_SCAN`, `B2_CALLS_JSONL`, `B2_BODY_DIR`, `B2_BODY_CAP`.

## Socket methods

### B2's methods

Every B2 method listed below behaves as in B2:

- `balance`, `quote_payment`, `pay`, `approve`, `history`;
- `health`, `chain_backend`, `channels`, `hot_address`, `notice_hot_txid`, `fund`;
- `open_channel`, `sign_state`, `xbt402_pay`;
- `xbt402_request_auth`, `xbt402_sign_state_a3`;
- `close_channel`, `xbt402_refund` (alias `refund_channel`), `watch_tick`;
- `rotate_hot_key`, `sweep_hot`, `signatures`, `anchor_now`, `anchor_status`, `hot_reconcile`.

`xbt402_pay` includes streamed results (`xbt402-merkle-v1`). Limit: on a postpay channel a streamed
result can be bought once per channel and not after a lost answer (each further try pays for the
manifest and gets no data); an open item, see `docs/LIMITS.md`.

### New for an external payer

These are B1's `ChannelSigner` interface, so a client never holds a payer key. Each one is
policy-checked where it raises the signed amount.

| method | params | result |
|---|---|---|
| `xbt402_new_key` | `origin` | `{pub}`: the payer key issued for that origin and not yet bound to a channel (a new one only when none is pending), sealed on disk at once as `pending:<origin>` |
| `xbt402_attach` | `origin`, `params` (ChannelParams `to_dict`) | `{chan, dest}`: binds the issued key to the funded channel (open at once); `<origin>/next` is a rollover's successor, attached only once this signer's node shows the rollover (else `deny/rollover_unproven`) |
| `xbt402_sign_state` (= `sign_state`) | `chan` or `dest`, `cum` | policy on `cum - used`, then `{verdict, chan, cum, sig}` |
| `xbt402_sign_rollover` | `chan`, `amount`, `next_spk`, `next_capacity` | policy on the increase, then `{sig}` (audit kind `channel_rollover`) |
| `xbt402_sign_conditional` | `chan`, `uncond`, `hash`, `amount`, `csv_delta` | policy on `uncond + amount - used`, then `{sig}` |
| `xbt402_sign_close` | `chan` | `{sig}` (close authorisation) |
| `xbt402_sign_refund` | `chan` | `{hex, expiry, to}`: the CLTV refund, always to the hot key |
| `xbt402_mark_closed` | `chan`, `txid` | the channel's record after its change was learned (AGP-022), once this signer's node shows the funding spent; before that `deny/close_unproven` and the channel stays refundable (AGP-080) |
| `tx_confirmations` | `txid`, `vout` | `{confirmations, height}` (read-only; for the payer's P2 wait) |

`client::RemoteSigner` implements `xbt402::signer::StateSigner` and `xbt402::client::Wallet` over
these methods: `Client::new(..).with_signer(Arc::new(RemoteSigner::new(sock)))`.

### Routed payments (retired)

The hub was retired on 2026-10-11: payments between parties route over ordinary Lightning instead.
The signer no longer has a routing policy and no longer answers B2's lock methods
(`xbt402_sign_state_adaptor`, `xbt402_resolve_lock`, `xbt402_void_lock`, `xbt402_adopt_lock`,
`xbt402_recover_lock`, `routing_status`); B2 still has them. A `routing` section in `policy.json`
is ignored, with a warning. A channel record that an earlier version left with a pending lock
keeps it: no plain state below the locked amount is signed, and the channel is refunded at its
expiry. The code is in the git history (last at commit `a548fb0`).

### For the web UI (AGP-039)

These are the methods behind `xbt-wallet-ui` (see its README). Every one that raises what the wallet
may spend, or that moves or exports keys, needs a signature by the human's ed25519 key. The domains
are in `approval.rs`. None of these methods is an MCP tool.

| method | params | result |
|---|---|---|
| `approvals` | | pending, approved (xbt402 grants) and expired approval tokens with dest, amount, memo, url, expiry |
| `approval_status` | `token` | `pending`, `approved`, `used`, `denied`, `expired` or `unknown` |
| `deny_approval` | `token`, `reason`, `expiry`, `signature` | drops the token. AGP-063 W3: a live approval needs the human signature over `deny_message(token, expiry)`, so the agent cannot refuse for the owner; an expired one is dropped without one |
| `policy_get` / `policy_validate` | / `policy` | the file, its SHA-256 and the values in force; the validator's `errors` (the engine's parse errors first) and `warnings` |
| `policy_prepare` | `policy` | the canonical text, `prev_sha256`, `expiry`, the message to sign, and a diff; the human key is kept |
| `policy_set` | `text`, `prev_sha256`, `expiry`, `signature` | writes policy.json atomically (the old file is kept as `.prev`) and puts it in force without a restart; start-only keys are reported in `pending_restart` |
| `human_key_enroll` | `pubkey`, `code` | the first human key, only while none is enrolled. AGP-063 W4: `code` is the one-time enrolment code the signer prints to stderr (the Umbrel app log, StartOS Logs) and writes to `.run/enroll-code` (0600); five wrong codes replace it |
| `human_key_rotate` | `pubkey`, `expiry`, `signature` (by the current key) | the new human key |
| `rotate_hot_key_signed` | `expiry`, `signature` | `rotate_hot_key`, logged under `human:rotate_signature`. AGP-063 W3: `rotate_hot_key` itself is this method now |
| `backup_export` | `backup_pass`, `expiry`, `signature` | policy, sealed keys, books and logs, plus the wrapping secret sealed under the backup passphrase |
| `keystore_status`, `channel_reports` | | the wrapping-key source and mode; each close's report (AGP-029: cum, unpaidMsat, payeeFee, payeeNet) |

An over-threshold `xbt402_pay` stores its approval as `kind: "xbt402"` with its url and method.
`approve` of such a token grants it: nothing is paid yet. The agent's next `xbt402_pay` with the same
url, method and `max_sats` then pays under it once, with `human = true`, and returns `approved: true`.
Other tokens keep B2's `approve`, which pays at once. `close_channel` now returns B2's AGP-029
`close_report`.

### Lightning: `rail=ln` (AGP-048)

`ln_pay {invoice, max_sats, description?}` and `ln_status {}`. The signer pays XBT Lightning invoices
through a Lightning Fork (LND) node, under B2's policy: `dest` is `ln:<payee node id>` (put it on the
allowlist), and max_per_tx, the budgets, per-counterparty, velocity, split-bypass and the human
threshold apply to the invoice amount plus the routing-fee limit. An over-threshold invoice becomes an
approval token; the human's `approve` grants it and the agent's same `ln_pay` then pays, once.

Before anything reaches the router (`src/ln.rs`, `src/bolt11.rs`):

1. the invoice, decoded and signature-checked here: this chain's prefix (`lnbc` / `lnbcrt`), feature bit
   512 (`option_blake2b`; without it the invoice is SHA-256 Lightning's), an amount, at least
   `ln.min_expiry_s` left, `min_final_cltv` within `ln.max_cltv_blocks`, the caller's `description`
   (plain or hashed) when given;
2. the LN node's chain identity against the signer's own Knots node: its network, its hash at the
   anchor height (961,640 pinned on mainnet; `ln.anchor_height` / `ln.anchor_hash` elsewhere), its tip,
   its own bit 512, synced;
3. the node's `DecodePayReq` must match field by field;
4. only channels that are active, `unified_sigs`, not taproot, not zero-conf, and funded at or above
   the split (961,632 on mainnet; `ln.split_height` elsewhere) go in `outgoing_chan_ids`, and only once
   their **funding transaction is proven on the signer's own node** (AGP-049, `src/ln_funding.rs`): the
   transaction at the short channel id's block position is the channel point's, its output is the
   channel's P2WSH of its capacity, every signature each input's script checks carries sighash
   **0x21**, every input's coin was confirmed at or above the split, and (AGP-092) something its txid
   commits to pins it to XBT: the funding, or a transaction it descends from above the split, is a
   coinbase or carries a 0x21 signature in a scriptSig (`ln_funding::xbt_only`, at most 256
   transactions looked up; witness signatures are outside the txid, so on their own they prove
   nothing about the same txid on the SHA-256 chain). A node whose coins have no such ancestor in reach
   is refused: fund it from mined coins, or from coins that went through a P2PKH address after the
   split. Only spends whose sole
   condition is signatures are read (P2WPKH, P2SH-P2WPKH, P2PKH, `<key> CHECKSIG` or
   `m <keys> n CHECKMULTISIG` P2WSH, a taproot key path; AGP-066). LND's `unified_sigs` flag is not
   trusted for this. A verdict holds while the funding block is on the node's best chain: after a reorg
   the channel is proven again. The signer's node needs `txindex=1` to look up the inputs; an unprovable
   channel carries nothing;
5. the node's exposure: while it holds more than `ln.exposure_cap_sats` (channel local balances, HTLCs
   in flight and its on-chain coins), `ln_pay` refuses (`ln_exposure_cap`); mainnet requires a cap;
6. the send rate: at most `ln.max_sends_per_hour` payments reach the router per hour, failed ones
   included (`ln_rate_limit`; LND has no per-macaroon rate limit);
7. the watchtowers (`GET /v2/watchtower/client`): Lightning Fork's wtclient identifies a tower's chain
   only by the genesis hash, which the SHA-256 chain shares, and no tower advertises a chain feature, so
   every tower is unverified unless listed in `ln.trusted_towers`. `ln.tower_policy` `warn` (the default
   off mainnet: a loud warning in `ln_status` and `ln_pay`) or `refuse` (mainnet's default:
   `ln_tower_chain`);
8. the macaroon, read from the file (`src/macaroon.rs`): `ln_status` shows its permissions and
   caveats (`only_needed`, `excess_ops`); on mainnet one granting anything beyond `info:read
   offchain:read offchain:write onchain:read` (a `uri:` permission included), or whose permissions
   cannot be read, is refused (`ln_macaroon`; AGP-066);
9. HTLCs under CLTV: outgoing HTLCs the node started that the wallet did not book (sent outside it)
   hold funds until their expiry and count against what is left of the daily and weekly budgets
   (`ln_htlc_lock`) until they resolve. The wallet's own in-flight payments stay booked, with the CLTV
   height they can hold funds until, and a FAILED payment with an HTLC still out stays booked.

The worst case is booked to the ledger and to `.run/ln_payments.json` before the send; a settled
payment's booking becomes what it cost, a failed one's goes (the audit log keeps `ln_amend`). A payment
left in flight is reconciled from the node's record of it, looked up by payment hash (TrackPaymentV2;
by `ln_status`, the next `ln_pay`, the watcher), and blocks new LN payments until then. A booking
released because the node had no record of it (a crash before the send, or a send that errored) is
watched for as long as its HTLC could be out: `ln.max_cltv_blocks` + 144 blocks, in blocks and in time
(for a BOLT 12 payment `ln.node_max_cltv_blocks` + 144: `PayOffer` takes no limit of ours, so the
node's own `max-cltv-expiry` is the bound; AGP-092).
If the node records it late, it is booked again and settled or kept in flight (AGP-048 risk 7); one
whose HTLC is on a channel is not released at all. If that late booking breaks the policy, the rail
**halts** (AGP-066): every `ln_pay` is refused `ln_halted`, `ln_status` shows `halted`, and an approval
of kind `ln_resume` waits in the human's queue; only the human's signed `approve` of it resumes the
rail. Each settled payment is a `ln_payment` line in the
signature log whose `sig_sha256` is the payment hash (the log holds the SHA-256 of the preimage).
The wallet never opens channels; `ln_status` lists the node's coins below the split, which must never
fund one.

**BOLT 12 offers (AGP-082).** `ln_pay {invoice: "lno1...", max_sats, amount_sats?, description?}`
pays an offer: `dest` is `ln-offer:<offer id>` (the SHA-256 of the offer's fields, which Lightning Fork
and Core Lightning report as the offer id). The signer decodes the offer itself (`src/bolt12.rs`: bit
512, a chain this node is on, where an offer that names no chain is Bitcoin's genesis and so mainnet's
only; expiry; amount), runs the policy on the offer and the amount plus the fee limit, and only then
has the node fetch an invoice (`POST /v2/offers/fetchinvoice`). It decodes that `lni1...` too, verifies
the issuer's signature, checks it against the offer and against the node's summary of it, writes it to
`.run/ln_offers.json`, and has the node pay that invoice (`POST /v2/offers/pay` with `invoice`). A
retry pays the stored invoice, so one attempt never has two invoices out. The key that signed an
offer's first invoice is recorded, and a later invoice signed by another key is refused
(`ln_offer_signer`). The node chooses the channels of such a payment, so it is refused
(`ln_offer_unsafe_channel`) unless every channel of the node passes guards 4 and 5. Decoding on the
node is never used: the macaroon needs nothing beyond the four permissions above. Each payment records
the `invreq_payer_id` its request was signed with; Lightning Fork draws a new one per request, so it
names one payment, not the payer.

The node's word on a settled payment is checked (AGP-082): the booking is never below the invoice
amount, and `SUCCEEDED` counts only with the preimage of the payment hash; without it the whole
booking stays and the rail halts. The REST client follows no redirect.

policy.json `ln`: `enabled` (default off), `max_fee_base_sats` (10), `max_fee_ppm` (5000),
`min_expiry_s` (60), `max_cltv_blocks` (1008), `timeout_s` (60), `anchor_height`, `anchor_hash`,
`split_height`, `max_tip_lead` (2), `require_description` (false), `exposure_cap_sats` (0: none, not
allowed on mainnet), `max_sends_per_hour` (60; 0: none; every send counts, retries of one invoice
included), `node_max_cltv_blocks` (2016: the LN node's `max-cltv-expiry`; raise it if the node's was
raised), `tower_policy` (`warn` / `refuse`; default
`refuse` on mainnet), `trusted_towers` (tower public keys, hex). Environment: `B2_LN_REST`
(`https://host:port`; plain http only to 127.0.0.0/8 or `::1`, not to a name), `B2_LN_MACAROON`, `B2_LN_TLS_CERT` (LND's
`tls.cert`: the connection is pinned to exactly that certificate). A bad LN configuration shuts the
rail (`ln_config`), not the signer. Regtest proof: `scripts/ln_rail_regtest.sh`.

**The macaroon.** Bake one with only what the rail needs and a lifetime:

    lncli bakemacaroon --save_to=rail.macaroon --timeout=2592000 info:read offchain:read offchain:write onchain:read

`offchain:read` also covers the watchtower list. **IP caveats do not bind REST callers.** LND checks
`ipaddr` / `iprange` against the gRPC peer, and its REST gateway is an in-process gRPC client dialling
`127.0.0.1`: over REST, `--ip_address=127.0.0.1` passes every caller and any other address refuses
every call (shown on the lab, S12; over gRPC the caveat binds). So for this REST client, restrict the
REST listener itself: bind `restlisten` to a private interface or loopback (with an SSH or WireGuard
tunnel) and firewall it to the signer's host. The signer's own `max_sends_per_hour` is the rate limit;
LND has none per macaroon.

### Stream tickets: the ticket book

The buyer's side of `docs/TICKETS.md` (`src/ticket.rs`: the rules, no IO; `src/ticket_rail.rs`: the
book on disk, the node, the methods). A ticket is a hold invoice of the seller's node for a hash
whose secret only this signer can derive; the caller speaks HTTP to the seller, the signer decides
and books. Tickets are paid through the same node as `ln_pay`, with the same macaroon, after the
same checks of the node and its channels.

| method | params | what it does |
|---|---|---|
| `ticket_open` | `terms` (the `accepts` entry of the seller's 402), `task`, `origin?`, `expect_sats?`, `max_sats?` | a session with one seller under one of the owner's tasks; answers the ticket size and the pool. Refused: terms above the owner's bounds, a seller the task does not admit, a task the policy does not name. Pays and locks nothing |
| `ticket_offer` | `session` | the payment hashes the pool wants locked now (none above the refill mark); the secrets stay in the signer |
| `ticket_lock` | `session`, `tickets: [{hash, invoice}]` | checks each invoice (payee, hash, amount, bit 512, final CLTV delta, expiry, the caps) and pays those that pass; each is written to the book before the node sees it |
| `ticket_release` | `session` | the secret of one locked ticket, after its spend is in the ledger, the ticket is `released` in the book and the release is in the signature log. The only method that returns a secret, and it returns each once |
| `ticket_stop` | `session` | no more offers, locks or releases; answers the hashes to ask the seller to cancel |
| `ticket_status` | `session?` | the book after a reconcile with the node, and whether the node's HTLCs are the book's |

policy.json `tickets` (all optional but `enabled` and one task): `enabled` (false), `max_ticket_sats`
(1000), `max_ticket_blocks` (40), `max_htlc_blocks` (204: the `cltv_limit` of a ticket's route),
`max_invoice_expiry_s` (3600), `max_locked_sats` (16000) and `max_locked_tickets` (64): the exposure cap;
`seller_max_tickets` (8) and `seller_max_locked_sats` (8000): one named seller; `max_sellers` (32),
`max_new_sellers_per_min` (30), `max_sends_per_hour` (1200); and `tasks`, by name (`a-z`, `0-9`, `-`,
`_`): `budget_sats` (required), `window_s` (86400, at most a week), `max_locked_sats`,
`max_locked_tickets`, `max_sellers` (each the rail's by default), `admit` (`"listed"`, the default: only
sellers the owner named; `"any"`: any seller inside the caps that follow), `unlisted_max_tickets` (2),
`unlisted_max_locked_sats` (two tickets), `unlisted_max_spend_sats` (four tickets, in the task's
window). The pool: `pool` (8 unreleased tickets with a seller), `pool_many` (2, with each seller of a
task that has more than `many_sellers`, 8), `floor_ticket_sats` (64, the smallest ticket the wallet
chooses by itself). `velocity` (`"release"`, the default: every release is one payment for
`velocity_max`; `"session"`: a session is one). For the payer under `xbt402_pay`: `http_idle_s` (120),
`ready_wait_ms` (3000), `read_timeout_s` (30), `max_answer_s` (50). The owner names a seller with
`ln:<node id>` on the allowlist, or with an allowlisted origin whose `counterparties` entry has
`ln_node`. The wallet's own rules (the daily and weekly budgets, the per-counterparty cap, velocity,
the split window) apply to every release; a ticket that would reach the human threshold is refused
when the session opens. Top-level `channel_rail` (true): whether `xbt402_pay` may still pay the
on-chain channel.

### Stream tickets: `xbt402_pay` pays a seller

`src/ticket_http.rs` (a seller's messages read strictly, the wallet's count of a session: no IO) and
`src/ticket_pay.rs` (the rail choice, the session over HTTP, the answer read as it arrives). With
tickets on, `xbt402_pay` takes one more argument, `task`, and asks the seller once without paying; the
402 it gets back decides the rail (`docs/TICKETS.md`, section 12): a ticket entry, a single Lightning
invoice, the on-chain channel, or `no_rail` with what each entry would need. The reply of a call paid
with tickets has `rail: "ticket"`, `status`, `charged_sats` (what the book put in the ledger for the
tickets this call released), `tickets_released`, `price_msat` (what the call used, by the wallet's own
count), `balance_msat` (what is left with the seller), `complete` and `ended`, `bytes`, `body_digest`
(and `saved_to` under `B2_BODY_DIR`), `receipt` and `tickets`. `ticket_stop` then also asks the seller
to cancel and waits for the wallet's node to show the tickets back; `ticket_status` and `channels`
show, under `paying`, the wallet's count for each seller. `tests/ticket_pay.rs` runs this against the
real `xbt-gateway` in process (a seller that lies, lost and forged answers, a kill at every write step);
`scripts/ticket_e2e_regtest.sh` runs it against Lightning Fork nodes.

What is booked, and when:

- **Locked** tickets are counted against the exposure caps and booked nowhere. Nothing is locked that
  the budgets could not release.
- **A release** books the ticket and its routing-fee limit in the ledger (`ticket:<payment hash>`,
  memo `ticket task=<task> session=<id>`) before the secret is returned. When the node shows the payment settled,
  with the preimage, the row becomes the ticket plus the fee the node paid; when it shows it failed
  with no HTLC out (the seller cancelled, or the ticket expired), the row goes.
- **At every start** each ticket the book holds locked is retired: booked as if released, never
  released by this process, until the node shows it settled or failed; sessions are stopped. A start
  cannot be told from a restore of an older book, in which such a ticket may have been released.
- **After a restore** the node's payment list is read from the book's cursor. A payment that carries
  this wallet's tag (custom record 1953063787: a nonce and a MAC under the ticket seed) and is not in
  the book is retired the same way. Nothing is locked or released until that list has been read to its
  end once (`ticket_sync`).
- A ticket that settles without a release by this book, or that the node reports settled without the
  preimage, halts Lightning payments as the rail's own halts do (`ln_halted`, resumed by the human).

Files: `.run/tickets.jsonl` (the book: an append-only log of whole sessions and tickets, compacted
when it has doubled), `.run/ticket_seed.json` (32 bytes, sealed by the wallet's keystore; a secret is
`HMAC-SHA256(seed, "xbt/ticket/secret/v0" || nonce)` and is never stored). A wallet that never opens a
ticket session has neither. `scripts/ticket_book_regtest.sh` runs all of this through the release
binaries against Lightning Fork nodes; `tests/ticket_book.rs` against a fake node, with a kill at every
write step of a release, a lock, a settle and a start. `docs/LIMITS.md` states what the book does not do.

## Budget integrity and privileged methods (AGP-063)

Every signature that raises the signed amount is booked as the signed delta (`xbt402:<chan>:<cum>`)
before it is sent, never the seller's `charged`. The budget sums are held to that increase,
including a channel's dust floor (`PolicyEngine::evaluate_booking`). `minCapacity` above the owner's cap is
`deny/min_capacity`. A negative payment or amend is refused. `fund`, `open_channel`,
`xbt402_attach` and `xbt402_sign_rollover` are bound to an issued key, the seller's verified payTo
and the owner's bounds. `rotate_hot_key` and a live `deny_approval` need the human signature, and
the first `human_key_enroll` needs the one-time code. Passphrase blobs use scrypt N=2^17 with
`log_n`. Details, error codes and the wire changes are in the workspace README section
"Agent-wallet budget integrity and privileged methods (AGP-063)".

## No unbooked signature, no close on anyone's word (AGP-080)

- **Hash-locked last chunk.** A stream's last chunk is bought with a state that pays the plain
  amount plus the chunk to whoever holds the key. The ledger holds both before that state is
  signed. The plain state that folds the lock in books nothing more, and a seller that keeps the
  signature and withholds the key releases nothing.
- **Closed means spent on our node.** `xbt402_mark_closed` marks a channel closed only when this
  signer's node shows its funding output spent (`deny/close_unproven` otherwise; the claim is kept
  in memory and the watcher marks the channel closed when the spend arrives). `close_channel`
  reports the provider's close with `close_proven`; a close our node has not shown is recorded
  `close_unproven`, stays with the watcher, and is not replaced by a new channel
  (`deny/close_unproven`). If the funding is still unspent at expiry the record is opened again
  and refunded. `xbt402_attach` of `<origin>/next` needs the rollover on our node: the live
  channel's funding spent by the transaction whose output is the next channel's script and
  capacity (it waits up to `open_wait_s`, then `deny/rollover_unproven`; the issued key and the
  live record are kept). A live record is never overwritten.
- **Seller URLs.** `openUrl`, `closeUrl` and a stream's `chunkUrl` are the seller's strings. Each
  must be a path starting with one `/`, or an absolute URL on the channel's own origin, with no
  backslash, whitespace or control character (`xbt402::wire::seller_url`; `deny/seller_url`
  before any request). The HTTP client follows no redirect.
- **On-chain `pay`.** The payment is committed to the ledger before `sendtoaddress`. The node's
  own refusal (`rpc_refused`, a JSON-RPC error) takes the row back; any other failure leaves it
  (`onchain:unconfirmed:<id>`), because the node may have sent.
- **Keys in memory.** The hot keys, the channel payer keys, a `Payer`'s key and every plaintext
  the keystore opens are wiped when dropped. `SecretKey` is `Copy`: a copy made on the stack while
  signing is not tracked, and libsecp256k1's own scratch memory is its own.

## Files and durability (AGP-055)

One process owns a wallet directory. The files are B2's, byte format included: a directory written
by either signer opens in the other (`tests/custody_compat.rs`), except B2's routed-spend log
(`.run/routing.json`), which this signer no longer reads or writes.

- `.run/ledger.payments.jsonl` (the policy ledger's payments) is an append-only log (`src/applog.rs`): a header line
  `{"kind":...,"v":1}`, then one JSON object per line, each fsynced. A last line without its newline
  is a crash mid-append and is cut at start; any other line that does not parse stops the signer
  from starting (it never reads as a shorter log). A log is compacted (temp file, fsync, rename)
  once it holds over twice the rows still in use plus 1,024: payments are in use for the policy's
  longest window plus a day. `.run/audit.jsonl` keeps every commit.
- `.run/ledger.json` holds the pending approvals and `"payments_log": "ledger.payments.jsonl"`; it
  has no `payments` key. A settled or failed Lightning booking is a line
  `{"amend": txid, "amount_sats": n | null}` in the payments log. Files from before AGP-055 are
  converted at the first start.
- `src/fsx.rs` has the durable steps (write, fsync, rename, truncate, directory fsync) every file
  goes through, and `fsx::probe`, which counts them per thread and lets a test make any one the last
  thing the process does. Nothing in the signer arms it.

## Not ported

Each of these answers that it is unavailable:

- **The forward rail** (`forward.py`): `forward_status` answers `ported: false`, and `forward_recover`
  is refused. `xbt402_pay` refuses an offer with `extra.forward` before any payment
  (`deny/forward_disabled`).
- **The CSV treasury and the presigned vault**: `fund_treasury`, `recover_treasury` and
  `recover_vault` answer `ok: false`, and `balance` reports `vault`/`treasury` as null.
- **The Electrum light backend** (AGP-024). With `B2_CHAIN_BACKEND=electrum` the signer refuses to
  start; AGP-028 owns Electrum.

## Portability

The library has no platform-specific dependencies:

- No OpenSSL: HTTP is `ureq` with rustls/ring, the workspace's existing choice.
- No async runtime: blocking threads, like B2.
- File modes (0600/0640) are applied under `cfg(unix)` (`fsx.rs`).
- The socket (`ipc.rs`) is a Unix-domain socket on Unix, which is B2's protocol and is
  access-controlled by its 0600 mode. On every platform it can also be `tcp://127.0.0.1:PORT`,
  bound to loopback only.

`cargo check -p xbt-signer --bins` passes for:

- Linux on x86_64, aarch64, armv7 and riscv64 (glibc) and on x86_64, aarch64 and armv7 (musl);
- macOS on x86_64 and aarch64;
- Windows on x86_64 (gnu).

The C compiler for libsecp256k1 and ring is zig. An aarch64 binary links to 4.6 MB.

**What cannot be fully portable:** on Windows, std has no Unix sockets, so the signer listens on
loopback TCP. Any local user can connect to it, whereas a 0600 socket file restricts it to the
signer's user. Run it on a single-user host or firewall the port per user, until a named-pipe
transport is added. File modes are no-ops there; protect the run directory with ACLs.
