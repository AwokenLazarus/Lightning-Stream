# Stream tickets: the wire, draft v0

**Draft v0.** It was written down before any wallet or seller code so that it could be argued
with. Both sides are now built, and a wallet pays a gateway on regtest: the seller's side is
`xbt-gateway` (`crates/xbt-gateway`), and the buyer's side is the wallet's signer: the ticket book
(`crates/xbt-signer/src/ticket.rs` and `ticket_rail.rs`) and the HTTP binding under `xbt402_pay`
(`ticket_http.rs` and `ticket_pay.rs`, section 12). The numbers were measured on regtest (Lightning
Fork nodes, default settings, one host, loopback) by the script each sentence names:
`scripts/ln_ticket_regtest.sh` where none is named, `scripts/gateway_regtest.sh` for the gateway
with a test buyer, `scripts/ticket_book_regtest.sh` for the book, and
`scripts/ticket_e2e_regtest.sh` for the wallet paying the gateway; anyone can rerun them. The few
that come from reading the node's source say so. Nothing here has run on mainnet. Sections 10, 13
and 14 list what building each side changed in this draft. Section 11 (2026-10-12) sets the
defaults again for channels that carry 30 pending payments, which is Core Lightning's default,
and for the dust limits; it was measured with the XBT Core Lightning fork in the lab. Since
2026-10-13 the wallet and the gateway in this tree have those defaults and keep those rules, and
both build the prepaid tickets of section 5 (section 14). Section 9 is the lottery: pieces priced
below a ticket, paid by draws with nothing held; both sides build its first form, in which the
buyer pays after a win, and `scripts/lottery_regtest.sh` runs it. XBT is Bitcoin on BLAKE2b proof
of work; "the SHA-256 chain" is the other chain.

A **ticket** is a small Lightning payment that is locked along an ordinary route and not yet
released. The buyer picks a 32-byte secret and gives the seller its SHA-256 hash. The seller's node
issues a hold invoice for that hash, and the buyer's node pays it. The money is now committed to the
seller along the route, and nobody can take it, because only the buyer knows the secret. To pay for
a request the buyer puts the secret in the request. The seller hashes it, finds the ticket, collects
and serves. Tickets are locked a few at a time, ahead of use, so no request waits for a payment.
This needs no change to the Lightning node: it is `AddHoldInvoice`, `SettleInvoice` and
`CancelInvoice`, as nodes ship them.

None of the parts is ours. Hold invoices are lnd's (Joost Jager, 2019). A payment that the payer
releases in a second step was proposed for Lightning by Hiroki Gondo in 2019 as "stuckless
payments", with point locks. The 402 shape is x402's. The lab is Paul Lamb's
`lightning-fork-lab` (commit `a5cadc5`), and the nodes are his Lightning Fork at
`v0.21.3-beta-blake2b.17`, a fork of lnd, on a Bitcoin Knots BLAKE2b regtest. References:
[`REFERENCES.md`](REFERENCES.md).

Words: MUST and SHOULD are followed by what goes wrong otherwise. Amounts are millisatoshi (msat)
as decimal strings; hashes, secrets and keys are lower-case hex.

## 1. Terms: the 402

A seller that takes tickets adds one entry to `accepts` in its `402` (`PAYMENT-REQUIRED`, x402 v2):

```json
{"scheme": "ticket", "network": "lightning:0000000000000050c1e5f69672f45929",
 "asset": "XBT:msat", "amount": "2500", "payTo": "<the seller's Lightning node id, 33 bytes>",
 "extra": {"version": "ticket/0", "features": [512],
           "ticketMsat": "1000000", "maxTickets": 2, "ticketBlocks": 40,
           "release": "with-request", "settle": "on-use",
           "receiptKey": "<33-byte public key>", "session": "/x402/ticket",
           "price": {"requestMsat": "2500", "byteMsat": "0", "perBytes": "1", "secondMsat": "0"}}}
```

| Field | Meaning | Why |
|---|---|---|
| `network` | `lightning:` and the 32 hex characters of the chain's `bip122` id. Not the chain id itself. | A client picks an entry by scheme and network. The chain id names the chain itself (it was the network of the on-chain channel entry this project once had). XBT and the SHA-256 chain share a genesis block, so a Lightning id keyed on it would name both networks. |
| `features: [512]` | Every invoice of this entry carries feature bit 512, required. | Bit 512 is what separates an XBT Lightning invoice from one of the SHA-256 chain. The wallet's Lightning rail already refuses an invoice without it. |
| `amount` | The price of this request before its body, in msat: `price.requestMsat`. | Pieces are metered below one sat; money moves a ticket at a time (section 3). |
| `price` | The whole price rule: `requestMsat` once per request, `byteMsat` for every `perBytes` bytes of the response body (rounded up over the whole body), `secondMsat` for every started second the response is open. | A body priced by its size or its duration has no price before it is sent (section 4). |
| `payTo` | The node every ticket invoice must name as payee. | The 402 came over TLS from the seller. An invoice naming another node pays a stranger. |
| `ticketMsat` | The size of one ticket. | One size per session, so that an invoice has one right amount. |
| `minTicketMsat` | Optional. The smallest ticket the seller issues when a buyer asks for a smaller one (section 2). Absent: `ticketMsat` is the only size. | A buyer that pays many sellers a little each sizes its tickets to what a seller will earn; without this a seller cannot say how small it will go. A ticket that is held is never below 546 sat (section 11). |
| `maxTickets` | The most tickets the seller holds unreleased for one session. | Each held ticket takes one HTLC slot of every channel on the route, and the seller's inbound capacity. A channel has between 30 and 483 slots each way, for everyone who uses it (section 11). |
| `ticketBlocks` | The final CLTV delta of every ticket invoice: how long a ticket lives. | It bounds how long the buyer's money can be locked (section 6). |
| `release` | `with-request`: the secret comes with the request. `after-verify`: section 5. | Who goes first, and so who risks one piece. |
| `settle` | `on-use`: tickets are held until used. `on-arrival`: section 5. | Whether a ticket can be had back. |
| `receiptKey` | The key that signs the seller's receipts. | With tickets the payment preimage proves nothing: the buyer always knew it. The signed receipt is the proof of what was paid for. |
| `session` | Path of the session endpoints on the seller's origin. | |

A buyer MUST refuse an entry whose `ticketBlocks` is above what its owner allows, and one whose
`ticketMsat` is above it unless `minTicketMsat` lets it ask for a size its owner does allow, or it
locks more, or for longer, than the owner agreed to. `maxTickets` is the most the seller will hold:
a buyer whose owner allows fewer locks fewer.

In an entry with `settle: "on-use"`, `ticketMsat` and `minTicketMsat` MUST be at least 546000
(546 sat), or the ticket has no output in a Core Lightning channel's transaction and nobody can
claim it on chain (section 11). The terms carry no slot count and no dust limit: each side reads
those of its own channels, and neither could check a number the other sent.

A seller that settles both ways lists two entries, alike but for `settle` (and, if it likes, the
ticket size): the `on-use` one first. A buyer takes the first entry it can use. One that knows
only held tickets skips the other, since an entry it cannot read is an entry it does not take.

## 2. Lock

```text
POST <session>/lock    {"version": "ticket/0", "session": "<id, absent the first time>", "hashes": ["<h1>", "<h2>", ...],
                        "ticketMsat": "<the size asked for, optional>"}
200                    {"session": "<id>", "key": "<32 bytes, the first time only>",
                        "tickets": [{"hash": "<h1>", "invoice": "<BOLT 11>"}, ...],
                        "refused": [{"hash": "<h>", "error": "hash_refused"}, ...]}
```

A lock for tickets settled on arrival (section 5) names no hashes: its body is
`{"version": "ticket/0", "settle": "on-arrival", "count": <n>}`, and the answer has the same
shape, with hashes of the seller's choosing. Without `settle`, a lock is for held tickets.

The first lock of a session carries no authentication and makes the session. Every later lock is
a request of that session and carries `PAYMENT-SIGNATURE` as any paid request does (section 3):
without it, anyone who learns a session id can fill that session's ticket places. A request names
at most `maxTickets` hashes. A hash the seller's node will not issue (it has had an invoice for
that hash before, in any session) comes back under `refused`; a first lock that issues nothing
makes no session.

The buyer derives each secret in its signer, from its own seed, and sends only the hashes. The
seller registers a hold invoice per hash (`AddHoldInvoice`: the hash, `ticketMsat`, a final CLTV
delta of `ticketBlocks`, a time expiry of 60 seconds) and returns the invoices, for as many of the
hashes as its cap allows, in order. `key` is a session key for authenticating requests (section 3);
it travels once, over TLS. A secret is for one invoice. The buyer MUST NOT send a hash twice, even
after a payment that failed: an HTLC for it may still be somewhere on a route. `ticketMsat` in the
request is the size the buyer wants for this session, between the terms' `minTicketMsat` and
`ticketMsat`; a seller whose terms have no `minTicketMsat` ignores it and issues its one size, and
the buyer, which knows that from the terms, does not ask. A buyer drops a hash it got no invoice
for after two minutes: an invoice that arrives later is not paid.

Before paying each invoice the buyer MUST check all of these. They are the whole of the buyer's
safety, since a paid ticket cannot be recalled:

| Check | What goes wrong without it |
|---|---|
| The payee is `payTo`. | The ticket pays another node. |
| The payment hash is one of the hashes just sent, and none is used twice. | An invoice for any other hash is an ordinary invoice: whoever knows its preimage takes the money on arrival. |
| The amount is exactly the session's ticket size: `ticketMsat`, or the size the buyer asked for. | The buyer locks more than the terms said. |
| Feature bit 512 is set and required; the prefix is XBT's. | The wallet pays on the SHA-256 chain's Lightning network. |
| The final CLTV delta is `ticketBlocks`, and within the owner's bound. | Funds can stay locked for as long as the seller wrote (the node's ceiling for a route is 2,016 blocks, from its source). |
| With this ticket, unreleased tickets for this seller are at most `maxTickets`, and their sum is within the owner's cap on locked funds. | A seller that asks for more locks more. |
| The amount is at least 546 sat, and at least the dust limit of each side of the channel the payment will leave on, as the buyer's node reports them (section 11). | A ticket below a channel's dust limit has no output there. Nobody can claim it on chain, and it is lost to the miners if that channel is force-closed while it is held. |
| With this ticket, the payments pending on the channel it will leave on are at most half of that channel's slots: the smaller of the two `max_accepted_htlcs` the buyer's node reports for it (section 11). | The channel's slots are shared. Measured on a 30-slot channel: the 31st ticket failed, and so did an ordinary payment. |
| The invoice is payable for no longer than the owner allows (an hour by default), has not expired, and has a payment secret. | An invoice that stays payable is one the buyer's node could still pay long after the buyer gave the hash up. |

The buyer's node then pays each invoice, under all the checks the wallet's Lightning rail already
makes of its own node and channels, with a fee limit and a limit on the route's total time lock
(`cltv_limit`), both set by the owner. Each hop adds its own time lock delta to the buyer's
HTLC (80 blocks per hop at the forks' default): a 40-block ticket through one hop is an HTLC that
expires 123 blocks after it was locked. Without the limit, a long route decides how long the
buyer's funds can be stuck behind a hop that has gone away.

**The buyer's tag.** A ticket payment MAY carry one custom record to the seller's node: type
1953063787 (odd, so a node that does not know it ignores it), 32 bytes, a nonce and a MAC under a
key only the buyer's wallet has. It says nothing to the seller, which ignores it. The buyer's own
node keeps it with the payment, and that is its use: a wallet whose records are older than its
node's (a restore from a backup) reads its node's payment list and knows which payments are its
tickets. On the lab the record reached the seller's hold invoice and stayed in the buyer node's
record of the payment while it was in flight and after it settled; a failed payment's record no
longer lists it.

A ticket is **locked** when the seller's node shows its invoice as `ACCEPTED`. The buyer's node shows
the payment as `IN_FLIGHT` and stays that way until the ticket is settled or cancelled. The buyer
sees `IN_FLIGHT` first, by about one commitment exchange per channel on the route (0.1 s each on
the lab), and cannot see `ACCEPTED` at all. A buyer that releases a ticket in that moment gets
`ticket_not_locked` (section 3); the seller has not used the ticket, and the buyer sends the same
secret again. On the lab a buyer that paid as soon as its own node showed 8 tickets in flight was
answered so and served on the retry. A buyer SHOULD wait for the seller's own word instead: the
session's signed `status` (section 4) lists each ticket's state, and the wallet built here releases
a ticket only after `status` has shown it `ACCEPTED`, for a bounded time (3 s by default), so that
no secret leaves for a ticket the seller cannot yet use. Locked funds
are not spent. They count against a cap on locked funds, not against a budget.

The seller MUST cap sessions as well as tickets per session, and SHOULD let an unpaid invoice lapse
within a minute, or anyone can fill its node with invoices and its channels with held payments at
no cost but locking the same amount of their own money. An unpaid invoice is cancelled by the node
when its time expiry passes. A locked ticket is not: only block height ends it (section 6). A lock
the caps refuse is `402` with `too_many_tickets` or `too_many_sessions`, and asks the node for
nothing.

The seller MUST also cap the tickets it holds for all sessions together, at half of its inbound
HTLC slots (15 where a channel has 30, section 11), or a few buyers fill its channels and nobody
else can pay it. A lock that cap refuses is `402` with `slots_short` and `retryAfter` (seconds),
and asks the node for nothing: a buyer that is told waits, where a buyer whose payment fails for
lack of a slot is told only that its balance is short. A first lock that is refused so makes no
session. An invoice counts against the cap from the moment it is issued, paid or not, so a
buyer whose payment for one failed SHOULD ask for it to be cancelled (section 4) and not leave
it to lapse: the wallet built here does, after every lock round.

How the seller learns that a ticket is locked: the node's stream of all invoices
(`SubscribeInvoices`) reports an invoice when it is added and when it is settled, and nothing in
between (seen on the lab). A held invoice is reported only on that invoice's own stream
(`SubscribeSingleInvoice`), with the height it was accepted at and the height its HTLC expires
at. A seller follows one such stream per unreleased ticket, or looks each ticket up.

## 3. Paying a request

```text
PAYMENT-SIGNATURE: base64({"x402Version": 2, "accepted": <the accepts entry>,
    "payload": {"session": "<id>", "seq": <n>, "secret": "<32 bytes, or absent>", "auth": "<HMAC>"}})
auth = HMAC-SHA256(key, "ticket/auth|" session "|" seq "|" secret "|" ticket "|" request_digest_v2)
```

`seq` starts at 0 and rises by one per request in a session. `request_digest_v2` is the hex of
`tagged_hash("xbt402/req/v2", f(method) ‖ f(scheme) ‖ f(host) ‖ f(port) ‖ f(target) ‖ f(body))`,
where `f(x)` is the length of `x` as 8 bytes little-endian followed by `x`, `tagged_hash(t, m)` is
`SHA-256(SHA-256(t) ‖ SHA-256(t) ‖ m)`, the scheme and host are lower case, and the port is
its decimal number, 80 or 443 when the URL names none (`xbt402::wire::request_digest_v2`). A field that is absent is
empty in `auth` (`ticket` belongs to section 5). A request needs no ticket id: **the secret names
its ticket**, since its hash is the ticket's payment hash.

Every request of a session is authenticated this way: a paid request for a resource, and the
session's own `lock`, `release`, `cancel` and `status` (section 4), whose JSON bodies the digest
covers. A `seq` is used up by a request whose `auth` was good and whose `seq` was the next one,
whether it was then served or refused; its answer carries a receipt. A request that was not
authenticated uses up nothing and gets no receipt: `401 bad_auth`, or `402 bad_seq` with the
`nextSeq` the seller expects, which a buyer adopts (a seller can lose its last half second of
counters in a power cut). The buyer sends the requests of one session one after another, the next
when the head of the last answer has arrived: two sent together can arrive out of order.

The session has a balance in msat. Each secret released adds `ticketMsat`; each request served
subtracts its price. A request carries a secret when the balance does not cover its price, and none
otherwise. The seller, for each request, in this order:

1. Checks `auth` and that `seq` is the next one. Without `auth` anyone who sees a session id spends
   its balance. Without `seq` a replayed request is served twice.
2. If there is a secret: hashes it and finds that ticket in this session. The ticket MUST be
   `ACCEPTED` on the seller's own node for the full `ticketMsat` (by a lookup, or from the node's
   invoice subscription), not used before, and MUST have more than 24 blocks left before its HTLC
   expires. The seller MUST mark it used before going on, or two requests arriving together with
   one secret are both served for one ticket.
3. Settles (`SettleInvoice` with the secret) and checks the call succeeded. The seller MUST settle
   before it serves, and at once, never "later": its own node cancels a ticket it still holds 18
   blocks before expiry, and a ticket cancelled is a ticket not paid. The node refuses to settle a
   ticket that is not locked (`invoice still open`), one that was cancelled (`invoice already
   canceled`) or a secret that is not a ticket's (`unable to locate invoice`). **It does not
   refuse a ticket that was settled before: a second `SettleInvoice` with the same secret answers
   success** (seen on the lab). The call's success therefore shows the ticket was not open or
   cancelled, and nothing more. What makes a secret good once is step 2: the seller has seen the
   ticket `ACCEPTED`, and marks it used itself before it settles.
4. Serves, and returns `PAYMENT-RESPONSE` with a receipt signed by `receiptKey`:
   `{"scheme": "ticket", "session", "seq", "releasedMsat", "spentMsat", "charged", "req", "status",
   "bodyHash"}`. What is signed is `tagged_hash("xbt402/ticket-receipt/v0", f(v1) ‖ … ‖ f(v9))`
   over these fields in this order, each value as its decimal or plain string (a JSON number and
   its decimal string sign alike), `f` and `tagged_hash` as in the request digest above; the
   signature is ECDSA on secp256k1, strict DER, low S (`xbt402::ticket::receipt_message`). `releasedMsat` is the sum of the
   tickets settled in this session and `spentMsat` the running total of what was served.
   `releasedMsat` only rises. `spentMsat` rises as pieces are served, and falls only by what the
   seller charged ahead of sending and then did not send (an answer the buyer stopped reading).

The step-2 height is the seller's node's, and the seller's macaroon of section 7 cannot read it:
with `invoices:read` and `invoices:write` the node answers `permission denied` to `GetInfo` and to
the chain kit's best-block call (seen on the lab), and no invoice call returns the height the
chain is at now. The seller needs a second
macaroon with `info:read`, or another source of the height. Without a height that is a few seconds
old at most, a seller MUST NOT take a secret: it cannot show the ticket is outside its margin.

The node's own record is what keeps a secret good once across a restart: a settled ticket is
`SETTLED`, not `ACCEPTED`, and a seller that has lost its memory reads each ticket's state from the
node before it uses it (it must not rely on the settle call to refuse, as step 3 says). What the
node shows as `SETTLED` for a session is what that session released. The seller stores each
session's key, `seq` and `spentMsat` itself; one that loses them costs each buyer the unused part
of its tickets, or serves again what it had served, depending on which it lost.

If the request cannot be served (no balance, a ticket not locked, too old or used), the seller
answers `402` again with one of `ticket_unknown`, `ticket_not_locked`, `ticket_used`,
`ticket_expiring`, `balance_short`, `session_unknown`, `too_many_tickets`, `too_many_sessions`,
`slots_short`,
`pledge_outstanding` (section 5), or `503` with `node_unavailable` when its node gives no answer or
no fresh height: the secret was not taken, and the same request with the next `seq` is good later.
A refusal of an authenticated request is signed like any answer: its receipt has `charged` 0 and
the session's totals, so a buyer can tell a refusal from the seller from one made up on the way.

The buyer does not release a ticket with 25 blocks or fewer before the expiry of the HTLC at the
seller, as its own node reports it: the seller would refuse it at 24 (step 2), and a secret sent
with a refused request has left all the same.

The buyer MUST record a ticket as spent, on disk, before its secret leaves the signer, whatever the
reply turns out to be. A secret that has left can be collected at any time until the ticket
expires, so a wallet that books on the reply under-counts what it spent after a crash or a refusal.
The buyer books what it released plus the routing fee its own node reports, never a number the
seller sends. It checks each receipt against its own count, and stops if `spentMsat` exceeds what it
asked for or `releasedMsat` differs from what it released. The requests MUST go over TLS (or
loopback): on a plain connection a listener learns the session key.

The wallet built here never puts a secret in a request for a resource: every secret travels in
`release` (section 4), and requests are paid from the balance. A secret then has one path and one
answer, and a request that is refused has cost no secret (section 12).

A buyer that starts cannot tell a restart from a restore of older records, in which a ticket shown
as locked may have been released since. It MUST treat every ticket that was locked before the start
as released: counted as spent, never released by it, until its own node shows the payment settled
or failed. A seller therefore sees a buyer that has restarted stop its session and ask for its
tickets to be cancelled.

On the lab a paid request cost the seller about 1 ms to hash the secret and look the ticket up on
its node, and about 4 ms in all until the settle call returned. The buyer's node showed the payment
`SUCCEEDED`, with the buyer's own secret as the preimage, about 13 ms after the request (medians of
30, one hop, loopback). On a shared host the runs gave 0.9 to 1.2 ms, 3.3 to 5.4 ms and 12 to 34 ms.

Through the gateway (`scripts/gateway_regtest.sh latency`; medians of 300 requests, loopback, a
260-byte file behind it): 0.45 ms direct to the file server, 0.56 ms through a free route and
0.63 ms paid from the balance. A paid request added 0.07 to 0.11 ms over an unpaid one in five
runs. The one request in a ticket's worth that carries a secret waits for the node's settle call:
it added 3.4, 3.5 and 3.6 ms on a lab just set up, and 5.7 and 6.0 ms on one that had run for an
hour (medians of 32). The longest any secret waited for its settle was 19 ms.

## 4. Refill, long answers, stop, cancel

**Refill.** When fewer than a set number of tickets are unreleased, the buyer locks more, in the
background, up to `maxTickets`. Locking 8 tickets took 0.3 s through one hop, 0.2 s on a direct
channel and 0.5 s through two hops (100 tickets: 2 s through one hop), and locking one took
0.2 s. With the default of 2 tickets the buyer locks the next when one is left, which covers any
buyer that spends less than one ticket in that time. A buyer that spends faster asks for larger
tickets, not for more of them (section 11). A ticket with 24 blocks or fewer left can no longer be
used (section 3, step 2): the buyer SHOULD ask for it to be cancelled and lock a fresh one. A
40-block ticket is usable for 19 blocks by the seller's rule, and for 18 by a buyer that stops
one block earlier.

A buyer with many sellers in one task locks fewer tickets with each: 2 with each of up to 4
sellers, and 1 with each beyond that, for as long as all its held tickets fit in half the slots of
the channel they leave on (15 on a 30-slot channel). Beyond that it holds no ticket with a further
seller, and pays it by a ticket settled on arrival (section 5) or after a lottery win (section 9).
Where the seller's terms let it choose a size it takes one near what the seller is expected to
earn, never below 546 sat. These are the wallet's defaults (`tickets.pool`, `pool_many` and
`many_sellers` in the owner's policy): from one 30-slot channel it holds tickets with 11 sellers
of one task, 4 at 2 each and 7 at 1 each.

**A lock that fails for lack of a slot.** A ticket payment that ends `FAILED` with
`INSUFFICIENT_BALANCE` on a channel that has the balance, or with `TEMPORARY_CHANNEL_FAILURE` or
`NO_ROUTE` after an earlier lock with the same seller worked, has most likely met a full channel
(section 11). The buyer MUST NOT send that hash again, and SHOULD NOT lock again at once: it cuts
the session to one ticket and waits (30 seconds, doubling to 10 minutes), and if one ticket does
not lock either it stops holding tickets with that seller and pays it another way or not at all.
A buyer that keeps trying fills the last free slots of a channel other people are using. The
wallet built here halves the session's pool at each such round, stops holding after the third in
a row for ten minutes, and carries what it learnt to its next session with that seller, so that
a new session is no new start (section 14).

**An answer priced as it goes.** A body priced per byte or per second (section 1, `price`) is paid
for while it is sent: the seller takes the price of each piece of the body from the balance before
it sends that piece, and of each second as it starts. When the balance runs out it stops sending
and waits a few seconds for more; then it ends the answer, cut short where the buyer can see it
(a body shorter than its `Content-Length`, or a chunked body with no last chunk). The buyer keeps
such an answer going with `POST <session>/release {"secrets": ["<s1>", ...]}`: each secret is
taken as in section 3, steps 2 and 3, and the answer names the hashes `released` and those
`refused`, each with its code. A buyer that releases one ticket when the last is used up is never
more than one ticket ahead of what it has received; what it has not used stays its balance.

The head of such an answer carries a receipt for what was charged before the body (`bodyHash`
empty, and `"stream": true` beside the receipt). The receipt for the whole answer, with the bytes
sent, their hash and their price, is in the answer to `POST <session>/status {}`, under
`responses`, signed for the request's own `seq`; `status` also lists the session's tickets with
their state and expiry height. On the lab a 100 MB file at 200,000 msat per MiB, fetched through
a hop with one ticket released each time the last was used up, stopped after the tenth ticket at
52,428,800 bytes: what ten tickets pay for, to the byte (`scripts/gateway_regtest.sh fetch`).

**An answer without a body.** A `HEAD`, and a `GET` the service answers with 204 or 304, costs
the request's price and no byte or second: on a route priced only by the byte or the second it
costs nothing. Its headers are still the service's (a length, an ETag, a date), so a seller
SHOULD NOT give such an answer to a session that has paid nothing, or anyone who asks for
tickets and pays none reads them for as long as that session lives. The gateway serves a request
of a priced route, with a body or without, only to a session whose balance covers the request's
price and the body's first byte and first second (`balance_short` otherwise); it charges a
`HEAD` what it did before. A session of draws (section 9) has no balance and costs nothing to
open, so there the rule is the piece: a `HEAD` of a route with no price per request has no piece,
is not offered by lottery (its 402 lists the ticket entries only) and is refused
(`amount_not_below_win`) before the service is asked; and a `GET` such a route answers without a
body is passed on as its status alone, with none of the service's headers. A `HEAD` of a route
that has a price per request is that request's piece, and is served like any other.

**Stop and cancel.** `POST <session>/cancel {"hashes": [...] or "all"}`, authenticated as any
request of the session. The seller cancels those tickets on its node (`CancelInvoice`) and answers
with the hashes it cancelled and a receipt. The seller SHOULD NOT take the call's success for the
ticket's state: a ticket it drops as cancelled that its node had in fact settled (a settle whose
answer was lost) is money it holds and never credited. The gateway looks each ticket up after
the call and follows what the node shows: cancelled, or settled and then credited. The buyer's funds are free as soon as the cancel has travelled back
along the route: 0.16 s for 8 tickets on the lab. The buyer believes its own node, not the answer:
a ticket is free when its payment shows `FAILED` there. The seller SHOULD also cancel the tickets
of a session that has been idle for some minutes, and SHOULD cancel a ticket that has reached its
margin, which it can no longer use. Held tickets cost it inbound capacity, and they are what
closes its channel if its node goes down (section 6). The gateway cancels after 5 minutes without
a paid request, after 1 minute for a session that has never released a secret, and at the margin.

Cancelling needs the seller. A seller that does nothing leaves the buyer's tickets locked until
they end by block height.

## 5. Two settings

**`settle: "on-arrival"` (a prepaid balance).** For a seller whose node has no hold invoices, and
for any seller when slots are short: such a ticket is an ordinary payment, in flight for a
fraction of a second, and holds no slot on any channel. The buyer sends no hashes, only a count
(section 2). The seller returns ordinary invoices with hashes of its own, for the terms'
`ticketMsat` and with `ticketBlocks` as their final CLTV delta, and each is paid in full when it
arrives. The buyer's node receives the preimage, and that preimage is sent as a secret in
`release` (section 4). The seller credits it for a `SETTLED` invoice of the session, once.
Everything else is the same. The difference is in what can be lost: every ticket bought is spent
at once, used or not, so the buyer's exposure is everything it has bought ahead and not one
ticket. A buyer SHOULD buy one such ticket at a time, when its balance no longer covers the next
piece, and MUST record it as spent before its payment is sent: a payment that has left cannot be
recalled, and a wallet that books on the preimage under-counts after a crash.

Before paying such an invoice the buyer checks what it checks of a held ticket's (section 2):
the payee, the exact amount, feature bit 512, the final CLTV delta, the time it stays payable,
the payment secret. It does not check the hash against its own, since the hash is the seller's,
and it does not apply the dust and slot checks, since nothing is held. The seller MUST credit a
session only for an invoice its own node shows settled for the full amount, and MUST NOT take
the preimage alone as proof: a preimage is known to the seller's node from the start. The
gateway built here makes the preimage itself, gives it to the node with the invoice and keeps no
copy; it credits the session when the buyer presents the preimage and the node shows the invoice
settled, and credits a paid ticket nobody presented when its sweep finds it (75 seconds after
issue). A buyer that presents a preimage after that is answered `ticket_used`, and finds the
ticket in the session's signed totals.

**`release: "after-verify"` (pay only for what checks out).** For content the buyer can check piece
by piece, such as chunks with a Merkle proof against a root in the terms. A request names the
ticket that will pay for it by its hash (`"ticket": "<hash>"`) and holds the secret back. The
seller checks that ticket is locked, whole and outside its margin, and serves on it: pieces up to
one ticket's worth, and nothing beyond until it has the secret. The buyer verifies what it got
and sends the secret (with its next request, or with `release`); a session pledges one ticket at a
time, and none while it owes for a piece (`pledge_outstanding`). A pledged ticket whose secret
never comes is cancelled by the seller's node 18 blocks before its expiry, and the session then
owes what it was served: its next tickets pay that first. Here the seller risks one ticket's worth
per session and the buyer nothing, so the seller sets `ticketMsat` to the price of what it will
risk. A key that unlocks the whole (a hash-locked last chunk) is an ordinary
Lightning invoice whose preimage is that key: paying it reveals it, across any number of hops.

## 6. What each side can lose

| Who | Worst case | Bound, and what the lab showed |
|---|---|---|
| Buyer | **One ticket** (`with-request`). A seller takes the secret and serves nothing. | It cannot take the next one: the buyer releases one secret at a time and stops. |
| Buyer | **The unused part of the last ticket.** A ticket cannot be partly released. | Less than one ticket. Trusted to the seller, by design. |
| Buyer | **Funds locked, not lost: a seller that neither settles nor cancels.** | The seller's node cancels 18 blocks before the ticket's expiry: 25 blocks after the lock for a 40-block ticket. All channels stayed open. |
| Buyer | **Funds locked, not lost: a seller whose node has gone.** | The hop closed its channel to the seller on chain at the tickets' expiry (43 blocks after the lock) and the buyer's funds were free 47 blocks after the lock, 48 with 100 tickets. The buyer's own channel stayed open and its balance was unchanged. |
| Buyer | **Funds locked, not lost: a hop that has gone.** | Until the buyer's own HTLC expires: 123 blocks through one hop at the default, which is what `cltv_limit` bounds. Then the buyer's node closes that channel on chain. Not run here. |
| Seller | **Nothing**, if it serves only after a successful settle of a locked ticket. | Settle returned in 4 ms with the hop stopped, and the buyer's node had the secret as soon as the hop was back. After a restart of the seller, the hop or the buyer the tickets were still `ACCEPTED` and settled. |
| Seller | **A ticket it served and did not settle** in time. | Its own node cancels it 18 blocks before expiry. So: settle first, then serve. |
| Seller | **An on-chain claim**, when it settled and the hop then stays away. | Its node closed the channel 16 blocks before the tickets' expiry and had the secrets on chain 12 blocks before it. It kept the 3 tickets (3,000 sat), paid 900 to 1,700 sat in fees at 1 sat/vB (five runs), and waited about 650 blocks for its funds, its whole channel balance with them. The buyer's node learned the secrets from the chain when the hop returned. |
| Seller | **A closed channel**, if its node is offline when locked tickets expire. | As in the fourth row: the hop closes it. The seller's balance comes back on chain. |
| Routing hop | **Slots and capacity held for no fee.** A cancelled ticket pays nothing: 10 locked and 5 settled cost the buyer 5,005 sat for 5,000 delivered. A hop's slots are shared by all who route through it: through a Core Lightning hop one buyer held 20 tickets and a second got 10 of the 20 it asked for. | `maxTickets`, `ticketBlocks` and the half rule of section 11. This is Lightning's known jamming exposure. Tickets use it on purpose, which is why the defaults are small. |
| Seller | **Being unreachable**, when held tickets fill its inbound slots. | With 30 tickets held on a 30-slot channel an ordinary payment over it failed. A buyer free to route filled the seller's other channels too: 70 tickets held on three. The seller's cap on what it holds for all sessions is the only bound. |
| Any node on the route | **A ticket below a dust limit, if that channel is force-closed while it is held.** | Its value goes to the miners. Not possible for a ticket of 546 sat or more on the channel types the forks open by default. |
| Routing hop | **The cost of a force close** when a seller vanishes with tickets locked, if the hop opened that channel. | With 100 tickets: a commitment transaction of 18,313 weight units and 104 outputs, 4,635 sat in fee, and about 29,000 sat in all to get its funds back at 1 sat/vB, which is 29% of the tickets' value. With 3 tickets it was 1,530 sat. |

Two more things that are true of any Lightning payment and matter more here. Every hop sees the
same hash, so hops that work together can tell that a run of equal payments goes to one seller.
And a ticket below a channel's dust limit has no output in that side's commitment transaction, so
nobody can claim it on chain. The limit is 354 sat on a Lightning Fork node and 546 sat on a Core
Lightning node, and each node caps the total of such HTLCs per channel (section 11).

## 7. The numbers and their reasons

| Number | Value | Reason |
|---|---|---|
| Ticket size | 1,000 sat | A hop charges 1,001 msat for a settled 1,000-sat ticket at the forks' default policy (0.1% per hop; nothing on a direct channel, 2,002 msat through two hops). Above both dust limits (354 and 546 sat), so it has an output in every channel on the route and can be claimed on chain. |
| Smallest ticket that is held | 546 sat, the larger of the two dust limits | Below 354 sat a ticket has no output in a Lightning Fork channel's transaction, below 546 sat none in a Core Lightning one (seen on chain, section 11). At 546 sat one hop's fee is 0.18%. A node takes nothing below 1 sat (999 msat found no route, through a Lightning Fork hop or on one channel), and a 1-sat ticket through a hop pays a fee of 1 sat. |
| Tickets unreleased per session | 2 | 2,000 sat locked and 2 slots of every channel on the route, of which a Core Lightning channel has 30. The next is locked when one is left; a lock of one takes 0.2 s through a hop. It was 8 until 2026-10-12, sized for 483 slots. |
| Held tickets on one channel, all sessions together | Half of the channel's slots: 15 of 30 | The other half is for ordinary payments, for settles on their way and for everyone else (section 11). |
| Ticket life (`ticketBlocks`) | 40 blocks | The node takes no less than 24. The seller's node cancels at 18 before expiry, the seller stops accepting at 24 before, and the payer's node adds 3: so 19 usable blocks, and at most 25 blocks locked behind a silent seller. |
| Seller's margin | 24 blocks before expiry | 18, when its node cancels the ticket itself, and 6 more for a settle that has to go on chain (the node starts that 16 blocks before expiry). The 18 is the node's `invoices.holdexpirydelta`, a setting of the node's runner: 18 on the Lightning Fork node at its default, 12 on upstream lnd. The node does not tell it, so the gateway takes it from its config (`node.hold_expiry_delta`, 18 unless the runner says otherwise) and refuses to start when it is above 18: the margin is one number for both sides (a buyer stops releasing a ticket at 25 blocks), so it is not moved to fit a node. |
| Invoice time expiry | 60 s | Long enough to pay through a few hops (0.5 s through two), short enough that unpaid invoices do not pile up. |
| Tickets in flight per channel | 30 on a Core Lightning channel, 483 at most | 483 is the protocol's limit and Lightning Fork's default; 30 is Core Lightning's default, each way, set when the channel opens. Between Lightning Fork nodes, of 520 offered at once 483 locked in 8 s and 37 failed on the buyer's node (`INSUFFICIENT_BALANCE`) with nothing held; to a Core Lightning node, of 40 offered 30 locked and 10 failed the same way. 483 tickets take a commitment transaction from 1,116 to 84,200 weight units. |
| Macaroons | Buyer: `info:read`, `offchain:read`, `offchain:write`, `onchain:read`. Seller: one with `invoices:read`, `invoices:write`, and one with `info:read`. | The buyer's was enough for its side. The seller's invoice macaroon makes, follows, settles and cancels tickets and cannot read the block height; the second one reads it. Neither could send coins, pay, open a channel, read the wallet or bake another. |
| Seller's caps (the gateway's defaults in this tree) | 15 held tickets for all sessions together, 2 a session, 30 sessions, 2 from one address | What buyers can hold of the seller's inbound capacity at no cost to them: 15,000 sat and half of one 30-slot channel. A runner whose inbound channels all carry more says so (`caps.inbound_slots`), and one with several channels may raise the cap past half of one (`caps.held_over_half`). Until 2026-10-13 the defaults were 8 a session and 240 in all. |
| Ticket payments with the buyer's router at once | 8 | On a 30-slot channel, 200 small payments sent 8 at a time all succeeded, and 139 of 200 sent 64 at a time failed (section 11). A win of the lottery is one of them. |
| A win of the lottery (section 9) | 64 sat, 16 at the least | A hop's base fee of 1 sat is 1.6% of 64 sat and 6% of 16. A win is paid at once and never held, so the dust limits and the slot budget do not apply to it. |

## 8. Open in this draft

- The scheme name and the `lightning:` network id are ours. Nothing upstream defines them.
- What `auth` covers in a second `lock` and in a `cancel` is not written down: section 3 defines it
  for a paid request only.
- A lock is not idempotent. If the answer to a lock is lost, the seller holds invoices the buyer
  never pays; they lapse, and the buyer's next lock sends new hashes.
- The custom record type of the buyer's tag is ours, as the scheme name is.
- Receipts are signed by a key the 402 names. Nothing ties that key to the node id but the TLS
  origin that served both.
- BOLT 11 only. The fork's BOLT 12 offer code issues each invoice with its own preimage and has no
  hold path.
- The Core Lightning fork (v26.06.9-blake2b.7) was run as buyer, hop and seller on the lab
  (section 11). As buyer and hop it needs nothing. As seller it has no hold invoice call: a ticket
  was held through its `htlc_accepted` hook by a lab plugin only. Of the two published hold
  plugins, one issues invoices without feature bit 512, which a Lightning Fork buyer refuses, and
  the other keeps the secret on the seller's node. Nothing on a Core Lightning node cancels a
  held ticket before it expires, as Lightning Fork does 18 blocks before. The gateway and the
  wallet speak to Lightning Fork nodes only.
- `settle: "on-arrival"` (section 5) holds no slot and needs no hold invoice, so it is what a
  Core Lightning seller could offer as shipped, and what a buyer falls back to when slots are
  short. The wallet and the gateway implement it (section 14). The gateway still speaks to a
  Lightning Fork node only: a seller component for a Core Lightning node does not exist.
- How a seller says that it settles both ways (two entries of `accepts`), and the `settle` and
  `count` fields of a lock, are this tree's reading of section 5. No other implementation has
  been checked against them.
- A hop that has gone, and real network latency, were not run. Fees are the forks' defaults, not
  what XBT's nodes charge.
- A fee for a held payment does not exist on this network. If one is adopted, tickets pay it.
- The list of what a seller sells (`GET /services` on the gateway: the node id, the receipt key,
  the ticket terms and each route's price) is not signed. Signing it with the node's key needs the
  node's `SignMessage`, which neither of the seller's macaroons allows; the runner can sign the
  list once with its own tools, or a third narrow macaroon can. Until then the list is the TLS
  origin's word, as the terms are.
- The entry for a single Lightning payment (section 12, rail 2) is x402's `exact` with a network
  id of ours and the invoice in `extra.invoice`. No seller in this tree offers it, and it was not
  run on the lab.
- `bytes` and `complete` beside the last receipt of a long answer are not signed. What is signed
  is `charged` and `bodyHash`.
- The price of a piece only the service can count, such as the tokens a model produced, cannot be
  stated by a gateway that sees bytes and seconds. The response header `Ticket-Units` is kept for
  such a count; this draft reads no price from it.

## 9. The lottery: pay after a win

A request, or a piece of an answer, priced below one payment is paid by a fair draw: it wins a
payment of one fixed size (a **win**, 64 sat unless the terms say otherwise) with probability
price ÷ that size, so what is paid is the price on average. Most draws pay nothing. A win is paid
at once by an ordinary Lightning payment, in flight for a fraction of a second, and nothing is
locked with the seller at any time: no hold invoice, no slot of any channel between wins. This is
how the wallet pays amounts below a ticket, and how it pays more sellers at once than tickets can
be held with (section 11).

Both sides are built: the draw is `xbt402::lottery` (`crates/xbt402/src/lottery.rs`, no IO, used
by both), the seller's side is in `xbt-gateway` (`lottery.rs`, `gateway/draws.rs`), and the
buyer's side is in the wallet's signer (`lottery.rs`, `ticket_pay/draws.rs`, and the ticket rail's
payment of an ordinary invoice). `scripts/lottery/draw.py` is the same draw written a second
time; both read `vectors/lottery_vectors.json`. `scripts/lottery_regtest.sh` runs it on
Lightning Fork nodes; the numbers of this section are that script's.

Paying by lottery is Wheeler's and Rivest's idea. The seller's hash chain is Rivest's, the
shape (a commitment by the receiver, a value of the payer's, a hash of both under a threshold)
is the one Orchid and Livepeer use against a contract, and a win that pays itself over Lightning
was first set out by Gerhart, Taylor and Thyagarajan in 2026 ([`REFERENCES.md`](REFERENCES.md),
33 to 44). What is ours is the binding to a metered HTTP answer and to an ordinary Lightning
invoice with nobody holding money for the winner.

**The fairness argument is this project's own and nobody else has reviewed it.** It takes
SHA-256 as a random function and is stated in section 9.3. What is built is the form in which
the buyer pays after a win. The form in which a win pays itself (a sealed draw from a locked
ticket) is not specified here and not built; `pay` in the terms is where it would be named.

### 9.1 Terms

A seller that takes draws adds one entry to `accepts`, after its ticket entries: a client that
knows only tickets skips an entry it cannot read.

```json
{"scheme": "lottery", "network": "lightning:0000000000000050c1e5f69672f45929",
 "asset": "XBT:msat", "amount": "0", "payTo": "<the seller's Lightning node id, 33 bytes>",
 "extra": {"version": "lottery/0", "features": [512],
           "winMsat": "64000", "minWinMsat": "16000", "winBlocks": 40,
           "pay": "on-win", "release": "after-answer",
           "window": 8, "graceSeconds": 30, "gracePieces": 64, "maxUnpaidWins": 2,
           "chainDraws": 65536, "pieceBytes": "262144",
           "receiptKey": "<33-byte public key>", "session": "/x402/lottery",
           "price": {"requestMsat": "0", "byteMsat": "100", "perBytes": "262144", "secondMsat": "0"}}}
```

| Field | Meaning | Why |
|---|---|---|
| `amount`, `price` | As for a ticket (section 1): the price rule of the route. | With the win size it fixes the odds of every piece. Both come from the entry the buyer's request repeats, so a seller cannot change the odds after the fact. |
| `winMsat` | What one win pays unless the buyer asks for less. | One size per session, so that an invoice has one right amount. |
| `minWinMsat` | The smallest win a buyer may ask for when it opens a session. | A buyer sizes its win to the session (section 9.7). A smaller win is steadier and pays more in routing fees. |
| `winBlocks` | The final CLTV delta of a win's invoice. | It bounds how long the payment of a win can lock the buyer's funds on its way. |
| `pay` | `on-win`: a win is paid by an invoice the seller sends after it. | Who can walk away from a win, and so who goes first. No other value is defined. |
| `release` | `after-answer`: a value follows any piece. `after-verify`: the route's pieces can be checked one by one, and a buyer that holds their hashes gives a value only for a piece that matched. | Whether a draw depends on the content. The seller does the same in both cases; the word tells the buyer what it can check. |
| `window` | How many pieces the seller serves beyond the last one it holds a value or a void for. | It bounds what a buyer that sends no values is served. |
| `graceSeconds`, `gracePieces`, `maxUnpaidWins` | How long, how many pieces and how many wins the seller serves on while a win is unpaid. | The payment of a win takes a quarter of a second through a hop, and a wallet that pays many sellers sends 8 at a time: with 100 sellers a win waited up to 13 s for its turn (section 9.12). |
| `chainDraws` | The draws one session's chain covers. | A session ends when its chain does; the buyer opens another. |
| `pieceBytes` | The bytes of an answer that make one piece. | Both sides must cut an answer at the same places. |

An entry is offered only for a route whose dearest piece (its request, one second, one full piece
of bytes) is a small part of `winMsat`: a quarter at the most at the gateway (`max_odds_den`, 4),
which is the odds cap the wallet's owner has too (section 9.8). The seller serves `window` pieces
before any value has come, so the dearest piece over the win is what that costs it in wins: 8
pieces of a quarter of a win are 2 wins. A request that names the lottery for a route that is not
offered is refused `amount_not_below_win`, and the service is not asked. A buyer MUST refuse an entry whose win is outside what its
owner allows, or whose pieces would win more often than its owner allows, or it pays larger
amounts, or more often, than the owner agreed to. It MUST refuse an entry it cannot read whole,
and one whose `pay` it does not build: a draw the two sides would work out differently is a win
one of them does not see.

### 9.2 Open

```text
POST <session>/open    {"version": "lottery/0", "winMsat": "<the size asked for, optional>"}
200                    {"session": "<id>", "key": "<32 bytes>", "anchor": "<c[0], 32 bytes>",
                        "winMsat": "<the session's win size>", "chainDraws": <n>}
```

Opening a session asks the seller's node for nothing and costs the buyer nothing. The seller
makes a chain for the session: a random 32-byte seed `c[n]`, hashed down, `c[i-1] = SHA256(c[i])`,
and sends its end `c[0]`, the **anchor**. `key` authenticates the session's requests as a
ticket session's does (section 3), under another label:

```text
auth = HMAC-SHA256(key, "lottery/auth|" session "|" seq "|" request_digest_v2)
PAYMENT-SIGNATURE: base64({"x402Version": 2, "accepted": <the lottery entry>,
                           "payload": {"session": "<id>", "seq": <n>, "auth": "<HMAC>"}})
```

- The seller MUST make a new chain for every session, from fresh random bytes, and send its
  anchor before it has any value of the buyer's. A chain used for two sessions lets their
  buyers know values ahead and lose on purpose. A seller whose sessions outlive a restart keeps
  each chain's seed where only it can read it: whoever reads the seed knows every draw to come.
  The gateway writes it to the lottery's journal in its state directory (`lottery.jsonl`,
  private to its owner, beside the session keys and the receipt key).
- The seller MUST cap sessions, in all and from one address, and forget a quiet one. A session
  costs `chainDraws` hashes to make and about 34 KiB to keep at the default length (one chain value
  in every 1,024 and the block last read), and anyone can ask for one. Every session is also
  served its window before any value (section 9.6), so the cap per address is what bounds the
  pieces one buyer gets for nothing, and it MUST count the buyer's address: behind a reverse
  proxy the socket's address is the proxy's for everyone, and the cap then holds the whole world
  to a few sessions or, set to 0, holds nobody. The gateway counts the address a proxy reports
  only where its runner names the proxy and the header (`http.forwarded_address`, off by
  default); section 9.9.
- The buyer MUST refuse an anchor it has been given before, and an answer that names another win
  size or chain length than it asked for.
- The requests MUST go over TLS (or loopback): the session key travels in this answer.

### 9.3 Pieces and the draw

What is paid for is cut into **pieces**. A request has at most one piece of kind `request`
(`price.requestMsat`, when it is above nothing and the answer's status is below 400). The body of
an answer priced by its size has one piece of kind `bytes` for every `pieceBytes` bytes, numbered
from 0, and a last, shorter one when the body ends; the price of a piece is the price of the body
up to its end less the price up to its start, so that the pieces of a body add up to the price of
the body with no rounding left over. An answer priced by the second has one piece of kind
`second` for every second that starts while it is open, numbered from 0. A piece with no price is
not a piece.

```text
piece = SHA256("lottery/0/piece" ‖ seq:8 ‖ req:32 ‖ kind:1 ‖ k:8 ‖ amount_msat:8 ‖ win_msat:8)
d     = SHA256("lottery/0/draw" ‖ len(session):1 ‖ session ‖ i:8 ‖ c[i]:32 ‖ b:32 ‖ piece:32)
win   = uint64(d[0..8]) < floor(2^64 × amount_msat / win_msat)
```

Integers are big-endian; `kind` is 0 for `request`, 1 for `bytes`, 2 for `second`; `seq` is the
request's own, `req` its `request_digest_v2`, `k` the piece's number among its kind in that
request. `i` is the number of the draw in its session, from 1. `b` is the buyer's value, 32
random bytes. The odds are the two integers `amount_msat` and `win_msat`, never a rounded "1 in
N", and the floor drops less than one part in 2^64 of a draw.

Draws are numbered by the buyer, in the order it gives values, with no gaps: the value for draw
`i` names the piece it is for. The seller takes a value only as the next draw of the session and
reveals `c[i]` only in the answer to the request that brought the value of draw `i`.

**Why neither side can steer a draw** (the argument that is ours and unreviewed):

- The seller fixed `c[i]` with the anchor before it saw any value of the buyer's. To reveal
  another value that hashes down to the anchor it would need a second preimage. The buyer's value
  is 256 random bits the seller has not seen, so to the seller `d` is uniform whatever seed it
  chose. Its other move is not to reveal, which gives up its own win.
- The buyer picks `b` holding `c[i-1]` at most, and `c[i]` is a preimage of that. Whatever it
  picks, `d` is uniform. It cannot wait: the seller reveals `c[i]` only with the value of draw
  `i` in hand, and takes no second value for a draw.
- The seller learns no result before it has served: the value follows the piece. A seller that
  held the value first could serve only winners.
- A win is for one piece: its request, its place in the answer, its price and the win size are
  all inside `d`. Neither side can use a draw for a cheaper or a dearer piece.
- Either side can walk away at any time, and neither knows anything of the draws to come, so no
  rule for stopping moves what is paid on average.

What the draw does not do is make the buyer pay: section 9.6.

### 9.4 A request, its values and the reveal

A request for a resource is sent as a ticket session's is, with the header of section 9.2, one
request of a session after another. The seller, in this order: checks `auth` and `seq`; refuses
a session that is outside its window or its grace (section 9.6); refuses a route with a piece
that costs the session's win or more (`amount_not_below_win`: such a piece is paid with
tickets); asks the service; and for an answer below 400 serves, with a receipt signed by
`receiptKey` over, in this order, `scheme`, `session`, `seq`, `drawn`, `servedMsat`, `wonMsat`,
`paidMsat`, `charged`, `req`, `status`, `bodyHash`, under the tag `xbt402/lottery-receipt/v0`.
An answer that is sent as it arrives carries a first receipt at its head (`bodyHash` empty,
`"stream": true` beside it) and its last receipt in `status`, as in section 4.

Values travel one way only, in a request of their own:

```text
POST <session>/draw   {"values": [{"draw": <i>, "seq": <n>, "kind": "bytes", "k": <k>,
                                   "amountMsat": "<the piece's price>", "value": "<32 bytes>"}, ...],
                       "void": [{"seq": <n>, "kind": "bytes", "k": <k>}, ...]}
200                   {"drawn": <i>, "reveal": "<c[i]>", "refused": {"draw": <i>, "error": "<code>"} or null,
                       "wins": [{"draw": <w>, "invoice": "<BOLT 11>"}, ...], "session": {...}}
```

`drawn` is the last draw the seller has taken and `reveal` its chain value. `wins` lists every
win of the session that is not paid, each with the invoice that pays it. `POST <session>/status
{}` answers the same without taking a value, with the last receipts of the session's answers;
`POST <session>/close {}` ends the session.

The buyer:

- MUST make each value from its own random source, never from the session key or anything else
  the seller has seen. A seller that can predict values can try seeds until its chain wins.
- MUST give the value for a piece only when all of the piece has arrived, and under
  `after-verify`, where it holds the piece's hash, only when the piece matched. A seller that
  holds the value before it has served knows the result.
- MUST give one value for a draw, ever, and send the same one again when its request got no
  answer. Two values for one draw is choosing the result.
- MUST check that `reveal` hashes down to the last chain value it holds in exactly `drawn` less
  the last checked draw steps, at most 4,096, and MUST work out every draw up to `drawn` itself.
  A value that is not on the chain is not a reveal, and a win the buyer cannot reproduce is not a
  win.
- SHOULD give no more than a few values (8 in the wallet built here) beyond the last reveal it
  checked. A seller that takes values and reveals nothing is told nothing more.
- MAY list a piece under `void` in place of a value: it never arrived, or failed its check. The
  buyer knows no result when it says so.

The seller:

- MUST take a value only as the next draw of the session (`draw_out_of_order`), only for a
  piece it served that has neither a value nor a void (`piece_unknown`), and only at that piece's
  own price (`amount_mismatch`). A value for an earlier draw is answered as it was the first
  time when it is the same value, and refused when it is another (`value_conflict`): a buyer
  that has seen `c[i]` must not get to pick again. A value the session has used before is
  refused (`value_reused`).
- MUST NOT reveal `c[i]` before it holds the value of draw `i`. A reveal discloses every chain
  value below it.
- MUST have draw `i` on disk before `c[i]` leaves, where its sessions outlive a restart. A
  restart that had lost the draw would take a second value for it from a buyer that holds
  `c[i]`, and that buyer then chooses the result. The gateway syncs its lottery journal before
  every answer that reveals; a draw it cannot write down is not revealed (`500 journal`), and
  its session ends.
- MUST mark a piece as served no earlier than when its last bytes leave. The gateway marks a
  piece just before its last write, so that a buyer that has all of it never names a piece the
  seller does not know; the last, short piece of a body of unknown length is marked when the body
  has ended, and a buyer whose value for it is refused `piece_unknown` sends the same value again.
- MUST count a voided piece against the window (section 9.6) for the rest of its session: a
  void closes the piece and makes no room. A seller that lets a void make room serves a buyer
  that voids every piece without end and without a draw, and cannot tell it from a buyer whose
  connection was cut.
- SHOULD end a session with more voids than it allows (`too_many_voids`; 4 at the gateway, half
  of its window), and one in which voids alone fill the window.

### 9.5 Paying a win

Before it pays a win the buyer's signer MUST check all of these; a paid invoice cannot be
recalled.

| Check | What goes wrong without it |
|---|---|
| The draw is one the signer worked out itself, on the chain value it checked, and found won. | The wallet pays what a seller, or an agent, says was won. |
| The invoice's payee is `payTo`. | The win pays another node. |
| The amount is exactly the session's win size. | The buyer pays more than the odds were worked out for. |
| Feature bit 512 is set and required; the prefix is XBT's. | The wallet pays on the SHA-256 chain's Lightning network. |
| The final CLTV delta is `winBlocks`, and within the owner's bound; the invoice is not expired and stays payable for no longer than the owner allows; it has a payment secret. | As for a ticket (section 2). |
| The win has no payment in the wallet's book that has not failed, and the invoice's hash has never been paid. | A seller that sends two invoices for one win is paid twice. |
| The win and its fee limit are inside the task's budget, the cap for this seller, the wallet's own budgets, and, for a seller the owner has not named, the wins it may be paid in the task's window. | A seller that sets bad terms is paid without bound. |

The buyer MUST write the spend down, on disk, before the payment leaves, and take it back only
when its own node shows the payment failed with nothing in flight. It books what its node paid
and the fee its node reports, never an expected value and never a number in a receipt. The
wallet sends at most 8 payments to its node's router at once, tickets and wins together (section
7). They go in the order they were found, with one exception: a win that its seller's answer
stands still for (section 9.6) goes before the wins no seller waits for. A buyer that pays many
sellers at once SHOULD do the same, or such a win waits behind all the others while its seller
counts 10 s. The buyer knows which wins these are by its own count against the terms, and takes
no seller's word for it: with more than `maxUnpaidWins` wins of a session unpaid, the oldest
ones above that number; and a win since which it has given values for `gracePieces` pieces,
less the `window` the seller may be ahead of it.

The seller treats a win as paid when its own node shows that invoice settled for the full
amount, never on the buyer's word. The gateway makes the preimage of each invoice itself, gives
it to the node and keeps no copy, writes the invoice's payment hash to its journal, on disk,
before the node is asked (so that a win paid across a restart is seen paid), makes one invoice
for a win at a time, and makes another only
when the node shows the first cancelled (it lapsed unpaid).

A payment that fails (no route, a fee limit) is not a spent one. The wallet does not send that
invoice again: the win stays owed until the seller sends another invoice for it, which the
gateway does when the first has lapsed (60 s). A payment the wallet could not begin (its own node
gave no answer) is tried again with the same invoice. A seller whose invoices fail the checks
above three times is not asked for another: the session ends as faulty.

An answer that did not arrive whole (the wallet stopped reading it, or it was cut) can leave
pieces open with the seller: it marks a piece when its last bytes leave. The buyer SHOULD name as
`void` every piece of such an answer that will get no value. That makes no room in the seller's
window (section 9.6); it tells the seller that no value will come, so that the seller ends a
session whose window is used up (`too_many_voids`) and the buyer opens another, where a seller
that was told nothing would wait for values (`value_missing`). The same goes for the end of any
answer priced by the second:
the seller counts its seconds on its own clock, which started a moment before the buyer's, and
may have begun one second more than the buyer gave a value for.

### 9.6 The window and the grace: when the seller stops

The seller goes first, and these are what bound it:

- **The window.** A session is served no piece while the pieces it was served and gave no value
  for are `window` or more: the ones still open and the ones it voided, together. A value for an
  open piece makes room for one more; a void makes none. A request beyond the window is refused
  `value_missing` while a value could still make room, and `too_many_voids` when none could; an
  answer that is being sent waits for a value for as long as it would wait for a ticket (3 s at
  the gateway) and is then cut short. So a buyer that sends nothing, and a buyer that voids
  every piece, are each served `window` pieces in a session and no more. An honest buyer pays
  for this too: every piece of an answer that was cut (one to a few; `window` at the most)
  narrows its window by one for the rest of the session, and after 4 voids at the gateway
  (`max_voids`) the session ends and it opens another.
- **Closing.** A session its buyer closes is served nothing more. If it owes (pieces it gave no
  value for, or a win unpaid) it keeps its place in the seller's caps until it has been quiet
  for as long as a session that never drew is kept (60 s at the gateway): or opening, taking
  the window and closing would be a loop with no bound but the request rate.
- **The grace.** While a win is unpaid the seller serves on: for `graceSeconds`, for
  `gracePieces` pieces after that win, and with at most `maxUnpaidWins` wins unpaid. Beyond any
  of the three a request is refused `win_unpaid`, with the unpaid wins and their invoices, and
  an answer that is being sent stands still for the payment (10 s at the gateway, and never
  beyond the grace) and is then cut short. Service goes on when the seller's node shows the wins
  paid. A file of 64 pieces at one win expected draws three or more wins 8 times in 100,
  and its answer then stands still at the third until the first is paid: what that takes is the
  buyer's to keep short (section 9.5).

A buyer that gives values and never pays is therefore served up to its first win, and the grace.
Nothing on today's Lightning makes it pay: the lottery is a cheap way for buyers who mean to pay
to do so, with a bounded loss to each one that does not. Where a seller earns less than one win
from a buyer, a buyer that never pays has had everything free.

### 9.7 Which is used, and how large a win is

One function in the wallet decides, when a seller's 402 has a ticket entry and a lottery entry
(`crate::lottery::choose`); the other is tried after it where the first cannot be used.

| Case | Paid by |
|---|---|
| A session with this seller is open | what that session pays by |
| The seller offers one of the two, the owner turned the lottery off (`tickets.lottery.enabled`), or the task says (`meter`: `tickets` or `draws`) | that one |
| A piece of the route costs one ticket or more | tickets |
| The call may use four tickets' worth or more with this seller (`max_sats`), and a held ticket fits (the slot budget of section 11 and the owner's caps have room) | tickets |
| Anything smaller, and whenever no held ticket fits | draws |
| Draws were chosen and no win size fits the owner's bounds | tickets, and with them the prepaid ticket of section 5 where none can be held |

The win size is fixed when the session opens: one sixteenth of what the call may use, in whole
sats, so that a session expects about 16 wins; never above the seller's `winMsat` or the owner's
cap; never below the seller's `minWinMsat`, the owner's smallest win, four times the route's
dearest piece (so that no piece wins more than one time in four, the owner's `max_odds_den`), or
the **fee floor** of the way to the seller. That floor is 64 sat when the payment goes through a
routing node and 4 sat over a channel of the wallet's own to the seller's node.

What a wallet can know of a route's fee before it pays is little. It knows its own channels,
and so whether the seller's node is its direct peer, where no hop is paid. It knows the fee
limit it gives its node, which is the most a payment can cost. It does not know the route its
node will choose or what the hops on it charge until the payment has settled and its node
reports the fee. So the floor is a rule and not a measurement: a routing node at the forks'
default policy charges a base fee of 1 sat for any payment, which is 1.6% of a 64-sat win for
each hop and 6% of a 16-sat one.

### 9.8 The owner's policy

`tickets.lottery` in the owner's policy, each with its default:

| Field | Default | What it bounds |
|---|---|---|
| `enabled` | on wherever tickets are | Whether anything is paid by draws |
| `max_win_sats`, `unlisted_max_win_sats` | 1,000 and 250 | The size of one payment, and of the spread, for a seller the owner named and for one it did not |
| `min_win_sats` | 16 | A seller cannot make the wallet pay wins so small that the fee is most of them |
| `max_odds_den` | 4 | No piece wins more often than 1 time in this many: a piece nearer a whole win is paid with tickets |
| `expected_wins` | 16 | The wins a session is sized to expect |
| `luck_tenths` | 31 | How far above its price a call may pay before the wallet asks for no more pieces: 3.1 standard deviations, which about one honest call in 1,000 reaches |
| `ahead` | 8 | Values given beyond the last reveal the wallet checked |
| `unlisted_max_wins` | 32 | Wins paid to one seller the owner has not named, in a task's window |
| `routed_floor_sats`, `direct_floor_sats` | 64 and 4 | The fee floor of section 9.7 |
| `stay_tickets` | 4 | The tickets' worth above which a seller is one the buyer stays with |

and, for a task, `meter` (`auto`, `tickets` or `draws`). Everything else is what bounds a ticket:
the task's `budget_sats`, the cap on sats paid to one seller, the wallet's daily and weekly
budgets, `max_sellers`, `max_new_sellers_per_min`, `max_sends_per_hour`.

- **Spend is what the node paid.** A win and its routing fee, booked before the payment leaves.
  Never an expected value.
- **`max_sats` bounds what a call uses**, by the wallet's own count of the pieces it gave values
  for. What the call pays is uneven: nothing, or several wins. The wallet asks for no more pieces
  when the wins of a call come to more than `max_sats`, plus 3.1 times the square root of
  `max_sats` times the win, plus one win. For a call of 1,000 sat on 64-sat wins that is 1,848
  sat. The task's budget is the bound that holds whatever the draws do.
- **A budget below one win and its fee pays nothing at all.** The wallet says so when the session
  would open, before it asks the seller for anything.
- **A session counts once** for `velocity_max` (`tickets.velocity: "session"`, the default),
  however many wins it pays; with `"release"` every win is a payment.
- **The wallet checks the draw, not the delivery.** It gives a value for a piece that arrived,
  and for a piece that matched where the caller gave the piece's hash (`piece_sha256` of the
  signer's `xbt402_pay`). For anything else it is the caller that judges what arrived.

### 9.9 What each side can lose

| Who | Worst case | Bound |
|---|---|---|
| Seller | The service given to a buyer that gives values and never pays: up to its first unpaid win, and the grace. | `winMsat` (a smaller win for a buyer it does not know), `graceSeconds`, `gracePieces`, `maxUnpaidWins`. Measured in section 9.12. |
| Seller | `window` pieces to a buyer that sends no values, or that voids every piece, for every session it is given: 8 pieces of a quarter of a win at the most, 2 wins. One address is given 4 sessions and gets each place back after a minute: 8 wins a minute at the most. All 64 places, taken from 16 addresses or more: 128 wins a minute. | `window`; the dearest piece a route may have (`max_odds_den`); the caps on sessions and on sessions from one address; a session that never drew, or was closed while it owed, keeps its place for a minute. Behind a reverse proxy the cap per address counts nothing unless the runner names the proxy and its header (`http.forwarded_address`): the gateway then believes that header from that proxy's address, the last entry of a list, and counts a request without one under the proxy's own address. A proxy that passes on a header its client wrote, or a gateway that can be reached past the proxy from one of the named addresses, makes the cap the buyer's to set. |
| Seller | A win it never invoices or whose invoice lapses. | Its own node and gateway. A session and its unpaid wins outlive a restart of the gateway (its lottery journal); a win whose invoice the node made and the gateway never learnt of (the answer lost, then a restart) is cancelled on the node and invoiced again. A lost state directory loses them all. |
| Seller | Uneven income: a seller that earns less than a win from a buyer is usually paid nothing by it, and sometimes a whole win. | The number of wins: pay is within 20% after about 68 wins. |
| Buyer | Nothing beyond wins it worked out itself. An unlucky run costs more than the price, a lucky one less. | The owner's caps on a win, on the odds and on wins to an unnamed seller; the luck cap of a call; the task's budget. |
| Buyer | A win it could not pay (its node away, no route, a cap reached): the seller stops serving it. | The grace. A signer that starts again pays no win it found before: it cannot tell a start from a restore of older records, in which that win may be paid already. |
| Buyer | A seller whose prices are a lie, or whose content is worthless. | As for a ticket: the caps per seller and the task's budget. |
| Routing hop | Nothing. It carries ordinary payments and is paid for each. | |

### 9.10 Errors

Beside those of section 3 that apply (`bad_auth`, `bad_seq`, `session_unknown`,
`too_many_sessions`, `upstream_unavailable`): `value_missing`, `win_unpaid`, `too_many_voids`
(the session is over: its voids are past the seller's cap, or fill its window),
`amount_not_below_win` (a piece of the route costs the session's win or more, or the route is
not one the terms offer by lottery), `win_size` (the size asked for at `open` is outside the terms),
`chain_spent`, and, for a value in a `draw` request, `draw_out_of_order`, `draw_used` (a draw
taken too long ago to answer again), `piece_unknown`, `amount_mismatch`, `value_conflict`,
`value_reused`. A session outlives a restart of the gateway, with its draws, its open pieces
and its unpaid wins. One the gateway has forgotten (closed, quiet too long, or one whose draw
it could not write down) is answered `session_unknown`, unsigned; the wallet ends its session
and opens another.

### 9.11 What building it changed in the design

The design this was built from numbered draws by request and let values arrive in any order.
Each line below was found by building both sides and running them.

| The design | Now, and why |
|---|---|
| One draw per request, numbered by the request's `seq`. | A draw per piece, and draws numbered by the buyer in the order of its values. An answer priced by its size or its time has many pieces and one `seq`; and with draws in order the seller never holds a gap, so a reveal never discloses a value that is still open and no list of holes is needed. |
| A value rides in the next request. | Every value travels in `draw`. One path for a value and one answer to it, as the wallet does with a ticket's secret (section 12); and a long answer needs its values while it is still arriving. |
| The draw binds the request's digest. | It binds the piece: the request, the kind, the number, the price and the win size. Two pieces of one request must not share a draw, and both sides must have drawn at the same odds or got different results. |
| "A reveal more than 4,096 steps past the last is refused." | Kept, and a buyer gives at most 8 values beyond the last reveal, so in practice a reveal is checked in a few hashes. |
| The buyer MUST write a value down before it leaves. | The wallet keeps values in memory. A session of draws does not outlive the signer's process, so after a restart there is nothing to send again; what is on disk is every payment of a win, before it is sent. |
| The seller's chain is renewed by a `nextAnchor` in a receipt. | Not built. A session ends with its chain (65,536 draws) and the buyer opens another. |
| Several wins in one invoice. | Not built: one invoice a win. |
| A seller-held ticket for content that cannot be checked. | Not built. Every route is paid after a win, and the buyer checks what it can. |
| The seller serves on for `graceSeconds`. | And for `gracePieces`, and with `maxUnpaidWins` at most: a fast seller gives away more in ten seconds than a win. |
| A win's invoice was not specified. | An ordinary invoice of the win size with the terms' `winBlocks`, payable for 60 s, one at a time for a win. Found by a test: two answers of one session each asked the node for the same win's invoice, the wallet paid the first, and the gateway knew only the second; the gateway now lets one request at a time ask. |

### 9.12 Measured

On regtest on 2026-10-13, by `scripts/lottery_regtest.sh` (30 checks): the release binaries of
this tree (the wallet's signer, its MCP server, the gateway), a stock file server, three
Lightning Fork nodes (buyer, one routing hop, seller) on one host over loopback, the buyer's
channel and the seller's inbound channel opened with 30 slots. The wallet's lottery policy and
the gateway's lottery terms as they ship, with pieces of 64 KiB. No Core Lightning node. The
numbers are one run's; a draw is random, so the wins differ from run to run.

| What | Measured | Check |
|---|---|---|
| A 100 MB file at a quarter of a sat a piece (1,526 pieces, 381.5 sat), bought five times by an agent's `xbt402_pay` | Whole each time, in 1.2 to 2.3 s. 8, 12, 6, 4 and 5 wins (6 expected each): 520, 780, 390, 260 and 325 sat paid, fees included; the luck cap of those calls was 1,565 sat | `file` |
| What the buyer's node paid, what the seller's node received, the wins in the wallet's book, and its ledger | 2,240,000 msat on both nodes: 35 wins of 64,000 msat, each paid once. The ledger: 2,275 sat, each win and its fee of 1 sat | `file` |
| A win, from its payment's start on the buyer's node to its settle, one at a time | 221 ms at the median, 267 ms at the longest (35 payments, one hop) | `file` |
| What was pending on the buyer's channel during the downloads, asked every 20 ms | Nothing in 47% of the samples, never more than 3 payments, and every one of them a win on its way; nothing when the downloads were over, and nothing held on the seller's node | `file` |
| A page priced at 2.5 sat a request, 200 times | One draw each, 7 wins (7.8 expected). 3.0 ms a call against 1.5 ms for a free page through the same wallet (medians): a draw is one more request | `page` |
| 20 sellers paid at once, three files of 64 one-sat pieces from each | 3,840 draws, 68 wins (60 expected), every file whole, no payment failed, 4.8 s. At most 8 wins on the channel at once; an ordinary 5,000-sat payment of someone else's over the same channel succeeded meanwhile in 0.5 s | `swarm` |
| 100 sellers paid at once, the same | 19,200 draws, 288 wins (300 expected), every file whole, no payment failed, 20 s: 14 wins a second. At most 8 wins on the channel at once; the ordinary payment succeeded in 0.5 s. A win was on its way for 0.44 s at the median with 8 at a time, 1.2 s at the longest | `swarm` |
| A buyer that sends no values | 8 pieces (the window), then its answer is cut and its next request is refused `value_missing` | `cheat` |
| A buyer that gives values and never pays, pieces of a quarter of a sat | Served 1.4 wins' worth on average before it was stopped (ten sessions; 1.2 at the median, 3.3 at the most; 0.8 to 1.4 on average in four runs) | `cheat` |
| The same, pieces of a quarter of a win | 3.9 wins' worth on average (ten sessions; 3.9 to 4.9 in four runs): the gateway bears two unpaid wins and serves 8 pieces ahead of the buyer's values | `cheat` |
| A second implementation of the draw (`scripts/lottery/draw.py`) as that buyer | The seller's wins were exactly the ones it worked out, in every session | `cheat` |
| A seller that claims a win for a draw that lost, with a real invoice of its own node | Refused by the wallet's own draw, nothing paid, the session ended | `liar` |
| A seller that sends, for a real win, an invoice that pays another node, or one for one sat more | Refused by the checks every invoice passes (5 and 6 invoices), nothing paid, the session ended after the third | `liar` |
| A seller that sends two invoices for every win | 64 wins, each paid once; none of the 64 second invoices paid | `liar` |
| The signer, the gateway, the buyer's node and the seller's node each killed between two calls and again in the middle of a download with wins being paid | In all eight cases: no win paid twice, nothing in the ledger that the node did not pay, nothing paid that is not in the ledger, and the next call was served (after the buyer's node was killed in a download, on the second call) | `kill` |

**Found by running it**, and changed since the first run:

- The gate that lets 8 payments through at a time let a win out when its send returned, as it
  does a held ticket. With 100 sellers, 24 wins were pending on the 30-slot channel at once and
  47 of 313 payments failed. A win now stays inside the gate, with the checks before it, until
  the node shows it over, and wins go through in the order they were found (but see the last
  item).
- The gateway's grace of 10 s was sized for wins that are not paced. Paced 8 at a time, the last
  of 100 sellers' wins waited 13 s. The default is 30 s, and an answer that is being sent stands
  still for a payment for 10 s at the most.
- A wallet killed between the two writes that book a win kept a ledger row for a payment that
  was never sent. The book's row is now written first. The same was true of a prepaid ticket.
- A wallet that stopped reading an answer left pieces open with the seller, and the session's
  next request was refused `value_missing`. The wallet now names them as void.
- A win whose payment could not begin, or was not final when the wallet stopped waiting, was not
  looked at again. It is owed again, and the wallet asks the seller for its list while one is.
- With 100 sellers, a file that drew three wins was cut short by its seller, with every one of
  its wins paid a moment later (2026-10-13). The gateway bears two unpaid wins; at the third
  its answer stands still, for 10 s at the most. The first of the three was waiting its turn
  behind the other sellers' wins: about 7 s by the rate (100 wins at 14 a second) when the
  host did nothing else, where 13 runs of the swarm check cut no file, and more than 10 s when
  it was busy. With 16 busy loops beside the lab (`while :; do :; done`, on its 16 cores), a
  file was cut in 12 of 15 runs of the swarm check: 5 of 5 at the tree before this change (a
  compile ran beside those as well), 3 of 5 at the one before the on-chain channel was removed,
  and 4 of 5 at the tree the lottery was first merged in. The wallet now pays first the wins a seller's answer stands still for (section
  9.5): under the same load, 5 runs of 5 had every file whole. The numbers are of one lab on
  one day; the load is not a measure of anything but itself.

## 10. What building the seller changed in this draft

Each of these was found by building `xbt-gateway` against this draft and running it on the lab.

| Section | Before | Now, and why |
|---|---|---|
| 1 | The terms had `amount` only. | `price` states the whole rule: a body priced per byte or per second has no amount before it is sent. |
| 2 | A lock named a session in its body, unauthenticated. | A lock for an existing session carries `PAYMENT-SIGNATURE`; a lock answers `refused` hashes; `too_many_sessions`. A session id alone must not let a stranger fill a session's ticket places. |
| 2 | "from the node's invoice subscription". | The stream of all invoices never reports `ACCEPTED`; the per-invoice stream does. |
| 3 | The seller's macaroon was `invoices:read`, `invoices:write`. | It cannot read the block height, which step 2 needs: a second macaroon with `info:read`. |
| 3 | "The node's own record is what makes a secret good once." | A second settle of a settled ticket answers success: the seller reads the state, and marks the ticket used itself. |
| 3 | `seq` "rises by one". | Starts at 0; used up by any authenticated request; `bad_seq` carries `nextSeq`; one request of a session at a time. |
| 3 | A receipt on a served request. | A receipt on every authenticated answer, refusals included; `bad_auth` (401), `node_unavailable` (503). |
| 4 | Nothing on a long answer. | `release` keeps a metered answer going; the head's receipt and the last receipt (`status`). |
| 4 | `cancel` carried `session`, `seq` and `auth` in its body. | Authenticated by `PAYMENT-SIGNATURE` like every other request: `auth` cannot cover a body that holds it. |
| 5 | One chunk per ticket, no further chunk before its secret. | Pieces up to one ticket's worth on one pledged ticket; a debt when the pledged ticket is cancelled. |
| 7 | | The seller's caps and what they cost. |

## 11. Slots and dust (2026-10-12)

Kyle Santiago, who read this draft, said: design around Core Lightning's limit of 30 HTLCs
and around the dust limits. Sections 1 to 9 were measured on Lightning Fork nodes only, where a
channel carries 483. This section states the two limits, what was measured with the XBT Core
Lightning fork in the lab, and the rules that follow. The rules are in sections 1, 2, 4 and 7
above. The wallet and the gateway in this tree keep them since 2026-10-13; the last table says
where, and what each side cannot see.

**Slots.** Each side of a channel tells the other, when the channel opens, how many pending HTLCs
it will accept from it (`max_accepted_htlcs`, BOLT 2; 483 at most). Lightning Fork's default is
483. Core Lightning's is 30 on mainnet (`--max-concurrent-htlcs`), and a Core Lightning node also
sends no more than its own number, so a channel with a Core Lightning node at either end carries
30 each way. The number cannot be changed while the channel is open. A held ticket takes one slot
of every channel on its route until it is settled or cancelled, and the slots of a channel are
shared by every buyer, every seller and every ordinary payment that crosses it. A node knows the
numbers of its own channels. Nobody can know a remote channel's: it is not in gossip.

**Dust.** An HTLC below a side's dust limit has no output in that side's commitment transaction.
The limit is 354 sat on a Lightning Fork node and 546 sat on a Core Lightning node. On the channel
type both forks open by default (anchors, with HTLC transactions that pay no fee) the limit does
not move with the fee rate; on a channel without anchors it rises by the fee of 703 weight units,
so a 1,000-sat ticket would lose its output at about 2.6 sat/vB against a Core Lightning node
(computed, not run). Such an HTLC cannot be claimed on chain, and its value goes to the miners if
the channel is force-closed while it is pending. A Core Lightning node carries at most 50,000 sat
of them per channel and a Lightning Fork node 500,000 sat, counted with the channel's fee.

**The rules.**

1. A session holds 2 tickets, not 8. A buyer that spends faster takes larger tickets.
2. Held tickets take at most half the slots of any channel their holder can see, counting what
   is pending there already: the buyer on the channel its payments leave on, the seller on its
   inbound channels. A channel's slots are the smaller of the two numbers its node reports for
   it, and 30 where they cannot be read. On a 30-slot channel that is 15 held tickets: 7 sellers
   at 2 each or 15 at 1 each for a buyer, 7 buyers at 2 each for a seller.
3. A held ticket is never below 546 sat, nor below the dust limit of either side of the channel
   it leaves on. Smaller amounts are paid at once and never held.
4. A lock that fails for lack of a slot makes the buyer hold less: one ticket, a wait, and then
   no held ticket with that seller (section 4). A seller at its cap says `slots_short`
   (section 2).
5. Beyond what rule 2 holds, a seller is paid without a held payment: a ticket settled on arrival
   (section 5), bought one at a time, or a lottery win paid at once (section 9).

**Measured** on regtest, by a lab run whose driver is not in this tree: three Lightning
Fork nodes at `v0.21.3-beta-blake2b.17` with default settings and three nodes of the Core
Lightning fork at `v26.06.9-blake2b.7` (the released binaries), two of them started with the
values that binary has by default on mainnet (30 slots, a time lock delta of 34, a base fee of
1,000 msat), because on regtest it defaults to 483 slots. All channels were the anchors type.

| Question | Result |
|---|---|
| 40 tickets of 1,000 sat to a Core Lightning seller on one channel | 30 locked. 10 failed on the buyer's node with `INSUFFICIENT_BALANCE`; the channel had 3,998,056 sat on the buyer's side. |
| An ordinary 5,000-sat payment on that channel while the 30 were held | Failed the same way. Free to route, it went round through another node for a fee of 1,005 msat. |
| 40 more tickets, the buyer free to route | All 40 locked, on two more of the seller's inbound channels. The seller held 70 tickets on three channels. |
| 40 tickets through a Core Lightning routing hop | 30 locked, 10 failed. |
| Two buyers through one Core Lightning hop to one seller | The first held 20. The second offered 20: 10 locked, 10 failed with `NO_ROUTE`. |
| A Core Lightning buyer at its own limit | "Too many HTLCs": its node names the limit, where Lightning Fork's says the balance is short. |
| Lock 1, 8 and 30 tickets through one hop, invoices made first | To a Lightning Fork seller 0.21 s, 0.28 s, 0.6 s; to a Core Lightning seller 0.22 s, 0.25 to 0.31 s, 0.55 s. |
| The smallest ticket with an output | 354 sat in a Lightning Fork node's transaction. With tickets of 400, 600 and 1,000 sat held, a Core Lightning node's own force close had outputs for 600 and 1,000 only. |
| Core Lightning's dust cap, on a channel it opened with 483 slots | Of 130 tickets of 500 sat, 100 locked (50,000 sat) and 30 failed. Of 130 tickets of 546 sat, all locked. |
| The next ticket to that seller after a refusal at the cap | `NO_ROUTE`, though it was 1,000 sat: the seller's node had answered with a failure of the node, and the buyer's node stopped trying it. |
| Lightning Fork's cap | Not reached: 483 tickets of 300 sat locked (144,900 sat below dust). |
| 200 payments of 64 sat on a 30-slot channel, nothing held | Sent 64 at a time: 61 succeeded and 139 failed. Sent 8 at a time: all 200 succeeded, 28 a second. |
| A Core Lightning seller that neither settles nor cancels | Nothing cancelled the tickets. At their expiry height the buyer's node force-closed its own channel to the seller. |

**How the code in this tree keeps them.**

| | This draft | The wallet's ticket book | The gateway |
|---|---|---|---|
| Tickets per session | 2 | 2 for up to 4 sellers of a task, then 1: the defaults of the owner's `tickets.pool`, `many_sellers` and `pool_many`. The next is locked when half of a pool or fewer are left | 2 (`tickets.max_tickets`) |
| Smallest held ticket | 546 sat | 546 sat whatever the owner's `tickets.floor_ticket_sats` says, and no less than the larger `dust_limit_sat` of a channel the payment may leave on; on a channel without anchors, the fee of 703 weight units at four times the channel's fee rate on top | 546 sat where held tickets are offered (`tickets.ticket_msat`); it does not read its channels' dust limits |
| Held tickets in all | Half the slots of a channel: 15 of 30 | Read before every lock from the node's channel list: half of the smallest usable channel for the wallet's own tickets, and half of each channel for everything pending outwards on it. 30 slots where the listing does not say; no listing, no lock. The owner's `max_locked_tickets` (15) on top | 15 (`caps.max_held_tickets`, half of `caps.inbound_slots`); with a channels macaroon, half of its smallest active channel, and nothing while a channel is half full inwards |
| A lock that fails for lack of a slot | Hold less, wait, stop | The pool is halved, nothing is locked for 30 s doubling to 10 minutes, and after three rounds in a row no ticket is held with that seller for 10 minutes | Not its part |
| `slots_short` | Yes | A wait of the seller's `retryAfter`, at most 10 minutes | Sent with `retryAfter` (30 s; `caps.slots_retry_secs`) |
| `settle: "on-arrival"` | Section 5 | Bought one at a time, by the payer of section 12, where no ticket can be held or the seller offers nothing else | Offered beside held tickets (`tickets.settle`) |
| What it cannot see | | A remote channel's slots and dust limit; which of its own channels its node will use | Which of its channels a ticket will arrive on; without the channels macaroon, anything pending on them that it did not issue |

The 30-slot rules were run on the lab on a channel a Lightning Fork node opened with 30 slots
(`--default-remote-max-htlcs=30`), by `scripts/ticket_e2e_regtest.sh slots`: no Core Lightning
node is in that lab. Such a channel takes 30 payments towards that node and 483 away from it,
where a channel with a Core Lightning node takes 30 both ways; the buyer's side of the rule, which
reads the smaller of the two numbers, sees 30 in both cases.

## 12. The wallet's side: `xbt402_pay`

An agent pays with one tool call, `xbt402_pay(url, method, body, max_sats, task)`. Everything else
is the wallet's signer's (`crates/xbt-signer/src/ticket_pay.rs`): it sends the request once without
paying, reads the 402 itself, and chooses the rail. Who the seller is therefore comes from what
the signer fetched from the URL's own origin, never from its caller.

**The rail.** One function, in this order; the first entry the seller offers and the owner's
policy allows is paid. Where a seller's 402 has a ticket entry and a lottery entry, the rule of
section 9.7 says which of the two is tried first, and the other is tried after it.

| | Entry of the 402 | Paid when | Otherwise |
|---|---|---|---|
| 1a | `scheme: "ticket"` on the wallet's Lightning network | Tickets are on (`tickets.enabled`); the call names one of the owner's tasks, or the owner has one task, or one named `default`; the seller is admitted (its origin is on the allowlist and tied to its node id, or the task pays any seller); the terms are inside the owner's bounds; `release` is `with-request`; the origin is https, or http on this machine. | The next entry, with the reason. |
| 1b | `scheme: "lottery"` on the wallet's Lightning network (section 9) | The lottery is on (`tickets.lottery.enabled`); the task and the seller are admitted as for a ticket; a win size fits the seller's terms and the owner's bounds (section 9.7); the task's budget covers one win and its fee; the origin is https, or http on this machine. | The next entry, with the reason. |
| 2 | `scheme: "exact"` on the wallet's Lightning network, with a BOLT 11 invoice in `extra.invoice` | The Lightning rail is on; the origin is on the allowlist; the invoice pays the entry's `payTo` its `amount`; and `ln_pay` would pay that invoice (every rule of that rail, the payee on the allowlist among them). The wallet pays it and sends the request again with `{"preimage"}` as the payload of `PAYMENT-SIGNATURE`. | The report below. |
| | None of them | Nothing is paid. The reply is `no_rail` and lists each entry that was passed over and why. | |

A rail is passed over only for a reason that makes it unusable for this seller: it is off, the
seller is not admitted, or the terms are outside the owner's bounds. A budget, a cap or a velocity
limit that is used up refuses the call and tries no other rail. With tickets off in the policy
the wallet still sends the one unpaid request and reads the 402; entries 1a and 1b are then passed
over. A call with `max_sats` 0 pays nothing: an answer that is not a 402 is handed back, and a 402
is refused (`max_sats`). Until October 2026 a third entry, the on-chain channel
(`batch-settlement`), was paid here, and both of these cases went to it; that channel was removed
(`docs/LIMITS.md`). A seller that still offers it is told so in `rails_passed_over`.
No request leaves for a host the owner did not allow: the URL is read by one parser, and its origin
is on the allowlist, or the call's task pays any seller, before the first byte is sent.

**A paid request, in order.**

1. The unpaid request, and the 402's ticket entry, read strictly (section 1). An open session
   whose seller now states another node, receipt key, ticket or session path is stopped, and the
   call is refused (`ticket_terms_changed`). A route's price may differ from request to request.
2. No session yet: the book opens one under the owner's rules, the wallet sends the pool's hashes
   to `lock`, writes the seller's session id and key to its book, and only then pays the invoices
   that pass the checks of section 2.
3. While the seller's balance does not cover what it wants before it serves (the request's price,
   the first second, the first byte): one ticket. The seller's signed `status` must list the
   ticket `ACCEPTED`; the book books it and gives the secret; the secret goes to `release`; the
   seller's signed answer must credit it. One secret at a time. No ticket is released while the
   seller has not closed an earlier answer of the session that the wallet stopped reading: a
   seller that is waiting for a refill of that answer would take the ticket for it. The answer's
   last receipt in `status` is the seller's word that it is closed; the wallet waits 5 s a call
   for it and gives the session up after 30 s.
4. The request, authenticated, with no secret. Its answer must carry a receipt signed by the
   terms' `receiptKey` for this session, this `seq`, this request digest and this status.
5. The body. An answer paid at its head is read and hashed against the receipt's `bodyHash`. An
   answer priced as it goes is read as it arrives; the next ticket is released when everything
   the released ones pay for has arrived (by the second: in the last fifth of the second before
   the unpaid one), and the wallet stops reading when the book refuses a release, when the call's
   `max_sats` is used up by its own count of bytes and seconds, or when the answer has been open
   for `tickets.max_answer_s` (50 s by default). It then asks `status` for the last receipt and
   checks it against what arrived.
6. The pool is refilled behind the call when half of it or fewer are left: with the default of
   2, when 1 is left.

Where the session holds no ticket and can lock none (section 14 lists when), step 3 buys a
prepaid ticket instead: a lock with `settle: "on-arrival"` and a count of 1, the book's checks of
the invoice and every rule of a release, the ledger row, the payment, and then the preimage in
`release`. One at a time, and none ahead of need.

`max_sats` bounds what the call uses, by the wallet's own count. Money moves a ticket at a time,
so a call can release one ticket more than it uses: a 3-sat page releases a 1,000-sat ticket, and
the rest is the session's balance for later calls. What a seller's receipts say moves only the
wallet's count of that balance, and only where it stands inside the wallet's own count (the
released total never above what the wallet released, a charge never above the price by the terms
of what was asked for and received). The ledger holds the wallet's own tickets and the fees its
node reports, and nothing else.

**Stop.** `ticket_stop`, a session idle for `tickets.http_idle_s` (120 s by default), a seller
fault and changed terms all end a session the same way: the book locks and releases nothing more,
the wallet sends `cancel` for all the session's tickets, and its own node shows them back. A
wallet that starts again has stopped every session (section 3); it asks each seller on record,
once, to cancel what it left locked. Stopping gives up the session's balance: the unused part of
the last ticket.

**What goes wrong, and what the wallet then does.**

| What happens | What the wallet does | What it can cost |
|---|---|---|
| The answer to a `release` is lost. | It asks `status`. Credited: it goes on. Not credited: the same secret again, never another. | Nothing more: the ticket was booked when its secret left. |
| The seller says a released ticket is `ticket_not_locked`. | The same secret again, five times within about a second; then the call is refused and the next call sends it first. | The ticket, if the seller never takes it and never cancels it: booked until the wallet's node shows it failed. |
| The answer to a paid request is lost. | The call says so. No secret travels with a request. | What the seller charged the balance for it. |
| An answer carries a receipt for another request (a replay), a receipt signed by another key, or none. | It is not believed. A 5xx without a receipt is reported and the session kept; any other answer nobody signed stops the session. | The session's balance. |
| A refusal that is not signed (a forged `balance_short`, or `session_unknown` from a seller that lost its records). | Nothing is released on its word. The session is stopped; the next call opens a new one. | The session's balance. |
| An unsigned `bad_seq` with `nextSeq`. | Adopted, twice at most: a `seq` only orders requests. | Nothing. |
| A receipt's totals or charge contradict the wallet's count (inflated metering). | The session is stopped as faulty. | At most the ticket in use. |
| The body is not the one the receipt signs. | The body is handed on marked as such, and the session is stopped. | At most the ticket in use. |
| The answer stops in the middle. | The call reports how far it came, and the last receipt if there is one. No ticket is released after the last byte. | The part of the last released ticket that paid for nothing. |
| The wallet stopped reading an answer when its pool ran out, and pays that seller again at once. | It waits until the seller has closed the old answer (the gateway does so after its 3 s wait for a refill), then releases. | Up to 3 s of waiting. Before this rule a ticket released in that time was charged for bytes of the old answer that nobody read, and the wallet took the honest seller's receipt for a lie. |
| The seller stops answering. | The call reports it. An unconfirmed secret is sent again by the next call before anything else. The idle rule stops the session. | At most one ticket, and the pool locked until the seller cancels it or it expires (section 6). |
| The seller never shows a ticket `ACCEPTED`. | `ticket_not_ready` after `tickets.ready_wait_ms`. | Nothing: no secret was released. |
| The wallet's signer is killed. | On its next start every locked ticket is booked as if released and never released, and the sellers on record are asked to cancel. | The balance; and the pool's worst case held against the budgets until the node shows the tickets failed. |

**Velocity.** The owner's `velocity_max` (8 an hour as shipped) counts payments. What a ticket
payment is for that count is the owner's choice, `tickets.velocity`: `"session"`, the default
since 2026-10-13, counts a session once, from its first release, and bounds its releases by the
budgets, the caps on locked funds and `max_sends_per_hour`; `"release"` counts every release, so
that a wallet releases at most 8 tickets an hour on every rail together and a long answer stops
at the eighth. A policy written before that date has no `tickets.velocity`: it meant `"release"`
and now means `"session"`. An owner who wants the earlier meaning writes `"release"`.

Measured on the lab before 2026-10-13, with a pool of 8 (`scripts/ticket_e2e_regtest.sh`; one hop,
loopback, the release binaries, an agent calling the MCP tool): a first request on a new session (the unpaid request, 8 tickets locked through the hop, the
seller's word that they are locked, one release, the paid request) took 0.37 to 0.42 s in 50
tries over ten runs, median 0.38 s. A paid page from the balance took 1.7 to 1.9 ms and a free
page 1.3 to 1.5 ms, both through the MCP server, the signer and the gateway (medians of 200): paying
added 0.30 to 0.38 ms. A 100 MB file at 200,000 msat per MiB came through whole in 1.7 to 1.9 s
with 20 tickets released one at a time; under a call that allowed half its price (9,536 sat,
which pays for 49,996,103 bytes) it stopped at 49,996,224 to 50,004,032 bytes, the end of the
read that reached the limit. After the agent's stop the unused tickets were back on both nodes
in 2.1 to 3.1 s. What the buyer's node paid, what the seller's node received, what the wallet's
book holds as settled and what the seller's receipts say was released were one number to the
millisat (37,000,000 or 38,000,000 msat, by how far the stopped answer had come), and the ledger
was each ticket and its routing fee (1,002 sat a ticket).

## 13. What building the wallet changed in this draft

Each of these was found by building `xbt402_pay` over tickets against this draft and the gateway.

| Section | Before | Now, and why |
|---|---|---|
| 2 | The buyer cannot see `ACCEPTED`; it releases and sends the same secret again on `ticket_not_locked`. | It asks the seller's signed `status` first and releases only what `status` shows `ACCEPTED`. A secret is spent when it leaves, so the wallet does not let one leave to find out. |
| 3 | The secret travels with the request it pays for. | The wallet sends every secret in `release` and pays requests from the balance. One path for a secret, one signed answer to it, and a refused or lost request has cost no secret. |
| 3 | `releasedMsat` and `spentMsat` "both only rise". | `spentMsat` falls by what the gateway charged ahead and did not send. A buyer that treats a fall as a lie stops honest sellers; a fall is in its favour, so it is taken. |
| 3 | A refusal of an authenticated request is signed. | `bad_seq` and `session_unknown` cannot be: the first is answered before authentication, and a seller that has forgotten a session has no totals to sign. The wallet adopts the first and treats the second as the end of the session. |
| 4 | "The receipt for the whole answer ... is in the answer to `status`." | It appears there when the seller has finished with the answer, which for one the buyer stopped reading is when the seller's next write fails or its wait for a refill ends. The wallet asks for 2 s and otherwise keeps its own count. |
| 4 | A buyer that stops paying for a long answer lets it end. | The seller goes on waiting for a refill for a few seconds, and a ticket released to the session in that time continues the old answer, which the buyer no longer reads. A buyer MUST NOT release into a session until `status` lists the last receipt of every answer it stopped reading. Found on the lab when the buyer's node was killed in the middle of a file and the next call came 2 s later. |
| 2 | A buyer drops a hash it got no invoice for after two minutes. | The wallet drops it at once when the lock's answer was lost or refused, or when its own node could not be asked about the invoices, and offers new hashes in the next round. Waiting two minutes left the pool empty for as long: after its node had been away for a few seconds the wallet could pay nobody. A hash whose invoice was refused by a cap still waits. |
| 4 | Stop and cancel need the session's key. | A wallet that starts again has lost its sessions but kept each seller's session id and key in its book, written before any ticket of the session was paid. Its first `cancel` uses `seq` 0 and adopts the `nextSeq` the seller answers. |
| 1 | The terms came "over TLS from the seller". | The wallet refuses the ticket entry of an origin that is neither https nor on its own machine: the session key travels in the first lock answer. |
| 7, 11 | The pool and the smallest ticket were numbers in the wallet's code. | They are the owner's settings (`tickets.pool`, `pool_many`, `many_sellers`, `floor_ticket_sats`), each with its default in one place. Section 14 has the defaults and the checks that section 11 asked for. |
| new | | The rail table of section 12 and the `exact` entry for a single Lightning payment. (The owner's `channel_rail` switch, added with them, went with the on-chain channel.) |

## 14. What building the limits changed in this draft

Sections 11 and 5 were built into the wallet and the gateway on 2026-10-13. Each line below was
found by building them and running the tests and the lab scripts.

| Section | Before | Now, and why |
|---|---|---|
| 1 | One `ticket` entry in `accepts`, with one `settle`. | A seller that settles both ways lists two entries, the held one first. One entry cannot say "either", and a buyer that reads only held tickets must be able to skip the other. |
| 2 | "The buyer sends no hashes, only a count" (section 5), with no field for it. | `settle` and `count` in the lock's body. The answer is the one a held lock gets, so a buyer has one reader for both. |
| 2 | A lock the held cap refuses is `slots_short`. | The session's own cap is told first (`too_many_tickets`): a buyer at its own cap gains nothing by waiting for another's slots. A first lock that is refused makes no session, so being told to wait costs the seller nothing. |
| 2 | An unpaid invoice lapses within a minute. | It holds a place under the seller's cap on held tickets until it does. A buyer whose payments failed asks for those invoices to be cancelled at once. Found in the tests: a buyer whose two held locks had failed for lack of a slot was refused the prepaid ticket it then asked for, because its two dead invoices still filled its session; held and prepaid tickets of a session are now counted apart. |
| 4 | "It cuts the session to one ticket and waits, and if one ticket does not lock either it stops holding." | What a session learnt has to outlive it. A wallet that stops a session with nothing locked and opens a new one would otherwise try again at once, every call. The next session with that seller starts with the smaller pool, the count of failed rounds and what is left of the wait; after a route was full for three rounds, one more failed round is ten more minutes. |
| 4 | A refill "when fewer than a set number of tickets are unreleased". | With half of a pool or fewer left. Below half, a pool of 2 was refilled only when it was empty, and every second ticket of a stream waited for a lock. |
| 5 | The seller "accepts [the preimage] for a `SETTLED` invoice of the session, once". | The seller's node knows every preimage of its own invoices, so the preimage proves nothing to the seller: what credits a session is the node's word that the invoice is settled in full. The preimage only names the ticket. A paid ticket nobody presents is credited by the seller's sweep, so a buyer that lost the preimage (a crash between paying and presenting) has lost nothing at the seller. |
| 5 | "A buyer SHOULD buy one such ticket at a time." | And books it before the payment is sent, under every rule of a release, and tags the payment as it tags a held ticket's, so that a wallet restored from an older backup finds it in its node's payment list. The tag of a prepaid ticket is made from a random nonce under another label: its hash is the seller's, and no nonce of the buyer derives it. |
| 11 | "Held tickets take at most half the slots of any channel their holder can see, counting what is pending there already." | The buyer's node chooses the channel among those the wallet allows, so the wallet takes the smallest of them for its budget and the fullest for the room. And a ticket that was released and not yet settled is still pending: it takes its slot until the seller's settle has come back. |
| 11 | "A channel's slots are ... 30 where they cannot be read." | 30 where the listing names no number for a channel. Where the list itself cannot be read, nothing is locked: the wallet does not lock on a guess of which channels it has. |
| 11 | A held ticket is not below "the dust limit of either side of the channel it leaves on". | Checked when a session opens, where it decides the ticket size, and again at every lock, where it can refuse a size decided earlier: a channel can close and another, with a higher limit, be in the way. A session whose ticket became dust holds nothing from then on. |
| 12 | `tickets.velocity` defaults to `"release"`. | To `"session"`: with a pool of 2 and one release per ticket, counting every release stopped a stream at its eighth ticket by a rule meant for payments to different places. |

**When the wallet buys a prepaid ticket.** The seller's 402 lists an `on-arrival` entry of the
same node, receipt key and endpoints as the entry the session was opened on, and one of these
holds: the seller lists nothing else; the slot budget has no room for a held ticket with this
seller; the ticket would be below a dust limit on the wallet's channel; the session waits after
a lock that failed for lack of a slot, or holds nothing after three such rounds; the seller
answered `slots_short`. Otherwise it releases a held ticket. A seller that offers no prepaid
tickets is, in those cases, not paid: the call says why and how long to wait, or the next rail of
the 402 is tried (section 12).

**Measured on the lab on 2026-10-13**, with the wallet and the gateway as they ship, Lightning Fork
nodes, and the buyer's channel and the seller's inbound channel opened with 30 slots (one host,
loopback, one hop, the release binaries; no Core Lightning node). Each line names its script.

| What | Measured | Script |
|---|---|---|
| The wallet's node lists its 30-slot channel | `max_accepted_htlcs` 30 on one side and 483 on the other; the wallet takes 30 | `ticket_book_regtest.sh` (`one`) |
| Lock 2 tickets through the hop; lock the next when one is left | 0.04 s each, by the signer's own call (invoices made by a stand-in seller) | `ticket_book_regtest.sh` (`one`) |
| 15 sellers of one task, 1 ticket each | 15 locked in 0.21 to 0.23 s: half of the channel; a sixteenth seller is refused | `ticket_book_regtest.sh` (`many`) |
| 13 payments of others pending on the buyer's channel | the wallet holds its 2: 15 pending. With 15 pending a lock is refused before the node is asked, and a new session holds nothing | `ticket_book_regtest.sh` (`slots`) |
| A seller behind a channel with no free slot (483 of 483 taken) | the ticket is in flight on the buyer's node for a moment, then `FAILURE_REASON_NO_ROUTE`; the second try fails at once; waits of 30 s and 60 s, and after the third round nothing is held | `ticket_book_regtest.sh` (`full`) |
| 2,000 lock requests to the gateway | 8 sessions served and 15 tickets issued; 1,992 answered `slots_short` with `retryAfter` 30, in 0.5 s | `gateway_regtest.sh` (`flood`) |
| A prepaid ticket, from the lock request to the seller's signed credit | 0.21 s at the median, 0.26 s at most (10 tickets); its HTLC was off the seller's channel 0.04 s after the payment succeeded | `gateway_regtest.sh` (`prepaid`) |
| The gateway given `offchain:read`, with a config that assumed 483 | cap 15, read from the node; with 15 payments it did not issue pending inwards, `slots_short` | `gateway_regtest.sh` (`slots`) |
| A first request through the wallet, pool of 2 locked through the hop | 0.34 s (median of 5 new sessions; it was 0.38 s with a pool of 8) | `ticket_e2e_regtest.sh` (`page`) |
| A paid page from the balance over a free page, through MCP, signer and gateway | 1.7 to 1.8 ms against 1.3 to 1.4 ms: 0.3 to 0.4 ms more (medians of 200, four runs) | `ticket_e2e_regtest.sh` (`latency`) |
| A 100 MB file, 20 tickets | 3.4 to 3.7 s (1.7 to 1.9 s with a pool of 8): with 2 held, a stream that uses a ticket every 0.09 s waits for locks. A buyer that spends this fast wants larger tickets (section 11, rule 1) | `ticket_e2e_regtest.sh` (`stream`) |
| The same wallet with 15 payments of others on its channel | a first request by prepaid ticket in 0.33 s; a stream bought its tickets prepaid at 0.32 s each, never more than one of its payments pending | `ticket_e2e_regtest.sh` (`slots`) |
| One slot left on the seller's channel | one of the wallet's two tickets held, the other `FAILURE_REASON_NO_ROUTE`; the page was paid, the session went to 1 ticket and a 30 s wait, and the next tickets were prepaid | `ticket_e2e_regtest.sh` (`slots`) |

