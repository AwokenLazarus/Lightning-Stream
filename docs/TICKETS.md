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
that come from reading the node's source say so. Nothing here has run on mainnet. Sections 10 and
13 list what building each side changed in this draft. Section 11 (2026-10-12) sets the defaults
again for channels that carry 30 pending payments, which is Core Lightning's default, and for the
dust limits; it was measured with the XBT Core Lightning fork in the lab, and the wallet and the
gateway in this tree still have the earlier defaults. XBT is Bitcoin on BLAKE2b proof of work;
"the SHA-256 chain" is the other chain.

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
| `network` | `lightning:` and the 32 hex characters of the chain's `bip122` id. Not the chain id itself. | A client picks an entry by scheme and network. The chain id already means "a channel on the chain". XBT and the SHA-256 chain share a genesis block, so a Lightning id keyed on it would name both networks. |
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

## 2. Lock

```text
POST <session>/lock    {"version": "ticket/0", "session": "<id, absent the first time>", "hashes": ["<h1>", "<h2>", ...],
                        "ticketMsat": "<the size asked for, optional>"}
200                    {"session": "<id>", "key": "<32 bytes, the first time only>",
                        "tickets": [{"hash": "<h1>", "invoice": "<BOLT 11>"}, ...],
                        "refused": [{"hash": "<h>", "error": "hash_refused"}, ...]}
```

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
lack of a slot is told only that its balance is short.

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

`seq` starts at 0 and rises by one per request in a session. `request_digest_v2` is the request
digest of the channel wire (method, scheme, host, port, target, body); a field that is absent is
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
   "bodyHash"}`, signed as the channel wire signs its receipts, under the tag
   `xbt402/ticket-receipt/v0`, over these fields in this order. `releasedMsat` is the sum of the
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
earn, never below 546 sat. The wallet in this tree still has the earlier default: 8 tickets up to
8 sellers, and beyond that 2 a seller, each at least 64 sat.

**A lock that fails for lack of a slot.** A ticket payment that ends `FAILED` with
`INSUFFICIENT_BALANCE` on a channel that has the balance, or with `TEMPORARY_CHANNEL_FAILURE` or
`NO_ROUTE` after an earlier lock with the same seller worked, has most likely met a full channel
(section 11). The buyer MUST NOT send that hash again, and SHOULD NOT lock again at once: it cuts
the session to one ticket and waits (30 seconds, doubling to 10 minutes), and if one ticket does
not lock either it stops holding tickets with that seller and pays it another way or not at all.
A buyer that keeps trying fills the last free slots of a channel other people are using.

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

**Stop and cancel.** `POST <session>/cancel {"hashes": [...] or "all"}`, authenticated as any
request of the session. The seller cancels those tickets on its node (`CancelInvoice`) and answers
with the hashes it cancelled and a receipt. The buyer's funds are free as soon as the cancel has travelled back
along the route: 0.16 s for 8 tickets on the lab. The buyer believes its own node, not the answer:
a ticket is free when its payment shows `FAILED` there. The seller SHOULD also cancel the tickets
of a session that has been idle for some minutes, and SHOULD cancel a ticket that has reached its
margin, which it can no longer use. Held tickets cost it inbound capacity, and they are what
closes its channel if its node goes down (section 6). The gateway cancels after 5 minutes without
a paid request, after 1 minute for a session that has never released a secret, and at the margin.

Cancelling needs the seller. A seller that does nothing leaves the buyer's tickets locked until
they end by block height.

## 5. Two settings

**`settle: "on-arrival"` (a prepaid balance).** For a seller whose node has no hold invoices. The
buyer sends no hashes, only a count. The seller returns ordinary invoices with hashes of its own,
and each is paid in full when it arrives. The buyer's node receives the preimage, and that preimage
is used as the secret in section 3. The seller accepts it for a `SETTLED` invoice of the session,
once. Everything else is the same. The difference is in what can be lost: every ticket bought is
spent at once, used or not, so the buyer's exposure is everything it has bought ahead and not one
ticket. A buyer SHOULD buy one such ticket at a time.

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
| Seller's margin | 24 blocks before expiry | 18, when its node cancels the ticket itself, and 6 more for a settle that has to go on chain (the node starts that 16 blocks before expiry). |
| Invoice time expiry | 60 s | Long enough to pay through a few hops (0.5 s through two), short enough that unpaid invoices do not pile up. |
| Tickets in flight per channel | 30 on a Core Lightning channel, 483 at most | 483 is the protocol's limit and Lightning Fork's default; 30 is Core Lightning's default, each way, set when the channel opens. Between Lightning Fork nodes, of 520 offered at once 483 locked in 8 s and 37 failed on the buyer's node (`INSUFFICIENT_BALANCE`) with nothing held; to a Core Lightning node, of 40 offered 30 locked and 10 failed the same way. 483 tickets take a commitment transaction from 1,116 to 84,200 weight units. |
| Macaroons | Buyer: `info:read`, `offchain:read`, `offchain:write`, `onchain:read`. Seller: one with `invoices:read`, `invoices:write`, and one with `info:read`. | The buyer's was enough for its side. The seller's invoice macaroon makes, follows, settles and cancels tickets and cannot read the block height; the second one reads it. Neither could send coins, pay, open a channel, read the wallet or bake another. |
| Seller's caps (the gateway's defaults in this tree) | 30 sessions with tickets locked, 4 from one address, 8 tickets each: 240 tickets, 240,000 sat | What buyers can hold of the seller's inbound capacity at no cost to them. That is half of one channel's slots only where the channel has 483; it is eight channels of 30. The cap this draft now asks for is 15 held tickets per 30-slot channel (section 11), and the gateway does not have it yet. |

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
  short. Neither the wallet nor the gateway implements it.
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

## 9. Reserved: lottery

Not specified here, and nothing implements it. A request priced below one ticket is to be paid
by a fair roll that wins a payment of one fixed size with probability price ÷ that size
(`docs/LIMITS.md`, "Lottery tickets (in design)"). Paying by lottery is Wheeler's and Rivest's
idea, and a win that pays itself over Lightning was first set out by Gerhart, Taylor and
Thyagarajan in 2026 ([`REFERENCES.md`](REFERENCES.md), 33, 34 and 44). This draft leaves room for
it and no more:

- A seller will offer it as a further entry of `accepts`, with a scheme name of its own, beside
  `ticket`. A `ticket/0` client that does not know the entry skips it.
- Its terms will carry the size of a win and, with `amount`, the odds, so that the buyer's
  owner can cap both before anything is paid.
- Its requests will carry the buyer's part of the draw, and its responses the seller's part and
  any win. The buyer's wallet checks every win itself before it pays one.
- Where a win is paid from a locked ticket, that ticket is locked and cancelled as in sections 2
  and 4, and is at least 546 sat like any held ticket (section 11). A win that is paid at once,
  by an ordinary payment, may be smaller, and the buyer sends at most 8 such payments at a time
  on one channel.

Field names, the draw and its checks are left to a later draft.

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
above; **the wallet and the gateway in this tree do not follow them yet** and the last table says
where they differ.

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

**Where the code in this tree differs.**

| | This draft now | The wallet's ticket book | The gateway |
|---|---|---|---|
| Tickets per session | 2 | 8 for up to 8 sellers, then 2: the defaults of the owner's `tickets.pool`, `many_sellers` and `pool_many` | 8 (`tickets.max_tickets`) |
| Smallest held ticket | 546 sat | 64 sat by its own choice: the default of the owner's `tickets.floor_ticket_sats` | 1 sat (`tickets.ticket_msat` from 1000) |
| Held tickets in all | Half the slots of a channel: 15 of 30 | 64 (`max_locked_tickets`), with no look at the channel's slots | 240 (30 sessions of 8), with 483 slots assumed |
| A dust check before paying | Yes | No | Not its part |
| A lock that fails for lack of a slot | Hold less, wait, stop | The reason is noted on the ticket | Not its part |
| `slots_short` | Yes | Not known | Not sent |
| `settle: "on-arrival"` | Section 5 | Refused | Not offered |

## 12. The wallet's side: `xbt402_pay`

An agent pays with one tool call, `xbt402_pay(url, method, body, max_sats, task)`. Everything else
is the wallet's signer's (`crates/xbt-signer/src/ticket_pay.rs`): it sends the request once without
paying, reads the 402 itself, and chooses the rail. Who the seller is therefore comes from what
the signer fetched from the URL's own origin, never from its caller.

**The rail.** One function, in this order; the first entry the seller offers and the owner's
policy allows is paid.

| | Entry of the 402 | Paid when | Otherwise |
|---|---|---|---|
| 1 | `scheme: "ticket"` on the wallet's Lightning network | Tickets are on (`tickets.enabled`); the call names one of the owner's tasks, or the owner has one task, or one named `default`; the seller is admitted (its origin is on the allowlist and tied to its node id, or the task pays any seller); the terms are inside the owner's bounds; `release` is `with-request`; the origin is https, or http on this machine. | The next entry, with the reason. |
| 2 | `scheme: "exact"` on the wallet's Lightning network, with a BOLT 11 invoice in `extra.invoice` | The Lightning rail is on; the origin is on the allowlist; the invoice pays the entry's `payTo` its `amount`; and `ln_pay` would pay that invoice (every rule of that rail, the payee on the allowlist among them). The wallet pays it and sends the request again with `{"preimage"}` as the payload of `PAYMENT-SIGNATURE`. | The next entry, with the reason. |
| 3 | `batch-settlement` (alias `xbt-channel`) on the chain: the frozen on-chain channel | The origin is on the allowlist and the owner has not set `channel_rail: false`. This path is unchanged. | The report below. |
| | None of them | Nothing is paid. The reply is `no_rail` and lists each entry that was passed over and why. | |

A rail is passed over only for a reason that makes it unusable for this seller: it is off, the
seller is not admitted, or the terms are outside the owner's bounds. A budget, a cap or a velocity
limit that is used up refuses the call and tries no other rail. With tickets off in the policy,
and for a call with `max_sats` 0, `xbt402_pay` is the channel path from its first byte, as before.
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
6. The pool is refilled behind the call when fewer than half of it are left.

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
payment is for that count is the owner's choice, `tickets.velocity`: `"release"`, the default,
counts every release, so a wallet with the shipped policy releases at most 8 tickets an hour on
every rail together and a long answer stops at the eighth; `"session"` counts a session once, from
its first release, and bounds its releases by the budgets, the caps on locked funds and
`max_sends_per_hour`. An existing policy has no `tickets.velocity` and means `"release"`.

Measured on the lab (`scripts/ticket_e2e_regtest.sh`; one hop, loopback, the release binaries, an
agent calling the MCP tool): a first request on a new session (the unpaid request, 8 tickets locked through the hop, the
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
| 7, 11 | The pool and the smallest ticket were numbers in the wallet's code. | They are the owner's settings (`tickets.pool`, `pool_many`, `many_sellers`, `floor_ticket_sats`), each with its default in one place. The defaults are still the earlier ones (8, then 2 beyond 8 sellers, 64 sat): section 11's rules change those defaults and add the checks of a channel's slots and dust limit, which the wallet does not make yet. |
| new | | The rail table of section 12, the `exact` entry for a single Lightning payment, and the owner's `channel_rail` switch. |
