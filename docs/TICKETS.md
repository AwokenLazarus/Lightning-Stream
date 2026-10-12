# Stream tickets: the wire, draft v0

**Draft v0.** It was written down before any wallet or seller code so that it could be argued
with. Both sides are now built and run on regtest: the seller's side by `xbt-gateway`
(`crates/xbt-gateway`, run by `scripts/gateway_regtest.sh` against Lightning Fork nodes with a test
buyer that speaks this wire), and the buyer's side of sections 2 to 4 by the ticket book in the
wallet's signer (`crates/xbt-signer/src/ticket.rs` and `ticket_rail.rs`, run by
`scripts/ticket_book_regtest.sh`). The wallet's HTTP binding of section 3 is not built, so no
wallet pays a gateway yet. The numbers were measured on regtest by `scripts/ln_ticket_regtest.sh`
(four Lightning Fork nodes, default settings, one host, loopback) and, where a sentence names the
gateway, by `scripts/gateway_regtest.sh`; anyone can rerun them. The few that come from reading
the node's source say so. Nothing here has run on mainnet. Section 10 lists what building the
gateway changed in this draft. XBT is Bitcoin on BLAKE2b proof of work; "the SHA-256 chain" is the
other chain.

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
           "ticketMsat": "1000000", "maxTickets": 8, "ticketBlocks": 40,
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
| `minTicketMsat` | Optional. The smallest ticket the seller issues when a buyer asks for a smaller one (section 2). Absent: `ticketMsat` is the only size. | A buyer that pays many sellers a little each sizes its tickets to what a seller will earn, down to 64 sat by its own choice; without this a seller cannot say how small it will go. |
| `maxTickets` | The most tickets the seller holds unreleased for one session. | Each held ticket takes one of the 483 HTLC slots of every channel on the route and the seller's inbound capacity. |
| `ticketBlocks` | The final CLTV delta of every ticket invoice: how long a ticket lives. | It bounds how long the buyer's money can be locked (section 6). |
| `release` | `with-request`: the secret comes with the request. `after-verify`: section 5. | Who goes first, and so who risks one piece. |
| `settle` | `on-use`: tickets are held until used. `on-arrival`: section 5. | Whether a ticket can be had back. |
| `receiptKey` | The key that signs the seller's receipts. | With tickets the payment preimage proves nothing: the buyer always knew it. The signed receipt is the proof of what was paid for. |
| `session` | Path of the session endpoints on the seller's origin. | |

A buyer MUST refuse an entry whose `ticketBlocks` is above what its owner allows, and one whose
`ticketMsat` is above it unless `minTicketMsat` lets it ask for a size its owner does allow, or it
locks more, or for longer, than the owner agreed to. `maxTickets` is the most the seller will hold:
a buyer whose owner allows fewer locks fewer.

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
answered so and served on the retry. Locked funds
are not spent. They count against a cap on locked funds, not against a budget.

The seller MUST cap sessions as well as tickets per session, and SHOULD let an unpaid invoice lapse
within a minute, or anyone can fill its node with invoices and its channels with held payments at
no cost but locking the same amount of their own money. An unpaid invoice is cancelled by the node
when its time expiry passes. A locked ticket is not: only block height ends it (section 6). A lock
the caps refuse is `402` with `too_many_tickets` or `too_many_sessions`, and asks the node for
nothing.

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
   tickets settled in this session and `spentMsat` the running total of what was served. Both only
   rise.

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
channel and 0.5 s through two hops (100 tickets: 2 s through one hop), so a refill mark of half of
`maxTickets` covers any buyer that spends fewer than four tickets in that time. A ticket with 24 blocks or fewer left can no longer be
used (section 3, step 2): the buyer SHOULD ask for it to be cancelled and lock a fresh one. A
40-block ticket is usable for 19 blocks by the seller's rule, and for 18 by a buyer that stops
one block earlier.

A buyer with many sellers in one task locks fewer and smaller tickets with each: the wallet's
default is 8 tickets of the seller's size up to 8 sellers, and beyond that 2 tickets a seller,
each half of what the seller is expected to earn and at least 64 sat, where the seller's terms
let it choose a size.

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
| Routing hop | **Slots and capacity held for no fee.** A cancelled ticket pays nothing: 10 locked and 5 settled cost the buyer 5,005 sat for 5,000 delivered. | `maxTickets` and `ticketBlocks`. This is Lightning's known jamming exposure. Tickets use it on purpose, which is why the defaults are small. |
| Routing hop | **The cost of a force close** when a seller vanishes with tickets locked, if the hop opened that channel. | With 100 tickets: a commitment transaction of 18,313 weight units and 104 outputs, 4,635 sat in fee, and about 29,000 sat in all to get its funds back at 1 sat/vB, which is 29% of the tickets' value. With 3 tickets it was 1,530 sat. |

Two more things that are true of any Lightning payment and matter more here. Every hop sees the
same hash, so hops that work together can tell that a run of equal payments goes to one seller.
And a ticket below the channel's dust limit (354 sat on the lab) has no output in the commitment
transaction, so nobody can claim it on chain; the node also caps the total of such HTLCs per
channel.

## 7. The numbers and their reasons

| Number | Value | Reason |
|---|---|---|
| Ticket size | 1,000 sat | A hop charges 1,001 msat for a settled 1,000-sat ticket at the forks' default policy (0.1% per hop; nothing on a direct channel, 2,002 msat through two hops). Above the dust limit, so it can be claimed on chain. |
| Smallest ticket | 354 sat, the dust limit | Below it a ticket has no output on chain. At 354 sat one hop's fee is 0.28%. A node takes nothing below 1 sat (999 msat found no route, through a hop or on one channel), and a 1-sat ticket through a hop pays a fee of 1 sat. |
| Tickets unreleased per session | 8 | 8,000 sat locked and 8 of 483 slots. One lock of 8 takes 0.3 s through a hop. |
| Ticket life (`ticketBlocks`) | 40 blocks | The node takes no less than 24. The seller's node cancels at 18 before expiry, the seller stops accepting at 24 before, and the payer's node adds 3: so 19 usable blocks, and at most 25 blocks locked behind a silent seller. |
| Seller's margin | 24 blocks before expiry | 18, when its node cancels the ticket itself, and 6 more for a settle that has to go on chain (the node starts that 16 blocks before expiry). |
| Invoice time expiry | 60 s | Long enough to pay through a few hops (0.5 s through two), short enough that unpaid invoices do not pile up. |
| Tickets in flight per channel | 483 at most | The protocol's limit. Of 520 offered at once, 483 locked in 8 s and 37 failed on the buyer's node (`INSUFFICIENT_BALANCE`) with nothing held. 483 tickets take a commitment transaction from 1,116 to 84,200 weight units. |
| Macaroons | Buyer: `info:read`, `offchain:read`, `offchain:write`, `onchain:read`. Seller: one with `invoices:read`, `invoices:write`, and one with `info:read`. | The buyer's was enough for its side. The seller's invoice macaroon makes, follows, settles and cancels tickets and cannot read the block height; the second one reads it. Neither could send coins, pay, open a channel, read the wallet or bake another. |
| Seller's caps (the gateway's defaults) | 30 sessions with tickets locked, 4 from one address, 8 tickets each: 240 tickets, 240,000 sat | What buyers can hold of the seller's inbound capacity at no cost to them: half of one channel's 483 slots. |

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
- One node implementation. The Core Lightning fork has no hold invoice call of its own and was not
  tried, as seller, buyer or hop.
- A hop that has gone, and real network latency, were not run. Fees are the forks' defaults, not
  what XBT's nodes charge.
- A fee for a held payment does not exist on this network. If one is adopted, tickets pay it.
- The list of what a seller sells (`GET /services` on the gateway: the node id, the receipt key,
  the ticket terms and each route's price) is not signed. Signing it with the node's key needs the
  node's `SignMessage`, which neither of the seller's macaroons allows; the runner can sign the
  list once with its own tools, or a third narrow macaroon can. Until then the list is the TLS
  origin's word, as the terms are.
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
  and 4.

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
