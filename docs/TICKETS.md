# Stream tickets: the wire, draft v0

**Draft v0. Nothing in the tree implements this yet.** It is written down before any wallet or
seller code so that it can be argued with. Its numbers were measured on regtest by
`scripts/ln_ticket_regtest.sh` (four Lightning Fork nodes, default settings, one host, loopback),
which anyone can rerun; the few that come from reading the node's source say so. Nothing here has
run on mainnet. XBT is Bitcoin on BLAKE2b proof of work; "the
SHA-256 chain" is the other chain.

A **ticket** is a small Lightning payment that is locked along an ordinary route and not yet
released. The buyer picks a 32-byte secret and gives the seller its SHA-256 hash. The seller's node
issues a hold invoice for that hash, and the buyer's node pays it. The money is now committed to the
seller along the route, and nobody can take it, because only the buyer knows the secret. To pay for
a request the buyer puts the secret in the request. The seller hashes it, finds the ticket, collects
and serves. Tickets are locked a few at a time, ahead of use, so no request waits for a payment.
This needs no change to the Lightning node: it is `AddHoldInvoice`, `SettleInvoice` and
`CancelInvoice`, as nodes ship them.

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
           "receiptKey": "<33-byte public key>", "session": "/x402/ticket"}}
```

| Field | Meaning | Why |
|---|---|---|
| `network` | `lightning:` and the 32 hex characters of the chain's `bip122` id. Not the chain id itself. | A client picks an entry by scheme and network. The chain id already means "a channel on the chain". XBT and the SHA-256 chain share a genesis block, so a Lightning id keyed on it would name both networks. |
| `features: [512]` | Every invoice of this entry carries feature bit 512, required. | Bit 512 is what separates an XBT Lightning invoice from one of the SHA-256 chain. The wallet's Lightning rail already refuses an invoice without it. |
| `amount` | The price of this request, in msat. | Pieces are metered below one sat; money moves a ticket at a time (section 3). |
| `payTo` | The node every ticket invoice must name as payee. | The 402 came over TLS from the seller. An invoice naming another node pays a stranger. |
| `ticketMsat` | The size of one ticket. | One fixed size, so that an invoice has one right amount. |
| `maxTickets` | The most tickets the seller holds unreleased for one session. | Each held ticket takes one of the 483 HTLC slots of every channel on the route and the seller's inbound capacity. |
| `ticketBlocks` | The final CLTV delta of every ticket invoice: how long a ticket lives. | It bounds how long the buyer's money can be locked (section 6). |
| `release` | `with-request`: the secret comes with the request. `after-verify`: section 5. | Who goes first, and so who risks one piece. |
| `settle` | `on-use`: tickets are held until used. `on-arrival`: section 5. | Whether a ticket can be had back. |
| `receiptKey` | The key that signs the seller's receipts. | With tickets the payment preimage proves nothing: the buyer always knew it. The signed receipt is the proof of what was paid for. |
| `session` | Path of the session endpoints on the seller's origin. | |

A buyer MUST refuse an entry whose `ticketMsat`, `maxTickets` or `ticketBlocks` is above what its
owner allows, or it locks more, or for longer, than the owner agreed to.

## 2. Lock

```text
POST <session>/lock    {"version": "ticket/0", "session": "<id, absent the first time>", "hashes": ["<h1>", "<h2>", ...]}
200                    {"session": "<id>", "key": "<32 bytes, the first time only>",
                        "tickets": [{"hash": "<h1>", "invoice": "<BOLT 11>"}, ...]}
```

The buyer derives each secret in its signer, from its own seed, and sends only the hashes. The
seller registers a hold invoice per hash (`AddHoldInvoice`: the hash, `ticketMsat`, a final CLTV
delta of `ticketBlocks`, a time expiry of 60 seconds) and returns the invoices, for as many of the
hashes as its cap allows, in order. `key` is a session key for authenticating requests (section 3);
it travels once, over TLS. A secret is for one invoice. The buyer MUST NOT send a hash twice, even
after a payment that failed: an HTLC for it may still be somewhere on a route.

Before paying each invoice the buyer MUST check all of these. They are the whole of the buyer's
safety, since a paid ticket cannot be recalled:

| Check | What goes wrong without it |
|---|---|
| The payee is `payTo`. | The ticket pays another node. |
| The payment hash is one of the hashes just sent, and none is used twice. | An invoice for any other hash is an ordinary invoice: whoever knows its preimage takes the money on arrival. |
| The amount is exactly `ticketMsat`. | The buyer locks more than the terms said. |
| Feature bit 512 is set and required; the prefix is XBT's. | The wallet pays on the SHA-256 chain's Lightning network. |
| The final CLTV delta is `ticketBlocks`, and within the owner's bound. | Funds can stay locked for as long as the seller wrote (the node's ceiling for a route is 2,016 blocks, from its source). |
| With this ticket, unreleased tickets for this seller are at most `maxTickets`, and their sum is within the owner's cap on locked funds. | A seller that asks for more locks more. |

The buyer's node then pays each invoice, under all the checks the wallet's Lightning rail already
makes of its own node and channels, with a fee limit and a limit on the route's total time lock
(`cltv_limit`), both set by the owner. Each hop adds its own time lock delta to the buyer's
HTLC (80 blocks per hop at the forks' default): a 40-block ticket through one hop is an HTLC that
expires 123 blocks after it was locked. Without the limit, a long route decides how long the
buyer's funds can be stuck behind a hop that has gone away.

A ticket is **locked** when the seller's node shows its invoice as `ACCEPTED`. The buyer's node shows
the payment as `IN_FLIGHT` and stays that way until the ticket is settled or cancelled. Locked funds
are not spent. They count against a cap on locked funds, not against a budget.

The seller MUST cap sessions as well as tickets per session, and SHOULD let an unpaid invoice lapse
within a minute, or anyone can fill its node with invoices and its channels with held payments at
no cost but locking the same amount of their own money. An unpaid invoice is cancelled by the node
when its time expiry passes. A locked ticket is not: only block height ends it (section 6).

## 3. Paying a request

```text
PAYMENT-SIGNATURE: base64({"x402Version": 2, "accepted": <the accepts entry>,
    "payload": {"session": "<id>", "seq": <n>, "secret": "<32 bytes, or absent>", "auth": "<HMAC>"}})
auth = HMAC-SHA256(key, "ticket/auth|" session "|" seq "|" secret "|" ticket "|" request_digest_v2)
```

`seq` rises by one per request in a session. `request_digest_v2` is the request digest of the
channel wire (method, scheme, host, port, target, body); a field that is absent is empty in `auth`
(`ticket` belongs to section 5). A request needs no ticket id: **the secret names its ticket**, since
its hash is the ticket's payment hash.

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
   ticket that is not locked (`invoice still open`) or a secret that is not a ticket's.
4. Serves, and returns `PAYMENT-RESPONSE` with a receipt signed by `receiptKey`:
   `{"scheme": "ticket", "session", "seq", "releasedMsat", "spentMsat", "charged", "req", "status",
   "bodyHash"}`, signed as the channel wire signs its receipts, under the tag
   `xbt402/ticket-receipt/v0`, over these fields in this order. `releasedMsat` is the sum of the
   tickets settled in this session and `spentMsat` the running total of what was served. Both only
   rise.

The node's own record is what makes a secret good once: a settled ticket is `SETTLED`, not
`ACCEPTED`, also after a restart. A seller that loses its memory cannot be made to serve twice for
one ticket. It does lose its sessions' balances unless it stores them, which costs each buyer the
unused part of one ticket.

If the request cannot be served (no balance, a ticket not locked, too old or used), the seller
answers `402` again with one of `ticket_unknown`, `ticket_not_locked`, `ticket_used`,
`ticket_expiring`, `balance_short`, `session_unknown`, `too_many_tickets`.

The buyer MUST record a ticket as spent, on disk, before its secret leaves the signer, whatever the
reply turns out to be. A secret that has left can be collected at any time until the ticket
expires, so a wallet that books on the reply under-counts what it spent after a crash or a refusal.
The buyer books what it released plus the routing fee its own node reports, never a number the
seller sends. It checks each receipt against its own count, and stops if `spentMsat` exceeds what it
asked for or `releasedMsat` differs from what it released. The requests MUST go over TLS (or
loopback): on a plain connection a listener learns the session key.

On the lab a paid request cost the seller about 1 ms to hash the secret and look the ticket up on
its node, and about 4 ms in all until the settle call returned. The buyer's node showed the payment
`SUCCEEDED`, with the buyer's own secret as the preimage, about 13 ms after the request (medians of
30, one hop, loopback). On a shared host the runs gave 0.9 to 1.2 ms, 3.3 to 5.4 ms and 12 to 34 ms.

## 4. Refill, stop, cancel

**Refill.** When fewer than a set number of tickets are unreleased, the buyer locks more, in the
background, up to `maxTickets`. Locking 8 tickets took 0.3 s through one hop, 0.2 s on a direct
channel and 0.5 s through two hops (100 tickets: 2 s through one hop), so a refill mark of half of
`maxTickets` covers any buyer that spends fewer than four tickets in that time. A ticket with 24 blocks or fewer left can no longer be
used (section 3, step 2): the buyer SHOULD ask for it to be cancelled and lock a fresh one. A
40-block ticket is usable for 19 blocks.

**Stop and cancel.** `POST <session>/cancel {"session", "seq", "hashes": [...] or "all", "auth"}`.
The seller cancels those tickets on its node (`CancelInvoice`) and answers with the hashes it
cancelled and a last receipt. The buyer's funds are free as soon as the cancel has travelled back
along the route: 0.16 s for 8 tickets on the lab. The buyer believes its own node, not the answer:
a ticket is free when its payment shows `FAILED` there. The seller SHOULD also cancel the tickets
of a session that has been idle for some minutes. Held tickets cost it inbound capacity, and they
are what closes its channel if its node goes down (section 6).

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
seller checks that ticket is locked and serves the chunk. The buyer verifies it, and the next
request carries the secret of the previous chunk; the seller serves no further chunk until it has
it. Here the seller risks one chunk and the buyer nothing, so the seller sets `ticketMsat` to the
price of what it will risk. A key that unlocks the whole (a hash-locked last chunk) is an ordinary
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
| Macaroons | Buyer: `info:read`, `offchain:read`, `offchain:write`, `onchain:read`. Seller: `invoices:read`, `invoices:write`. | Each was enough for its side. The seller's could not send coins, pay, open a channel, read the wallet or bake another. |

## 8. Open in this draft

- The scheme name and the `lightning:` network id are ours. Nothing upstream defines them.
- Receipts are signed by a key the 402 names. Nothing ties that key to the node id but the TLS
  origin that served both.
- BOLT 11 only. The fork's BOLT 12 offer code issues each invoice with its own preimage and has no
  hold path.
- One node implementation. The Core Lightning fork has no hold invoice call of its own and was not
  tried, as seller, buyer or hop.
- A hop that has gone, and real network latency, were not run. Fees are the forks' defaults, not
  what XBT's nodes charge.
- A fee for a held payment does not exist on this network. If one is adopted, tickets pay it.
