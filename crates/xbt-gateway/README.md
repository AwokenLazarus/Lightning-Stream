# xbt-gateway

The stream-ticket seller gateway: one program beside a Lightning node. Point it at an HTTP
service you already run, set a price per route, and buyers pay piece by piece with stream tickets.
The service needs no change. The wire is `docs/TICKETS.md` (draft v0); what the gateway does not
do is in `docs/LIMITS.md`, section "Seller gateway".

Status: regtest only. It has run against Lightning Fork nodes on one host
(`scripts/gateway_regtest.sh`) and against a stand-in node in its tests. Nobody outside the
project has reviewed it. No wallet pays it yet: the buyer in the regtest script is a test buyer.

## What it does with a request

1. An unpaid request to a priced route gets `402` with the ticket terms: the node id, the ticket
   size, how many tickets a buyer may hold, how long a ticket lives, who goes first, the price rule.
2. `POST /x402/ticket/lock` registers a hold invoice on your node for each hash the buyer sends.
   The buyer's node pays them; each is now a locked ticket. Only the buyer knows the secrets.
3. A paid request carries a secret. The gateway hashes it, finds the ticket in that buyer's
   session, checks the node holds it (`ACCEPTED`) with more than 24 blocks left, settles it on
   your node, and only then passes the request to your service.
4. The answer is metered against the session's balance in millisatoshi and comes with a receipt
   signed by the gateway's receipt key. A long answer stops when the buyer stops releasing tickets.
5. Tickets of a buyer that goes quiet are cancelled, so they stop holding your inbound capacity.

## Run it

Bake two macaroons on the node. The gateway refuses wider ones on mainnet:

```bash
lncli bakemacaroon invoices:read invoices:write --save_to invoices.macaroon
lncli bakemacaroon info:read --save_to info.macaroon
```

The first makes, follows, settles and cancels invoices. The second reads the block height, which
the first cannot, and which the gateway needs to keep a ticket's last 24 blocks unused. Neither
can send coins, pay, open a channel or bake a macaroon.

```bash
cargo build --release -p xbt-gateway
target/release/xbt-gateway --check gateway.json   # reads the config and the macaroons, says what the caps cost
target/release/xbt-gateway gateway.json
```

`gateway.example.json` is a config for mainnet. Every key is checked: an unknown one stops the
start. For a public seller, put a TLS reverse proxy in front and set `public_url` to the origin
buyers use.

## Pricing a piece

A route's price is the sum of three rules:

| Rule | Config | Charged |
|---|---|---|
| per request | `request_msat` | once, when your service answers with a status below 400 |
| per byte | `byte_msat` for every `per_bytes` bytes | as the body is sent, rounded up over the whole body |
| per second | `second_msat` | for every started second the answer is open, the first at its head |

A route is either priced or marked `"free": true`; a path with no route is not served at all.
`"release": "after-verify"` marks a route whose content the buyer can check: a piece is served on
a locked ticket before its secret arrives, up to one ticket's worth.

What these rules cannot price is anything only your service can count, such as the tokens a
model produced.

## The rules it keeps

| Rule | Where |
|---|---|
| Nothing is served on a ticket the node does not hold (`ACCEPTED`, whole, in the buyer's own session). | `book.rs`, `Book::present` |
| A ticket is credited once. | `Book::settled` |
| A used ticket is settled at once, before the service is asked, and never with 24 blocks or fewer left. | `gateway.rs`, `take_secret` |
| Without a block height from the node that is at most 10 seconds old, no secret is taken. | `Gateway::known_height` |
| A charge comes out of what was released and not spent; an answer the service did not give is not charged. | `Book::charge`, `Gateway::route` |
| Sessions, sessions per address and unreleased tickets are capped before the node is asked for anything. | `Book::lock` |
| Only the headers and methods you allowed reach your service; nothing it answers is read for money. | `upstream.rs` |

## What the defaults cost you

Buyers can hold up to 30 sessions of 8 tickets of 1,000 sat: 240,000 sat of your node's inbound
capacity and 240 of a channel's 483 HTLC slots, at no fee to them, until they use the tickets or
the gateway cancels them (1 minute for a session that never released a secret, 5 minutes after a
session's last paid request, and when a ticket reaches its last 24 blocks). `--check` prints the
figure for your config. Lower `caps.max_sessions` if your node has less inbound capacity.

## Measured

Regtest, one host, loopback, three Lightning Fork nodes (buyer, a routing hop, seller), a stock
`python3 -m http.server` behind the gateway. Rerun with `scripts/gateway_regtest.sh` (about 8
minutes, 40 checks); the report is `run/gateway_regtest.json`. From five runs:

| What | Measured | Check |
|---|---|---|
| A paid request over the same request through a free route, median of 300 | 0.07 to 0.11 ms more (0.63 ms against 0.56 ms) | `latency` |
| A paid request that carries a secret (one settle on the node), median of 32 | 3.4 to 6.0 ms more | `latency` |
| The longest a secret waited for its settle | 19 ms | `latency` |
| A 100 MB file at 200,000 msat per MiB, the buyer releasing one ticket at a time and stopping after ten | 52,428,800 bytes: what ten tickets pay for, to the byte; 10,010 msat in routing fees | `fetch` |
| 2,000 lock requests against a cap of 6 sessions | 6 served, 1,994 refused, 48 invoices on the node | `flood` |
| A buyer that locks 8 tickets and releases none, limit set to 15 s | its tickets cancelled after 16 s | `flood` |
| A restart of the gateway with tickets locked | back in 0.05 s, the tickets still good | `restart` |
