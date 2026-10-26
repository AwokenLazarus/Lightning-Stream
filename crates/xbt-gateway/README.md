# xbt-gateway

The stream-ticket seller gateway: one program beside a Lightning node. Point it at an HTTP
service you already run, set a price per route, and buyers pay piece by piece with stream tickets.
The service needs no change, and nor does the node if it is of the lnd family (lnd and its forks):
the gateway uses that node's hold invoices over its REST interface, and has run against Lightning
Fork only. **It cannot make a Core Lightning node a seller.** Such a node has no hold-invoice
call, neither published hold plugin fits, nothing on it cancels a held ticket before the ticket
expires, and the gateway does not speak its interface (`docs/TICKETS.md`, section 8). The wire is `docs/TICKETS.md` (draft v0); what the gateway does not
do is in `docs/LIMITS.md`, section "Seller gateway".

Status: regtest only. It has run against Lightning Fork nodes on one host
(`scripts/gateway_regtest.sh`) and against a stand-in node in its tests. Nobody outside the
project has reviewed it. The wallet of this tree pays it (`scripts/ticket_e2e_regtest.sh` with
tickets, `scripts/lottery_regtest.sh` by draws); the buyer in `scripts/gateway_regtest.sh` is a
test buyer.

**Your node must be an lnd-family node.** The gateway speaks lnd's REST interface (hold
invoices: `/v2/invoices/hodl`, `settle`, `cancel`, `lookup`, `subscribe`) and nothing else. A
Core Lightning seller is not supported for held tickets today: Core Lightning has no hold
invoice call, and nothing on it cancels a held ticket before it expires (`docs/TICKETS.md`,
section 8). Pointed at a node that answers `getinfo` in Core Lightning's names, or has no lnd
`GetInfo`, the gateway stops at start and says so.

## What it does with a request

1. An unpaid request to a priced route gets `402` with the ticket terms: the node id, the ticket
   size, how many tickets a buyer may hold, how long a ticket lives, who goes first, the price rule.
2. `POST /x402/ticket/lock` registers a hold invoice on your node for each hash the buyer sends.
   The buyer's node pays them; each is now a locked ticket. Only the buyer knows the secrets.
   As shipped, a session's first lock is for a prepaid ticket (an ordinary invoice, paid in
   full on arrival), and hold invoices are issued only to a session that has paid one: a lock
   for held tickets before that is `402 prepaid_first`, and asks your node for nothing
   (`caps.held_after_paid`, on wherever you offer both kinds; `false` turns it off). A first
   lock's invoice lapses after 20 s (`caps.first_lock_secs`), and one client address has at most
   2 unpaid invoices at once (`caps.unpaid_per_address`, 0 for no cap: the address is the
   socket's unless `http.forwarded_address` names your proxy).
3. The buyer releases a ticket by sending its secret: in `POST /x402/ticket/release`, which is
   what the wallet of this tree does, or inside a paid request, which the gateway also takes.
   The gateway hashes it, finds the ticket in that buyer's session, checks the node holds it
   (`ACCEPTED`) with more than 24 blocks left, settles it on your node, and only then serves on
   it.
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

A third is your choice, and the gateway does not ask for it:

```bash
lncli bakemacaroon offchain:read --save_to channels.macaroon   # node.channels_macaroon
```

With it the gateway reads your node's channel list before it issues a held ticket: its cap on
held tickets becomes half of what your smallest active channel carries, and it issues none while
any channel is half full of pending payments. Know what you hand over: `offchain:read` also
shows your channel balances, your node's payments and what it forwarded, to whoever has the
gateway's files. Without it the gateway keeps to the numbers in its config, which assume a
channel that carries 30 pending payments.

The gateway takes a ticket's secret only while more than 24 blocks are left before it expires:
your node cancels a held ticket itself a number of blocks before expiry (lnd's
`invoices.holdexpirydelta`: 18 on the Lightning Fork node at its default, 12 on upstream lnd),
and 6 more are kept for a settle that has to go on chain. The node does not say what it is set
to, so tell the gateway if yours is not 18: `"node": {"hold_expiry_delta": 12, ...}`. Above 18 the
gateway does not start: lower the node's setting.

```bash
cargo build --release -p xbt-gateway
target/release/xbt-gateway --check gateway.json   # reads the config and the macaroons, says what the caps cost
target/release/xbt-gateway gateway.json
```

`gateway.example.json` is a config for regtest. Every key is checked: an unknown one stops the
start.

- **The chain.** A file that names no `chain` is a regtest file. Every chain but `main` also
  names its `network`: `bip122:` and the first 32 hex characters of the hash of that chain's
  block 101 (`getblockhash 101`); the example's is a placeholder. (The terms say it with
  `extra.layer: "lightning"`. A file that still writes `lightning:` and the same hex, the name of
  before 2026-10, is read for one release.) Mainnet is asked for twice:
  `"chain": "main"` and `"mainnet_ack": "real funds, software that has run on regtest only"`,
  word for word. With one and not the other nothing starts. A gateway that starts on mainnet
  prints, at every start and every `--check`, a short list of what is known to be open there;
  the whole of it is `docs/LIMITS.md`.
- **Where it listens.** The gateway speaks plain HTTP. It listens on a loopback address
  (`127.0.0.1` or `[::1]`, written as an address), or on any other address only when
  `public_url` is an `https` origin: that is how you say a TLS reverse proxy stands in front.
  For a public seller, run that proxy and set `public_url` to the origin buyers use. The
  gateway cannot check that the proxy is there.

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

## Several services behind one gateway

`upstream` at the top of the config is the service every route passes requests to. A route may
name its own instead, so one gateway sells several services, each under a path with its own
price:

```json
"routes": [
  {"path": "/", "upstream": "http://jellyfin:8096", "price": {"byte_msat": 20000, "per_bytes": 1048576}},
  {"path": "/ai/", "upstream": "http://ollama:11434", "strip_prefix": true, "methods": ["GET", "HEAD", "POST"],
   "max_body": 1048576, "price": {"request_msat": 10000}}
]
```

The longest matching path wins, so `/ai/...` goes to the model and everything else to the media
server. `"strip_prefix": true` (on a path ending in `/`) passes the request on without the route's
path: `/ai/api/generate` reaches the model as `/api/generate`. When every route names its own,
the top-level `upstream` may be left out. A `listing` with a `services` list (`docs/LISTINGS.md`,
`listing/1`) tells buyers what each path sells.

## The rules it keeps

| Rule | Where |
|---|---|
| Nothing is served on a ticket the node does not hold (`ACCEPTED`, whole, in the buyer's own session). | `book.rs`, `Book::present` |
| A ticket is credited once. | `Book::settled` |
| A used ticket is settled at once, before the service is asked, and never with 24 blocks or fewer left. | `gateway.rs`, `take_secret` |
| Without a block height from the node that is at most 10 seconds old, no secret is taken. | `Gateway::known_height` |
| A charge comes out of what was released and not spent; an answer the service did not give is not charged. | `Book::charge`, `Gateway::route` |
| Sessions, sessions per address and unreleased tickets are capped before the node is asked for anything. | `Book::lock` |
| Held tickets, all sessions together, stop at half of the pending payments one inbound channel carries (15 of 30); a buyer beyond that is told `slots_short` and when to come back, and has no session. | `Book::lock`, `Gateway::slot_room` |
| A held ticket is at least 546 sat: below a channel's dust limit it could not be claimed on chain. | `config.rs` |
| A prepaid ticket is credited once, when the node shows its invoice settled in full: on the buyer's preimage, or by the sweep. | `Gateway::take_prepaid`, `Book::settled` |
| Only the headers and methods you allowed reach your service; nothing it answers is read for money. | `upstream.rs` |

## What the gateway knows of your money

Only what your node says of an invoice. A held ticket counts as settled (`settled` in
`/x402/ticket/health`, and the buyer's balance that the gateway serves against) when the settle
call to your node returns success; a prepaid ticket and a lottery win count when your node shows
the invoice `SETTLED`. That is your node's own state: it is set when your node releases the
preimage, and nothing in the invoice changes when the channel peer the payment came through
commits to the fulfil, or if it never does. The money is yours once the peer has done so (your
node no longer lists the HTLC among that open channel's pending HTLCs) or once you have claimed it
on chain. The gateway does not read your channels for this, so do not read `settled` as income
(`docs/TICKETS.md`, section 6, the seller's rows; `docs/LIMITS.md`).

## Two kinds of ticket

`tickets.settle` lists what your terms offer; the default is both.

- **Held** (`"on-use"`): a hold invoice for the buyer's hash, settled when the buyer uses it and
  given back when it does not. A session holds 2 (`tickets.max_tickets`). Each takes one of the
  pending payments ("slots") of the channel it arrives on until it is used or cancelled.
- **Prepaid** (`"on-arrival"`): an ordinary invoice, paid in full when it arrives and never given
  back. It holds no slot. Buyers use it when no slot is free, and it is the only kind a config
  with `"settle": ["on-arrival"]` offers.

## The lottery: pieces that cost less than a ticket

Add a `lottery` section to the config and the gateway offers, beside tickets, to be paid by
draws (`docs/TICKETS.md`, section 9). It is off unless you write the section: with it you serve
first.

```json
"lottery": {"win_msat": 64000, "min_win_msat": 16000, "window": 8, "grace_seconds": 30,
            "grace_pieces": 64, "max_unpaid_wins": 2, "piece_bytes": 262144}
```

A buyer in a lottery session locks nothing with your node. Each request, each `piece_bytes` of
an answer priced by its size and each second of an answer priced by its time is a piece. After
the piece the buyer sends a random value; the gateway reveals the next value of a chain it
committed to when the session opened, and the two together decide whether the piece won. Most
pieces win nothing. A piece that wins gets an ordinary invoice of `win_msat` from your node, and
the buyer pays it at once. The odds are the piece's price over the win, so what you can expect to
be paid is your price: a piece of a tenth of a sat wins a 64-sat payment one time in 640. What
you are actually paid comes near that only over many wins: within 20% takes about 68 wins
(4,350 sat at this win size), nine times in ten.

A route is offered this way only if its dearest piece (its request, one second, or `piece_bytes`
of its body) costs a quarter of `win_msat` or less (`max_odds_den`, 4: no piece wins more often
than one time in four, which is also the most a wallet's owner allows by default). You serve
`window` pieces before any value has come, so this is what the window costs you in wins: 8
pieces of a quarter of a win are 2. A dearer route is paid with tickets, and a request that
names the lottery for it is refused. `GET /services` says which routes are offered.

What it costs you, and what bounds it:

| What a buyer can do | What it gets | The setting |
|---|---|---|
| Send no values | `window` pieces a session, then `value_missing` | `window` (8) and `max_odds_den` (4): 2 wins' worth a session at the most. `max_sessions` (64) and `sessions_per_address` (4); a session that never sent a value is forgotten after `first_use_secs` (60): 8 wins' worth a minute from one address |
| Send values and never pay a win | What it was served up to its first win, then the grace: `grace_pieces` more pieces, `grace_seconds`, or until more than `max_unpaid_wins` are unpaid, whichever comes first. Then `win_unpaid` until your node shows the wins paid. An answer that is being sent stands still for the payment for `pay_wait_secs` (10) at the most, holding its connection and one of the server's threads, and is then cut short | `win_msat`, the three grace settings and `pay_wait_secs` |
| Say a piece never arrived (`void`) | Nothing more than by sending no values: a voided piece stays counted against `window` for the rest of the session. After `max_voids` voids (4) the session is ended (`too_many_voids`) | `window`, `max_voids`. An honest buyer whose answer was cut voids the pieces that were on their way (one to a few), has a narrower window from then on, and opens another session after the fifth |
| Close its session and open another | The window again, but a session closed while it owes (pieces with no value, a win unpaid) keeps its place for `first_use_secs` | `sessions_per_address`, `max_sessions`, `first_use_secs` |
| Open sessions | A chain each: `chain_draws` hashes to make (65,536) and about 34 KiB to keep (one chain value in every 1,024, the block of 1,024 last read, and 8 bytes for every draw taken) | `max_sessions`, `idle_secs` (300) |

Measured on regtest with the wallet of this tree and a buyer that never pays
(`scripts/lottery_regtest.sh`, `cheat`): with pieces of a quarter of a sat and wins of 64 sat it
was served 1.4 wins' worth on average before the gateway stopped it (ten sessions; 0.8 to 1.4 in
four runs, 3.3 at the most in one session). With pieces of a quarter of a win it was served 3.9
wins' worth (ten sessions; 3.9 to 4.9 in four runs): the gateway bears two unpaid wins and
serves 8 pieces ahead of the buyer's values. Where your buyers each
earn you less than one win, a buyer that never pays has had everything free, and nothing on
today's Lightning makes it pay. Your income is uneven too: a buyer that owes you less than a win
usually pays you nothing, and sometimes a whole win.

The rules it keeps, beside those of the table above:

| Rule | Where |
|---|---|
| A chain is made for one session from fresh random bytes, and its anchor is sent before any value of the buyer's. A session outlives a restart: its seed is in the lottery's journal, and a draw is on disk before the reveal for it leaves, so a restart never takes a second value for a draw it revealed for. | `lottery.rs`, `Book::open`; `gateway/draws.rs`, `lottery_open` |
| A piece waits for its value only once it has left. | `Gateway::lottery_route`, `lottery_pump` |
| A value is taken only as the next draw, for a piece that was served, at its price, once. The chain value of a draw leaves only in the answer to the request that brought its value. | `xbt402::lottery::Seller::take`, `Book::draw` |
| A win is paid when the node shows its invoice settled for the full amount, never on a buyer's word. One invoice for a win at a time; another only when the node has cancelled the first. | `Gateway::lottery_refresh`, `Book::claim_invoice` |
| No piece is served outside the window or the grace. | `Book::blocked` |

The fairness of the draw rests on an argument of this project's own that nobody else has
reviewed (`docs/LIMITS.md`, "The lottery").

## Paid by BOLT 12 offer

```json
"offers": {"enabled": true, "description": "My shop"}
```

With this section the gateway makes one BOLT 12 offer of your node at its start (no amount; the
same description finds the same offer after a restart) and names it in its terms for prepaid
tickets and for the lottery. A buyer that understands it pays a prepaid ticket or a win by the
offer, with a payer note that names its session; the gateway credits a paid offer invoice to the
session the note names, only when the note's MAC holds under that session's key, the amount is
the session's own and was paid in full, and the payment and its note were not credited before
(`docs/TICKETS.md`, section 15). Held tickets stay hold invoices: offers have none. The offer
calls need `invoices:read` and `invoices:write`, which `node.macaroon` already has. Run against
the stand-in node only.

### Behind a reverse proxy: whose address is counted

The caps per address (`caps.sessions_per_address` for tickets, `lottery.sessions_per_address`)
count the address of the socket. Behind a reverse proxy that is the proxy's for every buyer: the
cap then holds all your buyers together to a few sessions, or you set it to 0 and it holds
nobody, and the lottery's bound per address above is gone. To have it count buyers, name the
proxy and the header it reports their address in:

```json
"http": {"forwarded_address": {"header": "X-Real-IP", "proxies": ["127.0.0.1"]}}
```

Off unless you write it. The gateway then reads that header on connections from the listed
addresses only (written as addresses), takes the last entry if it is a list, and counts a
request with no such header, or two, under the proxy's own address. Two things are yours to get
right, and the gateway cannot check either: the proxy must set the header itself on every
request, replacing whatever the client sent (nginx: `proxy_set_header X-Real-IP $remote_addr;`),
and nothing else may reach the gateway from a listed address. Get one wrong and a buyer writes
its own address. The cap on connections (`http.per_address`) is taken before any header is read:
set it to 0 behind a proxy.

## The listing on Nostr

With a `listing` section, the gateway can also send its signed listing to Nostr relays, so that
buyers' apps (and any Nostr client that shows NIP-99 classifieds) find the seller without a
directory. It is off unless the config says so:

```json
"nostr": {"relays": ["wss://relay.example"], "publish": true, "republish_s": 21600}
```

The gateway signs the events with a Nostr key of its own, `nostr.key` in the state directory,
made on first start, and the receipt key signs a binding of that key to `public_url`. It sends the
listing at start and every `republish_s` seconds (default six hours, from 600 to 604800). It reads
nothing back from relays. What goes over Nostr and why: `docs/NOSTR.md`.

## What the defaults cost you

A channel carries a fixed number of pending payments each way, for everyone who pays over it:
483 between Lightning Fork nodes, 30 where either end is a Core Lightning node at its default.
When they are all taken, nobody can pay you over that channel. So buyers can hold up to 15
tickets of 1,000 sat between them (`caps.max_held_tickets`, half of `caps.inbound_slots`, which
is 30 unless you say more): 15,000 sat of your node's inbound capacity and 15 slots, at no fee to
them, until they use the tickets or the gateway cancels them (1 minute for a session that never
released a secret, 5 minutes after a session's last paid request, and when a ticket reaches its
last 24 blocks). The sixteenth ticket is not issued: its buyer is told `slots_short` and to come
back in 30 seconds, or buys a prepaid ticket. `--check` prints the figures for your config.

If every inbound channel of your node carries more, set `caps.inbound_slots` to what the smallest
carries (483 for Lightning Fork peers) and the cap follows. A cap above half of that is refused
unless you also write `"held_over_half": true`, which is for a node with several inbound
channels: the buyer's node chooses the channel a ticket arrives on, so the gateway cannot spread
tickets over your channels, and a cap sized for several can fill one.

## Measured

Regtest, one host, loopback, three Lightning Fork nodes (buyer, a routing hop, seller), a stock
`python3 -m http.server` behind the gateway. Rerun with `scripts/gateway_regtest.sh` (about 12
minutes, 51 checks); the report is `run/gateway_regtest.json`. The first six rows are from five
runs before 2026-10-13, with 8 tickets a session; the rows after them from the run of that day,
with the shipped caps and the seller's channel opened with 30 slots:

| What | Measured | Check |
|---|---|---|
| A paid request over the same request through a free route, median of 300 | 0.07 to 0.11 ms more (0.63 ms against 0.56 ms) | `latency` |
| A paid request that carries a secret (one settle on the node), median of 32 | 3.4 to 6.0 ms more | `latency` |
| The longest a secret waited for its settle | 19 ms | `latency` |
| A 100 MB file at 200,000 msat per MiB, the buyer releasing one ticket at a time and stopping after ten | 52,428,800 bytes: what ten tickets pay for, to the byte; 10,010 msat in routing fees | `fetch` |
| 2,000 lock requests against a cap of 6 sessions of 8 tickets (the caps before 2026-10-13) | 6 served, 1,994 refused, 48 invoices on the node | `flood` |
| A buyer that locks 8 tickets and releases none, limit set to 15 s (before 2026-10-13) | its tickets cancelled after 16 s | `flood` |
| A restart of the gateway with tickets locked | back in 0.05 s, the tickets still good | `restart` |
| A paid request over an unpaid one; one that carries a secret | 0.08 ms and 3.1 ms more (medians of 300 and 32) | `latency` |
| 2,000 lock requests against the shipped cap of 15 held tickets | 8 sessions served, 15 tickets issued, 1,992 answered `slots_short` with `retryAfter` 30; 15 invoices on the node | `flood` |
| A prepaid ticket through the hop, from the lock request to the signed credit | 0.21 s at the median, 0.26 s at most (10 tickets); nothing left pending on the channel 0.04 s after the payment | `prepaid` |
| The gateway given the channels macaroon, its config assuming 483 slots | cap 15, read from the node; no held ticket while 15 payments it did not issue are pending inwards | `slots` |
