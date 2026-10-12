# Lightning Stream

Pay for a service piece by piece, as it arrives, over XBT (Bitcoin on BLAKE2b proof of work).
Stop at any moment and nothing more is owed.

The aim: people who run Lightning nodes connect any service they want to offer to the network
(a file or media server, AI compute, storage, software of their own) and anyone pays them piece
by piece. That can be one buyer and one seller, as with a streamed film, or many sellers at
once, as in a torrent swarm or people lending hardware for AI.

**Lightning Stream is a streaming upgrade to Lightning.** It is built on ordinary XBT Lightning
channels, not beside them, and adds one thing: the **stream ticket**. A ticket is a small
Lightning payment that is locked along the route but not yet released. The buyer picks a secret
and gives the seller only its hash; the seller's node issues a hold invoice for that hash and the
buyer's node pays it. Nobody can take the money, because only the buyer knows the secret. To pay
for a request, the buyer puts the secret in the request; the seller checks it, serves, and
collects. A few tickets are locked before the service starts and topped up in the background, so
no request waits for a payment. Lightning's own routing carries tickets to any seller the
network reaches, with no change to the node software.

This direction was decided on 2026-10-11. **Tickets are half built**: the design was measured on
a three-node Lightning Fork regtest, and the seller's side (the gateway) is built and runs on
that regtest. The wallet's side is not built, so nothing can be bought with tickets yet. The
sections below say what exists today, what is being built, and what was retired.

Whitepaper: **<https://lazarus-xbt.xyz/stream/>**

Lightning Stream adds little of its own to a great deal of other people's work. What it is
built on and what came before it are under [Built on](#built-on) and [Prior art](#prior-art);
the full list, with a link for each, is [`docs/REFERENCES.md`](docs/REFERENCES.md).

> **Status: test networks only.** Everything here runs on XBT regtest. Do not use it with mainnet
> funds. It has had an internal security review and one external review, not an independent audit.
> The external review (October 2026) found critical and high-severity issues in the agent wallet's
> budget accounting, the hub, the pay-with-work audit and the HTTP layer. Six rounds of fixes are in
> this tree. Four follow-up audits of our own checked them: the first found 14 items (3 high), the
> second 20 (6 high), the third 23 (none high, 11 medium), the fourth 18 (none high, 9 medium).
> After the sixth round every finding is fixed or ends as a stated limit, and two items are open.
> A later run of failure paths through the release binaries found three more open items, all on
> the frozen on-chain channel. The hub has since been removed, and that removal has not been
> reviewed by anyone.
> **`docs/LIMITS.md` lists every stated limit, the open items, and what nobody has reviewed.**
> None of the fixes has been re-reviewed by anyone outside the project; an independent audit is
> planned.
>
> Conformance results in `docs/ENGINEERING.md` are measured against our own Python references:
> [Lightning-Stream-py-channel](https://github.com/AwokenLazarus/Lightning-Stream-py-channel) and
> [Lightning-Stream-py-wallet](https://github.com/AwokenLazarus/Lightning-Stream-py-wallet). The
> pay-with-work specification (XBT-053) and its vectors are not published yet. The channel scheme
> uses the x402 `batch-settlement` name with our own binding to XBT; upstream x402 clients cannot
> pay it.

## What exists today

- **The agent wallet and its policy engine.** An AI agent pays through the wallet over MCP and
  never holds a key. The owner sets a signed policy: budgets, per-seller caps, an allowlist, a
  threshold above which a human approves. Every signature goes into a tamper-evident log.
- **The Lightning rail.** The wallet pays XBT Lightning invoices (BOLT 11) and offers (BOLT 12)
  through the owner's Lightning node, under the same policy. This rail is what tickets are
  built on.
- **The seller gateway (regtest only).** `xbt-gateway` runs beside a seller's Lightning node in
  front of any HTTP service: it offers ticket terms in a 402, registers hold invoices for a
  buyer's hashes, settles a ticket when its secret arrives, meters the answer per request, per
  byte or per second, and signs a receipt. `scripts/gateway_regtest.sh` runs it on three
  Lightning Fork nodes with a test buyer; no wallet pays it yet.
- **The ticket book in the wallet's signer.** The buyer's side of stream tickets: secrets derived
  in the signer from a sealed seed, many tickets locked at once through the owner's node, each
  release written to disk as spent before its secret leaves, under an owner's policy with a
  budget for each task, an exposure cap, and small caps for sellers the owner has not named.
  `scripts/ticket_book_regtest.sh` runs it against Lightning Fork nodes on regtest. It is reached
  through the signer's socket; paying an HTTP request with it is not built yet.
- **The on-chain one-way channel (frozen).** A direct channel anchored on the chain, for paying
  one seller piece by piece: the buyer signs a slightly larger running total for each piece and
  the seller settles once. It is kept in the tree and tested, off the main path, with no new
  work. Its remaining case is a seller that cannot run a Lightning node. Whether it stays is
  decided after tickets run end to end.
- **Pay with work.** A miner pays for a service with pool shares, settled in the coinbase and
  checked by an audit.
- **Fair exchange.** Content that can be checked piece by piece is paid for only as it checks
  out: each chunk is bound by a Merkle proof, and the last one by a hash lock. Today this runs on
  the frozen channel.

## What is being built

Stream tickets. The ticket book in the wallet's signer and the seller gateway beside a Lightning
node are both built (above) and run on regtest. Next: the wallet's side of the HTTP 402 entry, so
that `xbt402_pay` pays a gateway; then the lottery for amounts smaller than a ticket.
The wire is written down as a draft in [`docs/TICKETS.md`](docs/TICKETS.md), and
`scripts/ln_ticket_regtest.sh` reproduces its measurements on four Lightning Fork nodes (31 checks).
Defaults in the design: 1,000-sat tickets, 8 in flight, a life of about 40 blocks. The buyer goes
first and can lose at most one ticket; for content that can be checked, the buyer checks a piece
before releasing its ticket.

A seller will need a Lightning node with inbound capacity, and a buyer a Lightning node with a
channel. `docs/LIMITS.md` states what the design gives up, what the wallet's ticket book does not
do and what the gateway does not do (the "Stream tickets" sections and "Seller gateway").

### Lottery tickets (in design)

Some pieces are worth less than the smallest payment worth sending: a routing node charges about
1 sat to carry any payment, and a piece of a shared file may be worth a tenth of a sat. For those,
buyer and seller roll a fair die for every piece. Most rolls pay nothing, a win pays a
normal-sized amount, and the odds are set so that the average is the exact price: at a tenth of
a sat a piece and a win of 64 sat, 1 roll in 640 wins. Neither side can steer a roll, because the
seller fixes its half before the session and the buyer sends its half after the piece arrived.
Income and cost are uneven in the short run and exact in the long run, as a miner's income is.
Paying by lottery is an old idea and not ours: David Wheeler (1996) and Ronald Rivest (1997).

There are two forms. In the first the buyer pays an ordinary invoice after a win: it is simple,
nothing is locked ahead, and a buyer that does not pay gets about one win's worth of service
free before the seller stops. In the second a win pays itself: the buyer locks one ticket with
the seller, each roll gives the seller a small chance of drawing its secret, and the buyer
cannot refuse. The aim of a win that enforces itself over Lightning is Paul Gerhart's, Jay
Taylor's and Sri Aravinda Krishnan Thyagarajan's ("Probabilistic Atomic Swaps for Bitcoin and
Friends", [arXiv:2605.04975](https://arxiv.org/abs/2605.04975), May 2026), who set it out and
built it first; our construction differs from theirs and, unlike theirs, has no formal
treatment. **Both forms are designed and were measured on a regtest lab. Neither is built
into the wallet or a seller.** The second rests on an argument that no cryptographer has
reviewed, and it will not be built until one has. `docs/LIMITS.md`, section "Lottery tickets
(in design)", states the limits; `docs/TICKETS.md` reserves a place for it on the wire and does
not specify it.

## What was retired

**The hub**, on 2026-10-11: the `xbt402-hub` service, routing between channels with adaptor
signatures, the hub's link to a Lightning node, and the routed client. It was this project's own
way for one channel to reach many sellers. Lightning's routing already does that, on a network
that exists, so the hub rebuilt part of Lightning beside it. The external review also found the
hub the weakest part of the tree. Its code, tests, scripts, vectors and packages are removed;
they are in the git history, last at commit `a548fb0`.

## Built on

- **Bitcoin Knots**, maintained by Luke Dashjr: XBT's node, and the source of the consensus
  rules this code follows. The BLAKE2b proof of work is Luke Dashjr's and the unified signature
  hash (`SIGHASH_UNIFIED`, flag 0x20) is Kyle Santiago's, both released in Knots 29.4.1. The
  signature-hash and retarget code here are ports of Knots' rules, and some vectors are copied
  from its tree (`THIRD_PARTY_NOTICES.md`).
- **Lightning Fork** by Paul Lamb ([paulscode/lightning-fork](https://github.com/paulscode/lightning-fork)),
  the fork of Lightning Labs' **lnd** that runs on XBT. The wallet's Lightning rail pays through
  it, and every ticket and lottery number in this tree was measured on it (tag
  `v0.21.3-beta-blake2b.17`), in the regtest lab the same author publishes
  ([paulscode/lightning-fork-lab](https://github.com/paulscode/lightning-fork-lab), commit `a5cadc5`).
  The other XBT Lightning implementation is the **Core Lightning fork** by PrivKey
  ([privkeyio/lightning](https://github.com/privkeyio/lightning)); we have not tested it.
- **electrs** by Roman Zeyde, the Electrum server the light chain backend talks to, and
  **libsecp256k1**, where all signing and verification runs.
- **x402** (created by Coinbase, kept by the x402 Foundation) for the HTTP 402 wire, and the
  **Model Context Protocol** (Anthropic; now the Agentic AI Foundation) for the agent's tools.
- **OCEAN's DATUM and TIDES**, which pay with work is built around.
- The Rust libraries in `THIRD_PARTY_NOTICES.md`, among them a vendored and patched **ureq**
  (Martin Algesten and Jacob Hoffman-Andrews).

## Prior art

Nothing in a stream ticket is a new mechanism. Each line names whose it is;
[`docs/REFERENCES.md`](docs/REFERENCES.md) has the references.

- **The ticket** is a hold invoice (Joost Jager, lnd, 2019) on a hash the buyer chose. Releasing
  a payment in a second step, by a key the payer holds back, is Hiroki Gondo's "stuckless
  payments" proposal of 2019, which uses point locks.
- **The on-chain channel** is Jeremy Spilman's one-way channel of 2013, in the
  `CHECKLOCKTIMEVERIFY` form BIP 65 describes. **Lightning** is Joseph Poon's and Tadge Dryja's.
- **The retired hub** used adaptor signatures (Andrew Poelstra's scriptless scripts; ECDSA
  adaptor signatures after Lloyd Fournier) in the shape of TumbleBit and A2L.
- **Paying over HTTP 402**: x402, and Lightning Labs' L402, which a seller that settles each
  ticket on arrival reproduces in ticket-sized units.
- **A wallet an app may spend from within limits**: Nostr Wallet Connect (NIP-47).
- **Paying by lottery**: Wheeler and Rivest; Micali and Rivest; Pass and shelat; Orchid and
  Livepeer on a chain; on Bitcoin, Dryja's 2016 slides and Kurbatov's "Emulating OP_RAND". **A
  win that enforces itself over Lightning**: Gerhart, Taylor and Thyagarajan, May 2026.
- **The first-piece credit** for content that can be checked is BitTorrent's optimistic unchoke.
- **The held payments tickets rely on** are what the channel-jamming defences proposed for
  Lightning (unconditional fees, hold fees, endorsement) are meant to price or limit.

Chris Guida's external review of the earlier design (October 2026) is why this is built on
Lightning: he found what we had missed, and said the hub was rebuilding Lightning beside it. The
credit for that is his; the mistakes that remain are ours.

## What is in the tree

A Rust workspace: the agent wallet that AI agents use over MCP, its Lightning rail, the frozen
on-chain channel, pay with work, and the services and packages around them.

| crate | what |
|---|---|
| `xbt-primitives` | XBT transactions, scripts, addresses, UnifiedSighash (0x21), strict ECDSA, BLAKE2b headers and proof of work |
| `xbt402` | the frozen on-chain channel: funding, signed states, close, rollover, refund, the HTTP 402 wire (x402 v2 `batch-settlement`), receipts, provider and payer |
| `xbt-signer` | the agent wallet's signer: keys never reach the agent (the owner can export a sealed backup); the owner's signed policy (budgets, per-seller caps, allowlist, human approval); a tamper-evident signature log; the Lightning rail (BOLT 11 and BOLT 12) |
| `xbt-wallet-mcp` | the wallet's MCP server, over stdio and streamable HTTP, so an AI agent can quote and pay without holding a key |
| `xbt-wallet-ui` | the owner's web UI: approvals, policy, channels, signature log |
| `xbt-electrum` | a light chain backend for the buyer's wallet (it watches the frozen channel): it checks headers, proof of work and Merkle proofs itself; "not there" is answered only when every configured server answered, and servers that all hide a transaction make it read as absent |
| `xbt-work`, `xbt-work-relay` | pay with work: a miner pays with pool shares, settled in the coinbase and checked by an audit |
| `xbt-gateway` | the stream-ticket seller gateway: a reverse proxy beside a Lightning node that puts a price per piece on any HTTP service (regtest only) |
| `xbt-svc` | container plumbing: data dir, secrets, readiness, the bounded HTTP server |
| `xbt402-interop` | conformance vectors and cross-implementation tools |

`packaging/` holds the Umbrel and StartOS apps of the wallet. `container/` and `docs/CONTAINER.md`
cover the images. `docs/ENGINEERING.md` has the design notes, conformance results and measurements
of the on-chain channel and the hub, as history. `docs/LIMITS.md` has the stated limits and open
items.

## Build

```bash
cargo test -j2 --workspace
cargo build --release -p xbt-signer -p xbt-wallet-mcp -p xbt-wallet-ui
```

Rust stable; libsecp256k1 is built from source. Cross builds (Linux x86_64, aarch64, armv7, riscv64,
macOS, Windows) use zig as the C compiler: see `docs/ENGINEERING.md`.

The regtest scripts in `scripts/` need a Bitcoin Knots 29.4.2 build for XBT (`XBT_BIN`), and the
cross-implementation ones also need the Python reference implementations (linked above; set
`XBT402_B1` and `XBT402_B2` to their checkouts).

## License

Licensed under either of

* Apache License, Version 2.0 (`LICENSE-APACHE`)
* MIT license (`LICENSE-MIT`)

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

Code, data and libraries from others, with their licences: `THIRD_PARTY_NOTICES.md`. Ideas,
designs and prior work: `docs/REFERENCES.md`.
