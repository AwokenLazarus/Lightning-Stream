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
buyer's node pays it. Nobody can take the money, because only the buyer knows the secret. To pay,
the buyer sends the seller the secret; the seller checks it, collects, and serves requests from
the balance that ticket makes. A few tickets are locked before the service starts and topped up in the background, so
no request waits for a payment. Lightning's own routing carries tickets to any seller the
network reaches, with no change to an lnd-family node: lnd and its forks, which have hold
invoices. Only one of them was run, Lightning Fork. **A Core Lightning node cannot be a seller's
node for held tickets today**: it has no hold-invoice call, neither published hold plugin fits
(one issues invoices without XBT's feature bit, the other keeps the secret on the seller's node),
nothing on it cancels a held ticket before the ticket expires, and the gateway speaks to
lnd-family nodes only. As a buyer's node or a routing node it needed nothing in the lab
([`docs/TICKETS.md`](docs/TICKETS.md), sections 8 and 11).

This direction was decided on 2026-10-11. **Tickets run end to end on regtest, and nowhere
else**: the design was measured on a three-node Lightning Fork regtest, the seller's side (the
gateway) and the wallet's side are built, and on that regtest an agent's one call to the wallet
buys a page, or a 100 MB file as it arrives, from a service behind the gateway. Nothing has run
on mainnet. The sections below say what exists today, what is being built, and what was retired
or removed.

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
> After the sixth round every finding was fixed or ended as a stated limit, with two items open.
> The hub was then removed, and in October 2026 the on-chain channel, which most of those findings
> were about: the findings on it, its stated limits and the open items on its path left the tree
> with it, and one open item remains, in the Python reference wallet. Neither removal has been
> reviewed by anyone.
> **`docs/LIMITS.md` lists every stated limit, the open items, and what nobody has reviewed.**
> None of the fixes has been re-reviewed by anyone outside the project; an independent audit is
> planned.
>
> Conformance results in `docs/ENGINEERING.md` are measured against our own Python references:
> [Lightning-Stream-py-channel](https://github.com/AwokenLazarus/Lightning-Stream-py-channel) and
> [Lightning-Stream-py-wallet](https://github.com/AwokenLazarus/Lightning-Stream-py-wallet). The
> pay-with-work specification (XBT-053) and its vectors are not published yet. Both Python
> repositories still hold the on-chain channel that this tree no longer has.

## What exists today

- **The agent wallet and its policy engine.** An AI agent pays through the wallet over MCP and
  never holds a key. The owner sets a signed policy: budgets, per-seller caps, an allowlist, a
  threshold above which a human approves a single payment (a ticket or lottery call is bounded
  by its task's budget and asks nobody). Every signature goes into a tamper-evident log.
- **The Lightning rail.** The wallet pays XBT Lightning invoices (BOLT 11) and offers (BOLT 12)
  through the owner's Lightning node, under the same policy. This rail is what tickets are
  built on.
- **The seller gateway (regtest only).** `xbt-gateway` runs beside a seller's Lightning node in
  front of any HTTP service: it offers ticket terms in a 402, registers hold invoices for a
  buyer's hashes, settles a ticket when its secret arrives, meters the answer per request, per
  byte or per second, and signs a receipt. `scripts/gateway_regtest.sh` runs it on three
  Lightning Fork nodes with a test buyer, and `scripts/ticket_e2e_regtest.sh` with the wallet as
  the buyer.
- **The ticket book in the wallet's signer.** The buyer's side of stream tickets: secrets derived
  in the signer from a sealed seed, many tickets locked at once through the owner's node, each
  release written to disk as spent before its secret leaves, under an owner's policy with a
  budget for each task, an exposure cap, and small caps for sellers the owner has not named.
  `scripts/ticket_book_regtest.sh` runs it against Lightning Fork nodes on regtest.
- **The wallet pays a gateway (regtest only).** The agent's ordinary `xbt402_pay` call chooses
  the rail: stream tickets where the seller offers them and the owner's policy allows them, and
  a single Lightning invoice where that is what the seller offers. For tickets the signer fetches the seller's terms itself, locks a pool, releases a
  ticket each time the balance with that seller runs out, reads the answer as it arrives, checks
  every receipt against its own count, and cancels what is left when the session stops.
  `scripts/ticket_e2e_regtest.sh` runs it through a routing hop with the release binaries and a
  stock file server behind the gateway, a lying seller and a kill of each part included.
- **The lottery, pay after a win (regtest only).** For pieces that cost less than a ticket and
  for paying many sellers at once. The gateway offers it beside tickets and the wallet's
  `xbt402_pay` chooses between them. Every piece is a draw the wallet's signer checks itself; a
  win is paid at once by an ordinary Lightning payment, booked before it leaves and paid once,
  and nothing is locked with any seller. `scripts/lottery_regtest.sh` runs it with the release
  binaries on channels of 30 slots: a 100 MB file bought by draws, 100 sellers paid at once, a
  buyer that never pays, a seller that lies about wins, and a kill of each part. The argument
  that the draw is fair is our own and unreviewed.
- **A demo: a film paid for as it plays (regtest only).** A stock Jellyfin behind the gateway,
  and a film bought piece by piece through the wallet while a player reads it (ffmpeg and a scripted HLS client): first
  frame in half a second, nothing paid while paused, the held tickets back when the viewer stops.
  The same file is then bought in 1,054 pieces from 20 gateways at once, paid by draws.
  `scripts/demo_film.sh` runs it; [`docs/DEMO.md`](docs/DEMO.md) is the guide for a node runner,
  with the numbers and what the demo does not show.
- **Pay with work.** A miner pays for a service with pool shares, settled in the coinbase and
  checked by an audit.

## What is being built

Stream tickets. The ticket book in the wallet's signer, the seller gateway beside a Lightning
node and the wallet's side of the HTTP 402 entry are built (above) and run on regtest, and so is
the lottery for amounts smaller than a ticket, in its first form (below). Next: a signed list of
what a seller sells, and packaging.
The wire is written down as a draft in [`docs/TICKETS.md`](docs/TICKETS.md), and
`scripts/ln_ticket_regtest.sh` reproduces its measurements on four Lightning Fork nodes (31 checks).
Defaults in the design: 1,000-sat tickets, 2 in flight, a life of about 40 blocks. The buyer goes
first and can lose at most one ticket; for content that can be checked, the buyer checks a piece
before releasing its ticket.

**Two limits shape those defaults** (set on 2026-10-12, after Kyle Santiago pointed them out). A held ticket takes one of a channel's slots for pending payments on every channel of its
route, and those slots are shared by everyone using the channel: 483 between Lightning Fork
nodes, 30 where either end is a Core Lightning node at its default (as commonly documented, lnd's
default is 483, Core Lightning's 30, LDK's 50 and eclair's 30). So a session holds 2 tickets,
not 8, and held tickets take at most half of a channel's slots: from one 30-slot channel a buyer
holds tickets with 7 sellers at once, or 15 at one ticket each. And a ticket below a channel's
dust limit (354 sat on Lightning Fork, 546 sat on Core Lightning) cannot be claimed on chain, so
a held ticket is never below 546 sat. Paying many sellers at once, as in a swarm, is therefore
the lottery's job (below): a win is paid at once and holds nothing. This was measured with the
XBT Core Lightning fork in the lab ([`docs/TICKETS.md`](docs/TICKETS.md), section 11). **The
wallet's ticket book and the gateway have these defaults and keep these rules since 2026-10-13**,
each as far as it can see. The wallet reads the slots and the dust limits of its own node's
channels before every lock, and holds less after a lock that finds no slot. The gateway keeps to
the numbers in its config (30 slots unless the runner says more); it reads its node's slots only
when the runner gives it a third, wider macaroon, and it never reads a dust limit. A seller at
its cap tells buyers to wait. Where no ticket can be
held, the wallet buys **prepaid tickets** one at a time: ordinary payments that are spent when
they are paid and hold nothing, which the gateway offers beside held tickets. The regtest scripts
run all of it on channels opened with 30 slots between Lightning Fork nodes; no Core Lightning
node is in their lab. An owner's policy written before that date means the new numbers where it
sets none ([`docs/LIMITS.md`](docs/LIMITS.md), "Stream tickets: the wallet's ticket book").

A seller will need an lnd-family Lightning node with inbound capacity (today that is a Lightning
Fork node: see the top of this page for why a Core Lightning node cannot hold tickets), and a
buyer a Lightning Fork node with a channel. `docs/LIMITS.md` states what the design gives up, and what the wallet's ticket book, its
payer and the gateway do not do (the "Stream tickets" sections and "Seller gateway").

### The lottery: amounts smaller than a ticket (built, its first form)

Some pieces are worth less than the smallest payment worth sending: a routing node charges about
1 sat to carry any payment, and a piece of a shared file may be worth a tenth of a sat. For those,
buyer and seller roll a fair die for every piece. Most rolls pay nothing, a win pays a
normal-sized amount, and the odds are set so that the expected payment is the exact price: at a
tenth of a sat a piece and a win of 64 sat, 1 roll in 640 wins. Neither side can steer a roll, because the
seller fixes its half before the session and the buyer sends its half after the piece arrived.
Income and cost are exact in expectation and uneven in any one run, as a miner's income is. How
uneven depends on the number of wins between one buyer and one seller: the spread is about 1
over the square root of the wins expected, so it takes about 68 wins (4,350 sat at 64-sat wins)
to be within 20% nine times in ten, and about 1,080 wins (69,000 sat) to be within 5%. A call
worth 10 sat, paid through a routing node where a win is 64 sat, pays nothing about 85% of the
time and 64 sat or more otherwise ([`docs/TICKETS.md`](docs/TICKETS.md), section 9, has the
arithmetic).
Paying by lottery is an old idea and not ours: David Wheeler (1996) and Ronald Rivest (1997).

**The first form is built: the buyer pays after a win.** It is the Wheeler and Rivest shape and
nothing newer: the seller commits to a hash chain, the buyer adds a random value after each
piece, and a hash of the two decides. It is not built on the 2026 paper named below and uses
none of its construction; that paper is cited for the second form only, which is not built. The
seller sends an ordinary Lightning
invoice with each win and the wallet pays it at once. Nothing is locked ahead, no channel slot is
held between wins, and a seller that leaves leaves nothing stuck. The gateway offers it beside
tickets for every route whose pieces cost less than a win, and the wallet chooses: tickets for a
piece worth a ticket or more and for a seller it stays with, draws for anything smaller and
whenever it pays more sellers than tickets can be held with. The wallet's signer works out every
draw itself and pays only a win it found, so neither a seller nor an agent can talk it into
paying one that is not. On regtest, with the shipped binaries on channels of 30 slots
(`scripts/lottery_regtest.sh`): a 100 MB file priced at a quarter of a sat a piece was bought by
draws, and what the buyer's node paid was the wins the wallet booked, to the millisat; 100
sellers were paid at once from one channel with no payment failed, at most 8 payments on their
way at a time. **What it does not do**: it does not make a buyer pay. A buyer that never pays
was served about one win's worth before the seller stopped it (measured: 0.8 to 1.4 wins' worth
on average at a quarter of a sat a piece), and a seller that earns less than one win from a buyer
can be paid nothing by a cheat. **The argument that the draw is fair is our own and nobody else
has reviewed it.** `docs/TICKETS.md`, section 9, is the wire; `docs/LIMITS.md`, "The lottery",
states the limits.

**The second form is designed and not built: a win that pays itself.** The buyer locks one
ticket with the seller, each roll gives the seller a small chance of drawing its secret, and the
buyer cannot refuse. The aim of a win that enforces itself over Lightning is Paul Gerhart's, Jay
Taylor's and Sri Aravinda Krishnan Thyagarajan's ("Probabilistic Atomic Swaps for Bitcoin and
Friends", [arXiv:2605.04975](https://arxiv.org/abs/2605.04975), May 2026), who set it out and
built it first; our construction differs from theirs and, unlike theirs, has no formal
treatment. It was measured on a regtest lab and rests on an argument that no cryptographer has
reviewed; it will not be built until one has (`docs/LIMITS.md`, "The win that pays itself").

## What was retired and removed

**The hub**, on 2026-10-11: the `xbt402-hub` service, routing between channels with adaptor
signatures, the hub's link to a Lightning node, and the routed client. It was this project's own
way for one channel to reach many sellers. Lightning's routing already does that, on a network
that exists, so the hub rebuilt part of Lightning beside it. The external review also found the
hub the weakest part of the tree. Its code, tests, scripts, vectors and packages are removed;
they are in the git history, last at commit `0911cc0`.

**The on-chain one-way channel**, frozen on 2026-10-11 and removed in October 2026. It was a
direct channel anchored on the chain for paying one seller piece by piece (x402's
`batch-settlement` name, with our own binding to XBT): the buyer signed a slightly larger running
total for each piece and the seller settled once. Tickets and the lottery do that job on
Lightning, and the channel carried the open defects that were left. With it went its provider
and library client, the wallet's channel rail, the light client that watched it
(`xbt-electrum`), the fair exchange built on its states (Merkle-proved chunks and a hash-locked
last one), and their tests, vectors and scripts. They are in the git history, last at commit
`1ad0c48`. Three things follow from the removal:

- A wallet that was upgraded with channels on record cannot close or refund them with this
  version. It leaves their records and sealed keys untouched and says which revision settles them.
- The wallet pays sellers over Lightning only. The Umbrel and StartOS packages do not wire a
  Lightning node into the wallet yet, so a packaged wallet can pay no seller for now.
- A seller that cannot run a Lightning node has no rail here; pay with work is the other way in.

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
  ([privkeyio/lightning](https://github.com/privkeyio/lightning)). We ran its release
  `v26.06.9-blake2b.7` in the lab as buyer, hop and seller to measure its limits
  ([`docs/TICKETS.md`](docs/TICKETS.md), section 11); the wallet and the gateway speak to
  Lightning Fork nodes only.
- **libsecp256k1**, where all signing and verification runs.
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
- **Lightning** is Joseph Poon's and Tadge Dryja's. **The removed on-chain channel** was Jeremy
  Spilman's one-way channel of 2013, in the `CHECKLOCKTIMEVERIFY` form BIP 65 describes; the
  light client that watched it spoke the Electrum protocol to **electrs** (Roman Zeyde).
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

A Rust workspace: the agent wallet that AI agents use over MCP, its Lightning rail, stream
tickets and the lottery on both sides, pay with work, and the services and packages around them.

| crate | what |
|---|---|
| `xbt-primitives` | XBT transactions, scripts, addresses, UnifiedSighash (0x21), strict ECDSA, BLAKE2b headers and proof of work |
| `xbt402` | what the paid-HTTP schemes share: the x402 v2 headers and the request binding, the stream-ticket and lottery wires, and the server and payer that pay with work plugs into |
| `xbt-signer` | the agent wallet's signer: keys never reach the agent (the owner can export a sealed backup); the owner's signed policy (budgets, per-seller caps, allowlist, human approval); a tamper-evident signature log; the Lightning rail (BOLT 11 and BOLT 12); the ticket book and the payer that lets `xbt402_pay` pay a gateway with stream tickets (regtest only) |
| `xbt-wallet-mcp` | the wallet's MCP server, over stdio and streamable HTTP, so an AI agent can quote and pay without holding a key |
| `xbt-wallet-ui` | the owner's web UI: approvals, policy, keys, signature log |
| `xbt-work`, `xbt-work-relay` | pay with work: a miner pays with pool shares, settled in the coinbase and checked by an audit |
| `xbt-gateway` | the stream-ticket seller gateway: a reverse proxy beside a Lightning node that puts a price per piece on any HTTP service (regtest only) |
| `xbt-svc` | container plumbing: data dir, secrets, readiness, the bounded HTTP server |

`packaging/` holds the Umbrel and StartOS apps of the wallet. `container/` and `docs/CONTAINER.md`
cover the images. `docs/ENGINEERING.md` has the design notes, conformance results and measurements
of the on-chain channel and the hub, as history: most of what it names is no longer in the tree.
`docs/LIMITS.md` has the stated limits and open items. `reports/` holds the reports the regtest
scripts wrote on their latest runs, as they were written: our own runs, on one host
(`reports/README.md`).

## Build

```bash
cargo test -j2 --workspace
cargo build --release -p xbt-signer -p xbt-wallet-mcp -p xbt-wallet-ui
```

Rust stable; libsecp256k1 is built from source. The workspace builds, tests and passes clippy on
Rust 1.98.0, which is what `.github/workflows/ci.yml` runs on every push and pull request, and
builds, tests and passes clippy on 1.91.1. The minimum stated in `Cargo.toml` is 1.90: the locked
`ruint` 1.20.1 declares it, the highest of any locked package (the code itself needs 1.89). No
toolchain older than 1.91.1 was run. Cross builds (Linux x86_64, aarch64, armv7, riscv64,
macOS, Windows) use zig as the C compiler: see `docs/ENGINEERING.md`.

What each script needs beyond this repository:

| Scripts | Need | Can someone outside the project run them? |
|---|---|---|
| The Lightning regtest scripts: `ln_ticket_regtest.sh`, `gateway_regtest.sh`, `ticket_book_regtest.sh`, `ticket_e2e_regtest.sh`, `lottery_regtest.sh`, `ln_rail_regtest.sh`, `demo_film.sh` | Docker with compose and python3 (the demo also ffmpeg). They fetch and build the Lightning Fork lab under `run/` | Yes. The reports of our latest runs are in `reports/` |
| `container_test.sh`, `ui/regtest_ui.sh` | A Bitcoin Knots 29.4.2 build for XBT (`XBT_BIN`), Docker | Yes, with that build |
| `mcp/verify_agp030.sh`, `ui/regtest_ui.sh`, the vector generators (`gen_*.py`) | The Python references linked above, at the paths their headers name (`B2_TREE`, `XBT402_B1`); `gen_unified_sighash_ext.py` needs a Knots source tree instead | Yes |
| The cross builds: `build_matrix.sh`, `oci_build.sh`, `cmp_clean_build.sh`, `work_matrix.sh` | zig as the C compiler, from the `ziglang` Python wheel in a virtual environment (`XBT_ZIG_PY`; no version of it is pinned in this tree). `cmp_clean_build.sh` also needs cargo-zigbuild 0.23.4 | Yes |
| The pay-with-work scripts: `work_conformance.sh`, `work_interop.sh`, `work_nta.sh`, `relay_container_test.sh` | The pay-with-work specification tree (XBT-053) and a pool server (`primed`) built from a branch that is not published; `work_nta.sh` also calls a helper of the machine it was written on, and goes on without it | **No.** Nothing they report can be reproduced outside the project until those are published |
| `tools/lazarus-crosscheck` (headers and proof of work against the pool's own Rust) | A checkout of [AwokenLazarus/Bitcoin](https://github.com/AwokenLazarus/Bitcoin) at a fixed place outside this repository: `../../Bitcoin` seen from this repository's root, two directories up. It is not a workspace member, so the workspace builds and tests without it | Yes, with that checkout in that place |

Several scripts have defaults that point into the directory layout of the machine they were
written on (`$HOME/xbt-rnd/...`); each takes the path from an environment variable its header
names.

## License

Licensed under either of

* Apache License, Version 2.0 (`LICENSE-APACHE`)
* MIT license (`LICENSE-MIT`)

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

Code, data and libraries from others, with their licences: `THIRD_PARTY_NOTICES.md`. Ideas,
designs and prior work: `docs/REFERENCES.md`.
