# Lightning Stream

Pay for a service piece by piece, as it arrives, over XBT (Bitcoin on BLAKE2b proof of work).
Stop at any moment and nothing more is owed.

**Lightning Stream is a streaming upgrade to Lightning.** It is built on ordinary XBT Lightning
channels, not beside them, and adds one thing: the **stream ticket**. A ticket is a small
Lightning payment that is locked along the route but not yet released. The buyer picks a secret
and gives the seller only its hash; the seller's node issues a hold invoice for that hash and the
buyer's node pays it. Nobody can take the money, because only the buyer knows the secret. To pay
for a request, the buyer puts the secret in the request; the seller checks it, serves, and
collects. A few tickets are locked before the service starts and topped up in the background, so
no request waits for a payment. Lightning's own routing carries tickets to any seller the
network reaches, with no change to the node software.

This direction was decided on 2026-10-11. **Tickets are in design, not built**: the design was
measured on a three-node Lightning Fork regtest, and none of it is in the wallet or in a seller
yet. The sections below say what exists today, what is being built, and what was retired.

Whitepaper: **<https://lazarus-xbt.xyz/stream/>**

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
  through the owner's Lightning node, under the same policy. This rail is what tickets will be
  built on.
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

Stream tickets, in this order: the ticket book in the wallet's signer (secrets derived in the
signer, many tickets in flight, each booked when it is locked and when its secret leaves); the
seller component beside a Lightning node (registers the buyer's hashes, serves on a good secret,
settles on use, cancels what is left); and the HTTP 402 entry that offers tickets to a buyer.
The wire is written down as a draft in [`docs/TICKETS.md`](docs/TICKETS.md), and
`scripts/ln_ticket_regtest.sh` reproduces its measurements on four Lightning Fork nodes (31 checks).
Defaults in the design: 1,000-sat tickets, 8 in flight, a life of about 40 blocks. The buyer goes
first and can lose at most one ticket; for content that can be checked, the buyer checks a piece
before releasing its ticket.

A seller will need a Lightning node with inbound capacity, and a buyer a Lightning node with a
channel. `docs/LIMITS.md`, section "Stream tickets (in design)", states what the design gives up.

## What was retired

**The hub**, on 2026-10-11: the `xbt402-hub` service, routing between channels with adaptor
signatures, the hub's link to a Lightning node, and the routed client. It was this project's own
way for one channel to reach many sellers. Lightning's routing already does that, on a network
that exists, so the hub rebuilt part of Lightning beside it. The external review also found the
hub the weakest part of the tree. Its code, tests, scripts, vectors and packages are removed;
they are in the git history, last at commit `a548fb0`.

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
| `xbt-svc` | container plumbing: data dir, secrets, readiness |
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

Code, data and libraries from others, with their licences: `THIRD_PARTY_NOTICES.md`.
