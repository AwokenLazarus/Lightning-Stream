# Lightning Stream

Pay for a service piece by piece, as it arrives, over XBT (Bitcoin on BLAKE2b proof of work).
Lock coins once in a payment channel. For each piece delivered, the buyer signs a slightly larger
running total. The seller settles once, for the last total. Stop at any moment and nothing more is owed.

Lightning Stream works beside Lightning, not inside it. A Stream channel is a direct, one-way
channel anchored on the chain, for paying one seller piece by piece; it is not a Lightning channel
and Lightning nodes do not route it. The two meet in two places. The agent wallet here pays over
both under one owner policy: XBT Lightning invoices (BOLT 11) and offers (BOLT 12) through the
owner's Lightning node, and Stream channels. And a hub, the way one channel reaches many sellers,
is meant to run beside a Lightning node (planned; hubs are experimental). A Stream channel is not
opened, funded or closed over Lightning and does not pay Lightning invoices: carrying it over
Lightning would give up paying per piece or "stop any time and the rest is never paid". The
whitepaper's section "Beside Lightning" has the reasons.

Whitepaper: **<https://lazarus-xbt.xyz/stream/>**

> **Status: test networks only.** Everything here runs on XBT regtest. Do not use it with mainnet
> funds. It has had an internal security review and one external review, not an independent audit.
> The external review (October 2026) found critical and high-severity issues in the agent wallet's
> budget accounting, the hub, the pay-with-work audit and the HTTP layer. Six rounds of fixes are in
> this tree. Four follow-up audits of our own checked them: the first found 14 items (3 high), the
> second 20 (6 high), the third 23 (none high, 11 medium), the fourth 18 (none high, 9 medium).
> After the sixth round every finding is fixed or ends as a stated limit, and two items are open.
> **`docs/LIMITS.md` lists every stated limit, the open items, and what nobody has reviewed.**
> None of the fixes has been re-reviewed by anyone outside the project; an independent audit is
> planned. Hub routing (`xbt402-hub`) is experimental.
>
> Conformance results in `docs/ENGINEERING.md` are measured against our own Python references:
> [Lightning-Stream-py-channel](https://github.com/AwokenLazarus/Lightning-Stream-py-channel) and
> [Lightning-Stream-py-wallet](https://github.com/AwokenLazarus/Lightning-Stream-py-wallet). The
> pay-with-work specification (XBT-053) and its vectors are not published yet. The channel scheme
> uses the x402 `batch-settlement` name with our own binding to XBT; upstream x402 clients cannot
> pay it.

## What is here

A Rust workspace: the channel protocol, an agent wallet that AI agents use over MCP, and the services
and packages around them.

| crate | what |
|---|---|
| `xbt-primitives` | XBT transactions, scripts, addresses, UnifiedSighash (0x21), strict ECDSA, BLAKE2b headers and proof of work |
| `xbt402` | the Stream channel: funding, signed states, close, rollover, refund, the HTTP 402 wire (x402 v2 `batch-settlement`), receipts, provider and payer, hub routing with adaptor signatures (`xbt402-hub`) |
| `xbt-signer` | the agent wallet's signer: keys never reach the agent (the owner can export a sealed backup); the owner's signed policy (budgets, per-seller caps, allowlist, human approval); a tamper-evident signature log; an optional Lightning rail |
| `xbt-wallet-mcp` | the wallet's MCP server, over stdio and streamable HTTP, so an AI agent can quote and pay without holding a key |
| `xbt-wallet-ui` | the owner's web UI: approvals, policy, channels, signature log |
| `xbt-electrum` | a light chain backend for the buyer's wallet: it checks headers, proof of work and Merkle proofs itself; "not there" is answered only when every configured server answered, and servers that all hide a transaction make it read as absent |
| `xbt-work`, `xbt-work-relay` | pay with work: a miner pays with pool shares, settled in the coinbase and checked by an audit |
| `xbt-svc` | container plumbing: data dir, secrets, readiness |
| `xbt402-interop` | conformance vectors and cross-implementation tools |

`packaging/` holds the Umbrel and StartOS apps. `container/` and `docs/CONTAINER.md` cover the
images. `docs/ENGINEERING.md` has the detailed design notes, conformance results and measurements.
`docs/LIMITS.md` has the stated limits and open items.

## Build

```bash
cargo test -j2 --workspace
cargo build --release -p xbt-signer -p xbt-wallet-mcp -p xbt402
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
