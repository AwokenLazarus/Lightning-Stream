# Lightning Stream

Buy and sell services over XBT Lightning, paid piece by piece as they arrive: a film by the
megabyte, an AI model by the token, a miner's hashrate by the slice of work. XBT is Bitcoin on
BLAKE2b proof of work.

The buyer pays a small ticket ahead (about 900 sats), the seller counts what it delivers to the
millisatoshi and signs a receipt for every answer, and the buyer can lose no more than one ticket.
It runs on ordinary XBT Lightning nodes. Lightning Stream never holds anyone's money: each person
pays from, and is paid to, their own node.

- **Website and setup:** <https://lazarus-xbt.xyz/stream/start/>
- **Whitepaper:** <https://lazarus-xbt.xyz/stream/>
- **What changed in each version:** [`CHANGELOG.md`](CHANGELOG.md), also at
  <https://lazarus-xbt.xyz/stream/changelog/>
- **Bugs and confusing screens:** [issues](https://github.com/AwokenLazarus/Lightning-Stream/issues)

> **Status.** Released for Umbrel, StartOS and Linux, and tested on XBT mainnet between our own
> nodes with small amounts. It has had design and code reviews, not an independent audit. Use
> amounts you can afford to lose. [`docs/LIMITS.md`](docs/LIMITS.md) lists every stated limit and
> what nobody has reviewed.

## Install

You need a synced Knots-BLAKE2b node (a first sync takes days, and Lightning Fork waits until block
961,640), Lightning Fork beside it, and a small channel on XBT Lightning.

- **Umbrel:** add the community store
  [AwokenLazarus/lightning-stream-umbrel-store](https://github.com/AwokenLazarus/lightning-stream-umbrel-store)
  and install Lightning Stream. Knots-BLAKE2b and Lightning Fork come from Paul's store.
- **StartOS:** add our registry `https://registry.lazarus-xbt.xyz` and install Lightning Stream,
  with Lightning Fork from Paul's registry; then approve Lightning Fork's *Grant app access* task.
  See [`docs/STARTOS.md`](docs/STARTOS.md).
- **Linux:** Docker Compose beside your own nodes: [`docs/LINUX.md`](docs/LINUX.md).

Then, in the app: make your approval key, sign the safe starter rules, confirm **Pay with real
money**, and allow a seller. Our test shop is `https://stream.lazarus-xbt.xyz`. The
[setup page](https://lazarus-xbt.xyz/stream/start/) has each step, and how to get a channel.

## What it does

- **Buy.** Browse sellers' signed listings (published on Nostr relays), play films as they arrive,
  ask an AI model, or rent hashrate. Every payment stays within spending rules the owner signs:
  budgets, caps per seller, allowed sellers only, and an approval above a threshold.
- **Sell.** Put a price on the services already on your box (a media server, an AI model, any web
  service). A gateway answers buyers with HTTP 402 and its terms, meters each answer per request,
  byte, token or second, and signs a receipt.
- **Rent hashrate.** A *hashmaker* lists its miners and a *hashtaker* rents them into its own
  DATUM Gateway, paying for each slice of work after it is delivered. Only shares the hashtaker's
  own gateway accepted are counted. ([`docs/P2P-HASH.md`](docs/P2P-HASH.md))
- **Agents.** An AI agent pays through the same wallet over MCP and never holds a key.
- **A local AI address.** The app gives the box an OpenAI-compatible address on the owner's network.
  Any AI app or agent that speaks that API uses the sellers' models through it, paid per token, each
  program with its own key and limit. It picks the cheapest seller that answers and moves on if one
  fails before answering. ([`docs/INFERENCE.md`](docs/INFERENCE.md))

## How it works

A **ticket** is an ordinary Lightning payment. A *prepaid* ticket is collected by the seller as it
arrives, and the seller serves from that credit. A *held* ticket uses a hold invoice on a hash
the buyer chose, so the payment sits committed along the route until the buyer releases the
secret. Unused held tickets come back. For pieces too small to pay one by one, a **lottery**
decides which pieces are paid, so the price is exact on average. The wire is written down in
[`docs/TICKETS.md`](docs/TICKETS.md); the whitepaper explains the idea and its costs.

## What is in the tree

| crate | what |
|---|---|
| `xbt-primitives` | XBT transactions, scripts, addresses, UnifiedSighash, strict ECDSA, BLAKE2b headers and proof of work |
| `xbt402` | the paid-HTTP wires: x402 v2 headers and request binding, stream tickets and the lottery |
| `xbt-signer` | the wallet's signer: keys, the owner's signed spending rules, a tamper-evident signature log, the Lightning rail (BOLT 11 and 12), the ticket book and the payer |
| `xbt-wallet-ui` | the app: Services, Sell, Wallet, Apps & agents and Settings |
| `xbt-wallet-mcp` | the wallet's MCP server, so an AI agent can quote and pay without holding a key |
| `lightning-stream` | the connector: hands a paid answer to a local player as it is paid for, and serves the local AI address, holding no keys |
| `xbt-gateway` | the seller's gateway beside a Lightning node, in front of any HTTP service |
| `xbt-hashlink` | rented hashrate: the encrypted link between hashmaker and hashtaker, the Stratum relay, the work meter and listings |
| `xbt-nostr` | Nostr events, relays and sellers' signed listings ([`docs/NOSTR.md`](docs/NOSTR.md)) |
| `xbt-nwc` | Nostr Wallet Connect on the service side ([`docs/NWC.md`](docs/NWC.md)) |
| `xbt-work`, `xbt-work-relay` | pay with work: a miner pays with pool shares, settled in the coinbase |
| `xbt-svc` | container plumbing |

`packaging/` holds the Umbrel, StartOS and Linux packages ([`packaging/README.md`](packaging/README.md)).
The images are published on GitHub's container registry and pinned by digest. `docs/TESTING.md`
is the guide for running the regtest labs yourself, and `reports/` holds our latest lab reports.

## Build

On Ubuntu 24.04, with git, `build-essential` and Rust stable from <https://rustup.rs>:

```bash
git clone https://github.com/AwokenLazarus/Lightning-Stream.git && cd Lightning-Stream
ulimit -n 4096    # the tests open many loopback connections at once
cargo test -j2 --workspace --locked
cargo build --release -p xbt-signer -p xbt-wallet-mcp -p xbt-wallet-ui
```

CI builds, tests and runs clippy on Rust 1.98.0 on every push; the minimum is 1.90. The regtest
lab scripts in `scripts/` need Docker and python3 and fetch the rest themselves. Cross builds and
the scripts that need more are described in [`docs/ENGINEERING.md`](docs/ENGINEERING.md) and
[`docs/TESTING.md`](docs/TESTING.md).

## Credits

Lightning Stream is a small addition to other people's work. XBT runs on Bitcoin Knots, maintained
by Luke Dashjr, who wrote the BLAKE2b proof of work; the signature hash that keeps a payment from
being replayed on the SHA-256 chain is Kyle Santiago's. Lightning on XBT is Paul Lamb's Lightning
Fork, a fork of Lightning Labs' lnd, and PrivKey's Core Lightning fork. Paul also packages
Knots-BLAKE2b and Lightning Fork for Umbrel and StartOS, and built the access grant the StartOS
package uses. Hashrate rental is built around OCEAN's DATUM.

Chris Guida's two reviews are why Lightning Stream is built on Lightning, and they narrowed what it
claims. Kyle Santiago pointed out the slot and dust limits the ticket defaults are built around.
Kilombino named the hashmaker and the hashtaker and runs a relay the app uses. The mistakes that
remain are ours. Ideas and prior work, with references: [`docs/REFERENCES.md`](docs/REFERENCES.md).
Code and libraries from others: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## License

Licensed under either of the Apache License, Version 2.0 (`LICENSE-APACHE`) or the MIT license
(`LICENSE-MIT`), at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
