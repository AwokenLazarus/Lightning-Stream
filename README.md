# xbt-rs

Rust rails for XBT (Bitcoin with BLAKE2b proof of work): a shared chain-primitives crate and the
xbt402 payment-channel crate (the x402 v2 scheme `xbt-channel`, spec v1.1 plus the v1.2
`closeFeePayer` additions). It ports the Python references and is byte-identical to them. Built for
xbt-compute's Rust device runtime (AGP-025, owned by xbt-agentpay).

Local repo, no remote. Workspace crates:

| crate | what | published |
|---|---|---|
| `xbt-primitives` | tx (de)serialization with witness, scripts, bech32/bech32m per chain, UnifiedSighash 0x21/0xA3, strict-DER low-S ECDSA (libsecp256k1), BLAKE2b header v2 + PoW + Knots retarget + most-work header chain, network ids | library (for other projects too) |
| `xbt402` | channel params, payee tweak v2, funding script, states, close, rollover, refund, v1.2 payee-pays, conditional hash locks, the 402 wire, receipts, request auth, provider verifier, payer client, ledger; the signer seam (`StateSigner` + the routing extension `RouteSigner`); hub routing (AGP-026): ECDSA adaptor locks, provider route offers, `RouteHub` + the `xbt402-hub` service, `RoutePayer` | library (+ `xbt402-hub` bin) |
| `xbt-signer` | B2's agent-wallet signer (AGP-027): keys never in the client (xbt402 `StateSigner` and `RouteSigner`), B2's policy engine and routing policy, sealed hot/channel keys, write-ahead opens, refund custody, anchored signature log; B2's socket protocol and file formats. See `crates/xbt-signer/README.md` | binaries `xbt-signer`, `xbt-anchor-witness`, `xbt-signer-payer` |
| `xbt402` | channel params, payee tweak v2, funding script, states, close, rollover, refund, v1.2 payee-pays, conditional hash locks, the 402 wire, receipts, request auth, provider verifier, payer client, ledger | library |
| `xbt-wallet-mcp` | the agent wallet's MCP server (AGP-030): B2's ten tools (same names, schemas, validation, results and errors as `mcp_server.py`) over stdio and streamable HTTP, talking only to the B2 signer socket (Rust or Python signer), optional in-process xbt402 payer with keys in the signer. See `crates/xbt-wallet-mcp/README.md` (Claude Code, Hermes, OpenClaw config) | binary `xbt-wallet-mcp` |
| `xbt-electrum` | the light chain backend: Electrum servers (TCP/TLS, batching, several servers) checked against our own `HeaderChain` and Merkle proofs; `xbt402::ChainBackend`, a typed API, and the node-RPC surface of the client path | library |
| `xbt402-interop` | conformance suite, Rust→JSON vector emitter, regtest cross-implementation tools | no (`publish = false`) |

References (read-only): B1 `agp-029` `a7c3521` (`~/xbt-rnd/b1-agp-029`, `xbt402/`; AGP-023 `f105ccc` plus the AGP-029 close report), B2 `agp-next2`
`04c3f56` (`~/xbt-rnd/b2`, `agentwallet/headers.py`), and `lazarus-protocol` (`~/Bitcoin/lazarus/protocol`).

## Build and verify

```bash
cargo test -j2 --workspace
cargo build -j2 --release --target aarch64-unknown-linux-gnu -p xbt402
./scripts/conformance.sh           # N/N byte-identical, both directions
./scripts/regtest_interop.sh       # Rust <-> Python on a private Knots 29.4.2 regtest node
./scripts/signer_interop.sh        # AGP-027: the AGP-017 runbook with the Rust signer behind B2's MCP, + a Rust payer
./scripts/route_interop.sh         # routed: every client x hub x provider (Rust/Python), the all-Rust demo, + a Rust payer on the Rust signer
cargo run --release -p xbt402 --example adaptor_bench
./scripts/build_matrix.sh          # every AGP-031 target; writes dist/MATRIX.md
./scripts/electrum_interop.sh      # the light Rust payer on real electrs (tcp + TLS) vs the Python provider
cargo test -j2 -p xbt402 --no-default-features --test cmp_surface   # AGP-035: what cmp links, no features
./scripts/cmp_clean_build.sh [REF] # AGP-035: clean clone, no .cargo, cargo-zigbuild, x86_64/aarch64/armv7 musl
scripts/cmp_keys_ecdsa.py          # AGP-035: xbt_primitives::ecdsa vs cmp/keys.py, byte for byte
cargo test -j2 --manifest-path tools/lazarus-crosscheck/Cargo.toml  # header/PoW vs the pool's lazarus-protocol
```

Run heavy work under a CPU and memory cap:
`systemd-run --user --scope -p CPUQuota=200% -p MemoryMax=4G nice -n 19 ...` (the scripts do).

**Cross builds (AGP-031).** There is no system cross toolchain on the build host, so zig is the C
compiler (libsecp256k1) and the rustc linker. Set it up once with
`python3 -m venv ~/.local/share/ziglang-venv && ~/.local/share/ziglang-venv/bin/pip install ziglang`.
`.cargo/config.toml` points every non-host target at `tools/zig-cc` (GNU/Linux glibc floor 2.28;
musl targets are statically linked). `scripts/build_matrix.sh` builds `xbt-primitives`, `xbt402`
and the offline `selftest` example in `release` and `release-small` (opt-level `z`, fat LTO) for
x86_64/aarch64/armv7/riscv64 Linux (glibc + static musl), macOS x86_64/arm64, and Windows x86_64,
and writes sizes plus status to `dist/MATRIX.md`. The self-test is executed on the host for
x86_64; other arches need a user-mode emulator already on PATH (the script never installs
binfmt/qemu).

Dependencies: `secp256k1` 0.29 (libsecp256k1, the global context), `sha2`, `ripemd`, `blake2`,
`hmac`, `ruint` (256-bit targets and work), `serde_json` with `preserve_order` (never
`arbitrary_precision`, AGP-035), `base64`, `thiserror`,
`getrandom`, `indexmap`. Optional: `ureq` (features `http-client`, `rpc`) and `tiny_http` (`http-server`).
std only; no_std isn't a goal.

## API overview

### xbt-primitives

```rust
use xbt_primitives::{tx::Tx, sighash::*, ecdsa, header, address, network};

let tx = Tx::parse_hex(hex)?;                          // strict: no trailing bytes, bounded allocations
let msg = unified_sighash(&tx, &prevouts, 0, ScriptType::WitnessV0, &script, SIGHASH_ALL_UNIFIED, None)?;
let sig = ecdsa::sign(&sk, &msg);                       // RFC 6979, low S, DER (no hash-type byte)
assert!(ecdsa::verify(&pubkey, &msg, &sig));            // BIP66 strict DER + low S, never panics
let addr = address::segwit_address(network::Chain::Regtest.hrp(), &spk)?;   // bech32 v0 / bech32m v1+
let h = header::parse_header(&raw164)?;                 // BLAKE2b v2: hash, committed height, time
let mut chain = header::HeaderChain::with_system_clock("main", header::MAINNET_CHECKPOINT, Some(path))?;
chain.set_checkpoint(&cp_raw)?;
chain.connect(fork_height, &raws)?;                     // most work wins; every Knots rule checked
let net = network::network_id(&block_961640_hash);      // "bip122:0000000000000050c1e5f69672f45929"
```

Modules: `tx` (OutPoint, TxIn, TxOut, Tx, txid, vsize), `script` (push, script_num, p2wpkh/p2wsh/p2tr
spk, classify), `address` (bech32/bech32m, hrp check), `sighash` (UnifiedSighash, BIP143),
`ecdsa` (sign, verify, is_strict_der, ecdh_x, tweaks), `header` (v2 stages, bits/targets/work, check_pow,
ChainRules with the retarget, HeaderChain, merkle proofs with the txcount bound, blocks), `network`
(Chain, hrp, anchors, network ids), `amount`, `hash`, `encode`.

### xbt402

```rust
use xbt402::{channel::*, provider::*, client::*, ledger::Ledger};

// provider (resource server): transport-independent
let prov = Provider::new(chain_backend, pay_to_secret, ProviderConfig::new(&network), Ledger::open(path)?,
                         Box::new(|_method, _path| 150), Box::new(|m, p, body| my_api(m, p, body)))?;
let resp = prov.serve(method, path, &headers, &body, &url, None);   // 402s, open/close/rollover, paid calls
prov.close_due()?;                                                  // watcher tick (every block)

// payer
let mut client = Client::new(ClientConfig::new(&network), Box::new(UreqTransport::default()),
                             Box::new(my_wallet), Box::new(move || node.block_count()));
let r = client.request("POST", "https://api.example/v1/infer", body)?;   // opens on the first 402
let (r, plaintext) = client.request_conditional("GET", "https://api.example/v1/report", b"")?;
client.rollover(origin)?; /* mine */ client.open_rolled(origin)?;
client.close(origin)?;
```

* `channel`: `ChannelParams` (`derive`, `state_tx`, `state_tx_a3`, `rollover_tx`, `refund_tx`,
  `sighash`, `min_amount`/`max_amount`/`payee_value`, `close_fee_payer`, `to_json`/`from_json` in the
  reference's `to_dict` format), `Payer`, `Payee`, `channel_payee_pub`/`secret` (the tweak v2),
  `channel_auth_key` (ECDH), `settle_due`, `sign_p2wpkh`, `cpfp_child`, `canonical_chan`.
* `conditional`: `ConditionalParams` (hash-lock state, claim), `encrypt`/`decrypt`, `preimage_from_tx`.
* `wire`: `b64json`/`unb64json`, `request_digest`, `request_auth`, `receipt_message`, `close_message`,
  `settlement_response`, `receipt_of`, `facilitator_request`, `upstream_code`, and typed serde views
  (`PaymentRequired`, `PaymentRequirements`, `ChannelExtra`, `SchemePayload`, `Receipt`,
  `SettlementResponse`, `VerifyResponse`, `SupportedResponse`, `OpenChannel`, `OpenResponse`, `CloseResponse`).
* `provider`: `Provider` (serve, open, close, rollover, facilitator verify/settle/supported, terms,
  offer_conditional, close_due, sweep_payee), `ProviderConfig`.
* `client`: `Client`, `ClientConfig`, and the two hooks the application supplies: `Transport` and `Wallet`;
  optionally a `ClientLedger` for the channel book (`Client::with_ledger`, `FileClientLedger`,
  `MemoryClientLedger`; AGP-035).
* `funding`: `ChainBackend` (the four node calls), `FundingPolicy`, `check_funding`.
* `ledger`: `ChannelState`, `Ledger` (in memory, or an fsynced append-only JSONL file).
* `json`: JSON written byte-exactly as Python's `json.dumps`, which the wire headers need, and read
  losslessly by `json::parse` (integers of any size, correctly rounded floats; see below).
* Features: `http-client` (`http::UreqTransport`), `http-server` (`http::serve_http`), `rpc`
  (`rpc::Rpc`: bitcoind JSON-RPC as `ChainBackend` and `Wallet`). cmp can bring its own transport.

Errors are `ChannelError { code, msg }` (`thiserror`). `code` is the wire error code
(`bad_sig`, `bad_amount`, `stale_amount`, `bad_auth`, ...). The library does not panic on
untrusted input: parsers and the provider are fuzzed with hostile bytes and JSON in the tests.

## Conformance statement

`scripts/conformance.sh` (2026-09-28):

| group | vectors | source | result |
|---|---|---|---|
| xbt402 v1.1 + v1.2 (counted as `check_vectors.py` counts them) | 50 | B1 agp-029 `docs/x402/vectors.json` | 50/50 byte-identical |
| UnifiedSighash (Knots hf-sighash-opt-in reference) | 166 | B1 `tests/data/unified_sighash.json` | 166/166 |
| BLAKE2b header v2, every hash stage | 5 | B2 `tests/vectors/block_header_v2.json` | 5/5 |
| Knots BLAKE2b regtest capture: 24 headers across v1/v2, 3 blocks' merkle roots, a header chain | 28 | B2 `tests/vectors/blake2b_regtest.json` | 28/28 |
| **total** | **249** | | **249/249** |

It works in both directions:

* Rust → reference. The Rust emitter (`xbt402-vectors`) rebuilds the whole xbt402 vector file with
  the Rust crates, the Rust provider serving every round trip (402, open, 5 paid calls, replay,
  facilitator, close, settle, the conditional sale and its claim, the v1.2 section). Any difference
  from the published file is charged to the vector it belongs to. The generator-independent checks
  of `check_vectors.py`, ported to Rust, run over the published values: refusal codes, which key
  signed what, receipts, script layouts.
* Reference → Rust. B1's `check_vectors.py` checks the Rust-emitted file: `diff(python_generate(), rust)`
  plus `independent_checks(rust)`. The result is 50 vectors, 0 mismatches under both Python ECC
  backends (pure Python and coincurve/libsecp256k1).

Mutation tests prove each check bites: a tampered value fails exactly its own vector. The pinned
copies in `vectors/` are checked against the source files on every run.

The header/PoW code is also cross-checked against `lazarus-protocol`, the pool's Rust, through a
path dev-dependency of a standalone crate outside the workspace (`tools/lazarus-crosscheck`, so a
clean checkout never needs `~/Bitcoin`; nothing is written there). It covers 2,000 random profile-0 headers (pow hash, h2, time, height), the Knots-captured
v2 headers, more than 4,000 compact targets, and merkle roots. The mainnet retarget rule is checked on
400 cases recorded from B2's Python (`scripts/gen_retarget_cases.py` → `vectors/retarget_main_cases.json`).

## Cross-implementation on regtest

`scripts/regtest_interop.sh` runs on a private Knots 29.4.2 node (RDTS on, #419
`-testcoinbasematuritylong=200:200:6680`, `-testactivationheight=blake2b@101`), on ports 33030–33043.
It starts no miners. Each close is mined, then its outputs are checked exactly.

| | payer | provider | fee payer | what | result |
|---|---|---|---|---|---|
| A1 | Rust | Python B1 | payer (v1.1) | 10 calls + 1 hash-locked conditional call, close | payee 2100, payer 197300, fee 600 |
| A2 | Rust | Python B1 | payee (v1.2) | 10 calls, close | payee 900, payer 198500 |
| A3 | Rust | Python B1 | payer | 5 calls, rollover (the provider co-signs), 5 calls on the next channel, close | next channel 198650; payee 750, payer 197300 |
| B1 | Python B1 | Rust | payer | 10 calls + 1 conditional call, close | payee 2100, payer 197300 |
| B2 | Python B1 | Rust | payee | 10 calls, close | payee 900, payer 198500 |
| C1 | Rust | Rust | payee | 10 calls, close | payee 900, payer 198500 |

## Where the Rust differs from the reference (deliberately)

* **Ledger.** The reference uses SQLite (WAL, synchronous=FULL). The Rust ledger is an append-only
  JSONL log, fsynced per save, replayed and compacted at open. Each paid call is still O(1) writes.
* **Keys.** Payer and payee keys must be 33-byte compressed. The Python accepts any SEC1 encoding;
  an uncompressed key would change the funding script.
* **Parsing is stricter.** The segwit flag must be `0x01`, trailing bytes after a tx are refused, a
  mixed-case bech32 address is refused (BIP173), and bech32m/v1+ addresses are supported.
* **Routing keeps the last 256 lock answers per channel** (B1 keeps all). Only the pending lock is
  ever retried; an older lockId is refused as `bad_invoice`.
* **A paid invoice is never locked again** (AGP-026 fix, see below).
* **Not in this wave.** The Electrum light backend is AGP-028 and will reuse `header::HeaderChain`.

## The v1.2 payee-pays close report (AGP-029)

AGP-025 found that under v1.2 payee-pays the close answer reported `cum` as the payee's output **net
of its fee** (900 for a 1,500 state with a 600 fee) and `unpaidMsat` as `spent − that`, so the close
fee showed up as unpaid (600000); `/x402/settle`'s `amount` likewise. The on-chain amounts were right.
AGP-029 fixed the report in B1 and here, byte for byte: `cum` / `amount` are the gross state the
payer paid, `unpaidMsat` = `spent − cum × 1000`, and a payee-pays answer adds `payeeFee` and
`payeeNet` (in `/x402/settle`, inside `extra`). A payer-pays (v1.1) answer is unchanged. The vector
`payeePays.close` pins it (ten 150-sat calls closed at 1,500: `cum "1500"`, `unpaidMsat "0"`,
`payeeFee "600"`, `payeeNet "900"`), and the interop payers check it as `provider_report_gross` and
`provider_report_fee`.

## Hub routing (AGP-026)

A port of B1 agp-023 `xbt402/adaptor.py`, `route.py`, `hub.py`, `route_client.py` and the provider's
routing endpoints (AGP-021 + AGP-023 v1.2), wire-compatible in every direction.

```rust
use xbt402::{adaptor, route::*, route_seller::RouteOffer, hub::{RouteHub, HubConfig}, route_client::*, signer::*};

// provider (shard server): sell a path through hubs, metered in amsat (1e-21 sat)
prov.offer_route(RouteOffer { window: 1.0, lock_wait: 2.0, invoice_ttl: 15.0, ..RouteOffer::new("/forward", amsat_per_call) });
// hub (merchant --hub mode): library, or `xbt402-hub --config hub.json` (B1's config format)
let hub = Arc::new(RouteHub::new(chain, spend_scan, wallet, transport, pay_to_secret, &network, Some(datadir), HubConfig::from_json(&conf)?)?);
hub.connect("http://shard:port", None, None)?; let _stop = hub.watch(Duration::from_secs(5));
xbt402::http::serve_service(hub.clone(), "127.0.0.1:9480", 16)?;
// client: one ch1 to the hub, per-window locks off the data path; keys behind RouteSigner
// (LocalSigner, or xbt_signer::client::RemoteSigner), ch1 funded by a Wallet
let payer = Arc::new(RoutePayer::new(hub_url, RoutePayerConfig::new(&network), signer, wallet, transport, height));
payer.open()?; let sh = payer.shard("http://shard:port/forward", "POST")?; payer.start(Duration::from_millis(500));
let r = payer.call(&sh, "POST", chunk)?;      // a 402 with error route_credit: the shard stopped serving
payer.stop(); payer.close()?;
```

* `adaptor`: pre-sign / pre-verify / adapt / extract with B1's DLEQ encoding. Every secret operation
  runs in libsecp256k1 (point multiplications, scalar products and sums via `seckey_tweak_mul/add`,
  inversions as a fixed ladder over n − 2), so unlike the Python there is no bigint remainder.
  `AdaptorBackend` is the seam for a libsecp256k1-zkp backend. Timings (`adaptor_bench`, x86_64):
  presign 99 µs, preverify 132 µs, adapt 22 µs, extract 42 µs (B1 Python + coincurve: 297/501/147/190).
* `route`: `route_ok`, `FeeQuote` + `fee_due` (carry in 1e-6 msat), `PriceQuote`, `Invoice`,
  ROUTE-STATE signatures, session/call/lock auth, `next_cum`, `SpendScan` (no txindex; `Rpc` has it).
* `route_seller`: route offers, sessions, ROUTE-AUTH/ROUTE-STATE, `POST /x402/xbt-channel/lock`
  (pre-verify, write-ahead, idempotent), hub binding, `close_now`.
* `hub`: `RouteHub`, `HubConfig` (fees, fee strategy flat/utilization/callable, liquidity cap, lock
  caps, reveal timeout, `ch1/ch2_close_fee_payer`), the 7 ordered checks with B1's codes, the watcher
  (open, retry, write-off, t from a ch2 close, rollover at the net threshold, ch1 margin).
* `route_client`: `RoutePayer`, over `signer::RouteSigner` (below) and a `client::Wallet`.
* `http::serve_service` serves a provider or a hub (`HttpService`).
* amsat prices exceed u64 and signed quotes must round-trip Python's ints exactly. Since AGP-035 that
  is `xbt402::json`'s job, not serde_json's `arbitrary_precision` (see "Linking xbt-rs from cmp").

**Routing conformance** (`conformance.sh` step 4): `scripts/route_vectors.py` generates
`vectors/xbt402_routing_vectors.json` from B1 (nonces injected, byte-identical under both B1 ECC
backends); the Rust emitter reproduces it byte for byte; Rust re-verifies it (79/79 checks) and B1
re-verifies the Rust file. It covers 5 adaptor cases, quotes (an amsat price above 2^64), invoices,
ROUTE-STATE, auths, `route_ok`/`next_cum` tables and one two-hop lock end to end.

**Routed cross-implementation** (`route_interop.sh`, ports 33100–33212; `XBT_RS_ROUTE_PORT_BASE=B
ROUTE_RSS_OFFSET=3` keeps every port in B..B+99): all 8 combinations of
client × hub × provider in Rust or Python, 2 providers each, exact amounts on chain for every ch1
and ch2 close; then `xbt402-route-demo`, the AGP-021 demo in Rust (4 providers, rollover, a
non-revealing provider, a withholding hub): see AGP-026's result for the tables.

**A client bug found here (fixed in Rust, present in B1).** A lock can complete while the client
still holds a ROUTE-STATE from before it, with the same invoice. Locking that invoice again gets the
hub's saved answer; a normal lock rejects it (it does not open the new T1), but a *floor* lock only
checks t·G == T and counted d + f twice, after which every lock on ch1 was `bad_amount`. The Rust
`RoutePayer` never locks an invoice it already paid (`ShardState::last_locked`, test
`a_paid_invoice_is_never_locked_again_even_a_floor_lock`). B1 `route_client.py` reproduces it
(client routed 10 sat, hub 7) and needs the same one-line guard.

## Portability

No platform-specific dependencies: libsecp256k1 (C, via `secp256k1-sys`), pure-Rust hashes and JSON,
`getrandom`, std threads (no async runtime). The optional HTTP features use `ureq` with rustls/ring
(no OpenSSL) and `tiny_http`. `cargo check -p xbt402` (library, and all features + the hub binary)
passes for x86_64/aarch64 Linux gnu and musl, armv7 and riscv64 Linux, x86_64/aarch64 macOS and
x86_64 Windows (gnu), with zig as the cross C compiler; aarch64 links (`xbt402-hub` 4.5 MB).
Under v1.2 payee-pays, the close response reports `cum` as what the close pays the payee **net of
its fee** (900 for a 1500 state with a 600 fee), and `unpaidMsat` as `spent − that`. So it shows
the close fee as unpaid (600000), and `/x402/settle`'s `amount` likewise. The on-chain amounts are
right. B1 `x402_channel.py` does this (`_close_paid` sums the payee outputs), and the Rust port
matches it byte for byte. The interop run records it as `provider_report_as_reference`. Whether the
reference should report the gross `cum` is for the lead (AGP-023 follow-up), not this port.

## The light backend: xbt-electrum (AGP-028)

A client with no node: the xbt402 payer (and later the wallet) reads the chain from Electrum servers
and trusts only what it can check. A port of B2's `agentwallet/electrum.py` (AGP-024) with the same
trust rules; the threat model is in B2 `docs/B2_CHAIN_BACKEND.md` and the crate docs.

```rust
use xbt_electrum::{Config, ElectrumBackend};
let mut cfg = Config::new(&["tcp://127.0.0.1:50001", "ssl://electrum.example:50002"], "main");  // mainnet: checkpoint 961640
cfg.store_path = Some(run_dir.join("headers-main.bin"));        // verified headers, re-verified at load
let chain = std::sync::Arc::new(ElectrumBackend::new(cfg)?);      // or Config::from_env (B2's variables)
let n = chain.block_count()?;                                     // our verified tip
let out = chain.tx_out(txid, vout, true)?;                        // proven confirmations; a mempool spend never hides it
chain.watch(&[&funding_spk])?; chain.wait_for_change(timeout);    // scripthash/headers subscriptions wake a watcher
let prov = Provider::new(chain.clone(), ...);                     // any ChainBackend user
let v = chain.call("gettxout", &json!([txid, 0, true]))?;         // the node RPCs of the client path, answered as the node does
```

* **Headers**: `HeaderChain` from the pinned checkpoint (PoW, Knots retarget, linkage, height, time),
  most work wins, caught up in batches of 4x2016 headers per round trip. Servers that answer but
  cannot serve the checkpoint mean the wrong chain (`Kind::CheckpointMismatch`).
* **Transactions**: the raw tx must re-serialize and hash to the txid; confirmed only with a Merkle
  proof into our header whose committed txcount fixes the proof's depth and position bound.
* **Servers**: histories and unspent lists are the union over every live server (queried in
  parallel), broadcasts go to all, the fee estimate is the median (and marked unverified).
* **Refunds cannot be suppressed**: a spend seen only in a mempool never makes an output count as spent.
* Node-only calls (wallet, `getblock`, mining) are refused with `Kind::LightBackend`.

Tests: `crates/xbt-electrum/tests/backend.rs` runs every call, TLS, batching, persistence, reconnects
and subscriptions against a simulated chain and Electrum server (`sim` feature), and the lying servers:
a hidden tx, withheld headers and a stale tip, a lying fee, the wrong chain, a weaker and a stronger
(reorging) chain, three kinds of bad proof, a substituted tx, wrong heights, an invented spend that
tries to stop a refund, and broadcasts answered with another txid.

`scripts/electrum_interop.sh` (ports 33300-33399) runs a light Rust payer (its own hot key; every read
and broadcast through Electrum) against two patched electrs 0.11.1 (AGP-024), one behind TLS, both
required, on a Knots 29.4.2 regtest node, against the Python B1 provider. The node is only the faucet,
the miner, and the oracle every answer is compared with.

| | provider | what | result |
|---|---|---|---|
| E1 | Python B1, v1.1 payer-pays | open, 10 calls, close; the close change counted late (mempool hint, then proof after the block's notification) | payee 1500, payer 197900, 14/14 checks, 35/35 answers = node |
| E2 | Python B1, v1.2 payee-pays | same | payee 900, payer 198500, 14/14, 35/35 |
| E3 | Python B1 (then killed) | open, 3 calls, the provider vanishes; early refund refused (non-final); refund at expiry via Electrum, proven | refund 199400, 10/10, 18/18 |

Deliberately different from B2's Python: `gettxspendingprevout` reports mempool spends only, as
Knots does (the Python also reported confirmed spends; the typed `spending_tx` still does), and the
fee estimate is the median over servers (the Python took the first answer).

## Linking xbt-rs from cmp (AGP-035)

xbt-compute's Rust runtime pins this repo by full rev with `default-features = false`. What that
gets, and what it must not get:

**No `arbitrary_precision`.** Cargo unifies features, so a serde_json feature here would change
`serde_json::Number` in every crate cmp links. `cargo tree -e features -i serde_json` shows only
`default`, `std`, `preserve_order` and `indexmap`. Routed amsat prices and meters (above u64) are
still exact: `xbt402::json::parse` reads JSON without serde_json ever rounding a number through
f64, holding an integer beyond i64/u64 as a reserved one-key object `{"$xbt402::int": "<decimal>"}`
(`json::big_int`/`big_uint`/`as_big_int`/`int_text`), which `json::dumps`/`dumps_compact`/`canon`
write back as the bare integer. Floats are parsed with Rust's correctly rounded parser and written
as Python's `repr`. A document that contains the reserved key itself is refused. Every xbt402 input
goes through `json::parse`, and every output through `json::dumps`: the 249 + 79 vectors are
byte-identical both ways and `route_interop` is green. If cmp handles xbt402 JSON itself, it reads
with `xbt402::json::parse` and writes with `xbt402::json::dumps*`. `serde_json::to_string` would
print a big integer as the reserved object.

Options weighed for this (best-performing-stack rule):

| option | exact amsat | cmp's serde_json untouched | change in xbt-rs | risk |
|---|---|---|---|---|
| keep `arbitrary_precision` | yes | **no** (the reason for AGP-035) | none | changes cmp's numbers |
| a number newtype over `RawValue` (`raw_value` feature) | yes | yes (`raw_value` adds a type, changes no semantics) | typed structs instead of `Value` across hub, seller, route client and vectors (~4k lines) | large rewrite of byte-exact code |
| decimal strings at the Rust boundary | no: B1 signs amsat as a JSON *number*, a string canonicalises differently | yes | small | breaks signature interop |
| a canonical writer for the signed messages only | signing yes, but the parse is still lossy | yes | medium | quotes nested in 402 bodies are still rounded on read |
| **a lossless parse front end + reserved big-int object (chosen)** | yes, in both directions | yes, no serde_json features at all | `json.rs` (+ 25 call sites `serde_json::from_*` → `json::parse*`) | the reserved object must not leak through `serde_json::to_string`: every writer is `json::dumps*` |

**Clean-checkout builds.** `scripts/cmp_clean_build.sh [REF]` clones REF, deletes `.cargo/`, refuses
if any other cargo config or cross build variable is in effect, then runs `cargo zigbuild --release
--locked` (cargo-zigbuild 0.23.4 from `~/xbt-rnd/tools/zigbuild`, zig 0.16.0 from the ziglang venv)
of `-p xbt402 --no-default-features` and `-p xbt-signer` for x86_64/aarch64-unknown-linux-musl and
armv7-unknown-linux-musleabihf, checks each binary is a static ELF of its machine, and builds and runs
a cmp-shaped consumer that takes `xbt402` and `xbt-signer` as git dependencies. The one blocker was
here, not in the build: `xbt402-interop`'s path dev-dependency on `~/Bitcoin/lazarus/protocol` kept a
clean clone from even loading the workspace. That cross-check now lives in `tools/lazarus-crosscheck`.

**The surface with no features** (`crates/xbt402/tests/cmp_surface.rs`, run with
`--no-default-features` and only cmp-style `Transport`, `Wallet`, `ChainBackend` + `SpendScan` and a
signer):
* `Provider::new(chain, pay_to, cfg, ledger, price, handler)` takes its `Ledger`
  (`Ledger::open(path)` or `in_memory()`) and `Provider::serve(...)` is the whole HTTP surface.
* `Client::new(cfg, transport, wallet, height).with_signer(signer).with_ledger(ledger)?`: the
  channel book goes to any `ClientLedger` (`load`/`save` of keyed JSON records). `FileClientLedger` is
  an fsynced JSONL file, mode 0600, compacted on open; `MemoryClientLedger` is in memory. Every paid
  call, close and rollover saves what it touched (`Client::persist` after hand edits). A signer-held
  channel is stored as `"key": "signer"` and needs the same signer to load; a local key is stored as
  its secret. Additive: without `with_ledger` nothing changes.
* One process holds a Provider ledger and a Client ledger at once (the MoE dispatcher sells and buys).
  The test runs that, restarts the client from its file, and keeps paying on the same channels.
* `RoutePayer::new(hub, cfg, route_signer, wallet, transport, height)` pays two providers through
  one hub channel, one of them priced above u64 amsat.

**ECDSA vs `cmp/keys.py`.** `scripts/cmp_keys_ecdsa.py` (with cmp's venv; cmp's tree is only read,
no bytecode is written) signs 2,000 (secret, message) pairs with `OperatorKey(secret).sign(msg)` and with
`xbt_primitives::ecdsa::sign(secret, sha256(msg))` (via `xbt-ecdsa-cmp`). Edge keys 1, 2, 3, n−1,
n−2, 2^255 and messages from empty to 1 KiB give identical pubs and identical strict-DER low-S
signatures, and 4,000 cross-verifications agree.

### Micro-payments: 16–64 vendors at a few msat per call

**Direct channels (one per origin).** Numbers are the defaults (`ProviderConfig`, `ClientConfig`,
`channel.rs`):

| per origin | amount |
|---|---|
| funding tx (1 P2WPKH in → P2WSH + change) | ~153 vB; ~306 sat at 2 sat/vB |
| capacity locked | `ClientConfig.capacity` 200,000 sat (provider floor `min_capacity` 20,000) |
| first state (the least the vendor is ever paid) | `min_amount()` = DUST 546 sat (payer pays the close fee), 1,146 sat under v1.2 payee-pays |
| close | `STATE_VSIZE` 190 vB, `closeFeeSat` 600 sat |
| wait before the first paid call | `min_conf` 1 block (3 above 1,000,000 sat capacity) |

So each direct vendor costs at least 546 + 600 + ~306 ≈ 1,450 sat of floor plus fees over a
channel's life, whatever it is used for. Prices on direct channels are whole sats per call (`PriceFn`,
`ChargeFn`). The provider meters `spentMsat` and reports `owedMsat` = spent − 1000·cum. Postpay
signs a new state only when ⌈spentMsat/1000⌉ passes the last signed cum, so one floor state covers
the first 546 sat of use. A metered call can charge less than its price, but not
less than 1 sat. **Do not price a direct vendor below the DUST floor over the channel's life, and do
not use direct channels for sub-sat calls.**

**~64 channels in one Client:** memory is ~0.5 KB of struct plus ~1.9 KB of JSON per channel
(`accepted` terms, params, refund), about 160 KB for 64. Receipts are also kept per call (0.4 KB of
JSON each, more as a `Value`): 64 vendors × 10,000 calls is 640,000 receipts, so call
`Client::trim_receipts(n)` now and then. A `FileClientLedger` saves at most 16 receipts per channel,
about 8.7 KB per channel record. Opening means 64 fundings (~9,800 vB), 64 confirmations to wait for,
and 12.8 M sat locked at the default capacity. Note that the default `budget_sats` of 1,000,000 stops
at 5 channels: raise it. Closing means 64 × 190 vB ≈ 12,200 vB and 64 × 600 = 38,400 sat of close
fees, plus 64 × 546 = 34,944 sat of floors. In total that is ~22,000 vB on chain and ~93,000 sat of
fees and floors before any real use.

**Hub routing (the intended answer).** One ch1 to a hub (one funding, one close, one floor: ~340 vB
and ~1,450 sat in all) reaches every vendor. The hub runs the ch2s and charges `feeBaseMsat` +
`feePpm` per lock (defaults 1,000 msat + 2,000 ppm; carried exactly in 1e-6 msat, charged as the
ceil of the running total, never rounded per lock). Prices are amsat per call (1 sat = 10^21 amsat)
with exact meters on both sides and signed ROUTE-STATEs per call. Locks are per window (`window`
1 s) of ⌈owed⌉ sat, so at 5 msat per call a vendor is paid 1 sat per 200 calls, with no rounding lost.
`credit_msat` caps unpaid credit. That per-window lock *is* the aggregated per-N-calls payment. We
advise against a separate aggregation API: the window and the amsat meter already amortise it,
without giving up the per-call evidence.

