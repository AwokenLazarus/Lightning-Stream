# xbt-rs

Rust rails for XBT (Bitcoin with BLAKE2b proof of work): a shared chain-primitives crate and the
xbt402 payment-channel crate (the x402 v2 scheme `xbt-channel`, spec v1.1 plus the v1.2
`closeFeePayer` additions). It ports the Python references and is byte-identical to them. Built for
xbt-compute's Rust device runtime (AGP-025, owned by xbt-agentpay).

Local repo, no remote. Workspace crates:

| crate | what | published |
|---|---|---|
| `xbt-primitives` | tx (de)serialization with witness, scripts, bech32/bech32m per chain, UnifiedSighash 0x21/0xA3, strict-DER low-S ECDSA (libsecp256k1), BLAKE2b header v2 + PoW + Knots retarget + most-work header chain, network ids | library (for other projects too) |
| `xbt402` | channel params, payee tweak v2, funding script, states, close, rollover, refund, v1.2 payee-pays, conditional hash locks, the 402 wire, receipts, request auth, provider verifier, payer client, ledger; hub routing (AGP-026): ECDSA adaptor locks, provider route offers, `RouteHub` + the `xbt402-hub` service, `RoutePayer`, `StateSigner` | library (+ `xbt402-hub` bin) |
| `xbt402-interop` | conformance suite, Rust→JSON vector emitter, regtest cross-implementation tools | no (`publish = false`) |

References (read-only): B1 `agp-023` `f105ccc` (`~/xbt-rnd/b1-agp-023`, `xbt402/`), B2 `agp-next2`
`04c3f56` (`~/xbt-rnd/b2`, `agentwallet/headers.py`), and `lazarus-protocol` (`~/Bitcoin/lazarus/protocol`).

## Build and verify

```bash
cargo test -j2 --workspace
cargo build -j2 --release --target aarch64-unknown-linux-gnu -p xbt402
./scripts/conformance.sh           # N/N byte-identical, both directions
./scripts/regtest_interop.sh       # Rust <-> Python on a private Knots 29.4.2 regtest node
./scripts/route_interop.sh         # routed: every client x hub x provider (Rust/Python) + the all-Rust demo
cargo run --release -p xbt402 --example adaptor_bench
```

Run heavy work under a CPU and memory cap:
`systemd-run --user --scope -p CPUQuota=200% -p MemoryMax=4G nice -n 19 ...` (the scripts do).

**aarch64.** There is no system cross toolchain on the build host, so zig is the C compiler (for
libsecp256k1) and the linker. Set it up once with
`python3 -m venv ~/.local/share/ziglang-venv && ~/.local/share/ziglang-venv/bin/pip install ziglang`.
`.cargo/config.toml` points the aarch64 target at `tools/zig-cc-aarch64` (glibc 2.28 floor). The
offline self-test `cargo build --release --target aarch64-unknown-linux-gnu -p xbt402 --example selftest`
links to a 1.99 MB aarch64 PIE (2.30 MB on x86_64). A Pi can run it; build-host has no aarch64
emulator.

Dependencies: `secp256k1` 0.29 (libsecp256k1, the global context), `sha2`, `ripemd`, `blake2`,
`hmac`, `ruint` (256-bit targets and work), `serde_json` with `preserve_order`, `base64`, `thiserror`,
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
* `client`: `Client`, `ClientConfig`, and the two hooks the application supplies: `Transport` and `Wallet`.
* `funding`: `ChainBackend` (the four node calls), `FundingPolicy`, `check_funding`.
* `ledger`: `ChannelState`, `Ledger` (in memory, or an fsynced append-only JSONL file).
* `json`: JSON written byte-exactly as Python's `json.dumps`, which the wire headers need.
* Features: `http-client` (`http::UreqTransport`), `http-server` (`http::serve_http`), `rpc`
  (`rpc::Rpc`: bitcoind JSON-RPC as `ChainBackend` and `Wallet`). cmp can bring its own transport.

Errors are `ChannelError { code, msg }` (`thiserror`). `code` is the wire error code
(`bad_sig`, `bad_amount`, `stale_amount`, `bad_auth`, ...). The library does not panic on
untrusted input: parsers and the provider are fuzzed with hostile bytes and JSON in the tests.

## Conformance statement

`scripts/conformance.sh` (2026-09-28):

| group | vectors | source | result |
|---|---|---|---|
| xbt402 v1.1 + v1.2 (counted as `check_vectors.py` counts them) | 49 | B1 agp-023 `docs/x402/vectors.json` | 49/49 byte-identical |
| UnifiedSighash (Knots hf-sighash-opt-in reference) | 166 | B1 `tests/data/unified_sighash.json` | 166/166 |
| BLAKE2b header v2, every hash stage | 5 | B2 `tests/vectors/block_header_v2.json` | 5/5 |
| Knots BLAKE2b regtest capture: 24 headers across v1/v2, 3 blocks' merkle roots, a header chain | 28 | B2 `tests/vectors/blake2b_regtest.json` | 28/28 |
| **total** | **248** | | **248/248** |

It works in both directions:

* Rust → reference. The Rust emitter (`xbt402-vectors`) rebuilds the whole xbt402 vector file with
  the Rust crates, the Rust provider serving every round trip (402, open, 5 paid calls, replay,
  facilitator, close, settle, the conditional sale and its claim, the v1.2 section). Any difference
  from the published file is charged to the vector it belongs to. The generator-independent checks
  of `check_vectors.py`, ported to Rust, run over the published values: refusal codes, which key
  signed what, receipts, script layouts.
* Reference → Rust. B1's `check_vectors.py` checks the Rust-emitted file: `diff(python_generate(), rust)`
  plus `independent_checks(rust)`. The result is 49 vectors, 0 mismatches under both Python ECC
  backends (pure Python and coincurve/libsecp256k1).

Mutation tests prove each check bites: a tampered value fails exactly its own vector. The pinned
copies in `vectors/` are checked against the source files on every run.

The header/PoW code is also cross-checked against `lazarus-protocol`, the pool's Rust, through a
path dev-dependency (`crates/xbt402-interop/tests/lazarus_crosscheck.rs`; nothing is written to
`~/Bitcoin`). It covers 2,000 random profile-0 headers (pow hash, h2, time, height), the Knots-captured
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
* **Not in this wave.** The B2 signer backend, which keeps payer keys out of the
  client, is AGP-027: `Payer` holds its key today, behind the same `sign_state` seam. The Electrum
  light backend is AGP-028 and will reuse `header::HeaderChain`.

## A reference behaviour worth a look (reproduced faithfully)

Under v1.2 payee-pays, the close response reports `cum` as what the close pays the payee **net of
its fee** (900 for a 1500 state with a 600 fee), and `unpaidMsat` as `spent − that`. So it shows
the close fee as unpaid (600000), and `/x402/settle`'s `amount` likewise. The on-chain amounts are
right. B1 `x402_channel.py` does this (`_close_paid` sums the payee outputs), and the Rust port
matches it byte for byte. The interop run records it as `provider_report_as_reference`. Whether the
reference should report the gross `cum` is for the lead (AGP-023 follow-up), not this port.

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
// client: one ch1 to the hub, per-window locks off the data path; keys behind StateSigner
let payer = Arc::new(RoutePayer::new(hub_url, RoutePayerConfig::new(&network), signer, transport, height));
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
* `route_client`: `RoutePayer`. `signer`: `StateSigner` (B1 `ChannelSigner` / B2 `xbt402_*` names;
  AGP-027 implements it over the B2 socket) and `LocalSigner`.
* `http::serve_service` serves a provider or a hub (`HttpService`).
* `serde_json` runs with `arbitrary_precision`: amsat prices exceed u64 and signed quotes must
  round-trip Python's ints exactly.

**Routing conformance** (`conformance.sh` step 4): `scripts/route_vectors.py` generates
`vectors/xbt402_routing_vectors.json` from B1 (nonces injected, byte-identical under both B1 ECC
backends); the Rust emitter reproduces it byte for byte; Rust re-verifies it (79/79 checks) and B1
re-verifies the Rust file. It covers 5 adaptor cases, quotes (an amsat price above 2^64), invoices,
ROUTE-STATE, auths, `route_ok`/`next_cum` tables and one two-hop lock end to end.

**Routed cross-implementation** (`route_interop.sh`, ports 33100–33199): all 8 combinations of
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
