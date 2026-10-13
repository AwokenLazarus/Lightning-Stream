# Engineering notes (xbt-rs)

> **Read this first (2026-10-11).** The direction changed on this day. Lightning Stream is now
> built on Lightning: it adds stream tickets to ordinary XBT Lightning channels, and that work is
> in design, not built. The hub was retired and its code removed: the `xbt402-hub` binary, hub
> routing with adaptor signatures, the hub's link to a Lightning node, the routed client, the
> route providers, the wallet's routing policy and lock methods, their tests, scripts, vectors and
> packages. The on-chain one-way channel is frozen: kept and tested, off the main path, no new
> work.
>
> Everything below this note is the history of the on-chain channel and the hub, left as it was
> written. Sections about the hub, routing, adaptor locks and the routed client describe code
> that is no longer in the tree; it is in the git history, last at commit `a548fb0`. Commands,
> scripts, crate rows, test counts and vector counts below that name removed parts no longer run
> or no longer match. What runs today is in `README.md`; what is and is not covered is in
> `docs/LIMITS.md`.

Rust rails for XBT (Bitcoin with BLAKE2b proof of work): a shared chain-primitives crate and the
xbt402 payment-channel crate (the x402 v2 XBT binding of `batch-settlement`,
`extra.assetTransferMethod: "channel"`; `xbt-channel` accepted as an alias; spec v1.1 plus the v1.2
`closeFeePayer` additions). It ports the Python references and is byte-identical to them. Built for
xbt-compute's Rust device runtime (AGP-025, owned by xbt-agentpay).

What this software does not do, the open items and what no review has
covered are in `docs/LIMITS.md`: read it before relying on any part. Workspace crates:

| crate | what | published |
|---|---|---|
| `xbt-primitives` | tx (de)serialization with witness, scripts, bech32/bech32m per chain, UnifiedSighash 0x21/0xA3, strict-DER low-S ECDSA (libsecp256k1), BLAKE2b header v2 + PoW + Knots retarget + most-work header chain, network ids | library (for other projects too) |
| `xbt402` | channel params, payee tweak v2, funding script, states, close, rollover, refund, v1.2 payee-pays, conditional hash locks, the 402 wire, receipts, request auth, provider verifier, payer client, ledger; the signer seam (`StateSigner` + the routing extension `RouteSigner`); hub routing (AGP-026): ECDSA adaptor locks, provider route offers, `RouteHub` + the `xbt402-hub` service, `RoutePayer` | library (+ `xbt402-hub` bin) |
| `xbt-signer` | B2's agent-wallet signer (AGP-027): keys never in the client (xbt402 `StateSigner` and `RouteSigner`), B2's policy engine and routing policy, sealed hot/channel keys, write-ahead opens, refund custody, anchored signature log; B2's socket protocol and file formats. See `crates/xbt-signer/README.md` | binaries `xbt-signer`, `xbt-anchor-witness`, `xbt-signer-payer` |
| `xbt402` | channel params, payee tweak v2, funding script, states, close, rollover, refund, v1.2 payee-pays, conditional hash locks, the 402 wire, receipts, request auth, provider verifier, payer client, ledger | library |
| `xbt-wallet-mcp` | the agent wallet's MCP server (AGP-030): B2's ten tools (same names, schemas, validation, results and errors as `mcp_server.py`) over stdio and streamable HTTP, talking only to the B2 signer socket (Rust or Python signer), optional in-process xbt402 payer with keys in the signer. See `crates/xbt-wallet-mcp/README.md` (Claude Code, Hermes, OpenClaw config) | binary `xbt-wallet-mcp` |
| `xbt-electrum` | the light chain backend: Electrum servers (TCP/TLS, batching, several servers) checked against our own `HeaderChain` and Merkle proofs; `xbt402::ChainBackend`, a typed API, and the node-RPC surface of the client path | library |
| `xbt-svc` | container-ready service plumbing (AGP-038): one data dir, the secret source, readiness, proxy URLs, probes; see `docs/CONTAINER.md` | library |
| `xbt-gateway` | the stream-ticket seller gateway: a reverse proxy beside a Lightning node (hold invoices for a buyer's hashes, settle on use, an answer metered per request, per byte or per second, signed receipts); the wire is `docs/TICKETS.md`, the limits are in `docs/LIMITS.md`, and `crates/xbt-gateway/README.md` says how to run it | binary + library |
| `xbt-work` | pay-with-work (AGP-032): the x402 scheme `xbt-work` v1 draft. Invoices (base32 ids, both usernames), the strict receipt grammar and Ed25519 verification, the provider's receipt book (delta credit, equivocation proofs, audit intervals), exact work-unit pricing per nBits epoch, the `auth` binding, the xbt-work offer beside the channel binding in the xbt402 Provider and a payer for the xbt402 Client, window statements and NTA deferral lines, the coinbase audit with fraud proofs and a carry ledger, the blinded relay client (ChaCha20-Poly1305), NTA attestation helpers | library (+ `xbt-work-{vectors,provider,payer}` with feature `tools`) |
| `xbt402-interop` | conformance suite, Rust→JSON vector emitter, regtest cross-implementation tools | no (`publish = false`) |

References: B1 and B2 are the Python reference implementations of the channel scheme and the agent wallet
([Lightning-Stream-py-channel](https://github.com/AwokenLazarus/Lightning-Stream-py-channel) and
[Lightning-Stream-py-wallet](https://github.com/AwokenLazarus/Lightning-Stream-py-wallet)).
The pinned vectors in `vectors/` are what the Rust is checked against. `lazarus-protocol` is the pool's Rust, in
[AwokenLazarus/Bitcoin](https://github.com/AwokenLazarus/Bitcoin) (`lazarus/protocol`).

## Build and verify

```bash
cargo test -j2 --workspace
cargo deny check                   # AGP-075: licences (deny.toml), advisories, crates.io only
                                   # (it cannot see advisories for the vendored ureq: vendor/ureq/XBT-PATCH.md)
cargo clippy --workspace --all-targets --all-features -- -D warnings   # AGP-075: clean on main
cargo build -j2 --release --target aarch64-unknown-linux-gnu -p xbt402
./scripts/conformance.sh           # N/N byte-identical, both directions
./scripts/regtest_interop.sh       # Rust <-> Python on a private Knots 29.4.2 regtest node
./scripts/signer_interop.sh        # AGP-027: the AGP-017 runbook with the Rust signer behind B2's MCP, + a Rust payer
./scripts/hub_returns_regtest.sh    # AGP-104: the hub's full cycle on regtest (Rust and Python hub), no coin left on a per-channel key, /status to the sat, start-up checks
./scripts/route_interop.sh         # routed: every client x hub x provider (Rust/Python), the all-Rust demo, + a Rust payer on the Rust signer
cargo run --release -p xbt402 --example adaptor_bench
./scripts/build_matrix.sh          # every AGP-031 target; writes dist/MATRIX.md
./scripts/electrum_interop.sh      # the light Rust payer on real electrs (tcp + TLS) vs the Python provider
./scripts/failure_interop.sh       # AGP-111: failure paths through the release binaries (lost answers, a silent provider, a hostile Electrum
                                   # server, kills mid-payment, a refused funded open); each check PASS or FAIL with what it observed
scripts/third_party_table.py --check   # the dependency table of THIRD_PARTY_NOTICES.md is what cargo tree gives
cargo test -j2 -p xbt402 --no-default-features --test cmp_surface   # AGP-035: what cmp links, no features
./scripts/cmp_clean_build.sh [REF] # AGP-035: clean clone, no .cargo, cargo-zigbuild, x86_64/aarch64/armv7 musl
scripts/cmp_keys_ecdsa.py          # AGP-035: xbt_primitives::ecdsa vs cmp/keys.py, byte for byte
cargo test -j2 --manifest-path tools/lazarus-crosscheck/Cargo.toml  # header/PoW vs the pool's lazarus-protocol
./scripts/oci_build.sh [--load]    # AGP-038: FROM scratch images, amd64/arm64/arm-v7, dist/oci/*.tar + IMAGES.md (docs/CONTAINER.md)
./scripts/work_conformance.sh      # AGP-032: xbt-work vectors, Rust -> XBT-053 and XBT-053 -> Rust
./scripts/work_interop.sh          # AGP-032: pay-with-work on regtest, Rust payer/provider vs primed (branch rnd/agp-011, not public) (PAYER=py / PROVIDER=py: vs the Python side)
./scripts/work_matrix.sh           # AGP-032: xbt-work on every AGP-031 target; writes dist/WORK_MATRIX.md
./scripts/container_test.sh         # AGP-038: the images on regtest (signer+witness+MCP+hub, env + data dir only), paid call, restart, /readyz
./scripts/ln_rail_regtest.sh        # the Lightning rail (ln_pay) on Lightning Fork nodes
./scripts/ln_ticket_regtest.sh      # stream tickets as such: the measurements of docs/TICKETS.md
./scripts/ticket_book_regtest.sh    # the ticket book in the wallet's signer, through its socket
./scripts/gateway_regtest.sh        # the seller gateway with a test buyer
./scripts/ticket_e2e_regtest.sh     # the wallet pays the gateway: xbt402_pay over tickets through a hop, a lying seller, kills of each part
./scripts/lottery_regtest.sh        # the lottery: xbt402_pay by draws through a hop, 100 sellers at once, a buyer that never pays, a lying seller, kills
python3 scripts/lottery/draw.py check  # the lottery's draw, written a second time, against vectors/lottery_vectors.json
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
and writes sizes plus status to `dist/MATRIX.md`. (`release-small` sets `panic = "abort"`: any panic ends the
whole process, so it is for size measurements and clients, not for a server. Every release profile
has `overflow-checks` on.) The self-test is executed on the host for
x86_64; other arches need a user-mode emulator already on PATH (the script never installs
binfmt/qemu).

Dependencies: `secp256k1` 0.29 (libsecp256k1, the global context), `sha2`, `ripemd`, `blake2`,
`hmac`, `ruint` (256-bit targets and work), `serde_json` with `preserve_order` (never
`arbitrary_precision`, AGP-035), `base64`, `thiserror`,
`getrandom`, `indexmap`. Optional: `ureq` (features `http-client`, `rpc`), built from `vendor/ureq`: a build
outside this workspace needs the same `[patch.crates-io]` (`vendor/ureq/XBT-PATCH.md`, AGP-096). The `http-server` feature is std only (AGP-068).
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
  offer_conditional, close_due, close_channel, sweep_payee, recovered_reservations), `ProviderConfig`.
* `client`: `Client` (`request`/`request_with`, `close`/`close_with`), `CallOpts`, `ClientConfig`, and the two hooks the application supplies: `Transport` and `Wallet`;
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

`scripts/conformance.sh` (2026-10-08, AGP-068):

The vectors come from our own Python references (B1, B2) and from Knots. B1 and B2 are not yet
published, so the B1/B2 groups show agreement between our two implementations, not conformance to
an outside implementation. XBT-053 (the pay-with-work specification, its Python reference and its
vectors) is not published either and has no public repository: where this document names its
vectors, they are a file a reader cannot fetch today. The UnifiedSighash vectors are Knots' own file, byte for byte.

| group | vectors | source | result |
|---|---|---|---|
| xbt402 v1.1 to v1.3 (counted as `check_vectors.py` counts them) | 54 | B1 agp-068 `docs/x402/vectors.json` | 54/54 byte-identical |
| UnifiedSighash (Knots hf-sighash-opt-in reference) | 166 | B1 `tests/data/unified_sighash.json` | 166/166 |
| BLAKE2b header v2, every hash stage | 5 | B2 `tests/vectors/block_header_v2.json` | 5/5 |
| Knots BLAKE2b regtest capture: 24 headers across v1/v2, 3 blocks' merkle roots, a header chain | 28 | B2 `tests/vectors/blake2b_regtest.json` | 28/28 |
| **total** | **253** | | **253/253** |

It works in both directions:

* Rust → reference. The Rust emitter (`xbt402-vectors`) rebuilds the whole xbt402 vector file with
  the Rust crates, the Rust provider serving every round trip (402, open, 5 paid calls, replay,
  facilitator, close, settle, the conditional sale and its claim, the v1.2 section). Any difference
  from B1's vector file is charged to the vector it belongs to. The generator-independent checks
  of `check_vectors.py`, ported to Rust, run over the recorded values: refusal codes, which key
  signed what, receipts, script layouts.
* Reference → Rust. B1's `check_vectors.py` checks the Rust-emitted file: `diff(python_generate(), rust)`
  plus `independent_checks(rust)`. The result is 54 vectors, 0 mismatches under both Python ECC
  backends (pure Python and coincurve/libsecp256k1). (Corrected by AGP-107: this said 50, an
  earlier count; `check_vectors.py` prints 54, the table's number.)

Mutation tests prove each check bites: a tampered value fails exactly its own vector. The pinned
copies in `vectors/` are checked against the source files on every run.

The header/PoW code is also cross-checked against `lazarus-protocol`, the pool's Rust, through a
path dev-dependency of a standalone crate outside the workspace (`tools/lazarus-crosscheck`, so a
clean checkout never needs `~/Bitcoin`; nothing is written there). It covers 2,000 random profile-0 headers (pow hash, h2, time, height), the Knots-captured
v2 headers, more than 4,000 compact targets, and merkle roots. The mainnet retarget rule is checked on
400 cases recorded from B2's Python (`scripts/gen_retarget_cases.py` → `vectors/retarget_main_cases.json`).

## Cross-implementation on regtest

`scripts/regtest_interop.sh` runs on a private Knots 29.4.2 node (RDTS on, #419
`-testcoinbasematuritylong=200:200:6680`, `-testactivationheight=blake2b@101`), on ports 23030–23043.
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

> **Experimental.** The hub (`RouteHub`, `xbt402-hub`, `RoutePayer`'s routing) is not
> production-ready: do not route funds you cannot lose. `xbt402-hub` says so when it starts. No flag
> is needed, so the demos keep running. See "Hub routing safety (AGP-064)".

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

**Routed cross-implementation** (`route_interop.sh`, ports 23100–23232; `XBT_RS_ROUTE_PORT_BASE=B
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

## Hub and client leftovers (AGP-044)

The routing items AGP-035 and AGP-037 left open. Items 1 and 2 are the same in B1's `xbt402/hub.py`
(b1 `agp-044`).

**1. A stuck ch2 refund is bumped by RBF.** A hub refund that is still unconfirmed
`refund_bump_blocks` (default 3) after it was signed is signed again at a higher fee and replaces
itself. The new fee is the estimate, at least double the stuck fee, and at least the stuck fee
+ 1 sat/vB (BIP125's increment). It is capped by `refund_max_fee_sat` (default 5,000) and always
leaves dust. It pays the same destination as the version it replaces.
* Hub refunds signal replaceability: nSequence `RBF_SEQUENCE` = 0xFFFFFFFD, with nLockTime still
  enforced. `ChannelParams::refund_tx_seq` builds them; the client refund (`refund_tx`) and its
  vector are unchanged.
* Every version is written ahead and kept in `refund_prev` until one confirms. Whichever version
  confirms is the refund, and its fee is the one counted.
* Events: `ch2_refund_bump` (`replaces`, `feeFrom`), `ch2_refund_bump_capped`,
  `ch2_refund_bump_failed` (the node refused the replacement; both versions stay tracked), and
  `ch2_refund_confirmed` (with `versions`).

Why RBF and not CPFP:

| | RBF (chosen) | CPFP |
|---|---|---|
| who can sign | the hub alone: it holds the ch2 payer key, and the refund is 1-in-1-out | the owner of the refund output: with `refund_to` (a wallet address) the hub cannot, unless the `Wallet` trait grows a spend-this-UTXO call |
| extra chain use | none: the same tx at a higher fee | a second tx (~110 vB) whose fee must also cover the parent |
| a refund that left the mempool (too cheap to relay, evicted) | the higher-fee version simply goes out | no parent to attach to without package relay |
| cost | the txid changes: every version must be tracked | the parent's txid is stable |
| node support | a signalling refund replaces on any node | needs the parent in the mempool |

A refund the hub signed before AGP-044 (0xFFFFFFFE) is replaceable only where full-RBF is on. On
other nodes the replacement is refused (`ch2_refund_bump_failed`), and whichever version confirms
still counts.

**2. One live ch2 per origin** (was: per payTo; changed by AGP-056, see "Multi-process operators"
below). Origins are canonical (`route::canon_origin`: scheme and host lowercased, the default port and
trailing `/`s dropped), and `connect` to an origin that already has a live ch2 funds nothing: it
returns that ch2. The two-connects race is closed under the book lock (`ch2_funding`).

**3. The RoutePayer ledger seam.**
```rust
let payer = RoutePayer::new(hub_url, cfg, signer, wallet, transport, height)
    .with_ledger(Box::new(FileRouteLedger::open(&path)?))?;   // resumes whatever the file holds
payer.open()?;                          // {"resumed": true} with the same ch1
let sh = payer.shard(url, "POST")?;     // the same provider session (no new 402)
```
* The `RouteLedger` trait is the `ClientLedger` store: every `ClientLedger` is a `RouteLedger`.
  `FileRouteLedger` is JSON lines, fsynced, mode 0600, and compacts itself as it grows.
  `MemoryRouteLedger` keeps the records in memory.
* Records: `ch1`, `book` (counters, given-up locks, stats, quote), `pending`, and one `shard <url>`
  per session.
* Write-ahead: the lock and its ch1 seq before the request leaves, and a block of `SEQ_RESERVE`
  (16) call seqs before the first of them leaves. The meters are saved every `persist_every`
  answered calls (default 1).
* Resuming a pending lock: the same request is sent again with a fresh seq and auth. The hub
  answers a lock it completed with its saved answer, or takes a lock it never saw.
* A presignature the ledger never recorded never left, so it is voided in the signer. A lock the
  signer resolved just before the crash is committed on its secret (y opens T1, so t = y − r).
* Calls a crash left unanswered are in doubt. The provider's next signed total may exceed the
  client's meter by at most their count × the quoted price, and that gap is adopted
  (`meter_adopted`). A larger gap is not adopted (`meter_gap`), so the mismatch stays visible.
* No payer key, signature or refund is written: they stay in the signer (`xbt-signer`, or a
  `LocalSigner` that outlives the payer). The file does hold each session's call-auth key, as
  `FileClientLedger` holds `auth_key`. That key can make metered calls on its session; it can never
  sign a state.

**Tests.**
* Rust: `tests/hub_leftovers.rs` (18) and `tests/route_payer_restart.rs` (11). Python:
  `tests/security/test_agp044_hub_leftovers.py` (18, same names).
* `scripts/refund_bump_regtest.sh` runs both hubs on Knots regtest. A refund is left out of blocks
  with `generateblock ADDR []`, bumped 1 → 2 sat/vB, replaced in the node's mempool and confirmed.
  A second run is capped (122 → 244 → 427 sat), 11/11 checks per hub.
* `route_interop.sh` adds RSSR: the payer on xbt-signer with a route ledger is SIGKILLed mid-stream,
  restarted on the same ledger and signer, and every on-chain check still holds to the sat.

Fixed along the way: `xbt402-hub` (and B1 `python -m xbt402.hub`) asked the wallet for its default
address type as the refund destination. That type is legacy on the Knots node, so every refund failed
`bad_address`. Both now ask for `bech32`.

## RouteHub reconcile fixes (AGP-045)

Three items from cmp-lead's CMP-012 review of the hub (b1 `agp-037`). All three are the same in B1's
`xbt402/hub.py` (b1 `agp-045`), with the same record fields, states, events and test names.

**1. The refill hook is looked up at each refill.** `set_refill` may be called at any time (`None`
restores `connect`). The hook is now called with no hub lock held, so a hook may replace itself or
call back into the hub. Before, `close_ch2` held the refill mutex during the call, and such a hook
deadlocked. In B1, `hub.refill` is a property (`refill or self.connect`, looked up per call), so
assigning `hub.connect` after construction takes effect.

**2. A `funding` record is not reconciled by `scantxoutset` alone.** `scantxoutset` sees only the
confirmed UTXO set, so a funding still in the mempool at `funding_timeout_blocks` used to be
dropped and never refunded. The watcher now looks in this order:
* the sends the fund wallet knows to the ch2 address: `Wallet::wallet_sends_to` (`listtransactions`)
  and `Wallet::wallet_send` (`gettransaction`: vout, sats, confirmations, abandoned), with the
  record's own `fund_txid` first;
* each send's output via `gettxout` including the mempool, and the send via
  `SpendScan::in_mempool` (`getmempoolentry`);
* `scantxoutset` last, for a fund hook outside the wallet.

What happens next:
* Found in a block or the mempool: the record is `funded`, and it opens once it has minConf.
* Not found by `funding_timeout_blocks`: the record is `dropped`, with its key kept.
  * If the wallet still knows the send (not conflicted, not abandoned), `fund_txid`/`fund_vout` are
    kept and the archived record is watched. If the send confirms late, the record becomes `funded`
    in the archive (`ch2_funding_late`) and is refunded at expiry like any unused ch2. If the wallet
    later reports it conflicted or abandoned, it is final (`ch2_funding_failed`).
  * A send that failed outright (none known, conflicted or abandoned) is dropped and final.

The new trait methods have defaults (empty or false), so existing `Wallet` and `SpendScan`
implementations compile unchanged. `Rpc` implements them.

**3. A ch2 is `closed` only on a confirmed spender.** (Since AGP-094 "confirmed" is
`spend_final_depth` blocks deep, six by default, here and in the third bullet.) A new state, `closing`, is non-final and not
live: the hub never routes over it or rolls it over.
* A provider's close seen in the mempool makes the ch2 `closing` (`ch2_closing`, with
  `refundAtRisk` when a refund fee is booked). So does `close_ch2`'s good reply.
* Lock secrets are still read off the mempool close at once.
* Only a confirmed spender sets `closed` and `final` and takes the refund fee back (`ch2_closed`,
  `refundFeeReverted`). Until then the fee stays booked (`refund_fees_sat` counts a `closing` ch2
  whose `close_prev` is `refunded`).
* If the funding is unspent again (the close left the mempool), `ch2_close_vanished` fires:
  * a ch2 that was refunded goes back to `refunded`: its fee is booked again and the refund goes out
    again;
  * any other ch2 stays `closing` and is refunded at expiry unless the close returns.

New `ch2.json` fields (both languages): `close_prev`, `fund_txid`, `fund_vout`.

**For cmp.**
* Embedders that read `state == "closed"` right after a close should expect `closing` first.
* Pass the fund wallet's RPC handle: B1 `RouteHub(..., wallet=)`, Rust through the `Wallet`
  methods.
* Handle the events `ch2_closing`, `ch2_close_vanished`, `ch2_funding_late` and
  `ch2_funding_failed`.

Tests: `crates/xbt402-interop/tests/hub_reconcile.rs` (16), and B1
`tests/security/test_agp045_hub_reconcile.py` (16) with the same names. On regtest,
`scripts/funding_reconcile_regtest.sh` runs Knots 29.4.2 with the Rust hub
(`xbt402-funding-reconcile`) and the Python hub:
* a mempool funding past the timeout is recovered and opened;
* a conflicted funding is dropped but watched, then failed (`gettransaction` confirmations −1).

## Make-before-break ch2 rollover (AGP-053)

Before this, a ch2 rollover was break-before-make. The rollover tx pays the provider and funds the
next ch2 in one tx, but the next ch2 opened only once it had the provider's minConf. Until then the
hub refused every lock to that provider (`route_blocked`); on a real chain that lasts a block
interval (cmp CMP-024). Now the next ch2 is routed at once, before it confirms. B1's
`xbt402/hub.py` and `x402_channel.py` (b1 `agp-053`) do the same, with the same fields, events and
wire.

**Why this is safe for the provider.** The next ch2 spends the old ch2's funding. That funding is the
provider's own confirmed, hub-bound channel. Before its expiry, every spend of it needs the
provider's signature, so only the provider can sign a tx that conflicts with the rollover; the hub's
refund is valid only after expiry. The provider takes the unconfirmed child (`zero_conf` on its
ledger row) only when all of these hold:
* it is the `rollover_to` of one of its own channels, bound to the same hub;
* that parent has its `conf_for` confirmations;
* the tip is below the parent's close margin (`until` = parent expiry − close_margin).

While the child is unconfirmed, the provider takes locks only up to
`ProviderConfig::rollover_zero_conf_max` (cum; default 2 × settleMultiple × closeFee; 0 turns the
feature off) and only before `until`. Otherwise it refuses `zero_conf_cap` or `unconfirmed`. It also
refuses to roll over an unconfirmed child. The watcher recomputes all of this each tick, so a reorg
of the rollover applies the bounds again, and a reorg of the parent suspends the child.

**Wire.** The only change is an optional `zeroConf: {parent, maxCum (string), until}` in the
`/x402/xbt-channel/open` reply, plus the lock refusal code `zero_conf_cap`. The routing vectors and
`/terms` are unchanged. A provider without this feature refuses the unconfirmed open, and the hub
opens the child at minConf as before.

**Hub.**
* The hub calls `/open` for the child right after the provider's rollover reply, still holding that
  provider's busy flag. The next lock therefore goes over the child. It is not refused as `funded`:
  a route request that finds a rollover child waits for the flag and is checked again once the
  flag is free.
* `route` re-reads the ch2 under the busy flag and makes the channel checks again on the ch2 the
  lock will use: pending, open, blocked, the expiry rule and the zero-conf bounds.
* The hub keeps the provider's `maxCum` and `until`, so it refuses `route_blocked` before it signs
  or sends anything past them. It never rolls over an unconfirmed child.
* New record fields: `rolled_from` and `zero_conf` (`{parent, maxCum, until, confirmed}`).
* New config key: `zero_conf_rollover` (default true).
* New events:
  * `ch2_open` with `zeroConf`;
  * `ch2_zero_conf_confirmed` and `ch2_zero_conf_reorg`;
  * `ch2_rollover_vanished` / `ch2_rollover_back`: the rollover left the mempool and the parent is
    unspent. The child is blocked with `ROLLOVER_GONE` until the provider's watcher sends the
    rollover again.
  * `ch2_rollover_replaced`: another tx spent the parent. The child never existed, so it is
    `dropped` and final, and any secrets of the parent's written-off locks are read off that tx.
* The watcher no longer starves a provider that streams locks. A tick first tries each provider's
  flag without waiting, then waits for the skipped ones between two locks: 250 ms each, 1 s per tick
  in all. Before, a tick in step with the locks could miss every gap, and a due rollover waited a
  long time.
* Liquidity is unchanged: the child reuses the old ch2's coins, so there is still one live ch2 per
  payTo and `committed_sat` counts each coin once.

Tests: `crates/xbt402-interop/tests/hub_make_before_break.rs` (13), and B1
`tests/security/test_agp053_make_before_break.py` (15). `routing_checks` c5 now expects the next
ch2 to be open at once.

On regtest, `scripts/rollover_load_regtest.sh` (ports 24900–24999; driver
`scripts/interop/rollover_load.py`, client bin `xbt402-rollover-load`) runs one lock after every call
at 15/s, one block every 3 s, for 45 s. It covers every hub × provider pair of Rust and B1. The runs:
* 7–8 rollovers per run, with zero refused locks, every call 200, max gap between paid locks
  80–197 ms;
* the pre-AGP-053 baseline (`--zero-conf-max 0`): about 24 `route_blocked` per rollover and gaps of
  3.1 s;
* a rollover held out of blocks: locks run on the unconfirmed child up to the cap, then the hub
  holds until the rollover confirms;
* a reorg across the switch: zero refusals.

Every run also checks the money on chain. Each rollover tx pays signed − closeFee to the provider and
capacity − signed to the next ch2. The total routed over all ch2s equals what the client's locks
paid.

## Routed billing throughput (AGP-054)

Before this change, cmp measured routed decode at 0.742 of unpaid (CMP-024): about 4–5 ms of billing per stage per
token. With `RouteWal`, B1's 3-stage benchmark (`scripts/route_perf.py`, 3 × 300 tokens) went from
0.833 to 0.964 of unpaid (0.973 with no durability at all), and cmp's routed end-to-end gate
(CMP-027) measured 0.894–0.923. A profile of the per-call path traced most of it to one step. cmp's `RouteJournal`
fdatasyncs every routed call's meter after the handler, before the answer: 2.5 ms on the lab's
ext4, 66% of the provider-side cost. The rails' own work is small. ROUTE-STATE signing takes
0.12 ms and the client's verify 0.03 ms (B1 with coincurve).

**`RouteWal`** (`ProviderConfig::route_wal`, `RouteOffer::precharge`; B1 `route_wal=` and
`precharge=`, same file format and rules) makes that guarantee part of the rails, without an fsync
on the critical path:
* Before the handler runs, `reserve` counts the call in flight at its expected charge and queues
  the session's projected meter `{s, v, seq, calls, acc, us}`. The expected charge is the
  precharge, or `amsat_per_call` on a flat path.
* One writer thread appends the queue and syncs it (group commit) while the handler computes.
* `end_call_reserved` returns the ROUTE-STATE only once a snapshot covering it is durable. The
  state carries the session's *current* meter, which can already hold a concurrent call metered
  in memory, or a seq a later `begin_call` took:
  * when the charge is as projected, it waits for the session's *latest* snapshot if that covers
    the state (sequentially, the call's own reserved one), else it queues a fresh one;
  * any other charge writes a corrected snapshot, which costs one more fsync.
  * A refused call's 402 `routeState` (`refusal_state`) waits the same way.
* A write failure answers `500 route_wal_failed`, with no ROUTE-STATE and nothing billed. The
  exception is a call that a later state of the session already carries: it stays billed, like a
  call in flight at a crash, so no state goes backwards.
* The routes file keeps each session projected over its calls in flight, plus `walV`. A lock that
  completes during a call therefore covers that call's reservation.
* At start, a WAL snapshot wins over the routes file when its `v` is above `walV`. Versions resume
  above `walV` even if the log was lost.
* The log is compacted to one line per session past 1 MiB.
* The writer thread ends once its provider is dropped.

After a crash:
* every answered state survives;
* a seq is durable before its handler runs, so a ROUTE-AUTH is never served twice;
* the restart counts more only for calls in flight at the crash, once each, at their projected
  charge. Those are the in-doubt chunks a client already reconciles.

**RoutePayer.** A data call no longer resolves a lock whose POST to the hub is still out. The hub's
answer settles it off the data path, so the signer's and the ledger's write-ahead fsyncs no longer
land on a chunk. A hub refusal of a lock that the provider's signed ROUTE-STATE shows as paid now
resolves it through the provider instead of voiding it.

**ROUTE-STATE.** The window's invoice is signed once per window. The bytes are identical: ECDSA
signing is deterministic, so no vector changes.

Tests: `crates/xbt402-interop/tests/route_wal.rs` (12) and `routing_checks.rs` `agp054_*` (2). In B1:
`tests/security/test_agp054_route_wal.py` (16). The measurements are in
`docs/route-perf-agp054-2026-09-30.json`, from B1 `scripts/route_perf.py`.

## Multi-process operators, rollover relay and the settle floor (AGP-056)
From cmp's CMP-027 gate: after a hub ch2 rollover, locks to that provider were refused
`route_blocked` until the next block, on almost every lock. Four causes, three fixed here (hub and
provider, the same in B1 `agp-056`) and one in cmp.

**1. ch2 identity: one per provider process.** A ch2 lives in ONE provider process's ledger, with
that process's route sessions. AGP-044 kept one live ch2 per payTo and sent the locks of a second
origin under that key to the origin that opened the ch2. With two provider processes on one operator
key (cmp merchants) that process has no session for them: `unknown_session`, and the client sees
`route_failed`. The hub keys a ch2 by the canonical origin again.
* `connect(origin)` funds that origin's own ch2. A lock goes to the origin the client named, on its ch2.
* One payTo key holds at most `ch2_max_per_pay_to` live ch2s (default 8, 0: no bound). The next
  `connect` is refused `pay_to_limit` and nothing is funded. `liquidity_cap_sat` counts every ch2.
* `OutBook::live_for_pay_to` is gone (`live_keys(pay_to)` lists them); `key_for(origin)` and
  `RouteHub::ch2_for(origin)` return the origin's own ch2 only. The event `ch2_reuse` is gone.
* A refusal names its cause: `route_blocked` "no open channel to that provider: its payTo has a ch2
  at <origin>, another provider process ...".
* An operator who serves ONE provider process at two URLs should give the hub one of them: each URL
  would get its own ch2 (they work; the capital is split).

**2. Rollover relay.** The provider broadcasts a rollover on its own node. A hub with its own node
sees it only after P2P relay, and used to block the child as vanished (`ch2_rollover_vanished`) until
the next block. Now it blocks only if its node showed the rollover before (`fund_seen`), or still
does not `rollover_relay_grace` seconds (default 60) after it (`rolled_at`).

**3. Settle floor.** `settleMultiple × closeFee` (12,600 sat at the defaults) is when a settlement is
worth its fee to the provider. With locks larger than that the ch2 rolled over on every lock.
* Hub: a due rollover waits until the ch2 has taken `settle_lock_multiple` (k, default 4) × the
  largest lock routed to that provider (`max_lock`, carried over rollovers). It never waits past the
  point where another lock of that size would not fit, and not at all once the ch2 has had no lock
  for `settle_idle` seconds (default 600). `settle_lock_multiple: 0` is the old rule.
* A rollover child that could not take one more lock of that size is not made: the ch2 is closed
  and refilled (before, such a child sat exhausted and unsigned until its expiry).
* Provider: the default zero-conf cap of a rollover child is
  `max(2 × settleMultiple × closeFee, 2 × settle_lock_multiple × largest lock on the parent's line)`
  (`ProviderConfig::settle_lock_multiple`, `zero_conf_max_for`). An explicit `rollover_zero_conf_max`
  is used as it is.
* Why k = 4: at most one rollover per four of the largest locks (the provider's close fees and the
  unconfirmed windows fall by the same factor), and with a ch2 capacity of five such locks, the
  usual sizing (100k / 20k, 200k / 40k), it is the largest k that still leaves room for one more
  lock when the rollover is due.

**4. Refusal detail.** The hub's `route_failed` for a provider refusal now carries
`provider refused the lock: <code> (<the provider's detail, printable ASCII, bounded>)`. The Rust
`RoutePayer` already returned `detail`; B1's does now.

No wire change: no new field or message, and the conformance vectors are byte-identical.

Tests: `crates/xbt402-interop/tests/hub_multi_process.rs` (21; B1
`tests/security/test_agp056_multi_process.py`, 21), each checked against 12 mutations.
`scripts/rollover_load_regtest.sh` has two more kinds, `<H>-<P>-high` and `-high-nofloor`: at 3,000 sat
a lock the floor gives a rollover per four or more locks and zero refusals, and without it a
rollover and a refusal per lock.

## The embedder surface (AGP-059)
For an application that meters a channel itself (cmp, CMP-051). Before this, cmp's payer was built
on `channel` + `wire` because `Client` took no headers and signed only its own amount, and cmp's
provider repaired the ledger's `spent_msat` after a crash. The same surface is in B1 `agp-059`
(`docs/embedders.md` there).

**Payer: its own headers and its own cumulative amount.**

```rust
use xbt402::client::CallOpts;

let headers = [("X-CMP-Payer".to_string(), identity)];
let opts = CallOpts::new().headers(&headers).cum(meter.payer_sats());   // sats, cumulative
let resp = client.request_with("POST", &url, &frame, &opts)?;
let done = client.close_with(origin, &CallOpts::new().cum(meter.payer_sats()))?;
```

`request` and `close` are these with `CallOpts::new()`. The headers go with every request of the
call (the unpaid try and the paid retry); a `PAYMENT-SIGNATURE`, an empty name or a CR/LF/NUL is
`bad_header` and nothing is sent. A chosen `cum` replaces only the amount `Client` works out from
its receipts. Everything else `Client` does still happens: the offer checks, the price pinned at
open, request auth, the receipt checks, the ledger save. The amount is bounded before anything is
signed or a seq is spent:

| a chosen `cum` | answer |
|---|---|
| below the last signed state | `bad_amount` (a state never goes down) |
| above `max_amount()` (capacity less the payer's close fee) | `exhausted` |
| above `ceil(receipted spentMsat / 1000)` + one call at the price pinned at open | `too_expensive` |
| its increase over the last signed state exceeds what is left of `daily_budget` | `budget` |
| under `min_amount()` while nothing is signed yet | sent unsigned (cum 0): never rounded up |

The third bound is the one `Client` has always had implicitly: it signs what its verified receipts
show, plus (prepay) the call it is making. So a metering embedder can sign ahead of the receipts by
at most one call, which is what a lost answer needs. `CallOpts` is `#[non_exhaustive]`: build it
with `new()`.

**Provider: close one channel now.**

```rust
let st = provider.channel_state(&chan).ok_or(...)?;
if idle && provider.settle_due(&st.params, st.best_cum, Some(provider.height()?), 0) {
    match provider.close_channel(&chan) {
        Ok(r) => info!("closed {} by {}: cum {} unpaidMsat {}", r["chan"], r["txid"], r["cum"], r["unpaidMsat"]),
        Err(e) if matches!(e.code.as_str(), "call_in_flight" | "lock_pending" | "hub_channel" | "channel_closed" | "no_state") => {}
        Err(e) => return Err(e),
    }
}
```

It is the watcher's margin close for one named channel: the same write-ahead intent, broadcast,
record and hash-lock claim (`close_locked`), with the best signed state (the conditional state when
that pays more). The answer is the cooperative close's (`chan`, `txid`, `cum`, `unpaidMsat`, and
`payeeFee`/`payeeNet` under payee-pays). Refused, with nothing changed:

| code | when |
|---|---|
| `unknown_channel` | not in this provider's ledger |
| `channel_closed` | already closed or rolled over |
| `lock_pending` | a routed lock is open on it (`route_lock`, `stale_locks`: a hub's ch1) |
| `hub_channel` | a hub-funded ch2: its hub rolls it over or closes it, and the margin close still protects it |
| `call_in_flight` | a paid call is between its reservation and its settlement: the best state does not cover it yet |
| `no_state` | the payer has signed nothing |
| `close_failed` | the node refused the broadcast (the intent stays; a later call or the watcher adopts or replaces it) |

**Provider: the reservation crash window.** A direct call reserves its maximum price in
`spent_msat` before the handler runs (saved, with the payer's state and the seq) and refunds the
difference once the charge is known. A process that died in between restarted with `spent_msat`
above what it had billed; a payer signing its own meter was then refused `insufficient_payment` on
every later call. Now:

* A metered call (a provider with `with_charge`) records its reservation in the row:
  `extra.resv = {"<seq>": msat}`. Its settlement is always saved before the answer leaves (also
  when the charge equals the price), which removes the record.
* `Provider::new` refunds every reservation still recorded and saves the rows:
  `provider.recovered_reservations()` lists `(chan, msat)` for the operator's log. After a restart
  `spent_msat` is what was charged. A metered call in flight at the crash is charged nothing: its
  charge was never durable and its answer never left.
* An unmetered call's reservation is its exact charge, so nothing is recorded and a paid call is
  still one fsync. In flight at a crash it stays charged once at its price, as before.
* A handler or charge function that panics refunds its reservation (a guard dropped unsettled), and
  a failed settlement save answers `500 ledger_error` with nothing charged.

There is no setter for `spent_msat`, and none is needed: `reconcile_direct` in cmp can go. A ledger
row written by an older build that crashed mid-call still holds its reservation unrecorded; nothing
in the row tells it from a charge, so it is not touched.

API changes for embedders: all additive. `Client::request_with`, `Client::close_with`, `CallOpts`;
`Provider::close_channel`, `Provider::recovered_reservations`; `ChannelState::reserve`, `release`,
`reserved_msat`, `refund_reservations`. Behaviour: a metered provider saves once more per call when
the charge equals the price; a ledger row may carry `extra.resv` while a call is in flight (an older
build reading such a ledger after a crash sees the reservation as spent, as it always did).
Tests: `crates/xbt402/tests/lifecycle.rs` (the last seven).

## ch2 lifecycle under load: the zero-conf cap and make-before-break refill (AGP-057)
Two things still paused routing to a provider under load. Both are fixed in the hub (and one line in
the provider), the same in B1 `agp-057` (`docs/routing.md` there). No wire change.

### A. The zero-conf cap of a rollover child (cmp CMP-149)
cmp saw about 20 `route_blocked` per R14 replay: "the rollover funding this ch2 is unconfirmed: cum
134687 > the provider's zero-conf cap 132120". The cap is the provider's bound on what it takes over
a rollover child that is still unconfirmed (`rollover_zero_conf_max`; by default
`max(2 × settleMultiple × closeFee, 2 × settle_lock_multiple × the largest lock)`, here 8 × 16,515).

Reproduced at cmp's lock size with four new kinds of `scripts/rollover_load_regtest.sh`: 16,515-sat
locks at 2/s for 28 s on a 1,000,000-sat ch2, settleMultiple 20. `cmp`: cmp's own cadence (a block
whenever the mempool is not empty, looked at every 0.4 s; the hub's watcher every second). `cmp-lag`:
the watcher every 5 s (the hub's default). `cmp-slow`: a block only every 6 s. `cmp-slow-sized`: the
same with the provider's cap sized for it (`--zero-conf-max` 24 locks). Every cap refusal is
classified: was the child's rollover in a block already (the hub's flag was stale), or not.

| run | refused before (base `25f5e2f`) | paid | max gap ms | refused after | paid | max gap ms |
|---|---|---|---|---|---|---|
| `RS-RS-cmp` | 0 | 56 | 529 | 0 | 56 | 521 |
| `PY-PY-cmp` | 0 | 56 | 525 | 0 | 56 | 547 |
| `RS-RS-cmp-lag` | 6 (6 stale flag, 0 unconfirmed) | 50 | 2,517 | 0 | 56 | 515 |
| `PY-PY-cmp-lag` | 2 (2 stale flag, 0 unconfirmed) | 54 | 1,517 | 0 | 56 | 515 |
| `RS-RS-cmp-slow` | 13 (1 stale flag, 12 unconfirmed) | 43 | 4,507 | 12 (0 stale flag, 12 unconfirmed) | 44 | 4,510 |
| `PY-PY-cmp-slow` | 13 (1 stale flag, 12 unconfirmed) | 43 | 4,497 | 12 (0 stale flag, 12 unconfirmed) | 44 | 4,493 |
| `RS-RS-cmp-slow-sized` | 0 | 56 | 532 | 0 | 56 | 519 |
| `PY-PY-cmp-slow-sized` | 0 | 56 | 556 | 0 | 56 | 524 |

Reports: `docs/rollover-load-agp057-cap-before-2026-10-03.json` and `...-cap-after-...` (each run's
`capDiagnosis` has the refusals one by one). The command, in a 20-port grant:

```sh
XBT_RS_LOAD_PORT_BASE=42000 XBT_RS_LOAD_PORT_SPAN=20 \
LOAD_ONLY=RS-RS-cmp,PY-PY-cmp,RS-RS-cmp-lag,PY-PY-cmp-lag,RS-RS-cmp-slow,PY-PY-cmp-slow,RS-RS-cmp-slow-sized,PY-PY-cmp-slow-sized \
  lazvault heavy --project xbt-agentpay -- ./scripts/rollover_load_regtest.sh
```
(the before column: the same command on the base commits, `XBT402_B1` at the B1 checkout).

What the runs say:

* **Nothing of the parent is carried into the cap.** A child's cum starts at 0 in the hub and at the
  provider; `childCumCarried` is 0 in all 16 runs.
* **The hub's stale flag (fixed).** The hub refuses before it sends anything, on its own
  `zero_conf.confirmed`, and that flag was only the watcher's last look: a child that had confirmed
  was refused until the next tick. Before a lock is refused on either of the provider's bounds (the
  cap, the parent's close margin) the hub now looks at the chain itself, as the provider already did.
  A node that does not answer leaves the bound standing (`ch2_watch_error`, step `zero_conf`).
* **A block that lands while the provider checks the child (fixed).** Found by a `cmp-lag` run after
  the first fix. The provider read the child's funding unconfirmed; then the block with the rollover
  came, so the parent was spent in a block and the child was no zero-conf child any more. The open was
  refused `unconfirmed` although the child was confirmed, and the ch2 stayed `funded` until the hub's
  next tick (10 refusals at a 5 s watcher). `Provider::open` reads the funding once more before it
  refuses. A refused open is also written to the hub's stderr now.
* **The provider's own stale look at a lock (fixed).** The provider's watcher can meet the block the
  same way and leave a confirmed child `suspended` until its next tick: a lock in between was refused
  `unconfirmed` (two `route_failed` in a first `RS-RS-high-nofloor` run). Before it refuses a lock on
  a suspended rollover child the provider now reads the chain, as the hub does before it sends one.
  Any other suspended channel is refused as before.
* **A child that really is unconfirmed is still refused (sizing).** With more than the cap's 8 locks
  per block interval the hub refuses, as it should: that is the provider's risk bound (`cmp-slow`:
  12 of the 13 before, and all 12 after). How many depends on where the blocks fall. A provider paid faster than
  8 of its largest locks per block sets `rollover_zero_conf_max` to what it earns from one hub in a
  block interval or two (`cmp-slow-sized`: zero refusals).

Which of these cmp hit cannot be read off its logs (they carry no block times). Its topology (the
hub, the operator and the miner on three nodes) adds relay time to the first case.

### B. Make-before-break refill
A rollover adds no coins, so a ch2 line carries its capacity in locks and was then closed and
refilled. The refill is a wallet funding, which the provider cannot take unconfirmed (its payer could
spend it again), so it opened at minConf: a block without routing to that provider.

* **Funded ahead.** Once the live ch2's room is under `refill_ahead_locks` (N, default 4) × the
  largest lock routed to that provider, the watcher funds the origin's NEXT ch2
  (`OutBook::next_chans`, at most one per origin; `RouteHub::connect_next`). Room is what the line
  still takes: `max_amount − signed`, less the provider's `minCapacity` (a rollover child under it is
  not made). Not for a provider the hub stopped routing to, nor one with no lock for `settle_idle` s.
* **Usable** means open at the provider, at its minConf. The live ch2 keeps taking locks meanwhile,
  rollovers included.
* **The switch** (`ch2_switch`): with the first lock the live ch2 cannot take (exhausted, no longer
  open, or an unconfirmed rollover child at the provider's bounds); when the live ch2 is closed as
  too small to roll over (`close_ch2(.., true)` hands over instead of funding; while the next one is
  funded but not open yet and the live one still takes a lock, it is kept: `ch2_wait_next`); or once the live ch2
  has had no lock for `settle_idle` seconds, so two ch2s do not stay committed to an idle provider.
  Never while a lock is pending on the live ch2, and never because the hub stopped routing to the
  provider (a lock it did not reveal).
* **The old ch2** is `retired`: the watcher asks the provider to close it on its best state (once a
  block until it answers) and reconciles it like any archived ch2. One with nothing signed has
  nothing to close and is refunded at its expiry, as an unused ch2 always was.
* **Bounds.** Per origin: one live ch2 plus at most one next (the AGP-056 guard, widened). An origin
  counts once for `ch2_max_per_pay_to`. `committed_sat` counts the live ch2, the next one and a
  retired one until its close is out, so `liquidity_cap_sat` needs room for one more `ch2_capacity`
  than the hub has origins. Without it nothing is funded ahead (`ch2_refill_ahead_failed`, tried
  again next block) and the refill follows the close as before.
* **Sizing N.** N locks must cover what the provider is paid while a funding confirms and opens: the
  locks of one block interval plus one watcher tick. `refill_ahead_locks: 0` is the old behaviour.
* **Embedders.** `RouteHub::set_refill_ahead` replaces the default (`connect_next`). An embedder that
  set its own `refill` and no `refill_ahead` gets none: its path, lock and cap are never bypassed.
  `ch2.json` has a new key `next_chans`, and a record a new field `retired`.

Events: `ch2_refill_ahead` {live, next, room, maxLock, capacity}, `ch2_refill_ahead_failed`,
`ch2_switch` {from, to, why}, `ch2_wait_next`, `ch2_retire_failed`.

**Exhaustion under load** (`<H>-<P>-exhaust`): 3,000-sat locks at 2/s for 60 s over a ch2 of 120,000
sat (40 locks), a block every 3 s, `refill_ahead_locks` 16, `liquidity_cap_sat` 240,000. The line
runs out three times. `-exhaust-before` is the same with `refill_ahead_locks` 0.

| run | refused | paid | max gap ms | gaps > 1 s | wallet-funded ch2s | funded ahead | max committed sat | closes | rollovers |
|---|---|---|---|---|---|---|---|---|---|
| `RS-RS-exhaust` | 0 | 120 | 531 | 0 | 4 | 3 | 186,000 | 3 | 20 |
| `PY-PY-exhaust` | 0 | 120 | 525 | 0 | 4 | 3 | 186,000 | 3 | 20 |
| `RS-PY-exhaust` | 0 | 120 | 616 | 0 | 4 | 3 | 186,000 | 3 | 20 |
| `PY-RS-exhaust` | 0 | 120 | 525 | 0 | 4 | 4 | 189,000 | 3 | 20 |
| `RS-RS-exhaust-before` | 12 | 108 | 3,995 | 3 | 4 | 0 | 120,000 | 3 | 10 |
| `PY-PY-exhaust-before` | 11 | 109 | 3,494 | 3 | 4 | 0 | 120,000 | 3 | 9 |

```sh
XBT_RS_LOAD_PORT_BASE=42000 XBT_RS_LOAD_PORT_SPAN=20 \
LOAD_ONLY=RS-RS-exhaust,PY-PY-exhaust,RS-PY-exhaust,PY-RS-exhaust,RS-RS-exhaust-before,PY-PY-exhaust-before \
  lazvault heavy --project xbt-agentpay -- ./scripts/rollover_load_regtest.sh
```
Report: `docs/rollover-load-agp057-exhaust-2026-10-03.json`. Each run also checks the money: every
rollover tx pays the provider signed − closeFee, every replaced ch2 is closed on its signed state
and confirmed, routed over all ch2s equals what the client paid, nothing pending or written off.

Tests: `crates/xbt402-interop/tests/hub_refill_ahead.rs` (25; B1
`tests/security/test_agp057_refill_ahead.py`, 25, where 12 of 13 mutations of the hub are caught and
the 13th is equivalent). The older test worlds set `refill_ahead_locks: 0`, as they set
`settle_lock_multiple: 0`.

**The older runs, again** (the AGP-053 and AGP-056 kinds, on this commit; 45 s at 15 locks/s, the `high`
kinds at 2/s). The make-before-break runs still refuse nothing; `-before`, `-stuck` and `-high-nofloor`
are the baselines that refuse by design.

| run | refused | paid | max gap ms | rollovers | checks |
|---|---|---|---|---|---|
| `RS-RS` | 0 | 675 | 115 | 8 | PASS |
| `PY-PY` | 0 | 586 | 131 | 7 | PASS |
| `RS-PY` | 0 | 603 | 232 | 7 | PASS |
| `PY-RS` | 0 | 594 | 127 | 7 | PASS |
| `RS-RS-before` | 143 | 532 | 3,206 | 6 | PASS |
| `PY-PY-before` | 134 | 502 | 2,722 | 3 | PASS |
| `RS-RS-stuck` | 158 | 456 | 14,287 | 2 | PASS |
| `RS-RS-reorg-zero` | 0 | 656 | 123 | 8 | FAIL: reorg: the hub saw the child unconfirmed again |
| `PY-PY-stuck` | 193 | 389 | 14,034 | 2 | PASS |
| `RS-RS-reorg` | 35 (35 in the reorg window) | 640 | 2,299 | 5 | PASS |
| `PY-PY-reorg` | 32 (32 in the reorg window) | 592 | 1,535 | 5 | PASS |
| `RS-RS-high` | 0 | 90 | 554 | 16 | PASS |
| `PY-PY-high` | 0 | 90 | 525 | 16 | PASS |
| `RS-RS-high-nofloor` | 74 | 16 | 3,512 | 16 | PASS |
| `PY-PY-high-nofloor` | 74 | 16 | 3,503 | 16 | PASS |

Reports: `docs/rollover-load-agp057-a-2026-10-03.json` and `...-b-...` (two batches of the 20-port grant).

* The `reorg` runs refuse inside the reorg window, which their checks allow and earlier reports did
  not show (AGP-053: 0 and 0): here the first rollover waited a whole block interval (3.0 s) for its
  block, the reorg held it 5 s more, and at 15 locks/s the child's cap (100 locks) is 6.7 s of
  traffic. In AGP-053's report the block came 0.4 s after the rollover. So it is where the block
  clock falls against the first rollover (probably the driver's changed start-up timing; not
  isolated), and every refusal is the reorged child's zero-conf cap.
* `RS-RS-reorg-zero` is an optional kind added to the batch: zero refusals, re-confirmed. Its check
  "the hub saw the child unconfirmed again" fails: the block was re-mined 52 ms after the reorg,
  between two watcher ticks. Whether that check ever held for this kind was not measured on the base.

**The driver in a small port grant.** `XBT_RS_LOAD_PORT_SPAN` under 100 packs the selected runs two
ports each from base + 4 (8 runs in 20 ports). Such a grant (42000-42019 here) lies in the kernel's
ephemeral range (`ip_local_port_range` 32768-60999) and outside `ip_local_reserved_ports`
(30000-34999 on that host, where the default base was 349xx at the time; the default is 24900 now, below the ephemeral range): any local connection can hold one of
its ports as its source port for a moment, a poll of that very port included, and a hub or provider
then cannot bind it (`Address already in use`; it cost three runs their start today). The driver
therefore waits for a process's "ready" line before it polls its port, and starts one that exited
before that line again.

## Hub routing safety (AGP-064)
From an external review of the hub: two High findings, H1 and H2, where the hub could pay a
provider on ch2 without being able to collect from the client on ch1. There was also a test-only
nonce API in the library. Both were still present on `main` (`e0b832a`), and the tests below
reproduce each one there. The same changes are in B1 `agp-064-w4`, with the same test names. The
hub is now marked **experimental** (above, and in `xbt402-hub`'s startup log).

**H1: a ch1 close while a lock is in flight.** `route()` writes ch1's `route_lock`, lets go of
ch1's ledger, and then forwards to the provider for up to `reveal_timeout`. A cooperative close in
that gap closed ch1 below the lock, and the provider was still paid on ch2.
* The provider's `POST /x402/xbt-channel/close` now refuses a close with `lock_pending` while ch1
  has a routed lock its best state does not cover: the lock in flight, or a written-off lock above
  `best_cum`. A written-off lock that `best_cum` covers does not block. `close_channel` (AGP-059)
  uses the same test.
* The margin close lets a lock in flight finish, but only in the first half of the margin (the
  lock takes seconds). It never waits for a written-off lock: a skipped margin close would let the
  payer refund the whole channel at expiry.
* A lock that completes after ch1 was closed below it (an operator's `close_now`, or a margin close
  past its wait) is never counted as routed. It is counted in `HubStats::uncollected`, and the
  event is `lock_uncollected`.
* A ch1 lock that no route is forwarding and that sits on no ch2 can never complete: the hub
  stopped between its two write-aheads, or the `withhold "all"` test hook was used. The hub drops
  it when the client asks to close (`orphan_lock_dropped`), so it does not keep ch1 from closing.
  (AGP-073: the watcher sweeps these too, and holds one its ch2 wrote off.)
  This is checked under the provider's busy flag, which `route()` holds from before it writes the
  lock until its forward ends, so a lock in flight is never dropped.

**H2: written-off locks were superseded.** A lock is written off at `reveal_timeout`, or when the
provider refuses it. (Since AGP-094 a refusal at the hub's check writes nothing off and blocks
nothing; a lock is written off only when a provider said yes and then refuses or does not reveal.
See "Fix wave 5, the hub and the routed client".) Its ch2 pre-signature may already be out: a slow honest provider can still
use t, and so can one that answers 400 and keeps the pre-signature. The client's next lock was
quoted on the old base, so its state did not include the written-off amount, and a t read later off
the ch2 close collected nothing.
* **Hold.** If the lock was pending on ch2 when it was written off (the pre-signature may have
  left), ch1's counters (`routed_sat`, `fee_units`, `fee_paid`) are raised to the lock's `after`.
  What was added is stored on the lock (`stale_locks[].hold`). Later locks are quoted above it, so
  a t read off the ch2 close later still collects. A write-off whose pre-signature never left
  ("ch2 exhausted", a failed pre-sign, a final ch2) holds nothing and is not kept.
* **Block.** No route over a ch2 with written-off locks (`route_blocked` "a written-off lock on
  this ch2 is unresolved"), and no rollover of it: `rollover()` refuses with `lock_pending`, and
  the watcher does not roll it over. The ch2's close shows whether t was used; its refund shows it
  was not.
* **Release.** A confirmed refund, or a confirmed provider close that does not reveal the lock's t,
  proves it unpaid. The hold leaves the base (`lock_released`), and the lockId goes on ch1's
  `released` list (the last 64). The client is then quoted below its signed state (the dust floor)
  until what it signed ahead for that lock is used.
* **`max_lock_sat`.** A written-off lock holds the client's base and blocks its ch2 until that ch2
  resolves, so a lock should be small next to a ch2. The default is now 20,000 sat (a fifth of the
  default `ch2_capacity`, was 50,000). `HubConfig::from_json` refuses 0 or more than half of
  `ch2_capacity` (`bad_config`).

**The client (`RoutePayer`).** A given-up lock now records the counters `before` it as well as
`after`, whether it was a floor lock, and whether the hub `held` it. Floor locks are recorded too:
the hub can hold one. `resync` adopts three hub views, each only when it matches a lock the client
gave up:
* completed: as before, the hub's best state is that lock (also after a hold);
* held: the hub's counters are the lock's `after`, ours are its `before`, and its lockId is in
  `held`;
* released: our counters minus the released holds equal the hub's.
A refusal that carries `held` is resynced at once. A held entry is kept until its release or
completion: the 16-entry list drops the oldest entry that is not held.

**Nonces.** `adaptor::presign_with_nonces` (caller-chosen k and w, for the routing vectors) is
compiled only under `cfg(test)` or the `vector-emitter` feature, which only `xbt402-interop`
enables. `presign` uses a private inner function. The routing vectors are byte-identical
(`conformance.sh` step 4, 79/79). B1's `presign` never took nonces.

**For embedders (cmp).** These are the wire and behaviour changes:
* `POST /x402/route` refusals with ch1's view (`bad_amount`, and now also the 502 `route_failed`
  of a held write-off) carry `held: [lockId]` and `released: [lockId]` beside `bestCum`,
  `routedSat`, `feeUnits` and `feePaid`. Before, the 502 `route_failed` carried only
  `providerError`. Old clients ignore the new fields.
* A client close of a ch1 with a routed lock open is refused `lock_pending` (400). Retry it after
  the lock resolves.
* After a write-off, that provider's ch2 is `route_blocked` until the ch2 closes or is refunded
  (what counts as a write-off changed in AGP-094: see the note at H2 above).
  The hub's switch to a ch2 funded ahead (AGP-057) can still take over.
* `RoutePayer`'s persisted ledger: entries in `given_up` gain `before`, `floor` and `held`. Older
  records load, with `before` taken as `after`.
* `max_lock_sat` above half of `ch2_capacity` is now a config error. The default is 20,000.
* `HubStats::uncollected`, and the events `lock_uncollected`, `lock_released`,
  `orphan_lock_dropped`, `resync_hold` and `resync_release`; `void` gains `held`.
* `presign_with_nonces` is gone from the default build (enable `vector-emitter` to get it).

Tests: `crates/xbt402-interop/tests/hub_routing_safety.rs` (8; B1
`tests/security/test_agp064_hub_safety.py`, the same 8 plus the config test). All of them fail on
`main` and pass here:
* H1: `h1_close_while_a_lock_is_in_flight_is_refused_either_order` (lock then close, and close
  then lock), `h1_a_lock_completed_after_ch1_closed_below_it_is_not_counted`,
  `h1_the_margin_close_lets_a_lock_in_flight_finish`,
  `h1_a_lock_the_hub_never_forwarded_does_not_keep_ch1_open`;
* H2, both unfriendly orders: `h2_a_slow_provider_stays_in_the_base_and_a_later_route_sits_above_it`
  (the answer lost, then t on the close) and
  `h2_a_refused_lock_stays_in_the_base_and_blocks_routing_and_rollover` (400 with the
  pre-signature kept: routing and rollover refused, then t on the close);
  `h2_a_refunded_ch2_gives_the_unpaid_hold_back` and
  `h2_a_void_whose_pre_signature_never_left_holds_nothing`;
* `hub::tests::max_lock_sat_defaults_small_and_is_at_most_half_of_ch2_capacity`.

The tests use a wrapper `HttpService` around the provider (it holds the provider's answer at a
gate, or turns it into a 400), so the shipping code has no new test hooks. Two existing tests
changed with H2, because a provider's refusal now blocks that ch2:
`hub_make_before_break::provider_enforces_its_cap_and_margin_itself` and
`hub_refill_ahead::a_child_the_providers_watcher_left_suspended_is_looked_at_before_a_lock_is_refused`
(the same two in B1).

**Trade-offs.**
* An honest slow provider, once written off, can leave the client paying the lock twice: once in
  the held base, and once by rerouting the same service. The provider's own meter credit is out of
  the hub's reach.
* A provider that refuses after taking the pre-signature stops its ch2 for that ch2's lifetime
  (close or refund). This is the spec's choice (no route over a stale ch2). The follow-up was to
  close and refill such a ch2 early: AGP-073 does.

## Agent-wallet budget integrity and privileged methods (AGP-063)

Fixes for the external review's agent-wallet findings W1-W4, X1 and K1, plus the library payer's watermark.
Each test fails on `main` and passes here (the run is in the task's `result.md`). Most are in
`crates/xbt-signer/tests/review_w.rs`; B2's port (branch `agp-063`) has the same names in
`tests/test_review_w.py`.

**W1: the wallet books what it signs.** `xbt402_pay` books the **signed delta**: the cumulative amount
signed after the call, minus what the policy ledger already holds for that channel
(`ledger_booked_sats`). It never books `charged` from the seller's PAYMENT-RESPONSE. The receipt is
still checked: the payee's signature, the request digest and channel, a `cum` no higher than the one
signed, and a `charged` that is neither negative nor above the quote. A bad receipt does not change
what is booked. Since AGP-089 the receipt must also carry the `seq` of this request, an answer below
400 without a good receipt is refused (`deny/bad_receipt`, its body is not handed on), and a state
counts as arrived only on such a receipt (anything else leaves it unacked: the next call sends the same
state again). Since AGP-095 that next call signs one new state when the seller answers the state sent
again with a 402 that names it (`insufficient_payment`, this channel, this `cum`, this `seq`): see
"Fix wave 5, agent wallets" below. An error answer's bad receipt is still reported as
`receipt_error`. The answer also carries `booked_sats`.
- **When it books.** The `pay` channel rail, `sign_state`, `xbt402_sign_state_a3`, the rollover and
  `xbt402_sign_conditional` book before they sign, and take the row out again if signing fails.
  `xbt402_pay` books after the state is persisted and before it is sent; a crash in between is
  booked by the next call.
- **No double count.** The ledger txid is `xbt402:<chan>:<cum>`, so a restart books an increase once.
- **No lower state.** A lower `cum` is `deny/amount`.
- **No negative rows.** A negative payment or amend row is refused, both when written and when the log
  is loaded, so a row can never lower a daily, weekly or per-seller total.
- **Streams.** The stream budget is `max_sats` minus what was booked.
- **The budget check.** The per-tx limit, the human threshold and approvals still apply to the amount
  asked (`max_sats`, or `pay`'s `amount_sats`). The daily, weekly, per-seller and split sums apply to
  what the call can book (`PolicyEngine::evaluate_booking`). On an open channel that is known before the
  402: `next_cum(max_sats)` minus the booked amount. A call that fits the budget exactly is paid, even
  when `max_sats` alone would not fit.
- **The dust floor.** A new channel's first state signs the dust floor (546) when the price is below
  it. Those 546 sats are booked, and that first state is allowed even when `max_sats` is lower (500 in
  the runbook). When the floor is more than the amount asked, the budgets are checked again on the whole
  floor before anything is signed, on both rails (the session's `set_spend_check` hook for
  `xbt402_pay`). A floor that does not fit is refused with the budget's rule, and the reason names the
  dust floor. Tests: `w1_the_budget_is_checked_on_the_signed_increase_not_max_sats`,
  `w1_a_dust_floor_above_the_remaining_budget_is_refused` and
  `w1_the_dust_floor_on_the_pay_rail_is_held_to_the_budget`.
- **Old records.** A record from before this field loads as booked through `used_sats` and does not
  gain the key, so B2 still loads it.

**W2: the seller cannot raise the cap.** An offer whose `minCapacity` is above the owner's per-channel
cap (the cap plus the payer's close fee, which is what `minCapacity` bounds) is refused with
`deny/min_capacity` before any funding. The combined W1+W2 test (a huge `minCapacity` and a receipt
of zero) stops at the owner's cap.

**W3: what a process on the agent socket can still do.** The agent socket is shared with the
model-facing MCP process, so every method there that moves or commits coins either stays inside the owner's policy or needs the
human's ed25519 signature. (Corrected by AGP-107: this said "every method". Some methods are
neither and move nothing: `xbt402_new_key` issues payer keys without limit, and `xbt402_funded`
(AGP-101) tells any caller which channel the signer funded for a seller.)
- **`fund`** pays only a channel for a payer key this signer issued (`xbt402_new_key`) to that origin,
  and only to the seller's verified terms. The verified payTo is the policy's
  `counterparties[origin].pay_to`, else the seller's `GET <origin>/x402/xbt-channel/terms`, which the
  signer fetches itself, only for an allowlisted origin or routing hub, and checks for the right
  network. The channel must also have:
  - the hot key's change script;
  - a close fee within `close_fee_max_sats`;
  - an expiry in (`refund_margin_blocks`, max(`channel_expiry_blocks`, 4032)] blocks;
  - a capacity within `per_counterparty_cap_sats` plus the payer's fee.

  The funded channel is written ahead as pending, so the watcher refunds it at expiry if no attach
  follows. Without `origin` and `params` the answer is `deny/fund_unbound`. Other codes:
  `bad_key`, `pay_to`, `payer_spk`, `close_fee`, `expiry`, `channel_cap`, `bad_address`,
  `channel_open`, `channel_pending`.
- **`open_channel`** takes payTo only from the policy; a different `pay_to` parameter is `deny/pay_to`.
  The dest must be allowlisted, and `cap_sats`, `expiry_blocks` and `close_fee` must stay inside the
  owner's bounds.
- **`xbt402_attach`** of a funded channel must match the pending record `fund` wrote. A `/next`
  channel passes the same checks as `fund`, and is attached only once the signer's own node shows
  the rollover that funds it (AGP-080; `deny/rollover_unproven` until then).
- **`xbt402_sign_rollover`** needs `next`: the unfunded params of the channel's own next channel. Its
  script must be `next_spk`; it must have the same close fee and fee payer; its capacity must be
  exactly `rollover_next_capacity(amount)`; and it passes the `fund` checks for `<origin>/next`.
  A bare `next_spk` is `deny/rollover_unbound`. Only the increase in the signed amount is booked, not
  the new channel's capacity, because that capacity is the wallet's own refundable channel and
  booking it as well would count the same sats twice.
- **`rotate_hot_key`** needs the human signature over `rotate_message(hot_address, expiry)`; it is
  the same method as `rotate_hot_key_signed`. Codes: `human_key`, `human_sig`, `expired`.
- **`deny_approval`** of an approval that has not expired needs the human signature over
  `deny_message(token, expiry)` (domain `xbt-agentwallet-deny-v1`), so the agent cannot refuse for
  the owner. An expired one can still be dropped without a signature. The UI signs it in the page,
  like approve.

**W4: the first human key.** While no human key is enrolled, the signer prints a one-time enrolment
code (`XXXX-XXXX-XXXX`, 60 bits) to stderr and writes it to `.run/enroll-code` (0600).
- **Enrolling.** `human_key_enroll` needs `code`. Five wrong codes replace it with a new one. Success
  removes the code and the file.
- **Where the owner finds it.** On Umbrel it is in the app's log (the app page, then Troubleshoot).
  On StartOS it is in the service's Logs. Elsewhere it is on the signer's stderr or in
  `.run/enroll-code`. The UI's enrolment form says so.
- **Host and Origin.** The UI answers only to IP literals, single-label names (`localhost`, a
  container name), `*.local`, `*.localhost`, `*.onion`, and the names in `XBT_UI_ALLOWED_HOSTS`;
  anything else is 421. A POST whose `Origin` is not one of those hosts is 403. `Origin: null` is
  accepted, because the UI sends `Referrer-Policy: no-referrer` and Chrome then sends `null` on
  same-origin form posts. The Host check is what stops DNS rebinding.

**X1: the MCP HTTP transport.**
- **The token is always required.** With a data dir it is the `mcp-http-token` secret, generated on
  first run. Without one it is `<signer socket dir>/mcp-http-token` (0600), generated on first run
  and read again on restart. A non-loopback listener with no token is refused at start.
- **Origin is checked whether or not `--http-allow-remote` is set.** It must be a loopback origin or
  one of `XBT_MCP_ALLOWED_ORIGINS` (comma-separated). There is no same-origin exception, because a
  DNS-rebound page has Origin equal to Host.
- **Local payer mode** checks the signer's allowlist before any request to a URL, so a refused origin
  is never probed. Since AGP-105 the host the allowlist is checked on is the host the request is sent
  to: a URL whose host two parsers could read differently is refused first (`wire::sendable_url`).

**K1: key storage.**
- **scrypt cost.** A passphrase blob is sealed at scrypt N=2^17 (r=8, p=1, 128 MiB) and records
  `log_n`. A blob without `log_n` (B2 and older Rust files) opens at 2^15, and only 15..=18 are read.
  The measurements and the comparison with argon2id are in the task's `result.md`. The default
  (Umbrel/StartOS) wrapping key is a key file, which has no KDF.
- **Zeroised secrets.** Wrapping keys, the passphrase, derived keys and the key-file bytes are held in
  `Zeroizing` buffers.
- **Key file.** The key file (after symlinks are resolved) must be a regular file with no group or
  other bits; otherwise the signer refuses to start.
- **Durable approvals.** `PolicyStore::write` (the approvals document) writes a temp file, fsyncs
  it, renames it, fsyncs the directory and sets mode 0600.
- **xbt-svc ownership changes.** `xbt-svc` `own_dir`, `chown_tree` and `put_secret` open each entry
  with `O_NOFOLLOW` and chown or chmod it through that fd. Children are named through
  `/proc/self/fd/N`, so an entry swapped for a symlink during the walk is never followed.
- **Deferred: sealing the hub's ch2 payer keys.** They are still stored as hex in the hub state
  (AGP-064 is changing `hub.rs` now, and B1's `hub.py` shares the file format).

**The library payer's watermark.** `Payer::sign_state_a3` and `Payer::sign_conditional` refuse an
amount below the highest one signed (`stale_amount`) and advance it, as `sign_state` already did.

**Wire changes for embedders (cmp, B1 clients, scripts).**

| change | before | now |
|---|---|---|
| `fund` | `{address, sats}` | `{origin, params, address?, sats}`; `xbt402::client::Wallet::fund_channel` (`RemoteSigner` sends it) |
| `xbt402_sign_rollover` | `{chan, amount, next_spk, next_capacity}` | the same plus `next` (the next channel's params); `StateSigner::sign_rollover_next` |
| `xbt402_pay` answer | `charged_sats` | plus `booked_sats` and, for a bad receipt, `receipt_error` |
| `xbt402_pay` / `pay` budget | sums held to `max_sats` / `amount_sats` | sums held to the signed increase; a dust floor above the budget is `deny/<budget rule>` |
| `Session` (Rust) / `Xbt402Session` (B2) | `set_spend_book` | plus `set_spend_check(dest, max_sats, delta)` |
| `rotate_hot_key` | no params | `{expiry, signature}` |
| `deny_approval` | `{token, reason}` | plus `{expiry, signature}` while the approval is live |
| `human_key_enroll` | `{pubkey}` | `{pubkey, code}` |
| MCP HTTP | token optional on loopback | always a bearer token; Origin is checked; `XBT_MCP_ALLOWED_ORIGINS` |
| web UI | any Host | Host allow-list (`XBT_UI_ALLOWED_HOSTS`) and an Origin check on POST |
| keystore blob | no `log_n` | `"log_n": 17` on passphrase blobs |

## Request binding and the HTTP server (AGP-068)

review T1–T4. A few slow connections must not stall a provider, and a receipt binds one request and
the answer that was actually returned. B1 `x402_channel.py` on `agp-068` (`5032212`) does the same, and
`tests/test_agp068.py` there uses the same test names.

**Wire (v1.3).** `extra.derivation` is `"v3"`, and it is the only version signal: a v1.2 client
requires `"v2"` and refuses the offer before it funds. The payee key is still
`xbt-channel/payee/v2`. There is no separate binding flag, because an old client echoes whatever
terms it was given, so a server-side check of one would never fire.

- `request_digest_v2` is
  `tagged_hash("xbt402/req/v2", f(method) ‖ f(scheme) ‖ f(host) ‖ f(port) ‖ f(target) ‖ f(body))`
  with `f(x) = LE64(len(x)) ‖ x`. Scheme and host are lowercased, the port is decimal or the
  scheme's default, userinfo and fragment are dropped. A provider reached at another origin, or a
  `|` moved between target and body, gives another digest. A bare target binds no origin. Since
  AGP-081 a URL or target with a `#` is refused by payer and provider before the digest is taken.
- The client binds `origin + path`, and the server binds the URL it rebuilt from the request.
- Receipts are `tagged_hash("xbt402/receipt/v2", …)` over the length-prefixed chan, seq, cum,
  charged, spentMsat, req, status and bodyHash (sha256 of the body sent). The client checks status
  and bodyHash against the bytes it received (`bad_receipt`). On a conditional call the hash lock
  stays pending until the receipt checks out, so after a `bad_receipt` `recover_conditional` still
  reads k from the provider's claim.
- `seq` is the call's own, and cum and spentMsat come from the call's reservation (less its own
  refund), not from whatever another call wrote meanwhile. A seq spent on a refusal is saved before
  the 402 goes out (a 500 if that save fails), so a replay after a restart is still `bad_auth`.
- xbt-work moved to request binding v2 with the XBT-053 vectors (AGP-074): see "Embedders on
  xbt402 v1.3 (AGP-074)".

**HTTP server (`http-server` feature).** It is now `std::net`:

- header lines are capped at 8 KiB and the header block at 32 KiB (431);
- at most 64 connections, then 503 (since AGP-081 at most 48 of them from one client address);
- the head must arrive within 10 s (408) and the body within 30 s, both as absolute deadlines;
- only Content-Length bodies (Transfer-Encoding gives 501), and `Expect: 100-continue` is honoured;
- `Connection: close` on every answer;
- bodies are read on the connection thread, so a slow body cannot occupy a worker. Jobs go to the
  workers through a bounded queue, and a panicking handler costs a 500, not a worker (in a
  `release-small` build, which aborts on panic, it ends the process).

The URL the digest is checked against is rebuilt from `Host`, the target and `X-Forwarded-Proto`
(`https` or `http`). Both headers are client-controlled, so trusting them gives an attacker nothing
it could not already send. Behind TLS, put a reverse proxy in front that overwrites both with the
URL the payer used. For example, with nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8402;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_request_buffering on;     # the proxy, not this process, absorbs slow bodies
    client_max_body_size 1m;
}
```

**Client (T3).** The payer's `ureq` transport refuses a declared Content-Length over 64 MiB
(`response_too_large`) and a body shorter or longer than declared (`response_truncated`), instead
of returning a short buffer. B1's `_read_capped` uses the same codes.

Options weighed for the server (best-performing-stack rule):

| option | slowloris / long headers fixable | new dependency | other cost |
|---|---|---|---|
| keep `tiny_http`, wrap it | no: its listener thread reads heads with no deadline or line cap | none | the bug stays |
| vendor and patch `tiny_http` | yes | none (but a fork to carry) | maintaining a fork |
| `rouille` | no | yes | built on `tiny_http` |
| `hyper` | yes | yes, with an async runtime (tokio) | larger binary, a runtime on Pi-class devices |
| `may_minihttp` | partly | yes | coroutine runtime, heavy use of `unsafe` |
| **`std::net`, ~360 lines (chosen)** | yes | **none** (`tiny_http` dropped from xbt402) | ours to maintain; tested in `http_limits.rs` |

**Cost.** Pass line declared before measuring: (a) the added per-call hashing (the v2 digest twice
on the server, v2 receipt framing, bodyHash of a 4 KiB answer) is at most 5% of one ECDSA receipt
signature; (b) bodyHash on armv7 keeps up with a 100 Mbit/s link (12.5 MB/s).
`cargo run --release -p xbt402 --example binding_bench` on a Ryzen 9 9950X3D (SHA-NI) gives
digest v1 100 ns / v2 288 ns, receipt v1 345 ns / v2 445 ns, bodyHash 4 KiB 1.7 µs, ECDSA sign
16.2 µs, and SHA-256 at 2.5 GB/s:

- framing alone adds 0.48 µs, which is 2.9% of a signature and passes (a);
- framing plus a 4 KiB bodyHash adds 2.2 µs, which is 13.7% and **fails (a)**;
- the bodyHash part is one SHA-256 pass over the answer, which T4 requires and the payer repeats to
  check, and it grows with the answer size.

There was no armv7 box or emulator, so the armv7 figures are estimates. Software SHA-256 on a
Cortex-A7 at 900 MHz runs at about 25–35 cycles/byte, about 25–35 MB/s, so (b) passes with room to
spare. Signing on 32-bit libsecp256k1 slows down by roughly the same factor as hashing, so the
bodyHash share on armv7 is in the same 10–25% range: (a) fails there too for answers of a few KiB
and up.

**Embedders.**

- cmp, xbt-compute and anyone else who builds the payload themselves must bind
  `request_digest_v2(method, origin + target, body)` and verify receipts against the answer. A v1.2
  digest no longer authenticates.
- B5 and xbt-063 vendor pinned B1/B2 and are unaffected until they re-pin. On re-pin, B5
  `fwd/server.py` must add status and bodyHash to its receipts and use the v2 digest.
- The B2 wallet (`agp-068`, `611ec39`) binds the v2 digest. Since the AGP-063 merge it also checks the seller's receipt (request binding v2, status and bodyHash), as xbt-signer does.
- xbt-wallet-ui, xbt-work-relay and xbt-wallet-mcp still served with `tiny_http`, so they kept T1's
  slowloris exposure until AGP-072 moved them to the same server ("One bounded HTTP server for every service (AGP-072)"). Moving xbt-work
  to v2 is a follow-up.
- The interop scripts' B1 default went back to the main B1 checkout when this merged.

Tests: `crates/xbt402/tests/http_limits.rs` (`slow_bodies_do_not_stall_the_server`,
`slow_heads_do_not_stall_the_server_and_are_cut_off`, `an_endless_header_line_is_refused`,
`an_oversized_response_is_an_error_not_a_truncated_body`, `a_body_cut_short_is_an_error`) and the
AGP-068 tests in `lifecycle.rs` (`a_payment_is_bound_to_one_request_and_one_origin`,
`concurrent_calls_get_the_numbers_of_their_own_reservation`,
  `a_seq_spent_on_a_refusal_survives_a_restart`, `the_receipt_covers_the_response`,
`an_altered_conditional_answer_keeps_the_hash_lock`).

## Fix wave 5, agent wallets (AGP-095)

The third closure audit (AGP-093) left eight items in the wallets. Each is one rule; the tests are
`crates/xbt-signer/tests/agp093_wallet_rs.rs`, `agp093_ln.rs` (the audit's) and `agp095_wallet.rs`,
and B2's `tests/test_agp093_wallet_b2.py` and `test_agp095_wallet_b2.py`.

- **One call signs at most one new state, and only when the seller holds the last one** (`pay_once`).
  A state without a receipt is sent again and nothing higher is signed. A seller that served a call
  whose answer was lost has charged it, so the state sent again no longer pays for the next call and
  the channel stopped for good. Now, when the seller answers that state with a 402 naming it
  (`insufficient_payment`, this channel, this `cum`, this `seq`), the call signs one new state of
  the quoted price, inside its `max_sats` and booked before it leaves, and sends the request once
  more. The 402 is not a receipt and acks nothing. Limit: the 402 is unsigned, so whoever sits
  between the wallet and the seller can write one; what it buys is one state of one price per
  `xbt402_pay` the agent makes, which the budgets count.
- **How long a channel lasts is the owner's number at both ends** (`open_from_offer`). An offer's
  window is refused before funding when it lets the channel last less than the offer's own floor
  (`minExpiryBlocks + minConf + closeMarginBlocks`), no longer than `refund_margin_blocks`, or less
  than 144 blocks (or the policy's `channel_expiry_blocks` when that is lower). A negative price is
  refused as an offer. The socket's `open_channel`, `fund` and `xbt402_sign_rollover` already
  refused an expiry inside the refund margin.
- **A next-channel slot is taken by a signature, never by a request** (`xbt402_sign_rollover`). The
  key and terms of a rollover's next channel are stored by the signing itself, after the policy and
  the book have decided, in the write that precedes the signature.
- **A channel this signer's signature funded gets a record and the refund at its expiry.** The
  watcher adopts the next channel of a signed rollover once that rollover is in a block, whoever
  broadcast it (`rollover_adopted`), with the terms checked when it was signed. `xbt402_attach`
  afterwards answers the same channel.
- **A channel leaves the refund watch only when our node shows its funding spent in a block**
  (`funding_spend`). A close seen only in the mempool is closed but not proven (`close_proven:
  false`): the record stays with the watcher, is not replaced by a new channel, is proven by the
  block, and is refunded at expiry if that transaction leaves the mempool unmined. The refund
  itself answers `close_unconfirmed` while such a close is in the mempool. Limit: `xbt402_attach`
  still takes a rollover that is only in the mempool (a client attaches as soon as the seller
  answers); if that rollover is then never mined, the channel it would have spent is no longer
  watched and no wallet method refunds it: the signer still holds its key, and the owner must
  restore the record by hand. No new channel to that seller opens meanwhile. (Corrected by
  AGP-107: this said "its refund is a manual one"; `xbt402_refund` reads live records only.)
- **A used human signature stays used by the highest clock its file has seen.** `human_sigs.json`
  carries `clock`; an entry leaves only when its expiry is behind it, and a message whose expiry is
  behind it is refused (`expired`), used or not. Limit: a missing file is an empty one, because
  whoever can delete it can write an empty one.
- **A panic in one step of a watcher tick ends that step of that tick.** Each step is guarded and
  reported (`watcher_panic`), the later steps run, and the thread ends only when the signer stops.
  Under `panic = "abort"` (`release-small`) no panic can be caught: the process ends and its
  supervisor restarts it.
- Checked arithmetic on the socket's `open_channel` (`cap_sats + close_fee`, the expiry height),
  `xbt402_sign_conditional`'s `csv_delta`, a BOLT 11 amount, and the Lightning node's amounts
  (`paid_msat`, `htlc_locks`, the exposure sum): a number that does not fit is refused or counts as
  the most there is, never a panic.

## Channel findings C1–C5 (AGP-067, external review)

The provider's close must confirm before the payer's refund is valid, the payer must not fund a
channel the seller then refuses, a rollover is the tx the payer signed, the payTo key and ledger
survive a restart, and one ledger file has one writer. B1 `x402_channel.py`/`ledger.py` on branch
`agp-067` does the same for C1, C2 and C5, and `tests/security/test_agp067_review_c.py` and
`test_agp067_review_c1.py` there use the test names of `review_c.rs` and `review_c1.rs`. C3 does not
apply to B1's client (it has no wire rollover; B1's hub already refuses `bad_rollover_reply`). C4 is
xbt-rs only (B1's launcher already seals its payTo key, P7). The conformance vectors are unchanged.

**Wire.**

- `/open` takes `"preflight": true` with a `channel` that has no `txid`/`vout`. The provider runs
  every check of a funded open that does not need the funding output (network, payTo, closeFeePayer,
  redeemScript, capacity and expiry against its policy). It records nothing and answers
  `{"preflight": true, "expiry", "maxCum", "minConf"}`, plus `closeFeePayer` and `minCum` under
  payee-pays, or the refusal the funded open would get. The Rust client, the B1 client and the
  xbt-signer session preflight before they fund. A provider from before AGP-067 answers
  `bad_request` (no `vout`), and only after its own terms checks have passed, so on `bad_request`
  the client funds and opens as before.
- The funded `/open` carries the same fields. In the Rust client `txid` and `vout` are now the last
  keys of `channel`, not the first (serde_json keeps insertion order); B1 keeps them first. JSON
  key order carries no meaning.
- A rollover reply is accepted only if `txid`, `nextChan` (`txid:1`) and `nextCapacity` match the
  rollover tx the payer computed and signed (`bad_rollover` otherwise). The next channel's refund
  is kept (`on_refund`) and its key bound before that check, so a provider that broadcast the real
  tx and lied about its id cannot strand the payer's refund.

**C1: the close bump.** The close pays the `closeFee` fixed at open (600 sat, about 3.5 sat/vB on a
171 vB close; `STATE_VSIZE`, 190 vB, is the same close with room for a P2TR change output, the
number fee arithmetic uses). Until now a fee spike through the close margin meant the close never confirmed and
the payer's refund took the whole channel back at expiry. Now the watcher (`close_due`, and
`close_locked` when the node refuses the close outright) works out the package feerate the close
needs for each block it is unconfirmed:

- the highest of `close_min_feerate`, the node's estimate for confirmation within a quarter of the
  blocks left (`estimatesmartfee`, clamped to 1–1008) and the mempool's floor
  (`max(mempoolminfee, minrelaytxfee)`);
- in the second half of the close margin, at least double the last send's rate once
  `close_bump_blocks` have passed without confirming (an estimate that lags the market).

If the close alone pays that, it is sent alone. Otherwise it goes out with a CPFP child that spends
the provider's own close output back to the same key (`submitpackage`), replacing the previous
child under BIP125 (the new child pays at least the old fee plus its own vsize). The child's fee is
capped at `close_bump_max_fee` and at the output less dust; at the cap the last child is rebroadcast.
`sweep_payee` spends the child's output when there is one. A node that answers `getrawtransaction`
for an evicted close does not fool the watcher: the close counts as in the mempool only while the
funding outpoint is spent there.

- `ProviderConfig`: `close_bump_max_fee` (default 10,000 sat; 0 is main's behaviour, the close
  rebroadcast and nothing else), `close_min_feerate` (1.0 sat/vB), `close_bump_blocks` (3).
- `ChainBackend` gains three methods with defaults, so existing backends compile unchanged:
  `estimate_fee_rate(target) -> Result<Option<f64>>` and `mempool_min_fee() -> Result<Option<f64>>`
  (both default to `None`, meaning no estimate) and `submit_package(&[hex])` (default: send each in
  order, only the last one's refusal counts). `Rpc` implements all three. An RPC error on the
  estimate or the floor counts as no estimate; `close_min_feerate` and the doubling still apply.
- The record is `extra.close_bump`: `{at, seen, rate, fee, txid, hex, capped, replaced:[[txid, fee]…]}`
  (`at` is the last send, `seen` the last block looked at). `close_failed` now names the bump's error
  after the close's own (`…; bump: close_bump_failed: …`).
- Limits. The child can only spend what the provider's output holds, so a small channel can only be
  bumped a little: a 2-call channel at 1,000 sat a call has 1,546 sat to give. Package relay (Knots
  and Core 28 and later) lets a close below the dynamic `mempoolminfee` in on its child's fee, but
  not one below the node's static `minrelaytxfee`: a node configured above 3.5 sat/vB refuses the
  close in any package. Payer-pays closes are bumped from the provider's output too.

Options weighed (best-performing-stack rule):

| option | wire change | needs | cost |
|---|---|---|---|
| raise the fixed `closeFee` | no | nothing | paid on every close in every market; still loses to a big enough spike |
| the 0xA3 fee-input close (SIGHASH_SINGLE\|ACP) | no | a provider wallet with spare UTXOs and their key on the watcher | a wallet hook per embedder, and UTXOs locked for every channel near its margin |
| anchors / TRUC (v3) closes | yes: a new state tx format both sides sign | v3 relay | a protocol version and new vectors |
| **CPFP from the provider's own close output (chosen)** | **no** | package relay (Knots 29 has it) | bounded by that output; one child sign per bump |

**Cost.** Per channel in its close margin, each block: up to three extra RPCs (estimate, mempool
info, `gettxout`) and at most one child signature. One ECDSA sign is 16.2 µs on the Ryzen 9 9950X3D
(`binding_bench`, AGP-068) and well under a millisecond on 32-bit libsecp256k1. Nothing is added
to a paid call.

**C2: preflight.** Options weighed: hand the provider a signed, unbroadcast funding tx to check (it
could broadcast and refuse, and every wallet would need a sign-without-broadcast hook), a separate
`/terms` endpoint (a second code path to drift from `/open`'s checks), or **the same `/open` with
`preflight` (chosen)**, which runs the exact checks of the funded open minus the outpoint. Cost: one
HTTP round trip per channel open (not per call), and no signature on either side.

**C3.** The client computes the rollover txid from the tx it signed (segwit: the witness is not in
the txid) and checks the reply against it. There is no wire change and no extra cost.

**C4: a provider that survives a restart.** `xbt-work-provider` and `xbt402-rust-provider` keep
their payTo key and their ledger under `--data-dir` (`XBT_WORK_DATA_DIR`; defaults
`./xbt-work-provider-data` and `./xbt402-rust-provider-data`). `xbt402-rust-provider --ledger FILE`
still overrides the ledger path. The key is `DIR/payto.key`, created once with mode 0600: it is
written to a temp file, hard-linked into place (a crash leaves no half-written key) and the
directory is fsynced. A key file with any group or other permission bit (`mode & 0o077`), or that
is not a key, is refused (error code `key_file`). `xbt-work-provider` runs a watcher (`close_due`) every `--watch-secs`
(`XBT_WORK_WATCH_SECS`, default 5), which closes channels before their payers' refunds and bumps
stuck closes. `load_or_create_secret(path)` is public for embedders. `xbt402-route-provider`
takes the same `--data-dir` (AGP-075; default `./xbt402-route-provider-data`); `--ledger FILE`
and `--secret HEX` still override the ledger and the key.

**C5: one opener per ledger.** `Ledger::open` and `FileClientLedger::open` take an exclusive
`flock(2)` on a sidecar `<path>.lock`, which holds the opener's pid. A second opener, in this
process or another, gets `ledger_locked` with the holder's pid. The lock goes with the ledger, and
with the process when it dies, so a crash never leaves a stale lock. B1's `Ledger` takes the same
lock with `fcntl.flock` (the same system call), and its `Ledger.close()` releases it. Options weighed:
the `fs2` or `fd-lock` crates (a new dependency for what std has done since 1.89), a lock on the
ledger file itself (the ledger is replaced by rename, which would drop the lock), a pid file without
a lock (stale after a crash, racy), or **std `File::try_lock` on a sidecar (chosen)**: no `unsafe`, no
new dependency, and it works on Linux, macOS and Windows. Cost: one syscall per ledger open. The
workspace MSRV is now **1.89**.

**Embedders.**

- A payer client from before AGP-067 talks to a new provider unchanged (it never preflights). A
  new client talks to an old provider through the `bad_request` fallback.
- Anything that opens one ledger file twice in one process (tests that "restart" a provider while
  the old instance is alive) now gets `ledger_locked`. Drop the old instance first, or copy the
  files the way a crash leaves them: `xbt402_interop::crash_copy(from, to)` copies a ledger file or
  directory and skips `.lock`. B1's tests use `sechelp.crashed(...)`, which releases the old
  instance's lock.
- A provider binary started without `--data-dir` now writes `./xbt*-provider-data` in its working
  directory instead of keeping everything in memory.
- Custom `ChainBackend`s get the defaults above. Override `submit_package` (and the estimate and
  floor) to get the bump through a package-relay node; with the defaults the close and child are
  sent one at a time, which works whenever the close alone clears the floor.

**Regtest.** `scripts/close_bump_regtest.sh` (ports 24860–24869) runs `xbt402-close-bump` against a
private Knots 29.4.2 node with `maxmempool=5`. A direct channel and a hub ch2 are each opened with
the bump on and off. Before the close margin the mempool is filled at 9.5 sat/vB until
`mempoolminfee` is 10.5 sat/vB, and from then on blocks take only packages paying 10 sat/vB or more.
Result (`run/close_bump.json`):

- with the bump, the direct and the ch2 close go in with a 2,351 sat child (package 10.50 sat/vB)
  and confirm in the first block after the margin, 19 blocks before expiry, paying the provider its
  best state;
- without it, both closes are refused (`mempool min fee not met`) until expiry. Then the payer's
  refund at 12 sat/vB and the hub's ch2 refund take both channels back.

Tests: `crates/xbt402/tests/review_c.rs` (`c2_a_refused_open_funds_nothing`,
`c2_the_preflight_records_nothing`, `c2_a_provider_without_preflight_still_opens`,
`c3_a_rollover_reply_naming_another_txid_is_refused`,
`c4_the_payto_key_persists_0600_and_a_loose_file_is_refused`,
`c4_a_restarted_provider_keeps_its_key_and_channels_and_closes_them`,
`c5_a_second_provider_on_one_ledger_is_refused`, `c5_a_second_client_on_one_client_ledger_is_refused`,
`c5_another_process_holding_the_lock_is_refused`) and `review_c1.rs`
(`c1_a_close_below_the_mempool_floor_goes_in_with_a_child`,
`c1_without_the_bump_the_close_never_confirms`,
`c1_the_bump_follows_the_estimate_and_escalates_near_expiry`,
`c1_the_child_never_pays_more_than_the_cap_or_the_output`,
`c1_the_payee_sweep_spends_the_child_after_a_bump`, `c1_a_close_that_pays_enough_is_left_alone`),
which run against a mempool model with a floor, full RBF, `submitpackage`, an estimate and
fee-market blocks.

## One bounded HTTP server for every service (AGP-072)

review T1 for the other servers. AGP-068 fixed xbt402's server only; xbt-wallet-ui, xbt-wallet-mcp
(streamable HTTP) and xbt-work-relay (both listeners) still served with `tiny_http` 0.12, with no
header-line cap and no read deadline, and the MCP started one thread per request with no limit.
All three, and xbt402, now listen with **`xbt_svc::http`**: the AGP-068 server, moved into xbt-svc
(which all four already depend on) behind a small `Handler` trait. `tiny_http` is gone from the
workspace (`Cargo.lock` loses it; `cargo tree -i tiny_http` finds nothing).

**Limits** (`xbt_svc::http::Limits::default()`, the same as AGP-068): 8 KiB header line and 32 KiB
head (431), the head within 10 s (408) and the body within 30 s, both absolute; at most 64
connections, 48 from one client address since AGP-081 (503); Content-Length bodies only, at most the handler's `body_limit` (413 before a
body byte is read; Transfer-Encoding is 501); `Expect: 100-continue`; `Connection: close`.

**What changed in the server while moving it:**

- Connection threads are reused (an idle one waits 60 s for the next connection) instead of one
  spawned per connection. The accept thread only queues a connection, so it is no longer the cap.
- A complete request runs on its connection thread once one of `threads` handler slots is free,
  instead of being handed to a worker and back. The bound on concurrent handlers is the same;
  two thread switches per request are gone. A panicking handler still costs a 500 and its slot
  is given back (not in a `release-small` build: a panic ends the process there).
- `HEAD` gets the headers and the length but no body; 1xx, 204 and 304 carry neither.
  `Content-Length`, `Connection` and `Transfer-Encoding` are the server's: a handler's copies are
  dropped, as before any header holding CR, LF or NUL.
- The server's own refusals (400, 408, 413, 431, 501, 503) are `text/plain` with `Cache-Control:
  no-store` and `nosniff`.
- An accept error (out of descriptors) backs off 10 ms instead of spinning; a failed thread
  spawn closes that connection.

**Per server.**

| server | handler slots | body limit | kept |
|---|---|---|---|
| xbt402 provider / hub | the caller's `threads` | the service's, per path | public API (`serve_http`, `serve_service`, `serve_listener`, `HttpService`), `X-Xbt402-Peer` from the socket only, `X-Forwarded-Proto` + `Host` URL, duplicate `PAYMENT-SIGNATURE` is 400 |
| xbt-wallet-ui | `XBT_UI_THREADS` (4) | 256 KiB | security headers on every app response, Host and Origin checks (AGP-063 W4), `Running` stops on drop |
| xbt-wallet-mcp | `HTTP_WORKERS` = 16 (was unbounded) | 1 MiB | bearer token and token file, Origin allowlist (AGP-063 X1), loopback guard; new `serve_listener` for a caller-bound listener |
| xbt-work-relay public | `--threads` (8) | 1052 B (a blob, so a misdirected push still gets 405) | rate limit per client, no-store, no listing |
| xbt-work-relay push | `--threads`, at most 4 | 1052 B | push token, exact blob length |

**Behaviour changes for operators and embedders.** Every answer closes the connection (browsers
and the MCP SDKs reconnect; `tiny_http` kept connections alive). A chunked request body is 501
(the MCP SDKs send Content-Length). Over-limit bodies get the server's plain-text 413 instead of
the app's (the MCP's was a JSON-RPC error). The MCP runs at most 16 requests at once; a paid tool
call waiting on a funding confirmation holds one, and further requests wait in their connection.
No wire change.

Options weighed (best-performing-stack rule):

| option | outcome |
|---|---|
| each crate depends on xbt402's `http-server` | links the provider and secp256k1 into the UI and the relay, which are meant to stay small and keyless |
| a new `xbt-http` crate | works, but xbt-svc already is the shared std-only service plumbing all four use |
| `hyper` / `axum` | an async runtime, ruled out for Pi-class boxes (AGP-068) |
| keep `tiny_http` behind a reverse proxy | the bare-metal default stays exposed |
| **move the AGP-068 server into xbt-svc (chosen)** | no new dependency, one implementation and one set of tests |

**Cost.** Pass line declared before measuring: (a) median latency of `GET /healthz` on loopback,
a fresh connection per request, served by xbt-work-relay, is at most `tiny_http`'s + 50 µs; (b) on
armv7 the extra per request is at most 0.5 ms. Measured with
`cargo run --release -p xbt-svc --example http_bench -- 127.0.0.1:29080 /healthz 5000 8` against
`xbt-work-relay --bind 127.0.0.1:29080 --push-bind off --memory` built from `main` (7d03b84) and
from this branch, on a Ryzen 9 9950X3D, two runs each:

| build | median | p99 | 8 clients |
|---|---|---|---|
| `tiny_http` (main) | 114 / 121 µs | 163 / 212 µs | 49.7k / 38.5k req/s |
| first cut: a thread spawned per connection, worker hand-off | 147 µs | 197 µs | 28.6k req/s |
| **reused connection threads, handler slots (shipped)** | **89 / 85 µs** | **143 / 125 µs** | **57.4k / 69.0k req/s** |

(a) passes: the shipped server is faster than `tiny_http`. The first cut passed (a) on latency but
halved throughput, because the accept thread spawned a thread per connection; that is why
connection threads are reused. (b) was not measured (no armv7 box or emulator, as in AGP-068).
With threads reused, a request costs the same kind of work as under `tiny_http` (a few syscalls,
one buffer), and no thread spawn, so (b) holds by construction. The three binaries cross-build for
`armv7-unknown-linux-musleabihf`, and the x86_64 relay binary shrinks from 1.12 MB to 0.77 MB.

Tests: the AGP-068 slowloris checks as shared functions in `crates/xbt-svc/tests/common/slowloris.rs`
(`slow_bodies_do_not_stall_and_are_cut_off`, `slow_heads_do_not_stall_and_are_cut_off`,
`an_endless_header_line_is_refused`), run by `tests/http_limits.rs` in xbt-wallet-ui (3 tests),
xbt-wallet-mcp (3) and xbt-work-relay (5, both listeners). All 11 fail on `main`: no 431 after
4 MiB of one header line, slow heads held for 20 s, slow bodies stall the UI and the relay, and
the MCP holds a body that never comes for over 60 s. The server's edges are in
`crates/xbt-svc/tests/http_server.rs` (HEAD and 204, header injection, a panicking handler, the
Content-Length rules and 100-continue, the socket peer, stop). xbt402's `http_limits.rs` passes
unchanged. Each slow-body test waits for the 30 s body deadline.

## Hub follow-ups: sealed ch2 keys, written-off ch2s, orphan locks, preflight (AGP-073)
Four follow-ups from AGP-063 (K1) and from the trade-offs of AGP-064 and AGP-067. The same changes
are in B1 `agp-073`, with the same test names. All the tests below fail on `main` (`20900a0`) and pass
here.

**K1: the ch2 payer keys are sealed at rest.** The hub's state file (`<datadir>/ch2.json`) held every
ch2 payer key in plaintext: the live and next ch2s, the archive, and a rollover's next ch2 written
ahead inside a record. Each key is now stored as `secret_sealed` in the B2 keystore's blob format:
`{"v":1,"alg":"aes-256-gcm","kdf":"keyfile","salt":"","nonce","ct","aad":"xbt402/hub-ch2"}`. The rest
of each record stays readable, for the operator and the reconcile tools.
* **The wrap key** is 32 random bytes, kept in a file of mode 0600 (32 raw bytes or 64 hex). It is
  made with `O_EXCL`, and a file that is not regular or is open to group or others is refused
  (`keystore`). `xbt402-hub` takes it from the config's `wrap_key_file`. Failing that, in a container
  or with `XBT_SECRETS_DIR`, it uses the secret `hub-wrap-key`, made on first start. Otherwise it uses
  `<datadir>/hub-wrap-key` and logs a warning: beside the file it seals, it only protects copies of
  `ch2.json` made without it.
* **On load**, every blob is opened with the wrap key. The hub refuses to start (`keystore`) if a blob
  does not open (another wrap key, a changed file), or if a key is not its record's `payer_pub` (a blob
  moved to another record; checked for every record not yet final).
* **A legacy file** with plaintext keys is read once and rewritten sealed at startup. The event is
  `ch2_keys_sealed {count}`, with a line on stderr. The old file's blocks and any backups still hold
  the keys.
* A save seals only keys it has not sealed before (each blob is cached in memory), so a write does no
  AES work once a ch2 is funded. The temp file is created 0600 before the rename.

Design comparison (the best-performing-stack rule):

| option | per-write cost | file readable | unattended restart |
|---|---|---|---|
| **per-key AES-256-GCM, cached blobs (chosen)** | a cache lookup per key (31 µs armv7, 10 records) | yes, except the keys | yes |
| whole-file AES-256-GCM | encrypt the whole file on every write, growing with the archive | no | yes |
| passphrase KDF (scrypt or Argon2) for the wrap key | as chosen | as chosen | no: an operator at every start |

Per key keeps the write path flat on small boards and the file inspectable. `kdf: "keyfile"` leaves
room for a passphrase later. The Rust side uses RustCrypto's `aes-gcm` and `zeroize`: pure Rust, no C,
builds for every target in the matrix, and already in the lock through `xbt-signer` (whose keystore
cannot be reused: `xbt-signer` depends on `xbt402`). No new duplicates in `cargo tree -d`. B1 uses
`cryptography` (now in `requirements.txt`; only `xbt402.hub_keys` imports it).

**A ch2 blocked by a written-off lock is closed early.** AGP-064 blocks routing and rollover over a ch2
with a written-off lock until the ch2 closes or is refunded, which could be its whole life. The
watcher now asks the provider to close that ch2 at once, once a block until it does, with the best
state (`ch2_close`, `why: "written_off"`). A close that shows t pays the held lock on ch1; one that
confirms without t releases the hold (AGP-064; since AGP-094 once that close is six blocks deep).
* After a **refusal** (the provider answered 400 after taking the pre-signature; since AGP-094 that
  is a provider that said yes to the hub's check and then refused the lock), the hub refills: its
  next ch2, if one was funded ahead and is open, takes over at once (`ch2_switch`, `why:
  "written_off"`) and the old one is closed as retired (AGP-057); otherwise a new ch2 is funded after
  the close.
* After a **timeout** (no reveal in time), the hub stopped routing to that provider (AGP-064), so it
  closes the ch2 and does not fund a new one.
* A ch2 with nothing signed but a written-off lock is asked to close too (before, a ch2 with nothing
  signed was "idle"). An honest provider has no state to close it with and answers `no_state`, on
  every block: the failed request is reported (`ch2_written_off_close_failed`), no new ch2 is funded,
  and the hub routes nothing to that provider until its own refund at the ch2's expiry. (Corrected by
  AGP-094: this said such a ch2 "is closed". Until AGP-094 any client could bring this about with one
  lock the provider refuses, a bad `lockAuth`; now only the provider can, by refusing a lock it had
  agreed to take. See fix wave 5.)

**Orphan ch1 locks are swept by the watcher.** A ch1 lock that no route is forwarding and that sits on
no ch2 (the hub stopped between its two write-aheads) was dropped only when the client asked to
close. The watcher now checks every open ch1 with a lock, each tick, before the margin close. The
check runs under the provider's busy flag, which `route()` holds from before it writes the lock until
its forward ends, so a lock in flight is never touched. AGP-064's drop had a gap: if the crash came
between a void's two writes, ch2 had the lock written off (its pre-signature may be out) while ch1
still had it as its lock, and the drop let ch1 close below it. Such a lock is now held in the base
like any written-off lock (`orphan_lock_held`), and the client's close is refused `lock_pending`
until it resolves. Other orphans are dropped as before (`orphan_lock_dropped`).

With the sweep, the hub now settles a lock's ch1 side before its ch2 side (the provider's answer,
and t read off a close). A stop between the two leaves the ch2 lock pending, which the provider's
answer or its close completes again; the other order left a ch1 lock with no ch2 lock, which the
sweep would drop unpaid. Completing a lock a second time returns the first result.

**C2: the routed funders ask before they broadcast.** AGP-067 made the payer client preflight
`/open`. `RoutePayer::open` (ch1, to the hub) and the hub's ch2 funding (`connect`, refills,
`fund_ch2`) funded first and asked afterwards. Both now send the same preflight (`"preflight": true`,
the terms, no funding outpoint) and fund only after a yes. A refusal is passed on with its code
(`ch2_preflight_refused` on the hub), and nothing is funded or written. A provider from before AGP-067
answers `bad_request`, and the funder goes on as before. B1's route payer already preflighted (its
open is `XbtChannelClient._open`); its hub did not.

**Cost.** Pass lines declared before measuring, armv7 musl release under `qemu-arm-static` as the
Pi-class figure, x86_64 native beside it (`hub::tests::seal_cost`, ignored by default: `cargo test -p
xbt402 --release --lib seal_cost -- --ignored --nocapture`):

| step | pass line (armv7) | armv7 | x86_64 |
|---|---|---|---|
| sealing step added to a state write (10 records, keys cached) | ≤ 100 µs | 29–31 µs | 7.2 µs |
| seal one new key (once per funded ch2) | ≤ 1 ms | 12 µs | 1.0 µs |
| open a 100-record file at startup (opens + `payer_pub` checks) | ≤ 500 ms | 16 ms | 1.3 ms |

For scale, serializing the same 10-record file costs 131 µs on armv7, before its fsync. The sweep is
one busy-flag try per open ch1 with a lock, per tick. The preflight is one HTTP round trip per funded
channel, not per call.

**For embedders (cmp).**
* `RouteHub::new` with a data dir makes `<datadir>/hub-wrap-key` if there is none. Use
  `RouteHub::new_with_wrap_key(.., Some(WrapKey::load_or_create(path)?))` to keep the wrap key off the
  data dir. In B1, pass `RouteHub(..., wrap_key=WrapKey.load_or_create(path))`. `OutBook::open` takes
  the wrap key and refuses a file without one.
* **Downgrade:** an older hub cannot read a sealed `ch2.json`. Old B1 fails at start (`TypeError` on
  `secret_sealed`); old Rust loads it with empty keys and cannot sign. Keep a copy from before the
  upgrade, plaintext keys and all, if a rollback is possible.
* The ch2 record's `secret` field is gone from the file (it is still in memory). Tools that read keys
  from `ch2.json` must open `secret_sealed` with the wrap key.
* A written-off ch2 is closed early, so the provider sees a cooperative close request soon after a
  refused or timed-out lock. A payee-pays ch2 pays its close fee then.
* The hub and the route payer send one more `/open` (the preflight) per channel.
* New events: `ch2_keys_sealed`, `ch2_written_off_close_failed`, `orphan_lock_held`,
  `ch2_preflight_refused`; `ch2_close` and `ch2_switch` can carry `why: "written_off"`.

Tests: `crates/xbt402-interop/tests/hub_followups.rs` (10; B1
`tests/security/test_agp073_hub_followups.py`, the same 10):
* K1: `k1_the_state_file_holds_no_plaintext_ch2_key`,
  `k1_a_legacy_plaintext_state_file_is_read_once_and_rewritten_sealed`,
  `k1_a_wrong_wrap_key_or_a_swapped_blob_is_refused`;
* written off: `written_off_a_refused_lock_ch2_is_closed_and_refilled`,
  `written_off_with_a_next_ch2_the_hub_switches_and_has_the_old_one_closed`,
  `written_off_on_a_timeout_the_ch2_is_closed_and_not_refilled`;
* orphans: `orphan_a_lock_a_crash_left_is_swept_by_the_watcher`,
  `orphan_a_lock_its_ch2_wrote_off_before_the_crash_is_held_not_dropped`;
* C2: `c2_the_route_payer_asks_the_hub_before_it_funds_ch1`,
  `c2_the_hub_asks_the_provider_before_it_funds_ch2`;
* `hub_keys` unit tests: the seal round trip and its refusals, the key file's forms, and its mode.

On `main`, 9 of the 10 fail; the tenth (the wrong-key test) needs the new API. In B1 master, 9 of 10
fail: the route payer test passes there, since B1's client already preflighted. Existing tests changed
with the new behaviour: `hub_money_safety::wa_the_key_is_on_disk_before_fund_runs` (the key is sealed),
`hub_reconcile::close_fields_round_trip`, and
`hub_routing_safety::h2_a_refused_lock_stays_in_the_base_and_blocks_routing_and_rollover` (the
watcher asks for the close itself). In B1: `test_agp037` (key on disk, rollover next key, the
unknown-spender reconcile), `test_agp053` `HubOff` (one more `/open`) and the same `test_agp064` H2
test.

**Trade-offs.**
* A refused first lock on a ch2 with nothing signed asks for a close every block until the provider
  closes or the refund comes, unless a next ch2 is open.
* The default wrap key beside the state file only protects copies of `ch2.json`. A secrets mount or
  `wrap_key_file` elsewhere is the real protection.
* The write does not fsync the directory after the rename, as before: no extra IO per call. A
  follow-up could add it.

## Hub closure-audit fixes: rollover with a lock open, refused seqs, the lock bound (AGP-078)
The closure audit of the external review (AGP-077) found three hub items still open on `main`
(`0a84665`). Each was the neighbour of a path an earlier fix had closed. The same changes are in B1
`agp-078`, with the same test names. The hub stays **experimental**.

**H1 and H2 through a ch1 rollover.** AGP-064 made a ch1 close refuse `lock_pending` while a routed
lock is open. `POST /x402/xbt-channel/rollover` spends the same funding and was not checked: a client
rolled ch1 over at its old state while a lock was in flight, or held after a write-off, and the hub
still paid the provider on ch2.
* `Provider::rollover` now makes the same test as the close (`locks_open`: the lock in flight, or a
  written-off lock above `best_cum`) and refuses `lock_pending` (400). The test is made under the
  ledger lock that is held until the rollover is sent, the lock `route()` writes its ch1 lock under.
* It refuses whatever `amount` the rollover pays, as a close refuses whatever state its payload
  carries. A rollover that paid for the open lock would be safe for the hub's coins, but the hub's
  counters and `complete_ch1` read `best_cum`, which a rollover does not move.
* The hub drops a lock it never forwarded before a ch1 rollover, as before a close (the same sweep),
  so an orphan does not keep ch1 from rolling over.

Every path that spends or replaces ch1, and its lock test:

| path | lock test |
|---|---|
| `POST /x402/xbt-channel/close` (`Provider::close`) | `locks_open`, refused `lock_pending` (AGP-064) |
| `POST /x402/settle` (`facilitator_settle`) | calls `close`: the same |
| `POST /x402/xbt-channel/rollover` (`Provider::rollover`) | `locks_open`, refused `lock_pending` (this change) |
| `Provider::close_channel` (embedder API, AGP-059) | `locks_open`, refused `lock_pending` |
| the margin close (`close_due`) | waits for a lock in flight in the first half of the margin; never for a written-off lock (AGP-064, a stated limit) |
| `adopt_intent` (the watcher, `close_channel`) | records a spend already sent by `close` or `rollover`, which made the test before writing the intent |
| `Provider::close_now` | none, by design: the operator's own close, not reachable over HTTP. A lock completed after it is not counted as routed |
| the hub's ch2 `rollover` / `close_ch2` | ch2, not ch1: `rollover` refuses `lock_pending` on a pending or written-off ch2 lock (AGP-064) |

**A seq spent on a refusal (review T4), on `/x402/route` and `/x402/xbt-channel/lock`.** AGP-068
saved the seq of a refused paid call. The hub's `/route` and the provider's `/lock` still kept it
only in memory, so after a restart the refused header authenticated again.
* `/route`: the checks after auth moved into `RouteHub::admit`; any answer it returns without
  writing the lock (every refusal, and the replayed answer of a completed lock) saves ch1's row
  first. If that save fails the answer is a 500.
* `/lock`: every answer saves the row once: `complete_lock` on each answer it gives, the caller on
  each refusal. A lock that completes still costs one fsync, as before.
* A request that fails auth changes nothing, as before.

**`max_lock_sat`.** The bound (at most half of `ch2_capacity`, not 0) was made only by
`HubConfig::from_json`. It is now `HubConfig::validate`, which `from_json` and `RouteHub::new` both
call, so a config built as a struct is refused `bad_config` before anything is written. The bound is
against the configured `ch2_capacity`; a ch2 opened with another capacity (`connect(.., Some(cap), ..)`)
is not checked against it.

**For embedders (cmp).**
* A ch1 rollover with a routed lock open is refused `lock_pending` (400). Retry it after the lock
  resolves, as for a close.
* `RouteHub::new` returns `bad_config` for a `HubConfig` with `max_lock_sat` 0 or above half of
  `ch2_capacity`.
* A refused `/route` or `/lock` now costs one ledger write (an fsync).

Tests, each failing on `main` and passing here (B1: `tests/security/test_agp078_hub_closure.py`):
* `hub_routing_safety.rs`: `h1_a_ch1_rollover_while_a_lock_is_in_flight_is_refused`,
  `h2_a_ch1_rollover_below_a_held_written_off_lock_is_refused` (the audit's two, from branch
  `agp-077`), `h1_a_lock_the_hub_never_forwarded_does_not_keep_ch1_from_rolling_over`;
* `routing_checks.rs`: `t4b_a_seq_spent_on_a_refused_route_survives_a_hub_restart`,
  `t4b_a_seq_spent_on_a_refused_lock_survives_a_provider_restart`,
  `hub_bounds_max_lock_sat_however_its_config_was_built`.

## Fix wave 2 leftovers: an errored ch1 spend, the lock bound per ch2, unpaid blocks (AGP-084)

Three things AGP-078 and AGP-079 reported as found and not fixed. B1 has the two hub items with the
same test names (`tests/security/test_agp084_hub_leftovers.py`); pay-with-work is Rust only.

| item | before | now | tests |
|---|---|---|---|
| a ch1 close or rollover whose broadcast errored | the intent stayed, the channel went on taking states; if the tx confirmed later, a lock routed in between sat above it (the hub paid 3,000 on ch2 over a ch1 spent at 3,007) | a channel with an unresolved intent takes no state: paid call, `/lock` and `/route` answer `channel_closing` | `hub_routing_safety.rs::h1_no_lock_is_routed_above_a_ch1_spend_the_node_errored_on`, `h1_a_provider_takes_no_lock_on_a_ch2_whose_spend_its_node_errored_on`; `lifecycle.rs::a_channel_whose_spend_the_node_errored_on_serves_nothing_above_it` |
| the same, resolving it | only the margin close, or the node showing the tx | the watcher sends an errored **close** again each tick; a close or rollover request first records an earlier spend the node has after all | `h1_a_ch1_close_the_node_errored_on_goes_through_at_the_next_tick`, `the_watcher_sends_a_close_the_node_errored_on_again`, `a_spend_that_reached_the_chain_is_recorded_before_another_replaces_it` |
| `max_lock_sat` against a ch2 opened with another capacity | checked against the configured `ch2_capacity` only | `ch2_terms` (so `connect` and `connect_next`) refuses `bad_config` when `2 x max_lock_sat` is above the capacity it would fund, before anything is funded | `routing_checks.rs::hub_bounds_max_lock_sat_against_the_capacity_a_ch2_is_opened_with` |
| an unpaid block with no statement | no verdict, nothing recorded | still no verdict; counted while credit is unpaid (`unpaidBlocks` in the report), with an optional stop | `agp084_unpaid_blocks.rs` (6) |

**The errored spend.** `close` and `rollover` write `close_intent` and then send (M8). When the node
answers with an error and does not know the tx, the answer is `close_failed` and the channel stays
open. The tx is complete all the same, and the provider cannot know that it will never confirm: a
node can take a tx and still answer with an error. So `provider::closing(st)` is true for a closed
channel and for one with an open intent, and every path that takes a state asks it: the paid-call
path, `/x402/verify`, the provider's `/x402/route/lock` and the hub's `/x402/route`. Nothing is
signed or served above a spend that can still land. The intent ends in one of four ways:

- the node shows the tx: `adopt_intent` records it (as before; now also at the start of `close` and
  `rollover`, so a new intent never overwrites one that is already on the chain). A rollover's
  intent carries `next`, so a rollover adopted later gets its `rollover_to`;
- it is a close: the watcher sends it again every tick (`close_locked`, with the AGP-067 bump), and
  the failure shows in `close_error` until it goes through;
- the client rolls over again or closes: the new spend replaces the intent. No state was taken in
  between, so whichever of the two confirms pays at least the best state;
- the margin close, as before.

The watcher never sends a **rollover** again. Its client was answered `close_failed`, and the
library client then no longer holds the next channel's key (below): sent later, the rollover would
fund a channel nobody can spend from before its refund.

Limits. After a failed close the channel routes and serves nothing until that close is on the node;
that is the point of the fix, and it changes what a failed close means for the client (it could go
on paying before). A replaced intent is forgotten: if the first spend errored, a second one errored
too, and then the *first* confirms, the ledger has the second one's intent and the close is never
recorded (the channel shows as suspended; no state sits above either spend). (AGP-085, below,
keeps every replaced intent and closes the first of the two payer-library points; AGP-081 closed
the second.) Found on the way and not fixed, both in the payer library (`client.rs`), not in the
provider:

- after a rollover the provider answered with an error, `Client::close` is refused `bad_sig`: the
  payer's watermark moved to the rollover's amount and its kept signature did not;
- `Client::rollover` drops the next channel's key when the POST fails (an error answer or a lost
  one). If the provider did broadcast, the leftover is in a channel the client cannot sign for.

**The lock bound.** AGP-064's rule is that a lock is at most half of a ch2. A ch2 funded with an
explicit capacity went around the check on the configured one. A rollover's child is not held to
it: its capacity is what the parent left, and it is replaced when a lock no longer fits. The route
demo's small ch2 (provider D) is 40,000 now, twice its `max_lock_sat`.

**Unpaid blocks.** A block that paid the identity nothing, with no statement, may be the Prime's or
any other pool's; the provider has nothing that tells them apart (no share-log commitment yet), and
on a chain with other miners most blocks are of this kind. So the decision on "do N such blocks
distrust the Prime" is no: distrust is a verdict and is never undone, and this is not evidence.
What is done instead:

- **Recorded.** While credit is unpaid, each such block extends a run kept in the state file and
  shown in the report: `"unpaidBlocks": {"from", "to", "count", "refused"}` (`refused`: those that
  came with a statement the audit refused). A block walked twice counts once. A coinbase that pays
  for credit ends the run; with no unpaid credit nothing is counted. (AGP-091: "pays for credit"
  is now "pays its share of all the unpaid credit, in a block above the run"; 1 sat did it. See
  the AGP-091 section.)
- **An operator's stop.** `--max-unpaid-blocks N` (`WorkConfig::max_unpaid_blocks`, off by default)
  stops new credit (`frozen: "unpaid_blocks"`) once the run reaches N and lifts it when a coinbase
  pays. It is a stop, not distrust. N has to come from how often the Prime's pool finds a block,
  which the provider cannot measure; set too low it stops an honest Prime during a run of bad luck.
- **Signed garbage is a failure.** A refused statement that did verify under the pinned key for
  this Prime and this block (`bad_window`, `window_start_regressed`) is the Prime saying the block
  is its own. On an unpaid block it had no verdict; now it fails the audit and distrusts the Prime
  (`refused_statement`), as on a paid block. A statement that does not bind the Prime to the block
  (`bad_window_sig`, `wrong_prime`, `wrong_block`) is counted in the run.

Without `--max-unpaid-blocks` the loss to a Prime that never pays is what it was: the total cap
(900 calls with the shipped defaults at exact pricing, 1,000 under a fixed amount per call; once
while the difficulty does not fall: corrected by AGP-107 from "1,000 calls ..., once", see the
AGP-091 and AGP-097 sections). For embedders: `WorkConfig` gains
`max_unpaid_blocks`; the state file gains an optional `unpaid` (version stays 3; older state loads
with no run); the freeze rules are applied again when the state loads.

## Transport, light-client and rollover closure fixes (AGP-081)

The closure audit of the external review (AGP-077, list 1 items 8, 9 and 10) found these still open
on `main` (`68d9650`). Each is the neighbour of a path an earlier fix closed. B1 `agp-081`
(`7e28c87`) and B2 `agp-081` (`542d0ca`) carry the same changes where they have the code, with the
same test names (`test_` prefixed): B1 `tests/security/test_agp081_closure_audit.py` (receipt,
fragment, per-address cap, the ASGI path held to loopback and documented as needing a proxy, and
payers opening at `minExpiryBlocks + minConf + closeMarginBlocks`), B2
`tests/test_agp081_closure_audit.py` (the Electrum limits, where B2 had no line limit at all, and
the fragment), with B2's own measurements from `tests/e1_attacks.py`.

**A paid answer needs its receipt (T4c).** `Client::request` checked a PAYMENT-RESPONSE only when
the header was there: with it stripped on the way, any body passed as the paid answer.
* An answer below 400 to a request that carried a payment, with no PAYMENT-RESPONSE, is
  `bad_receipt` ("paid call returned no receipt"). Nothing is adopted from it.
* An answer of 400 or above may have none (the provider's own failures carry no receipt). It goes
  back as it is; the caller must not read it as the answer it paid for.

| paying path | receipt |
|---|---|
| `Client::request` / `request_with`, channel | required below 400 (this change) |
| `Client::request_conditional` | required below 400 (this change); the hash lock stays pending, so `recover_conditional` still reads k from the provider's claim |
| `Client` with a scheme payer (`with_payer`, xbt-work) | required below 400 (this change); what it proves on that rail is less, see below |
| `xbt-signer` `pay_once` (the wallet) | a missing or bad receipt below 400 is refused: `deny/bad_receipt`, `charged_sats` 0, the body is not handed on; the signed state stays booked and is sent again by the next call (AGP-089; before that it was reported as `receipt_error` and the body went to the agent) |
| the stream's chunk calls (`xbt-signer`) | no receipt needed: each chunk is checked against the manifest's Merkle root before the state paying for it is signed (unchanged) |
| `RoutePayer` (routed calls) | none per call, by design: a ROUTE-STATE is a running meter (a stated limit) |
| close, rollover, open | control requests: their answers are checked against the transaction we signed |

**A `#` in a URL or target (T2).** The digest drops a fragment and the server routes on the target
as it arrives, so a payment for `/a` also authenticated `/a#b`. The digest and its vectors are
unchanged; a `#` is refused on both sides (`xbt402::wire::no_fragment`):
* payer, `bad_request` before anything is sent, numbered or signed: `Client::request`,
  `request_conditional`, every payload it authenticates (`Client::auth`), `RoutePayer::shard` and its
  hub URL, the wallet (`origin_of`, `with_auth`), a seller's `openUrl` / `closeUrl` / `chunkUrl`
  (`seller_url`), and the provider origin of a routed lock at the hub;
* provider, HTTP 400 before anything is authenticated or routed: `Provider::serve` (paid, control,
  `/lock`, facilitator and other-scheme paths alike), `RouteHub::serve`, and the shared server
  itself (`xbt_svc::http`, so the MCP, the UI and the relay too).

**One address cannot hold every connection (T1).** The cap was one global number. `Limits` has
`per_address` (default 48 of the 64): a client address above it gets 503 while other addresses are
still served. An address is an IPv4 address (an IPv4-mapped IPv6 address counts as its IPv4) or an
IPv6 /64. `XBT_HTTP_MAX_PER_ADDRESS` sets it for a process (0: no cap per address, for a server
whose only peer is its reverse proxy; anything but a whole number stops the server from starting).
* Why 48: behind a reverse proxy every connection comes from the proxy's address, so a low default
  would cut such a deployment to a fraction of its slots, and one address that sends 32 slow heads
  must still be able to make a request (the AGP-068 slowloris checks). 48 leaves 16 slots that one
  address cannot take.
* The limit that remains: two addresses fill the server (48 and the other 16; corrected by
  AGP-107, this said four). A public listener still belongs behind a
  proxy or firewall with its own per-client limits.

**One Electrum server cannot stall or exhaust the light client (E1).**
* *Line limit, before parsing.* Every request has an answer cap from its method
  (`conn::answer_cap`): bytes and JSON values. A line, complete or still arriving, is held to the
  sum of the caps of the requests waiting on that connection plus 16 KiB for notifications, and to
  8 MiB in any case (`MAX_LINE`, down from 64 MiB). A server that sends more is dropped and flagged.
  The values bound (`values_in`: commas and opening brackets, plus one) is there because a dense
  line costs many times its size as a parsed tree.

  | request | bytes | values |
  |---|---|---|
  | `blockchain.block.headers` (n headers) | 4,096 + 328 n (2016: 665,344) | 64 |
  | `blockchain.transaction.get` | 2,001,024 (a transaction of 1,000,000 bytes) | 64 |
  | `blockchain.scripthash.get_history`, `listunspent` | 1,604,096 (10,000 entries) | 60,016 |
  | `blockchain.transaction.get_merkle` | 8,192 | 128 |
  | everything else, and each notification | 16,384 | 64 |

* *Sync.* One server's part of a round ends at `Config::sync_deadline` (default four times the
  request timeout), each request inside it waiting no longer than what is left, or at the first
  answer with fewer headers than asked (all below the tip the server itself claimed). Either way
  the headers it proved are kept and it is flagged. A batch that fails no longer drops the headers
  proven before it.
* *History and cache.* A history or unspent list of more than `MAX_HISTORY` (10,000) entries is not
  used and its server is flagged. Transactions are fetched 16 per batch (`TX_BATCH`), not one batch
  of everything. The transaction cache holds 32 MiB of raw transactions (`TX_CACHE_BYTES`), oldest
  out first, and a cached proof goes with its transaction. A history entry that neither pays the
  script nor spends an output that pays it flags the server that listed it. A history or unspent
  call that no server answered is an error; before, it was an empty list.

Measured with `crates/xbt-electrum/examples/e1_attacks.rs` on a Ryzen 9 9950X3D, release build, the
hostile server in a child process, wall time and the client's peak resident memory. "Before" is the
same file built in a worktree of `main` (`68d9650`):

```
for a in trickle bigline history "history 20000"; do
  cargo run -q --release --offline -p xbt-electrum --example e1_attacks -- $a
done
```

| attack | before | after |
|---|---|---|
| trickle: 120 headers, one per answer, 400 ms each, an honest server beside it; the first `block_count()` | 48.45 s, 4.0 MiB, no flag | 0.40 s, 4.0 MiB, flagged `withheld headers` |
| a 16 MiB line of `[[],[],…]` ahead of one small answer | 0.62 s, 403.6 MiB, parsed, no flag | 0.005 s, 3.9 MiB, dropped at 32,768 bytes and flagged; the call fails |
| 8,000 invented history entries, each served | 11.75 s, 28.8 MiB, 8,001 fetches, no flag | 11.55 s, 17.4 MiB, 8,001 fetches, flagged |
| 20,000 invented history entries | 138.85 s, 64.4 MiB, 40,001 fetches, no flag | 0.03 s, 5.1 MiB, 1 fetch, dropped at the line cap and flagged; the call fails |

The 8,000-entry row is under the bound, so its fetches still happen: what changed is that they come
in batches of 16, stay inside the cache, and are flagged. Most of its time is the simulator's.
(This row is as measured for AGP-081 and was not measured again. Since AGP-092 a server's list
ends at the first entry it does not supply, so later code fetches fewer.)

Limits, stated: a script with more than 10,000 history entries, or a transaction above 1,000,000
bytes, is not answered by this backend (every standard transaction is at most 400,000 bytes). An
invented transaction that pays the script cannot be told from an unconfirmed payment, so that flag
catches only entries unrelated to the script. A server that trickles full-size answers just inside
the timeout is cut at the deadline every round, and with no honest server beside it the tip still
advances only as fast as that server allows (`status()["tip_age_s"]`, and on mainnet the stale-tip
rule, show it). A server whose `blockchain.block.headers` maximum is below 2016 is treated as
withholding.

**A rollover keeps its next channel from before the request leaves (C3).** `rollover_inner`
returned at a failed POST before the next key was bound or a refund produced, while the provider
may have broadcast the one transaction we signed: a client with a local key then held no key and no
refund for the next channel.
* The next channel is recorded in `Client::next_rolled` and saved to the injected ledger (record
  `next <origin>`) before the POST. With a local key its refund is produced and handed to
  `on_refund` at that point too.
* With a signer, the key was always the signer's (`new_key`), and the wallet's signer binds a next
  channel only once its own node shows the rollover (AGP-080). The record therefore carries the
  funded params; the bind (`attach`) and the refund follow the reply. Before, an `attach` refused
  `rollover_unproven` after a good reply lost the next channel's params as well.
* `Client::adopt_rolled(origin, txid)` makes a recorded next channel the live one when the reply
  was lost or an error and the embedder sees the rollover transaction on chain; then `open_rolled`
  as usual. A record stays until it is adopted; one whose transaction can no longer confirm (the old
  channel was closed another way) is the embedder's to remove from `next_rolled`.

| path that signs a rollover | next channel kept |
|---|---|
| `Client::rollover`, local key | key, refund and record before the POST (this change) |
| `Client::rollover`, signer (`RemoteSigner`, `LocalSigner`) | record before the POST; bound and refunded after the reply or by `adopt_rolled` (this change) |
| the hub's ch2 rollover (`RouteHub`) | already safe: the next ch2, its key and its refund are written to the hub's book before the request (`hub.rs`, "write-ahead"), and only a 400/401/403 answer clears them |
| `xbt-signer` `xbt402_new_key` / `xbt402_sign_rollover` | already safe on the signer's side: the issued key is sealed to disk at once as `pending:<origin>/next`, and `next` is checked at signing (since AGP-095 a next-channel slot is taken by a signature, never by a request, at most eight per channel: the wave 5 wallet section) |

**The xbt-work rail, stated limits.** Its request binding is taken over the bare target (as the
XBT-053 vectors are): no scheme, host or port. Its PAYMENT-RESPONSE is unsigned and covers
neither the status nor the body. The client now requires that response on every call paid with
work, and a `#` is refused as on the channel rail; raising the rest to the channel rail's level is
a change to the xbt-work spec and its vectors, not made here. The module docs of `xbt_work::payer`
say the same. Run this rail over TLS to the provider.

**For embedders (cmp).**
* A paid call below 400 with no PAYMENT-RESPONSE is now `Err(bad_receipt)`, and a URL with a `#` is
  `Err(bad_request)`.
* `xbt_svc::http::Limits` has a new field, `per_address`; `Limits::default()` sets it.
* `xbt_electrum::Config` has a new field, `sync_deadline` (`None`: four times `timeout`), and
  `MAX_LINE` is 8 MiB. `history`-backed calls (`tx_out`, `spending_tx`, `unspent`) return an error
  when no server answered, where they returned "nothing" before.
* After a failed `Client::rollover`, look at `next_rolled`: the refund of each record is the way
  back for that next channel if its rollover confirms.

Found and not fixed here: the hub's ch2 rollover writes the next ch2 ahead, but clears it when the
provider answers 400, 401 or 403 ("refused: nothing was broadcast"). A provider that answers so
and broadcasts anyway leaves the hub without the next ch2's key. Same in B1; a B1-only change is
parked on B1 branch `agp-081-hub-rollover`, not reviewed, for a hub task in both languages.

Noticed and not changed: after one answer lost on the way, the next receipt shows two calls' growth
in `spentMsat` and the client refuses it `bad_receipt` (`Client::receipt` has no slack for a lost
answer; the 402 path has one call of slack).
(Changed in AGP-090: see "Fix wave 4, channel client and transport".)

Tests, each failing on `main` and passing here unless marked:
* `xbt402/tests/lifecycle.rs`: `a_paid_answer_without_a_receipt_is_refused`,
  `a_conditional_answer_without_a_receipt_is_refused`,
  `a_target_with_a_fragment_is_refused_by_the_payer`,
  `a_target_with_a_fragment_is_refused_by_the_provider`,
  `a_rollover_binds_the_next_channel_before_the_request_leaves`; and, using the new
  `adopt_rolled` (so they do not build on `main`),
  `a_signer_backed_rollover_keeps_its_next_channel_until_the_signer_binds_it`,
  `a_rollover_whose_reply_was_lost_is_adopted_from_the_chain`;
* `xbt-work/tests/rail.rs`: `a_paid_answer_without_a_receipt_is_refused`;
* `xbt-svc/tests/http_server.rs`: `one_address_cannot_hold_every_connection` (two addresses over a
  dual-stack listener; without IPv6 loopback only its same-address half runs),
  `a_target_with_a_fragment_is_refused`; unit tests in `http.rs`
  (`an_address_at_its_cap_is_refused_and_no_other_is`,
  `one_address_is_an_ipv4_address_or_an_ipv6_slash_64`);
* `xbt-electrum/tests/backend.rs`: `a_trickled_header_sync_is_cut_off_and_flagged`,
  `an_oversized_line_is_dropped_before_it_is_parsed`, `an_invented_history_is_bounded_and_flagged`,
  and `a_slow_header_sync_ends_at_its_deadline` (uses the new `sync_deadline`); unit tests
  `conn::tests::answer_caps_fit_the_largest_legitimate_answer`,
  `conn::tests::values_in_never_undercounts`,
  `backend::tests::the_transaction_cache_drops_the_oldest_at_its_cap`.

New dependency: none (`cargo tree -d` is unchanged).

## Fix wave 3: the hub's next ch2, counters by delta, funding and approvals, replaced intents (AGP-085)

What fix wave 2 found and left open (AGP-081 "Decisions for the lead" item 1, AGP-084 "Found, not
fixed" items 1 to 6 and its stated limit 2). B1 has the hub and provider items with the same test
names (`tests/security/test_agp085_hub.py`), B2 the signer items (`tests/test_agp085_write_ahead.py`).

| item | before | now | tests |
|---|---|---|---|
| 1 hub ch2 rollover answered 400, 401 or 403 | the next ch2 written ahead (key and refund) was cleared: a provider that answers 400 and broadcasts anyway left the hub's leftover in a script it had no key for | `next` outlives every answer; one next key per ch2; adopted by its script whatever amount the broadcast rollover paid; cleared only when another spend of the funding confirms | `hub_money_safety.rs`: `a_refused_rollover_keeps_the_next_channel`, `a_rollover_broadcast_after_a_refusal_is_adopted_with_its_refund`, `a_retried_rollover_asks_under_the_same_key`, `a_rollover_at_an_earlier_amount_is_adopted_by_its_script`, `a_next_channel_too_old_to_ask_again_is_kept_and_the_ch2_closed`, `a_rollover_into_a_closing_ch2s_next_channel_is_adopted`, `a_kept_next_channel_is_dropped_once_another_spend_confirms`, `a_rollover_refused_before_a_restart_is_adopted_after_it` |
| 2 ch1's `fee_units` when a hold is released under a lock in flight | set to the absolute value fixed at admission: the released units came back, the client (which counts by delta) and the hub disagreed for good, every later lock was `bad_amount` | the lock records `unitsBy`; completion adds it; a hold is the lock's own three deltas | `hub_routing_safety.rs`: `a_lock_admitted_before_a_release_completes_by_delta`, `a_lock_admitted_before_a_release_and_written_off_holds_only_its_own` |
| 3 library client after a rollover answered with an error | `Client::close` refused `bad_sig` | the plain state for the rollover's amount is signed and kept first | `lifecycle.rs::a_client_can_close_after_a_rollover_the_node_errored_on` |
| 4 channel funding of unknown fate | the pending record and its payer key were forgotten on ANY broadcast failure | forgotten only on the node's own refusal; else kept, sent again by the watcher, refunded at expiry | `xbt-signer/tests/agp085_funding.rs`: `a_funding_of_unknown_fate_keeps_its_pending_record_and_key`, `a_funding_the_node_never_received_is_sent_again_by_the_watcher`, `a_refused_funding_the_node_cannot_be_asked_about_is_kept`, `a_funding_the_node_refused_is_forgotten` |
| 6 `approve` (the Rust signer had B2's order) | the token was popped before the payment: a node refusal cost the human's approval and paid nothing | held (`used` on disk) while the payment runs; spent by a payment; given back on the node's refusal or a verdict that is not `allow` | same file: `an_approval_the_node_refused_to_pay_is_not_spent`, `an_approval_the_policy_denied_is_not_spent`, `an_approval_whose_payment_is_of_unknown_fate_stays_spent` |
| 7 a replaced intent | forgotten: if it confirmed later the close was never recorded | every unresolved intent is kept (`close_intents`) and looked for; at most 8 beside the latest | `lifecycle.rs`: `a_replaced_intent_is_still_recorded_when_it_confirms`, `unresolved_intents_are_bounded` |
| 8 `route_wal::a_routes_file_save_during_a_call_covers_it` | failed under load (sync count 0, not 1) | the test was wrong, not the log (below) | the test itself |

(Item 5, `fund_treasury`, is B2 only: the Rust signer has no treasury.)

**1. The next ch2.** `RouteHub::rollover` writes the next ch2 ahead and signs one transaction
into it. The provider then holds that request signed whatever it answers. The rule now:

- No answer clears `next`. A ch2 has one next key while its funding is unspent. A later attempt
  asks under the kept key and expiry, so every rollover the hub ever signed from this funding pays
  the same script; only the amount (and so the txid and the next capacity) differs.
- `reconcile` adopts by script (`next_funded`): a spender of the funding with two outputs whose
  second pays `next`'s script is a rollover the hub signed. `next` takes that transaction's
  outpoint and value and a fresh refund, then becomes the ch2 (`ch2_rollover`, with the amount
  that transaction paid). This holds for a live ch2 and for one already archived by a refill.
- When the kept expiry no longer clears the payer's floor (`minExpiryBlocks + minConf +
  closeMarginBlocks`), the hub does not make a second key, which would leave the first behind: it
  asks for a close (and a refill) and keeps `next`. The cost: a ch2 whose rollover was refused
  once, and that then lives to within that floor of the kept expiry, settles by a close and a new
  funding where it would have rolled over (two tests that relied on the old clearing were
  changed: `child_is_not_rolled_over_before_it_confirms`, `v12_provider_refuses_an_early_rollover`).
- A `closing` ch2 with a `next` is not marked closed on the provider's word once its funding is
  spent and confirmed: the spender is read first. A provider that names a close txid and
  broadcasts the rollover it kept is adopted, not written off.
- `next` goes when a spend of the funding that is not a rollover into it confirms.

Paths that reach the same state, each covered: a refusal with nothing broadcast (kept, reused);
a refusal with a broadcast; a lost answer (AGP-037's `wa_a_lost_rollover_answer_is_finished_by_the_watcher`,
unchanged); a retry at another amount; a restart between the refusal and the adoption; a parent
archived by close and refill (AGP-073) or by `promote` (AGP-057: same archive, same reconcile);
the provider's own close winning. Limit: while the fate is unknown the hub goes on routing over
the old ch2. If the provider then broadcasts the earlier rollover, the states signed since are
void: the provider gave up what they paid it (its choice, as with closing on an old state).

Three more paths beside these, found by the B1 review and closed in both languages:

- **A rollover adopted over locks.** A rollover reveals no `t`. If the old ch2 has a pending or
  written-off lock when the rollover is seen, it is adopted only once it confirms (a close that
  shows `t` could still replace it); then the pending lock is written off, every written-off lock
  is released (its hold leaves ch1's base) and the rollover is finished. Before, a `rolled` ch2 was
  never reconciled again and the hold stayed for good; that was already so for a rollover whose
  answer was lost (`a_rollover_adopted_over_a_written_off_lock_releases_it_once_confirmed`).
- **Another attempt confirms in place of the adopted one.** The hub adopts attempt 2 from the
  mempool and attempt 1 confirms. `rollover_gone` used to drop the child as "replaced", final,
  with no refund. A spender of the parent whose second output pays the child's script is the same
  ch2 at another outpoint: the child takes it, with a fresh refund, starts again as `funded` with
  nothing signed (states on the old outpoint are void), and the watcher opens it. Locks out on
  the old outpoint are released once the replacement confirms
  (`a_rollover_replaced_by_another_attempt_into_the_same_script_keeps_the_coins`;
  `ch2_rollover_replaced` then carries `kept`).
- **Our own refund confirms:** `next` is cleared, as on the provider's confirmed close.

**2. Counters by delta.** A lock's record gains `unitsBy` (what the lock adds to `fee_units`).
`complete_ch1` adds it, as `routed_sat` and `fee_paid` were already added. `hold_in_base` (a lock
written off while its pre-signature is out) adds the lock's own `d + f`, `unitsBy` and `f`; it
used to raise the counters to the lock's `after`, fixed at admission, which held a released hold a
second time in all three counters. A record without `unitsBy` (written before this change) keeps
the old rule. Other writers checked and left: `release_unpaid` subtracts exactly the recorded
hold; a legacy written-off lock with no hold is raised to its `after` only when it is the best
state; the routed client's `commit` sets `fee_units` from its own pending lock, and nothing on the
client changes its counters between building a lock and committing it (locks are serial, a
resync happens only on a refused lock). The client's `resync` did need a change: with a hold by
delta, the hub's view can carry a release and a hold (or a completion) of the lock in flight at
once, which matched none of its three cases and left it on `bad_amount`. Each case is now also
tried with the released holds taken out; the hold-plus-release case has a test (the second one
above), the completion-plus-release case has none. Counts: `scripts/route_interop.sh` and B1's
`demo_route.sh` looped (numbers in the task result).

**3. The client after an errored rollover.** `sign_rollover` moves the payer's watermark to the
amount owed; `last_sig` stayed at the state before, so the next close named a cum its signature
did not match. The plain state for that amount is now signed first and kept. It pays the provider
what the rollover would. The next channel's key: since AGP-081 every signed rollover's next
channel stays in `next_rolled` until `adopt_rolled` takes it, whatever the POST answered; checked
again here (the test above asserts it). The hub never moves its watermark in a rollover (it signs
`signed`), and a signer-backed client goes through the same code.

**4. Funding of unknown fate.** `session::send_funding` is now the one place a channel funding is
broadcast (the session's open, the socket's `open_channel`, an external client's `fund`: every
`prepare_fund` caller). `HotWallet::broadcast` answers `rpc_refused` only when the node refused
the send and then said it has no such output; a refusal whose lookup failed, and every timeout,
is `rpc_error`: unknown. On unknown the pending record and key stay, the inputs count as spent,
and the caller's error says the channel stays pending. `complete_open` (the watcher) sends a
pending funding with no open URL again until the node shows it; the signer's own channel is then
open, an external client's waits for its attach. Limits: an open against a node that is merely
unreachable leaves a pending channel that is funded when the node is back, although the caller
got an error; a kept funding that can never confirm blocks its destination until its expiry, and is freed
then only when the node shows, in a block, another transaction that spent one of its inputs
(`funding_dead`; otherwise `funding_unknown` until an operator removes the record: AGP-089, corrected here by AGP-107); the hot balance counts the change before the transaction is known to exist
(`hot_reconcile` corrects it). Sweeps and the rotation have no key to forget and are unchanged.

**6. Approvals.** The token is `used` on disk before the payment and through it. `allow` removes
it; the node's own refusal, or any verdict that is not `allow`, with nothing booked, gives it
back as it was (same expiry). Anything else, a crash included, leaves it used: a later approve is
`approval_replay`. `xbt402` and `ln` grants are separate paths and unchanged.

**7. Replaced intents.** `set_intent` moves an earlier unresolved intent for another transaction to
`close_intents`; `adopt_intent` looks for the latest, then those, newest first, at every place it
already ran (the watcher's tick, the start of `close` and `rollover`). A rollover is refused
`channel_closing` once 8 are kept, before anything is signed (a client could otherwise grow the
ledger while the node is down); a close is never refused. The hub's ch1 is a `Provider`, so it is
the same code. Limit: once a spend is recorded as the close, a kept intent that displaces it (a
reorg) is not looked for.

**8. The flaky test.** The test saves the routes file inside the handler and then expected exactly
one log sync "for the reservation" when the call returned. That save holds the session's meter
with the call in it, so the answer waits for nothing; the reservation's sync runs on the writer
thread and may finish after the call. With `sync_delay_ms` = 300 the old assertion reads 0 every
time; under 96 busy loops on 16 cores it failed 23 runs of 200. The test now holds the writer,
checks the call answers with nothing synced, crashes there (the routes file alone restores the
meter) and then checks the log gets the reservation only: 100 of 100 under the same load. The
log's code is unchanged.

For embedders: `xbt402::provider::MAX_KEPT_INTENTS`; a channel's `extra` may hold `close_intents`;
a hub lock record holds `unitsBy`; `HotWallet::broadcast` may answer `rpc_error` where it
answered `rpc_refused`; `open_channel`, `fund` and `xbt402_pay` may leave a pending channel
behind an error.

## Fix wave 4, the hub: one lock per ch2, "in a block", the watcher and the cap, what the client believes (AGP-088)

The hub items of the second closure audit (AGP-087, list 1 items 1, 2, 12, 13 and the hub parts
of 19). B1 has the same fixes and tests (`tests/security/test_agp088_hub.py`). Each fix keeps one
rule, stated where the code keeps it.

| item | the rule | before | now | tests |
|---|---|---|---|---|
| 1 two written-off locks under one lockId | a lock on ch1 is the lock of ONE ch2, and only that ch2's fate moves it (`hub::is_lock`) | a written-off lock was found, completed and released by its lockId, which is the provider's choice: when one of two completed or was released the other left ch1 with it, ch1 then closed below it, and its provider's later close was paid for nothing | every ch1 lock records the ch2 it went over (`ch2`, that ch2's payer key) and is matched by lockId and ch2; a completion also needs the `t` that opens the lock's own `T`; and a ch2 does not take a lock under a lockId ch1 still holds written off (`lock_held`, with the hub's view) | `agp087_hub_a.rs` `hole_h2_a_written_off_lock_is_dropped_*` (2), `agp088_hub.rs::a_lock_under_a_lock_id_ch1_holds_written_off_is_refused` |
| 2 a hold released on a mempool-only close of an unconfirmed rollover child | a funding is spent for good only when the spend is in a block (`RouteHub::spent_in_block`) | "confirmed" was `gettxout(funding, false) == None`, which a node also answers for every output of an unconfirmed transaction: any spend of an unconfirmed child counted as confirmed, the ch2 became final and its hold left ch1 | "in a block" is the depth the scan found the spender at (`SpendScan::find_spend_at`: bitcoind's `gettxspendingprevout` is the mempool, a block read is a block), or without a depth an output of the spender in the confirmed set, or a funding the watcher saw confirmed while unspent (`fund_confirmed`). `MemChain` now answers `gettxout` without the mempool as a node does | `hole_h2_a_hold_is_released_on_an_unconfirmed_close_of_an_unconfirmed_rollover_child`, `agp088_hub.rs::a_hold_on_an_unconfirmed_child_is_released_once_its_close_is_in_a_block`, `::the_same_with_a_scan_that_does_not_say_how_deep_a_spender_is` |
| 12a a rollover answered 200 and never broadcast | a ch2 leaves the watcher only on a spend in a block; no answer does that | the parent became `rolled`, which the watcher did not reconcile: its coins stayed in it past its expiry | `rolled` is watched until its rollover is in a block, and refunded at expiry like any ch2 if the rollover never comes | `agp087_hub_b.rs::hole_a_rollover_answered_200_*`, `agp088_hub.rs::a_rolled_ch2_is_watched_until_its_rollover_is_in_a_block` |
| 12b the refill funded on the provider's word, outside the cap | coins count against `liquidity_cap_sat` until this node shows them leaving, and a refill is funded when it does | a close reply started the refill at once, and a `closing` ch2 no longer counted: a provider that named closes it never sent had the hub fund one more ch2 per cycle | the refill follows the close only when this node shows a spender of the funding (at once on the provider's own node; else `refillError: deferred` and the watcher funds it when it sees the close); `committed_sat` counts every record until then, archived ones too | `hole_a_close_the_provider_names_and_never_sends_stays_within_the_liquidity_cap`, `agp088_hub.rs::the_refill_follows_a_close_once_this_node_shows_it` |
| 13 the routed client adopts a hub's claims without bound or proof | a completion is proved, a hold is bounded | each hold the hub claimed raised the client's next pre-signed state by one lock, and so did each completion it claimed | a completion is adopted only with the `t + r` that opens that lock's own point (the view's `secret`); at most `max_held_locks` (2) holds are adopted, and at that many the client pre-signs nothing and asks for the hub's view (`POST /x402/route/view`) | `hole_a_hub_that_lies_about_holds_*`, `agp088_hub.rs::a_completion_the_hub_claims_is_adopted_only_with_the_secret_that_opens_the_lock`, `::at_max_held_locks_nothing_more_is_signed_until_the_view_shows_a_hold_resolved`, `::the_view_is_answered_to_ch1s_own_auth_and_spends_its_seq` |
| 19 kept intents | a channel never keeps more than `MAX_KEPT_INTENTS` unresolved spends | only a rollover was refused at the bound: closes one sat apart kept one each | once one slot is left a rollover is refused and the state no longer moves (a close's payload and `/x402/verify` raise nothing), so every close is the same transaction and the last slot is the payee's own close | `hole_unresolved_close_intents_are_not_bounded_*`, `agp088_hub.rs::once_the_kept_intents_are_full_no_request_moves_the_state`, `lifecycle.rs::unresolved_intents_are_bounded` |
| 19 release order | the locks a confirmed spend did not pay leave ch1 before the ch2 record is final | the ch2 record was cleared and made final first: a stop before the ch1 write left a held lock nothing would release | ch1 first, then the record; the next tick finishes a stop in between and nothing is given back twice | `agp088_hub.rs::a_stop_between_the_ch1_release_and_the_ch2_record_is_finished_by_the_next_tick` |
| 19 a lock pending on a ch2 that is not open | a pending lock is completed or written off wherever its ch2 record is | the watcher asked again (and wrote off) only on an open ch2: after a restart with the provider's close in the mempool, ch1 kept its lock in flight until its margin and the ch2 ended final with it pending | written off after `reveal_timeout` on any non-final record, held on ch1, released when the spend confirms without `t`; a ch2 with a pending lock is not replaced (`connect`: `lock_pending`) and its next ch2 does not take over until the lock is written off | `agp088_hub.rs::a_lock_pending_on_a_ch2_that_is_closing_is_written_off_and_resolved`, `::a_ch2_with_a_lock_pending_is_not_replaced_when_its_pay_to_changes`, `::a_next_ch2_does_not_take_over_from_under_a_pending_lock` |
| nit: an adopted earlier attempt's event | | carried the amount last asked for on its second pass | the amount that transaction paid | `hub_money_safety.rs::an_earlier_attempt_adopted_over_a_written_off_lock_reports_what_it_paid` |

On the wire: a refusal `lock_held` (400, with the view); `secret` in the hub's view of ch1; `POST
/x402/route/view` (ch1's PAYMENT-SIGNATURE, an empty body) answers that view. `RoutePayerConfig` has
`max_held_locks` and `held_probe_secs`.

**Stated limits.**
- *What a routed client trusts its hub for.* A hold cannot be proved (the client cannot see a ch2).
  A hub that lies about holds gets the client to sign `max_held_locks - 1` locks above what it
  owes, each at most the client's own `RoutePayerConfig.max_lock_sat` (50,000 sat by default; a
  hub's quoted `maxLockSat` can only lower it, 20,000 at a default hub) plus its fee: one lock by
  default, at most 50,510 sat with the default client settings. With `max_held_locks: 1`
  that is nothing, and one refusing provider then pauses the client's payments to its other
  providers until that provider's ch2 resolves (at the latest its refund).
- *A given-up lock recorded before this version* has no point kept: a completion of it is adopted
  as before, on the hub's word (at most the 16 the client keeps).
- *A ch2 rolled before this version* stays as it was (final, not watched): only ch2s rolled since
  are refunded when their rollover never comes.
- *A refill waits for the hub's own node.* A hub whose node lags the provider's funds the refill
  when the close reaches it (the next tick), not at the provider's answer; a provider that never
  closes gets no new ch2, and the operator's `connect` is refused past the cap while the old one
  is unspent.
- *"In a block" was one block deep.* Since AGP-094 (fix wave 5) it is `spend_final_depth` blocks, 6
  by default.
- *"In a block" without a depth.* A custom `SpendScan` that only has `find_spend` leaves the hub
  with the spender's outputs and `fund_confirmed`: a close of a ch2 never seen confirmed, whose
  outputs are all spent again in the same block, stays `closing` (nothing is released early; it is
  refunded or read again once the scan gives a depth). `fund_confirmed` is the watcher's last look:
  a reorg that unconfirms a funding between two ticks is seen at the next one.
- *One slot short.* A rollover is refused once 7 earlier spends are unresolved (it was 8), and with
  the kept intents full a close takes no higher final state: it reports what it closed at.

New dependency: none (`cargo tree -d` is unchanged).

## Fix wave 5, the hub and the routed client (AGP-094)

The third closure audit (AGP-093) found no High item left and 23 smaller ones. These are its items
for the hub and the routed client. Each row is one rule, kept in one place. The tests named
`agp093_*` are the audit's; `agp094_*` are the neighbours. B1 `xbt402/hub.py`, `route.py` and
`route_client.py` on `agp-094` do the same where B1 has the code, with the same test names where a
test exists: 9 of the 22 names below have no B1 twin, B1's routed open follows the library client's
rule (a keyed ch1 too old to fund is derived again, not refused), and item 13 changed nothing in B1
(B1 `README.md`). (Corrected by AGP-107.)

| item | the rule | what broke it | now | tests |
|---|---|---|---|---|
| 1 one client request stopped the hub routing to a provider | no request of a client's stops the hub routing to a provider, or costs the hub or the provider a transaction | a lock carries what only the client and the provider can check (`lockAuth`, the session, the amount). The hub pre-signed its ch2, the provider refused, and the lock was written off: the ch2 was blocked and closed, and one with nothing signed could not be closed at all (`no_state`) and stayed blocked until its refund | the hub asks the provider first: the lock's own request, marked `check`, without the pre-signature. A refusal there leaves nothing written off, held or blocked (`502 route_failed`, `providerError`). Once it said yes the provider pays that invoice over that hub's channel alone, and does not end its window early, so nothing a client does afterwards makes it refuse. A lock the ch2's floor covers needs no pre-signature: refused, it is dropped. The hub counts a lock only if the provider counted it (`routedSat`), so an invoice sent again from another ch1 does not put the two out of step | `agp093_overflow.rs::one_client_request_does_not_stop_the_hub_routing_to_a_provider`, `::agp094_a_refused_lock_the_floor_covers_is_dropped_and_blocks_nothing`, `::agp094_an_invoice_sent_again_from_another_ch1_does_not_put_the_ch2_out_of_step`, `::agp094_an_invoice_one_hub_checked_is_refused_to_another_channel_at_its_check` |
| 2 a hold released on a close one block deep | what is done on a spend "for good" (a hold given back, a record made final, a refund fee taken back) is done when the spend is `spend_final_depth` blocks deep | one block was final: the block was replaced by one with the provider's other close, the one with `t`, after the client had closed ch1 below the lock | `HubConfig.spend_final_depth`, 6 by default (the depth the hub already asks before it trusts a funding, `ch2_max_min_conf`; the wait costs time, and it is the client's own coins that wait; since AGP-105 the watcher looks for the spend in the block it found it in, not from the ch2's first block on every tick). Until then a spend in a block is treated as one in the mempool: its secrets are read, nothing is released | `agp093_hub.rs::hole_a_lock_released_on_a_close_one_block_deep_is_lost_when_that_block_is_reorged`, `::agp094_a_hold_is_released_when_the_close_is_spend_final_depth_deep` |
| 5, 18 the routed client funded a refusing hub on every `open` | ch1 is funded once: its key is on the books before the wallet is asked, its outpoint before the hub hears of it | ch1 was recorded only with a ledger and only after the funding; without one every `open` asked for a new key and funded again. `duplicate_channel` was not taken as the yes that was lost | `open` goes on from the stage the last call reached, with a ledger or without (then for the life of the `RoutePayer`): a failed funding call is looked for in the wallet before anything is sent again, a funded ch1 is put to the hub again, `duplicate_channel` finishes it | `agp093_client.rs::hole_the_routed_client_funds_a_refusing_hub_once`, `::hole_the_routed_client_finishes_an_open_whose_answer_was_lost`, `::agp094_a_ch1_funding_that_failed_after_it_was_sent_is_adopted_under_the_same_key`, `::agp094_a_keyed_ch1_is_funded_once_by_the_next_open_with_and_without_a_ledger`, `::agp094_a_keyed_ch1_too_old_to_fund_is_refused_until_it_is_forgotten` |
| 12 locks from a ledger before AGP-088 | a ch1 lock is the lock of one ch2 | such a lock was matched by its provider's origin, and one origin can have two ch2s | each is given its ch2 when the hub starts and on every tick (the record of its origin that holds a lock of that ch1 with its lockId and point; of two, the earlier lock is the earlier record's) | `agp093_hub.rs::hole_two_locks_from_a_ledger_before_agp088_to_one_provider_are_released_together`, `::agp094_two_locks_of_one_invoice_from_a_ledger_before_agp088_are_each_given_their_ch2` |
| 12 a held lock completed below ch1's best state | a client stops counting a lock as held when the hub proves it was completed or lists it released | it was in no list of the hub's view, so it counted against `max_held_locks` for the life of ch1 | the view lists the last 16 completed written-off locks with the `t + r` that completed each (`completed`); the client drops one whose secret opens that lock's own point | `agp093_hub.rs::hole_a_held_lock_completed_below_the_best_state_still_counts_against_max_held_locks` |
| 12 a ch2 replaced for a changed payTo | coins count against `liquidity_cap_sat` until this node shows them leaving | the cap check took the replaced ch2 off although it stays counted in the archive | nothing is taken off; the replaced ch2 is `retired`, so the watcher has the provider close it | `agp093_hub.rs::hole_a_ch2_replaced_because_its_pay_to_changed_is_funded_past_the_liquidity_cap`, `::agp094_a_ch2_replaced_for_a_changed_pay_to_is_retired_and_counted_until_it_is_spent` |
| 12 from reading | a lock leaves a ch2 record after ch1 took its completion; a close and the refill it owes are one write; a pending lock is written off wherever its ch2 record is | a failed ch1 write still cleared the ch2 record; a stop between the close's write and `refill_owed` lost the refill; a ch2 archived while open (a ledger before AGP-088) kept its lock pending | the lock stays on the ch2 record for the next tick; `refill_owed` is written with the close and cleared after the refill; the archived one is written off and closed as retired | `agp093_hub.rs::agp094_a_completion_ch1_did_not_take_keeps_the_lock_on_the_ch2_record`, `::agp094_a_stop_after_the_close_is_written_does_not_lose_the_refill`, `::agp094_a_lock_pending_on_a_ch2_archived_while_open_is_written_off` |
| 13 a watcher tick that panics | it ends that tick, never the watcher | nothing caught it: the thread ended and the service went on answering | `RouteHub::watch` and `Provider::close_due` (every provider binary's loop calls it) catch a panic, say it and count it. `xbt402-hub`'s `/healthz` carries `watcher` (`ticks`, `panics`, `lastPanic`, `ch1`) and answers 503 from a tick that panicked until one that did not | `agp093_overflow.rs::a_panic_in_one_tick_does_not_end_the_hub_watcher`, `xbt402/tests/agp093_overflow.rs::a_panic_in_one_watcher_tick_does_not_end_the_provider_watcher`, `agp093_overflow.rs::agp094_the_watchers_health_counts_a_tick_that_panicked` |

On the wire: a lock request with `route.check: true` and no `adaptor` is answered `{"check": lockId}`
or refused as the lock would be (a provider from before the check stops at the missing
pre-signature, `bad_adaptor`, which the hub takes for its yes); `completed` in the hub's view of
ch1; `lock_outstanding` from a provider for an invoice another channel was told it could pay.
`HubConfig` has `spend_final_depth`. `RoutePayer` has `forget_unfunded`.

**Stated limits.**
- *A provider can still stop its own ch2.* A provider that says yes to the check and then refuses
  the lock, or does not reveal in time, is written off as before: that ch2 takes no lock, the hub
  asks for its close, and one with nothing signed waits for the hub's refund at its expiry.
- *One more round trip.* A lock that needs a pre-signature is two requests to the provider, not one.
- *A lock must outlive the hub's wait.* The hub refuses an invoice with less than
  `revealTimeoutSec` left (it was half a second); the client already keeps one second more.
- *Six blocks.* A hold is released, and a ch2 leaves the watcher, `spend_final_depth` blocks after
  the spend, not one. With a scan that gives no depth the count starts at the block where the
  watcher first saw the funding spent, and a reorg between two ticks that it does not see is not
  noticed (the shipped binaries scan with bitcoind, which gives the depth).
- *A held lock completed below the best state is proved by one of the last 16 completions.* A
  client that asks after 16 later ones goes on counting it as held, until ch1 is replaced.
- *A ch1 recorded and never funded* is funded by the next `open` for as long as the hub would still
  open it, then refused `open_unresolved` until the owner calls `forget_unfunded`.

New dependency: none (`cargo tree -d` is unchanged).

## The hub's returns, status and start-up checks (AGP-104)

Step 2 of the hub beside Lightning. Before it, two kinds of coin the hub got back stayed on keys only
its state files know: the hub's remainder when a provider closed a ch2 (paid to that ch2's own payer
key), and what clients paid, when a ch1 closed (paid to that ch1's own payee key). `sweep_payee`
existed and nothing called it. On a 100,000 sat ch2 and one small payment that was 98,854 sat and 546
sat with no tool to move either (`agp104_returns.rs::without_a_return_address_nothing_is_swept` is
that state, kept as the library's default).

**Rule R1: no coin of the hub's rests on a key only its state files know.** With a return address
set (`RouteHub::set_return_to`; `xbt402-hub` sets a fresh bech32 address of its node wallet):

| Where a coin comes back | What happens |
|---|---|
| a ch2 is funded (`connect`, a refill, a ch2 funded ahead) | its `payerSpk` is a return address, so the provider's close pays the remainder there. A hook that fails funds nothing (`return_address`) |
| a ch2 rolls over | the next ch2 names the same return address. One written ahead keeps the script every earlier attempt named. A ch2 on its own key takes a return address for its next one |
| a ch2 is refunded | to its `payerSpk`; a ch2 on its own key is refunded to a return address |
| a ch1 closes (the client's close, its rollover, the margin close) | the watcher sweeps the payout once the close is `spend_final_depth` deep |
| a ledger from before (ch2s on their own keys) | after the upgrade the watcher sweeps what a final close or refund left on each key |

`return_spk()` in `hub.rs` is the one function every return goes through. The link to a Lightning
wallet (AGP-109, below) sits behind it: a second hook, asked first for a return of a known amount.

**Rule R2: one signed sweep per output.** A sweep is written to the ledger before it is sent
(`payee_sweep_intent` on a ch1, `sweep` on a ch2 record). The same bytes are sent again each block
until the chain has them. It is never signed again at another fee or to another address, by the hub
or by `Provider::sweep_payee` called by hand. A sweep is `final` when it is `spend_final_depth` deep.

| What can break R2 | What the code does | Test (`agp104_returns.rs`) |
|---|---|---|
| the close is in a block that is replaced | nothing is signed before the close's output is six deep | `nothing_is_swept_before_the_close_is_final` |
| the send fails | the written sweep is sent again next block; fees and addresses that changed since are ignored | `a_failed_sweep_is_sent_again_with_the_same_bytes_and_never_signed_again` |
| the hub stops between the write and the send | the next start sends the written sweep | `a_stop_between_the_write_and_the_send_leaves_one_sweep_that_the_next_start_sends` |
| the sweep leaves the mempool, or its block is replaced | sent again; final only six deep | `a_sweep_that_leaves_the_mempool_goes_out_again` |
| the wallet spends the swept coin before it is six deep | counted from the block the watcher first saw it gone | `a_wallet_that_spends_the_swept_coin_at_once_does_not_leave_the_sweep_open` |
| the operator runs `sweep_payee` by hand | it gets the written sweep back | the second test above |

Stated limits, one sentence each:

- A sweep signed at a fee that later proves too low is not bumped: it waits in the mempool and is sent again each block.
- A payout under 110 sat plus dust (656 sat at 1 sat/vB) is left on its ch1's key and counted as `dustSat`; one the current fee is too high for waits for a lower fee.
- When fees are high the hub's close of a ch1 is bumped by a child that spends the payout (AGP-067), so less of it, or dust, is left to sweep.
- The hook's address is asked for once per funded ch2 and once per sweep: a wallet restored from seed must look past addresses that were handed out and never paid.
- The return address is an address of the node wallet, which every app on the same node can spend on Paul's Umbrel package: moving the float to the hub's own key is the next task.
- Without a return hook (a library user that sets none) nothing changes: closes pay per-channel keys and nothing is swept.

**Status.** `RouteHub::status(wallet_sat)`, served by `xbt402-hub` as `GET /status` (JSON) and as a
page at `/` (`XBT_HUB_STATUS=off` serves neither; both are on the hub's public port and show no
client's channel). Four numbers, each coin in exactly one:

| Number | What it is |
|---|---|
| `capitalSat` | free, in the hub's wallet |
| `inChannelsSat` | the hub's side of its ch2s, and what a close left on a ch2's own key until its sweep is out |
| `earnedSat` | signed to the hub by clients and not in the wallet yet |
| `stuckSat` | the part of a ch2 a lock without an answer may still take; each is in `stuck` with `resolvesBy`, the block of its ch2's refund six deep |

`capitalSat + inChannelsSat + earnedSat + stuckSat = depositsSat + feesEarnedSat − chainFeesSat − dustSat`,
to the sat, between two watcher ticks. `feesEarnedSat` is what clients signed to the hub less what
the hub signed to providers; it is negative while a provider's dust floor (546 + its close fee) is
above what its client has paid. `depositsSat` is derived from the others, so a test or an operator
who knows what was sent in can check the rest. `estimated` is set when a term was not read off the
chain or the wallet (a ledger from before, a wallet hook that reports no fee), `unsettled` while a
funding is being reconciled.

`capital_sat` is the operator's one setting: it is the liquidity cap, and with funding ahead on a
seller is admitted only while its ch2 and one spare `ch2_capacity` fit under it. `ch2_expiry_blocks`
ships as 1,153, a default seller's floor (it was 1,100 and was raised to 1,153 on every such open, so
what is asked is unchanged).

**Start-up checks (`xbt402-hub`).**

- The node must be on XBT (`node_check.rs`): on mainnet block 961,640 has the pinned hash; on any other chain the checked block (101 on regtest, else the tip) has a 164-byte BLAKE2b header that commits its height and hashes to what the node says. While the node is below that block the hub waits. A configured `network` that is not the node's is refused.
- Every funding states its fee rate: `node.fee_rate` or `XBT_HUB_FEE_RATE` (sat/vB), else the node's estimate for `node.fee_conf_target` blocks. With neither, `connect` answers `no_fee_rate` and writes no record.
- `/readyz` is not ready while the wallet does not answer, and the hub's wallet is created with `load_on_startup`.

Tests: `crates/xbt402-interop/tests/agp104_returns.rs` (20), `node_check.rs` and `status_page.rs`
(unit), four in `xbt402-hub.rs`; B1 `tests/security/test_agp104_returns.py` (18, the same names; B1
has the returns, the sweeps, `capital_sat` and the default, not the status page or the start-up
checks). On regtest, through the real binaries: `./scripts/hub_returns_regtest.sh`.

## The hub beside a Lightning node: wallet link and node-signed identity (AGP-109)

A hub's operator usually runs a Lightning node on the same machine. The hub links to it in two
places and no more: coins above the hub's capital return to the node's on-chain wallet, and the
node signs a statement that names the hub. The link is two calls, `NewAddress` and `SignMessage`.
No key is shared, no call can spend from the node, and no Lightning payment is part of a Stream
payment. Without the three settings the hub runs as before and its 402 is byte for byte what it
was.

Files: `crates/xbt402/src/ln_wallet.rs` (the link), `hub_identity.rs` (the statement and its
check), `macaroon.rs` (the reader, moved here from `xbt-signer` and shared with the wallet's
Lightning rail), `hub.rs` (`return_spk`, `set_return_above`, `set_lightning`, `returns_paid`),
`bin/xbt402-hub.rs` (settings, the link's thread, `/status`), `route_client.rs` (the payer's
check), `status_page.rs`.

**Settings.** `ln.rest` / `XBT_HUB_LN_REST`, `ln.tls_cert` / `XBT_HUB_LN_TLS_CERT`,
`ln.macaroon` / `XBT_HUB_LN_MACAROON` (a file's path; else the secret `hub-ln-macaroon`). The
macaroon is a credential and is never a plain setting. The operator makes it on the node, with
`lncli bakemacaroon --save_to=hub.macaroon uri:/lnrpc.Lightning/NewAddress uri:/lnrpc.Lightning/SignMessage`
or the same two permissions in the node's interface, and gives the hub the file or its hex. A link that cannot be set up (no macaroon,
one too wide on mainnet, no certificate for https) is said at start and on `/status`, and the hub
runs without it: the macaroon is then sent nowhere.

**Rule M1: on mainnet the hub uses a macaroon only if every permission in it is one of the two
calls.** An allowlist read from the macaroon itself: `uri:/lnrpc.Lightning/NewAddress`,
`uri:/lnrpc.Lightning/SignMessage`, and the entity pairs `address:write`, `message:write`, which at
Lightning Fork 0.21.3-beta-blake2b.17 are required by those two calls and by no other (read from
its permission tables: 179 methods, two hits). An identifier that is not LND's, or that does not
parse to its last byte, allows nothing: a reader that stops at a field it does not know has not
seen the whole list. The mainnet rule also applies when the node did not say which chain it is on,
and with `XBT_HUB_LN_STRICT=1`.

**Rule L1: a coin goes to the Lightning wallet only at an address the linked node gave, that the
hub wrote to disk before handing it out, and only until the chain shows that address used.** The
address is kept in `<datadir>/ln-link.json` with every address used before it. "Used" is a sweep or
refund in the hub's own books that pays that script and that the hub's node shows in a block
(`RouteHub::returns_paid`); the next address is then asked for. An answer that is not a witness v0
address of this network, or that the node gave before, is not taken. A file that does not parse
stops the link at start; it is never read as empty. A changed certificate setting holds the
address on file back until the node has signed, and a signature from another key retires it: it
was another node's.

**Rule L2: a return goes to the Lightning wallet only when the hub still holds its capital
without it.** `return_spk(known)` takes what the return pays when that is known as its address is
named (a sweep, a refund) and offers it to the link's hook first; everything the hook does not take
goes to the hub's own wallet as before, through the hook AGP-104 set. A seller channel's remainder
is named at funding, when its amount is not known, so it is never offered. What is above capital
is `status().totalSat - capital_sat`, looked at once a block by the link's thread; each return
takes its amount off that, and a return handed out just before a look stays counted for one more
look (`Budget`), because the look may have read the books before the return was written to them.
Unknown (the wallet does not answer, a funding is being reconciled) is zero. No `capital_sat` is
zero.

An output is not split, so this is coarse on purpose: a payout larger than what is above capital
refills the hub's wallet whole. Returning exactly what is above capital needs a send from the
hub's own wallet; `LnLink::address()` is there for that.

**Rule L3: the link never stands between the hub and the chain.** `LnLink::return_above` reads
memory. The node is asked only from the link's own thread (`ln-link`), with no lock held that a
route or a return takes, after a failure no sooner than 30 seconds later. With the node down the
address on file is still the node's and is paid; once it is used, returns refill the hub's wallet.

**Rule I1: a payer treats a hub as the hub of node N only on a statement that N's key signed, that
names the payTo key and the network of the offer in front of it, and that has not run out and runs
at most 31 days ahead.** The statement:

```
xbt-stream-hub v1
network=<network id>
payto=<the hub's payTo key, hex>
until=<unix time>
```

signed as any Lightning signed message (double SHA-256 of `Lightning Signed Message:` and the
text; 65 bytes in zbase32, the first carrying the recovery id). The hub asks for 30 days, asks
again after 7, checks the answer with the payer's own code before it serves it, and stops serving
it the second it runs out. It is `extra.routing.lightning` of the 402: `{nodeId, statement,
signature}`. The chain of keys is node key, hub key (the statement), fee quotes and the channel
(the hub key, as before). The 31-day bound is the payer's: without it, whoever holds the hub's
macaroon could sign one statement for years.

A hub's address is `<node id>@host:port`. `RoutePayer::new` takes it in place of a URL
(`http://host:port`; a full URL after the `@` is used as it is) and then checks every offer it
reads in `hub_offer`, before a quote is taken or a key asked for. Named by URL, a hub that shows no
statement is paid as before, and one that shows a statement must show a good one.

**What a platform package must pass** (the StartOS and Umbrel packages are later work):

| Setting | Umbrel | StartOS |
|---|---|---|
| the node's REST address | Lightning Fork's app address, port 8080 (its certificate lists that address) | the Lightning Fork container's own address. Not the OS bridge address: there the OS proxy answers with its own certificate, which is not the node's `tls.cert`, and the pin fails |
| the certificate | `tls.cert` from the node's data directory, mounted read-only, that file and nothing else | the same file; or, if the package can only reach the bridge address, the certificate that address presents, which changes when the OS renews it |
| the macaroon | pasted by the operator into the hub's setup and stored as the secret `hub-ln-macaroon`; never `admin.macaroon` read from the node's directory | the same, through an action |

The name in the certificate is not checked (the certificate is pinned), so any address that
reaches the node's own listener works. Not run on either platform.

**New state, and who can fill it.**

| State | Who fills it | At its bound | A slow or failing peer | A ledger from before | Shipped default |
|---|---|---|---|---|---|
| `ln-link.json`: the address in use, the addresses used, the statement | the hub, from the node's answers; one address per return the chain showed | unbounded list, one line per used address | the node down: nothing is added | no file: a new link; the hub's older sweeps paid its own wallet and are not the link's | no link: no file |
| what is above capital (`Budget`, in memory) | the link's thread, from the status | zero when unknown | a hub whose wallet does not answer returns nothing to Lightning | an estimated status sum is used as it is | `capital_sat` 0: always zero |
| `extra.routing.lightning` | the link's thread | absent when run out | the node down for 30 days: absent, the hub is paid by URL only | absent | absent |
| `hub_node` in the payer | whoever constructs the payer | - | a hub that shows nothing: refused | a payer resumed from a ledger checks the same way at its next offer | by URL: none |

Tests: `ln_wallet.rs` (12), `hub_identity.rs` (5), `macaroon.rs` (3) and `status_page.rs` (2 new)
unit; `crates/xbt402/tests/hub_identity_vectors.rs` (3) on `vectors/hub_identity.json`, whose cases
`scripts/hub_identity_vectors.py` writes and checks with code of its own, and which holds a
statement signed by a real Lightning Fork node and six macaroons that node baked;
`crates/xbt402-interop/tests/agp109_ln_link.rs` (11), a real hub, sellers and buyers in memory;
two in `xbt402-hub.rs`. On regtest, through the real binaries beside a real Lightning Fork node:
`./scripts/hub_ln_link_regtest.sh`.

## Fix wave 4: light client and Lightning (AGP-092)

The second closure audit (AGP-087) found each earlier fix had a neighbour left open. For this area
that was list 1 items 14 and 18. Each fix below states the rule the code keeps and goes through one
function; the tests named `agp087_*` are the audit's, those named `agp092_*` are the other sides.
B2 `agentwallet/electrum.py`, `chain.py`, `signer.py` and `xbt402.py` on `agp-092` do the same for
the light client, with the same test names.

### The light client (`xbt-electrum`)

**Rule 1: unknown is not absent.** A lookup says "not there" (no such transaction, no such output,
not in a block, no such coin) only when every configured server answered (`all_answer`). If one did
not answer, or is down, the call fails with `Kind::Unreachable`; `min_servers` is the floor for what
is proven, not for this. `tx_out` says "spent" only for a confirmed spend with a proof.

| place | before | now |
|---|---|---|
| `fetch_tx` (the transaction asked for) | every server failed `transaction.get`: `None` | every server is asked at once, the first that supplies it wins; `None` only if each said it has no such transaction (`NOT_THERE`), else an error |
| `locate` (is it in a block or a mempool) | one server answered the history without it, the others failed or were down: no status | `Hist::complete`: an error unless every configured server answered |
| a server that is down, or drops in the middle of a call | left out of what is asked, so the rest decided | it has not answered: "not there" is an error (`a_server_lost_in_the_middle_of_a_call_is_not_forgotten`) |
| `confirmed` (the Merkle proof) | the server that listed a height failed the proof request: "unconfirmed" | `Proof::checked`: an error unless a proof was found or every claim was answered |
| `unspent` (`scantxoutset`) | a coin whose transaction or proof went unanswered was left out | the scan fails |
| `unspent`, a server that did not answer the listing at all | a shorter list | still returned, since every coin in it is proven, and marked: `unspent_marked`, `"complete": false` in the `scantxoutset` answer |
| `transaction`, `has_transaction`, `tx_out`, `call("gettxout")`, `call("getrawtransaction")` | as above | all go through `locate` |
| `spender` (the search for a spend) | a spend only a failing server lists is not found | **unchanged, on purpose**: "unspent" can only be acted on by a broadcast, which the network refuses if it is wrong. Were this an error, one server could hold a refund back by listing a spend and never proving it (`evidence_an_unproven_spend_does_not_hold_the_refund_back`) |

**Rule 2: a call has a deadline.** Every request one call makes ends at `Config::call_deadline`
(four timeouts unless set), counted from the end of its header sync. A call forces one header sync
at most. A server is asked only for the transactions it listed itself (`supply`), in parallel with
the others: one first, then `TX_BATCH` at a time. Its list ends, with a flag, at the first it does
not supply, at the first that neither pays the script nor can spend an output that does
(`invented`), and at the deadline. A server has one claim per transaction: a block height replaces
a mempool entry for it (electrs lists both while a block arrives), and a second block height is
flagged and is not a claim. A server that refuses its tip is hung up on, so the next round
negotiates the protocol again (electrs answers 1.4 until it has indexed a v2 header). Connecting costs one timeout for the TCP connect and the TLS handshake together
(`Connection::connect_until`; `complete_io` waited a full read timeout for every byte), then one
for `server.version` and one for the subscriptions. A server that is down is tried once per call
(four times per `gettxout` before).

Measured by the audit's tests (their `AGP-087 measure` lines), debug build, loopback, one run: the
40 entries at 250 ms each held `gettxout` 13.2 s before and 0.97 s now (one request to the server
that listed them); 50 invented entries cost 150 `transaction.get` on the second call before and 1
now; 200 claims above the tip forced 202 sync rounds before and 2 now; a TLS handshake trickled at
one byte per 100 ms under a 300 ms timeout held `connect` 4.0 s before and 0.30 s now. Rerun:
`cargo test -p xbt-electrum --test agp087_light -- --nocapture --test-threads=1`. On regtest against
electrs 0.11.1: `XBT_ELECTRUM_PORT_BASE=26000 scripts/electrum_interop.sh`, 3/3 scenarios.

**What a server can still do.**

* If every configured server hides a transaction, it reads as absent
  (`evidence_every_server_hiding_reads_as_absent`). A caller that would book a loss on that must
  ask for the proven spend (`spending_tx` with a confirmed status), as B2's refund and
  `funding_spent` now do (`chain.spend_is_evidence`).
* By not answering, or by being down, a server turns every "not there" into an error for as long
  as it is configured. By listing transactions that pay the script (which cannot be told from unconfirmed
  payments) and supplying them slowly, it holds each call that reads that script up to
  `call_deadline`. Both are flagged (since AGP-097 a request the call's deadline cuts short is
  given up without a flag, and such a server is flagged only if it was asked for one of the
  transactions it withheld); the cure is to remove the server.
* "No such transaction" and "not in that block" are read from the server's words
  (`backend::NOT_THERE`). An error worded otherwise counts as no answer, which fails closed.
* The worst case of one call is its header sync (`sync_deadline` for the caller that holds the sync
  gate), then `call_deadline`, then one forced sync.

### The Lightning rail (`xbt-signer`)

**A booking released as never sent is watched for as long as its HTLC can last** (L4).
`LnPolicy::htlc_blocks` is the one function both the limit sent to the router and the watch read.
A BOLT 11 payment goes out with `cltv_limit = ln.max_cltv_blocks`. `PayOffer` takes no limit, so an
offer's HTLC is bounded by the node's own `max-cltv-expiry`, which the wallet cannot read: the new
policy field `ln.node_max_cltv_blocks` (2016, LND's default) says what it is, and an offer's
released booking is watched that long plus 144 blocks, by the send path and by the reconcile after
a crash. An HTLC seen in flight past the policy's figure is written to the audit log
(`ln_cltv_beyond_policy`). Tests: `agp087_ln_l4_an_offers_htlc_can_outlive_the_rebook_watch`,
`agp092_l4_every_release_is_watched_for_as_long_as_its_htlc_can_last`,
`agp092_l4_the_offer_watch_follows_the_policy`. Limit: an owner who raised the node's
`max-cltv-expiry` above 2016 and did not raise the policy field has a watch shorter than the HTLC.

**A funding is proven only when its txid cannot be a valid transaction on the SHA-256 chain** (L5).
The signatures of a segwit or taproot input are in the witness, which the txid does not commit to,
so the 0x21 bytes read on XBT say nothing about the same txid with other witnesses on the other
chain. `ln_funding::xbt_only` now asks what pins the txid: the funding, or a transaction it
descends from, is a coinbase at or above the split or carries a 0x21 signature in a scriptSig (a
P2PKH spend). The search is breadth first through coins confirmed at or above the split and looks
up at most `ANCESTRY_LOOKUPS` (256) transactions; the verdict is cached per funding block as
before. A funding with no pin in reach is refused, and the refusal says how to fund one that
passes (mined coins, or coins that went through a P2PKH address after the split). (AGP-097: the
coinbase pin is weaker than the sentence in bold; see the limits of fix wave 5 below.) Tests:
`agp087_ln_l5_a_funding_whose_replayed_parent_is_signed_0x01_is_not_proven`, `agp092_l5_*` (3), and
on real nodes `scripts/ln_rail_regtest.sh` (Lightning Fork `.17`): 87/87, with the lab's proven
channels now funded from a P2PKH coin (`drive.py::send_pinned`) and S10 checking the pin
(`docs/agp092_ln_rail_regtest.json`).
The test rig's channels are now funded from a coinbase, as a mined coin is; no assertion changed.
**This changes which channels carry payments**: a node funded from coins with a long history of
segwit spends is refused until it is funded as above. The signatures are still not verified in the
signer (the node that accepted the block did).

**The rate limit counts sends.** `LnBook::put_sending` is the one place a payment is booked before
it is sent, for an invoice and for an offer; it keeps the times of the sends of that payment hash
in the last hour, and `sends_since` adds them up. Tests:
`agp087_ln_side_retries_of_one_invoice_are_not_rate_limited`,
`agp092_retries_of_an_offers_invoice_are_rate_limited`.

**LN state files are durable.** `ln::write_json` (the payment book, `ln_halt.json`,
`ln_offers.json`) now writes through the counted steps of `fsx` and fsyncs the directory after the
rename, so a halt survives a power loss. Test:
`agp092_ln_state_files_are_written_through_the_durable_steps`.

**For embedders.** `xbt_electrum::Config` has a new field `call_deadline`; `Connection` has
`connect_until`, and `subscribe_many` takes a deadline. Calls that answered `None` or left a coin
out when a server was silent or down now return `Kind::Unreachable`; `unspent_marked` and the
`complete` field of a `scantxoutset` answer say whether every configured server answered. `LnPolicy` has `node_max_cltv_blocks`.
`ln_funding::Funding::Proven` evidence has an `xbt_only` object.

## Fix wave 5: light client and Lightning (AGP-097)

The third closure audit (AGP-093) found no High item left and, in this area, list 1 items 10, 11,
14 (one part), 20 and 22: half of them inside the rules wave 4 added. Each fix states the rule in
the code and has a test that failed first; the audit's tests are `agp093_light.rs` (10, all pass)
and B2 `tests/test_agp093_light.py` (10, all pass), the other sides are `agp097_light.rs` (7) and
B2 `tests/test_agp097_light.py` (12). B2 `agentwallet/electrum.py` on `agp-097` keeps the same
rules.

**What a scan asks a server for does not grow with the number of coins beyond what each coin
needs once** (`ElectrumBackend::unspent_marked`; B2 `_rpc_scantxoutset`). The call's deadline
covers the whole scan, and anyone can add coins to an address by paying it dust. The scan asked
every server for the script's whole history once per coin, and proved the coins one request at a
time, each from the first server that claimed it: with 20 coins, one honest server a quarter of
the timeout late made every scan fail at the deadline, for as long as it was configured. The
history is now asked for once a scan (`spends`), and the proofs in one batch per server, all
servers at once (`prove_ahead`; a proof that does not hold is asked for again and judged by the
request that follows, as before). Measured: 20 coins beside a server 250 ms late on each history
request, timeout 1 s: an error at 4.0 s before (the audit's run), 20 coins now; a cold scan beside
a server 250 ms late on each proof request, where one request a coin is 5 s against a deadline of
4 s: 20 coins in 0.46 s (`cargo test -p xbt-electrum --all-features --test agp093_light --test
agp097_light -- --nocapture` prints both).

**Every entry that makes requests runs under one call budget** (B2 only: `ElectrumBackend._budget`).
`call()` set the budget; `proven_spend`, which the refund's evidence calls on its own
(`chain.spend_is_evidence`), did not, so each of its steps had a deadline of its own and each
height a server claimed forced a header sync of its own: 20 claims were 20 sync rounds, and 30
took 12 s against a bound of 6 s. One sync round and 0.41 s now. The Rust backend takes its
budget in each typed call and was not affected.

**A server is hung up on only for a request that went a whole timeout unanswered**
(`Connection::batch_until`, `Kind::Deadline`; B2 `request_by`, `Late`). A call's deadline is shared
by every server it asks. A request it leaves no time for is no longer sent, and one it cuts short
is given up without closing the connection and without a flag; before, both ended as a timeout,
and the honest server that answered at once was dropped and flagged because another had used the
time up. A server whose list of transactions runs into the deadline is flagged only if it was
asked for any of them. A server's part of a header sync has its own deadline and still ends with
a hang-up.

**A claim is a lie only against a tip the server reported after it made the claim**
(`ElectrumBackend::confirmed`, `Call::round`). A claim above our chain forces one header sync. When
that sync found another in flight it ran nothing, and the claim was then judged against the tip
the server had reported earlier: a block that arrived in between made two honest servers liars,
and the lookup answered "no such output" for a confirmed coin. It is judged now only against a tip
the server reported in the round the call itself ran (or a later one); otherwise it is unknown and
the call fails.

**An error about the method is not "not there"** (`backend::says_not_there`). "Method not found"
contains two of the words "not there" is read from. An error that names the method is no answer,
and the connection puts JSON-RPC's code -32601 into those words when the server's own leave the
method out.

**A request is written by one deadline** (`Link::send`; B2 `ElectrumConnection._write`). B2 wrote
with `sendall` on a socket with no timeout: a server that stopped reading held a 2.6 MB broadcast
for good, under the signer's lock. The Rust write had a timeout per write, which a server that
reads a little at a time never trips: 3.3 s for a 10 MB line at a 500 ms timeout in a run made
before the change, 0.8 s now (`a_server_that_reads_a_little_at_a_time_does_not_hold_a_broadcast`
prints it). Each write gets what is left of one deadline.

**Sums of what servers supply are checked.** `scantxoutset` adds the proven coins' values with a
checked sum and refuses a total past 2^64-1 (it was a panic; the typed `unspent` adds nothing up).

**For embedders.** `Kind` has a new variant `Deadline`. `ElectrumBackend`'s API is unchanged.

**Limits, stated.**

* A cold scan of N coins still asks each server that lists them for N transactions and N proofs,
  16 to a batch. A server that takes longer than one timeout to answer a batch is dropped for that
  call; the other servers' answers decide, and what was proven is kept for the next call.
* A call that finds another sync in flight just as a block arrives fails with "not known" for that
  block's transactions until a sync that began after the block has ended. It no longer answers
  "not there".
* A request given up at the call's deadline stays pending on its connection until its answer comes
  or the connection ends, so a late answer is within what the connection allows. A server that
  never answers is still dropped by the first request that waits a whole timeout for it.
* **The Lightning funding proof takes a coinbase as XBT-only, and XBT's consensus does not make it
  so** (read from Knots `61b07b8`, not fixed). A coinbase's txid commits to its height and to
  nothing that names the chain: the txid is the double SHA-256 of the same bytes on both chains,
  and consensus asks a post-fork coinbase for the height (BIP 34), a value within subsidy plus
  fees, and the fork headline in the fork block only. The coinbase of XBT's block H is therefore a
  valid coinbase for the SHA-256 chain's block H, and for no other block there. It is XBT-only when
  the other chain already has another block at that height and does not reorganise below it; where
  it has not, whoever mines that block can mine the same coinbase, which pays the same keys. That
  takes one party a block on each chain at one height, or a miner giving its reward to the other
  coinbase's payees. The signer has no node of the SHA-256 chain to compare heights with. The 0x21
  scriptSig pin does not have this limit. Decision, 2026-10-11: the proof stays strict, so the rule is
  unchanged and this is its stated limit (`ln_funding.rs`, module documentation).
* **One channel that fails the funding proof stops every BOLT 12 payment** (decided: it stays).
  The node chooses the channels an offer's payment leaves through, after the wallet's check and in
  parts, and `PayOffer` takes no `outgoing_chan_ids`. Which channels "can" carry the payment
  changes between the check and the send (an HTLC towards us settles, a peer reconnects), so a rule
  read from balances would be checked at one moment and used at another. An inbound channel from
  an ordinary peer whose coins have no pinned ancestor therefore stops offers until the owner
  closes it; BOLT 11 payments go on, confined to the proven channels.

## Portability

No platform-specific dependencies: libsecp256k1 (C, via `secp256k1-sys`), pure-Rust hashes and JSON,
`getrandom`, std threads (no async runtime). The payer HTTP client uses `ureq` with rustls/ring
(no OpenSSL). Every HTTP server (xbt402 `http-server`, wallet-ui, the work relay, the MCP) is
`xbt_svc::http`, std only (AGP-068, AGP-072). `cargo check -p xbt402` (library, and all features + the hub binary)
passes for x86_64/aarch64 Linux gnu and musl, armv7 and riscv64 Linux, x86_64/aarch64 macOS and
x86_64 Windows (gnu), with zig as the cross C compiler; aarch64 links (`xbt402-hub` 4.5 MB).
Under v1.2 payee-pays, the close response reports `cum` as what the close pays the payee **net of
its fee** (900 for a 1500 state with a 600 fee), and `unpaidMsat` as `spent − that`. So it shows
the close fee as unpaid (600000), and `/x402/settle`'s `amount` likewise. The on-chain amounts are
right. B1 `x402_channel.py` does this (`_close_paid` sums the payee outputs), and the Rust port
matches it byte for byte. The interop run records it as `provider_report_as_reference`. Whether the
reference should report the gross `cum` is for the lead (AGP-023 follow-up), not this port.

## The light backend: xbt-electrum (AGP-028)

A client with no node: the xbt402 payer (and later the wallet) reads the chain from Electrum servers.
What it is told about headers, transactions, confirmations and confirmed spends it checks; that a
transaction or a spend does *not* exist it cannot check, and takes only as the answer of every
server it asked (see "Fix wave 4" below for the rule and its limits). A port of B2's `agentwallet/electrum.py` (AGP-024) with the same
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

`scripts/electrum_interop.sh` (ports 23300-23399) runs a light Rust payer (its own hot key; every read
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

## Light client and consensus edges (AGP-069, review E1–E3, S1, M1)

The light backend now checks headers as Knots does from the first header above the checkpoint. It
withholds answers while its chain is not believable, and a lying server cannot get a cheap fork
believed or stall the header sync. (What one server can cost any other call is bounded since
AGP-092: "Fix wave 4" below.) The hot wallet waits for the coinbase maturity the node reports. B2
`agentwallet/headers.py`, `electrum.py`, `maturity.py` and `hot.py` on `agp-069` (`21db571`) and B1
`xbt402/tx.py` on `agp-069` (`efd5770`) do the same, with the same test names (`test_` prefixed in
Python). Knots line numbers below are v29.4.2.

**Header rules (E3).** `HeaderChain` refuses:

- a header whose top two flag bits are set (`bad-flags-highbits`, validation.cpp:4431);
- a version below 4 once bit 31 is masked off (`bad-version`, 4757–4762);
- a time not above the median of the 11 before it, from the first header above the checkpoint on
  (4737);
- on regtest, nBits other than the min-difficulty walk-back gives (pow.cpp:42–56,
  `ChainRules::next_bits_with`);
- any block other than the pinned one at a pinned height (`ChainRules::pins`; on mainnet 964264,
  Knots' assumevalid block, chainparams.cpp:150).

The median and the walk-back need the 10 headers below the checkpoint, so
`set_checkpoint(raw, prior)` now takes `PRIOR_HEADERS` (10) 80-byte v1 headers. Each must hash-link
to the one above it, and the last to the checkpoint. The backend fetches them from the servers, and
they are never answered as ours. Testnet3, testnet4 (BIP94) and signet have no rules here, so
`ChainRules::for_chain` refuses them and no chain starts.

**Believable chain (E2).** On mainnet every chain answer fails with `Kind::Implausible` (B2:
`ImplausibleChain`, status `"implausible"`) until the verified chain:

- reaches every pinned block;
- carries Knots' nMinimumChainWork (chainparams.cpp:149, the chainwork of 964264) less the
  chainwork of 961640, which is 0x10c4284b5592c3c377 by Knots' `getblockheader`;
- trails one block per 600 s since the newest pinned block by at most 2016 blocks.

`Config.plausibility` overrides this (default `Plausibility::mainnet` on mainnet, none elsewhere)
and `Config.clock` sets the clock in tests. A checkpoint of unknown chainwork gets no minimum work,
but it still has to reach the pins.

**TLS (E2).** On mainnet every server must be `ssl://`. `tcp://` is allowed only to a loopback host
(`is_loopback_host`); anything else is `Kind::BadRequest` from `ElectrumBackend::new`.

**Lying servers (E1).**

- On mainnet a claimed tip is believed up to ours + (time since our tip / 150 s) + 2016
  (`TIP_CAP_SPACING_S`). Nothing above that is fetched, and the server is flagged.
  `Config.tip_cap_spacing_s` sets it; it is off by default elsewhere, because regtest mines blocks
  as fast as it is asked to (the interop run's electrs were flagged until it was).
- Each chunk is checked as it arrives (`HeaderChain::branch`, `Branch::extend`), so the first bad
  header stops that server's sync. The branch is adopted only if it has more work and our chain
  under it has not moved (`HeaderChain::adopt`).
- No lock is held across a network read. Servers sync in parallel. Once a chain is held, a caller
  that finds a sync running answers from the verified chain instead of waiting (a try-lock gate);
  only before the first chain do callers wait.
- Before a chain is held, a tip outside our powLimit means another chain: `Kind::CheckpointMismatch`,
  as for a missing checkpoint.

**Sighash (S1).** `unified_sighash_ext(…, SpendExt { annex, codesep_pos })` commits an annex as
`0x01 ‖ sha256(compact_size ‖ annex)` (interpreter.cpp:1730–1732, 2152) and the position of the
last executed OP_CODESEPARATOR after the leaf hash (1749). It refuses values the script type does not
commit to: an annex outside taproot, an annex without the 0x50 tag, and a position outside
tapscript. `unified_sighash` is `SpendExt::default()` and unchanged, so the 166 pinned vectors still
match. B1's `unified_sighash` takes keyword-only `annex=` and `codesep_pos=`. Knots' REDUCED_DATA
refuses any annex on mainnet until 2027-09-01 (2149–2150). For script type 0, `script_code` must
already have this signature's pushes removed: Knots still runs FindAndDelete there (345–349), and
the docs of both functions now say so. The 60 new vectors in `vectors/unified_sighash_ext.json`
were computed with Knots' own Python test framework (`scripts/gen_unified_sighash_ext.py`); main
matches 8 of them (the cases with neither an annex nor a codeseparator).

**Coinbase maturity (M1).** The hot wallet learns which coins are coinbase outputs from
`scantxoutset`, `gettxout`, and a funding transaction's `vin[0].coinbase`. Such a coin is spendable
once tip + 1 ≥ h + max(depth, 100), with the depth from the node's `getdeploymentinfo`
`long_coinbase_maturity` (Knots' mempool holds every coinbase spend to that depth,
validation.cpp:1021–1022). A node that cannot say holds them: the light backend has no
`getdeploymentinfo`, so a light hot wallet does not spend coinbase coins. `fund`, `rotate`, the
sweeps and `status` (`hot_coinbase_sats`) all use it. `Maturity` moved from xbt-work to
`xbt402::maturity` (xbt-work re-exports it), so the signer does not depend on xbt-work.

**CAIP-2.** `network.rs` now says why XBT's id is keyed to block 961640 and not genesis: a
genesis-keyed id would be the SHA-256 chain's as well.

**Embedders.**

| change | who must act |
|---|---|
| The header store records the priors; a store from an older release is ignored and the chain resyncs from the checkpoint once | nobody (one resync) |
| `set_checkpoint(raw, prior)`; `HeaderChain::new` takes `impl Fn() -> u64` (was `Box<dyn Fn>`); `Header` gains `version` and `flags` | anyone driving `HeaderChain` directly |
| Mainnet light backend: `ssl://` only, except loopback | configs listing `tcp://` mainnet servers |
| New `Kind::Implausible`: retry later, as for `NotFound` | exhaustive matches on `Kind` |
| Servers must serve the 10 v1 headers below the checkpoint (`blockchain.block.headers`; electrs does) | operators of other Electrum servers |
| Coin records gain `"coinbase": true, "height": h` (only on coinbase coins); spending them needs `getdeploymentinfo` | hot-wallet users with mined coins |
| `xbt_work::chain::Maturity` is `xbt402::maturity::Maturity` | nobody (re-exported) |

cmp, xbt-compute, B5 and xbt-063 pin their own copies and are unaffected until they re-pin.
Nothing on the xbt402 wire changes, and `scripts/conformance.sh` is unchanged (253/253).

Choices (best-performing-stack rule; the code ships in the existing Rust crates, with the Python
references kept in step, and adds no dependencies):

| question | options | chosen, and why |
|---|---|---|
| not stalling on a slow or lying server | one lock across reads (main); a background sync thread with a channel; a try-lock gate | **the gate**: no new thread or state, and callers keep answering from the verified chain |
| when headers are checked | after a whole batch (main); per chunk as it arrives; one request per header | **per chunk**: the first bad header ends the fetch, and the round trips stay batched |
| how high a claimed tip to believe | anything; a fixed cap; a cap from elapsed time | **elapsed time** (4× the target block rate, plus 2016): a real tip always fits |
| the headers under the checkpoint | skip the median for the first 10 (main); ship them in the binary; fetch and hash-link them | **fetch**: an operator checkpoint works too, and the hash link adds no trust in the server |
| coinbase depth | hard-code the #419 schedule; ask the node | **the node**: it is what the mempool enforces; unknown means hold |
| annex and codeseparator | more arguments on `unified_sighash`; a new function | **`unified_sighash_ext`**: no caller or pinned vector changes |

**Cost.** Pass line declared before measuring:

- (a) per 2016-header chunk, validation costs at most 10% more than on main;
- (b) on armv7 (Cortex-A7 class), the catch-up from 961640 to a tip about 10,000 headers above it
  takes at most 10 s of CPU, and the priors at most 10 ms;
- (c) the plausibility check on every answer costs at most 1 µs on x86.

`cargo run --release -p xbt-primitives --example header_cost` on a Ryzen 9 9950X3D, three runs
interleaved with the same example built on main:

| per header (8064 synthetic headers) | agp-069 | main |
|---|---|---|
| parse (BLAKE2b) and PoW alone | 810 ns | 820 ns |
| connect, mainnet's path (no min-difficulty walk) | 940–950 ns | 950–1004 ns |
| connect, regtest rules | 2176–2250 ns | 961–1011 ns |
| the 61 real mainnet headers from 961640, checkpoint included | 974–990 ns | 945–973 ns |

- Mainnet passes (a): no difference on its path, and +3% on the real headers.
- **Regtest fails (a) at +125%.** All of it is Knots' min-difficulty walk-back, which on regtest
  walks to the last 2016 boundary for every header. Mainnet never runs it. It is kept because it is
  the Knots rule; 8064 regtest headers still take 18 ms.
- The checkpoint with its priors costs 2.3 µs (main 0.9 µs). `branch()` at the tip copies the last
  2016 headers once per sync round, 31 µs. `implausible()` costs 8.4 ns per answer, which passes (c).
- There was no armv7 box or emulator, so (b) is an estimate. The armv7 build of the example
  compiles. BLAKE2b is 64-bit arithmetic, roughly 50–100× slower per header on a 900 MHz Cortex-A7,
  so 10,000 headers take about 0.5–1 s and the priors well under 1 ms. That passes.

**What this does not fix.**

- Above pin 964264 a fork is still cheap: difficulty there is `1a00f0b5`, about 2^56 hashes per
  block (2^72 / 0xf0b5). The floor only raises the bar for a fork that also hides the real tip. Releases should bump
  the pins, and operators can set a later checkpoint.
- A call that fans out to every server waits for the slowest one, up to the timeout (no lock held).
- One batch can fetch up to 4×2016 junk headers before the first is checked (B2 fetches chunk by
  chunk).
- If blocks really did come much slower than one per 600 s for weeks, the floor would withhold
  answers until the pins are bumped.
- A light hot wallet cannot spend coinbase coins (fail closed).

Tests, each failing on main first:

- `crates/xbt-primitives/tests/header_chain.rs`: `e3_flags_highbits_and_version`,
  `e3_median_time_from_the_first_header`, `e3_min_difficulty_walk_back`,
  `pinned_heights_refuse_any_other_block`, `unsupported_test_networks_fail_closed`,
  `a_branch_validates_as_it_grows` and `mainnet_checkpoint_with_its_real_priors` (the 71 real
  headers 961630–961700 from xbt-snapshot, `vectors/mainnet_headers_961630.json`). Unit test: `mainnet_minimum_work`.
- `crates/xbt-electrum/tests/backend.rs`:
  - `mainnet_needs_tls`;
  - `hostile_lying_server_cannot_stall`: main gives no answer within 10 s, and a slow server holds a
    caller 1.2 s;
  - `hostile_cheap_fork_is_not_believed`: main shows 20 confirmations on the fork;
  - `tip_cap_is_mainnet_only`.
- `crates/xbt-primitives/tests/sighash_ext.rs`: `s1_annex_and_codesep_vectors_match_knots` and
  `s1_refuses_values_the_script_type_does_not_commit_to`.
- `crates/xbt-signer/tests/review_e.rs`: `m1_coinbase_waits_for_the_node_maturity`,
  `m1_coinbase_waits_when_the_node_cannot_say` and
  `m1_coinbase_flag_from_gettxout_and_the_transaction`. On main the wallet spends a block-200
  coinbase at block 299. Unit test: `maturity_from_the_node`.

## Pay-with-work: xbt-work (AGP-032)

**XBT-053 is not published.** The pay-with-work specification this section follows, its Python
reference and its vector file are in a repository with no public remote. Every "XBT-053" below,
and every count over its vectors, names something a reader cannot fetch today; the Rust crate and
its tests are what can be checked. The Prime (`primed`) is on a branch that is not public either.

`crates/xbt-work` implements the x402 scheme `xbt-work` (v1 draft, XBT-053 `agp-011`
`docs/xbt-work-spec-v1-draft.md`): a client with hashrate pays by mining. It mines as
`<identity>.pw-<invoice>` so the Prime credits the provider, then presents the Prime's signed
cumulative receipt with each call. It ports XBT-053 `receipts.py`, `nta.py` and `relay/`, plus the
xbt-070 coinbase audit.

* **Provider.** `Provider::new(..).with_scheme(Arc::new(WorkScheme(Arc::new(WorkProvider::new(cfg)?))))`:
  every unpaid 402 lists `batch-settlement` and `xbt-work`. `POST /x402/xbt-work/invoice` issues invoices
  (`Cache-Control: no-store`; the bound on unfunded invoices and `429 too_many_invoices` are gone since AGP-091: issuing stores nothing). Payments are
  checked in the §9.1 order and debited durably (a 0600 state file, write+fsync+rename) before the
  handler runs. A handler answer ≥ 500 releases the debit. `refresh` pulls receipts through the
  blinded relay; `set_epoch` re-prices new 402s (§6.3). After an equivocation or a failed audit, the
  Prime's receipts are refused.
* **Payer.** `Client::new(..).with_payer(Arc::new(WorkPayer::new(cfg)?))`: on a 402 offering
  `xbt-work` it takes an invoice (`prepare` returns the username to mine as), fetches and verifies the
  latest receipt through the relay, and presents it with a fresh `n` and `auth`. It checks every
  `SettlementResponse`: the invoice, `req`, the charge within the quote, and `spentWork` growing by
  `charged` (since AGP-091: and by no more than the quotes of earlier calls still unanswered). An optional pinned Prime key is checked against the offer.
* **Audit.** `WorkProvider::audit(window, deferrals, V, paid)` applies §10.3 with the provider's own
  intervals and counts signed deferral lines (NTA `unattested` carry) as debt. The carry ledger
  tracks what is owed. A failing block yields a §10.4 fraud proof that `check_fraud_proof` verifies
  from its signed contents alone. Per invoice, the proof carries the latest receipt and the in-span
  receipt that brackets the window, so a third party can prove the work.

Conformance (`scripts/work_conformance.sh`): the Rust emitter rebuilds XBT-053's `vectors.json`
byte for byte (`cmp`). The Rust checks pass 91/91 over XBT-053's file (16 sections recomputed,
75 independent checks). XBT-053's own `check_work_vectors.py` passes 124/124 over the Rust-emitted
file.

Regtest (`scripts/work_interop.sh`, ports 24100–24199) uses primed (branch `rnd/agp-011`, not public), the stock DATUM
gateway, stratum-grind and the XBT-053 relay. Results on 2026-09-29 (evidence in
`docs/work-interop-agp032-*.json`):

| payer | provider | checks |
|---|---|---|
| Rust (xbt402 Client + WorkPayer) | Rust (xbt402 Provider + WorkProvider) | 20/20, incl. the provider's own audit and both fraud proofs |
| Python (xbt-063 `pww_payer`) | Rust | 20/20 |
| Rust | Python (xbt-063 `flagship.server` WorkRail) | 18/18 |

Regtest's difficulty makes `8 × D` less than one share, so primed runs with `window-min-work = 64`.
Otherwise the window holds only the latest share and no receipted span can be proven inside it.

Portability (`scripts/work_matrix.sh` → `dist/WORK_MATRIX.md`): 20/20 builds (10 AGP-031 targets ×
release and release-small, 1.8–2.5 MB self-test). The self-test runs natively on x86_64 glibc and
musl. Pure-Rust Ed25519 (`ed25519-dalek`) and ChaCha20-Poly1305 (RustCrypto); libsecp256k1 only
through `xbt-primitives` (NTA BIP340).

## xbt-work follow-ups: caps, the Rust relay, a live NTA leg (AGP-043)

* **§13.1 credit caps.** `WorkConfig::caps` (`CreditCaps { per_invoice, total }`, work units) caps credit that
  no passing audit covers yet. Receipted work beyond the caps is **held**: kept in the book, not spendable, and
  credited once a coinbase audit passes above it. The audit intervals record every receipted increase whether
  credited or held, so the audit bound never depends on the caps. Owed carry counts as unaudited credit too:
  above `max_owed_carry_sats`, or growing over `carry_growth_blocks` audited blocks, no new credit is extended
  until carry is released. A call the held work would have paid is refused with `credit_cap`, `carry_cap` or
  `carry_growing` and the balances in `work` (`heldWork`, `unauditedWork`, the caps); the Rust payer reports
  that as its error instead of paying again. Auditing a block again replaces its verdict and carry. Without caps
  the book is the reference, byte for byte (the vectors are unchanged: 91/91 and 124/0).
  `xbt-work-provider`: `--cap-invoice[-sats]`, `--cap-total[-sats]` (sats are converted at each epoch's price),
  `--max-carry-sats`, `--carry-growth-blocks`, `--nta` (refuse an identity that is not key-path P2TR, §13.8),
  `--audit-depth K` (audit every pool block K deep on its own), `GET /admin/xbt-work/report`.
* **The Rust relay server.** `crates/xbt-work-relay`, binary and image `xbt-work-relay` (docs/CONTAINER.md §9): a
  keyless store of exactly-1,052-byte blobs; a public GET-only listener (no listing, `no-store`, a token bucket
  per client) and a separate push listener for the Prime (optional bearer token `relay-push-token`); one file
  per lookup on disk, bounded by count and age. `scripts/work_interop.sh` now uses it by default (`RELAY=py` for
  the XBT-053 relay); `scripts/relay_container_test.sh` tests the image.
* **The live NTA leg.** `scripts/work_nta.sh` (ports 24300–24349, ~20 min): AGP-011's NTA regtest stack with the
  Rust provider (`--nta`, caps 1/1, carry cap 10 XBT), the Rust payer and the Rust relay. A: paid, the cap holds
  the new share (`credit_cap` live), the audit releases it. B: signer stopped, a signed `unattested` deferral
  line, the Rust audit passes on it (a fraud proof without it), carry freezes new credit (`carry_cap` live). C:
  paid with the carry, released. D: a pool block outside the invoice covers the rest. Then the payer's 19 checks.
  42/42 on 2026-09-29 (`docs/work-nta-agp043-20260929-032035/`).

## The coinbase audit without trusting the Prime (AGP-065, review P1–P6)

An external reviewer read the public snapshot (xbt-rs `9201104`). The point: the §10.3 audit took every
number from the Prime's own window statement, so a Prime colluding with a payer could receipt work
nobody mined and then sign a statement that excused the unpaid coinbase. Every finding was still
present on `main` (`e0b832a`). Each now has a test in `crates/xbt-work/tests/review_p.rs`; P1–P4 were
first run against `main` and failed there.

* **P1: the provider pins the Prime's terms.** `WorkConfig::terms` (`audit::PrimeTerms { window,
  window_min_work, window_tolerance_bps, fee_bps, max_min_payout }`) comes from the provider's config,
  never from a statement. `PrimeTerms::bounds(&ChainBlock)` turns it into `AuditBounds`:
  `window_work ≤ ⌈max(target(bits), target(prev_bits)) × (10⁴ + tolerance) / 10⁴⌉`, where
  `target(b) = max(⌈window × D(b)⌉, window_min_work)` (primed's own rule, `state.rs` 651–654) and `D` is
  the difficulty of the block's own nBits and of its parent's (the Prime may have built the window
  under either). `fee_bps` is capped at the advertised fee, and `min_payout` at `max_min_payout`.
  `audit_block` and `check_fraud_proof` both use `min(statement, bound)` for each value, so a third party
  holding the same terms convicts from the proof alone. A proof that needed a bound carries it under
  `"bounds"`; with no bound applied it is the AGP-032 document, byte for byte. A statement whose
  `window_start` is lower than that of an audited block beneath it is refused (`window_start_regressed`)
  and the block's credit stays held. A pass where `expected` fell below `min_payout` records the
  shortfall as owed carry (`belowMinSats`) instead of forgiving it. Tests:
  `p1_colluding_prime_statements_fail_the_audit` (`window_work = u64::MAX`, `fee_bps = 10000`,
  `min_payout = u64::MAX`), `p1_an_honest_statement_is_not_bounded`, `p1_window_start_is_monotonic`,
  `p1_a_below_min_pass_is_owed_carry`, `terms_bound_the_window`. Inside the bounds, the size of the
  window and who did the rest of its work are still the Prime's word.
  `docs/xbt-work-share-log-commitment.md` proposes a per-block commitment to the share log that a
  provider can sample (a spec proposal for XBT-053, not implemented).
* **Where the Prime validates shares.** The Prime is primed, at commit `91b2d8b` on branch `rnd/agp-011`
  of the project's node repository. That branch is not public, so a reader cannot open the files
  named here; what follows describes that code and cannot be checked from outside until the branch
  is published. No pool code changed. `prime/primed/src/session.rs` `on_pow`
  takes the share's job and coinbase sections, then holds the job's height, parent and nBits to the pool
  node's tip (stale, wrong-bits and dead-parent shares are refused). `prime/wire/src/verify.rs` `verify`
  rebuilds the coinbase (its BIP34 height must be the job's), refuses a coinbase that
  does not pay the split the Prime issued, rebuilds the BLAKE2b header from the merkle branches and the
  share's own fields, and checks the hash against the share target. Back in `on_pow`, a pool-wide set
  allows one credit per hash per height; then the TIDES ledger is credited and, for a
  `.pw-<invoice>` username, so is the receipt (`work_receipts.credit`). The audit does
  not re-check shares: it cannot see them. It bounds what the Prime can claim about them.
* **P2: a pass releases only what it covered.** (Replaced by AGP-079 below: a pass now covers only
  what the coinbase paid for, and nothing is forgiven. What follows is the AGP-065 design.) The book kept one `Span` per receipted increase:
  invoice, `lo..hi`, work, credited, coverage (`Open`, `Covered(h)`, `Skipped(h)`). A passing audit at `H`
  with window start `ws` covers only open spans with `lo > ws` and `hi < H`, exactly the intervals its
  bound counted. Spans at or below `ws` are `Skipped`: no later window can count them. Up to
  `CreditCaps::skipped` of skipped credit is forgiven; beyond that it counts against the total cap for good.
  Covered spans are credited in full, free of the caps. Tests: `p2_a_pass_releases_only_covered_credit`,
  `p2_skipped_credit_fills_the_total_cap`, `a_pass_covers_only_the_spans_its_bound_counts`.
* **P3: the statement must name the node's block.** The audit takes the block from the provider's node
  (`chain::ChainBlock { height, hash, value_sats, paid_sats, bits, prev_bits }`). A statement for another
  height or hash fails with `wrong_block` (`p3_statement_height_must_be_the_blocks`: `height = u32::MAX`
  and `height = window_start + 1`).
* **P4: a missing statement is not taken for a passing one.** (The heading said "is never skipped": since AGP-091 a block with no statement records nothing, so a Prime that gives none is never failed for it. AGP-091 changed two things said here: a coinbase
  that paid the identity with no statement no longer fails the audit, and a Prime error no longer
  stops the loop. See the AGP-091 section.) `provider::window_statement` (`tools::window`): 200 is a statement, 404 (primed's
  "no window statement", `stats.rs` 434) is `Statement::Missing`, and anything else is an error.
  `WorkProvider::audit_chain`: a missing statement for a coinbase that paid the identity fails the
  audit and distrusts the Prime (`missing_statement`); for one that paid nothing it records nothing and
  the credit stays held. The audit loop stops at a Prime or node error and resumes at that block.
  Tests: `p4_a_statement_error_is_not_a_missing_statement`, `p4_a_missing_statement_fails_or_holds`.
* **P5: default caps.** With no cap flag, `xbt-work-provider` caps unaudited credit at 100 calls per invoice
  and 1,000 calls in total (900 since the 10% haircut of AGP-079, at exact pricing; AGP-065 also forgave 100 calls of skipped credit; AGP-079 forgives none). `--cap-*-calls N` (new)
  sets a cap in calls at `--price`, and `off` removes a cap. The library's `CreditCaps::default()` is
  still uncapped (the reference's book, which the vectors pin). Test: `p5_the_binary_ships_non_zero_caps`.
* **P6: invoices, issuance, state, reorgs.**
  * An unfunded invoice past its TTL stays dormant for `invoice_grace_secs` (default 3600 s): its
    receipts are still pulled and a receipt with work still spends on it. Only a newer invoice that
    needs the room evicts it, oldest first (`p6_an_invoice_with_work_outlives_its_ttl`).
    (Since AGP-091 there is no table to evict from, and since AGP-097 a first receipt with work is
    taken at any time: the grace now only says how long such an invoice stays in the relay pull.)
  * (AGP-091: there is no limit any more, because issuing an invoice stores nothing; `max_unfunded`,
    `max_unfunded_per_client` and `issue_invoice_for` are gone. See the AGP-091 section.)
    Issuance is limited per client (`max_unfunded_per_client`, default 16, `429 too_many_invoices`). The
    client is the TCP peer, which the xbt402 HTTP server now passes in `X-Xbt402-Peer`
    (`xbt402::provider::PEER_HEADER`; a client-sent copy is dropped). Behind a reverse proxy,
    `--trust-forwarded` takes the last `X-Forwarded-For` hop instead (`p6_issuance_is_limited_per_client`).
  * The state is snapshotted under the lock with a generation number and written (fsync, rename) outside
    it. A writer skips a snapshot older than the last one written; a failed write on the payment path
    rolls the debit back (`p6_concurrent_writes_keep_the_newest_state`).
  * Earlier receipts (`by_seq`) are persisted as `"receipts"` (state version 2), so a restart still
    detects an equivocation against them. AGP-043 state migrates on load
    (`earlier_receipts_survive_a_restart_and_agp043_state_migrates`). A state file that exists but
    cannot be read is now an error, not an empty book.
  * Reorgs: before each pass the audit loop compares the audited blocks with its node.
    `WorkProvider::orphaned(h)` undoes a reorged block's verdict and carry and reopens the spans it
    covered, so they count against the caps again (`p6_a_reorg_rolls_back_released_credit`). Audits deeper
    than `SETTLE_DEPTH` (144) settle: their spans and the receipts under their window are pruned.
* **DATUM usernames.** The Prime can only receipt `.pw-<invoice>` if the gateway passes the miner's
  username through. That needs `datum.pool_pass_full_users = true`, which is the DATUM gateway's
  default. With it false and `pool_pass_workers` on, the gateway sends `pool_address.<username>`; with
  both false, `pool_address` alone (`datum_protocol.c` 2720–2728). Either way the Prime credits the
  gateway's pool address and no receipt appears. `xbt-work-payer prepare --gateway-config FILE` refuses
  such a config (`payer::check_gateway_config`, `datum_gateway_must_pass_full_usernames`). If no
  receipt arrives within 5 minutes, `pay` prints a hint naming the setting. On regtest the first
  receipt can take longer than that, so the hint is advice, not an error.
* **M1: locked coinbases.** `chain::Maturity::from_deployments` reads Knots'
  `getdeploymentinfo.deployments.long_coinbase_maturity` (`coinbase_start_height`, `height`,
  `height_end`, `maturity`) from the node and is never hard-coded. A node without the deployment means
  ordinary maturity (100). The choice: a locked payout **counts as paid** in the audit, because the
  coinbase did pay the identity and the Prime cannot do better. It is reported apart as illiquid.
  `WorkProvider::payouts(tip, &maturity)` and `GET /admin/xbt-work/report` `payouts` split the audited
  payouts into `liquidSats` and `lockedSats`. A provider that sells credit against its payouts should
  count only the liquid part as money in hand, and its caps bound what it extends meanwhile.
  `relay_at(h)` is when a spend of the coinbase relays (mempool policy applies the long depth to every
  coinbase); `consensus_at(h)` is the consensus rule (`m1_locked_payouts_are_paid_but_illiquid`,
  `maturity_from_the_node`).

**For embedders (cmp and anyone linking `xbt-work`).** Wire and behaviour changes:

| change | before | now |
|---|---|---|
| `audit_block(book, sw, V, paid, deferred)` | statement on trust | `audit_block(book, sw, &ChainBlock, &AuditBounds, deferred)`; `AuditBounds::STATEMENT_ONLY` is the old check |
| `check_fraud_proof(proof, pk)` | | `check_fraud_proof(proof, pk, &ChainBlock, &AuditBounds)` |
| `WorkProvider::audit(sw, deferred, V, paid)` | | `audit(sw, deferred, &ChainBlock)`, plus `audit_chain(&ChainBlock, Statement)` |
| `AuditOutcome` | | adds `below_min_sats`, `window_work`, `fee_bps`, `min_payout`, `bounded` |
| `WorkConfig` | | adds `terms`, `invoice_grace_secs`, `max_unfunded_per_client`, `trust_forwarded` |
| `CreditCaps` | `per_invoice`, `total` | adds `skipped: u64` (default 0: nothing forgiven) |
| `tools::window` | any non-200 → `None` | 404 → `None`, other errors → `Err` |
| provider state file | version 1 | version 2 (`spans`, `settledSkipped`, `receipts`); version 1 loads |
| fraud proof JSON | | `"bounds"` added only when a bound applied |
| `xbt-work-provider` | caps off by default | 100/1,000/100 calls (900 in total since AGP-079); Prime terms flags; reorg check; admin from loopback peers only (since AGP-097: with a bearer token as well) |
| xbt402 HTTP server | | sets `X-Xbt402-Peer` to the TCP peer on every request |

The pricing fee is now `terms.fee_bps`, the fee the audit holds the Prime to. Python parity: there is
none. XBT-053's Python (`receipts.py`) has the v1 draft audit only, with none of P1–P4; this crate is
the reference for them (see AGP-079 below). The vectors are unchanged
(`work_conformance.sh`: 91/91 and 124/0, byte-identical).

Results on 2026-10-08: `cargo test --workspace` (464 passed) and `scripts/conformance.sh`;
`scripts/work_interop.sh` Rust → Rust 20/20 with the provider and payer pinned to primed's regtest terms
(`--prime-window-min-work 64`), no honest statement bounded
(`docs/work-interop-agp065-2026-10-08-payer-rust-provider-rust.json`); `scripts/work_nta.sh` 42/42 with
primed's fee of 5,000 bps pinned (`docs/work-nta-agp065-2026-10-08/`). One NTA check changed with P2: at
C, block 115's pass covers the B share, which is now credited outside the caps (AGP-043 held it and
released it by cap), so nothing stays held.

CPU (`examples/audit_cost.rs`; armv7 musl under `qemu-arm-static` as the Pi-class figure, x86_64 native
beside it; pass lines declared before measuring):

| step | pass line (armv7) | armv7 | x86_64 |
|---|---|---|---|
| `PrimeTerms::bounds` (one block) | — | 2.2 µs | 0.1 µs |
| `audit_block`, 10 / 1,000 spans | ≤ 5 ms | 0.43 / 0.79 ms | 0.03 / 0.07 ms |
| credit room per paid call, 1,000 spans | ≤ 1 ms | 18 µs | 1.8 µs |
| `check_fraud_proof`, 1 / 100 invoices | ≤ 20 ms | 0.95 / 40 ms | 0.06 / 2.9 ms |

The fraud-proof check misses its line at 100 invoices: 200 Ed25519 receipt verifications (AGP-032), of
which the bounds add 2 µs. It runs once per disputed block, not per call. `ReceiptBook::credit` now
makes one pass over the spans; before, it recomputed the caps' room for each open span.

## Pay-with-work closure fixes: credit is covered by what coinbases paid (AGP-079, P1 and P4)

The closure audit (AGP-077) reproduced four routes by which a Prime colluding with a payer still got
unmined work credited and released, and two ways an underpaid block escaped the audit. All were present
on `main` (`0a84665`). Tests: `crates/xbt-work/tests/agp077_closure_audit.rs` (10; the six that state
the findings failed before the fix), `review_p.rs`, and the book's unit tests.

**The cause.** AGP-065 bounded every number in a window statement, but a *passing* audit still released
all the credit its bound counted, whatever the coinbase paid. A pass is cheap for the Prime to arrange:
a deferral line it signs counts as paid, `expected < min_payout` passes with nothing paid, a window
that starts above the credit expects nothing, and a block with no statement has no verdict at all.

**Options weighed.**

| option | verdict |
|---|---|
| Cover a span after it was counted in N passing blocks (N = `window`) | No. An honest pool finds a Poisson(8) number of blocks while a share is in its window: fewer than 8 about 45% of the time. Which blocks are pool blocks and where the window starts are the Prime's word. |
| Price a haircut for the risk | No. Paying one block of eight is a discount of 7/8; no usable haircut prices that. |
| Default carry caps only | Not enough. They stop the deferral route after a few blocks, and do nothing for the other three. Kept as a second line. |
| **Cover credit only by what coinbases paid, at the provider's own price** | Chosen. It uses nothing the Prime signs, so it closes the four routes and any other way of arranging a pass. |

**The rule.** `ReceiptBook` keeps credit in the order it was granted (`credits`). When a block's audit
passes, `WorkProvider::paid_work(&ChainBlock)` turns what its coinbase paid the identity (from the
provider's own node) into work units at the price the provider sells work for, at that block's own
difficulty and value: under exact pricing, the work `paidSats` buys by §6.2 with the pinned fee and the
haircut; with a fixed amount per call, `paidSats × amount / invoice_price_sats`. `ReceiptBook::pay(h,
work)` records it per height and the paid-for work covers the oldest credit first. Unaudited credit, the
thing the §13.1 caps count, is the credit no coinbase has paid for yet. A failed audit pays for nothing.
Auditing a block again replaces its payment, a reorg removes it (`uncover`), and `settle` forgets only
payments deeper than `SETTLE_DEPTH` together with the credit they cover; a settled block audited again
is not paid for twice (`settled_through`). Work paid for beyond the credit granted is room for new credit. The `Span`/`Coverage` states and the skipped allowance are gone.

So a Prime gets credit released only by paying the provider, in coinbases of real blocks, the price of
the calls. What it has not paid for stays inside the caps: 1,000 calls' worth of work in total with the shipped
defaults (900 calls after the 10% haircut), once, not per block. (The second audit found the count wrong under `--work-units` and
"once" too strong; both are in the AGP-091 section, the first fixed, the second stated.)

| route (closure audit, list 1 item 2 and 4) | before | now | test |
|---|---|---|---|
| deferral lines, no carry cap | 5,000 units credited over a cap of 1,000, nothing paid | the lines pass the audit and cover nothing; the shipped carry cap freezes credit after the first | `p1_deferral_lines_do_not_release_credit_no_coinbase_paid_for`, `p1_deferral_lines_release_nothing_even_without_a_carry_cap` |
| `min_payout` excuse | 2,000 units, nothing paid | the pass covers nothing; the total cap binds | `p1_the_min_payout_excuse_does_not_release_credit` |
| `window_start` moved forward | all credit for 1/8 of its price | 1/8 paid covers about 1/8 (14% at the 10% haircut) | `p1_a_window_start_moved_forward_does_not_release_unpaid_credit`, `p1_one_block_of_eight_pays_for_an_eighth_under_the_shipped_defaults` |
| unpaid pool blocks answered 404 | seven unpaid blocks vanish, the eighth releases everything | unpaid blocks cover nothing | `p4_unpaid_blocks_with_no_statement_do_not_vanish_from_the_audit` |
| a statement the audit refuses, on a paid block | logged, no verdict, never retried | a failed audit, the Prime distrusted (`refused_statement`), exactly as with no statement | `p4_a_refused_statement_on_an_underpaid_block_is_a_failed_audit`, `p4_every_refused_statement_on_a_paid_block_distrusts_the_prime` |
| the honest case | one pass released everything | the eight blocks of a window pay for all of it | `an_honest_window_pays_for_all_the_credit_under_the_shipped_defaults` |

**P4.** `WorkProvider::audit_chain` treats a statement that `audit` refuses with one of
`STATEMENT_REFUSALS` (`bad_window_sig`, `wrong_prime`, `wrong_block`, `bad_window`,
`window_start_regressed`) as the block having no statement. On a coinbase that paid the identity that
is a failed audit and distrust; the audit record carries `refusedStatement`. The audit loop no longer
logs and moves on. A block that paid the identity nothing and has no usable statement still has no
verdict: the provider cannot tell the Prime's unpaid block from another pool's block. It counts against
the Prime in the only way open to the provider: it covers nothing.

**Shipped defaults (`WorkConfig::shipped`, which `xbt-work-provider` starts from).** The decisions:

| setting | before | now | override |
|---|---|---|---|
| caps on unaudited credit | 100 / 1,000 calls | the same, before the 10% haircut: 900 calls served in total | `--cap-invoice*`, `--cap-total*` |
| skipped credit forgiven | 100 calls | none; the flag is ignored with a notice | — |
| cap on owed carry | off | the value of 1,000 calls (150,000 sats at the default price) | `--max-carry-sats S`, `off` |
| carry growth rule | off | off: at an honest Prime a share below `min-payout` grows as carry for several blocks; set it when the provider attests every tip | `--carry-growth-blocks N` |
| work book | memory only without `--state` | `DIR/work.json` in the data dir, under the ledger's process lock | `--state FILE`, `--state off` |
| audit loop | off without `--audit-depth` | 6 deep whenever `--window-url` is given | `--audit-depth K`, `off` |
| no `--window-url` | silent | starts, and says that no audit runs and credit stops for good at the total cap | — |

The two tests that needed `--features tools` run in the default sweep: `window_statement` moved to
`provider.rs` (`tools::window` re-exports it) and the caps (`Cap`, `Caps::SHIPPED`) moved from the
binary into the library. `p3_statement_height_must_be_the_blocks` now has the literal
`height = window_start + 1` case.

**Other paths to the same state, each checked.** Credit is granted in one place, `ReceiptBook::credit`,
within `room`; these reach it or the payments:

| path | covered by |
|---|---|
| a receipt from the relay, the Prime or a payer's header (`accept`, `refresh`, `check_and_debit`), a replay | `credit` within `room`; `caps_hold_unpaid_credit_until_a_coinbase_pays_for_it` |
| `audit`, the admin audit endpoint, the audit loop | all go through `audit` / `audit_chain`; the admin controls (`underpayHeight`, `withoutDeferrals`) record nothing |
| re-auditing a block | `pay` replaces: `payments_cover_the_oldest_credit_and_a_reorg_takes_them_back` |
| a reorg (`orphaned`) | `uncover`: `p6_a_reorg_rolls_back_released_credit` |
| settling deep audits (`record` → `settle`) | forgets only paid credit; same book test |
| new caps at an epoch (`set_caps`) | `release_held` within the new caps |
| a restart | `credits`, `cover`, `coverSettled` are in the state file (version 3): `unpaid_credit_and_payments_survive_a_restart` |
| state from AGP-065 or AGP-043 | covered spans count as paid and settled; open and skipped credit loads as unpaid, none forgiven: `earlier_receipts_survive_a_restart_and_agp043_state_migrates` |
| XBT-053's Python reference | has none of P1–P4 or of this rule: see below |
| B1, B2 | hold no pay-with-work audit code |

**Stated limits.**

- An unpaid block with no statement leaves no verdict and no fraud proof. A payer's real work that a
  Prime never pays for costs the provider up to the total cap. Naming the pool's blocks independently
  needs the share-log commitment (`docs/xbt-work-share-log-commitment.md`, not implemented).
- The provider now carries the pool's luck. An honest window pays in 8 blocks on average; when the pool
  finds fewer, credit stays unaudited longer and new credit can be held at the caps until later
  coinbases catch up. Paying for work at the list price (10% haircut) gives about 11% more cover than
  the work mined, which absorbs part of it. Operators who trust their Prime can raise the caps.
- Every coinbase output to the identity counts as payment, whatever it was for. Use an identity that
  receives nothing but this Prime's pay-with-work payouts.
- A locked coinbase payout still counts as paid (M1).
- Exact pricing rounds up to one work unit, so a passing block that paid 1 sat pays for 1 unit.
  At this repo's mainnet numbers (`1a00f0b5`, 3.125 XBT) a unit is 17.5 sat of work and a 150-sat
  call is 10 units, so that 1 sat pays for a tenth of a call: free cover of under one unit, about
  15 sat of calls, per block the Prime pays in. (This line said "0.09 sat of work on mainnet";
  that is the figure for `190141c5`, a difficulty about 190 times lower. Corrected by AGP-091 from
  the second audit; test `limit_one_sat_pays_for_a_tenth_of_a_call_at_mainnet_numbers`.) On
  regtest a call costs one unit and each paying block pays for one.
- (No longer so since AGP-091: such a statement is the block having no statement, with no verdict.)
  A statement for a stale block served during a reorg, on a block that pays the identity, distrusts
  the Prime like a missing one does. The shipped audit depth of 6 keeps the loop away from the tip.
- State migrated from AGP-065 cannot reopen a block audited before the upgrade if it is reorged after.
- Fraud proofs still convict only for a checker who knows the Prime's terms; T2/T4 for the xbt-work
  rail are not part of this task.

**Cost.** `cargo run --release -p xbt-work --example audit_cost` on x86_64, this branch against `main`
(`0a84665`), 1,000 receipted increases over 100 invoices: credit room per paid call 0.02 µs (main
1.8 µs), `audit_block` 71 µs (71 µs), `check_fraud_proof` 2.9 ms (2.9 ms). The AGP-065 pass lines are
for armv7; armv7 was not rerun. The room is now one walk over the unpaid credit instead of over every
span.

**XBT-053.** The Python reference (XBT-053 `receipts.py`; not published) implements the v1 draft audit:
no bounds, no chain block, no missing-statement rule, no caps. The audit rules of AGP-065 and the cover
rule above are specified by this crate, which is the reference for them until the spec (§10.2, §10.3,
§13.1) carries them; the spec diff is in the task result for the XBT-053 owner. `audit_block` and
`check_fraud_proof` are unchanged, so the vectors are too (`work_conformance.sh`).

**For embedders.**

| change | before | now |
|---|---|---|
| `CreditCaps` | `per_invoice`, `total`, `skipped` | `per_invoice`, `total` |
| `ReceiptBook` | `spans`, `settled_skipped`, `audited(h, ws, passed)`, `skipped_work()` | `credits`, `cover`, `cover_settled`, `pay(h, work)`, `paid_work()`; `uncover` and `settle` keep their signatures |
| `book::{Span, Coverage}` | | removed |
| `WorkProvider` | | adds `paid_work(&ChainBlock)`; `audit_chain` returns a failed outcome for a refused statement on a paid block instead of `Err` |
| `provider` | | adds `window_statement`, `Cap`, `Caps`, `WorkConfig::shipped`, `STATEMENT_REFUSALS`, `SHIPPED_*` |
| audit record, report | `skippedWork`, `forgivenSkippedWork` | `paidForWork` (per audited block; in `credit`, the paid-for work not yet settled against credit), `refusedStatement`; `coveredWork` is the credit the block newly covered |
| provider state file | version 2 | version 3 (`credits`, `cover`, `coverSettled`); versions 1 and 2 load |
| `xbt-work-provider` | see the defaults table | |
| `Amount::Fixed` providers | | set `invoice_price_sats`, or payments are valued at the work's §6.1 value |

## Pay-with-work, fix wave 4: what the second audit left (AGP-091)

The second closure audit (AGP-087, list 1 items 9, 10, 11 and 17) found the neighbours of the P1,
P4 and P6 fixes open on `main` (`f0554d0`). The cover rule of AGP-079 held against everything the
audit tried and is unchanged: no unit of credit leaves the caps without sats in a coinbase output to
the provider's address, read from the provider's node, under a statement that passes. Each item
below is one rule, kept in one place, with the paths that could break it.

**1. The Prime is failed only on what the Prime signed for this block** (`WorkProvider::audit_chain`).
A block with no statement the Prime signed for it has no verdict and covers nothing, whatever its
coinbase paid the identity. Before, a block that paid the identity with no statement failed the
audit and distrusted the Prime for good. The identity is the `payTo` of every 402, and whoever
mines a block chooses its coinbase outputs: one sat from a competing miner ended an honest Prime's
service to every payer. "No statement" is all of: a 404, a statement for another block or height
(the Prime's own, for a block that lost a race), one under another key, and an answer that is no
statement at all. What still fails: a statement that verifies under the pinned key for this Prime
and this block and that the audit cannot run on (`refused_statement`), a statement whose block
underpaid (`wrong_prime`, with a fraud proof), and an equivocation. A Prime gains nothing from the
change: a block it pays in without a statement covers nothing, which is less than the same block
with one. Such blocks are counted in `unpaidBlocks` (now with `paidSats`, what they paid in all).
The code `missing_statement` is gone. An audit recorded at a height for a block the chain no longer
has is undone when that height is audited again with no statement (the admin audit does not look
for reorgs first).

**2. A cap in calls is that many calls at what a call costs** (`Cap::units_under`,
`WorkConfig::cap_rule`). The provider derives its caps from the rule in force, when it starts and
at each epoch. Before, the binary computed them at exact pricing and then `--work-units N` changed
what a call costs: "1,000 calls" was 9,000 calls with `--work-units 1` at `1a00f0b5`. With exact
pricing the number is as it was: 1,000 calls' worth of work before the haircut, which is 900 calls
at the shipped 10%.

**3. No answer of the Prime's stops the audit walk** (`walk::Walk`, the loop the binary runs, now in
the library and tested). The provider's own node is the only thing it waits for. A statement fetch
that fails (500, a body that is no statement, no connection) leaves the block as one with no
statement, the walk goes on, and the block is asked for again: on each of the next passes at
first, then at most once in 64 passes, until it lies 144 blocks below the walk. Before, the loop
stopped at that block and tried it every 2 s for ever, so a Prime that answered 500 for one height
was never audited again. The walk's position is kept in the state file (`auditNext`): a provider
that was down for more than 106 blocks used to skip the blocks in between.

**4. The unpaid-blocks stop lifts when the Prime pays in full** (`--max-unpaid-blocks`). The run
ends when no credit is unpaid, or at a block above the run that passed on what its coinbase itself
paid (no deferral line, no `min_payout` clause) under a window that holds all the unpaid credit, so
that `expected` was the block's share of all of it. Before, any payment ended it: 1 sat under a
window moved past the credit, with 799 of 800 units unpaid.

**5. Issuing an invoice costs the provider no state** (`provider::Issued`). The 16 bytes of an
invoice identifier (§4.1) are its expiry (4), a nonce (8) and a 4-byte MAC under a secret in the
state file; the `authKey` is an HMAC of the identifier under the same secret. Nothing is written
when an invoice is issued, and the record (`n`, `spent`) is made by the first receipt the Prime
signed that shows work. Before, each unfunded invoice was a row in a table of 10,000, rationed per
client by the TCP peer. The binary listens on loopback, so every client behind a proxy was one
peer: 16 requests an hour from anyone stopped invoices for everyone, and with `--trust-forwarded`
625 addresses filled the table and pushed slow payers' invoices out, stranding their work. No
durable state is left to fill, ration or evict, and no `fsync` an anonymous request can cause.
`429 too_many_invoices` is never sent. The relay pull asks for the newest 64 invoices not yet seen
in a receipt (`PULL_NEW`, in memory), and 64 invoice requests push an invoice out of that list; an
invoice that is not in it is credited when its payer presents a receipt, which a payer does with
every call. As AGP-091 shipped, that receipt was refused once TTL and grace had passed, so 64
requests stranded the work of a payer whose first call came later: AGP-097 takes a first receipt
with work whenever it comes (below), and `expiresAt` ends only an invoice with no work.

**6. An admin request carries the admin token** (`provider::admin_request`). `--admin` makes
`DIR/admin.token` (0600) and every admin request needs `Authorization: Bearer <token>` and a
loopback peer. Before, the loopback peer was the whole check, and behind a proxy on the same host
that is every client on the internet: anyone could read the report and run audits.

**7. A lost answer costs that answer and no other** (`WorkPayer::check_response`). The provider
debits before it answers, so after a lost answer its `spentWork` is ahead of the payer's. A
PAYMENT-RESPONSE names the `n` of its call; `spentWork` must grow by `charged` and by no more than
the quotes of the earlier calls still unanswered (`Session::unanswered`, kept with the session).
Before, it had to grow by exactly `charged`: after one lost answer every later call was debited and
its answer thrown away. An answer whose `n` is not an open call (an earlier answer played again) is
refused.

**8. The payer fetches a receipt only where it said it would, or at the provider's own origin**
(`WorkPayer::provider_named`). The provider writes `receiptUrl` and `relayUrl` into the invoice.
The payer's own `relay_url` and `receipt_url` come first (the invoice's relay used to win). A URL
only the invoice names is fetched on the provider's origin or on one of `allow_origins`, and is
refused with `provider_url` before any request otherwise. Before, the payer sent a GET to whatever
URL the invoice named, before every paid call.

Tests: `crates/xbt-work/tests/agp087_work.rs` and `agp087_transport.rs` (the audit's; its six
failing tests pass), `agp091_work.rs` (17: items 1, 4, 5 on their other paths; 12 fail on the
audit's branch), `agp091_walk.rs` (10: items 2, 3, 6), `agp091_payer.rs` (7: items 7, 8).

**What operators and embedders see.**

| | before | now |
|---|---|---|
| a block that paid the identity, no statement | failed audit, Prime distrusted (`missing_statement`) | no verdict; counted in `unpaidBlocks` (`paidSats`) |
| `--work-units N` with no cap flag | caps of 1,000 priced calls' worth of units | caps of 100 and 1,000 calls at N units |
| a Prime answering 5xx for a block | the audit loop stops there | the walk goes on; the block is asked for again |
| `--max-unpaid-blocks` lifts | on any payment | on a full payment for all unpaid credit, above the run |
| `--trust-forwarded`, `--max-unfunded-per-client` | per-client invoice limit | accepted and ignored with a notice |
| `--admin` | loopback peer | loopback peer and `Authorization: Bearer` with `DIR/admin.token` |
| `xbt-work-payer` | fetches where the invoice says | `--relay-url` / `--receipt-url` / `--allow-origin`; `--provider-admin-token FILE` |
| `WorkConfig` | `max_unfunded`, `max_unfunded_per_client` | removed; `cap_rule` added; `trust_forwarded` kept, unused |
| `WorkProvider` | `issue_invoice_for(client)` | removed (`issue_invoice`); adds `caps()`, `audit_position()`, `set_audit_position()` |
| `Statement` | `Found`, `Missing` | adds `Unavailable` |
| `PayerConfig` | | adds `receipt_url`, `allow_origins`; `relay_url` now comes before the invoice's |
| state file (version 3) | | adds `invoiceSecret`, `auditNext`, `unpaid.paidSats`; older state loads and keeps its invoices |

**Limits, stated.**

- A Prime that never gives a statement for a block (404, 5xx or garbage) is never failed for that
  block, paid or not. The provider cannot tell the Prime's block from another pool's without the
  share-log commitment (`docs/xbt-work-share-log-commitment.md`, not implemented). The loss is the
  credit inside the caps, as before.
- "Once" is not once. Cover is one pool across payers, oldest credit first. An honest payer's work
  is paid for at its §6.1 value, which at the 10% haircut is 11% more than its credit costs, and
  the surplus covers whatever credit is older, mined or not. A Prime colluding with a payer gets
  its unmined credit covered by honest payers' coinbases at about one call per nine honest calls,
  and can then take that much again. The provider is still paid, in coinbases, for every unit it
  releases; what it loses is the haircut it priced in as its margin on those units. Not changed:
  a coinbase output cannot be attributed to an invoice (test
  `limit_an_honest_payers_overpayment_covers_older_unmined_credit`).
- With exact pricing a cap in calls is in calls' worth of work before the haircut: 900 calls, not
  1,000, at the shipped 10%. It errs towards the provider.
- The blocks whose statement the walk still asks for are kept in memory. After a restart those
  deeper than the walk's start (its kept position, and at least 100 blocks below the audit depth)
  stay blocks with no statement: their payments cover nothing. It errs against the payer and is
  the Prime's to avoid.
- The 4-byte MAC in an invoice identifier only tells this provider's identifiers from others'
  (`unknown_invoice` rather than `bad_auth`); one guess in 2^32 gets `bad_auth`. What authenticates
  a call is the 256-bit `authKey`. The identifier shows when the invoice expires.
- A provider that loses its state file loses the secret, and with it every invoice no receipt was
  presented for yet (as it lost them before). `--state off` keeps the secret in memory only.
- The spec (§4.5) says a provider MUST bound outstanding unfunded invoices and answer `429
  too_many_invoices` beyond the bound. This provider holds none, so the bound is met by having
  nothing to bound; the wording is XBT-053's to change.
- The admin token is a bearer secret on loopback, in a file. Whoever can read the provider's data
  directory can use it, as they can read the work book.
- A payer that sets no relay and no receipt URL of its own, facing a provider that names them on
  another origin, gets `provider_url` and has to configure one. That is the intended cost.
- The payer's check of `spentWork` is bookkeeping, not proof: the PAYMENT-RESPONSE is not signed
  (stated in AGP-081). After a call the provider refused, its quote stays in the slack until the
  next answer, so a provider could over-report by that much without being noticed.

## Pay-with-work, fix wave 5: what the third audit left (AGP-097)

The third closure audit (AGP-093) found, in this area, list 1 items 8, 13, 14 and 19: one Medium
(WORK 1) and five smaller ones, three of them inside rules wave 4 added. One rule each, written at
the function that keeps it. Tests: `crates/xbt-work/tests/agp093_work.rs` (the audit's 9, all
pass), `agp097_work.rs` (14, the other paths), and unit tests in `book.rs`, `pricing.rs` and
`guard.rs`. There is no pay-with-work code in B1 or B2 (the Python reference is XBT-053's).

**1. Work the Prime signed for an invoice of this provider is credited whenever its payer first
presents it** (`provider::Invoice`). Issuing is stateless, so an invoice gets a record only when
the relay pull or its payer's first call presents work, and the pull asks for the newest 64 issued
only. A first receipt was refused past TTL and grace: 64 anonymous invoice requests pushed a
payer's invoice out of the pull, and a payer that mined in time and called two hours later had
paid the provider and could not spend (`unknown_invoice`). The provider cannot tell when work was
mined (a receipt carries heights and no time), and it has been paid for it whenever that was, so a
first receipt that shows work makes the record at any time. `expiresAt` ends an invoice with no
work, as §4.5 says ("bounds only an invoice that has received no work"). Nothing an anonymous
caller sends makes the provider keep anything: the record still needs the Prime's signature on
work. `invoice_grace_secs` now only says how long an unfunded invoice past its TTL stays in the
relay pull.

**2. Unpaid credit counts against a cap that follows the price at the price it was granted at**
(`book::Rate`, `ReceiptBook::counted`). A cap in calls or sats is turned into work units at each
epoch, and credit is kept in work units. When a call came to cost twice the work, the cap doubled
and the same unpaid units filled half of it: a Prime that never paid was served 450 more calls,
1,350 against a cap of 900. Each grant now remembers what a call and a sat cost in work when it
was made, and the caps count its unpaid part at today's rate: 900 unpaid calls are 900 calls of
the cap at any difficulty, and a coinbase that pays for half of them frees 450. Balances are not
revalued (§6.3); only what the caps count is. A cap set in work units counts work units, as
before.

**3. A window start is held only against audits of blocks still in the chain**
(`WorkProvider::audit_chain_on`). `window_start_regressed` distrusts the Prime for good, and it
was judged against every audit on record without asking whether that block was still there. An
operator's audit near the tip (`POST /admin/xbt-work/audit` takes any range) and a reorg left a
record of a block that no longer existed, and the honest statement for the new branch went against
it. Before the refusal counts, the node is asked for the block at the record's height: still
there, and the Prime signed both for one chain and is failed; gone, and that audit is undone as a
reorged one is, the statement is audited without it, and the walk goes over the height again
(`WorkProvider::undone`). The admin audit also runs the walk's reorg check before it starts.

**4. An epoch the price cannot be worked out at never replaces one it can**
(`WorkProvider::set_epoch`, `pricing::bits_to_target`). A compact target whose mantissa the
exponent shifts out (`0x01000001`) is zero; it was returned as a target, and every price, cap and
window bound then divided by it. It is refused as a zero target, and an epoch whose `bits` or
block value no price follows from leaves the epoch in force as it is (the binary says so once).

**5. A panic in one round of a loop the provider depends on ends that round, not the loop**
(`guard::round`). The channel watcher, the relay pull (which also follows the epoch) and the audit
walk each ran in a thread that a panic ended for good while the service went on answering. Every
release build has overflow checks on, so that is what a missed overflow means. Each round now runs
under `catch_unwind`; the panic is logged and the loop goes on. Under `release-small`
(`panic = "abort"`) the process ends instead and its supervisor starts it again.

**6. The admin token is in a file only the operator's account can read, or it is not used**
(`provider::admin_token`, `fsx::write_private`). The 0600 mode applied only when the temporary file
was created by that call: one already in the directory was written into and renamed into place
with its own mode. The temporary file is now removed and made anew, exclusively (so a link in its
place is not followed either), and that holds for the state file, which holds the invoice secret.
A token file that is already there and that group or others can read or write is refused at
start, as `ssh` refuses such a key: the operator deletes it (a new token is made) or runs
`chmod 600`.

**7. Sums of numbers from outside saturate.** `xbt-work-payer` added a Prime's deferral amount to
the coinbase payment with a plain `+`; it uses the audit's own sum now (`audit::covers`).

**What operators and embedders see.**

| | before | now |
|---|---|---|
| a first receipt with work, past TTL and grace | `unknown_invoice` | credited |
| unpaid credit after the difficulty rises | fills less of a cap in calls or sats | fills as much as when it was granted |
| `window_start_regressed` against a record whose block left the chain | Prime distrusted | that audit undone, the statement audited |
| a `bits` value with a zero target from the node | pricing panics from then on | refused; the epoch in force stays |
| a panic in the watcher, the pull or the audit walk | the thread ends | logged, the loop goes on |
| an `admin.token` others can read | used | refused at start (`bad_config`) |
| `WorkProvider` | | adds `audit_chain_on`, `undone`, `epoch_error` |
| `walk::AuditSource` | | adds `hash_at` (defaults to the hash of `block`) |
| `ReceiptBook` | `credits: (invoice, work)` | `credits: (invoice, work, Rate)`; adds `rate`, `follows`, `counted` |
| state file (version 3) | | each credit carries its rate; older state loads |

**Limits, stated.**

- **A record is kept for every invoice that ever had one share, for good** (not changed; the
  audit's WORK 4). It is about 650 bytes of state (653 measured), the whole state is written on every paid call,
  and every such invoice is asked for in every relay pull. Rule 1 rests on it: `n` and `spent` are
  what keep a spent invoice spent, and an identifier can make its record again only while it has
  none, so a record must not be dropped while its identifier is still accepted. Pruning needs a
  retention after which an identifier is refused, which is an operator's setting to add. The
  audit log (one entry per audited block that had a statement) is not pruned either.
- **Credit held unspent buys more calls when the difficulty falls** (§6.3: balances are in work
  units and are not revalued). The caps bound the credit a Prime that never pays is given; what it
  buys is decided when it is spent. A pair that takes the whole cap as credit and spends none of
  it until the difficulty has halved is served 1,800 calls against a cap of 900
  (`limit_credit_held_unspent_buys_more_calls_when_the_difficulty_falls`); a fall by a factor f
  gives f times the cap at most, and it needs the difficulty to fall while the credit is held.
- Credit that was unpaid when a provider is upgraded has no rate in its state file. It is taken as
  granted at the epoch of the first start after the upgrade, which is right unless the epoch moved
  while it was unpaid.
- `WorkProvider::audit_chain`, the form with no node to ask, cannot tell a window start that went
  backwards on one chain from two statements for two branches. It never blames the Prime for it:
  the audit on record is undone and the statement audited without it. `xbt-work-provider` uses
  `audit_chain_on` in the walk and in the admin audit; an embedder that wants the Prime failed for
  a window start that goes backwards must use it too.
- An invoice identifier is accepted for as long as the provider keeps its secret. A payer that
  mines on an invoice long after `expiresAt` is credited; the provider was paid for that work.

## Lightning rail hardening (AGP-066, review L1–L5)

An external review of the public snapshot (xbt-rs `9201104`) found five weaknesses in the payer-only
`rail=ln` (AGP-048/049, `crates/xbt-signer/src/ln.rs`). All five were still present on `main`
(`7d03b84`); since `9201104`, the LN code had changed only in `a64c41e` (AGP-055, how the tests read
the ledger), which none of the findings depends on. Each
has a test in `crates/xbt-signer/tests/ln_rail.rs` that failed on `main`; commit `fbc55b2` holds the
tests alone. Neither Python reference has a Lightning rail (B1 `xbt402/` and B2 `agentwallet/` have
none), so there is no parity change and no vector changed.

Two design notes stand as before, and nothing below changes them:

* **The wallet's policy is advisory as far as LND is concerned.** The signer's checks bind what goes
  through the signer. Anyone holding a macaroon with more access (the node's `admin.macaroon`, `lncli`
  on its host) bypasses all of them. That is why mainnet requires `ln.exposure_cap_sats`: the LN node
  is trusted with everything it holds.
* **Everything rests on the Lightning Fork's behaviour.** Its unified signatures (`option_unified_sigs`,
  sighash 0x21) and its feature bit 512 (`option_blake2b`) are what keep a channel's transactions and
  invoices off the SHA-256 chain. The signer checks that they are in use (L5 below tightens the funding
  proof) but cannot make the fork implement them correctly.

* **L1: plain http only to a loopback address.** `LndRest::new` cut the URL's host at the first `:`,
  so in `http://[::ffff:10.0.0.5]:8080` the leftover `[` passed as loopback, and the spending macaroon
  crossed the LAN in cleartext. The URL is now parsed with the `url` crate (the parser `ureq` itself
  uses, so the host checked is the host dialled). Plain http is allowed only to an IPv4 address in
  127.0.0.0/8, to `::1`, or to an IPv4-mapped address inside 127.0.0.0/8. A hostname, `localhost`
  included, needs https. Test: `l1_plain_http_only_to_a_loopback_address`: a table of URLs, then a
  property over 400 random IPv4 addresses (half in 127/8), their IPv4-mapped forms and 400 random
  IPv6 addresses (accepted exactly when in 127/8; random IPv6 never). On
  regtest, S18 starts a signer with that URL and checks it is refused.
* **L2: the mainnet macaroon check is an allowlist.** The check refused only `onchain:write`,
  `macaroon:*` and `signer:generate`. A macaroon granting `uri:/lnrpc.Lightning/SendCoins` (or
  `invoices:write`, `peers:write`, …) passed. Now, on mainnet, `ln_macaroon` refuses any permission
  beyond the rail's four (`info:read offchain:read offchain:write onchain:read`). It also refuses a
  macaroon whose permissions cannot be read (not an LND identifier), since one that cannot be read
  cannot be shown to be least privilege. Off mainnet the macaroon is reported, not refused: `ln_status`
  `macaroon.only_needed` and `excess_ops`. `dangerous_ops` stays in the report. (The field is not
  called `least_privilege`: the response sanitizer drops every key containing `priv`, and the regtest
  caught it.) Test:
  `l2_the_mainnet_macaroon_holds_only_the_rails_permissions`, plus the `macaroon.rs` unit test.
  Regtest: S17. An allowlist scoped by URI (accepting the rail's own URIs and nothing else) would also
  work; the entity allowlist is simpler and is what `lncli bakemacaroon` produces.
* **L3: a payment is looked up by its hash.** `lookup` scanned `GET /v1/payments` (the newest 1,000),
  so on a busy node an older settled payment looked like no payment, and reconcile released its
  booking. It now calls `GET /v2/router/track/{payment_hash}` (TrackPaymentV2, base64url hash), reads
  the first line of the stream, and checks that the record's hash is the one asked for. Only LND's
  "payment isn't initiated" answer means "no payment": grpc-gateway answers an unknown route with a 404
  too, so the status code alone proves nothing, and any other error stays an error (nothing is
  released). LND has no hash filter on `ListPayments`, and scanning all of its pages costs O(payments)
  on every reconcile; TrackPaymentV2 costs one call. It needs the node built with `routerrpc` (Lightning
  Fork releases are) and `offchain:read`, which the rail's macaroon already has. Tests:
  `l3_a_payment_is_looked_up_by_its_hash_not_among_the_newest_1000` and
  `l3_reconcile_does_not_release_a_settled_payment_on_a_busy_node`, against a fake REST LND on
  loopback that holds 1,001 payments. On regtest, S16 checks both answers on lf1, and S15's reconcile
  goes through the new lookup.
* **L4: a late rebook that breaks the policy halts the rail.** A booking released because the node had
  no record of it is watched; if the node records the payment late, it is booked again (`ln_rebook`).
  That booking discarded the policy's verdict, so a release, a new payment in the freed room, and the
  late settle could overspend the daily budget without anyone noticing. Now the rebook still books what
  was spent (the ledger is the truth), but asks `evaluate_booking` first. If the booking breaks the
  policy (or cannot be committed), the signer:
  * writes a halt to `.run/ln_halt.json` (atomic write, `0600`) and audits `ln_halted`;
  * refuses every `ln_pay` with `ln_halted` (nothing reaches the router), and `ln_status` shows
    `halted`, `ready: false` and a warning;
  * puts an approval of kind `ln_resume` (dest `ln:resume`, the amount rebooked) in the human's queue.
    It is renewed while the halt stands, one live request per halt. Only the human's ed25519 signature
    on it resumes the rail (`ln_resumed`). A wrong signature, or a token for an earlier halt, is refused.

  A halt file that cannot be read counts as a halt. The watch lasted until the invoice's expiry plus
  10 minutes, far shorter than an HTLC can stay out. It now lasts `ln.max_cltv_blocks` + 144 blocks
  (`REBOOK_WATCH_MARGIN_BLOCKS`; for a BOLT 12 payment `ln.node_max_cltv_blocks` + 144, AGP-092),
  counted both in blocks from the tip at release
  (`watch_until_height`) and in time at 600 s a block. Tests:
  `l4_a_late_rebook_that_breaks_the_policy_halts_the_rail_until_the_human_resumes_it` and
  `l4_the_rebook_watch_lasts_as_long_as_the_htlc_can`. The AGP-048 test
  `a_payment_released_as_never_sent_and_settled_late_is_booked_again` now checks the longer window.
  The alert is the approval queue the human already watches: the wallet UI's card says the rail is
  halted and that approving pays nothing. No new message type or key was needed.
* **L5: the funding proof.**
  * **The cache is keyed on the block.** A `Proven` verdict was cached per channel point forever, so
    after a reorg removed the funding block the channel still carried payments. The signer now asks
    its node for the hash at the short channel id's height on every use, and a cached verdict counts
    only while that hash is the one it was reached on (`Funding::block_hash`, in the evidence as
    `block_hash`). After a reorg the channel is proven again from the new block. Test:
    `l5_a_proven_funding_is_proven_again_after_a_reorg` (refused while the block is gone, proven again
    when it returns).
  * **Which signatures count.** The proof read the sighash byte of every DER-shaped push, so a 0x21
    push that the script never checks (`OP_DROP OP_TRUE`, a taproot script path) "proved" the input.
    `ln_funding::checked_sighashes` now reads only spends whose sole condition is signatures: P2WPKH,
    P2SH-P2WPKH, P2PKH, P2WSH or P2SH-P2WSH whose witness script is `<key> CHECKSIG` or
    `m <keys> n CHECKMULTISIG` (with exactly its `m` signatures), and a taproot key path. Any other
    input leaves the channel unproven, and the refusal names the input and why. Tests:
    `l5_a_0x21_push_the_script_never_checks_proves_nothing` (an anyone-can-spend P2WSH and a taproot
    script path are refused; LND's 2-of-2 P2WSH and np2wkh spends are proven), the unit test
    `reads_sighash_bytes_by_input_kind`, and the property test `only_signature_only_scripts_are_read`
    (2,000 random P2WSH witnesses: one is read only if its script is a key-check template, and then
    yields exactly the `m` signatures that script checks).

**The replay-safety reasoning, corrected** (`ln_funding.rs` module documentation):

* A channel's transactions can replay on the SHA-256 chain only if its funding transaction is valid
  there too. One input with a signature that its script checks, and that the SHA-256 chain cannot verify,
  makes the transaction invalid there. The proof asks for that of every signature of every input.
* The earlier comment said the SHA-256 chain rejects a 0x21 signature. It does not: its consensus accepts
  hash type 0x21 on legacy and segwit v0 inputs (the byte is only non-standard there; taproot does
  reject it). The protection is the digest. An XBT signer signs 0x21 over the unified message
  (`unified_sighash`: BIP341-shaped, committing to every input's amount and scriptPubKey). The
  SHA-256 chain checks the same signature against its own legacy or BIP143 message for hash type 0x21. One
  ECDSA signature valid under one key for both messages would need the two digests to be equal modulo
  the group order.
* **Why reading the bytes suffices, without verifying the signatures in the signer.** The funding
  transaction is read from a block on the signer's own node's best chain, at the position its short
  channel id names. That node's consensus has already verified every signature each input's script
  checks, against XBT's message for its hash type (below an `assumevalid` block, the network that built
  on it has). Verifying again in the signer would repeat that work and add a second ECDSA path to keep
  in step with Knots. What the bytes alone cannot tell is which pushes the script checks, so the fix is
  the template restriction above.
* **The height proves nothing on its own.** A coin confirmed at or above the split is not thereby
  XBT-only. A transaction valid on both chains (a 0x01 spend of pre-split coins, broadcast on both) has
  the same txid on each, so its outputs exist on the SHA-256 chain too, however high it confirmed here.
  The signatures are the proof. The rule that every input's coin is confirmed at or above the split
  stays, as an extra, conservative rule: a channel opened after the split never needs older coins.

**For embedders (cmp and anyone linking `xbt-signer`).** Wire and behaviour changes:

| change | before | now |
|---|---|---|
| `B2_LN_REST` plain http | allowed to any host starting `127.`, `localhost`, or with a `[` (the bug) | only 127.0.0.0/8, `::1`, `::ffff:127.0.0.0/104`; `localhost` needs https |
| mainnet macaroon | refused if it grants `onchain:write`, `macaroon:*`, `signer:generate` | refused if it grants anything beyond the rail's 4 permissions, or cannot be read |
| `ln_status.macaroon` | | adds `only_needed` (bool) |
| payment lookup | `GET /v1/payments` (newest 1,000) | `GET /v2/router/track/{hash}`: needs `routerrpc` on the node |
| `ln_pay` | | new rule `ln_halted` (with `halted`, the halt record) |
| `ln_status` | | adds `halted` (`null` or `{halt_id, reason, payment_hash, dest, booked_sats, ts}`) |
| approvals | kinds `xbt402`, `ln`, payment | adds kind `ln_resume`, dest `ln:resume`; `approve` with the human's signature resumes the rail |
| audit log | | `ln_halted`, `ln_resumed`; `ln_rebooked` gains `breach` |
| `.run/` | | `ln_halt.json` while halted; `ln_payments.json` records gain `watch_until_height` |
| funding evidence | | adds `block_hash` |
| `LnBook::watched` | `watched(now)` | `watched(now, tip)` |
| `ln_funding` | `input_sighashes` | `checked_sighashes(&TxIn, prev_spk) -> Result<Vec<u8>, String>` |

New dependency: `url` 2.5, already in the tree through `ureq` 2.12 (`cargo tree -d` shows no new
duplicate).

Results on 2026-10-08: `cargo test --workspace` (517 passed) and `scripts/conformance.sh`;
`scripts/ln_rail_regtest.sh` 61/61 against Lightning Fork `dd659b3` (`docs/agp066_ln_rail_regtest.json`).
S16 shows the node's answer for an unknown hash: 404 `{"error": {"code": 5, "message": "payment isn't
initiated"}}`. Its first run also caught `least_privilege`, which the sanitizer had removed from every
response.

CPU (`crates/xbt-signer/examples/ln_funding_cost.rs`; armv7 musl under `qemu-arm-static` as the
Pi-class figure, x86_64 native beside it; pass line declared before measuring):

| step | pass line (armv7) | armv7 | x86_64 |
|---|---|---|---|
| `checked_sighashes`, one funding transaction of 10 inputs (P2WPKH, 2-of-3 P2WSH, P2SH-P2WPKH, P2TR key path) | ≤ 50 µs | 1.97 µs | 0.16 µs |

The L5 cache check adds one `getblockhash` RPC to the signer's own node per usable channel on each
`ln_pay` and `ln_status`: a loopback round trip, not CPU. TrackPaymentV2 replaces a 1,000-payment
listing with one record. The L1 parse runs once, at configuration.

## Fix wave 4, channel client and transport (AGP-090)

Five items of the second closure audit (AGP-087, list 1: 4, 5, 6, 9 and 17), in the library client
(`xbt402::client`), `funding.rs`, `wire.rs` and the HTTP transport. Each is fixed at one function
that every path of the library client goes through (two exceptions: `RoutePayer` opens its ch1 with
an open of its own, and a rollover's next channel is made `Open` in `Client::rollover`). The same rules are in B1 (`xbt402/x402_channel.py`, `funding.py`).

**A funded channel is never forgotten (C2).** A channel is on the books and in the ledger from the
moment it has a key, with a stage: `Keyed` (key and terms; saved before the wallet is asked to
fund), `Funded` (outpoint known, key bound, refund held and handed to `on_refund`; saved before the
provider hears of the outpoint) and `Open` (the provider answered). `Client::ensure_open` is the
only way to `Open` (but for a rollover's next channel), for a plain call, a conditional call, a retry and a restart. A seller that says
yes to the preflight and no to the funded open, or whose answer is lost, leaves a `Funded` channel:
the next call asks the provider again and funds nothing (`duplicate_channel` from a provider that
did open it is taken as the yes that was lost). No state, close or rollover is signed before `Open`.
A `fund` call that errors may have sent: the retry first asks the wallet (`wallet_sends_to`,
`wallet_send`) and otherwise funds the same script under the same key. A keyed channel that has
become too old to fund is moved to `Client::unfunded` and derived again (changed by AGP-096, below:
AGP-090 stopped the open with `open_unresolved` there, for good with a signer or after sixteen).
Still true: a channel a seller refuses to open locks its capacity until its expiry, when the kept
refund spends it. The embedder broadcasts that refund and then removes the record from `channels`
(by hand: the library has no call for a funded record, `forget_unfunded` covers the keyed ones only).

**The owner bounds the expiry (C2).** `funding::offer_expiry_blocks(extra, want, owner_max)`: the
payer asks for at most `owner_max` blocks, and an offer whose floor (`minExpiryBlocks + minConf +
closeMarginBlocks`) is above it is refused `bad_offer` before a key is made. `ClientConfig::
max_expiry_blocks` is 4,032 by default (`OWNER_MAX_EXPIRY_BLOCKS`, the bound of the signer socket's
`open_channel`); the routed client uses its own `expiry_blocks` or 8,064
(`OWNER_MAX_HUB_EXPIRY_BLOCKS`), whichever is larger. The seller's `minCapacity` is added to the
budget with a checked sum. `funding::open_expiry_blocks` itself is unchanged (xbt-signer's session
calls it directly and bounds it in its own task).

**One next key per channel (C3).** Every attempt to roll one channel over pays the key of the first
attempt (`ClientChannel::rolled_from` ties a `next_rolled` record to its parent), with a local key
and with a signer, so a signer's one issued key per origin is never replaced while a signed
rollover can still be broadcast. A retry at the same height and amount is the same transaction.
Past `MAX_KEPT` (16) unresolved rollovers of one channel the client signs no more
(`rollover_unresolved`).

**Receipts (T4).** A receipt must be for the seq of the request just sent, so an earlier answer
replayed with its genuine receipt is `bad_receipt`. The spent total a receipt (signed) or a 402
(unsigned) names may be ahead of the last verified receipt by one quote for each paid request the
provider has not answered (`ClientChannel::unanswered_msat`: added when a request leaves, taken off
when the provider answers 402, cleared by a verified receipt), plus the one call of slack a channel
has over its life (`slack_msat`). So after lost answers the channel goes on, and each call the
provider served is paid once. Stated limit: an answer lost or damaged on the way is paid for, and
a provider is believed for one quote for every paid request that got no receipt, whether the answer
was lost or the provider answered an error without one. Only a 402 takes a request off that count:
a provider that answers 402 to everything can claim one call over the channel's life, as before.
The numbers are under AGP-096 below.

**Transport (T2, T3).**
- A bare request target is bound byte for byte: `wire::split_scheme` takes a string as absolute
  only when everything before its first `://` is spelled as a URL scheme, and `request_url`,
  `url_origin` and `seller_url` all use it. `/a?next=http://h/x` and `/A?next=HTTP://H/x` no longer
  share a digest. The digest of every absolute URL, and every recorded vector, is unchanged.
- A chunked body whose connection ends inside a chunk is `transport_error`. ureq 2.12.1 returns
  the bytes it has as a whole body and shows a caller nothing else, so the workspace builds ureq
  from `vendor/ureq` (`[patch.crates-io]`): the published source with a two-line patch in
  `src/chunked/decoder.rs`, described in `vendor/ureq/XBT-PATCH.md`. This holds for builds whose
  root manifest carries that `[patch]`; since AGP-096 any other build of the transport stops with
  a compile error instead of running the published decoder. A body with neither
  Content-Length nor chunking still ends when the connection does (stated limit: the receipt's
  `bodyHash` covers it on a direct paid call; routed and work-rail calls have no such cover).
- A paid HEAD works: an answer to a HEAD, and a 1xx, 204 or 304, has no body by its framing, so the
  transport does not compare its Content-Length and the client checks its receipt on the status. A
  body that does arrive is checked, and a GET cut to nothing is not taken for a HEAD.

API changes for embedders: `ClientConfig::max_expiry_blocks`; `ClientChannel::{stage,
unanswered_msat, rolled_from}`; `Client::{unfunded, forget_unfunded}`; `funding::
offer_expiry_blocks` takes the owner's bound; a ledger record without the new fields reads as an
open channel with nothing unanswered. A channel in `channels` may now be `Keyed` or `Funded`.

Tests: the audit's `xbt402/tests/agp087_hub_b_client.rs`, `agp087_transport.rs` and
`agp087_transport_http.rs` pass; `xbt402/tests/agp090_client.rs` (15) covers the neighbouring paths;
unit tests in `funding.rs` and `wire.rs`. Three tests in `lifecycle.rs` assumed a retried rollover
is a new transaction to a new key and were changed to the one-key rule.

## Fix wave 5, the library client (AGP-096)

Items 4 (the library's side), 6, 7, 14 (the client's part), 18 and 21 of the third closure audit
(AGP-093, list 1), in `xbt402::client`, `funding.rs`, `wire.rs`, `signer.rs` (`LocalSigner`) and
`http.rs`. The same rules are in B1 (`xbt402/x402_channel.py`, `funding.py`, `signer.py`) where B1
has the code.

**A channel that holds no coins never stands in the way (item 6).** With the shipped provider
(floor 1,008 + 1 + 144 = 1,153 blocks) and the shipped payer (1,008) a keyed channel was "too old
to fund" one block after it was derived, and a too-old record was never set aside with a signer,
or refused the origin for good after sixteen with a local key. So one failed `fund` call (an empty
wallet, a policy refusal, a timeout) ended a payer's business with a seller. Now:
- A keyed channel whose `fund` call failed is retried as it is while it still has
  `funding::offer_retry_floor` blocks: `minExpiryBlocks + minConf` plus the larger half of
  `closeMarginBlocks` (1,081 against the shipped provider, so 72 blocks of retries; the other half
  of the margin is left for the funding to confirm).
- Past that it moves to `Client::unfunded` and the same call derives it again from its own offer
  and funds that. No call fails for it and nothing waits for the embedder.
- Only a channel the wallet was asked to fund is kept there (`ClientChannel::fund_tried`, saved
  before the wallet is asked): its `fund` call may have sent. One the wallet never heard of holds
  nothing and is dropped, so only the owner's own wallet failing fills `unfunded`.
- Every channel derived for an origin until one is funded pays one key: a signer answers the key
  it issued and has not bound (`StateSigner::new_key`, the rule `xbt-signer` has had since
  AGP-089, now also `LocalSigner`'s), and a local key is read back from `unfunded`. So past
  `MAX_KEPT` (16) the oldest script is forgotten and its key is not. A record with a key of its own
  (a ledger written by AGP-090) is never dropped.
- `Client::forget_unfunded` is still there and nothing in the library client needs it. (The Rust
  routed client is another rule: a ch1 recorded and never funded is refused `open_unresolved`
  until its owner calls `RoutePayer::forget_unfunded`. B1's routed client derives again, as here.)

**Funded only on terms the seller offers that day (item 18).** The preflight was asked once, when
the channel was derived; a later call funded it on those terms (after a seller rotated its payTo
key: 200,000 sat locked until the expiry). Before a keyed channel of an earlier call is funded,
the offer of this call must still describe it (payee, close fee and its payer, capacity range, a
price not above the pinned one) and the provider must answer yes to its terms again. If not, the
channel is set aside, derived again from the new offer, and the call fails `open_unresolved` with
nothing funded; the next call funds the new one after the same check. A preflight that gets no
answer changes nothing. The budget (`budget_sats`) is also checked when the coins leave, not only
when the channel is derived: six origins keyed while the wallet was empty were all funded later,
1,200,000 sat under a budget of 1,000,000.

**One seller, one origin (item 18).** `client::split_url` returns the origin as the request binding
reads it (`wire::canonical_origin`: lowercase scheme and host, no userinfo, no default port), and
every payer that keys a book by `split_url` gets it. Five spellings of one refusing seller were
five funded channels. A client ledger that holds a channel under another spelling moves it to the
origin's own key when it is opened; if both spellings were funded, the second stays under its
spelling, where `close` and `rollover` by that spelling find it and no request reaches it.
Not unified: a host with a trailing dot, percent-encoding and IDN forms are other origins, as they
are to the request binding.

**A request is counted before it leaves (item 18).** The seq, the state and the quote of a paid
request are saved to the client ledger before the request is on the wire (one more ledger save per
paid request). They were saved when the call returned, so a process that stopped in between came
back one call behind the provider; the channel's one call of slack covered that once, and the
second time every call was `bad_offer` for good.

**The expiry has a lower bound too (item 4, the library's side).** `funding::offer_expiry_blocks`
refuses (`bad_offer`, before a key is made) an offer whose window lets the channel last less than
the offer's own floor, or less than `OWNER_MIN_EXPIRY_BLOCKS` (144) or the owner's own wish if that
is smaller. An offer with `maxExpiryBlocks: 2` and a yes to the preflight got a channel funded
that expired one block later. The library client's open and rollover and the routed client's ch1
come through this function; `xbt-signer` holds the same bound in its own check (AGP-095).

**An earlier rollover that confirms after a later yes (item 7).** Every attempt pays one next key.
`LocalSigner` took that key out of its slot at the first `attach`, so when the seller said yes to a
later attempt and broadcast an earlier one, the next channel on chain had no key (198,200 sat in
the third audit's run; no test asserts the figure today). `LocalSigner` now keeps every key it issued for as long as it lives and binds one
key to each channel that pays it; `StateSigner`'s documentation states the rule for any signer.
The real signer was already right (it keeps the key under the next channel's script and binds a
next channel only when its node shows the rollover): `xbt-signer/tests/agp096_signer_client.rs`
runs the case through the signer's socket.

**Arithmetic (item 14, the client's part).** The audit's sweep ran with the default `max_price`
(1,000 sat), which refuses a large amount before any sum. `xbt-wallet-mcp` sets `max_price` from
its caller's `max_sats`, and then a seller's amount reached `price * 1000` and `uncond + amount`
unchecked: a panic in a release build. Those sums, the daily budget's, and the request counter are
checked or saturating now, and a conditional offer's `csvDelta` that does not fit 32 bits is
refused (it was cut to its low bits and signed for).

**The vendored ureq (item 21).** See `vendor/ureq/XBT-PATCH.md`: the patch reaches only builds
whose root manifest carries the `[patch]`; any other build of the transport is now a compile error
(`ureq::XBT_PATCH`), not a silent return to the published decoder; `cargo deny` cannot see an
advisory for a path crate, so advisories for ureq are looked up by hand.

Stated limits:
- **A refusal is not signed.** A 402 is the provider's word that a request was not charged, and
  whoever sits between payer and provider can put one in place of an answer the provider served.
  The payer gives the provider one call of doubt in a channel's life; at the second such charge
  every call on that channel fails `bad_offer` until its owner closes it (at what was signed, one
  call less than the provider served in the test) and removes its record; only then does a call
  open another. `Client::close` leaves the record; `xbt-wallet-mcp`'s close tool does both.
  (Corrected by AGP-107: this said the payer closes and opens another by itself.) Signing refusals would
  be a protocol change.
- **A provider is believed for one quote per paid request that got no receipt.** Measured: one
  honest call, ten paid requests answered `503` and never served, then one unsigned 402 naming
  eleven calls, and the client signed 1,650 sat for 150 sat of service. Nothing in the client
  bounds it; the caller's retries, the channel's capacity and `daily_budget` do. A caller that
  retries on errors should set `daily_budget`.
- **A key set aside is the signer's to keep.** With a signer that makes a new key on every
  `new_key` and forgets the one before (against `StateSigner`'s documented rule), a `fund` call
  that failed after it sent, followed by a new derivation, leaves coins under a key that signer
  dropped. `LocalSigner`, B1's `ChannelSigner` and `xbt-signer` do not.
- **A wallet that cannot list its sends may fund two scripts of one open**: a `fund` call that
  failed after it sent, then a retry past the retry floor. Both pay the same key; the client holds
  a refund for the channel it opened and the terms of the other in `unfunded`.
- A `Funded` channel a seller refuses to open still locks its capacity until its expiry and
  blocks its origin until the embedder removes the record (AGP-090's limit, unchanged).

API changes for embedders: `client::split_url` returns the canonical origin (the key of
`Client::channels`); `funding::{offer_retry_floor, OWNER_MIN_EXPIRY_BLOCKS}`;
`wire::canonical_origin`; `ClientChannel::fund_tried`; `LocalSigner::new_key` answers the unbound
key again; a channel too old
to fund no longer answers `open_unresolved` (a changed offer does, once).

Tests: `xbt402/tests/agp096_client.rs` (20), the audit's `agp093_client.rs` (one control line
changed: see the file), `xbt-signer/tests/agp096_signer_client.rs`, unit tests in `funding.rs`,
`signer.rs` and `wire.rs`; B1 `tests/security/test_agp096_client.py` (14).

## Fix wave 5 leftover: a funding the signer made that the client never heard of (AGP-101)

The one Medium that fix wave 5 found and left (AGP-096, "found, not fixed" 1), and two small ones.

**The rule: a funding the signer carried out is always learnable by the client that asked for it,
and a retry adopts it and never funds twice.** `xbt-signer`'s `fund` records the channel and moves
the issued key to it before it broadcasts (write-ahead, AGP-063), and funds one channel to an
origin. A client whose `fund` call got no answer knew no outpoint and could only ask again:
`bad_key` (the key had left its slot), then `channel_pending` once the client had derived the
channel again, until the signer's refund at expiry (1,153 blocks with the shipped provider). No
coin was lost and no seller could be paid. It was the usual case, not a rare one: the two shipped
signer-backed payers (`xbt-signer-payer`, `xbt-wallet-mcp` with `XBT_MCP_PAYER=local`) wait 180 s
for a confirmation and answer `funding_unconfirmed`, and with ten-minute blocks about three waits
in four end that way (e^-0.3).

- **The signer answers.** Socket method `xbt402_funded {origin}`, read-only: `{"funded": {"origin",
  "chan", "params"}}` for the channel `fund` recorded for that origin and no client has attached
  (`params`: the funded `ChannelParams`), else `{"funded": null}`. Only a client's channel, and
  only while it is pending: once attached it may carry signed states, which a client that lost its
  book cannot take over.
- **The client asks first.** `StateSigner::funded` (default `None`: a signer that funds nothing),
  answered by `RemoteSigner`. `Client::ensure_open` asks it on every open that has no outpoint
  yet, before a key is asked for or a wallet is called (`Client::adopt_funded`), and
  `RoutePayer` does the same for ch1. The channel on the books takes the outpoint; a client with
  no record of the channel (a process without a ledger: `xbt-signer-payer` ends at the first
  error) takes the signer's channel whole, if this call's offer still derives it.
- **Why the signer and not the wallet.** The client already asked its `Wallet` for a send to the
  script (`wallet_sends_to`, AGP-045), and `RemoteSigner` could have answered that. But the wallet
  a payer hands the client is a wrapper that waits for the confirmation, and the wrapper is what
  loses the answer; a wrapper that forgets to pass two more methods on reopens the hole without a
  sound. And a client that restarts without a ledger knows no script to ask about. The signer seam
  is not wrapped, and the question is by origin.
- **`xbt402_attach` is answered again.** An attach whose answer was lost found the record open
  and was refused `unknown_channel` for good. The same channel, same params, is answered the same.

Every place:

| place | holds | test |
|---|---|---|
| `fund` answered | yes, as before | `control_an_answered_funding_is_opened_as_before` |
| the payer's wait gave up, retry in the same process, 0, 1, 100 and 143 blocks after the first call (the last block at which the seller opens it) | yes | audit `agp096_signer_client.rs::hole_a_funding_the_signer_made_but_the_caller_never_heard_of_is_adopted_by_the_retry` (unchanged); `a_retry_adopts_the_funding_the_signer_made_and_never_funds_twice` |
| the socket call to `fund` timed out, same retries | yes | same test, `signer_unreachable` |
| retry before the funding has a confirmation | adopted and bound, refund held; opened by the call after the block | `a_retry_before_the_funding_confirms_holds_the_refund_and_opens_after_the_block` |
| restart with a ledger (`xbt-wallet-mcp`) | yes | `a_restarted_payer_adopts_the_funding_with_and_without_a_ledger` |
| restart without a ledger (`xbt-signer-payer`, `XBT_MCP_LEDGER=-`) | yes | same test |
| a ledger the code before left in the hole (funded channel set aside, another derived) | the funded one is taken back | `a_ledger_from_before_that_had_derived_the_channel_again_goes_on_with_the_funded_one` |
| `attach` answered, answer lost | yes | `an_attach_whose_answer_was_lost_is_answered_again` |
| the payer comes back 145 blocks or more after the funding (shipped terms) | not taken up: `open_unresolved`, nothing more funded; a new channel after the signer's refund | `a_funding_found_too_late_for_the_seller_to_open_is_left_to_the_signers_refund` |
| the seller changed its key after the funding, payer without its record | `open_unresolved`, nothing more funded, refund at expiry | `a_funded_channel_the_seller_no_longer_offers_is_not_adopted_and_nothing_more_is_funded` |
| the signer does not answer `xbt402_funded` (down, or a signer from before) | the open fails, nothing funded | `a_signer_that_does_not_answer_what_it_funded_funds_nothing` |
| a second `fund` for the origin on the socket | refused (`bad_key`), one funding | `the_signer_answers_the_channel_it_funded_until_it_is_attached` |
| the signer's own pay rail (`xbt402_pay`, the MCP tool in signer mode) | already held: the call answers `pending` with the channel, and the next call finishes its open | `control_the_signers_own_pending_channel_is_not_answered_as_a_clients`; `common::Rig::open` in every pay-rail test |
| routed client, ch1: retry, and a payer without its books | yes | `xbt402/tests/agp093_client.rs::agp101_a_ch1_the_signer_funded_is_adopted_by_the_next_open_and_by_a_payer_without_its_books` (a signer double that funds as `xbt-signer` does; the real signer has no hub rig) |
| `LocalSigner`, B1 `ChannelSigner` | fund nothing themselves: the wallet does, and is asked for its sends (AGP-045) | not applicable |

(The tests without a path are in `xbt-signer/tests/agp101_funded.rs`.)

Limits:
- **A funding is taken up only while the seller would still open it.** The provider opens a channel
  with `minExpiryBlocks` left, and the payer derives it with `closeMarginBlocks` more: with the
  shipped terms (1,153 against 1,008) a payer that comes back within 144 blocks of the funding,
  about a day, goes on with it. Later than that the seller refuses the open (`bad_expiry`) whatever
  the payer does, so the channel is not taken onto the books (`funding::offer_open_floor`): the
  call fails `open_unresolved`, and the seller can be paid through this signer again once it has
  refunded the channel at its expiry. That part of the hole cannot be closed from the payer's
  side; a longer expiry (`--expiry-blocks`, `XBT_MCP_EXPIRY_BLOCKS`, within the signer's policy)
  widens the day. Since AGP-105 the two shipped payers ask for 2,016 blocks, so the window is 1,007
  blocks, about a week; a payer built on `ClientConfig::new` still asks for 1,008 and has the day.
- **A payer that has lost its record of a channel that is already attached cannot take it over.**
  `xbt402_funded` answers a channel only until it is attached; after that a process without a
  ledger is refused `channel_open`, as before, until the owner closes the channel
  (`close_channel`) or it is refunded at expiry. A payer that must survive a restart keeps a
  ledger.
- **Payer and signer are upgraded together.** A payer of this version asks `xbt402_funded` on
  every open; a signer from before answers `unknown method`, and the open fails with nothing
  funded. It does not fall back to "nothing was funded".
- A funded channel whose seller changed its key stays locked until its expiry (AGP-090's limit;
  the call now says so instead of `channel_pending`).
- Two payers on one signer and one origin were never supported (they are given the same key); the
  second now adopts the first one's pending channel instead of being refused `channel_pending`.

**The second forged refusal is a limit (the audit's `hole_two_forged_refusals_do_not_end_the_channel`).**
The test is now `limit_two_forged_refusals_end_the_channel` and asserts what happens: after the
second charge hidden behind a forged 402 every call is `bad_offer` (nine calls served, seven answers
held), and the payer closes at what it signed. For the channel to go on the payer must take the
hidden charge onto its books on an unsigned word. The one small rule that does it (a refused
request stays among the unanswered ones, at one quote) was run: that test passes and AGP-090's
`a_provider_that_refuses_every_call_cannot_claim_them` (review M3) fails, because a seller that
serves nothing and answers every paid request with a 402 is then owed a quote for each. Telling
the two apart needs a signed refusal, which is a change of the protocol. Whoever can forge an
answer can also drop every answer, so no rule gives a payer a channel that works through them.

**The routing-fee limit saturates.** `LnPolicy::fee_limit_sats` is the owner's base plus ppm of the
amount, neither bounded: a product past `i64` was cast to a negative limit, and the sum with the
base or the amount could panic. Both saturate, and the payment is refused `max_sats`.

Not changed: `Wallet::wallet_sends_to` still answers an empty list both for "no send" and for
"this wallet cannot list its sends". The fix does not need the two told apart, since the question
that matters now goes to the signer, which answers or fails.

API for embedders: `StateSigner::funded` (a default method); `funding::offer_open_floor`; the signer
socket's `xbt402_funded`; `xbt402_attach` of a channel already attached answers the channel.

## Fix wave 6: one URL parser, a provider that does not answer, defaults that route (AGP-105)

The fourth closure audit (AGP-102) found no High item. This section is the library client, the hub
and the shipped defaults: its items 1, 2, 6, 7, 10 and the two fixes of 11. Each row is one rule,
kept in one place. The audit's tests are `agp102_*`; `agp105_*` are the neighbours. B1 `xbt402/hub.py`
on `agp-105` has items 2 and 11 with the same test names (`tests/security/test_agp105_hub.py`).

| item | the rule | what broke it | now | tests |
|---|---|---|---|---|
| 1 a URL paid as one host and sent to another | the host a payer keys its book by, checks an allowlist on and binds a payment to is the host the request is sent to | `request_url` decided the host for the book and the binding, and the transport parsed the caller's string again with the `url` crate: `http://A\@B/x` is B to the first and A to the second, so B's channel paid and A got the payment | no transport is given the caller's string: it gets `scheme://[userinfo@]host[:port]target` put together from what `request_url` read (`wire::sendable_url`), and a URL whose parts are not spelled in the one way every parser reads alike is refused `bad_request` before anything is signed, funded or probed | `agp102_client.rs::sockets::hole_a_paid_request_is_sent_only_to_the_host_its_origin_names`, `xbt-signer/tests/agp102_signer_client.rs::hole_a_url_that_passes_the_allowlist_is_sent_to_the_allowlisted_host`, `wire.rs::a_sendable_url_is_the_parsed_one_and_the_rest_is_refused`, `::the_transports_parser_reads_every_sendable_url_as_the_book_does`, `agp105_client.rs::the_client_gives_a_transport_only_the_url_its_own_parser_read` |
| 2 a provider that does not answer was waited for on every lock | a provider that did not answer the hub within `revealTimeoutSec` is not waited for again by a client's lock until it has answered the hub | the check before the pre-signature was one request with the transport's 30 s, and no answer wrote nothing off and blocked nothing, so the next lock waited again | the check is given up after `revealTimeoutSec` (`Transport::request_within`). When that time passed with no answer the ch2 is blocked with nothing written off or held, and later locks are refused at once (`route_blocked`). The watcher asks one such provider per tick with a check that names no lock and lifts the block when it answers (`ch2_answers_again`). A check that failed sooner blocks nothing | `agp102_hub.rs::a_provider_that_does_not_answer_the_check_is_not_waited_for_on_every_lock`, `agp105_hub.rs::a_provider_set_aside_is_refused_at_once_and_comes_back_when_it_answers`, `::providers_that_stay_dark_cost_a_tick_one_wait_and_are_asked_in_turn`, `::a_late_answer_is_an_answer`, `agp105_client.rs::sockets::the_shipped_transport_keeps_a_requests_own_deadline` |
| 2 (HUB 8) one busy provider held up every request | nothing waits for a provider inside ch1's ledger lock | a lock that found the provider's busy flag taken waited up to 500 ms for it with the ledger lock held, which every route, view, open and close needs | the flag is taken only if it is free; otherwise the ledger lock is released, the flag waited for, and admission run again from the top on ch1 as it is then | `agp102_hub.rs::a_provider_that_does_not_answer_does_not_hold_up_a_lock_to_another_provider`, `agp105_hub.rs::a_lock_that_waited_for_the_providers_flag_is_paid_when_it_is_free` |
| 6 a ch1 funding that failed after it sent was sent again | after a `fund` call that did not return an outpoint, ch1 is funded again only when the wallet says it sent nothing | "none known" from a wallet that cannot list its sends was read as "nothing was sent" | that the wallet was asked is on the books before the call. A wallet says whether its "none" means none (`Wallet::knows_its_sends`: `Rpc` and the signer's wallet do); one that cannot say is not asked again: `open_unresolved`, with the amount and the address to look for, until `forget_unfunded`. `xbt402-route-payer`'s wallet wrappers now pass the node wallet's list on | `agp102_route_client.rs::a_ch1_funding_that_failed_after_it_was_sent_is_not_sent_again_by_a_wallet_that_cannot_list`, `agp105_hub.rs::a_wallet_that_cannot_say_is_not_asked_twice_whatever_its_first_call_did`, `::that_the_wallet_was_asked_survives_a_restart` |
| 7 one day to come back for a funded channel | a shipped payer asks for more blocks than the shipped provider's floor, with room to come back | both asked for 1,008 against a floor of 1,153, so the window was the 144-block close margin | `xbt-signer-payer` and `xbt-wallet-mcp` ask for 2,016 (`client::SHIPPED_PAYER_EXPIRY_BLOCKS`): 1,007 blocks to come back, and the coins locked for up to two weeks in place of eight days | `agp105_client.rs::the_shipped_payers_have_a_week_to_come_back_for_a_funded_channel` |
| 10 the shipped hub and route provider routed nothing | binaries at their own defaults route, and a session nothing could pay is refused when it starts | `xbt402-route-provider` issued 8 s invoices and a hub admits one only with `revealTimeoutSec` (10 s) left; the interop script set 2 s | `--ttl` defaults to the library's 15 s; the provider refuses to start when `--ttl` is under `1 + --hub-reveal-timeout` (default: the hub's); the client refuses a session whose `invoiceTtl` is under `1 + revealTimeoutSec` (`route_blocked`, with both numbers); the hub counts every lock it refuses by code (`HubStats::not_admitted`) and says the 1st, 2nd, 4th... on stderr | `agp102_hub.rs::a_lock_is_routed_at_the_shipped_defaults_of_the_hub_and_the_route_provider`, `agp105_hub.rs::a_session_no_lock_could_pay_is_refused_when_it_starts` |
| 11 the watcher read the chain again on every tick | a spend the watcher found in a block is looked for in that block, not from the ch2's first block, while it waits for depth | `find_spend_at` was asked from the funding height on each of the about 600 ticks a close waits | the record keeps the height the spender was found at (`spend_at`); the scan starts there and runs from the first block again only when nothing is found from it | `agp102_hub.rs::the_watcher_reads_the_chain_once_for_a_spend_that_waits_for_depth`, `::..._for_a_rollover_...`, `agp105_hub.rs::the_remembered_height_is_only_where_the_scan_starts` |
| 11 the watcher's catch was per tick | one channel's failure, a panic included, does not stop the tick for the others | a ch2 whose reconcile panicked ended every tick there | each channel's step is caught (`RouteHub::step`); the first panic is raised again when the tick is done, so `/healthz` still says 503 | `agp102_hub.rs::a_ch2_whose_reconcile_panics_on_every_tick_does_not_stop_the_watcher_for_the_others` |

**What `sendable_url` refuses.** Not `scheme://...` (so `http:\\h` and `http:/h`, which a WHATWG
parser reads as absolute); a backslash, a `#`, whitespace or a control character anywhere; a second
`@`, or userinfo outside RFC 3986's set; an empty host; a host with a character other than a
letter, digit, `.`, `-` or `_` (so no percent-encoding and no non-ASCII name); a host whose last
label is a number and that is not a dotted quad as `Ipv4Addr` prints it (`127.1`, `2130706433`,
`0x7f.0.0.1`); a bracketed host that is not an IPv6 address as `Ipv6Addr` prints it, or with
anything but a port after it; a port that is not a number below 65536. Not refused, because both
readings agree: upper case, a default port, a port's leading zeros, an empty port, a trailing dot,
userinfo. `canonical_origin` and `split_url` are unchanged.

| place | before | now |
|---|---|---|
| `http::UreqTransport` (every request of the shipped binaries: client, routed client, work payer, the MCP wallet's probe, hub to provider) | parsed the caller's string | `sendable_url`, then sends what it returns |
| `Client::request_with`, `request_conditional` | `no_fragment` | `sendable_url` before anything is signed, for any transport |
| `RoutePayer::shard` | `no_fragment`; session keyed by the caller's string | `sendable_url`; the session is opened at, keyed by and paid at what it returns |
| `xbt-work` `WorkPayer::prepare` | `split_url` | `sendable_url` first |
| `xbt-wallet-mcp` local payer | allowlist on `split_url`, probe of the caller's string | `sendable_url` before the allowlist |
| `xbt-signer`'s own pay rail | refuses such a URL (`session::origin_of` keeps the spelling) | unchanged |
| URLs a seller or hub names (`wire::seller_url`) | a path on the canonical origin, no backslash, whitespace or `#` | unchanged |
| the hub, for the provider a client names | looks up its own ch2 by the canonical origin and sends to the origin the operator connected | unchanged |
| B1 | urllib refuses a URL with userinfo and resolves the others as one name | unchanged |

**New state, and what fills it.**

| state | who fills it | at its bound | an honest slow or failing peer | a ledger from before | shipped defaults |
|---|---|---|---|---|---|
| a ch2 blocked for an unanswered check | a provider the hub has a ch2 to, by not answering one check for `revealTimeoutSec`. A client cannot: its fields are refused in an answer | one per ch2; it stops routing and refill to that provider and nothing else | a provider that answers a check later than `revealTimeoutSec` is set aside until a tick's ask is answered: at most `providers × watch_interval` plus one check wait | none: `blocked` is the field older blocks use. A binary from before reads this text as a block it never lifts | 10 s check, 5 s tick |
| the watcher's ask | the hub, one provider per tick in turn | a tick is longer by at most `revealTimeoutSec` however many providers are dark; each ask spends one ch2 seq and one write at the hub and the provider | asked again next turn | none (the turn is in memory) | as above |
| `HubStats::not_admitted` | an authenticated client request the hub refuses | one counter per error code; stderr gets a line at each power of two | none | none (memory) | on |
| `spend_at` on a ch2 record | the watcher, from its own node's scan | one number per record | a reorg that moves the spend lower costs one full scan | absent is 0: the full scan, once | on |
| `fund_asked` on the routed client's ch1 | the client, before it asks its wallet | one flag per ch1 | a wallet that fails or refuses and cannot say what it sent stops the open until its owner calls `forget_unfunded` | absent is false: asked once more, the rule before | `xbt402-route-payer`'s wallets say |
| `Transport::request_within`, `Wallet::knows_its_sends` | an embedder's implementation | defaults: no bound but the transport's own, and "cannot say" | | | |

Limits:
- **A provider set aside is found again by the watcher only.** With the watcher stopped it stays
  blocked. The ask proves the provider answers a check, not that it will reveal: one that answers
  checks and holds locks is written off as before (`revealTimeoutSec`, then the ch2 is blocked for good).
- **The lock itself still waits the transport's 30 s** when the provider takes it and does not
  answer; that happens once, after which the ch2 is blocked as it always was. The hub's open, close
  and rollover requests to a provider also wait up to 30 s each.
- **An embedder's transport keeps the bound only if it implements `request_within`.** Without it the
  check waits as long as that transport does; the hub still sets the provider aside afterwards.
- **A wallet that cannot say what it sent is not asked twice**, also when its first call only
  refused: the owner looks and calls `forget_unfunded`. A wallet that lists its sends must say so
  (`knows_its_sends`), or it is treated as one that cannot. B1's `fund` is a bare callable and cannot
  say: there a retry after a `fund` that raised still pays the same script again.
- **The window to come back for a funded channel is 1,007 blocks with the shipped payers**, and 144
  for a payer that keeps `ClientConfig::new`'s 1,008. After it the coins wait for the signer's refund
  at the expiry, up to 1,009 blocks, and that seller cannot be paid through that signer meanwhile.
- **One seller can still be several origins**: a trailing dot, and an IDN against its punycode (the
  non-ASCII spelling is refused, so only one of the two can be paid). The number forms of an IPv4
  address and percent-encoding are now refused.
- **With a scan that gives no depth, `spend_at` stays 0** and the watcher scans as before.

## Review close-out: limits as tests, `docs/LIMITS.md` (AGP-107)

After fix wave 6 the tree had no regression and 21 of the fourth audit's tests were still red (10
here, 3 in B1, 8 in B2), because their items had been written down and not fixed. A red test that
states an accepted limit reads the same as a red test for a bug, so each of the 21 got one
decision, and the tree is green. No protocol or logic changed here; B1 got one small port (below).

**The rule for a limit test.** A hole the audit or a fix task decided to state is kept as the
executable statement of that limit: the test is renamed `limit_...`, its last assertion is turned
round so that it passes while the limit holds and fails when someone lifts it, and its comment
names the audit's item, the sentence of `docs/LIMITS.md` it pins, and the assertion to restore when
the limit goes. No test was deleted and no control was weakened. **The rule for an open item:** a
defect nobody decided to accept keeps its test as the audit wrote it, ignored with a reason that
starts `open:` (Python: `expectedFailure` under a comment with the same text), and is listed under
"Open items" in `docs/LIMITS.md`. `scripts/publish/review_summary.py --check <trees>` fails when
the markers and that list differ.

| test (as the audit named it) | audit item | decision |
|---|---|---|
| `xbt-signer` `agp102_signer_client::hole_a_payer_that_comes_back_two_days_...` | 7 | fixture: it pinned the library's 1,008 blocks as "the shipped payers' default"; it now sets what the shipped payers use (`SHIPPED_PAYER_EXPIRY_BLOCKS`, AGP-105) and passes. The library default's one day stays pinned by `limit_a_payer_away_for_145_blocks_...` |
| `agp102_wallet_rs::hole_a_channel_rolled_by_a_rollover_that_was_only_in_the_mempool_...` | 12 | limit (`limit_..._is_not_refunded_by_the_wallet_at_its_expiry`) |
| `agp102_wallet_rs::hole_the_next_channel_of_a_rollover_is_refunded_when_...` | 12 | limit (`limit_..._is_not_refunded_when_...`) |
| `agp102_wallet_rs::hole_a_second_stream_on_a_postpay_channel_is_delivered` | 13 | open |
| `agp102_wallet_rs::hole_a_stream_is_delivered_on_a_postpay_channel_that_lost_one_answer` | 13 | open |
| `xbt-work-relay` `agp102_work::the_pull_at_its_shipped_interval_gets_every_receipt_...` | 16 | limit (`limit_past_about_30_invoices_the_pull_...`), written down by AGP-106 |
| `xbt402` `agp102_client::hole_after_the_close_that_follows_two_forged_refusals_...` | 15 | limit (`limit_..._every_call_is_refused_until_the_record_is_removed`); the sentence it contradicted is corrected |
| `agp102_client::sockets::hole_a_refusing_seller_is_funded_once_however_its_host_is_spelled` | 15 | limit (`limit_a_refusing_seller_is_funded_once_for_each_spelling_that_is_not_refused`): AGP-105 refuses the audit's spellings, so its fixture could no longer reach the rule; the test now pins that refusal and the trailing dot that is left |
| `xbt402-interop` `agp102_hub::a_close_seen_back_in_the_mempool_...` | 11 | limit (`limit_with_a_scan_that_gives_no_depth_...`), written down by AGP-105 |
| `agp102_hub::a_completion_ch1_did_not_take_...` | 11 | limit (`limit_a_completion_ch1_did_not_take_is_released_as_unpaid_...`), written down by AGP-105 |

Items 5 and 13 are open and not limits because their own sentences forbid a use until a fix: the
Python wallet's forward rail must stay off, and a stream must not be bought on a postpay channel.
The B1 and B2 rows are in their READMEs.

Also here:

- `docs/LIMITS.md`: every stated limit, one sentence each, by area; the open items; what no review
  covered. It starts from the fourth audit's list and is corrected by what wave 6 changed. B1 and
  B2 each have a short `docs/LIMITS.md` for what differs in the Python references.
- `scripts/publish/review_summary.py` no longer writes "fixed" without what is left: it gives what
  was reviewed and when, the four audits with their counts, the table of first fixes, the number of
  limits per area, and the open items and the not-reviewed list word for word from
  `docs/LIMITS.md`; without that file or one of its sections it writes nothing. It also read the
  staged commit maps wrongly (they have three columns), so every commit came out as
  "not-a-separate-commit" with no error; a run in which no commit resolves now stops.
- The audit's two hub test files wrote their scratch files under one checkout's absolute path;
  they use the system's temporary directory now.
- `close_bump_regtest.sh`, `refund_bump_regtest.sh` and `funding_reconcile_regtest.sh` defaulted to
  B1 checkouts that are long gone; they default to the main B1 checkout as the other scripts do.
  `refund_bump_regtest.sh` failed two checks per hub on its first run since wave 5: its two tools
  look one block after a refund confirms, and a refund is final six blocks deep since AGP-094.
  They set `spend_final_depth` 1 now, as the close-bump and route-demo tools already did.
- Wave 6's light-client and pay-with-work rules (AGP-106) have no section of their own above. In
  one line each: a header sync is not paid for out of a call's time; every number a server sends
  is a finite float or a 64-bit integer before anything reads it; a request is written by one
  deadline over TLS too; a connection keeps at most 16 requests nobody waits for; in a scan only
  "no such transaction" withdraws a coin its server listed; the work provider writes its state
  when it changed, and only then; an equivocation distrusts the Prime wherever it is found; a
  price is worked out only from what the node answered. Their tests are `agp106_light.rs`,
  `agp106_work.rs` and B2 `test_agp106_light.py`.

## Lightning rail pays BOLT 12 offers (AGP-082)

`ln_pay` takes a BOLT 12 offer (`lno1...`) as well as a BOLT 11 invoice. The seller publishes one
offer; each payment is an invoice the seller signs for it, which the wallet keeps. Nothing else is new:
no bridge service, no channel-script change, no new 402 entry, and the wallet still only pays. Code:
`crates/xbt-signer/src/bolt12.rs` (the reader) and `src/ln_offer.rs` (the payment); tests in
`src/bolt12.rs` and `tests/ln_rail.rs` (`agp082_*`).

**What is checked, and where.** The signer reads the offer and the invoice itself, as it does a BOLT 11
invoice. It never asks the node to decode one, which would need `invoices:read`; the mainnet macaroon
stays at `info:read offchain:read offchain:write onchain:read`. In order:

1. **The offer** (`bolt12::check_offer`): feature bit 512, a chain this node is on, not expired, an
   amount (its own, or `amount_sats` from the caller when it names none), the caller's `description` if
   given, `max_sats`. Offers priced in a currency, sold by quantity, or carrying experimental-range
   fields are refused (`ln_offer`).
2. **The node and its channels**, as for BOLT 11: chain identity, macaroon, exposure cap, watchtowers,
   funding proofs. One rule is stricter, see "Channels" below.
3. **The policy**, on `ln-offer:<offer id>` and the amount plus the fee limit. Both are known before
   any invoice exists, so a denied or over-threshold payment asks the issuer for nothing. The human's
   approval is for that offer and that amount, once.
4. **The invoice.** The node fetches it (`POST /v2/offers/fetchinvoice`, `offchain:read`). The signer
   decodes the `lni1...`, verifies the BIP-340 signature over its Merkle root, and checks
   (`bolt12::check_invoice`): bit 512; the chain; that it repeats this offer's fields byte for byte;
   that the offer's issuer signed it (`offer_issuer_id`, or for an offer with none the last blinded
   node of one of its paths); the amount asked; at least `ln.min_expiry_s` left; each payment path's
   `cltv_expiry_delta` within `ln.max_cltv_blocks`. Then the node's own summary of the invoice
   (`InvoiceInfo`) must agree with the decode field by field (`ln_decode_mismatch`).
5. **The signer of the offer.** The key that signed an offer's first invoice is recorded in
   `.run/ln_offers.json`. A later invoice for that offer signed by another key is refused
   (`ln_offer_signer`), valid signature or not. An offer with several blinded paths may legitimately
   be answered by a different blinded key each time; that is refused too, until the owner removes the
   offer's entry from the file.

The offer id is the SHA-256 of the offer's TLV bytes. That is Core Lightning's definition and what
Lightning Fork reports as `offer_id`, so the allowlist entry can be read off either node.

**The chain.** BOLT 12 reads an offer that names no chain as "bitcoin" mainnet, by its genesis hash. XBT mainnet shares
that genesis hash with the SHA-256 chain, so on mainnet a chain-less offer names this chain and the SHA-256 chain alike,
and most offers are chain-less. Bit 512 is what tells them apart: a chain-less offer with bit 512 is
payable on mainnet, and without it is refused. Off mainnet a chain-less offer names another chain and
is refused. The chain an offer must name is block 0 of the signer's own node. Lightning Fork's code at
`v0.21.3-beta-blake2b.17` reads it the same way (its `docs/bolt12-offers.md` still says a chain-less
offer "is reported as not for this chain"; the code and its tests say otherwise). The test
`lightning_forks_own_offers_and_invoices` pins the fork's verdicts, so a drift on either side fails.

**One invoice per attempt.** The fetched invoice is written to `ln_offers.json` before it is paid, and
it is the invoice that is paid (`POST /v2/offers/pay` with `invoice`), never the offer. Paying the
offer again would fetch a second invoice, and a retry that settled beside the first would pay twice.
A later `ln_pay` of the same offer for the same amount pays the stored invoice while it is unpaid and
not expiring; a new one is fetched only after that one settled. Invoices asked of one offer are
limited by `ln.max_sends_per_hour`, paid or not, and so is every send of one invoice (AGP-092: a
retry used to replace the one record that was counted).

**Channels.** `PayOffer` takes neither a set of outgoing channels nor a CLTV limit, so the wallet
cannot confine an offer's payment to the channels it has proven, as it does for BOLT 11
(`outgoing_chan_ids`). Instead it refuses the payment (`ln_offer_unsafe_channel`) unless **every**
channel of the node passes the guards and the funding proof, inactive ones included. A node with a
taproot, non-unified, zero-conf or pre-split channel pays BOLT 11 invoices and no offers. The node's
own `max-cltv-expiry` bounds the route's time lock; the wallet bounds the invoice's blinded paths,
and watches a released booking for `ln.node_max_cltv_blocks` (2016, that setting's default) + 144
blocks (AGP-092).
The fee limit sent is never 0, which the node reads as its default limit: it is at least 1 sat.

**Not payer identity.** A BOLT 12 invoice names the key the request was signed with
(`invreq_payer_id`). Lightning Fork draws a fresh key for every request, and `PayOffer` has no field
for a caller's key, so two payments of one offer carry two payer ids. Each is recorded with its
payment (`payer_id` in `ln_payments.json`, the signature log and the reply) and names that payment
only. A stable payer id needs a change in the fork.

**The audit's two Lightning findings** (the AGP-077 closure audit, list 1, item 11), fixed here because they are in
the same file. Each has a test that failed before the fix (commit `db5d8cf` holds the tests alone):

* **Redirects.** The REST client followed up to five redirects and kept the macaroon header, so a
  node (or anything answering on its port) could send the macaroon to a host the loopback and
  pinned-certificate checks refuse. Redirects are off, and a 3xx answer is an error, never "no such
  payment". Test: `agp082_the_rest_client_follows_no_redirect_so_the_macaroon_goes_to_no_other_host`.
* **The settle booking.** A settled payment was booked at the value and fee the node reported, with
  no floor and no look at the preimage: a `SUCCEEDED` record with zero amounts took a 403 sat booking
  to 0. The booking is now at least the invoice amount, and `SUCCEEDED` counts only with the 32-byte
  preimage of the payment hash. Without it the whole worst-case booking stays, no proof of payment is
  logged, and the rail halts until the human resumes it (the `ln_resume` approval of AGP-066). Tests:
  `agp082_a_settled_payment_is_booked_at_no_less_than_the_invoice_amount`,
  `agp082_a_settled_payment_without_the_preimage_of_its_hash_keeps_its_whole_booking_and_halts_the_rail`.

**How the reader is tested.** No dependency was added; the reader and its checks are about 650 lines
beside `bolt11.rs`. Every length and count from the wire is bounded before use (a string of at most 16,384
characters, 64 records, 16 paths; a field's length is checked against the bytes left).

* The specification's vectors (`tests/data/bolt12`, CC-BY 4.0): 12 string-format cases, 53 offers
  (valid and malformed), 4 Merkle roots and the signed `invoice_request`.
* Lightning Fork's own codec at `.17` as the reference implementation
  (`tests/data/bolt12/lightning-fork-17.json`, generator `scripts/ln_rail/agp082vec.go`): 9 offers and
  8 invoices it wrote, with its reader's verdict on regtest and on mainnet. This reader holds the same
  fields, the same offer ids, verifies the fork's signatures, and reaches the same verdict on each.
  No node ran for this; it is the fork's `bolt12` package alone.
* A property test, `truncated_overlong_and_mutated_input_is_refused`: every truncation, every
  single-bit flip of a signed invoice, every field's length replaced by six overlong encodings, counts
  that promise more than is there, and 20,000 random mutations and random inputs. Nothing panics and
  nothing but the signed invoice is accepted.

**On a running node (AGP-083).** `scripts/ln_rail_regtest.sh` now pins Lightning Fork `cebc10fe`
(`v0.21.3-beta-blake2b.17`) and adds a third lab node, `lf3`, whose one channel is opened from a coin
confirmed above the split. 86/86 on 2026-10-10 (`docs/agp083_ln_rail_regtest.json`): S1-S18, the
BOLT 11 scenarios, unchanged on `.17`, and S19-S24 for offers `lf2` mints:

* `lf1`, which holds a taproot channel and a pre-split one, pays no offer (`ln_offer_unsafe_channel`,
  before any invoice is asked for) and still pays a BOLT 11 invoice.
* An offer the allowlist does not name is denied before any invoice is asked for.
* `lf3` pays a 15,000-sat offer it cannot yet send: the payment fails on the node
  (`FAILURE_REASON_INSUFFICIENT_BALANCE`) with nothing charged, twice. After `lf3` has the funds and
  the signer has restarted, the same `ln_pay` pays the stored `lni1`. `lf2` issued one invoice for
  all of it, and the preimage is in the reply, the payment book and the signature log.
* The same offer again: a second invoice, the same signing key, another payer id.
* An offer with no amount and two blinded paths, paid with `amount_sats`, twice. It keeps its issuer
  id beside the paths, and its invoices are signed by that key, not by a blinded one.

The reader agreed with the node on every offer and invoice: offer id, payment hash, signing key,
payer id, amount, and the node's own summary field by field. Two things about the fork that the
fake node did not show, neither in the reader:

* **A direct peer still costs a fee.** `lf2`'s invoices are paid over blinded paths that start at
  its peer `lf1`, so `lf3` pays `lf3 -> lf2 -> lf1 -> lf2`: 2,246 to 3,261 msat on 15,000 sats, and
  `lf2` needs funds towards `lf1`. The fee stays inside the limit the policy booked. The channels the
  payee's side uses are the payee's choice; the guards cover this node's channels only.
* **The first invoice request for an offer with blinded paths can time out.** `lf3`, not a peer of
  the path's first node, sent its request by `lf2`; `lf1` dropped it ("onion message cycle: next hop
  is the sending peer") and `ln_pay` answered `ln_fetch_invoice` after `ln.timeout_s`. It worked a
  minute later, once the node had connected to `lf1` (`docs/agp083_ln_rail_regtest_run1.json`). The
  lab now connects `lf3` to `lf1` first. Nothing is booked for a fetch that times out, but it counts
  against `ln.max_sends_per_hour` for that offer.

CPU (`crates/xbt-signer/examples/bolt12_cost.rs`; armv7 musl under `qemu-arm-static` as the Pi-class
figure, x86_64 native beside it; pass line declared before measuring). One iteration decodes and
checks an offer of 1,024 TLV bytes (1,643 characters, two blinded paths) and its invoice (2,420
characters), signature included:

| step | pass line (armv7) | armv7 median | armv7 slowest of 1,000 | x86_64 median |
|---|---|---|---|---|
| decode and check a 1 KB offer and its invoice | ≤ 20 ms | 0.93 to 1.00 ms | 4.06 ms | 0.085 ms |

**For embedders (cmp and anyone linking `xbt-signer`).** Wire and behaviour changes:

| change | before | now |
|---|---|---|
| `ln_pay` `invoice` | a BOLT 11 invoice | or a BOLT 12 offer (`lno1...`); an `lni1`/`lnr1` string is refused (`ln_invoice`) |
| `ln_pay` `amount_sats` | | optional: the amount to pay an offer that names none; 0 or absent otherwise |
| policy destination | `ln:<payee node id>` | or `ln-offer:<offer id>` for an offer |
| `ln_pay` reply for an offer | | adds `offer_id`, `payer_id`, `invoice_reused` |
| `ln_pay` rules | | adds `ln_offer`, `ln_offer_mismatch`, `ln_offer_signer`, `ln_offer_store`, `ln_offer_unsafe_channel`, `ln_fetch_invoice`, `ln_preimage` |
| a settled payment | booked at the node's reported value + fee | booked at no less than the invoice amount; without the preimage of its hash: verdict `pending`, rule `ln_preimage`, status `SUCCEEDED_UNPROVEN`, the rail halted |
| `B2_LN_REST` redirects | followed, macaroon header kept | never followed; a 3xx is an `ln_backend` error |
| node RPCs | | `POST /v2/offers/fetchinvoice`, `POST /v2/offers/pay`: needs `offersrpc` on the node, and onion messages on |
| `LnBackend` | | adds `fetch_invoice` and `pay_offer` (default: an error, so existing backends compile) |
| audit log | | `ln_preimage_mismatch` |
| `.run/` | | `ln_offers.json`; `ln_payments.json` records of offers gain `offer_id`, `offer`, `payer_id`, `node_id`; a record may hold `preimage_ok: false` |
| `ln_status` | | unchanged in shape |

New dependency: none (`cargo tree -d` is unchanged).

## Embedders on xbt402 v1.3 (AGP-074)

AGP-068 changed the wire (derivation v3, request binding v2, receipt v2) and left the embedders on
their pins. This moves them.

**xbt-work speaks request binding v2.** `xbt_work::auth::request_digest` is now
`xbt402::wire::request_digest_v2`: the digest is the tagged hash of the length-prefixed method,
scheme, host, port, target and body, taken over the URL the payer sent the request to. A bare
target binds no origin, which is what the XBT-053 vectors use. v1 (`request_digest_v1`) no longer
authenticates. The vectors are XBT-053's `vectors.json` with the `auth` section regenerated
(XBT-053 branch `agp-074`; `scripts/work_conformance.sh` still demands byte identity). The HMAC
over the digest is unchanged.

Options weighed for the binding (best-performing-stack rule): a digest of xbt-work's own (a second
definition to keep equal with xbt402's, forever), keeping v1 behind a version flag (two live
bindings, and a captured v1 header still spends), or **xbt402's v2 directly (chosen)**. One
function, the same one B1 and the channel scheme already verify, and the vector file moves
with it.

**Cost.** Declared before measuring: moving xbt-work's digest from v1 to v2 may add at most 50 µs
per paid call on the Ryzen 9 9950X3D, and at most 1 ms on the Pi 3's Cortex-A53. Measured with
`cargo run --release -p xbt402 --example binding_bench` (20,000 iterations, the bench's own empty
body): v1 98 ns, v2 273 ns, so +175 ns per call. The difference is the length prefix per field and
the origin split; both hash the same body bytes, and the bench's own line puts a 4 KiB body at
1,657 ns. On the Pi 3 the same SHA-256 is the cost, and 175 ns scaled by that core's gap to the
Ryzen stays far under 1 ms. Nothing is added per byte beyond what v1 already hashed.

**xbt-063.** `rehearsal/PINS` and `vendor/` move to the merged B1 and B2 masters. The flagship
refund probe's policy carries `allowlist` and `counterparties[probe].pay_to`, because AGP-063 (W3)
refuses an `open_channel` whose destination is not the policy's. `scripts/mcp/regtest_conformance.sh`
and `verify_agp030.sh` default to this xbt-063 tree.

**B5.** `vendor/` moves to the same masters, and `fwd/server.py` signs receipt v2: `status` and
`bodyHash` over the answer body, with `req` bound by `request_digest_v2`.

**B2.** `open_from_offer` posts the review C2 preflight `/open` (no outpoint) before it funds, as
`Payer::open` and the B1 client do. A refusal funds nothing; a provider from before the preflight
answers `bad_request` and the wallet funds as before.

`xbt-signer`'s `request_target` is gone: nothing called it once the binding moved to the full URL.

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
goes through `json::parse`, and every output through `json::dumps`: the 253 + 79 vectors are
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
--locked` (cargo-zigbuild 0.23.4 from a local install, zig 0.16.0 from the ziglang venv)
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

