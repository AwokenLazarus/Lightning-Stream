//! The Rust provider for the pay-with-work regtest run: a paid JSON API (`/v1/*`, 150 sat) behind
//! the xbt402 Provider, offering `xbt-channel` and `xbt-work` in one 402. The work rail pulls
//! receipts through the blinded relay every few seconds, re-prices on every new epoch (§6.3) and,
//! with `--admin`, audits pool coinbases on request (loopback only, with the admin token).
//!
//! xbt-work-provider --port P --rpc-port R --cookie PATH --identity ADDR --prime-pubkey HEX
//!                   --prime-id N --receipt-url URL [--relay-url URL] [--window-url URL]
//!                   [--state FILE | off] [--price SAT] [--haircut-bps N] [--work-units N] [--admin]
//!                   [--pull-secs N]   (relay pull interval, default 3; 0: only before an audit)
//!                   [--nta]           (§13.8: refuse an identity that is not key-path P2TR)
//!                   [--audit-depth K | off [--audit-from H]]   (audit every block K deep on its own)
//!                   [--cap-invoice W | --cap-invoice-sats S | --cap-invoice-calls N | off]
//!                   [--cap-total ... ]   (the same four forms)
//!                   [--max-carry-sats S | off] [--carry-growth-blocks N] [--max-unpaid-blocks N]
//!                   [--prime-window N] [--prime-window-min-work W] [--window-tolerance-bps N]
//!                   [--prime-fee-bps N] [--prime-min-payout S]
//!                   (`--max-unfunded-per-client` and `--trust-forwarded` are accepted and ignored: AGP-091)
//!                   [--data-dir DIR] [--watch-secs N]
//!
//! AGP-067 (review C4): the channel side keeps its payTo key (`DIR/payto.key`, created 0600 on first
//! start) and its channel ledger (`DIR/channels.jsonl`, locked to one process) in `--data-dir`
//! (`XBT_WORK_DATA_DIR`, default `./xbt-work-provider-data`), and a watcher runs `close_due` every
//! `--watch-secs` (default 5): it closes each channel before its expiry and bumps a stuck close. A
//! restart keeps every channel; before, a new random key and an empty ledger let each buyer refund.
//!
//! §13.1 caps (AGP-043): unaudited credit per invoice and in total, in work units, in sats converted
//! at each epoch's price (without the haircut), or in calls at the `--price` (sats); `off` removes
//! a cap. The provider turns them into work units under the pricing rule in force (AGP-091): with
//! `--work-units N` a cap in calls is that many calls at N units, and a cap in sats is turned into
//! calls at `--price`. Owed carry above `--max-carry-sats`, or growing over `--carry-growth-blocks` audited
//! blocks, stops new credit. AGP-065 (review P5): with no cap flag the provider caps unaudited
//! credit at 100 calls per invoice and 1000 calls in total (900 served since AGP-079's 10% haircut).
//!
//! AGP-079, the shipped defaults (`WorkConfig::shipped`; no flag needed for any of them):
//! * Credit stops being unaudited only as far as the audited coinbases paid for it, at this
//!   provider's price (`WorkProvider::paid_work`). `--cap-skipped` is gone: nothing is forgiven.
//! * Owed carry is capped at the value of 1000 calls (`--max-carry-sats S`, or `off`).
//!   `--carry-growth-blocks` stays off: a share below the Prime's `min-payout` grows as carry for
//!   several blocks at an honest Prime, so only a provider that attests every tip should set it.
//! * The work book is kept in `DIR/work.json` (`--state FILE` moves it, `--state off` keeps it in
//!   memory only: every balance is then lost on restart).
//! * With `--window-url` the audit loop runs 6 blocks deep (`--audit-depth K`, or `off`). Without a
//!   window URL nothing can be audited or paid for: credit stops for good at the total cap, and the
//!   provider says so when it starts.
//!
//! AGP-065 (review P1): the Prime's pool terms are pinned here, never taken from a statement:
//! `--prime-window` (primed `window`, default 8), `--prime-window-min-work` (primed
//! `window-min-work`, default 0; regtest runs need the Prime's floor), `--window-tolerance-bps`
//! (default 500), `--prime-fee-bps` (default 0, the fee the provider prices with) and
//! `--prime-min-payout` (default 546). Every flag also reads an env variable: `XBT_WORK_CAP_INVOICE`,
//! `XBT_WORK_CAP_INVOICE_SATS`, `XBT_WORK_CAP_INVOICE_CALLS`, the same for `_TOTAL`,
//! `XBT_WORK_MAX_CARRY_SATS`, `XBT_WORK_CARRY_GROWTH_BLOCKS`, `XBT_WORK_MAX_UNPAID_BLOCKS`, `XBT_WORK_AUDIT_DEPTH`, `XBT_WORK_NTA=1`,
//! `XBT_WORK_PRIME_WINDOW`, `XBT_WORK_PRIME_WINDOW_MIN_WORK`, `XBT_WORK_WINDOW_TOLERANCE_BPS`,
//! `XBT_WORK_PRIME_FEE_BPS`, `XBT_WORK_PRIME_MIN_PAYOUT`, `XBT_WORK_MAX_UNFUNDED_PER_CLIENT`.
//!
//! The audit walk audits every block (review P4; `xbt_work::walk`). Only a statement the Prime signed
//! for a block gives it a verdict: one the audit runs on, or one it then refuses, which fails and
//! distrusts the Prime whatever the coinbase paid. A block with no such statement (a 404, another
//! block's, another key's, an answer that is no statement) has no verdict and covers nothing,
//! whatever its coinbase paid the identity: anyone who mines a block can pay an address (AGP-091).
//! While credit is unpaid it is counted (AGP-084): the report's `unpaidBlocks` is the run of them.
//! `--max-unpaid-blocks N` stops new credit once the run reaches N, until a block above the run pays
//! the Prime's share of all the unpaid credit, or none is unpaid; it is off unless set, because N
//! depends on how often the Prime's pool finds a block. Only the node stops the walk: a statement
//! the Prime fails to serve leaves the block as one with no statement, the walk goes on, and it asks
//! again (at most once in 64 passes after the first few) until the block is 144 deep. The walk's
//! position is kept in the state, so a provider that was down goes on where it stopped. Before each
//! pass it compares the audited blocks with the node and undoes the audit of any reorged one.
//!
//! Admin (only with --admin; every request needs `Authorization: Bearer <token>`, the token in
//! `DIR/admin.token`, made 0600 on first start, and a loopback peer; the peer alone proves nothing
//! behind a proxy on the same host, AGP-091): `POST /admin/xbt-work/audit` with
//! `{"from": H0, "to": H1, "underpayHeight": H?}` audits every coinbase in [H0, H1] that pays the
//! identity against its signed window statement and returns the verdicts, the carry ledger and,
//! for `underpayHeight`, the fraud proof of the same block audited as if it paid 1 sat. Blocks that pay
//! the identity nothing are audited too when the Prime published a statement for them (a block that
//! carried the provider's share). `{"withoutDeferrals": H}` adds the control: block H audited as if its
//! deferral lines were missing (not recorded). `GET /admin/xbt-work/report`: the audit log, the carry
//! ledger, the credit exposure (unaudited, held, paid for, caps, frozen), the pinned Prime terms, and
//! the audited payouts split into liquid and locked by the node's coinbase maturity.
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::funding::ChainBackend;
use xbt402::http::{serve_service, HttpService, UreqTransport};
use xbt402::ledger::Ledger;
use xbt402::provider::{load_or_create_secret, HttpResponse, Provider, ProviderConfig, PEER_HEADER};
use xbt402::rpc::Rpc;
use xbt_work::audit::{audit_block, check_fraud_proof};
use xbt_work::chain::ChainBlock;
use xbt_work::guard;
use xbt_work::pricing::Pricing;
use xbt_work::provider::{admin_request, admin_token, Amount, Cap, Caps, ServedStatement, Statement, WorkConfig, WorkProvider, WorkScheme, SETTLE_DEPTH,
                         SHIPPED_AUDIT_DEPTH, SHIPPED_HAIRCUT_BPS};
use xbt_work::tools::{arg, block_count, block_hash, chain_block, epoch, flag, maturity, network, opt, prime_terms, rpc, window};
use xbt_work::walk::{AuditSource, Walk};

fn num<T: std::str::FromStr>(flag: &str, var: &str) -> Option<T> {
    opt(flag, var).map(|v| v.parse().unwrap_or_else(|_| panic!("{flag} / {var}: not a number: {v}")))
}

/// `--flag N` or `--flag off` (or the env variable): Some(None) for `off`, None when not given.
fn num_or_off<T: std::str::FromStr>(flag: &str, var: &str) -> Option<Option<T>> {
    opt(flag, var).map(|v| if v == "off" { None } else { Some(v.parse().unwrap_or_else(|_| panic!("{flag} / {var}: not a number or off: {v}"))) })
}

/// `--cap-<name>[-sats|-calls]` (or the env variables), else `default`.
fn cap_from_args(name: &str, default: Cap) -> Cap {
    let var = format!("XBT_WORK_CAP_{}", name.to_uppercase());
    for (suffix, mk) in [("", Cap::Work as fn(u64) -> Cap), ("-sats", Cap::Sats), ("-calls", Cap::Calls)] {
        let (f, v) = (format!("--cap-{name}{suffix}"), format!("{var}{}", suffix.replace('-', "_").to_uppercase()));
        if let Some(s) = opt(&f, &v) {
            return if s == "off" { Cap::Off } else { mk(s.parse().unwrap_or_else(|_| panic!("{f} / {v}: not a number or off: {s}"))) };
        }
    }
    default
}

struct Service {
    prov: Arc<Provider>,
    work: Arc<WorkProvider>,
    rpc: Rpc,
    window_url: Option<String>,
    /// The admin token (`--admin`): None, and the admin endpoints do not exist.
    admin: Option<String>,
}

/// The audit walk's view of the chain and the Prime: this provider's node and `--window-url`.
struct Source<'a> {
    svc: &'a Service,
    t: &'a UreqTransport,
    window_url: &'a str,
}

impl AuditSource for Source<'_> {
    fn block(&self, height: u32) -> xbt_work::Result<ChainBlock> {
        chain_block(&self.svc.rpc, height, self.svc.identity())
    }

    fn statement(&self, height: u32) -> xbt_work::Result<Option<ServedStatement>> {
        window(self.t, self.window_url, height)
    }

    fn hash_at(&self, height: u32) -> xbt_work::Result<Option<String>> {
        self.svc.hash_at(height)
    }
}

impl Service {
    fn identity(&self) -> &str {
        &self.work.cfg.identity
    }

    /// The hash of the block the node has at `height` now; None above its tip.
    fn hash_at(&self, height: u32) -> xbt_work::Result<Option<String>> {
        if height > block_count(&self.rpc)? {
            return Ok(None);
        }
        block_hash(&self.rpc, height).map(Some)
    }

    fn audit(&self, req: &Value) -> xbt_work::Result<Value> {
        let t = UreqTransport::default();
        let wurl = self.window_url.as_deref().ok_or_else(|| xbt_work::WorkError::new("no_window_url", ""))?;
        let tip = block_count(&self.rpc)?;
        // as the walk does before a pass: the audits of blocks that left the chain are undone
        // first (AGP-097; this audit takes any range, the tip included). A reorg after this check
        // is caught where it matters, in `audit_chain_on`.
        self.reorgs(tip)?;
        let h32 = |v: &Value| v.as_u64().and_then(|x| u32::try_from(x).ok());
        let from = h32(&req["from"]).unwrap_or(1);
        let to = h32(&req["to"]).unwrap_or(tip).min(tip);
        // pull the latest receipts first so the book's intervals are as tight as they can be
        let _ = self.work.refresh(&t);
        let mut results = vec![];
        for h in from..=to {
            let block = chain_block(&self.rpc, h, self.identity())?;
            let stmt = window(&t, wurl, h)?;
            let found = match &stmt {
                Some((sw, def, _)) => Statement::Found(sw, def),
                None => Statement::Missing,
            };
            match self.work.audit_chain_on(&block, found, &|h| self.hash_at(h)) {
                Ok(None) => {}
                Ok(Some(o)) => {
                    let mut r = json!({"height": h, "ok": o.ok, "blockHash": block.hash, "coinbaseValueSats": block.value_sats,
                                       "paidSats": block.paid_sats, "expectedSats": o.expected_sats, "deferredSats": o.deferred_sats,
                                       "belowMinSats": o.below_min_sats, "provenWork": o.proven_work, "windowWork": o.window_work,
                                       "bounded": o.bounded, "proof": o.proof});
                    match &stmt {
                        Some((sw, _, _)) => r["windowStart"] = sw.stmt.window_start.into(),
                        None => r["error"] = "no window statement".into(),
                    }
                    results.push(r);
                }
                Err(e) => results.push(json!({"height": h, "ok": false, "error": e.to_string()})),
            }
        }
        let (unaudited, held) = self.work.exposure();
        let mut out = json!({"identity": self.identity(), "results": results, "carry": self.work.carry().to_json(),
                             "credit": {"unauditedWork": unaudited, "heldWork": held},
                             "ok": results.iter().all(|r| r["ok"] == json!(true)) && !results.is_empty()});
        // the controls: the same block as if it paid 1 sat (the provider's own bound convicts it),
        // and with its deferral lines left out; neither is recorded
        let control = |h: u32, paid: Option<u64>, lines: bool| -> xbt_work::Result<Option<Value>> {
            let block = chain_block(&self.rpc, h, self.identity())?;
            let Some((sw, def, _)) = window(&t, wurl, h)? else { return Ok(None) };
            let b = ChainBlock { paid_sats: paid.unwrap_or(block.paid_sats), ..block };
            let bounds = self.work.bounds(&b)?;
            let o = audit_block(&self.work.book(), &sw, &b, &bounds, if lines { &def } else { &[] })?;
            let checks = o.proof.as_ref().is_some_and(|p| check_fraud_proof(p, self.work.prime_pubkey(), &b, &bounds));
            Ok(Some(json!({"height": h, "ok": o.ok, "expectedSats": o.expected_sats, "paidSats": b.paid_sats, "proof": o.proof, "proofChecks": checks})))
        };
        if let Some(h) = h32(&req["underpayHeight"]) {
            if let Some(v) = control(h, Some(1), true)? {
                out["underpay"] = v;
            }
        }
        if let Some(h) = h32(&req["withoutDeferrals"]) {
            if let Some(v) = control(h, None, false)? {
                out["withoutDeferrals"] = v;
            }
        }
        Ok(out)
    }

    /// Undo the audits of blocks the node no longer has (a reorg): the lowest height undone.
    fn reorgs(&self, tip: u32) -> xbt_work::Result<Option<u32>> {
        let mut low = None;
        for (h, hash) in self.work.audited_blocks().into_iter().filter(|(h, _)| h.saturating_add(SETTLE_DEPTH) > tip) {
            if h > tip || block_hash(&self.rpc, h)? != hash {
                if let Some(back) = self.work.orphaned(h)? {
                    eprintln!("audit: block {h} ({hash}) left the chain: its audit undone, {back} work units unaudited again");
                    low = Some(low.map_or(h, |l: u32| l.min(h)));
                }
            }
        }
        Ok(low)
    }

    fn report(&self) -> Value {
        let (unaudited, held) = self.work.exposure();
        let mut v = self.work.report();
        v["credit"]["unauditedWork"] = unaudited.into();
        v["credit"]["heldWork"] = held.into();
        // M1: payouts under the node's own coinbase maturity, never a hard-coded depth
        v["payouts"] = match block_count(&self.rpc).and_then(|tip| Ok((tip, maturity(&self.rpc)?))) {
            Ok((tip, m)) => {
                let (liquid, locked) = self.work.payouts(tip, &m);
                json!({"liquidSats": liquid, "lockedSats": locked, "tip": tip, "maturityDepth": m.relay_at(0)})
            }
            Err(e) => json!({"error": e.to_string()}),
        };
        v
    }
}

impl HttpService for Service {
    fn body_limit(&self, path: &str) -> usize {
        self.prov.body_limit(path, None)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        if path.starts_with("/admin/") {
            // the peer address the server set (Host is the client's to choose)
            let peer = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(PEER_HEADER)).map(|(_, v)| v.as_str());
            // the token, not the peer address: behind a same-host proxy every client is loopback (AGP-091)
            let allowed = self.admin.as_deref().is_some_and(|token| admin_request(headers, peer, token));
            if allowed && method == "GET" && path == "/admin/xbt-work/report" {
                let v = self.report();
                return HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], xbt402::json::dumps(&v).into_bytes());
            }
            if !allowed || method != "POST" || path != "/admin/xbt-work/audit" {
                return HttpResponse::new(404, vec![], b"not found".to_vec());
            }
            let req = xbt402::json::parse_slice(body).unwrap_or(json!({}));
            let v = self.audit(&req).unwrap_or_else(|e| json!({"ok": false, "error": e.to_string()}));
            return HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], xbt402::json::dumps(&v).into_bytes());
        }
        if path == "/" || path == "/health" {
            let v = json!({"server": "xbt-work-provider (rust)", "payTo": self.prov.pay_to(), "workIdentity": self.work.cfg.identity,
                           "network": self.prov.cfg.network, "invoices": self.work.invoices().len()});
            return HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], xbt402::json::dumps(&v).into_bytes());
        }
        self.prov.serve(method, path, headers, body, url, None)
    }
}

fn answer(path: &str) -> HttpResponse {
    // a small pool-analytics answer, the same shape as the flagship's
    let v = json!({"window": "7d", "server": "rust", "path": path,
                   "pools": [{"pool": "lazarus", "name": "Lazarus", "blocksThis": 333, "blocksPrev": 288, "shareThis": 0.2546,
                              "sharePrev": 0.1538, "deltaPp": 10.08},
                             {"pool": "other", "name": "Other", "blocksThis": 975, "blocksPrev": 1584, "shareThis": 0.7454,
                              "sharePrev": 0.8462, "deltaPp": -10.08}]});
    HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], xbt402::json::dumps(&v).into_bytes())
}

fn main() {
    let port = arg("--port").expect("--port");
    let node = rpc(&arg("--rpc-port").expect("--rpc-port"), &arg("--cookie").expect("--cookie")).expect("cookie");
    let net = network(&node).expect("network");
    let price: u64 = arg("--price").map(|p| p.parse().expect("price")).unwrap_or(150);
    // what the first price follows from is the node's answer or nothing (AGP-106, `tools::epoch`):
    // before, a subsidy the node did not give was taken for the first block's
    let (bits, subsidy) = epoch(&node).unwrap_or_else(|e| {
        eprintln!("xbt-work-provider: the node's height, bits and subsidy are needed to price a call: {e}");
        std::process::exit(2);
    });
    let mut wcfg = WorkConfig::new(&net, &arg("--identity").expect("--identity"), arg("--prime-id").expect("--prime-id").parse().expect("prime id"),
                                   &arg("--prime-pubkey").expect("--prime-pubkey"), &arg("--receipt-url").expect("--receipt-url"));
    wcfg.terms = prime_terms().unwrap_or_else(|e| {
        eprintln!("xbt-work-provider: {e}");
        std::process::exit(2);
    });
    // AGP-079: the shipped defaults (pricing, caps on unaudited credit and on owed carry), then the flags
    let mut wcfg = wcfg.shipped(bits, subsidy, price);
    wcfg.relay_url = arg("--relay-url");
    wcfg.nta = flag("--nta") || std::env::var("XBT_WORK_NTA").is_ok_and(|v| v == "1");
    // the caps as set; the provider turns them into work units under the pricing rule in force
    // (`--work-units` included), now and at every epoch (AGP-091)
    let caps = Caps { invoice: cap_from_args("invoice", Caps::SHIPPED.invoice), total: cap_from_args("total", Caps::SHIPPED.total) };
    wcfg.cap_rule = Some(caps);
    if ["--cap-skipped", "--cap-skipped-sats", "--cap-skipped-calls"].iter().any(|f| arg(f).is_some())
        || ["XBT_WORK_CAP_SKIPPED", "XBT_WORK_CAP_SKIPPED_SATS", "XBT_WORK_CAP_SKIPPED_CALLS"].iter().any(|v| std::env::var(v).is_ok())
    {
        eprintln!("caps: --cap-skipped is no longer used (AGP-079): no credit is forgiven, it is covered by what the coinbases paid");
    }
    if let Some(m) = num_or_off("--max-carry-sats", "XBT_WORK_MAX_CARRY_SATS") {
        wcfg.max_owed_carry_sats = m;
    }
    wcfg.carry_growth_blocks = num("--carry-growth-blocks", "XBT_WORK_CARRY_GROWTH_BLOCKS");
    wcfg.max_unpaid_blocks = num("--max-unpaid-blocks", "XBT_WORK_MAX_UNPAID_BLOCKS");
    if flag("--trust-forwarded") || opt("--max-unfunded-per-client", "XBT_WORK_MAX_UNFUNDED_PER_CLIENT").is_some() {
        eprintln!("invoices: --trust-forwarded and --max-unfunded-per-client are no longer used (AGP-091): issuing an invoice stores nothing, so there is no limit to set");
    }
    wcfg.amount = match arg("--work-units") {
        Some(n) => Amount::Fixed(n.parse().expect("work units")),
        None => Amount::Priced(Pricing { price_sats: price, bits, block_value_sats: subsidy, fee_bps: wcfg.terms.fee_bps,
                                         haircut_bps: arg("--haircut-bps").map(|h| h.parse().expect("haircut")).unwrap_or(SHIPPED_HAIRCUT_BPS) }),
    };
    let data = std::path::PathBuf::from(opt("--data-dir", "XBT_WORK_DATA_DIR").unwrap_or_else(|| "xbt-work-provider-data".into()));
    let die = |e: xbt402::ChannelError| -> ! {
        eprintln!("xbt-work-provider: {e}");
        std::process::exit(2);
    };
    // the ledger first: its lock keeps a second process off this data dir, key file and work book included
    let ledger = Ledger::open(&data.join("channels.jsonl")).unwrap_or_else(|e| die(e));
    let sk = load_or_create_secret(&data.join("payto.key")).unwrap_or_else(|e| die(e));
    wcfg.state_path = match arg("--state") {
        Some(s) if s == "off" => {
            eprintln!("state: --state off: the work book is in memory only, every balance is lost on restart");
            None
        }
        Some(s) => Some(s.into()),
        None => Some(data.join("work.json")),
    };
    let max_carry = wcfg.max_owed_carry_sats;
    let work = Arc::new(WorkProvider::new(wcfg).unwrap_or_else(|e| {
        eprintln!("xbt-work-provider: {e}");
        std::process::exit(2);
    }));
    eprintln!("caps: {:?} -> {:?} work units at this epoch ({} a call), owed carry at most {max_carry:?} sats; Prime terms {:?}",
              (caps.invoice, caps.total), work.caps(), work.amount(price).unwrap_or(0), work.cfg.terms);
    let chain: Arc<dyn ChainBackend> = Arc::new(node.clone());
    let prov = Arc::new(Provider::new(chain, sk, ProviderConfig::new(&net), ledger,
                                      Box::new(move |_, p| if p.starts_with("/v1/") { price } else { 0 }),
                                      Box::new(|_, p, _| answer(p))).unwrap_or_else(|e| die(e))
        .with_scheme(Arc::new(WorkScheme(work.clone()))));
    // Each of the three loops below runs its rounds through `guard::round` (AGP-097): a panic ends
    // the round, is reported, and the loop goes on.
    let (w, every) = (prov.clone(), num::<u64>("--watch-secs", "XBT_WORK_WATCH_SECS").unwrap_or(5).max(1));
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(every));
        let round = guard::round(|| match w.close_due() {
            Ok(closed) if !closed.is_empty() => eprintln!("watcher: closed {closed:?}"),
            Ok(_) => {}
            Err(e) => eprintln!("watcher: {e}"),
        });
        if let Err(why) = round {
            eprintln!("watcher: a round panicked ({why}); the watcher goes on");
        }
    });
    // pull receipts through the relay, and follow the epoch (§6.3: re-price new 402s)
    let (w2, n2) = (work.clone(), node.clone());
    let pull_secs: u64 = arg("--pull-secs").map(|p| p.parse().expect("pull secs")).unwrap_or(3);
    std::thread::spawn(move || {
        let t = UreqTransport::default();
        // an epoch the node reports and no price follows from: said once, not every round
        let mut refused: Option<(u32, u64)> = None;
        loop {
            let round = guard::round(|| {
                for (inv, r) in if pull_secs > 0 { w2.refresh(&t) } else { vec![] } {
                    match r {
                        Ok(0) => {}
                        Ok(d) => eprintln!("relay: invoice {inv}: +{d} work units credited (verified under the Prime key)"),
                        Err(e) => eprintln!("relay: invoice {inv}: {e}"),
                    }
                }
                // a round in which the node does not give all of it changes no price (AGP-106,
                // `tools::epoch`): the epoch in force stays, and the next round asks again
                if let Ok((b, v)) = epoch(&n2) {
                    if w2.set_epoch(b, v) {
                        refused = None;
                        eprintln!("epoch: bits {b:08x}, block value {v} sats: new 402s quote {} work units", w2.amount(price).unwrap_or(0));
                        if caps.invoice.priced() || caps.total.priced() {
                            let c = w2.caps();
                            eprintln!("caps: per invoice {:?}, total {:?} work units at this epoch", c.per_invoice, c.total);
                        }
                    } else if let (Some(e), true) = (w2.epoch_error(b, v), refused != Some((b, v))) {
                        refused = Some((b, v));
                        eprintln!("epoch: the node reports bits {b:08x}, block value {v} sats, which no price follows from ({e}): the epoch in force stays");
                    }
                }
            });
            if let Err(why) = round {
                eprintln!("relay pull: a round panicked ({why}); the pull goes on");
            }
            std::thread::sleep(Duration::from_secs(pull_secs.clamp(1, 3)));
        }
    });
    let admin = flag("--admin").then(|| {
        let path = data.join("admin.token");
        let token = admin_token(&path).unwrap_or_else(|e| {
            eprintln!("xbt-work-provider: {e}");
            std::process::exit(2);
        });
        eprintln!("admin: on; every request needs `Authorization: Bearer <the token in {}>` and a loopback peer", path.display());
        token
    });
    let svc = Arc::new(Service { prov: prov.clone(), work: work.clone(), rpc: node, window_url: arg("--window-url"), admin });
    // audit every pool block `depth` deep on its own (§10.3: RECOMMENDED k = 6), unless told not to;
    // what a passing block's coinbase paid for covers credit, and held credit follows
    let depth = match (num_or_off::<u32>("--audit-depth", "XBT_WORK_AUDIT_DEPTH"), svc.window_url.is_some()) {
        (Some(d), _) => d,
        (None, true) => Some(SHIPPED_AUDIT_DEPTH),
        (None, false) => None,
    };
    match (depth, svc.window_url.is_some()) {
        (Some(d), true) => eprintln!("audit: every block {d} deep, on its own"),
        (Some(_), false) => eprintln!("audit: --audit-depth without --window-url: NO AUDIT RUNS; credit stops for good at the total cap"),
        (None, true) => eprintln!("audit: off (--audit-depth off): only POST /admin/xbt-work/audit audits; credit stops at the total cap until it does"),
        (None, false) => eprintln!("audit: no --window-url: NO AUDIT RUNS; credit stops for good at the total cap"),
    }
    if let (Some(depth), Some(wurl)) = (depth, svc.window_url.clone()) {
        let s2 = svc.clone();
        // where the walk stopped (kept in the state), and at least the last 100 blocks again;
        // `--audit-from` overrides both
        // a height the node does not give is no height (AGP-106): taken for 0 it started the
        // walk at block 1 whatever position was kept
        let tip = block_count(&s2.rpc).unwrap_or_else(|e| {
            eprintln!("xbt-work-provider: the node's height is needed to start the audit: {e}");
            std::process::exit(2);
        });
        let back = tip.saturating_sub(depth.saturating_add(100)).max(1);
        let start = num::<u32>("--audit-from", "XBT_WORK_AUDIT_FROM").unwrap_or_else(|| s2.work.audit_position().map_or(back, |p| p.min(back)).max(1));
        eprintln!("audit: starting at height {start}");
        let mut walk = Walk::new(start);
        std::thread::spawn(move || {
            let t = UreqTransport::default();
            let src = Source { svc: &s2, t: &t, window_url: &wurl };
            loop {
                let round = guard::round(|| {
                    let Ok(tip) = block_count(&s2.rpc) else { return };
                    match s2.reorgs(tip) {
                        Ok(Some(low)) => walk.rewind(low),
                        Ok(None) => {}
                        Err(e) => eprintln!("audit: reorg check: {e}"),
                    }
                    // an audit the admin audit undid (its block had left the chain): over it again
                    if let Some(low) = s2.work.undone() {
                        walk.rewind(low);
                    }
                    let to = tip.saturating_sub(depth);
                    if to >= walk.next() || !walk.waiting().is_empty() {
                        let _ = s2.work.refresh(&t);
                        let pass = walk.pass(&s2.work, &src, to);
                        for (h, ok) in pass.verdicts {
                            let (u, held) = s2.work.exposure();
                            eprintln!("audit: block {h}: {} (unaudited {u}, held {held} work units, owed carry {} sats)",
                                      if ok { "PASS" } else { "FAIL" }, s2.work.carry().owed());
                        }
                        for (h, why) in pass.unavailable {
                            eprintln!("audit: height {h}: {why}; no statement for now (it covers nothing), asking again");
                        }
                        if let Some((h, why)) = pass.stopped {
                            eprintln!("audit: height {h}: {why}; retrying");
                        }
                    }
                });
                if let Err(why) = round {
                    eprintln!("audit: a round panicked ({why}); the walk goes on from height {}", walk.next());
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        });
    }
    let hs = serve_service(svc, &format!("127.0.0.1:{port}"), 4).expect("bind");
    println!("xbt-work-provider ready on 127.0.0.1:{port} network {net} channel payTo {} work payTo {} amount {} work units / {price} sat",
             prov.pay_to(), work.cfg.identity, work.amount(price).unwrap_or(0));
    for h in hs {
        let _ = h.join();
    }
}
