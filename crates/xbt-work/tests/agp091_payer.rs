//! AGP-091, fix wave 4, pay-with-work, the payer: one lost answer costs that answer and no other
//! (the second audit's list 1 item 9, work part), and the payer fetches a receipt only where it said
//! it would or at the provider's own origin (item 17, WORK 8). `agp087_transport.rs` has the audit's
//! own test; the harness below is that file's. The two tests marked FAILED-FIRST were run on the
//! audit's branch (`agp-087`, 5521674) with the lines that read fields the fix added taken out.
#![allow(dead_code, unused_imports)]
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{Client, ClientConfig, Transport, Wallet};
use xbt402::error::{ChannelError, Result as XResult};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json};
use xbt_primitives::secp256k1::SecretKey;
use xbt_work::audit::{check_fraud_proof, AuditBounds, Deferral, PrimeTerms, SignedWindow, WindowStatement};
use xbt_work::book::CreditCaps;
use xbt_work::chain::ChainBlock;
use xbt_work::payer::{PayerConfig, WorkPayer};
use xbt_work::provider::{Amount, WorkConfig, WorkProvider, WorkScheme};
use xbt_work::receipt::{PrimeKey, WorkReceipt};
use xbt_work::relay;

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const API: &str = "http://api.test";
const RELAY: &str = "http://relay.test";
/// The statements below have window_work 1000: the Prime's regtest floor.
const TERMS: PrimeTerms = PrimeTerms { window: 8, window_min_work: 1000, window_tolerance_bps: 500, fee_bps: 0, max_min_payout: 546 };

/// The block a statement names, as the provider's node would have it (regtest difficulty).
fn blk(sw: &SignedWindow, value_sats: u64, paid_sats: u64) -> ChainBlock {
    ChainBlock { height: sw.stmt.height, hash: sw.stmt.block_hash.clone(), value_sats, paid_sats, bits: 0x207f_ffff, prev_bits: 0x207f_ffff }
}

fn bounds(sw: &SignedWindow) -> AuditBounds {
    TERMS.bounds(&blk(sw, 0, 0)).unwrap()
}

struct Chain;

impl ChainBackend for Chain {
    fn block_count(&self) -> XResult<u32> {
        Ok(200)
    }
    fn get_tx_out(&self, _: &str, _: u32, _: bool) -> XResult<Option<UtxoInfo>> {
        Ok(None)
    }
    fn send_raw_transaction(&self, _: &str) -> XResult<String> {
        Err(ChannelError::code("no"))
    }
    fn has_transaction(&self, _: &str) -> XResult<bool> {
        Ok(false)
    }
}

struct NoWallet;

impl Wallet for NoWallet {
    fn fund(&self, _: &str, _: u64) -> XResult<(String, u32)> {
        Err(ChannelError::new("no_wallet", "this payer mines, it never funds a channel"))
    }
}

/// The in-process network: the API origin and the relay.
struct Net {
    api: Mutex<Option<Arc<Provider>>>,
    relay: Mutex<HashMap<String, Vec<u8>>>,
    /// Every URL requested that is not on the API origin.
    elsewhere: Mutex<Vec<String>>,
}

#[derive(Clone)]
struct T(Arc<Net>);

impl Transport for T {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> XResult<HttpResponse> {
        if !url.starts_with(&format!("{API}/")) {
            self.0.elsewhere.lock().unwrap().push(url.to_string());
        }
        if let Some(lk) = url.strip_prefix(&format!("{RELAY}/")).or_else(|| url.strip_prefix(&format!("{API}/relay/"))) {
            return Ok(match self.0.relay.lock().unwrap().get(lk) {
                Some(b) => HttpResponse::new(200, vec![], b.clone()),
                None => HttpResponse::new(404, vec![], b"not found".to_vec()),
            });
        }
        let Some(path) = url.strip_prefix(API) else { return Ok(HttpResponse::new(404, vec![], b"not found".to_vec())) };
        let p = self.0.api.lock().unwrap().clone().expect("provider");
        Ok(p.serve(method, path, headers, body, url, None))
    }
}

struct World {
    t: T,
    prime: PrimeKey,
    work: Arc<WorkProvider>,
}

impl World {
    fn new(state: Option<std::path::PathBuf>) -> Self {
        Self::new_with(state, |_| {})
    }

    fn new_with(state: Option<std::path::PathBuf>, f: impl FnOnce(&mut WorkConfig)) -> Self {
        let prime = PrimeKey::from_seed(70, &[9u8; 32]);
        let net = Arc::new(Net { api: Mutex::new(None), relay: Mutex::new(HashMap::new()), elsewhere: Mutex::new(vec![]) });
        let mut cfg = WorkConfig::new(NET, &PROV.to_uppercase(), 70, &format!("{}{}", prime.pubkey_hex(), "ab".repeat(32)), "http://prime.test/receipt");
        cfg.relay_url = Some(RELAY.into());
        cfg.amount = Amount::Fixed(10);
        cfg.state_path = state;
        cfg.terms = TERMS;
        f(&mut cfg);
        let work = Arc::new(WorkProvider::new(cfg).unwrap());
        let w = World { t: T(net), prime, work };
        w.install();
        w
    }

    fn install(&self) {
        let prov = Provider::new(Arc::new(Chain), SecretKey::from_slice(&[5u8; 32]).unwrap(), ProviderConfig::new(NET), Ledger::in_memory(),
                                 Box::new(|_, _| 150),
                                 Box::new(|_, p, _| if p == "/v1/fail" { HttpResponse::new(503, vec![], b"down".to_vec()) }
                                          else { HttpResponse::new(200, vec![], format!("{{\"answer\": \"{p}\"}}").into_bytes()) }))
            .unwrap().with_scheme(Arc::new(WorkScheme(self.work.clone())));
        *self.t.0.api.lock().unwrap() = Some(Arc::new(prov));
    }

    /// The Prime credits the invoice and pushes the blinded receipt.
    fn credit(&self, inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
        let r = WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) };
        let doc = self.prime.sign(&r).unwrap().to_doc();
        let blob = relay::seal(xbt402::json::dumps(&doc).as_bytes(), PROV, inv, None).unwrap();
        self.t.0.relay.lock().unwrap().insert(relay::lookup(PROV, inv), blob);
        r
    }

    fn client(&self, payer: Arc<WorkPayer>) -> Client {
        Client::new(ClientConfig::new(NET), Box::new(self.t.clone()), Box::new(NoWallet), Box::new(|| Ok(200))).with_payer(payer)
    }

    fn payer_with(&self, f: impl FnOnce(&mut PayerConfig)) -> Arc<WorkPayer> {
        let mut cfg = PayerConfig { network: NET.into(), max_amount: 100, pinned_prime: Some(self.prime.pubkey_hex()), ..Default::default() };
        f(&mut cfg);
        Arc::new(WorkPayer::new(cfg).unwrap())
    }

    fn payer(&self) -> Arc<WorkPayer> {
        Arc::new(WorkPayer::new(PayerConfig { network: NET.into(), max_amount: 100, pinned_prime: Some(self.prime.pubkey_hex()), relay_url: Some(RELAY.into()), ..Default::default() }).unwrap())
    }

    fn raw(&self, path: &str, hdr: &str) -> (u16, Value) {
        let r = self.t.request("GET", &format!("{API}{path}"), b"", &[("PAYMENT-SIGNATURE".into(), hdr.into())]).unwrap();
        let h = if r.status == 402 { "PAYMENT-REQUIRED" } else { "PAYMENT-RESPONSE" };
        (r.status, unb64json(r.header(h).unwrap()).unwrap())
    }
}



/// `T`, losing the answers to the paid requests whose 1-based numbers are listed: the provider
/// serves and debits them, the payer sees a transport error.
struct Lose(T, Mutex<u32>, Vec<u32>);

impl Transport for Lose {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> XResult<HttpResponse> {
        let r = self.0.request(method, url, body, headers)?;
        if url.contains("/v1/") && headers.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE") && r.status == 200 {
            let mut n = self.1.lock().unwrap();
            *n += 1;
            if self.2.contains(&n) {
                return Err(ChannelError::new("transport_error", "timed out reading the answer"));
            }
        }
        Ok(r)
    }
}

fn outcome(client: &mut Client, path: &str) -> String {
    match client.request("GET", &format!("{API}{path}"), b"") {
        Ok(r) => r.status.to_string(),
        Err(e) => e.code,
    }
}

fn lossy(w: &World, payer: &Arc<WorkPayer>, lost: &[u32]) -> Client {
    Client::new(ClientConfig::new(NET), Box::new(Lose(w.t.clone(), Mutex::new(0), lost.to_vec())), Box::new(NoWallet), Box::new(|| Ok(200))).with_payer(payer.clone())
}

// ------------------------------------------------------------------------------------------------
// Item 9, work part. The rule: a lost answer costs that answer and no other.
// ------------------------------------------------------------------------------------------------

/// FAILED-FIRST. Lost answers in a row, apart, and the very first one: each costs its own call
/// (the provider served and debited it) and nothing after it. The payer's count of what is spent
/// ends equal to the provider's.
#[test]
fn p9_lost_answers_cost_only_themselves() {
    for lost in [vec![2u32], vec![2, 3], vec![1], vec![1, 2, 3, 4], vec![2, 5, 9]] {
        let w = World::new(None);
        let payer = w.payer();
        let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
        w.credit(&inv, 5, 200, 101, 103);
        let mut client = lossy(&w, &payer, &lost);
        let out: Vec<String> = (0..12).map(|_| outcome(&mut client, "/v1/pools")).collect();
        let errors = out.iter().filter(|o| *o != "200").count();
        assert_eq!(errors, lost.len(), "answers lost: {lost:?}; outcomes: {out:?}");
        assert!(out.iter().all(|o| o == "200" || o == "transport_error"), "{lost:?}: {out:?}");
        assert_eq!(w.work.balance(&inv).unwrap().1, 120, "{lost:?}");
        assert_eq!(payer.session(API).unwrap().spent, 120, "{lost:?}: the payer's count is behind the provider's");
        assert!(payer.session(API).unwrap().unanswered.is_empty(), "{lost:?}");
    }
}

/// The same across a restart of the payer: what was sent and not answered is kept with the
/// session. (Reads `Session::unanswered`, which the fix added.)
#[test]
fn p9_a_lost_answer_before_a_restart_of_the_payer() {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp091-payer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("payer.json");
    let w = World::new(None);
    let payer = w.payer_with(|c| { c.relay_url = Some(RELAY.into()); c.state_path = Some(state.clone()); });
    let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    w.credit(&inv, 5, 200, 101, 103);
    let mut client = lossy(&w, &payer, &[2]);
    assert_eq!((outcome(&mut client, "/v1/pools"), outcome(&mut client, "/v1/pools")), ("200".to_string(), "transport_error".to_string()));
    drop(client);
    drop(payer);
    let payer = w.payer_with(|c| { c.relay_url = Some(RELAY.into()); c.state_path = Some(state.clone()); });
    assert_eq!(payer.session(API).unwrap().unanswered.len(), 1);
    let mut client = w.client(payer.clone());
    assert_eq!(outcome(&mut client, "/v1/pools"), "200");
    assert_eq!((payer.session(API).unwrap().spent, w.work.balance(&inv).unwrap().1), (30, 30));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `T`, as someone between payer and provider who rewrites each PAYMENT-RESPONSE.
struct Rewrite(T, Edit, Mutex<u32>);

/// What to do to the n-th PAYMENT-RESPONSE (1-based).
type Edit = Box<dyn Fn(u32, &mut Value) + Send + Sync>;

impl Transport for Rewrite {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> XResult<HttpResponse> {
        let mut r = self.0.request(method, url, body, headers)?;
        if let Some(h) = r.header("PAYMENT-RESPONSE").map(str::to_string) {
            let mut n = self.2.lock().unwrap();
            *n += 1;
            let mut v = unb64json(&h).unwrap();
            (self.1)(*n, &mut v);
            for (k, val) in r.headers.iter_mut() {
                if k.eq_ignore_ascii_case("PAYMENT-RESPONSE") {
                    *val = b64json(&v);
                }
            }
        }
        Ok(r)
    }
}

fn rewriting(w: &World, payer: &Arc<WorkPayer>, f: impl Fn(u32, &mut Value) + Send + Sync + 'static) -> Client {
    Client::new(ClientConfig::new(NET), Box::new(Rewrite(w.t.clone(), Box::new(f), Mutex::new(0))), Box::new(NoWallet), Box::new(|| Ok(200))).with_payer(payer.clone())
}

fn add_spent(v: &mut Value, by: u64) {
    let s: u64 = v["extra"]["receipt"]["spentWork"].as_str().unwrap().parse().unwrap();
    v["extra"]["receipt"]["spentWork"] = json!((s + by).to_string());
}

/// The slack is exactly the quotes of the calls still unanswered: with none lost, `spentWork`
/// must still grow by exactly `charged`; with one 10-unit call lost, a claim of 10 more is taken
/// (it is what happened) and 11 more is refused; a claim of less than `charged` is refused.
#[test]
fn p9_the_slack_is_what_was_sent_and_not_answered() {
    let fresh = || {
        let w = World::new(None);
        let payer = w.payer();
        let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
        w.credit(&inv, 5, 200, 101, 103);
        (w, payer)
    };
    // nothing lost: one unit more than charged is refused, as before
    let (w, payer) = fresh();
    let mut client = rewriting(&w, &payer, |n, v| if n == 2 { add_spent(v, 1) });
    assert_eq!((outcome(&mut client, "/v1/a"), outcome(&mut client, "/v1/b")), ("200".to_string(), "bad_receipt".to_string()));
    // nothing lost: less than charged is refused
    let (w, payer) = fresh();
    let mut client = rewriting(&w, &payer, |n, v| if n == 2 { v["extra"]["receipt"]["spentWork"] = json!("15") });
    assert_eq!((outcome(&mut client, "/v1/a"), outcome(&mut client, "/v1/b")), ("200".to_string(), "bad_receipt".to_string()));
    // one call lost for good (never reached the provider): the next answer may claim its quote, not a unit more
    for (extra, want) in [(0u64, "200"), (10, "200"), (11, "bad_receipt"), (1000, "bad_receipt")] {
        let (w, payer) = fresh();
        let mut client = rewriting(&w, &payer, move |n, v| if n == 2 { add_spent(v, extra) });
        assert_eq!(outcome(&mut client, "/v1/a"), "200");
        // a call that is sent and never arrives: the header is made (n is used) and nothing else happens
        payer.header(API, "GET", "/v1/lost", b"").unwrap();
        assert_eq!(outcome(&mut client, "/v1/b"), want, "{extra} units over charged after one 10-unit call went unanswered");
    }
}

/// An earlier answer played again for a later request (the same path, so the request digest
/// matches) is refused: it answers a call that is no longer open.
#[test]
fn p9_an_earlier_answer_played_again_is_refused() {
    let w = World::new(None);
    let payer = w.payer();
    let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    w.credit(&inv, 5, 200, 101, 103);
    let first: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let seen = first.clone();
    let mut client = rewriting(&w, &payer, move |n, v| {
        let mut f = seen.lock().unwrap();
        match (n, f.as_ref()) {
            (1, _) => *f = Some(v.clone()),
            (3, Some(old)) => *v = old.clone(),
            _ => {}
        }
    });
    let out: Vec<String> = (0..4).map(|_| outcome(&mut client, "/v1/pools")).collect();
    assert_eq!(out, ["200", "200", "bad_receipt", "200"], "the third answer was the first one played again");
    assert_eq!((payer.session(API).unwrap().spent, w.work.balance(&inv).unwrap().1), (40, 40));
    // a receipt whose n is no integer, or that names a call never sent
    for bad in [json!("2"), json!(99), json!(-1), json!(null)] {
        let w = World::new(None);
        let payer = w.payer();
        let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
        w.credit(&inv, 5, 200, 101, 103);
        let b = bad.clone();
        let mut client = rewriting(&w, &payer, move |_, v| v["extra"]["receipt"]["n"] = b.clone());
        assert_eq!(outcome(&mut client, "/v1/pools"), "bad_receipt", "n = {bad}");
    }
}

// ------------------------------------------------------------------------------------------------
// Item 17, WORK 8. The rule: the payer fetches a receipt only where it said it would, or at the
// provider's own origin.
// ------------------------------------------------------------------------------------------------

/// A provider that answers the invoice request with whatever document it likes.
struct Hostile(T, Value);

impl Transport for Hostile {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> XResult<HttpResponse> {
        if method == "POST" && url.ends_with("/x402/xbt-work/invoice") {
            let real = self.0.request(method, url, body, headers)?;
            let mut doc: Value = serde_json::from_slice(&real.body).unwrap();
            for (k, v) in self.1.as_object().unwrap() {
                doc[k] = v.clone();
            }
            return Ok(HttpResponse::new(200, vec![], serde_json::to_vec(&doc).unwrap()));
        }
        self.0.request(method, url, body, headers)
    }
}

/// FAILED-FIRST (run with the default `PayerConfig` on the audit's branch, the relay and the
/// receipt query on other origins were both fetched). A payer that named no relay and no receipt
/// URL of its own sends nothing to an origin only the invoice names: refused before any request.
#[test]
fn p17_a_url_only_the_invoice_names_on_another_origin_is_not_fetched() {
    // the provider's invoice names a relay on another origin (relay.test)
    let w = World::new(None);
    let payer = w.payer_with(|_| {});
    payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap();
    assert_eq!(payer.refresh(&w.t, API).unwrap_err().code, "provider_url");
    // no relay: the invoice's receiptUrl is the Prime's, on prime.test
    let w2 = World::new_with(None, |c| c.relay_url = None);
    let payer2 = w2.payer_with(|_| {});
    payer2.prepare(&w2.t, &format!("{API}/v1/pools")).unwrap();
    assert_eq!(payer2.refresh(&w2.t, API).unwrap_err().code, "provider_url");
    for net in [&w.t.0, &w2.t.0] {
        assert_eq!(*net.elsewhere.lock().unwrap(), Vec::<String>::new(), "the payer sent a request where the provider told it to");
    }
    // and a paid call says so instead of fetching
    let mut client = w.client(payer);
    assert_eq!(client.request("GET", &format!("{API}/v1/pools"), b"").unwrap_err().code, "provider_url");
    assert!(w.t.0.elsewhere.lock().unwrap().is_empty());
}

/// Every shape of URL a hostile provider can put in the invoice: none is requested.
#[test]
fn p17_no_hostile_url_in_the_invoice_is_requested() {
    for (field, url) in [("relayUrl", "http://169.254.169.254/latest/meta-data"), ("receiptUrl", "http://127.0.0.1:8332/"),
                         ("relayUrl", "http://api.test@evil.test"), ("relayUrl", "http://api.test.evil.test"), ("relayUrl", "http://api.testevil"),
                         ("receiptUrl", "http://api.test:8080/receipt?a=1"), ("receiptUrl", "https://api.test/receipt"), ("receiptUrl", "file:///etc/passwd"),
                         ("receiptUrl", "//evil.test/receipt"), ("receiptUrl", "/x402/receipt"), ("relayUrl", "http://evil.test/#http://api.test/"),
                         ("relayUrl", "http://api.test\\@evil.test/"), ("relayUrl", "http://evil.test?http://api.test/"), ("receiptUrl", "gopher://api.test/"),
                         ("relayUrl", " http://evil.test"), ("relayUrl", "HTTP://EVIL.TEST"), ("receiptUrl", "")] {
        let w = World::new_with(None, |c| c.relay_url = None);
        let hostile = Hostile(w.t.clone(), json!({field: url}));
        let payer = w.payer_with(|_| {});
        payer.prepare(&hostile, &format!("{API}/v1/pools")).unwrap();
        // with relayUrl hostile, the receiptUrl is not a fallback either
        let e = payer.refresh(&hostile, API).unwrap_err();
        assert_eq!(e.code, "provider_url", "{field} = {url:?}: {e}");
        assert!(w.t.0.elsewhere.lock().unwrap().is_empty(), "{field} = {url:?} was requested: {:?}", w.t.0.elsewhere.lock().unwrap());
    }
}

/// Where the payer does fetch: its own relay (before the invoice's, which no longer wins), its own
/// receipt query (the payer writes the query string), the provider's own origin, and an origin the
/// payer allowed.
#[test]
fn p17_the_payer_fetches_where_it_said_or_at_the_providers_origin() {
    // its own relay, though the invoice names another one
    let w = World::new(None);
    let hostile = Hostile(w.t.clone(), json!({"relayUrl": "http://evil.test"}));
    let payer = w.payer();
    let inv = payer.prepare(&hostile, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    w.credit(&inv, 5, 200, 101, 103);
    assert_eq!(payer.refresh(&hostile, API).unwrap().unwrap().receipt.cum_work, 200);
    assert!(w.t.0.elsewhere.lock().unwrap().iter().all(|u| u.starts_with(&format!("{RELAY}/"))), "{:?}", w.t.0.elsewhere.lock().unwrap());

    // its own receipt query: the payer builds the query, whatever the invoice's says
    let w = World::new_with(None, |c| c.relay_url = None);
    let hostile = Hostile(w.t.clone(), json!({"receiptUrl": "http://evil.test/r?identity=x"}));
    let payer = w.payer_with(|c| c.receipt_url = Some("http://prime.test/receipt".into()));
    let inv = payer.prepare(&hostile, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    let _ = payer.refresh(&hostile, API);
    assert_eq!(*w.t.0.elsewhere.lock().unwrap(), vec![format!("http://prime.test/receipt?identity={PROV}&invoice={inv}")]);

    // a relay on the provider's own origin, named only by the invoice
    let w = World::new(None);
    let same = Hostile(w.t.clone(), json!({"relayUrl": format!("{API}/relay")}));
    let payer = w.payer_with(|_| {});
    let inv = payer.prepare(&same, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    w.credit(&inv, 5, 200, 101, 103);
    assert_eq!(payer.refresh(&same, API).unwrap().unwrap().receipt.cum_work, 200);

    // an origin the payer allowed, and only that one
    let w = World::new(None);
    let payer = w.payer_with(|c| c.allow_origins = vec![RELAY.into()]);
    let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    w.credit(&inv, 5, 200, 101, 103);
    assert_eq!(payer.refresh(&w.t, API).unwrap().unwrap().receipt.cum_work, 200);
    let other = w.payer_with(|c| c.allow_origins = vec!["http://relay.test.evil.test".into(), "http://relay.tes".into()]);
    other.prepare(&w.t, &format!("{API}/v1/pools")).unwrap();
    assert_eq!(other.refresh(&w.t, API).unwrap_err().code, "provider_url");
}
