//! AGP-087 second closure audit, transport area (xbt-work rail, T4): tests written by the auditor.
//! A failing test here is a finding, not a regression.
#![allow(dead_code, unused_imports)]
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{Client, ClientConfig, Transport};
use xbt402::error::{ChannelError, Result as XResult};
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json};
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

/// The in-process network: the API origin and the relay.
struct Net {
    api: Mutex<Option<Arc<Provider>>>,
    relay: Mutex<HashMap<String, Vec<u8>>>,
}

#[derive(Clone)]
struct T(Arc<Net>);

impl Transport for T {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> XResult<HttpResponse> {
        if let Some(lk) = url.strip_prefix(&format!("{RELAY}/")) {
            return Ok(match self.0.relay.lock().unwrap().get(lk) {
                Some(b) => HttpResponse::new(200, vec![], b.clone()),
                None => HttpResponse::new(404, vec![], b"not found".to_vec()),
            });
        }
        let path = url.strip_prefix(API).expect("api url");
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
        let net = Arc::new(Net { api: Mutex::new(None), relay: Mutex::new(HashMap::new()) });
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
        let prov = Provider::new(ProviderConfig::default(),
                                 Box::new(|_, _| 150),
                                 Box::new(|_, p, _| if p == "/v1/fail" { HttpResponse::new(503, vec![], b"down".to_vec()) }
                                          else { HttpResponse::new(200, vec![], format!("{{\"answer\": \"{p}\"}}").into_bytes()) }))
            .with_scheme(Arc::new(WorkScheme(self.work.clone())));
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
        Client::new(ClientConfig::new(NET), Box::new(self.t.clone())).with_payer(payer)
    }

    fn payer(&self) -> Arc<WorkPayer> {
        Arc::new(WorkPayer::new(PayerConfig { network: NET.into(), max_amount: 100, pinned_prime: Some(self.prime.pubkey_hex()),
                                              // AGP-091: the payer names its relay; one only the invoice names, on another origin, is refused
                                              relay_url: Some(RELAY.into()), ..Default::default() }).unwrap())
    }

    fn raw(&self, path: &str, hdr: &str) -> (u16, Value) {
        let r = self.t.request("GET", &format!("{API}{path}"), b"", &[("PAYMENT-SIGNATURE".into(), hdr.into())]).unwrap();
        let h = if r.status == 402 { "PAYMENT-REQUIRED" } else { "PAYMENT-RESPONSE" };
        (r.status, unb64json(r.header(h).unwrap()).unwrap())
    }
}


/// `T`, losing the answer to the n-th request to `/v1/...` that carried a payment (1-based): the
/// provider serves and debits it, the payer sees a transport error.
struct Lose(T, Mutex<u32>, u32);

impl Transport for Lose {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> XResult<HttpResponse> {
        let r = self.0.request(method, url, body, headers)?;
        if url.contains("/v1/") && headers.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE") && r.status == 200 {
            let mut n = self.1.lock().unwrap();
            *n += 1;
            if *n == self.2 {
                return Err(ChannelError::new("transport_error", "timed out reading the answer"));
            }
        }
        Ok(r)
    }
}

/// AGP-081 "Noticed, not changed", first bullet, on the work rail: `spentWork` must grow by exactly
/// `charged` from what the payer last saw, and nothing resynchronises it while the provider keeps
/// serving. One lost answer, and every call after it is debited and thrown away.
#[test]
fn t4_one_lost_answer_does_not_cost_the_answers_after_it() {
    let w = World::new(None);
    let payer = w.payer();
    let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    w.credit(&inv, 5, 200, 101, 103);
    let mut client = Client::new(ClientConfig::new(NET), Box::new(Lose(w.t.clone(), Mutex::new(0), 2))).with_payer(payer.clone());
    assert_eq!(client.request("GET", &format!("{API}/v1/pools"), b"").unwrap().status, 200);
    assert_eq!(client.request("GET", &format!("{API}/v1/pools"), b"").unwrap_err().code, "transport_error");
    let mut out = vec![];
    for _ in 0..8 {
        out.push(match client.request("GET", &format!("{API}/v1/pools"), b"") {
            Ok(r) => r.status.to_string(),
            Err(e) => e.code,
        });
    }
    let debited = w.work.balance(&inv).map(|b| b.1).unwrap_or(0);
    let discarded = out.iter().filter(|o| *o != "200").count();
    assert_eq!(discarded, 0, "after ONE lost answer: {out:?}; the provider debited {debited} work units (10 a call), the payer holds answers for {} of them",
               payer.session(API).unwrap().spent);
}
