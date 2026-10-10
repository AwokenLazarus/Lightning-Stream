//! AGP-087 second closure audit, transport area (T4c on the signer's pay rail): tests written by the
//! auditor. A failing test here is a finding, not a regression.
mod common;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::client::Transport;
use xbt402::ledger::Ledger;
use xbt402::provider::HttpResponse;
use xbt_signer::signer::{Signer, SignerOptions};

/// `Web`, as someone between the wallet and the seller. Mode 1: a paid answer loses its
/// PAYMENT-RESPONSE and gets another body. Mode 2: a paid request never reaches the seller; the paid
/// answer before comes back, receipt and all.
struct Between {
    web: Arc<Web>,
    mode: AtomicU8,
    last: std::sync::Mutex<Option<HttpResponse>>,
}

impl Transport for Between {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> xbt402::Result<HttpResponse> {
        let paid = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE"));
        let mode = self.mode.load(Ordering::SeqCst);
        if paid && mode == 2 {
            return Ok(self.last.lock().unwrap().clone().expect("an earlier paid answer"));
        }
        let mut r = self.web.request(method, url, body, headers)?;
        if paid && r.status == 200 {
            *self.last.lock().unwrap() = Some(r.clone());
            if mode == 1 {
                r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("PAYMENT-RESPONSE"));
                r.body = b"a forged answer".to_vec();
            }
        }
        Ok(r)
    }
}

fn rig() -> (tempfile::TempDir, Arc<FakeChain>, Arc<Between>, Arc<Signer>) {
    let dir = tempfile::tempdir().unwrap();
    env_for(dir.path());
    let chain = FakeChain::new("regtest", 6_720);
    let web = Arc::new(Web::default());
    web.sites.lock().unwrap().insert(PROVIDER.into(), runbook_provider(&chain, Ledger::in_memory()));
    let root = root_with(dir.path(), &runbook_policy(json!({})));
    let between = Arc::new(Between { web, mode: AtomicU8::new(0), last: Default::default() });
    let s = Signer::new(&root, SignerOptions { node: Some(chain.clone()), transport: Some(between.clone()), ..Default::default() }).unwrap();
    (dir, chain, between, s)
}

fn pay(s: &Signer) -> Value {
    call(s, "xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 500}))
}

fn open(s: &Signer, chain: &Arc<FakeChain>) {
    let txid = hex::encode([1u8; 32]);
    let spk = call(s, "hot_address", json!({}))["hot_spk"].as_str().unwrap().to_string();
    chain.credit(&txid, 0, 12_000, &spk, true);
    call(s, "notice_hot_txid", json!({"txid": txid}));
    let r = pay(s);
    assert_eq!(r["verdict"], "pending", "{r}");
    chain.mine(1);
    let r = pay(s);
    assert_eq!(r["verdict"], "allow", "{r}");
}

/// T4c on the signer (the wallet MCP's and the signer socket's `xbt402_pay`): the library client
/// and B2 refuse a paid answer that came without its receipt. This rail hands the answer back.
#[test]
fn t4c_the_signer_refuses_a_paid_answer_without_a_receipt() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (_dir, chain, between, s) = rig();
    open(&s, &chain);
    between.mode.store(1, Ordering::SeqCst);
    let r = pay(&s);
    let text = r.to_string();
    assert!(!text.contains("a forged answer"), "the forged body with no receipt came back from xbt402_pay with verdict {}: {text}", r["verdict"]);
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("bad_receipt")), "{r}");
}

/// T4, the receipt's seq: the answer before, replayed with its own receipt, for a new paid request.
#[test]
fn t4_the_signer_refuses_an_earlier_answer_replayed_with_its_receipt() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (_dir, chain, between, s) = rig();
    open(&s, &chain);
    between.mode.store(2, Ordering::SeqCst);
    let r = pay(&s);
    assert!(r.get("receipt_error").is_some() || r["verdict"] == "deny",
            "the signer took the answer before and its receipt for a new paid request, with no error: {r}");
}
