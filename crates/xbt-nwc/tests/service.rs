//! The NWC service against a stand-in signer (a socket that answers `ln_pay`, `ln_lookup`,
//! `ln_status`, `health` and `approval_status` as the signer does, and records each call), and,
//! for the WebSocket flow, against the in-process stand-in relay.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secp256k1::SecretKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xbt_nwc::client::Uri;
use xbt_nwc::event::{tag, Event, Keys, KIND_INFO, KIND_REQUEST, KIND_RESPONSE};
use xbt_nwc::service::{Config, Service};
use xbt_nwc::standin::StandinRelay;
use xbt_nwc::ws::{Msg, WebSocket};
use xbt_signer::bolt11::encode::{invoice, Spec};

const T0: u64 = 1_790_000_000;
const XBT: &[usize] = &[8, 14, 17, 512];
const SHA256_LN: &[usize] = &[8, 14, 17];

/// What the stand-in signer does and saw.
#[derive(Default)]
struct Signer {
    calls: Vec<(String, Value)>,
    preimages: HashMap<String, Vec<u8>>,
    book: HashMap<String, Value>,
    /// The owner's daily budget (sats), as the signer's policy would hold it.
    daily: i64,
    spent: i64,
    human_threshold: i64,
    approval: String,
}

struct StandinSigner {
    st: Arc<Mutex<Signer>>,
    _run: Box<dyn std::any::Any>,
}

fn fee(amount: i64) -> i64 {
    1 + amount / 1000
}

fn signer_answer(st: &Mutex<Signer>, method: &str, p: &Value) -> Value {
    let mut s = st.lock().unwrap();
    s.calls.push((method.to_string(), p.clone()));
    match method {
        "health" => json!({"ok": true, "chain": "regtest"}),
        "ln_status" => json!({"ready": true, "exposure": {"channel_local_sats": 50_000}, "node": {"block_height": 777}}),
        "approval_status" => json!({"state": s.approval}),
        "ln_lookup" => {
            let h = p["payment_hash"].as_str().unwrap_or("");
            s.book.get(h).cloned().map(|mut r| {
                r["found"] = true.into();
                r
            }).unwrap_or(json!({"found": false}))
        }
        "ln_pay" => {
            let inv = xbt_signer::bolt11::decode(p["invoice"].as_str().unwrap()).unwrap();
            let amount = inv.amount_sats_ceil().unwrap() as i64;
            let max = p["max_sats"].as_i64().unwrap();
            let hash = inv.payment_hash_hex();
            if !inv.has_feature(512) {
                return json!({"verdict": "deny", "rule": "ln_feature_512", "reason": "not XBT", "charged_sats": 0});
            }
            if amount + fee(amount) > max {
                return json!({"verdict": "deny", "rule": "max_sats", "reason": format!("invoice {amount} + fee limit is above max_sats {max}"),
                              "charged_sats": 0});
            }
            if s.spent + amount + fee(amount) > s.daily {
                return json!({"verdict": "deny", "rule": "daily_budget", "reason": "daily budget exceeded", "charged_sats": 0});
            }
            if s.human_threshold > 0 && amount >= s.human_threshold && s.approval != "approved" {
                return json!({"verdict": "needs_human", "rule": "human_threshold", "approval_token": "tok-1", "charged_sats": 0});
            }
            let cost = amount + fee(amount);
            s.spent += cost;
            let pre = hex::encode(s.preimages.get(&hash).cloned().unwrap_or_default());
            s.book.insert(hash.clone(), json!({"state": "settled", "spent_sats": cost, "fee_msat": fee(amount) * 1000, "preimage": pre,
                                               "settled_ts": T0 as f64}));
            json!({"verdict": "allow", "status": "SUCCEEDED", "rail": "ln", "payment_hash": hash, "preimage": pre, "charged_sats": cost,
                   "fee_msat": fee(amount) * 1000})
        }
        _ => json!({"verdict": "deny", "rule": "unknown"}),
    }
}

impl StandinSigner {
    fn start(path: &Path) -> Self {
        let st = Arc::new(Mutex::new(Signer { daily: 100_000, approval: "pending".into(), ..Default::default() }));
        let l = xbt_signer::ipc::Listener::bind(path, 0o600).unwrap();
        let st2 = st.clone();
        std::thread::spawn(move || loop {
            let Ok(c) = l.accept() else { return };
            let st = st2.clone();
            std::thread::spawn(move || xbt_signer::anchor::serve_conn(c, |req| {
                Ok(signer_answer(&st, req["method"].as_str().unwrap_or(""), &req["params"]))
            }));
        });
        Self { st, _run: Box::new(()) }
    }

    fn calls(&self, method: &str) -> Vec<Value> {
        self.st.lock().unwrap().calls.iter().filter(|(m, _)| m == method).map(|(_, p)| p.clone()).collect()
    }
}

struct Rig {
    dir: tempfile::TempDir,
    clock: Arc<AtomicU64>,
    signer: StandinSigner,
    svc: Arc<Service>,
}

impl Rig {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(f: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("signer.sock");
        let signer = StandinSigner::start(&sock);
        let clock = Arc::new(AtomicU64::new(T0));
        let c = clock.clone();
        let mut cfg = Config::new(dir.path().join("nwc"), sock);
        cfg.default_relays = vec!["wss://relay.example.com".into()];
        cfg.clock = Some(Arc::new(move || c.load(Ordering::SeqCst)));
        f(&mut cfg);
        let svc = Service::new(cfg).unwrap();
        Self { dir, clock, signer, svc }
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn connect(&self, p: Value) -> (Uri, Value) {
        let r = self.svc.create(&p).unwrap();
        (Uri::parse(r["uri"].as_str().unwrap()).unwrap(), r["connection"].clone())
    }

    /// Send `method` as the app, and read the answer (None: no answer at all).
    fn ask(&self, uri: &Uri, method: &str, params: Value) -> Option<Value> {
        let req = uri.request(method, params, self.now());
        let resp = self.svc.handle(&req)?;
        assert_eq!(resp.kind, KIND_RESPONSE);
        Some(uri.read_response(&resp, &req.id).unwrap())
    }

    /// An invoice for `sats` with these feature bits; its preimage is known to the stand-in signer.
    fn invoice(&self, sats: u64, tag_byte: u8, features: &[usize]) -> (String, String, String) {
        let pre = vec![tag_byte; 32];
        let hash: [u8; 32] = Sha256::digest(&pre).into();
        let key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let inv = invoice(&Spec { hrp: &format!("lnbcrt{}n", sats * 10), timestamp: self.now() - 10, payment_hash: hash, description: Some("tea"),
                                  description_hash: None, expiry_s: Some(3600), features, include_payee: false }, &key);
        self.signer.st.lock().unwrap().preimages.insert(hex::encode(hash), pre.clone());
        (inv, hex::encode(hash), hex::encode(pre))
    }

    fn public(&self, id: &str) -> Value {
        self.svc.list()["connections"].as_array().unwrap().iter().find(|c| c["id"] == id).cloned().unwrap()
    }
}

fn err_code(r: &Value) -> &str {
    r["error"]["code"].as_str().unwrap_or("")
}

#[test]
fn pays_within_the_connection_budget_through_the_signer() {
    let rig = Rig::new();
    let (uri, c) = rig.connect(json!({"name": "phone", "budget_sats_per_day": 1000}));
    assert_eq!(uri.relays, vec!["wss://relay.example.com"]);
    let (inv, hash, pre) = rig.invoice(300, 1, XBT);
    let r = rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap();
    assert_eq!(r["result_type"], "pay_invoice");
    assert!(r["error"].is_null(), "{r}");
    assert_eq!(r["result"]["preimage"], pre);
    assert_eq!(r["result"]["fees_paid"], 1000);
    // the signer was asked once, with the connection's whole remaining budget as its ceiling
    let pays = rig.signer.calls("ln_pay");
    assert_eq!(pays.len(), 1);
    assert_eq!(pays[0]["max_sats"], 1000);
    assert_eq!(pays[0]["invoice"], inv);
    let pc = rig.public(c["id"].as_str().unwrap());
    assert_eq!(pc["spent_24h_sats"], 301);
    assert_eq!(pc["spent_total_sats"], 301);
    assert_eq!(pc["remaining_sats"], 699);
    // an app that asks again gets the same answer, and nothing is paid twice
    let again = rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap();
    assert_eq!(again["result"]["preimage"], pre);
    assert_eq!(rig.signer.calls("ln_pay").len(), 1);
    // lookup and list see it
    let l = rig.ask(&uri, "lookup_invoice", json!({"payment_hash": hash})).unwrap();
    assert_eq!(l["result"]["state"], "settled", "{l}");
    assert_eq!(l["result"]["type"], "outgoing");
    assert_eq!(l["result"]["amount"], 300_000);
    assert_eq!(l["result"]["preimage"], pre);
    let l = rig.ask(&uri, "lookup_invoice", json!({"invoice": inv})).unwrap();
    assert_eq!(l["result"]["payment_hash"], hash);
    let txs = rig.ask(&uri, "list_transactions", json!({})).unwrap();
    assert_eq!(txs["result"]["transactions"].as_array().unwrap().len(), 1);
    assert_eq!(rig.ask(&uri, "list_transactions", json!({"type": "incoming"})).unwrap()["result"]["transactions"], json!([]));
    assert_eq!(err_code(&rig.ask(&uri, "lookup_invoice", json!({"payment_hash": "00".repeat(32)})).unwrap()), "NOT_FOUND");
    // the balance: what is left of the budget (the channels hold more)
    assert_eq!(rig.ask(&uri, "get_balance", json!({})).unwrap()["result"]["balance"], 699_000);
    let info = rig.ask(&uri, "get_info", json!({})).unwrap();
    assert_eq!(info["result"]["network"], "regtest");
    assert_eq!(info["result"]["block_height"], 777);
    assert_eq!(info["result"]["methods"], json!(["pay_invoice", "get_balance", "get_info", "lookup_invoice", "list_transactions"]));
}

#[test]
fn over_the_connection_budget_is_refused_before_the_signer() {
    let rig = Rig::new();
    let (uri, c) = rig.connect(json!({"budget_sats_per_day": 500}));
    let (inv, _, _) = rig.invoice(300, 2, XBT);
    assert!(rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap()["error"].is_null());
    let (inv2, _, _) = rig.invoice(250, 3, XBT);
    let r = rig.ask(&uri, "pay_invoice", json!({"invoice": inv2})).unwrap();
    assert_eq!(err_code(&r), "QUOTA_EXCEEDED", "{r}");
    assert_eq!(rig.signer.calls("ln_pay").len(), 1, "the signer never saw it");
    // within what is left but not with the fee limit: the signer refuses at the ceiling we gave it
    let (inv3, _, _) = rig.invoice(199, 4, XBT);
    let r = rig.ask(&uri, "pay_invoice", json!({"invoice": inv3})).unwrap();
    assert_eq!(err_code(&r), "QUOTA_EXCEEDED", "{r}");
    assert_eq!(rig.signer.calls("ln_pay").last().unwrap()["max_sats"], 199);
    // a refused payment holds nothing of the budget
    assert_eq!(rig.public(c["id"].as_str().unwrap())["remaining_sats"], 199);
    // a day later the budget is whole again
    rig.clock.fetch_add(86_401, Ordering::SeqCst);
    assert_eq!(rig.public(c["id"].as_str().unwrap())["remaining_sats"], 500);
}

#[test]
fn the_owners_policy_still_decides() {
    let rig = Rig::new();
    let (uri, c) = rig.connect(json!({"budget_sats_per_day": 10_000}));
    // the signer's own daily budget is smaller than the connection's
    rig.signer.st.lock().unwrap().daily = 400;
    let (inv, _, _) = rig.invoice(500, 5, XBT);
    let r = rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap();
    assert_eq!(err_code(&r), "QUOTA_EXCEEDED");
    assert!(r["error"]["message"].as_str().unwrap().contains("daily_budget"), "{r}");
    assert_eq!(rig.public(c["id"].as_str().unwrap())["remaining_sats"], 10_000, "the booking is released");
    // the human threshold: the payment waits on the owner's Approvals page
    let mut s = rig.signer.st.lock().unwrap();
    s.daily = 100_000;
    s.human_threshold = 1000;
    drop(s);
    let (inv, _, _) = rig.invoice(2000, 6, XBT);
    let r = rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap();
    assert_eq!(err_code(&r), "QUOTA_EXCEEDED");
    assert!(r["error"]["message"].as_str().unwrap().contains("approval"), "{r}");
    // approved: the same invoice again pays
    rig.signer.st.lock().unwrap().approval = "approved".into();
    assert!(rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap()["error"].is_null());
}

#[test]
fn a_wait_for_the_owners_approval_pays_once_approved() {
    let rig = Rig::with(|c| c.approval_wait = Duration::from_secs(10));
    let (uri, _) = rig.connect(json!({"budget_sats_per_day": 10_000}));
    rig.signer.st.lock().unwrap().human_threshold = 1000;
    let (inv, _, pre) = rig.invoice(2000, 7, XBT);
    let st = rig.signer.st.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(800));
        st.lock().unwrap().approval = "approved".into();
    });
    let r = rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap();
    assert_eq!(r["result"]["preimage"], pre, "{r}");
    assert!(!rig.signer.calls("approval_status").is_empty());
}

#[test]
fn only_xbt_lightning_invoices_with_an_amount() {
    let rig = Rig::new();
    let (uri, _) = rig.connect(json!({"budget_sats_per_day": 10_000}));
    let (inv, _, _) = rig.invoice(100, 8, SHA256_LN);
    let r = rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap();
    assert_eq!(err_code(&r), "OTHER");
    assert!(r["error"]["message"].as_str().unwrap().contains("bit 512"), "{r}");
    assert_eq!(err_code(&rig.ask(&uri, "pay_invoice", json!({"invoice": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzr"})).unwrap()),
               "NOT_IMPLEMENTED");
    assert_eq!(err_code(&rig.ask(&uri, "pay_invoice", json!({"invoice": "lnbcrt1nothing"})).unwrap()), "OTHER");
    let (inv, _, _) = rig.invoice(100, 9, XBT);
    assert_eq!(err_code(&rig.ask(&uri, "pay_invoice", json!({"invoice": inv, "amount": 5})).unwrap()), "OTHER");
    assert!(rig.signer.calls("ln_pay").is_empty());
}

#[test]
fn expired_connections_and_unknown_keys() {
    let rig = Rig::new();
    let (uri, _) = rig.connect(json!({"budget_sats_per_day": 1000, "expires_in_s": 60}));
    assert!(rig.ask(&uri, "get_info", json!({})).unwrap()["error"].is_null());
    rig.clock.fetch_add(61, Ordering::SeqCst);
    let (inv, _, _) = rig.invoice(10, 10, XBT);
    let r = rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap();
    assert_eq!(err_code(&r), "UNAUTHORIZED", "{r}");
    assert!(rig.signer.calls("ln_pay").is_empty());
    // a key that is not the connection's: no answer at all
    let (uri2, _) = rig.connect(json!({"budget_sats_per_day": 1000}));
    let stranger = Uri { secret: Keys::generate(), ..uri2.clone() };
    assert!(rig.ask(&stranger, "get_info", json!({})).is_none());
    // addressed to a service key we do not have
    let nobody = Uri { service_pubkey: Keys::generate().public_hex(), ..uri2.clone() };
    assert!(rig.ask(&nobody, "get_info", json!({})).is_none());
    // a forged signature, a replay, a request past its expiration tag: dropped
    let mut forged = uri2.request("get_info", json!({}), rig.now());
    forged.content.push('A');
    assert!(rig.svc.handle(&forged).is_none());
    let req = uri2.request("get_info", json!({}), rig.now());
    assert!(rig.svc.handle(&req).is_some());
    assert!(rig.svc.handle(&req).is_none(), "the same event twice");
    let mut tags = req.tags.clone();
    tags.push(tag("expiration", &(rig.now() - 1).to_string()));
    let late = Event::sign(&uri2.secret, rig.now(), KIND_REQUEST, tags, req.content.clone());
    assert!(rig.svc.handle(&late).is_none());
    let old = Event::sign(&uri2.secret, rig.now() - 7200, KIND_REQUEST, req.tags.clone(), req.content.clone());
    assert!(rig.svc.handle(&old).is_none());
}

#[test]
fn methods_not_allowed_or_not_offered() {
    let rig = Rig::new();
    let (uri, _) = rig.connect(json!({"budget_sats_per_day": 1000, "methods": ["get_info"]}));
    let (inv, _, _) = rig.invoice(10, 11, XBT);
    assert_eq!(err_code(&rig.ask(&uri, "pay_invoice", json!({"invoice": inv})).unwrap()), "RESTRICTED");
    assert_eq!(err_code(&rig.ask(&uri, "get_balance", json!({})).unwrap()), "RESTRICTED");
    let r = rig.ask(&uri, "make_invoice", json!({"amount": 1000})).unwrap();
    assert_eq!(err_code(&r), "NOT_IMPLEMENTED");
    assert_eq!(r["result_type"], "make_invoice");
    assert_eq!(err_code(&rig.ask(&uri, "pay_keysend", json!({})).unwrap()), "NOT_IMPLEMENTED");
    assert!(rig.signer.calls("ln_pay").is_empty());
    assert_eq!(rig.ask(&uri, "get_info", json!({})).unwrap()["result"]["methods"], json!(["get_info"]));
    // a connection cannot be made with a method this service does not offer
    assert!(rig.svc.create(&json!({"budget_sats_per_day": 1, "methods": ["make_invoice"]})).is_err());
    assert!(rig.svc.create(&json!({"budget_sats_per_day": 0})).is_err());
    assert!(rig.svc.create(&json!({"budget_sats_per_day": 1, "relays": ["ws://relay.example.com"]})).is_err());
}

#[test]
fn nip04_requests_are_answered_unsupported() {
    let rig = Rig::new();
    let (uri, _) = rig.connect(json!({"budget_sats_per_day": 1000}));
    let req = uri.request("get_info", json!({}), rig.now());
    let tags = req.tags.iter().filter(|t| t[0] != "encryption").cloned().collect();
    let nip04 = Event::sign(&uri.secret, rig.now(), KIND_REQUEST, tags, req.content.clone());
    let resp = rig.svc.handle(&nip04).unwrap();
    assert_eq!(err_code(&uri.read_response(&resp, &nip04.id).unwrap()), "UNSUPPORTED_ENCRYPTION");
}

#[test]
fn rate_limited() {
    let rig = Rig::with(|c| c.rate_per_min = 3);
    let (uri, _) = rig.connect(json!({"budget_sats_per_day": 1000}));
    for _ in 0..3 {
        assert!(rig.ask(&uri, "get_info", json!({})).unwrap()["error"].is_null());
    }
    assert_eq!(err_code(&rig.ask(&uri, "get_info", json!({})).unwrap()), "RATE_LIMITED");
    rig.clock.fetch_add(61, Ordering::SeqCst);
    assert!(rig.ask(&uri, "get_info", json!({})).unwrap()["error"].is_null());
}

#[test]
fn revoked_at_once_and_secrets_stay_put() {
    let rig = Rig::new();
    let (uri, c) = rig.connect(json!({"name": "ext", "budget_sats_per_day": 1000}));
    let id = c["id"].as_str().unwrap();
    // the state file is 0600 and holds the service key, never the app's secret
    let state = rig.dir.path().join("nwc").join(xbt_nwc::store::STATE_FILE);
    assert_eq!(xbt_svc::mode_of(&state) & 0o777, 0o600);
    let text = std::fs::read_to_string(&state).unwrap();
    assert!(!text.contains(&uri.secret.secret_hex()));
    assert!(text.contains(&uri.secret.public_hex()));
    // the list (what the UI sees) has no secret at all
    let list = rig.svc.list().to_string();
    assert!(!list.contains("secret"), "{list}");
    assert!(!list.contains(&uri.secret.secret_hex()));
    assert!(rig.ask(&uri, "get_info", json!({})).is_some());
    assert_eq!(rig.svc.revoke(id).unwrap()["revoked"], true);
    assert!(rig.ask(&uri, "get_info", json!({})).is_none(), "a revoked connection gets no answer");
    assert_eq!(rig.svc.list()["connections"], json!([]));
    assert!(rig.svc.revoke(id).is_err());
    // and a restart keeps it gone
    let svc2 = Service::new(Config::new(rig.dir.path().join("nwc"), PathBuf::from("/nonexistent"))).unwrap();
    assert_eq!(svc2.list()["connections"], json!([]));
}

#[test]
fn admin_socket_create_list_revoke() {
    let rig = Rig::new();
    let sock = rig.dir.path().join("admin.sock");
    let _run = xbt_nwc::admin::spawn(rig.svc.clone(), &sock, 0o600).unwrap();
    assert_eq!(xbt_svc::mode_of(&sock) & 0o777, 0o600);
    let c = xbt_signer::client::SignerClient { sock_path: sock.clone(), timeout: Duration::from_secs(5) };
    let made = c.call("nwc_create", json!({"name": "a", "budget_sats_per_day": 50, "methods": ["get_info", "pay_invoice"]})).unwrap();
    assert!(made["uri"].as_str().unwrap().starts_with("nostr+walletconnect://"));
    let list = c.call("nwc_list", json!({})).unwrap();
    assert_eq!(list["connections"][0]["methods"], json!(["pay_invoice", "get_info"]));
    assert!(c.call("nwc_create", json!({"budget_sats_per_day": -1})).is_err());
    assert_eq!(c.call("nwc_revoke", json!({"id": made["connection"]["id"]})).unwrap()["revoked"], true);
    assert_eq!(c.call("nwc_status", json!({})).unwrap()["connections"], 0);
}

/// The whole path: the service on a relay, an app on the same relay, a payment request and its answer.
#[test]
fn over_a_relay() {
    let relay = StandinRelay::start().unwrap();
    let url = relay.url.clone();
    // real time here: the relay's `since` filters use it
    let rig = Rig::with(|c| {
        c.default_relays = vec![url.clone()];
        c.clock = None;
    });
    let (uri, _) = rig.connect(json!({"name": "app", "budget_sats_per_day": 1000}));
    assert_eq!(uri.relays, vec![url.clone()]);
    rig.svc.start();
    // the service subscribes and publishes the connection's info event
    let until = Instant::now() + Duration::from_secs(10);
    while relay.events(KIND_INFO).is_empty() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    let info = relay.events(KIND_INFO);
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].pubkey, uri.service_pubkey);
    assert_eq!(info[0].content, "pay_invoice get_balance get_info lookup_invoice list_transactions");
    assert_eq!(info[0].tag("encryption"), Some("nip44_v2"));
    // the app: listen for responses, then ask
    let mut app = WebSocket::connect(&url, Duration::from_secs(5)).unwrap();
    app.set_read_timeout(Duration::from_millis(50)).unwrap();
    let me = uri.secret.public_hex();
    app.send_text(&json!(["REQ", "r", {"kinds": [KIND_RESPONSE], "#p": [me]}]).to_string()).unwrap();
    let (inv, _, pre) = rig.invoice_now(120, 21);
    let req = uri.request("pay_invoice", json!({"invoice": inv}), xbt_nwc::now());
    app.send_text(&json!(["EVENT", req.to_value()]).to_string()).unwrap();
    let mut answer = None;
    let until = Instant::now() + Duration::from_secs(15);
    while answer.is_none() && Instant::now() < until {
        if let Some(Msg::Text(t)) = app.read().unwrap() {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v[0] == "EVENT" {
                answer = Event::from_value(&v[2]);
            }
        }
    }
    let ev = answer.expect("a response over the relay");
    let body = uri.read_response(&ev, &req.id).unwrap();
    assert_eq!(body["result"]["preimage"], pre, "{body}");
    let st = rig.svc.status();
    assert_eq!(st["relays"][0]["connected"], true, "{st}");
    // revoked: the relay is let go
    let id = rig.svc.list()["connections"][0]["id"].as_str().unwrap().to_string();
    rig.svc.revoke(&id).unwrap();
    assert_eq!(rig.svc.status()["relays"], json!([]));
    rig.svc.stop();
    app.close();
}

impl Rig {
    /// As [`Rig::invoice`], dated by the wall clock.
    fn invoice_now(&self, sats: u64, tag_byte: u8) -> (String, String, String) {
        let pre = vec![tag_byte; 32];
        let hash: [u8; 32] = Sha256::digest(&pre).into();
        let key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let inv = invoice(&Spec { hrp: &format!("lnbcrt{}n", sats * 10), timestamp: xbt_nwc::now() - 10, payment_hash: hash, description: Some("tea"),
                                  description_hash: None, expiry_s: Some(3600), features: XBT, include_payee: false }, &key);
        self.signer.st.lock().unwrap().preimages.insert(hex::encode(hash), pre.clone());
        (inv, hex::encode(hash), hex::encode(pre))
    }
}
