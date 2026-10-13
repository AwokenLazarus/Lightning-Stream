//! The resource server and the payer for schemes ([`Provider`], [`Client`]), in process, with a
//! scheme made for the test: a payer holds a balance of "beans" with a seller and spends one a
//! call. The rules under test are the ones every scheme relies on:
//!
//! * a 402 lists what each scheme asks, in the order they were given, and nothing else;
//! * a payment under a scheme the server does not sell is a 402, and the handler does not run;
//! * the scheme debits before the handler runs and settles after it, with the handler's status;
//! * a request target with a `#` is refused before anything is looked at, on both sides;
//! * the payer takes an answer below 400 to a paid request only with its `PAYMENT-RESPONSE`;
//! * the payer sends a URL to the transport only as its own parser read it.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, CallOpts, Client, ClientConfig, Transport};
use xbt402::provider::{load_or_create_secret, HttpResponse, Provider, ProviderConfig};
use xbt402::scheme::{ProviderScheme, SchemeCharge, SchemePayer};
use xbt402::wire::{b64json, payment_payload, unb64json};
use xbt402::Result;

const NET: &str = "bip122:11111111111111111111111111111111";
const O: &str = "http://seller.test";

/// The selling side: every call costs one bean of the balance it was opened with.
struct Beans {
    name: &'static str,
    left: AtomicU64,
    settled: Mutex<Vec<u16>>,
}

struct Charge(Arc<Beans>);

impl SchemeCharge for Charge {
    fn settle(self: Box<Self>, status: u16) -> Value {
        self.0.settled.lock().unwrap().push(status);
        if status >= 500 {
            // a failed call is not charged
            self.0.left.fetch_add(1, Ordering::SeqCst);
        }
        json!({"success": status < 400, "left": self.0.left.load(Ordering::SeqCst)})
    }
}

struct Selling(Arc<Beans>);

impl ProviderScheme for Selling {
    fn scheme(&self) -> &str {
        self.0.name
    }
    fn requirements(&self, _method: &str, path: &str, price_sats: u64) -> Option<Value> {
        (!path.starts_with("/unlisted")).then(|| json!({"scheme": self.0.name, "network": NET, "amount": price_sats.to_string()}))
    }
    fn control(&self, method: &str, path: &str, _headers: &[(String, String)], _body: &[u8]) -> Option<HttpResponse> {
        (method == "GET" && path == format!("/x402/{}/left", self.0.name))
            .then(|| HttpResponse::new(200, vec![], self.0.left.load(Ordering::SeqCst).to_string().into_bytes()))
    }
    fn authorize(&self, payment: &Value, _method: &str, _path: &str, _body: &[u8], _price_sats: u64, url: &str)
                 -> std::result::Result<Box<dyn SchemeCharge>, Value> {
        let refuse = |error: &str| json!({"x402Version": 2, "error": error, "resource": {"url": url}, "accepts": []});
        if payment["payload"]["word"] != "please" {
            return Err(refuse("bad_word"));
        }
        if self.0.left.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_err() {
            return Err(refuse("no_beans"));
        }
        Ok(Box::new(Charge(self.0.clone())))
    }
}

fn beans(name: &'static str, n: u64) -> Arc<Beans> {
    Arc::new(Beans { name, left: AtomicU64::new(n), settled: Mutex::new(vec![]) })
}

/// A server that sells with `schemes`; what its handler was asked for.
fn server(schemes: &[Arc<Beans>]) -> (Arc<Provider>, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    let mut p = Provider::new(ProviderConfig::default(), Box::new(|_, _| 7), Box::new(move |m, path, _| {
        s2.lock().unwrap().push(format!("{m} {path}"));
        match path {
            "/fail" => HttpResponse::new(503, vec![], b"down".to_vec()),
            "/bad-header" => HttpResponse::new(200, vec![("X-A".into(), "a\r\nX-B: b".into())], b"x".to_vec()),
            _ => HttpResponse::new(200, vec![], b"the answer".to_vec()),
        }
    }));
    for s in schemes {
        p = p.with_scheme(Arc::new(Selling(s.clone())));
    }
    (Arc::new(p), seen)
}

fn pay(scheme: &str, word: &str) -> Vec<(String, String)> {
    vec![("PAYMENT-SIGNATURE".into(), b64json(&payment_payload(&json!({"scheme": scheme, "network": NET}), &json!({"word": word}))))]
}

fn required(r: &HttpResponse) -> Value {
    assert_eq!(r.status, 402, "{}", String::from_utf8_lossy(&r.body));
    let pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&r.body).unwrap(), pr, "the same document in the header and the body");
    pr
}

#[test]
fn a_402_lists_what_each_scheme_asks_in_the_order_given() {
    let (a, b) = (beans("beans", 3), beans("peas", 3));
    let (p, seen) = server(&[a, b]);
    let pr = required(&p.serve("GET", "/v1/q", &[], b"", &format!("{O}/v1/q"), None));
    assert_eq!((pr["x402Version"].as_u64(), pr["error"].as_str(), pr["resource"]["url"].as_str()), (Some(2), Some("payment_required"), Some("http://seller.test/v1/q")));
    let offers: Vec<(&str, &str)> = pr["accepts"].as_array().unwrap().iter().map(|x| (x["scheme"].as_str().unwrap(), x["amount"].as_str().unwrap())).collect();
    assert_eq!(offers, [("beans", "7"), ("peas", "7")], "each scheme's own entry at the server's price, and no other entry");
    // a call a scheme does not offer for is not listed under it
    assert!(required(&p.serve("GET", "/unlisted", &[], b"", "", None))["accepts"].as_array().unwrap().is_empty());
    assert!(seen.lock().unwrap().is_empty(), "the handler never ran unpaid");
}

#[test]
fn a_paid_call_is_debited_served_and_settled_and_a_failed_one_is_given_back() {
    let a = beans("beans", 2);
    let (p, seen) = server(std::slice::from_ref(&a));
    let r = p.serve("GET", "/v1/q", &pay("beans", "please"), b"", &format!("{O}/v1/q"), None);
    assert_eq!((r.status, r.body.as_slice()), (200, b"the answer".as_slice()));
    assert_eq!(unb64json(r.header("PAYMENT-RESPONSE").unwrap()).unwrap(), json!({"success": true, "left": 1}));
    // the handler failed: the scheme is told the status, and gives the bean back
    let r = p.serve("GET", "/fail", &pay("beans", "please"), b"", "", None);
    assert_eq!(r.status, 503);
    assert_eq!(unb64json(r.header("PAYMENT-RESPONSE").unwrap()).unwrap(), json!({"success": false, "left": 1}));
    assert_eq!(*a.settled.lock().unwrap(), [200, 503]);
    assert_eq!(*seen.lock().unwrap(), ["GET /v1/q", "GET /fail"]);
    // a handler's header with a line break never leaves; the call is settled as failed
    let r = p.serve("GET", "/bad-header", &pay("beans", "please"), b"", "", None);
    assert_eq!(r.status, 500);
    assert!(r.headers.iter().all(|(k, v)| !k.contains('\n') && !v.contains('\n')));
    // the scheme's own endpoint is answered by the scheme, before any payment is asked for
    assert_eq!(p.serve("GET", "/x402/beans/left", &[], b"", "", None).body, b"1");
}

#[test]
fn a_payment_the_server_cannot_take_is_a_402_and_the_handler_does_not_run() {
    let a = beans("beans", 1);
    let (p, seen) = server(std::slice::from_ref(&a));
    let url = format!("{O}/v1/q");
    // a scheme this server does not sell (the removed on-chain channel's name among them)
    for other in ["batch-settlement", "xbt-channel", "exact", ""] {
        assert_eq!(required(&p.serve("GET", "/v1/q", &pay(other, "please"), b"", &url, None))["error"], "unsupported_scheme_or_network", "{other}");
    }
    // a header that is not a payment
    for bad in ["not base64", &b64json(&json!({"accepted": "beans", "payload": {}})), &b64json(&json!({"accepted": {"scheme": "beans"}})), &b64json(&json!([1]))] {
        let r = p.serve("GET", "/v1/q", &[("payment-signature".into(), bad.to_string())], b"", &url, None);
        assert_eq!(required(&r)["error"], "bad_payload", "{bad}");
    }
    // the scheme's own refusal is its document, sent as a 402
    assert_eq!(required(&p.serve("GET", "/v1/q", &pay("beans", "now"), b"", &url, None))["error"], "bad_word");
    assert_eq!(p.serve("GET", "/v1/q", &pay("beans", "please"), b"", &url, None).status, 200);
    assert_eq!(required(&p.serve("GET", "/v1/q", &pay("beans", "please"), b"", &url, None))["error"], "no_beans");
    assert_eq!(*seen.lock().unwrap(), ["GET /v1/q"], "the handler ran for the one call that was paid");
}

#[test]
fn a_body_over_the_bound_or_a_target_with_a_fragment_is_refused_before_anything_else() {
    let a = beans("beans", 5);
    let mut cfg = ProviderConfig { max_body: 8, ..Default::default() };
    cfg.route_max_body.insert("/upload".into(), 64);
    let p = Provider::new(cfg, Box::new(|_, _| 1), Box::new(|_, _, _| HttpResponse::new(200, vec![], b"ok".to_vec()))).with_scheme(Arc::new(Selling(a.clone())));
    assert_eq!((p.body_limit("/v1/q", None), p.body_limit("/upload?x=1", None), p.body_limit("/upload", Some(0))), (8, 64, 1));
    assert_eq!(p.serve("POST", "/v1/q", &pay("beans", "please"), &[0; 9], "", None).status, 400);
    assert_eq!(p.serve("POST", "/upload", &pay("beans", "please"), &[0; 9], "", None).status, 200);
    assert_eq!(p.serve("POST", "/upload", &pay("beans", "please"), &[0; 9], "", Some(4)).status, 400);
    for target in ["/v1/q#frag", "/v1/q?a=1#x", "/x402/beans/left#"] {
        let r = p.serve("GET", target, &pay("beans", "please"), b"", "", None);
        assert_eq!((r.status, String::from_utf8_lossy(&r.body).contains('#')), (400, true), "{target}");
    }
    assert_eq!(a.left.load(Ordering::SeqCst), 4, "one call was paid: the refused ones cost nothing");
}

/// The paying side of the test scheme. `ready`: it holds a session with every origin and pays up
/// front; otherwise it pays when a 402 offers its scheme.
struct Paying {
    name: &'static str,
    ready: bool,
    checked: Mutex<Vec<Value>>,
}

impl SchemePayer for Paying {
    fn scheme(&self) -> &str {
        self.name
    }
    fn upfront(&self, _origin: &str, _method: &str, _path: &str, _body: &[u8]) -> Result<Option<Vec<(String, String)>>> {
        Ok(self.ready.then(|| pay(self.name, "please")))
    }
    fn answer(&self, _t: &dyn Transport, _origin: &str, accepted: &Value, _pr: &Value, _method: &str, _path: &str, _body: &[u8]) -> Result<Vec<(String, String)>> {
        assert_eq!(accepted["scheme"], self.name, "handed the entry of its own scheme");
        Ok(pay(self.name, "please"))
    }
    fn check(&self, _origin: &str, resp: &Value, _method: &str, _path: &str, _body: &[u8]) -> Result<()> {
        self.checked.lock().unwrap().push(resp.clone());
        Ok(())
    }
}

/// Every request a client sent: its URL and its headers.
type Sent = Arc<Mutex<Vec<(String, Vec<(String, String)>)>>>;

/// In process to one server, recording every request; `strip`: the PAYMENT-RESPONSE is lost on the way.
struct Local {
    p: Arc<Provider>,
    strip: bool,
    sent: Sent,
}

impl Transport for Local {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        self.sent.lock().unwrap().push((url.to_string(), headers.to_vec()));
        let mut r = self.p.serve(method, &split_url(url).1, headers, body, url, None);
        if self.strip {
            r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("PAYMENT-RESPONSE"));
        }
        Ok(r)
    }
}

fn client(p: &Arc<Provider>, payer: &Arc<Paying>, strip: bool) -> (Client, Sent) {
    let sent: Sent = Arc::default();
    (Client::new(ClientConfig::new(NET), Box::new(Local { p: p.clone(), strip, sent: sent.clone() })).with_payer(payer.clone()), sent)
}

fn paying(name: &'static str, ready: bool) -> Arc<Paying> {
    Arc::new(Paying { name, ready, checked: Mutex::new(vec![]) })
}

#[test]
fn the_payer_answers_a_402_with_its_scheme_and_has_the_receipt_checked() {
    let a = beans("beans", 3);
    let (p, _) = server(&[beans("peas", 1), a.clone()]);
    let payer = paying("beans", false);
    let (mut c, sent) = client(&p, &payer, false);
    let extra = [("X-Embedder".to_string(), "1".to_string())];
    let r = c.request_with("GET", &format!("{O}/v1/q"), b"", &CallOpts::new().headers(&extra)).unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, b"the answer".as_slice()));
    assert_eq!(*payer.checked.lock().unwrap(), [json!({"success": true, "left": 2})]);
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 2, "asked once unpaid, then once paid");
    assert!(sent.iter().all(|(_, h)| h.contains(&extra[0])), "the caller's headers go with every request of the call");
    assert!(sent[0].1.iter().all(|(k, _)| k != "PAYMENT-SIGNATURE") && sent[1].1.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE"));
    // a caller cannot put its own payment header, or a line break, into a call
    for bad in [("PAYMENT-SIGNATURE", "x"), ("payment-signature", "x"), ("", "x"), ("X-A", "a\r\nb"), ("X\nA", "a")] {
        let h = [(bad.0.to_string(), bad.1.to_string())];
        assert_eq!(c.request_with("GET", &format!("{O}/v1/q"), b"", &CallOpts::new().headers(&h)).unwrap_err().code, "bad_header", "{bad:?}");
    }
}

#[test]
fn a_payer_with_a_session_pays_up_front_and_a_402_no_payer_can_answer_is_an_error() {
    let a = beans("beans", 3);
    let (p, seen) = server(std::slice::from_ref(&a));
    let payer = paying("beans", true);
    let (mut c, sent) = client(&p, &payer, false);
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    assert_eq!(sent.lock().unwrap().len(), 1, "one request, paid from the start");
    assert_eq!(payer.checked.lock().unwrap().len(), 1);
    // a seller that offers only what this client does not pay: nothing is sent again, nothing is paid
    let stranger = paying("peas", false);
    let (mut c, sent) = client(&p, &stranger, false);
    let e = c.request("GET", &format!("{O}/v1/q"), b"").unwrap_err();
    assert_eq!(e.code, "no_scheme", "{e}");
    assert_eq!((sent.lock().unwrap().len(), a.left.load(Ordering::SeqCst)), (1, 2));
    // an offer of the payer's scheme on another network is no offer
    let far = Client::new(ClientConfig::new("bip122:22222222222222222222222222222222"), Box::new(Local { p: p.clone(), strip: false, sent: Arc::default() }));
    assert_eq!(far.with_payer(paying("beans", false)).request("GET", &format!("{O}/v1/q"), b"").unwrap_err().code, "no_scheme");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

/// AGP-081, T4c: with the receipt stripped on the way, any body would pass as the paid answer.
#[test]
fn a_paid_answer_below_400_without_its_receipt_is_refused() {
    for ready in [true, false] {
        let a = beans("beans", 3);
        let (p, _) = server(std::slice::from_ref(&a));
        let payer = paying("beans", ready);
        let (mut c, _) = client(&p, &payer, true);
        let e = c.request("GET", &format!("{O}/v1/q"), b"").unwrap_err();
        assert_eq!(e.code, "bad_receipt", "ready={ready}: {e}");
        assert!(payer.checked.lock().unwrap().is_empty());
        // the seller's own failure carries no receipt: it goes back as it is, and nothing is taken from it
        let r = c.request("GET", &format!("{O}/fail"), b"").unwrap();
        assert_eq!(r.status, 503, "ready={ready}");
    }
}

/// AGP-105: a URL two parsers could read as two hosts is refused before anything is sent, whatever
/// the transport, and an accepted one reaches the transport as the one parser read it.
#[test]
fn the_payer_gives_a_transport_only_the_url_its_own_parser_read() {
    let (p, _) = server(&[beans("beans", 1)]);
    let (mut c, sent) = client(&p, &paying("beans", true), false);
    for url in ["http://a.example\\@b.example/v1/q", "http://a.example#@b.example/v1/q", "http://a.example\t@b.example/v1/q", "http:\\\\b.example/v1/q",
                "http://%62.example/v1/q", "http://127.1/v1/q", "http://a.example@b.example@c.example/v1/q", "/v1/q", "http://b.example/v1/q#frag"] {
        assert_eq!(c.request("GET", url, b"").map(|r| r.status).map_err(|e| e.code), Err("bad_request".into()), "{url:?}");
    }
    assert!(sent.lock().unwrap().is_empty(), "a refused URL is not sent: {:?}", sent.lock().unwrap());
    c.request("GET", "HTTP://U@B.Example:80/v1/q?x=1", b"").unwrap();
    assert_eq!(sent.lock().unwrap()[0].0, "http://U@b.example/v1/q?x=1");
}

/// Review C4: a service's signing key is created once, private, and never replaced by a start.
#[test]
fn a_services_key_persists_0600_and_a_loose_or_damaged_file_is_refused() {
    let d = std::env::temp_dir().join(format!("xbt402-key-{}-{:?}", std::process::id(), std::thread::current().id()));
    let _ = std::fs::remove_dir_all(&d);
    let path = d.join("sub").join("service.key");
    let k = load_or_create_secret(&path).unwrap();
    assert_eq!(load_or_create_secret(&path).unwrap(), k, "the same key after a restart");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_or_create_secret(&path).unwrap_err().code, "key_file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&path, "not a key").unwrap();
    assert_eq!(load_or_create_secret(&path).unwrap_err().code, "key_file");
    let _ = std::fs::remove_dir_all(d);
}
