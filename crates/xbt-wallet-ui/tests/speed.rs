//! 0.2.2: page speed. Each page says what it waited for (`Server-Timing`), a page asks the signer
//! each read once however many of its parts want it, the slow-changing reads serve the next pages
//! for a few seconds, and an action makes the pages ask afresh.
#[path = "../../xbt-signer/tests/common/mod.rs"]
mod common;

use std::time::Duration;

use common::*;
use serde_json::json;
use xbt_signer::approval::policy_message;
use xbt_wallet_ui::config::Config;

const PW: &str = "a long box password";

struct Box_ {
    rig: Rig,
    _sock: xbt_signer::server::Running,
    _srv: xbt_wallet_ui::server::Running,
    base: String,
    data: tempfile::TempDir,
}

fn start(keep: Duration) -> Box_ {
    start_with(keep, |_| {})
}

fn start_with(keep: Duration, tweak: impl FnOnce(&mut Config)) -> Box_ {
    // paying on already: the rules page edits the rules in force
    let rig = Rig::new(json!({"ln": {"enabled": true}}), false);
    let sock_path = rig.dir.path().join("signer.sock");
    let sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_test(sock_path, data.path().join("ui"), "127.0.0.1:0");
    cfg.read_cache = keep;
    tweak(&mut cfg);
    let app = xbt_wallet_ui::app::App::new(cfg).unwrap();
    let srv = xbt_wallet_ui::server::spawn(app).unwrap();
    Box_ { base: format!("http://{}", srv.addr), rig, _sock: sock, _srv: srv, data }
}

/// A logged-in browser: its cookie and agent.
struct B {
    base: String,
    cookie: String,
    agent: ureq::Agent,
}

struct Page {
    status: u16,
    body: String,
    /// (signer calls, signer reads answered from the cache), from `Server-Timing`.
    signer: (u32, u32),
    timing: String,
}

fn signer_of(timing: &str) -> (u32, u32) {
    // signer;dur=1.2;desc="5 calls, 1 cached"
    let d = &timing[timing.find("signer;").expect(timing)..];
    let d = &d[d.find("desc=\"").unwrap() + 6..];
    let d = &d[..d.find('"').unwrap()];
    let n: Vec<u32> = d.split(", ").map(|p| p.split(' ').next().unwrap().parse().unwrap()).collect();
    (n[0], n[1])
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

fn field(html: &str, name: &str) -> String {
    let pat = format!("name=\"{name}\" value=\"");
    let rest = &html[html.find(&pat).unwrap_or_else(|| panic!("no field {name}")) + pat.len()..];
    rest[..rest.find('"').unwrap()].replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

impl B {
    fn login(bx: &Box_) -> Self {
        let mut b = Self { base: bx.base.clone(), cookie: String::new(), agent: ureq::AgentBuilder::new().redirects(0).build() };
        let code = std::fs::read_to_string(bx.data.path().join("ui/setup-code")).unwrap();
        let r = b.send("POST", "/setup-password", Some(&[("code", code.trim()), ("password", PW), ("password2", PW)]));
        assert_eq!(r.status, 303, "{}", r.body);
        b
    }

    fn send(&mut self, method: &str, path: &str, form: Option<&[(&str, &str)]>) -> Page {
        let mut rq = self.agent.request(method, &format!("{}{path}", self.base));
        if !self.cookie.is_empty() {
            rq = rq.set("Cookie", &self.cookie);
        }
        let resp = match form {
            Some(f) => rq.set("Content-Type", "application/x-www-form-urlencoded")
                .send_string(&f.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")),
            None => rq.call(),
        };
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => panic!("{method} {path}: {e}"),
        };
        if let Some(c) = resp.header("set-cookie") {
            self.cookie = c.split(';').next().unwrap().to_string();
        }
        let timing = resp.header("server-timing").unwrap_or("").to_string();
        Page { status: resp.status(), signer: if timing.is_empty() { (0, 0) } else { signer_of(&timing) }, timing, body: resp.into_string().unwrap_or_default() }
    }

    fn get(&mut self, path: &str) -> Page {
        self.send("GET", path, None)
    }
}

#[test]
fn a_page_asks_the_signer_each_read_once_and_says_what_it_waited_for() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    // no keeping across requests: what one page asks, alone
    let bx = start(Duration::ZERO);
    let mut br = B::login(&bx);
    let mut over = vec![];
    // Home reads the rules for its Get started list, and Wallet the node for its Lightning card (0.2.3): one read each
    for (path, most) in [("/", 4), ("/wallet", 6), ("/policy", 5), ("/lightning", 3), ("/setup", 5), ("/connections", 2), ("/browse", 1)] {
        let p = br.get(path);
        assert_eq!(p.status, 200, "{path}");
        eprintln!("{path}: {}", p.timing);
        assert!(p.timing.starts_with("app;dur=") && p.timing.contains("upstream;dur="), "{path}: {}", p.timing);
        // the menu's badge and the page both read the approvals, the node's state is read by several parts: once each
        if p.signer.0 > most {
            over.push(format!("{path} asked the signer {} times (at most {most}): {}", p.signer.0, p.timing));
        }
        let again = br.get(path);
        assert_eq!(again.signer, p.signer, "{path}: without keeping, each page asks for itself");
    }
    assert!(over.is_empty(), "{over:#?}");
    // the wallet page's approvals are the menu badge's
    assert!(br.get("/wallet").signer.1 >= 1);
    // the home page reads the node's state twice and the keys once: the second read of the node is the first's
    assert!(br.get("/").signer.1 >= 1);
}

#[test]
fn slow_changing_reads_serve_the_next_pages_and_an_action_asks_afresh() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(Duration::from_secs(30));
    let mut br = B::login(&bx);
    let first = br.get("/policy");
    let second = br.get("/policy");
    assert!(second.signer.0 < first.signer.0, "the second render is served from the cache: {:?} then {:?}", first.signer, second.signer);
    assert!(second.signer.1 > first.signer.1);
    assert!(first.body.contains("name=\"f_human_threshold_sats\" value=\"1000\""));

    // a signed rule change through the app: the rules page shows it at once, with no wait for the cache
    let csrf = field(&first.body, "csrf");
    let mut p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    p["human_threshold_sats"] = 5000.into();
    let prev = br.send("POST", "/policy", Some(&[("csrf", &csrf), ("mode", "json"), ("json", &p.to_string())])).body;
    let (text, sha, exp) = (field(&prev, "text"), field(&prev, "prev_sha256"), field(&prev, "expiry"));
    let sig = sign_human(&policy_message(&sha, exp.parse().unwrap(), &text));
    let r = br.send("POST", "/policy-apply", Some(&[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp), ("signature", &sig)]));
    assert_eq!(r.status, 303, "{}", r.body);
    assert_eq!(bx.rig.s.config().human_threshold_sats, 5000);
    let after = br.get("/policy");
    assert!(after.body.contains("name=\"f_human_threshold_sats\" value=\"5000\""), "the page after an action is fresh");
    assert_eq!(after.signer.0, first.signer.0, "an action forgets what was kept: {:?}", after.signer);

    // a POST of any kind does too
    br.get("/policy");
    let csrf = field(&br.get("/signatures").body, "csrf");
    br.send("POST", "/anchor-now", Some(&[("csrf", &csrf)]));
    assert_eq!(br.get("/policy").signer.0, first.signer.0);
}

/// A hashtaker's control API that answers each request on its own thread after `delay(path)`, and
/// counts the requests by path.
fn slow_renter(delay: fn(&str) -> u64) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let seen = s2.clone();
            std::thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let mut it = line.split_whitespace();
                let (m, p) = (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string());
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    let h = h.trim_end().to_string();
                    if h.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap();
                        }
                    }
                }
                let mut body = vec![0u8; len];
                r.read_exact(&mut body).unwrap();
                seen.lock().unwrap().push(format!("{m} {p}"));
                std::thread::sleep(Duration::from_millis(delay(&p)));
                let v = match (m.as_str(), p.as_str()) {
                    ("GET", "/status") => json!({"datum": {"reachable": true, "addr": "datum:23334"}, "blinding": {"state": "blinded", "why": "pool"}, "rentals": []}),
                    ("GET", "/offers") => json!({"offers": [{"name": "Garage miners", "linkKey": "02dd", "priceMsat": 40000, "sliceWork": "140737488355328",
                                                             "miners": 1, "freeMiners": 1, "freeHs": "4000000000000"}]}),
                    _ => json!({"ok": true}),
                }.to_string();
                let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{v}", v.len());
            });
        }
    });
    (base, seen)
}

/// The Hashrate page asks the renter for its rentals and its offers at once, and keeps the offers
/// (gathered from Nostr: seconds when the renter's own copy is old) for the next visits; renting or
/// cutting asks for them afresh. On 0.2.1 the page waited for the two one after the other, each time.
#[test]
fn the_hashrate_page_asks_status_and_offers_at_once_and_keeps_the_offers() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (renter, seen) = slow_renter(|p| match p { "/status" => 300, "/offers" => 600, _ => 0 });
    let bx = start_with(Duration::from_secs(3), |c| c.hash.renter = Some(renter.clone()));
    let mut br = B::login(&bx);
    let offers = || seen.lock().unwrap().iter().filter(|r| *r == "GET /offers").count();
    let timed = |br: &mut B| {
        let t = std::time::Instant::now();
        let p = br.get("/hashrate");
        assert_eq!(p.status, 200);
        assert!(p.body.contains("Garage miners"), "the offers are shown");
        (t.elapsed(), p)
    };
    // the first visit: both at once, so the slower of the two, not their sum (900 ms)
    let (first, p) = timed(&mut br);
    eprintln!("first /hashrate: {first:?} {}", p.timing);
    assert!(first >= Duration::from_millis(600) && first < Duration::from_millis(850), "{first:?}");
    // the next: the offers kept, only the rentals asked
    let (second, p) = timed(&mut br);
    eprintln!("second /hashrate: {second:?} {}", p.timing);
    assert!(second < Duration::from_millis(550), "{second:?}");
    assert_eq!(offers(), 1);
    // a cut changes which miners are free: the offers are asked afresh
    let csrf = field(&p.body, "csrf");
    let r = br.send("POST", "/hashrate", Some(&[("csrf", &csrf), ("action", "cut"), ("rental", "r1")]));
    assert_eq!(r.status, 303);
    let (third, _) = timed(&mut br);
    assert!(third >= Duration::from_millis(600), "{third:?}");
    assert_eq!(offers(), 2);
}

/// The signer's slow-changing reads serve pages opened seconds apart (0.2.2 kept them 3 s: "2 calls, 0
/// cached" on every page of Mike's Umbrel), and a read-only call a page makes keeps them.
#[test]
fn kept_reads_serve_a_page_opened_seconds_later() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    const { assert!(xbt_wallet_ui::config::DEFAULT_CACHE_S >= 15) };
    assert!(xbt_wallet_ui::link::READS.contains(&"settled_amounts"), "the Wallet page's read of what each payment cost forgets nothing");
    let bx = start(Duration::from_secs(xbt_wallet_ui::config::DEFAULT_CACHE_S));
    let mut br = B::login(&bx);
    let first = br.get("/policy");
    std::thread::sleep(Duration::from_secs(4));
    let later = br.get("/policy");
    assert!(later.signer.1 > 0 && later.signer.0 < first.signer.0, "kept across pages: {:?} then {:?}", first.signer, later.signer);
}

/// The renter's offers are asked once at start, in the background (0.2.2: the first Hashrate page after a
/// start waited 3.7 s for them on Mike's Umbrel): the first visit shows them without that wait.
#[test]
fn the_first_hashrate_page_after_a_start_does_not_wait_for_the_offers() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (renter, seen) = slow_renter(|p| match p { "/status" => 100, "/offers" => 1500, _ => 0 });
    let bx = start_with(Duration::from_secs(20), |c| {
        c.hash.renter = Some(renter.clone());
        c.prefetch = true;
    });
    let mut br = B::login(&bx);
    let offers = || seen.lock().unwrap().iter().filter(|r| *r == "GET /offers").count();
    let t0 = std::time::Instant::now();
    while offers() == 0 && t0.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(offers(), 1, "asked at start");
    std::thread::sleep(Duration::from_millis(1700));
    let t = std::time::Instant::now();
    let p = br.get("/hashrate");
    assert!(p.body.contains("Garage miners"), "the offers are shown");
    assert!(t.elapsed() < Duration::from_millis(900), "the first visit after a start: {:?}", t.elapsed());
    assert_eq!(offers(), 1, "not asked again");
}
