//! AGP-102 fourth closure audit, CLIENT area, through the real signer's code behind its Unix
//! socket: tests written by the auditor against fix wave 5 (AGP-096, AGP-101). No fix is in this
//! file. The rig is `agp101_funded.rs`'s: xbt402's `Client` with a `RemoteSigner`, the signer's
//! own code behind the socket, on the test suite's fake node.
//!
//! `hole_*` tests failed when the audit wrote them and state the rule that should hold.
//! `control_*` tests are the honest path in the same rig and `limit_*` tests pin what a reader
//! must be told; all pass since fix wave 6 and AGP-107 (which made one fixture follow the shipped
//! payers: see `hole_a_payer_that_comes_back_two_days_...`).
//! One test binds 127.0.0.1:27755.
//!
//!   CARGO_TARGET_DIR=$PWD/target cargo test --offline -p xbt-signer --test agp102_signer_client -- --nocapture
mod common;

use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{json, Value};
use xbt402::channel::ChannelParams;
use xbt402::client::{split_url, Client, ClientConfig, Stage, Transport, Wallet};
use xbt402::conditional::ConditionalParams;
use xbt402::provider::HttpResponse;
use xbt402::signer::StateSigner;
use xbt402::ChannelError;
use xbt_primitives::ecdsa::PubkeyBytes;
use xbt_signer::client::RemoteSigner;

struct WebRef(Arc<Web>);

impl Transport for WebRef {
    fn request(&self, m: &str, u: &str, b: &[u8], h: &[(String, String)]) -> xbt402::Result<HttpResponse> {
        self.0.request(m, u, b, h)
    }
}

/// The wallet of the shipped signer-backed payers: the signer's `fund`, then a wait for a
/// confirmation that gives up (`funding_unconfirmed`) for the first `lose` calls.
struct GivesUp {
    remote: RemoteSigner,
    chain: Arc<FakeChain>,
    lose: AtomicUsize,
}

impl Wallet for GivesUp {
    fn fund(&self, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
        self.remote.fund(a, s)
    }

    fn fund_channel(&self, o: &str, p: &ChannelParams, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
        let r = self.remote.fund_channel(o, p, a, s)?;
        if self.lose.load(Ordering::SeqCst) > 0 {
            self.lose.fetch_sub(1, Ordering::SeqCst);
            return Err(ChannelError::new("funding_unconfirmed", "the funding did not confirm in time"));
        }
        self.chain.mine(1);
        Ok(r)
    }
}

/// The signer as a second process reaches it when it asked `xbt402_funded` a moment before the
/// first process attached the channel: `early` is that answer, given once.
struct Seam {
    remote: RemoteSigner,
    early: Mutex<Option<ChannelParams>>,
}

impl StateSigner for Seam {
    fn new_key(&self, o: &str) -> xbt402::Result<PubkeyBytes> {
        self.remote.new_key(o)
    }
    fn attach(&self, o: &str, p: &ChannelParams) -> xbt402::Result<String> {
        self.remote.attach(o, p)
    }
    fn payer_spk(&self) -> xbt402::Result<Option<Vec<u8>>> {
        self.remote.payer_spk()
    }
    fn funded(&self, o: &str) -> xbt402::Result<Option<ChannelParams>> {
        match self.early.lock().unwrap().take() {
            Some(f) => Ok(Some(f)),
            None => self.remote.funded(o),
        }
    }
    fn sign_state(&self, c: &str, a: u64) -> xbt402::Result<Vec<u8>> {
        self.remote.sign_state(c, a)
    }
    fn sign_state_a3(&self, c: &str, a: u64) -> xbt402::Result<Vec<u8>> {
        self.remote.sign_state_a3(c, a)
    }
    fn sign_rollover(&self, c: &str, a: u64, n: &[u8], cap: u64) -> xbt402::Result<Vec<u8>> {
        self.remote.sign_rollover(c, a, n, cap)
    }
    fn sign_close(&self, c: &str) -> xbt402::Result<Vec<u8>> {
        self.remote.sign_close(c)
    }
    fn sign_refund(&self, c: &str) -> xbt402::Result<String> {
        self.remote.sign_refund(c)
    }
    fn request_auth(&self, c: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> xbt402::Result<String> {
        self.remote.request_auth(c, seq, cum, sig, req)
    }
    fn sign_conditional(&self, c: &str, u: u64, cond: &ConditionalParams) -> xbt402::Result<Vec<u8>> {
        self.remote.sign_conditional(c, u, cond)
    }
}

/// A signer with 30,000 sat in its hot key, served on its socket.
struct Sock {
    rig: Rig,
    remote: RemoteSigner,
    _srv: xbt_signer::server::Running,
}

fn sock() -> Sock {
    let rig = Rig::new(json!({"hot_balance_cap_sats": 0}), false);
    rig.fund_hot(1, 30_000);
    let path = rig.dir.path().join("signer.sock");
    let _srv = xbt_signer::server::spawn(rig.s.clone(), &path, false).unwrap();
    Sock { remote: RemoteSigner::new(&path), rig, _srv }
}

impl Sock {
    fn payer(&self, signer: Arc<dyn StateSigner>, lose: usize) -> Client {
        let mut cfg = ClientConfig::new(&self.rig.chain.network());
        (cfg.capacity, cfg.max_price) = (10_000, 500);
        let chain = self.rig.chain.clone();
        let wallet = GivesUp { remote: self.remote.clone(), chain: self.rig.chain.clone(), lose: AtomicUsize::new(lose) };
        Client::new(cfg, Box::new(WebRef(self.rig.web.clone())), Box::new(wallet), Box::new(move || Ok(chain.height() as u32))).with_signer(signer)
    }

    fn remote(&self) -> Arc<dyn StateSigner> {
        Arc::new(self.remote.clone())
    }

    fn fundings(&self) -> usize {
        self.rig.chain.sent_txs().len()
    }

    fn record(&self) -> xbt_signer::channels::ChannelRecord {
        self.rig.s.book.get(PROVIDER).expect("the signer has a channel for the provider")
    }
}

fn get(c: &mut Client) -> Result<u16, String> {
    c.request("GET", URL, b"").map(|r| r.status).map_err(|e| e.code)
}

// --- question a: what adoption checks, and what it does not ---------------------------------------

/// LIMIT (AGP-101, "the budget counts the coins and refuses nothing"; question a). A payer with no
/// record takes up the channel its signer funded for another payer's `fund` call whatever its own
/// settings say: its `budget_sats` (5,000 here) is below the channel (10,000) and it would not
/// have derived that channel itself (`budget`). The signer's policy approved the funding; the
/// adopting payer's own budget, capacity and expiry settings are not applied to it. What IS
/// checked against this call's offer: payTo, close fee and fee payer (the offer must derive the
/// very script), the capacity window, and `max_price` (by `pick`, before the open).
#[test]
fn limit_a_payer_takes_up_a_funded_channel_its_own_budget_would_refuse() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut a = s.payer(s.remote(), 1);
    assert_eq!(get(&mut a), Err("funding_unconfirmed".into()));
    s.rig.chain.mine(1);
    // control: this payer derives nothing of that size itself
    let s2 = sock_control_budget();
    assert_eq!(s2, Err("budget".into()), "control: with no funded channel at the signer the same payer is refused `budget`");
    let mut b = s.payer(s.remote(), 0);
    b.cfg.budget_sats = 5_000;
    assert_eq!(get(&mut b), Ok(200));
    assert_eq!((b.opened_sats, b.cfg.budget_sats, s.fundings()), (10_000, 5_000, 1), "adopted past its own budget; one funding");
}

fn sock_control_budget() -> Result<u16, String> {
    let s = sock();
    let mut b = s.payer(s.remote(), 0);
    b.cfg.budget_sats = 5_000;
    get(&mut b)
}

// --- question b: AGP-101's limits 1 to 3 ----------------------------------------------------------

/// LIMIT (AGP-101 "not a limit but a change", and its stated limit 2; question b). Two payers on
/// one signer and one origin. While the first payer's funding waits for its confirmation (the
/// signer's record is `pending`, which with ten-minute blocks is most of the first ten minutes),
/// a second payer with no record is answered that channel and takes it up. The FIRST payer, whose
/// `fund` call it was, is then locked out: its retry is refused by the signer on every call
/// (`bad_key`, the key has moved), for as long as the second holds the channel. Before AGP-101 the
/// second payer was the one refused (`channel_pending`). And a payer that restarts without a
/// ledger after the attach is refused too (`channel_open`) until the owner closes the channel
/// through the signer (`close_channel`).
#[test]
fn limit_a_second_payer_takes_the_first_payers_pending_channel_and_the_first_is_locked_out() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut a = s.payer(s.remote(), 1);
    assert_eq!(get(&mut a), Err("funding_unconfirmed".into()));
    s.rig.chain.mine(1);
    let mut b = s.payer(s.remote(), 0);
    assert_eq!(get(&mut b), Ok(200), "the second payer adopts the first one's channel");
    assert_eq!(b.channels[PROVIDER].payer.params.spk(), a.channels[PROVIDER].payer.params.spk());
    // the first payer, whose funding it was
    let mut first = vec![];
    for _ in 0..3 {
        first.push(a.request("GET", URL, b"").map(|r| r.status).map_err(|e| e.code));
    }
    assert_eq!(first, vec![Err("bad_key".to_string()); 3], "the first payer is refused by its own signer");
    s.rig.chain.mine(100);
    let later = a.request("GET", URL, b"").map(|r| r.status).map_err(|e| e.code);
    assert_eq!(later, Err("channel_open".into()), "and past the retry floor too (it derives the channel again, for a new key)");
    // limit 2: the second payer restarts without a ledger
    drop(b);
    let mut b2 = s.payer(s.remote(), 0);
    let e = b2.request("GET", URL, b"").unwrap_err();
    assert_eq!((e.code.as_str(), s.remote.funded(PROVIDER).unwrap(), s.fundings()), ("channel_open", None, 1), "{}", e.msg);
    // "or the owner closes the channel": after ONE paid call nothing is signed yet (postpay), and
    // the signer's close is refused by the provider, so the seller cannot be paid through this
    // signer until the refund at the channel's expiry
    let closed = s.rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!((closed["verdict"].as_str(), closed["rule"].as_str()), (Some("deny"), Some("close_channel")), "{closed}");
    assert_eq!(b2.request("GET", URL, b"").unwrap_err().code, "channel_open");
}

/// CONTROL for limit 2's way out: once a state is signed (the payer made a second call before it
/// lost its book) the owner's `close_channel` through the signer closes the channel, and the next
/// call of a payer with no record funds and opens a new one.
#[test]
fn control_the_owner_closes_a_channel_a_payer_without_a_ledger_lost_once_a_state_is_signed() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut b = s.payer(s.remote(), 0);
    for _ in 0..3 {
        assert_eq!(get(&mut b), Ok(200));
    }
    drop(b);
    let mut b2 = s.payer(s.remote(), 0);
    assert_eq!(b2.request("GET", URL, b"").unwrap_err().code, "channel_open");
    let sent = s.fundings();
    let closed = s.rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!(closed["verdict"], "allow", "{closed}");
    s.rig.chain.mine(1);
    assert_eq!(get(&mut b2), Ok(200));
    assert_eq!(s.fundings(), sent + 2, "the close and one new funding");
}

/// LIMIT, measured (question b: "two processes signing states on one channel"). The race in which
/// BOTH payers hold the channel: the second asked `xbt402_funded` a moment before the first
/// attached. Since AGP-101 `attach` of an attached channel is answered again, so both bind it and
/// both are opened by the provider (`duplicate_channel` is taken as the yes). Neither can overpay:
/// the signer holds the one counter of what is signed and the provider counts what it served.
/// What breaks is the request counter they share at the provider and each payer's own count of
/// what was charged: in the run below the second payer is never served (402 on every call) while
/// the first goes on. The numbers are printed.
#[test]
fn limit_two_payers_that_both_hold_one_channel_wedge_each_other_and_nobody_overpays() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut a = s.payer(s.remote(), 1);
    assert_eq!(get(&mut a), Err("funding_unconfirmed".into()));
    let early = s.remote.funded(PROVIDER).unwrap().expect("pending at the signer");
    s.rig.chain.mine(1);
    assert_eq!(get(&mut a), Ok(200));
    let mut b = s.payer(Arc::new(Seam { remote: s.remote.clone(), early: Mutex::new(Some(early)) }), 0);
    let mut out = vec![];
    for _ in 0..4 {
        out.push(("b", get(&mut b)));
        out.push(("a", get(&mut a)));
    }
    let chan = a.channels[PROVIDER].payer.params.channel_id();
    assert_eq!(b.channels[PROVIDER].payer.params.channel_id(), chan, "both hold the one channel");
    assert_eq!((a.channels[PROVIDER].stage, b.channels[PROVIDER].stage), (Stage::Open, Stage::Open));
    // then the second payer alone, and then the first again
    let alone: Vec<_> = (0..6).map(|_| get(&mut b)).collect();
    let first_again: Vec<_> = (0..4).map(|_| get(&mut a)).collect();
    let served = s.rig.prov.channel_state(&chan).unwrap();
    let signed = s.record().used_sats as u64;
    let (ca, cb) = (&a.channels[PROVIDER], &b.channels[PROVIDER]);
    eprintln!("two payers on one channel, interleaved: {out:?}; b alone: {alone:?}; a again: {first_again:?}; the provider served {} msat (seq {}, best cum {}); \
               the signer signed {signed}; a: seq {} signed {} spent {} slack {}; b: seq {} signed {} spent {} slack {}",
              served.spent_msat, served.seq, served.best_cum, ca.seq, ca.payer.signed, ca.spent_msat, ca.slack_msat, cb.seq, cb.payer.signed, cb.spent_msat, cb.slack_msat);
    assert!(signed <= served.spent_msat.div_ceil(1000) && served.best_cum <= signed, "nobody overpays: the signer signed {signed} sat, the provider holds {} and served {} msat",
            served.best_cum, served.spent_msat);
    assert!(out.iter().chain(alone.iter().map(|r| ("b", r.clone())).collect::<Vec<_>>().iter()).filter(|(w, _)| *w == "b").all(|(_, r)| *r != Ok(200)),
            "the second payer is never served: {out:?} {alone:?}");
    assert_eq!(s.fundings(), 1);
}

/// LIMIT (AGP-101 stated limit 1, with the answers to "is there a way out"). A payer that comes
/// back 145 blocks after a funding whose answer it lost: every call is `open_unresolved` until the
/// signer's refund, 1,008 blocks later. In that time the seller cannot be paid through this signer
/// by any rail: the signer's own `xbt402_pay` answers `pending` and pays nothing, a refund before the
/// expiry is refused, and `close_channel` cannot close a channel the provider never opened. The
/// payer's message names the expiry height; it does not say how long that is or that nothing can
/// be done before it. Whether 144 blocks is "reached in honest use": the shipped payers derive
/// the channel with exactly the offer's floor (they ask for 1,008 and the shipped provider's floor
/// is 1,153), so the whole allowance is the provider's close margin, one day, however long the
/// owner would have been willing to lock the coins.
#[test]
fn limit_a_payer_away_for_145_blocks_cannot_pay_the_seller_through_this_signer_for_a_week() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut c = s.payer(s.remote(), 1);
    assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
    let f = s.remote.funded(PROVIDER).unwrap().unwrap();
    let funded_at = s.rig.chain.height();
    assert_eq!(f.expiry as u64 - funded_at, 1_153, "the shipped payer's wish (1,008) is below the offer's floor: the channel has exactly the floor");
    s.rig.chain.mine(145);
    let e = c.request("GET", URL, b"").unwrap_err();
    assert_eq!(e.code, "open_unresolved");
    assert!(e.msg.contains(&format!("({})", f.expiry)), "the message names the expiry height: {}", e.msg);
    // no rail and no owner's action gets through before the expiry
    // (wallet area, noted here: the signer's own rail answers "pending ... the watcher also opens it",
    // with 0 confirmations, for a client's channel that is 145 blocks deep and that no watcher opens)
    let own = s.rig.pay();
    assert_eq!((own["verdict"].as_str(), own["rule"].as_str(), own["charged_sats"].as_i64()), (Some("pending"), Some("funding_unconfirmed"), Some(0)), "{own}");
    let refund = s.rig.call("xbt402_refund", json!({"chan": f.channel_id()}));
    assert_ne!(refund["verdict"], "allow", "{refund}");
    let close = s.rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_ne!(close["verdict"], "allow", "{close}");
    assert_eq!((s.record().state.as_str(), s.fundings()), ("pending", 1));
    // one block before the expiry it is still so; 1,008 blocks of it
    s.rig.chain.mine_to(f.expiry as u64 - 1);
    s.rig.s.watch_tick();
    assert_eq!(get(&mut c), Err("open_unresolved".into()));
    assert_eq!(s.rig.chain.height() - (funded_at + 145), 1_007);
    assert_eq!(s.rig.chain.unspent_to(&hex::encode(f.spk())), 10_000, "the coins are in the channel's script for that whole time");
}

// --- question c: one origin for the book, another host for the transport --------------------------

/// HOLE (Medium, new in wave 5; the cause and the paid-request side are in
/// `xbt402/tests/agp102_client.rs::sockets::hole_a_paid_request_is_sent_only_to_the_host_its_origin_names`).
/// `xbt-wallet-mcp`'s local payer checks the owner's allowlist on `split_url(url).0`
/// (`crates/xbt-wallet-mcp/src/wallet.rs:308-313`) and then sends the unpaid probe to `url` with
/// the shipped transport (`:316`), "so the probe reaches no other host" (`:310`). Since AGP-096
/// `split_url` answers the canonical origin, which reads the host of `http://A\@B/x` as B; the
/// transport connects to A. With B on the allowlist the check passes and the request, with the
/// caller's method and body, goes to A. Before AGP-096 `split_url` answered the spelling
/// (`http://A\@B`), which is on no allowlist. The same three steps are run here on the real
/// signer's policy; the binary's private function is not called.
#[test]
fn hole_a_url_that_passes_the_allowlist_is_sent_to_the_allowlisted_host() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let l = std::net::TcpListener::bind(("127.0.0.1", 27_755)).unwrap();
    let heads = Arc::new(Mutex::new(Vec::<String>::new()));
    let h2 = heads.clone();
    std::thread::spawn(move || {
        for st in l.incoming() {
            let Ok(mut st) = st else { continue };
            st.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let (mut head, mut b) = (Vec::new(), [0u8; 1]);
            while !head.ends_with(b"\r\n\r\n") {
                match st.read(&mut b) {
                    Ok(1) => head.push(b[0]),
                    _ => break,
                }
            }
            h2.lock().unwrap().push(String::from_utf8_lossy(&head).to_string());
            let _ = st.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    let url = "http://127.0.0.1:27755\\@127.0.0.1:33210/agp015/echo";
    // wallet.rs:308-313, on the signer's own policy
    let (origin, _) = split_url(url);
    let dest = xbt_signer::policy::normalize_dest(&origin);
    let policy = s.remote.client.call("policy_get", json!({})).unwrap();
    let listed = policy.pointer("/policy/allowlist").and_then(Value::as_array).into_iter().flatten()
        .filter_map(Value::as_str).any(|a| xbt_signer::policy::normalize_dest(a) == dest);
    assert!(listed, "control: the URL passes the allowlist as {dest}");
    // wallet.rs:316, the probe
    let probe = xbt402::http::UreqTransport::default().request("POST", url, b"the caller's body", &[]);
    let seen = heads.lock().unwrap().clone();
    assert!(seen.is_empty(), "allowlisted as {dest}, and the probe ({:?}) went to 127.0.0.1:27755, which is on no allowlist: {:?}",
            probe.map(|r| r.status).map_err(|e| e.code), seen[0].lines().next().unwrap_or(""));
}

/// CONTROL for the hole above: the signer's own pay rail reads the URL's host as it is written and
/// refuses it (`session::origin_of` keeps the userinfo and the backslash in the destination).
#[test]
fn control_the_signers_own_pay_rail_refuses_that_url() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let r = s.rig.call("xbt402_pay", json!({"url": "http://127.0.0.1:27756\\@127.0.0.1:33210/agp015/echo", "method": "GET", "body": "", "max_sats": 500}));
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("allowlist")), "{r}");
    assert!(s.rig.web.requests.lock().unwrap().is_empty(), "and no request left");
}

/// CONTROL (question c). Which spellings the book and the shipped transport's URL parser (the `url`
/// crate, as ureq uses it) read as different hosts. Only the backslash form puts the book on one
/// host and the transport on another host that exists; the others the two read alike, or the book
/// reads a key that names no host at all (and so matches no channel and no allowlist entry).
#[test]
fn control_only_a_backslash_makes_the_book_and_the_transport_read_two_hosts() {
    let book = |u: &str| xbt402::wire::canonical_origin(u);
    let wire = |u: &str| url::Url::parse(u).ok().map(|p| match p.port() {
        Some(port) => format!("{}://{}:{port}", p.scheme(), p.host_str().unwrap_or("")),
        None => format!("{}://{}", p.scheme(), p.host_str().unwrap_or("")),
    });
    let same = ["http://b.example/x", "HTTP://B.example:80/x", "http://u:p@b.example/x", "http://a.example@b.example/x", "http://a.example%2f@b.example/x",
                "http://a.example:80@b.example/x", "http://b.example?@a.example/x", "http://b.example/@a.example/x", "http://a.example?x@b.example", "http://a.example\t@b.example/x", "http://b.example./x"];
    for u in same {
        assert_eq!(Some(book(u)), wire(u), "{u}");
    }
    let apart = ["http://a.example\\@b.example/x", "http://a.example\\.b.example/x", "http:///b.example/x", "http://ｂ.example/x",
                 "http://%62.example/x"];
    let mut onto_b = vec![];
    for u in apart {
        assert_ne!(Some(book(u)), wire(u), "{u}");
        if book(u) == "http://b.example" {
            onto_b.push((u, wire(u)));
        }
    }
    assert_eq!(onto_b, vec![("http://a.example\\@b.example/x", Some("http://a.example".to_string()))], "the book says b.example, the transport connects elsewhere");
}

/// LIMIT (AGP-096 stated limit 6 with a shipped binary's consequence; question a, "what does
/// adoption do when the seller changed its key"). A payer that still has its record takes up the
/// channel its signer funded without looking at this call's offer (only a payer with no record
/// checks it). The seller, with a new key, refuses the funded open; the channel is then on the
/// books as `Funded`, and it stays there after the signer has refunded it at its expiry: every
/// call is still the seller's refusal of the old channel, for good. An embedder removes the record;
/// `xbt-wallet-mcp` has no tool for it (its close tool cannot close a channel that was never
/// opened), so its owner edits the ledger file by hand.
#[test]
fn limit_a_funded_channel_the_seller_refuses_blocks_its_origin_after_the_signers_refund_too() {
    use xbt402::ledger::Ledger;
    use xbt402::provider::{Provider, ProviderConfig};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut c = s.payer(s.remote(), 1);
    assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
    let f = s.remote.funded(PROVIDER).unwrap().unwrap();
    let mut pc = ProviderConfig::new(&s.rig.chain.network());
    (pc.policy.min_capacity, pc.policy.max_capacity, pc.policy.min_expiry_blocks, pc.policy.min_conf) = (10_000, 10_000, 1_008, 1);
    let moved = Provider::new(Arc::new(ProviderChain(s.rig.chain.clone())), secret("another payTo"), pc, Ledger::in_memory(), Box::new(|_, _| 500),
                              Box::new(|_, p, _| HttpResponse::new(200, vec![], json!({"echo": p}).to_string().into_bytes()))).unwrap();
    s.rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(moved));
    s.rig.chain.mine(1);
    let refused = c.request("GET", URL, b"").unwrap_err();
    assert_eq!((c.channels[PROVIDER].stage, s.record().state.as_str()), (Stage::Funded, "open"), "{}: {}", refused.code, refused.msg);
    // the signer refunds it at its expiry
    s.rig.chain.mine_to(f.expiry as u64 + 1);
    s.rig.s.watch_tick();
    s.rig.chain.mine(1);
    assert_eq!((s.record().state.as_str(), s.rig.chain.unspent_to(&hex::encode(f.spk()))), ("refunded", 0));
    let after: Vec<_> = (0..3).map(|_| get(&mut c)).collect();
    assert_eq!(after, vec![Err(refused.code.clone()); 3], "after the refund the origin is still refused, on the refunded channel");
    assert_eq!((c.channels[PROVIDER].stage, s.fundings()), (Stage::Funded, 2), "one funding and its refund; nothing new is opened");
    // the embedder's part
    c.channels.remove(PROVIDER);
    assert_eq!(get(&mut c), Ok(200));
}

/// HOLE (Medium by what it strands, left from before and narrowed by AGP-101, which states it as
/// its limit 1; the `limit_` test above pins its numbers). With the shipped numbers on both sides
/// (the payers ask for 1,008 blocks, the provider's floor is 1,153, so the channel gets exactly
/// the floor) a payer whose first `fund` ended in `funding_unconfirmed`, which is most first runs
/// with ten-minute blocks, and that comes back two days later, cannot open the channel its signer
/// funded, and its coins and its business with that seller wait a week for the refund. Nobody
/// attacks and nothing failed but a 180 s wait. The rule a reader expects: a funded channel can
/// be opened for as long as the owner was willing to lock the coins, not for one day of it.
///
/// AGP-107: the fixture follows the shipped payers. AGP-105 gave `xbt-signer-payer` and
/// `xbt-wallet-mcp` `SHIPPED_PAYER_EXPIRY_BLOCKS` (2,016); this test pinned the library's default
/// (1,008) under the words "the shipped payers' default", which no shipped payer uses any more.
/// What is asserted after it is unchanged. A payer built on the library's default still has the
/// one day: `limit_a_payer_away_for_145_blocks_cannot_pay_the_seller_through_this_signer_for_a_week`.
#[test]
fn hole_a_payer_that_comes_back_two_days_after_a_lost_funding_answer_can_still_pay_the_seller() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut c = s.payer(s.remote(), 1);
    c.cfg.expiry_blocks = xbt402::client::SHIPPED_PAYER_EXPIRY_BLOCKS;
    assert_eq!(c.cfg.expiry_blocks, 2_016, "the shipped payers' default");
    assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
    let f = s.remote.funded(PROVIDER).unwrap().unwrap();
    s.rig.chain.mine(288);
    let r = c.request("GET", URL, b"").map(|r| r.status).map_err(|e| e.code);
    assert_eq!(r, Ok(200), "288 blocks after the funding: {} sat stay in the channel's script for {} more blocks, and every call until then is refused",
               s.rig.chain.unspent_to(&hex::encode(f.spk())), f.expiry as u64 - s.rig.chain.height());
}
