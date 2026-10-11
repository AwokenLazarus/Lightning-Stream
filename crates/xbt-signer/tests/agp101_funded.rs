//! AGP-101: a funding the signer made that its caller never heard of.
//!
//! The rule: **a funding the signer carried out is always learnable by the client that asked for
//! it, and a retry adopts it and never funds twice.** The signer's `fund` records the channel and
//! moves the issued key to it before it broadcasts; the socket's `xbt402_funded` answers that
//! channel by origin until a client attaches it, and xbt402's `Client` asks it on every open that
//! has no outpoint yet (`StateSigner::funded`).
//!
//! The audit's failing test for it is `agp096_signer_client.rs::hole_a_funding_the_signer_made_
//! but_the_caller_never_heard_of_is_adopted_by_the_retry`, unchanged. These are the other places
//! the rule can break: a caller that keeps asking for a day of blocks, a restart with and without
//! a ledger, a `fund` or an `attach` whose answer was lost on the socket, a ledger written by the
//! code before this rule, and a seller that changed its key after the funding.
//!
//! xbt402's `Client` with a `RemoteSigner` over the signer's Unix socket, the signer's own code
//! behind it on the test node. Every test here fails on the code before AGP-101, except the two
//! named `control_`.
mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::channel::ChannelParams;
use xbt402::client::{Client, ClientConfig, FileClientLedger, Stage, Transport, Wallet};
use xbt402::conditional::ConditionalParams;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
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

/// The wallet of the shipped signer-backed payers (`xbt-signer-payer`, `xbt-wallet-mcp` with
/// `XBT_MCP_PAYER=local`): the signer's `fund`, then a wait for a confirmation. Here the wait of
/// the first `lose` calls gives up at once, with `code`: `funding_unconfirmed` is the payers' own
/// after 180 s, `signer_unreachable` is the socket call that timed out while the signer went on.
/// It passes nothing else on, as theirs: what the wallet sent is not asked of it.
struct GivesUp {
    remote: RemoteSigner,
    chain: Arc<FakeChain>,
    lose: AtomicUsize,
    code: &'static str,
}

impl Wallet for GivesUp {
    fn fund(&self, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
        self.remote.fund(a, s)
    }

    fn fund_channel(&self, o: &str, p: &ChannelParams, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
        let r = self.remote.fund_channel(o, p, a, s)?;
        if self.lose.load(Ordering::SeqCst) > 0 {
            self.lose.fetch_sub(1, Ordering::SeqCst);
            return Err(ChannelError::new(self.code, "no answer about the funding"));
        }
        self.chain.mine(1);
        Ok(r)
    }
}

/// The signer as the client reaches it, with two faults. `old`: the signer seam of the code before
/// AGP-101, which had no `funded` (the trait's default). `lose_attach`: the next `attach` reaches
/// the signer and its answer is lost.
struct Seam {
    remote: RemoteSigner,
    old: bool,
    lose_attach: AtomicBool,
}

impl StateSigner for Seam {
    fn new_key(&self, o: &str) -> xbt402::Result<PubkeyBytes> {
        self.remote.new_key(o)
    }

    fn attach(&self, o: &str, p: &ChannelParams) -> xbt402::Result<String> {
        let r = self.remote.attach(o, p)?;
        if self.lose_attach.swap(false, Ordering::SeqCst) {
            return Err(ChannelError::new("signer_unreachable", "timed out reading the answer"));
        }
        Ok(r)
    }

    fn payer_spk(&self) -> xbt402::Result<Option<Vec<u8>>> {
        self.remote.payer_spk()
    }

    fn funded(&self, o: &str) -> xbt402::Result<Option<ChannelParams>> {
        if self.old { Ok(None) } else { self.remote.funded(o) }
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
    fn seam(&self, old: bool) -> Arc<Seam> {
        Arc::new(Seam { remote: self.remote.clone(), old, lose_attach: AtomicBool::new(false) })
    }

    /// A payer whose wallet loses the answer to its first `lose` fundings.
    fn payer(&self, signer: Arc<dyn StateSigner>, lose: usize, code: &'static str) -> Client {
        let mut cfg = ClientConfig::new(&self.rig.chain.network());
        (cfg.capacity, cfg.max_price) = (10_000, 500);
        let chain = self.rig.chain.clone();
        let wallet = GivesUp { remote: self.remote.clone(), chain: self.rig.chain.clone(), lose: AtomicUsize::new(lose), code };
        Client::new(cfg, Box::new(WebRef(self.rig.web.clone())), Box::new(wallet), Box::new(move || Ok(chain.height() as u32))).with_signer(signer)
    }

    /// How many fundings the signer's hot key has sent (every transaction it sent is one here).
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

/// What `xbt402_funded` answers: nothing before a `fund`, the channel with its outpoint from the
/// write that precedes the broadcast, and nothing once a client has attached it. A second `fund`
/// for the origin is refused and sends nothing.
#[test]
fn the_signer_answers_the_channel_it_funded_until_it_is_attached() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    assert_eq!(s.rig.call("xbt402_funded", json!({"origin": PROVIDER})), json!({"funded": null}));
    assert_eq!(s.remote.funded(PROVIDER).unwrap(), None);
    assert_eq!(s.rig.call("xbt402_funded", json!({}))["rule"], "dest", "no origin, no answer");
    let mut c = s.payer(Arc::new(s.remote.clone()), 1, "funding_unconfirmed");
    assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
    let keyed = c.channels[PROVIDER].payer.params.clone();
    let f = s.remote.funded(PROVIDER).unwrap().expect("the signer answers the channel it funded");
    assert_eq!(keyed.clone().with_funding(&f.funding_txid(), f.funding_vout(), f.capacity).unwrap(), f, "the client's channel, with an outpoint");
    assert_eq!((f.capacity, s.rig.chain.unspent_to(&hex::encode(f.spk()))), (10_000, 10_000));
    assert_eq!(s.remote.funded("http://127.0.0.1:33210/").unwrap(), Some(f.clone()), "by origin, however it is spelled");
    assert_eq!(s.remote.funded("http://other.example").unwrap(), None);
    // asking the signer to fund the same channel again sends nothing
    let addr = xbt_primitives::address::segwit_address("bcrt", &keyed.spk()).unwrap();
    let again = s.remote.fund_channel(PROVIDER, &keyed, &addr, 10_000).unwrap_err();
    assert_eq!((again.code.as_str(), s.fundings()), ("bad_key", 1), "{}", again.msg);
    // attached: the client knows it, and the signer's answer is for those who do not
    s.remote.attach(PROVIDER, &f).unwrap();
    assert_eq!((s.remote.funded(PROVIDER).unwrap(), s.record().state.as_str()), (None, "open"));
}

/// `xbt402_funded` answers only a client's channel: not the pending channel of the signer's own
/// pay rail (`xbt402_pay` finishes that one itself), which a client could otherwise attach.
#[test]
fn control_the_signers_own_pending_channel_is_not_answered_as_a_clients() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let r = s.rig.pay();
    assert_eq!((r["verdict"].as_str(), s.record().state.as_str()), (Some("pending"), "pending"), "{r}");
    assert_eq!(s.remote.funded(PROVIDER).unwrap(), None);
}

/// The hole, for every way the answer is lost and for as long as the seller would still open the
/// channel: the retry opens the channel the signer funded, on the next call, a block later, a
/// hundred blocks later (past the retry floor, where the client used to derive the channel again
/// and was refused `channel_pending`) and 144 blocks after the funding, the last block at which
/// the seller opens it. One funding leaves the hot key.
#[test]
fn a_retry_adopts_the_funding_the_signer_made_and_never_funds_twice() {
    for code in ["funding_unconfirmed", "signer_unreachable"] {
        for later in [0, 1, 100, 143] {
            let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
            let s = sock();
            let mut c = s.payer(Arc::new(s.remote.clone()), 1, code);
            assert_eq!(get(&mut c), Err(code.into()));
            let keyed = c.channels[PROVIDER].payer.params.clone();
            assert_eq!((c.channels[PROVIDER].stage, keyed.funding, s.record().state.as_str(), s.fundings()), (Stage::Keyed, None, "pending", 1));
            s.rig.chain.mine(1 + later); // the funding confirms
            assert_eq!(get(&mut c), Ok(200), "{code}, {later} blocks later");
            let p = &c.channels[PROVIDER].payer.params;
            assert_eq!((p.spk(), p.expiry, p.capacity), (keyed.spk(), keyed.expiry, 10_000), "the channel the signer funded, {code}, {later} blocks later");
            let rec = s.record();
            assert_eq!((rec.chan.as_str(), rec.state.as_str(), s.fundings()), (p.channel_id().as_str(), "open", 1), "{code}, {later} blocks later");
            assert_eq!(c.opened_sats, 10_000, "the budget counts the coins once");
            for _ in 0..3 {
                assert_eq!(get(&mut c), Ok(200));
            }
        }
    }
}

/// A caller that asks again before the funding has a confirmation: the channel is adopted and
/// bound at once (its refund is held), the seller says the funding is not confirmed yet, and the
/// call after the block opens it. Nothing is asked of the wallet again.
#[test]
fn a_retry_before_the_funding_confirms_holds_the_refund_and_opens_after_the_block() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut c = s.payer(Arc::new(s.remote.clone()), 1, "funding_unconfirmed");
    assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
    let e = c.request("GET", URL, b"").unwrap_err();
    let ch = &c.channels[PROVIDER];
    assert_eq!((ch.stage, ch.refund_hex.is_empty(), s.record().state.as_str()), (Stage::Funded, false, "open"), "{} {}", e.code, e.msg);
    s.rig.chain.mine(1);
    assert_eq!((get(&mut c), s.fundings()), (Ok(200), 1));
}

/// A restart. `xbt-signer-payer` has no ledger and ends at the first error, so its next run knows
/// no script at all; `xbt-wallet-mcp` keeps a ledger. Both open the channel the signer funded.
/// Without a ledger the new process used to be given a new key, and its `fund` was refused
/// `channel_pending` until the refund at expiry.
#[test]
fn a_restarted_payer_adopts_the_funding_with_and_without_a_ledger() {
    for with_ledger in [false, true] {
        let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
        let s = sock();
        let path = s.rig.dir.path().join("payer.jsonl");
        let make = |lose| {
            let c = s.payer(Arc::new(s.remote.clone()), lose, "funding_unconfirmed");
            if with_ledger { c.with_ledger(Box::new(FileClientLedger::open(&path).unwrap())).unwrap() } else { c }
        };
        let mut c = make(1);
        assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
        let funded = s.remote.funded(PROVIDER).unwrap().unwrap();
        drop(c);
        s.rig.chain.mine(3);
        let mut c = make(0);
        assert_eq!(c.channels.contains_key(PROVIDER), with_ledger, "what the new process knows");
        assert_eq!(get(&mut c), Ok(200), "ledger {with_ledger}");
        assert_eq!((c.channels[PROVIDER].payer.params.clone(), s.fundings(), c.opened_sats), (funded, 1, 10_000), "ledger {with_ledger}");
        assert_eq!(get(&mut c), Ok(200));
    }
}

/// `attach` reached the signer and its answer was lost. The client asks again; the signer's
/// record is open by then and it used to answer `unknown_channel`, for good.
#[test]
fn an_attach_whose_answer_was_lost_is_answered_again() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let seam = s.seam(false);
    seam.lose_attach.store(true, Ordering::SeqCst);
    let mut c = s.payer(seam, 0, "");
    assert_eq!(get(&mut c), Err("signer_unreachable".into()));
    assert_eq!((c.channels[PROVIDER].stage, s.record().state.as_str()), (Stage::Keyed, "open"));
    assert_eq!((get(&mut c), s.fundings()), (Ok(200), 1));
    // the same channel only: other params for the open record are refused as before
    let mut other = c.channels[PROVIDER].payer.params.clone();
    other.capacity -= 1;
    assert_eq!(s.remote.attach(PROVIDER, &other).unwrap_err().code, "bad_params");
}

/// A ledger the code before this rule left in the hole: the funded channel set aside as too old
/// (`unfunded`), a second one derived for a new key, and the signer refusing to fund that one.
/// The payer of this branch reads it, takes the funded channel back and pays.
#[test]
fn a_ledger_from_before_that_had_derived_the_channel_again_goes_on_with_the_funded_one() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let path = s.rig.dir.path().join("payer.jsonl");
    let make = |old: bool, lose| s.payer(s.seam(old), lose, "funding_unconfirmed").with_ledger(Box::new(FileClientLedger::open(&path).unwrap())).unwrap();
    let mut c = make(true, 1);
    assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
    let funded = s.remote.funded(PROVIDER).unwrap().unwrap();
    s.rig.chain.mine(100);
    // the code before: past the retry floor it derives the channel again, and the signer refuses
    let mut tries = vec![];
    for _ in 0..3 {
        tries.push(get(&mut c));
    }
    assert_eq!(tries, vec![Err("channel_pending".to_string()); 3], "control: the hole, as the audit found it");
    let (again, kept) = (c.channels[PROVIDER].payer.params.clone(), c.unfunded[PROVIDER].len());
    assert_ne!((again.spk(), again.payer_pub), (funded.spk(), funded.payer_pub), "control: another script for another key");
    assert_eq!((kept, c.unfunded[PROVIDER][0].payer.params.spk()), (1, funded.spk()));
    drop(c);
    let mut c = make(false, 0);
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!((c.channels[PROVIDER].payer.params.clone(), s.fundings(), c.opened_sats), (funded, 1, 10_000));
    // the channel derived in between is kept as every channel the wallet was asked to fund is (its
    // `fund` was refused, which the client cannot tell from an answer that was lost)
    let kept: Vec<Vec<u8>> = c.unfunded[PROVIDER].iter().map(|k| k.payer.params.spk()).collect();
    assert_eq!(kept, vec![again.spk()], "the funded channel is the live one and no longer among the unfunded");
    assert_eq!(get(&mut c), Ok(200));
}

/// The bound of the rule: the seller changed its key after the signer funded. A process that has
/// lost its record cannot open that channel with this seller (its payee is the old key), and the
/// signer funds no second channel to an origin. The call says so and funds nothing; the signer's
/// record stays pending and is refunded at its expiry.
#[test]
fn a_funded_channel_the_seller_no_longer_offers_is_not_adopted_and_nothing_more_is_funded() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut c = s.payer(Arc::new(s.remote.clone()), 1, "funding_unconfirmed");
    assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
    drop(c);
    let mut pc = ProviderConfig::new(&s.rig.chain.network());
    (pc.policy.min_capacity, pc.policy.max_capacity, pc.policy.min_expiry_blocks, pc.policy.min_conf) = (10_000, 10_000, 1_008, 1);
    let moved = Provider::new(Arc::new(ProviderChain(s.rig.chain.clone())), secret("another payTo"), pc, Ledger::in_memory(), Box::new(|_, _| 500),
                              Box::new(|_, p, _| HttpResponse::new(200, vec![], json!({"echo": p}).to_string().into_bytes()))).unwrap();
    s.rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(moved));
    s.rig.chain.mine(1);
    let mut c = s.payer(Arc::new(s.remote.clone()), 0, "");
    for _ in 0..3 {
        let e = c.request("GET", URL, b"").unwrap_err();
        assert_eq!(e.code, "open_unresolved", "{}", e.msg);
        assert!(e.msg.contains("refunds it at its expiry"), "{}", e.msg);
    }
    assert_eq!((s.fundings(), s.record().state.as_str(), c.channels.contains_key(PROVIDER), c.opened_sats), (1, "pending", false, 0));
}

/// The other bound: the payer comes back when the channel no longer has the blocks the seller
/// needs to open it (`minExpiryBlocks + minConf`, 1,009 here, of the 1,153 it was derived with: a
/// day and an hour of blocks after the funding). It is not taken onto the books, where the seller
/// would refuse its open on every call and it would stand in the way after its refund too. The
/// call says so and funds nothing; once the signer has refunded it, the next call funds a new one.
#[test]
fn a_funding_found_too_late_for_the_seller_to_open_is_left_to_the_signers_refund() {
    for restart in [false, true] {
        let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
        let s = sock();
        let mut c = s.payer(Arc::new(s.remote.clone()), 1, "funding_unconfirmed");
        assert_eq!(get(&mut c), Err("funding_unconfirmed".into()));
        let first = s.remote.funded(PROVIDER).unwrap().unwrap();
        // 144 blocks later the seller still opens it (1,009 left); one block more and it does not
        s.rig.chain.mine(145);
        if restart {
            c = s.payer(Arc::new(s.remote.clone()), 0, "");
        }
        for _ in 0..2 {
            let e = c.request("GET", URL, b"").unwrap_err();
            assert_eq!(e.code, "open_unresolved", "restart {restart}: {}", e.msg);
            assert!(e.msg.contains("too near its expiry"), "{}", e.msg);
        }
        assert_eq!((s.fundings(), s.record().state.as_str(), c.opened_sats), (1, "pending", 0), "restart {restart}");
        assert!(c.channels.get(PROVIDER).is_none_or(|ch| ch.payer.params.funding.is_none()), "not on the books as a funded channel");
        // the signer refunds it at its expiry, and the seller is paid through a new channel
        s.rig.chain.mine_to(first.expiry as u64 + 1);
        s.rig.s.watch_tick();
        s.rig.chain.mine(1);
        assert_eq!((s.record().state.as_str(), s.remote.funded(PROVIDER).unwrap()), ("refunded", None));
        assert_eq!(get(&mut c), Ok(200), "restart {restart}");
        let p = &c.channels[PROVIDER].payer.params;
        assert_ne!(p.spk(), first.spk());
        assert_eq!((s.record().chan.as_str(), s.record().state.as_str(), c.opened_sats), (p.channel_id().as_str(), "open", 10_000), "restart {restart}");
    }
}

/// A signer that cannot be asked is no answer: nothing is derived, keyed or funded on it.
#[test]
fn a_signer_that_does_not_answer_what_it_funded_funds_nothing() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    struct Mute(Arc<Seam>);
    impl StateSigner for Mute {
        fn new_key(&self, o: &str) -> xbt402::Result<PubkeyBytes> {
            self.0.new_key(o)
        }
        fn attach(&self, o: &str, p: &ChannelParams) -> xbt402::Result<String> {
            self.0.attach(o, p)
        }
        fn payer_spk(&self) -> xbt402::Result<Option<Vec<u8>>> {
            self.0.payer_spk()
        }
        fn funded(&self, _: &str) -> xbt402::Result<Option<ChannelParams>> {
            Err(ChannelError::new("signer_error", "unknown method xbt402_funded"))
        }
        fn sign_state(&self, c: &str, a: u64) -> xbt402::Result<Vec<u8>> {
            self.0.sign_state(c, a)
        }
        fn sign_state_a3(&self, c: &str, a: u64) -> xbt402::Result<Vec<u8>> {
            self.0.sign_state_a3(c, a)
        }
        fn sign_rollover(&self, c: &str, a: u64, n: &[u8], cap: u64) -> xbt402::Result<Vec<u8>> {
            self.0.sign_rollover(c, a, n, cap)
        }
        fn sign_close(&self, c: &str) -> xbt402::Result<Vec<u8>> {
            self.0.sign_close(c)
        }
        fn sign_refund(&self, c: &str) -> xbt402::Result<String> {
            self.0.sign_refund(c)
        }
        fn request_auth(&self, c: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> xbt402::Result<String> {
            self.0.request_auth(c, seq, cum, sig, req)
        }
        fn sign_conditional(&self, c: &str, u: u64, cond: &ConditionalParams) -> xbt402::Result<Vec<u8>> {
            self.0.sign_conditional(c, u, cond)
        }
    }
    let mut c = s.payer(Arc::new(Mute(s.seam(false))), 0, "");
    assert_eq!(get(&mut c), Err("signer_error".into()));
    assert_eq!((s.fundings(), c.channels.len(), s.rig.s.book.get(PROVIDER).is_none()), (0, 0, true));
}

/// Control: nothing changes for an open whose funding is answered. One `xbt402_funded` question
/// goes to the signer per open, none per paid call.
#[test]
fn control_an_answered_funding_is_opened_as_before() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let s = sock();
    let mut c = s.payer(Arc::new(s.remote.clone()), 0, "");
    for _ in 0..4 {
        assert_eq!(get(&mut c), Ok(200));
    }
    assert_eq!((s.fundings(), s.record().state.as_str(), c.opened_sats), (1, "open", 10_000));
}

/// Item 3: the routing-fee limit is the owner's base and ppm, with no bound of their own. A limit
/// that does not fit is the largest one, and the payment is refused on its sum with the amount.
#[test]
fn a_fee_limit_that_does_not_fit_is_the_largest_one_not_a_wrap_or_a_panic() {
    let pol = |base: i64, ppm: i64| xbt_signer::ln::LnPolicy { max_fee_base_sats: base, max_fee_ppm: ppm, ..Default::default() };
    assert_eq!(pol(2, 1_000).fee_limit_sats(300), 3, "control: 2 base + 1000 ppm of 300, rounded up");
    assert_eq!(pol(i64::MAX, 5_000).fee_limit_sats(1_000), i64::MAX, "base + ppm past i64");
    assert_eq!(pol(10, i64::MAX).fee_limit_sats(i64::MAX), i64::MAX, "amount * ppm / 1e6 past i64 (it was cast to a negative limit)");
    assert_eq!(pol(-5, -5).fee_limit_sats(1_000), 0, "control: negative settings are no limit at all");
}
