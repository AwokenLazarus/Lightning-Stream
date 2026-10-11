//! AGP-096: xbt402's `Client` with a `RemoteSigner` over the signer's Unix socket, the signer's
//! own code behind it on the test node.
//!
//! 1. The third closure audit's item 7 (CLIENT 3) run through the signer itself. The audit ran the
//!    case with the in-process `LocalSigner` only and called the real signer safe "from reading".
//!    Three attempts to roll one channel over: the seller broadcasts the first and answers it with
//!    an error, loses the answer to the second, and answers the third with a yes that names the
//!    second attempt's transaction, which it never broadcasts. The first then confirms.
//!    This test passed before AGP-096 changed anything: since AGP-089 the signer keeps a next
//!    channel's key under that channel's own script, and binds a next channel only when its node
//!    shows the rollover. It is here so that "C3 is closed with the real signer" rests on a run.
//!
//! 2. The audit's item 6 through the signer: a `fund` the signer refuses (an empty hot wallet)
//!    leaves the key in its issued slot, and the payer's later calls open the channel, a block
//!    later on the same terms and a hundred blocks later on new ones. Not run on the base with
//!    this signer; the audit ran the same client path with `LocalSigner` and got `open_unresolved`
//!    on every call.
//!
//! 3. `hole_*`: found beside AGP-096's items and NOT fixed (it is in the wallet's files). It fails
//!    today and states what should hold.
mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig, Stage, Transport, Wallet, WalletSend};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::signer::StateSigner;
use xbt402::wire::ROLLOVER_PATH;
use xbt402::ChannelError;
use xbt_primitives::tx::Tx;
use xbt_signer::client::RemoteSigner;

/// The rig's web, with the seller's three answers to a rollover.
struct Seller {
    web: Arc<Web>,
    n: AtomicUsize,
    forged: Arc<Mutex<Option<Value>>>,
}

impl Transport for Seller {
    fn request(&self, m: &str, u: &str, b: &[u8], h: &[(String, String)]) -> xbt402::Result<HttpResponse> {
        let r = self.web.request(m, u, b, h)?;
        if split_url(u).1 != ROLLOVER_PATH {
            return Ok(r);
        }
        match self.n.fetch_add(1, Ordering::SeqCst) {
            0 => {
                assert_eq!(r.status, 200, "the provider took the first rollover: {}", String::from_utf8_lossy(&r.body));
                Ok(HttpResponse::new(400, vec![], br#"{"error":"bad_request","detail":"no"}"#.to_vec()))
            }
            1 => Err(ChannelError::new("transport_error", "timed out")),
            _ => Ok(HttpResponse::new(200, vec![], self.forged.lock().unwrap().clone().unwrap().to_string().into_bytes())),
        }
    }
}

/// The signer's `fund`; the test node confirms at once.
struct ConfirmingWallet(RemoteSigner, Arc<FakeChain>);

impl Wallet for ConfirmingWallet {
    fn fund(&self, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
        let r = self.0.fund(a, s)?;
        self.1.mine(1);
        Ok(r)
    }

    fn fund_channel(&self, o: &str, p: &xbt402::channel::ChannelParams, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
        let r = self.0.fund_channel(o, p, a, s)?;
        self.1.mine(1);
        Ok(r)
    }
}

#[test]
fn an_earlier_rollover_that_confirms_after_a_later_yes_is_adopted_through_the_signer_socket() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 0}), false);
    // a seller that takes a next channel of 5,000 sat or more (the runbook's takes 10,000 only)
    let mut pc = ProviderConfig::new(&rig.chain.network());
    (pc.policy.min_capacity, pc.policy.max_capacity, pc.policy.min_expiry_blocks, pc.policy.min_conf) = (5_000, 10_000, 1_008, 1);
    let prov = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), pc, Ledger::in_memory(), Box::new(|_, _| 500),
                             Box::new(|_, p, _| HttpResponse::new(200, vec![], json!({"echo": p}).to_string().into_bytes()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(prov));
    rig.fund_hot(1, 30_000);
    let sock = rig.dir.path().join("signer.sock");
    let _srv = xbt_signer::server::spawn(rig.s.clone(), &sock, false).unwrap();
    let remote = RemoteSigner::new(&sock);
    let signer: Arc<dyn StateSigner> = Arc::new(remote.clone());
    let mut cfg = ClientConfig::new(&rig.chain.network());
    (cfg.capacity, cfg.max_price) = (10_000, 500);
    let forged = Arc::new(Mutex::new(None));
    let chain = rig.chain.clone();
    let mut c = Client::new(cfg, Box::new(Seller { web: rig.web.clone(), n: AtomicUsize::new(0), forged: forged.clone() }),
                            Box::new(ConfirmingWallet(remote.clone(), rig.chain.clone())), Box::new(move || Ok(chain.height() as u32))).with_signer(signer);
    for i in 0..4 {
        let r = c.request("GET", URL, b"").unwrap_or_else(|e| panic!("call {i}: {e:?}"));
        assert_eq!(r.status, 200);
    }
    let old = c.channels[PROVIDER].payer.params.clone();

    // attempt 1: broadcast by the seller, answered with an error
    let sent_before = rig.chain.sent_txs().len();
    assert_eq!(c.rollover(PROVIDER).unwrap_err().code, "bad_request");
    let on_chain = rig.chain.sent_txs().last().unwrap().txid();
    assert_eq!(rig.chain.sent_txs().len(), sent_before + 1);
    rig.chain.mine(1);
    // attempt 2, a block later (another transaction): the answer is lost
    assert_eq!(c.rollover(PROVIDER).unwrap_err().code, "transport_error");
    let second = c.next_rolled[PROVIDER][1].payer.params.clone();
    assert_ne!(second.funding_txid(), on_chain);
    assert_eq!(second.payer_pub, c.next_rolled[PROVIDER][0].payer.params.payer_pub, "every attempt pays one next key");
    // attempt 3: a yes that names attempt 2's transaction. The signer binds a next channel only
    // when its node shows the rollover, so the seller's word binds nothing
    *forged.lock().unwrap() = Some(json!({"txid": second.funding_txid(), "nextChan": format!("{}:1", second.funding_txid()), "nextCapacity": second.capacity}));
    let e = c.rollover(PROVIDER).unwrap_err();
    assert_eq!(e.code, "rollover_unproven", "{}", e.msg);
    assert_eq!(c.channels[PROVIDER].payer.params, old, "the live channel is still the one that was rolled");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().chan, old.channel_id());

    // the embedder sees attempt 1 on chain and adopts its next channel: bound, with its refund
    let next = c.next_rolled[PROVIDER].iter().find(|n| n.payer.params.funding_txid() == on_chain).expect("the record of the attempt on chain is kept").payer.params.clone();
    assert_eq!(rig.chain.unspent_to(&hex::encode(next.spk())), next.capacity as i64, "the next channel of the first attempt is funded on chain");
    c.adopt_rolled(PROVIDER, &on_chain).unwrap();
    let refund = Tx::parse_hex(&c.channels[PROVIDER].refund_hex).unwrap();
    assert_eq!((refund.inputs[0].prevout.txid_hex(), refund.inputs[0].prevout.vout, refund.locktime), (on_chain.clone(), 1, next.expiry));
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((rec.chan.as_str(), rec.state.as_str()), (next.channel_id().as_str(), "open"), "the signer's live channel is the one on chain");
    // and the channel pays on
    c.open_rolled(PROVIDER).unwrap();
    assert_eq!(c.request("GET", URL, b"").unwrap().status, 200);
    assert_eq!(c.channels[PROVIDER].payer.params.channel_id(), next.channel_id());
}

/// Item 6 with the shipped terms and the real signer: the hot wallet is empty, so the signer
/// refuses the first `fund`. The owner tops it up. The payer's next call pays, one block later
/// (the same channel) and a hundred blocks later (past the retry floor: derived again for the key
/// the signer answers again, which is the one it issued).
#[test]
fn a_fund_the_signer_refused_does_not_end_the_payers_business_with_the_seller() {
    for later in [1, 100] {
        let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
        let rig = Rig::new(json!({"hot_balance_cap_sats": 0}), false);
        let sock = rig.dir.path().join("signer.sock");
        let _srv = xbt_signer::server::spawn(rig.s.clone(), &sock, false).unwrap();
        let remote = RemoteSigner::new(&sock);
        let signer: Arc<dyn StateSigner> = Arc::new(remote.clone());
        let mut cfg = ClientConfig::new(&rig.chain.network());
        (cfg.capacity, cfg.max_price) = (10_000, 500);
        let chain = rig.chain.clone();
        let mut c = Client::new(cfg, Box::new(Seller { web: rig.web.clone(), n: AtomicUsize::new(0), forged: Arc::new(Mutex::new(None)) }),
                                Box::new(ConfirmingWallet(remote.clone(), rig.chain.clone())), Box::new(move || Ok(chain.height() as u32))).with_signer(signer);
        let e = c.request("GET", URL, b"").unwrap_err();
        assert!(rig.s.book.get(PROVIDER).is_none(), "the signer funded nothing: {} {}", e.code, e.msg);
        let derived = c.channels[PROVIDER].payer.params.clone();
        assert_eq!((c.channels[PROVIDER].stage, derived.expiry as u64), (Stage::Keyed, rig.chain.height() + 1_153));
        rig.fund_hot(1, 30_000);
        rig.chain.mine(later);
        let r = c.request("GET", URL, b"").unwrap_or_else(|e| panic!("{later} blocks later: {} {}", e.code, e.msg));
        assert_eq!(r.status, 200);
        let p = &c.channels[PROVIDER].payer.params;
        assert_eq!(p.payer_pub, derived.payer_pub, "the key the signer issued");
        assert_eq!(p.expiry == derived.expiry, later == 1, "{later} blocks later");
        assert_eq!(rig.s.book.get(PROVIDER).unwrap().state, "open");
    }
}

/// The wallet of the shipped signer-backed payers (`xbt-signer-payer`, `xbt-wallet-mcp` with
/// `XBT_MCP_PAYER=local`: their `Funding`): the signer's `fund`, then a wait for the funding's
/// confirmations that gives up after 180 s with `funding_unconfirmed`. Here the wait gives up at
/// once the first time. Unlike theirs it passes the wallet's two "what did you send" questions on
/// to the signer client, so that this test passes as soon as that client answers them.
struct GivesUp(RemoteSigner, Arc<FakeChain>, AtomicBool);

impl Wallet for GivesUp {
    fn fund(&self, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
        self.0.fund(a, s)
    }

    fn fund_channel(&self, o: &str, p: &xbt402::channel::ChannelParams, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
        let r = self.0.fund_channel(o, p, a, s)?;
        if !self.2.swap(true, Ordering::SeqCst) {
            return Err(ChannelError::new("funding_unconfirmed", "the funding did not confirm in time"));
        }
        self.1.mine(1);
        Ok(r)
    }

    fn wallet_sends_to(&self, a: &str) -> xbt402::Result<Vec<String>> {
        self.0.wallet_sends_to(a)
    }

    fn wallet_send(&self, t: &str, a: &str) -> xbt402::Result<Option<WalletSend>> {
        self.0.wallet_send(t, a)
    }
}

/// HOLE (Medium for availability; no coin is lost; found by AGP-096, in the wallet's files, not
/// fixed). The signer's `fund` records the channel and moves the issued key to it before it
/// broadcasts (write-ahead, AGP-063). When the caller then learns nothing of the outpoint (the
/// payers' wait for a confirmation ran out, which on a chain with ten-minute blocks is the usual
/// case after 180 s; or the socket call timed out), the library client's channel stays `Keyed`
/// with no outpoint. Its retry asks the wallet what it sent (`Wallet::wallet_sends_to`), which
/// `RemoteSigner` and the payers' `Funding` do not answer, and then asks the signer to fund the
/// same channel again: `bad_key`, the key is no longer in its issued slot. Once the client derives
/// the channel again it is `channel_pending` instead. The seller cannot be paid through this
/// payer until the signer has refunded the first funding at its expiry (1,153 blocks with the
/// shipped provider), though that funding confirmed a block later and the signer holds everything
/// needed to open it.
///
/// What should hold: the retry adopts the funding the signer made. `RemoteSigner` can answer
/// `wallet_sends_to` and `wallet_send` from the signer's pending record of the destination, and
/// the two `Funding` wrappers can pass them on.
#[test]
fn hole_a_funding_the_signer_made_but_the_caller_never_heard_of_is_adopted_by_the_retry() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 0}), false);
    rig.fund_hot(1, 30_000);
    let sock = rig.dir.path().join("signer.sock");
    let _srv = xbt_signer::server::spawn(rig.s.clone(), &sock, false).unwrap();
    let remote = RemoteSigner::new(&sock);
    let signer: Arc<dyn StateSigner> = Arc::new(remote.clone());
    let mut cfg = ClientConfig::new(&rig.chain.network());
    (cfg.capacity, cfg.max_price) = (10_000, 500);
    let chain = rig.chain.clone();
    let mut c = Client::new(cfg, Box::new(Seller { web: rig.web.clone(), n: AtomicUsize::new(0), forged: Arc::new(Mutex::new(None)) }),
                            Box::new(GivesUp(remote.clone(), rig.chain.clone(), AtomicBool::new(false))), Box::new(move || Ok(chain.height() as u32))).with_signer(signer);
    assert_eq!(c.request("GET", URL, b"").unwrap_err().code, "funding_unconfirmed");
    assert_eq!(c.channels[PROVIDER].stage, Stage::Keyed);
    let pending = rig.s.book.get(PROVIDER).expect("the signer recorded the channel it funded");
    assert_eq!((pending.state.as_str(), rig.chain.unspent_to(&hex::encode(c.channels[PROVIDER].payer.params.spk()))), ("pending", 10_000));
    // the funding confirms; the caller tries again, now and for a day of blocks
    rig.chain.mine(1);
    let mut out = vec![];
    for _ in 0..8 {
        out.push(c.request("GET", URL, b"").map(|r| r.status).map_err(|e| e.code));
        rig.chain.mine(20);
    }
    assert!(out.contains(&Ok(200)), "the signer funded {} sat to this seller's channel and the payer can never open it: {out:?}; the signer's record is {:?}",
            pending.funding_sats, rig.s.book.get(PROVIDER).map(|r| r.state));
}
