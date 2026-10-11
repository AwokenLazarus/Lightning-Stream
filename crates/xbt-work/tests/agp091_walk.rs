//! AGP-091, fix wave 4, pay-with-work: the audit walk (WORK 4), the caps under the pricing rule in
//! force (WORK 2) and the admin token (WORK 7). These use what the fix added (`walk::Walk`,
//! `WorkConfig::cap_rule`, `provider::admin_request`), so they cannot run on the audit's branch;
//! the result note says how each was seen to fail first.
use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::json;
use xbt_work::audit::{PrimeTerms, WindowStatement};
use xbt_work::book::CreditCaps;
use xbt_work::chain::ChainBlock;
use xbt_work::provider::{admin_request, admin_token, Amount, Cap, Caps, ServedStatement, WorkConfig, WorkProvider, SETTLE_DEPTH};
use xbt_work::receipt::{PrimeKey, WorkReceipt};
use xbt_work::walk::{AuditSource, Walk};
use xbt_work::{Result, WorkError};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const MAIN_BITS: u32 = 0x1a00_f0b5;
const MAIN_V: u64 = 312_500_000;

fn key() -> PrimeKey { PrimeKey::from_seed(70, &[9u8; 32]) }
fn config(k: &PrimeKey) -> WorkConfig {
    WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, 150)
}
fn hash(h: u32) -> String { format!("{h:064x}") }
fn window_work() -> u64 { PrimeTerms::default().window_target(MAIN_BITS).unwrap() }
fn share(work: u64) -> u64 { (u128::from(MAIN_V) * u128::from(work) / u128::from(window_work())) as u64 }
fn credit(k: &PrimeKey, wp: &WorkProvider, cum: u64) -> String {
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    let r = WorkReceipt { seq: 1, cum_work: cum, shares: 1, first_height: 101, last_height: 102, difficulty: 1, ..WorkReceipt::zero(70, PROV, &inv) };
    wp.accept(&k.sign(&r).unwrap()).unwrap();
    inv
}
fn state_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp091-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What the Prime answers for a height.
#[derive(Clone)]
enum Prime {
    /// A statement with this window start.
    Statement(u32),
    /// 404: it has none.
    None,
    /// Anything else: an error status, a body that is no statement.
    Garbage(&'static str),
}

/// The provider's node and the Prime, in memory.
struct World {
    k: PrimeKey,
    /// What each coinbase pays the identity (0 when not listed).
    paid: Mutex<HashMap<u32, u64>>,
    prime: Mutex<HashMap<u32, Prime>>,
    /// The node fails from this height up.
    node_down: Mutex<Option<u32>>,
    /// How often each height's statement was asked for.
    asked: Mutex<HashMap<u32, u32>>,
}

impl World {
    fn new() -> Self {
        Self { k: key(), paid: Mutex::new(HashMap::new()), prime: Mutex::new(HashMap::new()), node_down: Mutex::new(None), asked: Mutex::new(HashMap::new()) }
    }
    fn pays(&self, h: u32, sats: u64) { self.paid.lock().unwrap().insert(h, sats); }
    fn answers(&self, h: u32, p: Prime) { self.prime.lock().unwrap().insert(h, p); }
    fn asked(&self, h: u32) -> u32 { self.asked.lock().unwrap().get(&h).copied().unwrap_or(0) }
}

impl AuditSource for World {
    fn block(&self, height: u32) -> Result<ChainBlock> {
        if self.node_down.lock().unwrap().is_some_and(|d| height >= d) {
            return Err(WorkError::new("node", "connection refused"));
        }
        let paid = self.paid.lock().unwrap().get(&height).copied().unwrap_or(0);
        Ok(ChainBlock { height, hash: hash(height), value_sats: MAIN_V, paid_sats: paid, bits: MAIN_BITS, prev_bits: MAIN_BITS })
    }

    fn statement(&self, height: u32) -> Result<Option<ServedStatement>> {
        *self.asked.lock().unwrap().entry(height).or_insert(0) += 1;
        match self.prime.lock().unwrap().get(&height).cloned().unwrap_or(Prime::None) {
            Prime::None => Ok(None),
            Prime::Garbage(why) => Err(WorkError::new("prime", format!("window statement for {height}: {why}"))),
            Prime::Statement(ws) => {
                let s = WindowStatement { prime_id: 70, height, block_hash: hash(height), window_start: ws, window_work: window_work(), min_payout: 546, fee_bps: 0 };
                let sw = self.k.sign_window(&s).unwrap();
                let doc = sw.line_doc();
                Ok(Some((sw, vec![], doc)))
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// WORK 4. The rule: no answer of the Prime's stops the walk.
// ------------------------------------------------------------------------------------------------

/// A Prime that answers 500 (or a body that is no statement) for one height, for ever, on a block
/// that underpaid: the walk goes on, the blocks after it are audited and their payments cover
/// credit, and the block itself has no verdict and covers nothing. Before, the loop in the binary
/// stopped at that height and tried it every 2 s for ever (the audit's rig S2).
#[test]
fn w4_a_prime_that_fails_one_statement_for_ever_does_not_stop_the_walk() {
    for garbage in ["HTTP 500", "HTTP 503", "window statement is not JSON", "no sig"] {
        let k = key();
        let wp = WorkProvider::new(config(&k)).unwrap();
        credit(&k, &wp, 800);
        let w = World::new();
        // 105 is the Prime's block: it underpaid and the Prime will not serve its statement
        w.pays(105, 1);
        w.answers(105, Prime::Garbage(garbage));
        // 110 and 115 are honest blocks of the same Prime
        for h in [110, 115] {
            w.pays(h, share(800));
            w.answers(h, Prime::Statement(100));
        }
        let mut walk = Walk::new(103);
        let mut verdicts = vec![];
        for _ in 0..50 {
            let p = walk.pass(&wp, &w, 120);
            assert!(p.stopped.is_none(), "{garbage}: the walk stopped: {:?}", p.stopped);
            verdicts.extend(p.verdicts);
        }
        assert_eq!(walk.next(), 121, "{garbage}: the walk is stuck");
        assert_eq!(verdicts, vec![(110, true), (115, true)], "{garbage}");
        assert_eq!(walk.waiting(), vec![105], "{garbage}");
        let r = wp.report();
        assert!(r["distrust"].is_null(), "{garbage}: an answer nobody signed distrusted the Prime");
        assert!(!r["audits"].as_array().unwrap().iter().any(|a| a["height"] == json!(105)), "{garbage}: a verdict for 105");
        // the two honest blocks paid for a quarter of the credit and a bit; the sat at 105 for nothing
        let two = 2 * wp.paid_work(&w.block(110).unwrap()).unwrap();
        assert_eq!(wp.exposure().0, 800 - two, "{garbage}");
    }
}

/// The statement arrives later (the Prime was down): the block is audited then, and what its
/// coinbase paid covers credit. An honest Prime's outage costs nobody anything.
#[test]
fn w4_a_block_is_audited_when_the_prime_answers_again() {
    let k = key();
    let wp = WorkProvider::new(config(&k)).unwrap();
    credit(&k, &wp, 800);
    let w = World::new();
    w.pays(105, share(800));
    w.answers(105, Prime::Garbage("HTTP 502"));
    let mut walk = Walk::new(103);
    let p = walk.pass(&wp, &w, 120);
    assert_eq!((p.verdicts, p.unavailable.len(), walk.next()), (Vec::<(u32, bool)>::new(), 1, 121));
    assert_eq!(wp.exposure().0, 800, "an unanswered statement covered credit");
    assert_eq!(wp.report()["unpaidBlocks"]["count"], json!(18), "every block of the pass is counted once while credit is unpaid");
    w.answers(105, Prime::Statement(100));
    let mut verdicts = vec![];
    for _ in 0..4 {
        verdicts.extend(walk.pass(&wp, &w, 120).verdicts);
    }
    assert_eq!((verdicts, walk.waiting()), (vec![(105, true)], Vec::<u32>::new()));
    assert_eq!(wp.exposure().0, 800 - wp.paid_work(&w.block(105).unwrap()).unwrap());
    // a Prime that then says it has none (404) is taken at its word: not asked again
    let k = key();
    let wp = WorkProvider::new(config(&k)).unwrap();
    let w = World::new();
    w.answers(105, Prime::Garbage("HTTP 500"));
    let mut walk = Walk::new(103);
    walk.pass(&wp, &w, 110);
    w.answers(105, Prime::None);
    walk.pass(&wp, &w, 110);
    assert!(walk.waiting().is_empty());
}

/// A statement the Prime keeps failing to serve is asked for less and less often (never more than
/// once in 64 passes after the first few), and not at all once the block is deeper than the settle
/// depth: the cost of a Prime that fails on purpose is bounded.
#[test]
fn w4_a_failing_statement_is_asked_for_less_often_and_not_for_ever() {
    let k = key();
    let wp = WorkProvider::new(config(&k)).unwrap();
    let w = World::new();
    for h in 103..=110 {
        w.answers(h, Prime::Garbage("HTTP 500"));
    }
    let mut walk = Walk::new(103);
    for _ in 0..1000 {
        walk.pass(&wp, &w, 120);
    }
    assert_eq!(walk.waiting(), (103..=110).collect::<Vec<u32>>());
    for h in 103..=110 {
        assert!((16..=24).contains(&w.asked(h)), "height {h} asked for {} times in 1000 passes", w.asked(h));
    }
    // the chain moves on: past the settle depth they stay blocks with no statement
    let asked = w.asked(103);
    for to in [103 + SETTLE_DEPTH - 1, 103 + SETTLE_DEPTH, 110 + SETTLE_DEPTH] {
        walk.pass(&wp, &w, to);
    }
    assert!(walk.waiting().is_empty());
    for _ in 0..200 {
        walk.pass(&wp, &w, 110 + SETTLE_DEPTH);
    }
    assert!(w.asked(103) <= asked + 1);
}

/// The provider's own node is what the walk waits for: it stops there, audits nothing above, and
/// goes on from that height when the node answers.
#[test]
fn w4_the_node_is_the_only_thing_the_walk_waits_for() {
    let k = key();
    let wp = WorkProvider::new(config(&k)).unwrap();
    credit(&k, &wp, 800);
    let w = World::new();
    w.pays(110, share(800));
    w.answers(110, Prime::Statement(100));
    *w.node_down.lock().unwrap() = Some(107);
    let mut walk = Walk::new(103);
    let p = walk.pass(&wp, &w, 120);
    assert_eq!((walk.next(), p.stopped.map(|(h, _)| h), p.verdicts), (107, Some(107), Vec::<(u32, bool)>::new()));
    assert_eq!(w.asked(110), 0);
    *w.node_down.lock().unwrap() = None;
    assert_eq!(walk.pass(&wp, &w, 120).verdicts, vec![(110, true)]);
    assert_eq!(walk.next(), 121);
}

/// The position is kept in the provider's state, so a provider that was down goes on where it
/// stopped (it started 100 blocks below the tip each time, and skipped what lay between); a reorg
/// walks the changed heights again.
#[test]
fn w4_the_position_survives_a_restart_and_a_reorg_rewinds_it() {
    let dir = state_dir("walk");
    let k = key();
    let cfg = WorkConfig { state_path: Some(dir.join("work.json")), ..config(&k) };
    let wp = WorkProvider::new(cfg.clone()).unwrap();
    assert_eq!(wp.audit_position(), None);
    let w = World::new();
    w.answers(118, Prime::Garbage("HTTP 500"));
    let mut walk = Walk::new(103);
    walk.pass(&wp, &w, 120);
    drop(wp);
    let wp = WorkProvider::new(cfg).unwrap();
    assert_eq!(wp.audit_position(), Some(121));
    walk.rewind(115);
    assert_eq!((walk.next(), walk.waiting()), (115, Vec::<u32>::new()));
    walk.pass(&wp, &w, 120);
    assert_eq!((walk.next(), walk.waiting(), w.asked(116), w.asked(114)), (121, vec![118], 2, 1));
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------------------------------------
// WORK 2. The rule: a cap in calls is that many calls at what a call costs under the rule in force.
// ------------------------------------------------------------------------------------------------

/// As many invoices as it takes, each with far more receipted work than any cap: the calls of
/// unpaid credit the provider extends.
fn calls_of_unpaid_credit(wp: &WorkProvider, k: &PrimeKey) -> u64 {
    for _ in 0..200 {
        credit(k, wp, 1_000_000_000);
    }
    wp.book().credited.values().sum::<u64>() / wp.amount(150).unwrap()
}

/// The shipped caps ("100 calls per invoice, 1,000 in total") under every way a call can be
/// priced: `--work-units 1`, `--work-units 7`, `--work-units 1000` and exact pricing. Before, they
/// were computed at exact pricing whatever the flag made a call cost: 9,000 calls at `--work-units 1`.
#[test]
fn w2_the_shipped_cap_is_in_calls_under_every_pricing_rule() {
    let k = key();
    for units in [1u64, 7, 1000] {
        let wp = WorkProvider::new(WorkConfig { amount: Amount::Fixed(units), ..config(&k) }).unwrap();
        assert_eq!(wp.caps(), CreditCaps { per_invoice: Some(100 * units), total: Some(1000 * units) }, "--work-units {units}");
        assert_eq!(wp.cfg.caps, wp.caps(), "the configuration still says something else");
        assert_eq!(calls_of_unpaid_credit(&wp, &k), 1000, "--work-units {units}");
    }
    // exact pricing: the cap is in whole calls' worth of work before the haircut, so a little under
    let wp = WorkProvider::new(config(&k)).unwrap();
    assert_eq!((wp.amount(150).unwrap(), wp.caps().total), (10, Some(9000)));
    assert_eq!(calls_of_unpaid_credit(&wp, &k), 900);
}

/// The other ways to set a cap, under a fixed amount per call: in sats (at the invoice price), in
/// work units (as given), off; and a cap in sats with no sats price cannot be converted and holds
/// everything rather than lifting the cap.
#[test]
fn w2_caps_in_sats_and_work_under_a_fixed_amount() {
    let k = key();
    let with = |rule: Caps, amount: Amount, price: u64| {
        let cfg = WorkConfig { cap_rule: Some(rule), amount, invoice_price_sats: price, ..config(&k) };
        WorkProvider::new(cfg).unwrap().caps()
    };
    let sats = Caps { invoice: Cap::Sats(15_000), total: Cap::Sats(150_000) };
    assert_eq!(with(sats, Amount::Fixed(7), 150), CreditCaps { per_invoice: Some(700), total: Some(7000) });
    assert_eq!(with(sats, Amount::Fixed(1), 150), CreditCaps { per_invoice: Some(100), total: Some(1000) });
    assert_eq!(with(sats, Amount::Fixed(1), 0), CreditCaps { per_invoice: Some(0), total: Some(0) }, "an unconvertible cap lifted the cap");
    let work = Caps { invoice: Cap::Work(5), total: Cap::Off };
    assert_eq!(with(work, Amount::Fixed(7), 150), CreditCaps { per_invoice: Some(5), total: None });
    assert_eq!(Cap::Calls(u64::MAX).units_under(&Amount::Fixed(7), 150).unwrap(), Some(u64::MAX), "overflow");
    assert_eq!(Cap::Sats(u64::MAX).units_under(&Amount::Fixed(u64::MAX), 1).unwrap(), Some(u64::MAX), "overflow");
    // an embedder that sets the caps in work units itself (no rule) keeps them
    let own = CreditCaps { per_invoice: Some(3), total: Some(4) };
    let cfg = WorkConfig { cap_rule: None, caps: own, amount: Amount::Fixed(7), ..config(&k) };
    assert_eq!(WorkProvider::new(cfg).unwrap().caps(), own);
}

/// The caps follow the epoch inside the provider (the binary did it, from its own copy of the
/// numbers): at a lower difficulty a call is fewer work units and the cap in calls is too. They
/// are derived again at each start, never read from the state.
#[test]
fn w2_caps_in_calls_follow_the_epoch_and_a_restart() {
    let dir = state_dir("caps");
    let k = key();
    let cfg = WorkConfig { state_path: Some(dir.join("work.json")), ..config(&k) };
    let wp = WorkProvider::new(cfg.clone()).unwrap();
    let easier = 0x1b00_f0b5u32;
    assert!(wp.set_epoch(easier, MAIN_V));
    assert_eq!(wp.caps(), Caps::SHIPPED.at(easier, MAIN_V, 150));
    assert!(wp.caps().total.unwrap() < Caps::SHIPPED.at(MAIN_BITS, MAIN_V, 150).total.unwrap());
    assert!(!wp.set_epoch(easier, MAIN_V), "the same epoch again");
    // a fixed amount does not move with the epoch, and neither does its cap
    let fixed = WorkProvider::new(WorkConfig { amount: Amount::Fixed(3), ..config(&k) }).unwrap();
    assert!(!fixed.set_epoch(easier, MAIN_V));
    assert_eq!(fixed.caps().total, Some(3000));
    drop(wp);
    assert_eq!(WorkProvider::new(cfg).unwrap().caps(), Caps::SHIPPED.at(MAIN_BITS, MAIN_V, 150), "the caps came from the state file");
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------------------------------------
// WORK 7. The rule: an admin request proves it comes from the operator by carrying the token.
// ------------------------------------------------------------------------------------------------

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Behind a proxy on the same host every client is a loopback peer: the peer address alone opens
/// nothing. With the token and a loopback peer it opens; with the token from anywhere else, a
/// wrong one, a prefix, two of them, or none, it does not.
#[test]
fn w7_the_admin_endpoints_need_the_token_not_a_loopback_peer() {
    let token = "5f".repeat(32);
    let bearer = format!("Bearer {token}");
    let ok = |h: &[(&str, &str)], peer: Option<&str>| admin_request(&headers(h), peer, &token);
    // what a client behind nginx on the same host looks like: loopback peer, no token
    assert!(!ok(&[("Host", "api.example"), ("X-Forwarded-For", "198.51.100.7")], Some("127.0.0.1")));
    assert!(!ok(&[], Some("127.0.0.1")));
    assert!(!ok(&[], Some("::1")));
    assert!(ok(&[("Authorization", &bearer)], Some("127.0.0.1")));
    assert!(ok(&[("authorization", &bearer)], Some("::1")));
    for (what, h, peer) in [("another host", vec![("Authorization", bearer.as_str())], Some("203.0.113.9")),
                            ("no peer", vec![("Authorization", bearer.as_str())], None),
                            ("a peer that is no address", vec![("Authorization", bearer.as_str())], Some("localhost")),
                            ("the bare token", vec![("Authorization", token.as_str())], Some("127.0.0.1")),
                            ("another scheme", vec![("Authorization", "Basic NWY1ZjVm")], Some("127.0.0.1")),
                            ("a prefix", vec![("Authorization", &bearer[..bearer.len() - 1])], Some("127.0.0.1")),
                            ("an empty token", vec![("Authorization", "Bearer ")], Some("127.0.0.1")),
                            ("two headers", vec![("Authorization", "Bearer x"), ("Authorization", bearer.as_str())], Some("127.0.0.1")),
                            ("the token in another header", vec![("X-Admin-Token", token.as_str())], Some("127.0.0.1"))] {
        assert!(!ok(&h, peer), "{what} opened the admin endpoints");
    }
    // a provider configured with no usable token opens for nobody, whatever is sent
    assert!(!admin_request(&headers(&[("Authorization", "Bearer ")]), Some("127.0.0.1"), ""));
    assert!(!admin_request(&headers(&[("Authorization", "Bearer short")]), Some("127.0.0.1"), "short"));
}

/// The token file: made once (0600), read back the same, and a file that is there but holds no
/// token is an error, never a silently new token.
#[test]
fn w7_the_admin_token_file_is_made_once_and_kept_private() {
    let dir = state_dir("admin");
    let path = dir.join("admin.token");
    let t = admin_token(&path).unwrap();
    assert_eq!(t.len(), 64);
    assert_eq!(admin_token(&path).unwrap(), t);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    std::fs::write(&path, "").unwrap();
    assert_eq!(admin_token(&path).unwrap_err().code, "bad_config");
    std::fs::write(&path, "too short\n").unwrap();
    assert!(admin_token(&path).is_err());
    assert_ne!(admin_token(&dir.join("other.token")).unwrap(), t);
    let _ = std::fs::remove_dir_all(&dir);
}
