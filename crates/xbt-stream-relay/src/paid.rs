//! A paid relay (`docs/PAID-RELAYS.md`): each app pays its own home relay, and only that relay,
//! for the bytes it receives there.
//!
//! In iroh a packet is relayed through its receiver's home relay: a buyer's requests reach a shop
//! through the shop's home relay, and the shop's answers reach the buyer through the buyer's. So a
//! relayed session crosses two relays, one each way, and each side pays the relay it chose for what
//! that relay brings it. Nobody pays a relay it didn't choose.
//!
//! - **Home.** A link key is homed here once it says so: a balance read signed with the key and
//!   `home=1` ([`crate::credit`]) declares it for [`HOME_TTL_S`], and the app's payer renews it
//!   every minute. Crediting a key is a gift and declares nothing, so a key nobody has declared is
//!   never charged, whatever credit it was given.
//! - **Accounts.** Credit is bought one credit at a time ([`PaidSettings::credit_bytes`], 10 GB by
//!   default) through the operator's seller route, which calls the credit API once per paid request.
//!   The balance is kept in bytes, bought at the price of the moment.
//! - **Charging.** Every relayed packet is charged once, by its datagrams' length: first to its
//!   receiver's free allowance ([`PaidSettings::free_bytes_per_day`], 64 MB a day by default, as
//!   the relay announces it), then to its **receiver** when the receiver is homed here. iroh may
//!   also hand a reply to the relay the request came through (a shop answering a buyer whose home
//!   it doesn't know): its receiver isn't homed here and didn't choose it, so such a packet is
//!   charged to its **sender** when the sender is homed here (it chose this relay), and otherwise
//!   only the receiver's free allowance carries it.
//! - **Running out.** An account may go [`PaidSettings::grace_bytes`] below zero while its next
//!   credit is on its way. Past that its traffic **waits** for the next credit: the relay holds the
//!   packet and slows its sender ([`Forward::Hold`]) for up to [`HOLD_S`]. If no credit comes in
//!   that time, the packets are dropped and counted on the account (`dropped_bytes`, `waiting`),
//!   which the app reads and shows its owner, until it pays again. A packet nobody pays for, past
//!   the free allowance, is not carried.
//!
//! The relay never sees what it carries: only the keys, the lengths and when.
use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::meter::{Forward, Meter};

/// A gigabyte, as prices are stated: 10^9 bytes.
pub const GB: u64 = 1_000_000_000;
/// The suggested price, 2 sats per GB (`docs/RUN-A-RELAY.md`).
pub const DEFAULT_MSAT_PER_GB: u64 = 2_000;
/// One credit, what one paid request to the operator's seller route buys: 10 GB.
pub const DEFAULT_CREDIT_BYTES: u64 = 10 * GB;
pub const DEFAULT_GRACE_BYTES: u64 = 256 << 20;
/// 64 MB a day, free to every key, for what it receives (hole punching, address discovery, a
/// buyer's requests to a shop that doesn't pay this relay).
pub const DEFAULT_FREE_BYTES_PER_DAY: u64 = 64 << 20;
/// A home declared by a signed balance read lasts this long; the app's payer renews it every
/// minute, so a key that has moved its home elsewhere stops being charged here within it.
pub const HOME_TTL_S: u64 = 900;
/// Past the grace an account's traffic waits this long for the next credit, then is dropped
/// (counted) until it pays: shorter than iroh-relay's longest hold.
pub const HOLD_S: u64 = 8;
/// The smallest credit: a megabyte.
pub const MIN_CREDIT_BYTES: u64 = 1_000_000;
const DAY_S: u64 = 86_400;

/// The operator's terms (`relay.json` `paid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidSettings {
    pub enabled: bool,
    pub msat_per_gb: u64,
    /// The bytes one paid credit request buys; its price is [`PaidSettings::credit_msat`].
    pub credit_bytes: u64,
    pub grace_bytes: u64,
    pub free_bytes_per_day: u64,
    /// The secret the operator's gateway sends to the credit API (`x-relay-credit-token`).
    pub credit_token: String,
}

impl Default for PaidSettings {
    fn default() -> Self {
        Self { enabled: false, msat_per_gb: DEFAULT_MSAT_PER_GB, credit_bytes: DEFAULT_CREDIT_BYTES, grace_bytes: DEFAULT_GRACE_BYTES,
               free_bytes_per_day: DEFAULT_FREE_BYTES_PER_DAY, credit_token: String::new() }
    }
}

/// The shortest credit token taken.
pub const MIN_TOKEN: usize = 32;

impl PaidSettings {
    /// From `relay.json`'s `paid` object; absent or `null`: off.
    pub fn from_value(v: &Value) -> Self {
        let d = Self::default();
        let n = |k: &str, d: u64| v.get(k).and_then(Value::as_u64).unwrap_or(d);
        Self {
            enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
            msat_per_gb: n("msat_per_gb", d.msat_per_gb),
            credit_bytes: n("credit_bytes", d.credit_bytes),
            grace_bytes: n("grace_bytes", d.grace_bytes),
            free_bytes_per_day: n("free_bytes_per_day", d.free_bytes_per_day),
            credit_token: v.get("credit_token").and_then(Value::as_str).unwrap_or("").to_string(),
        }
    }

    pub fn to_value(&self) -> Value {
        json!({"enabled": self.enabled, "msat_per_gb": self.msat_per_gb, "credit_bytes": self.credit_bytes, "grace_bytes": self.grace_bytes,
               "free_bytes_per_day": self.free_bytes_per_day, "credit_token": self.credit_token})
    }

    /// What the terms can't run with, in words; empty when they can.
    pub fn problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.msat_per_gb == 0 {
            v.push("A paid relay needs a price above 0 per GB.".to_string());
        }
        if self.credit_bytes < MIN_CREDIT_BYTES {
            v.push("One credit must buy at least a megabyte.".to_string());
        }
        if self.credit_token.len() < MIN_TOKEN {
            v.push(format!("The credit token must be at least {MIN_TOKEN} characters."));
        }
        v
    }

    /// What one credit costs, in msat: its bytes at the price per GB, rounded up. The operator's
    /// seller route is priced at this.
    pub fn credit_msat(&self) -> u64 {
        credit_msat(self.credit_bytes, self.msat_per_gb)
    }

    /// The terms as apps read them (`GET /terms`, and the announcement): never the token.
    pub fn terms(&self) -> Value {
        json!({"msat_per_gb": self.msat_per_gb, "credit_bytes": self.credit_bytes, "credit_msat": self.credit_msat(),
               "grace_bytes": self.grace_bytes, "free_bytes_per_day": self.free_bytes_per_day, "home_ttl_s": HOME_TTL_S, "hold_s": HOLD_S})
    }
}

/// What `bytes` cost at `msat_per_gb`, rounded up.
pub fn credit_msat(bytes: u64, msat_per_gb: u64) -> u64 {
    u64::try_from((u128::from(bytes) * u128::from(msat_per_gb)).div_ceil(u128::from(GB))).unwrap_or(u64::MAX)
}

/// One app's account at its home relay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    /// Bytes bought minus bytes charged; below zero by at most the grace.
    pub balance: i64,
    pub credited_msat: u64,
    pub credited_bytes: u64,
    /// Bytes charged for what the app received here, and for what it sent here to a peer not homed
    /// here (iroh's reply on the relay a request came through).
    pub charged_in: u64,
    pub charged_out: u64,
    /// Bytes it received here free (its daily allowance).
    pub free_bytes: u64,
    /// Bytes dropped after waiting [`HOLD_S`] for credit, and their packets.
    pub dropped_bytes: u64,
    pub dropped: u64,
    /// Homed here until (Unix seconds); 0: never declared.
    pub home_until: u64,
    /// When its traffic began to wait for credit; 0: it isn't waiting.
    waiting_since: u64,
}

impl Account {
    fn home(&self, now: u64) -> bool {
        self.home_until > now
    }

    fn to_value(&self, key: &[u8; 32], s: &PaidSettings, now: u64) -> Value {
        json!({"key": hex::encode(key), "balance_bytes": self.balance, "credited_msat": self.credited_msat,
               "credited_bytes": self.credited_bytes, "charged_in": self.charged_in, "charged_out": self.charged_out,
               "free_bytes": self.free_bytes, "dropped_bytes": self.dropped_bytes, "home": self.home(now), "home_until": self.home_until,
               "waiting": self.waiting_since != 0, "carrying": self.balance > -(s.grace_bytes as i64)})
    }

    fn saved(&self) -> Value {
        json!({"balance": self.balance, "credited_msat": self.credited_msat, "credited_bytes": self.credited_bytes,
               "charged_in": self.charged_in, "charged_out": self.charged_out, "free_bytes": self.free_bytes,
               "dropped_bytes": self.dropped_bytes, "dropped": self.dropped, "home_until": self.home_until})
    }

    fn from_saved(v: &Value) -> Self {
        let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        Self { balance: v.get("balance").and_then(Value::as_i64).unwrap_or(0), credited_msat: n("credited_msat"), credited_bytes: n("credited_bytes"),
               charged_in: n("charged_in"), charged_out: n("charged_out"), free_bytes: n("free_bytes"), dropped_bytes: n("dropped_bytes"),
               dropped: n("dropped"), home_until: n("home_until"), waiting_since: 0 }
    }

    /// Can `len` more bytes be charged without passing the grace?
    fn covers(&self, len: u64, grace: u64) -> bool {
        self.balance.saturating_sub(len as i64) >= -(grace as i64)
    }
}

#[derive(Debug, Default)]
struct State {
    accounts: HashMap<[u8; 32], Account>,
    /// A key's free bytes received today: (day, bytes).
    free: HashMap<[u8; 32], (u64, u64)>,
    connected: HashMap<[u8; 32], usize>,
    /// Bytes carried on free allowances, and bytes not carried: nobody paid for them.
    free_carried: u64,
    unpaid_bytes: u64,
}

/// The paid relay's meter.
pub struct Paid {
    settings: Mutex<PaidSettings>,
    state: Mutex<State>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for Paid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paid").finish_non_exhaustive()
    }
}

/// Who carried a packet, or why not, for tests and the status page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// Charged to its receiver, homed here.
    In,
    /// Charged to its sender, homed here, the receiver not.
    Out,
    /// Carried on its receiver's free allowance.
    Free,
    /// Held: its payer is out of credit, and its traffic waits for the next.
    Wait,
    /// Dropped after waiting too long for its payer's credit (counted on the account).
    Dropped,
    /// Not carried: nobody pays for it, and the free allowance is used up.
    Unpaid,
}

impl Paid {
    pub fn new(settings: PaidSettings) -> Self {
        Self::with_clock(settings, Box::new(crate::status::now))
    }

    /// With the clock given (Unix seconds): for tests.
    pub fn with_clock(settings: PaidSettings, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self { settings: Mutex::new(settings), state: Mutex::default(), clock }
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn settings(&self) -> PaidSettings {
        self.settings.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// New terms take effect for bytes from now on; balances already bought stand.
    pub fn set_settings(&self, s: PaidSettings) {
        *self.settings.lock().unwrap_or_else(|p| p.into_inner()) = s;
    }

    /// One paid credit for `key`, at the terms of the moment: what the account shows after it.
    /// It declares no home: a key is charged only once its holder has declared it.
    pub fn credit(&self, key: &[u8; 32]) -> Value {
        let s = self.settings();
        let now = (self.clock)();
        let mut st = self.st();
        let a = st.accounts.entry(*key).or_default();
        a.balance = a.balance.saturating_add(i64::try_from(s.credit_bytes).unwrap_or(i64::MAX));
        a.credited_msat = a.credited_msat.saturating_add(s.credit_msat());
        a.credited_bytes = a.credited_bytes.saturating_add(s.credit_bytes);
        a.to_value(key, &s, now)
    }

    /// `key`'s holder says this relay is its home (a signed read, [`crate::credit`]): it is charged
    /// here for what it receives, for [`HOME_TTL_S`] from now.
    pub fn declare_home(&self, key: &[u8; 32]) {
        let now = (self.clock)();
        self.st().accounts.entry(*key).or_default().home_until = now + HOME_TTL_S;
    }

    /// What `key`'s account shows; `None` without one.
    pub fn account(&self, key: &[u8; 32]) -> Option<Value> {
        let s = self.settings();
        let now = (self.clock)();
        self.st().accounts.get(key).map(|a| a.to_value(key, &s, now))
    }

    /// The account itself, for tests.
    pub fn account_raw(&self, key: &[u8; 32]) -> Option<Account> {
        self.st().accounts.get(key).cloned()
    }

    /// Decide one packet (see the module's docs). A held packet is asked about again: nothing is
    /// counted for it until it is carried or dropped.
    pub fn charge(&self, src: &[u8; 32], dst: &[u8; 32], len: usize) -> Charge {
        let s = self.settings();
        let now = (self.clock)();
        let len = len as u64;
        let mut guard = self.st();
        let st = &mut *guard;
        // the receiver's daily free allowance first, whoever pays the rest
        let day = now / DAY_S;
        let f = st.free.entry(*dst).or_insert((day, 0));
        if f.0 != day {
            *f = (day, 0);
        }
        if f.1.saturating_add(len) <= s.free_bytes_per_day {
            f.1 += len;
            st.free_carried += len;
            if let Some(a) = st.accounts.get_mut(dst) {
                a.free_bytes += len;
            }
            return Charge::Free;
        }
        // then whoever chose this relay as home: the receiver, else the sender
        let payer = if st.accounts.get(dst).is_some_and(|a| a.home(now)) {
            Some((*dst, Charge::In))
        } else if st.accounts.get(src).is_some_and(|a| a.home(now)) {
            Some((*src, Charge::Out))
        } else {
            None
        };
        let Some((key, how)) = payer else {
            st.unpaid_bytes += len;
            return Charge::Unpaid;
        };
        let a = st.accounts.get_mut(&key).expect("the payer has an account");
        if a.covers(len, s.grace_bytes) {
            a.balance -= len as i64;
            if how == Charge::In {
                a.charged_in += len;
            } else {
                a.charged_out += len;
            }
            a.waiting_since = 0;
            return how;
        }
        // out of credit: its traffic waits for the next, for a while
        if a.waiting_since == 0 {
            a.waiting_since = now.max(1);
        }
        if now.saturating_sub(a.waiting_since) < HOLD_S {
            return Charge::Wait;
        }
        a.dropped += 1;
        a.dropped_bytes += len;
        Charge::Dropped
    }

    /// Forget yesterday's free allowances (called now and then; they would reset on use anyway).
    pub fn prune(&self) {
        let day = (self.clock)() / DAY_S;
        self.st().free.retain(|_, (d, _)| *d == day);
    }

    /// The accounts, to be kept across a restart.
    pub fn saved(&self) -> Value {
        let st = self.st();
        let m: serde_json::Map<String, Value> = st.accounts.iter().map(|(k, a)| (hex::encode(k), a.saved())).collect();
        json!({"version": 2, "accounts": m})
    }

    /// Accounts kept by [`Paid::saved`]; anything unreadable is skipped. Accounts from before
    /// receivers paid (version 1) keep their balance and credit; their home is declared again by
    /// their payer.
    pub fn restore(&self, v: &Value) {
        let mut st = self.st();
        for (k, a) in v.get("accounts").and_then(Value::as_object).into_iter().flatten() {
            if let Some(key) = key_from_hex(k) {
                st.accounts.insert(key, Account::from_saved(a));
            }
        }
    }

    /// Totals for the status page: accounts, homes, bytes charged, free, dropped and unpaid.
    pub fn totals(&self) -> Value {
        let now = (self.clock)();
        let st = self.st();
        let (mut inb, mut out, mut dropped, mut credited, mut homes, mut waiting) = (0u64, 0u64, 0u64, 0u64, 0usize, 0usize);
        for a in st.accounts.values() {
            inb += a.charged_in;
            out += a.charged_out;
            dropped += a.dropped_bytes;
            credited += a.credited_msat;
            homes += usize::from(a.home(now));
            waiting += usize::from(a.waiting_since != 0);
        }
        json!({"accounts": st.accounts.len(), "homes": homes, "waiting": waiting, "charged_in": inb, "charged_out": out,
               "dropped_bytes": dropped, "free_bytes": st.free_carried, "unpaid_bytes": st.unpaid_bytes, "credited_msat": credited})
    }
}

/// A link key from 64 hex characters.
pub fn key_from_hex(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s.trim()).ok()?;
    b.try_into().ok()
}

impl Meter for Paid {
    fn admit(&self, key: &[u8; 32]) -> Result<(), String> {
        // everyone may connect: a key without credit has its free allowance, and an app out of
        // credit stays connected so that it is carried again as soon as it pays
        *self.st().connected.entry(*key).or_insert(0) += 1;
        Ok(())
    }

    fn ended(&self, key: &[u8; 32]) {
        let mut st = self.st();
        if let Some(n) = st.connected.get_mut(key) {
            *n -= 1;
            if *n == 0 {
                st.connected.remove(key);
            }
        }
    }

    fn connected(&self) -> usize {
        self.st().connected.len()
    }

    fn forward(&self, src: &[u8; 32], dst: &[u8; 32], len: usize) -> Forward {
        match self.charge(src, dst, len) {
            Charge::In | Charge::Out | Charge::Free => Forward::Yes,
            Charge::Wait => Forward::Hold,
            Charge::Dropped | Charge::Unpaid => Forward::Drop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    const SHOP: [u8; 32] = [1; 32];
    const BUYER: [u8; 32] = [2; 32];
    const OTHER: [u8; 32] = [3; 32];

    fn terms() -> PaidSettings {
        // 1,000,000 msat a GB (1 msat a KB) and 1 MB credits (1 sat each)
        PaidSettings { enabled: true, msat_per_gb: 1_000_000, credit_bytes: 1_000_000, grace_bytes: 10_000, free_bytes_per_day: 5_000,
                       credit_token: "t".repeat(MIN_TOKEN) }
    }

    fn meter() -> (Paid, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(1_000_000));
        let t2 = t.clone();
        (Paid::with_clock(terms(), Box::new(move || t2.load(Ordering::Relaxed))), t)
    }

    #[test]
    fn prices_and_terms() {
        assert_eq!(credit_msat(10 * GB, DEFAULT_MSAT_PER_GB), 20_000, "10 GB at 2 sats a GB is 20 sats");
        assert_eq!(PaidSettings::default().credit_msat(), 20_000);
        assert_eq!(credit_msat(1, 1), 1, "rounded up");
        assert_eq!(credit_msat(10 * GB, 3_500), 35_000, "each relay's own price, 10 GB a credit");
        assert!(terms().problems().is_empty());
        assert_eq!(PaidSettings::from_value(&terms().to_value()), terms());
        assert!(!PaidSettings::from_value(&Value::Null).enabled);
        let d = PaidSettings::from_value(&json!({"enabled": true}));
        assert_eq!((d.credit_bytes, d.free_bytes_per_day), (10 * GB, 64 << 20), "10 GB credits, 64 MB a day free by default");
        let bad = PaidSettings { msat_per_gb: 0, credit_token: "short".into(), ..terms() };
        assert_eq!(bad.problems().len(), 2, "{:?}", bad.problems());
        let tiny = PaidSettings { credit_bytes: 1, ..terms() };
        assert_eq!(tiny.problems().len(), 1, "a credit below a megabyte");
        let t = terms().terms();
        assert!(t.get("credit_token").is_none(), "the token is never shown");
        assert_eq!((t["credit_msat"].as_u64(), t["free_bytes_per_day"].as_u64()), (Some(1_000), Some(5_000)));
    }

    #[test]
    fn the_receiver_pays_its_home_relay_to_the_msat() {
        let (m, _) = meter();
        m.credit(&SHOP);
        m.declare_home(&SHOP);
        // the buyer's requests to the shop: the first 5 KB on the shop's free allowance, the rest
        // charged to the shop, byte for byte
        let got: Vec<Charge> = (0..105).map(|_| m.charge(&BUYER, &SHOP, 1_000)).collect();
        assert_eq!(got.iter().filter(|c| **c == Charge::Free).count(), 5);
        assert_eq!(got.iter().filter(|c| **c == Charge::In).count(), 100);
        let a = m.account_raw(&SHOP).unwrap();
        assert_eq!((a.charged_in, a.charged_out, a.free_bytes, a.balance), (100_000, 0, 5_000, 900_000));
        // 100 KB at 1 msat a KB is 100 msat of the 1,000-msat credit
        assert_eq!(credit_msat(a.charged_in, terms().msat_per_gb), 100);
        assert_eq!(m.account(&SHOP).unwrap()["home"], true);
        // the shop's answers to a buyer homed elsewhere are not this relay's to charge the buyer:
        // the buyer has no account here and pays nothing
        assert!(m.account(&BUYER).is_none());
    }

    #[test]
    fn nobody_pays_a_relay_it_did_not_choose() {
        let (m, t) = meter();
        let s = PaidSettings { free_bytes_per_day: 0, ..terms() };
        m.set_settings(s);
        // credit given to a key that never declared this relay its home: it is never charged
        m.credit(&BUYER);
        assert_eq!(m.charge(&SHOP, &BUYER, 1_000), Charge::Unpaid);
        assert_eq!(m.account_raw(&BUYER).unwrap().balance, 1_000_000);
        // homed here, then gone elsewhere: charged until its declaration runs out, then not
        m.declare_home(&BUYER);
        assert_eq!(m.charge(&SHOP, &BUYER, 1_000), Charge::In);
        t.fetch_add(HOME_TTL_S, Ordering::Relaxed);
        assert_eq!(m.charge(&SHOP, &BUYER, 1_000), Charge::Unpaid);
        assert_eq!(m.account_raw(&BUYER).unwrap().charged_in, 1_000);
    }

    #[test]
    fn a_reply_through_the_senders_home_is_the_senders() {
        let (m, _) = meter();
        m.set_settings(PaidSettings { free_bytes_per_day: 0, ..terms() });
        m.credit(&SHOP);
        m.declare_home(&SHOP);
        // the shop answers the buyer on its own home relay (iroh replies on the relay a request came
        // through): the buyer isn't homed here, so the shop, which chose this relay, pays
        assert_eq!(m.charge(&SHOP, &BUYER, 2_000), Charge::Out);
        let a = m.account_raw(&SHOP).unwrap();
        assert_eq!((a.charged_out, a.charged_in), (2_000, 0));
        // when both are homed here, the receiver pays
        m.credit(&BUYER);
        m.declare_home(&BUYER);
        assert_eq!(m.charge(&SHOP, &BUYER, 3_000), Charge::In);
        assert_eq!(m.account_raw(&BUYER).unwrap().charged_in, 3_000);
        assert_eq!(m.account_raw(&SHOP).unwrap().charged_out, 2_000);
    }

    #[test]
    fn past_the_grace_traffic_waits_for_the_next_credit() {
        let (m, t) = meter();
        m.set_settings(PaidSettings { free_bytes_per_day: 0, ..terms() });
        m.credit(&SHOP);
        m.declare_home(&SHOP);
        // 1 MB of credit and 10 KB of grace: 1,010 packets of 1 KB, then the next waits
        let carried = (0..1_100).take_while(|_| m.forward(&BUYER, &SHOP, 1_000) == Forward::Yes).count();
        assert_eq!(carried, 1_010);
        assert_eq!(m.forward(&BUYER, &SHOP, 1_000), Forward::Hold, "held, not dropped");
        let a = m.account_raw(&SHOP).unwrap();
        assert_eq!((a.balance, a.dropped_bytes), (-10_000, 0));
        assert_eq!(m.account(&SHOP).unwrap()["waiting"], true);
        // the next credit comes within the hold: the held packet goes on, the debt is taken first
        t.fetch_add(HOLD_S - 1, Ordering::Relaxed);
        assert_eq!(m.forward(&BUYER, &SHOP, 1_000), Forward::Hold);
        m.credit(&SHOP);
        assert_eq!(m.forward(&BUYER, &SHOP, 1_000), Forward::Yes);
        let a = m.account_raw(&SHOP).unwrap();
        assert_eq!((a.balance, a.dropped_bytes), (989_000, 0));
        assert_eq!(m.account(&SHOP).unwrap()["waiting"], false);
    }

    #[test]
    fn traffic_that_waits_too_long_is_dropped_and_counted() {
        let (m, t) = meter();
        m.set_settings(PaidSettings { free_bytes_per_day: 0, grace_bytes: 0, ..terms() });
        m.declare_home(&SHOP);
        assert_eq!(m.charge(&BUYER, &SHOP, 1_000), Charge::Wait);
        t.fetch_add(HOLD_S, Ordering::Relaxed);
        assert_eq!(m.charge(&BUYER, &SHOP, 1_000), Charge::Dropped);
        assert_eq!(m.charge(&BUYER, &SHOP, 500), Charge::Dropped);
        let a = m.account(&SHOP).unwrap();
        assert_eq!((a["dropped_bytes"].as_u64(), a["waiting"].as_bool()), (Some(1_500), Some(true)), "told, never silent");
        m.credit(&SHOP);
        assert_eq!(m.charge(&BUYER, &SHOP, 1_000), Charge::In);
        assert_eq!(m.totals()["dropped_bytes"], 1_500);
    }

    #[test]
    fn every_key_has_a_daily_free_allowance_for_what_it_receives() {
        let (m, t) = meter();
        assert_eq!(m.charge(&BUYER, &OTHER, 5_000), Charge::Free);
        assert_eq!(m.charge(&BUYER, &OTHER, 1), Charge::Unpaid, "OTHER's 5 KB are used up");
        // another receiver has its own
        assert_eq!(m.charge(&OTHER, &BUYER, 5_000), Charge::Free);
        t.fetch_add(DAY_S, Ordering::Relaxed);
        m.prune();
        assert_eq!(m.charge(&BUYER, &OTHER, 5_000), Charge::Free);
        assert_eq!(m.totals()["free_bytes"], 15_000);
        assert_eq!(m.totals()["unpaid_bytes"], 1);
    }

    #[test]
    fn a_price_change_keeps_what_was_bought() {
        let (m, _) = meter();
        m.credit(&SHOP);
        m.set_settings(PaidSettings { msat_per_gb: 2_000_000, ..terms() });
        assert_eq!(m.account_raw(&SHOP).unwrap().balance, 1_000_000);
        m.credit(&SHOP);
        let a = m.account_raw(&SHOP).unwrap();
        assert_eq!((a.balance, a.credited_msat), (2_000_000, 3_000), "a credit is its bytes, at the price of the moment");
    }

    #[test]
    fn accounts_survive_a_restart() {
        let (m, _) = meter();
        m.credit(&SHOP);
        m.declare_home(&SHOP);
        m.charge(&BUYER, &SHOP, 6_234);
        let (m2, _) = meter();
        m2.restore(&serde_json::from_str(&m.saved().to_string()).unwrap());
        let (a, b) = (m.account_raw(&SHOP).unwrap(), m2.account_raw(&SHOP).unwrap());
        assert_eq!((a.balance, a.charged_in, a.credited_msat, a.home_until), (b.balance, b.charged_in, b.credited_msat, b.home_until));
    }

    #[test]
    fn counts_connected_clients() {
        let (m, _) = meter();
        m.admit(&SHOP).unwrap();
        m.admit(&SHOP).unwrap();
        m.admit(&BUYER).unwrap();
        assert_eq!(m.connected(), 2);
        m.ended(&SHOP);
        m.ended(&SHOP);
        assert_eq!(m.connected(), 1);
    }
}
