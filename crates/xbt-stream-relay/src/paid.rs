//! A paid relay (`docs/PAID-RELAYS.md`): the relay meters, for each shop that pays it, the bytes it
//! carries from and to that shop's link key, and carries them while the shop's prepaid credit
//! lasts.
//!
//! - **Accounts.** A link key has an account once it has been credited ([`Paid::credit`]): the
//!   relay's seller route (a priced route on the operator's own gateway, paid with Stream tickets)
//!   calls the credit API ([`crate::credit`]) once per paid request. The balance is kept in bytes,
//!   bought at the price of the moment.
//! - **Charging.** Every relayed packet is charged once, by its datagrams' length: to its sender
//!   when the sender has an account with credit (outbound), else to its receiver when the receiver
//!   has one (inbound). Inbound bytes are charged only up to [`PaidSettings::inbound_pct`] of what
//!   the shop itself sent in the same hour, plus [`PaidSettings::inbound_allowance_bytes`], so a
//!   buyer who floods a shop cannot make it pay: the excess is carried, or not, on the sender's free
//!   allowance.
//! - **Running out.** An account may go [`PaidSettings::grace_bytes`] below zero while its next
//!   payment is on its way; past that it is out of credit and treated as a key without an account
//!   (its own free allowance, nothing more) until it is credited again.
//! - **Free allowance.** A key without an account, or out of credit, may send
//!   [`PaidSettings::free_bytes_per_day`] a day: hole punching, address discovery and a buyer's
//!   requests to a shop that doesn't pay this relay. 0 makes the relay paid-only.
//!
//! The relay never sees what it carries: only the keys, the lengths and when.
use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::meter::Meter;

/// A gigabyte, as prices are stated: 10^9 bytes.
pub const GB: u64 = 1_000_000_000;
/// The suggested price, 2 sats per GB (`docs/RUN-A-RELAY.md`).
pub const DEFAULT_MSAT_PER_GB: u64 = 2_000;
/// One credit, what the operator's seller route charges per paid request: 20 sats, 10 GB at the
/// suggested price.
pub const DEFAULT_CREDIT_MSAT: u64 = 20_000;
pub const DEFAULT_GRACE_BYTES: u64 = 256 << 20;
pub const DEFAULT_FREE_BYTES_PER_DAY: u64 = 64 << 20;
pub const DEFAULT_INBOUND_PCT: u64 = 100;
pub const DEFAULT_INBOUND_ALLOWANCE_BYTES: u64 = 8 << 20;
/// The window inbound bytes are weighed against outbound ones in.
pub const INBOUND_WINDOW_S: u64 = 3_600;
const DAY_S: u64 = 86_400;

/// The operator's terms (`relay.json` `paid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidSettings {
    pub enabled: bool,
    pub msat_per_gb: u64,
    /// What one paid credit request costs: the price of the seller route on the operator's gateway.
    pub credit_msat: u64,
    pub grace_bytes: u64,
    pub free_bytes_per_day: u64,
    /// Inbound bytes charged to a shop in an hour, at most, as a percentage of its outbound bytes.
    pub inbound_pct: u64,
    pub inbound_allowance_bytes: u64,
    /// The secret the operator's gateway sends to the credit API (`x-relay-credit-token`).
    pub credit_token: String,
}

impl Default for PaidSettings {
    fn default() -> Self {
        Self { enabled: false, msat_per_gb: DEFAULT_MSAT_PER_GB, credit_msat: DEFAULT_CREDIT_MSAT, grace_bytes: DEFAULT_GRACE_BYTES,
               free_bytes_per_day: DEFAULT_FREE_BYTES_PER_DAY, inbound_pct: DEFAULT_INBOUND_PCT,
               inbound_allowance_bytes: DEFAULT_INBOUND_ALLOWANCE_BYTES, credit_token: String::new() }
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
            credit_msat: n("credit_msat", d.credit_msat),
            grace_bytes: n("grace_bytes", d.grace_bytes),
            free_bytes_per_day: n("free_bytes_per_day", d.free_bytes_per_day),
            inbound_pct: n("inbound_pct", d.inbound_pct),
            inbound_allowance_bytes: n("inbound_allowance_bytes", d.inbound_allowance_bytes),
            credit_token: v.get("credit_token").and_then(Value::as_str).unwrap_or("").to_string(),
        }
    }

    pub fn to_value(&self) -> Value {
        json!({"enabled": self.enabled, "msat_per_gb": self.msat_per_gb, "credit_msat": self.credit_msat, "grace_bytes": self.grace_bytes,
               "free_bytes_per_day": self.free_bytes_per_day, "inbound_pct": self.inbound_pct,
               "inbound_allowance_bytes": self.inbound_allowance_bytes, "credit_token": self.credit_token})
    }

    /// What the terms can't run with, in words; empty when they can.
    pub fn problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.msat_per_gb == 0 {
            v.push("A paid relay needs a price above 0 per GB.".to_string());
        }
        if self.credit_msat < self.msat_per_gb.div_ceil(1_000).max(1) {
            v.push("One credit must buy at least a megabyte.".to_string());
        }
        if self.credit_token.len() < MIN_TOKEN {
            v.push(format!("The credit token must be at least {MIN_TOKEN} characters."));
        }
        v
    }

    /// The bytes one credit buys.
    pub fn credit_bytes(&self) -> u64 {
        bytes_for(self.credit_msat, self.msat_per_gb)
    }

    /// The terms as shops read them (`GET /terms`, and the announcement): never the token.
    pub fn terms(&self) -> Value {
        json!({"msat_per_gb": self.msat_per_gb, "credit_msat": self.credit_msat, "credit_bytes": self.credit_bytes(),
               "grace_bytes": self.grace_bytes, "free_bytes_per_day": self.free_bytes_per_day, "inbound_pct": self.inbound_pct,
               "inbound_allowance_bytes": self.inbound_allowance_bytes})
    }
}

/// The bytes `msat` buys at `msat_per_gb`, rounded down.
pub fn bytes_for(msat: u64, msat_per_gb: u64) -> u64 {
    if msat_per_gb == 0 {
        return 0;
    }
    u64::try_from(u128::from(msat) * u128::from(GB) / u128::from(msat_per_gb)).unwrap_or(u64::MAX)
}

/// One shop's account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    /// Bytes bought minus bytes charged; below zero by at most the grace.
    pub balance: i64,
    pub credited_msat: u64,
    pub credited_bytes: u64,
    /// Bytes charged, from the shop (out) and to it (in), since the account was opened.
    pub charged_out: u64,
    pub charged_in: u64,
    /// Bytes of this hour, for weighing inbound against outbound.
    window: u64,
    window_out: u64,
    window_in: u64,
    /// Packets refused for want of credit, and their bytes.
    pub refused: u64,
    pub refused_bytes: u64,
}

impl Account {
    fn to_value(&self, key: &[u8; 32], grace: u64) -> Value {
        json!({"key": hex::encode(key), "balance_bytes": self.balance, "credited_msat": self.credited_msat,
               "credited_bytes": self.credited_bytes, "charged_out": self.charged_out, "charged_in": self.charged_in,
               "refused_bytes": self.refused_bytes, "carrying": self.balance > -(grace as i64)})
    }

    fn saved(&self) -> Value {
        json!({"balance": self.balance, "credited_msat": self.credited_msat, "credited_bytes": self.credited_bytes,
               "charged_out": self.charged_out, "charged_in": self.charged_in, "refused_bytes": self.refused_bytes})
    }

    fn from_saved(v: &Value) -> Self {
        let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        Self { balance: v.get("balance").and_then(Value::as_i64).unwrap_or(0), credited_msat: n("credited_msat"), credited_bytes: n("credited_bytes"),
               charged_out: n("charged_out"), charged_in: n("charged_in"), refused_bytes: n("refused_bytes"), ..Self::default() }
    }

    /// Can `len` more bytes be charged without passing the grace?
    fn covers(&self, len: u64, grace: u64) -> bool {
        self.balance.saturating_sub(len as i64) >= -(grace as i64)
    }

    fn roll(&mut self, now: u64) {
        let w = now / INBOUND_WINDOW_S;
        if w != self.window {
            (self.window, self.window_out, self.window_in) = (w, 0, 0);
        }
    }
}

#[derive(Debug, Default)]
struct State {
    accounts: HashMap<[u8; 32], Account>,
    /// A key's free bytes used today: (day, bytes).
    free: HashMap<[u8; 32], (u64, u64)>,
    connected: HashMap<[u8; 32], usize>,
    /// Bytes carried on free allowances, and packets refused with none left.
    free_carried: u64,
    free_refused_bytes: u64,
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

/// Why a packet was carried or not, for tests and the status page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// Charged to the sender's account.
    Out,
    /// Charged to the receiver's account.
    In,
    /// Carried on the sender's free allowance.
    Free,
    /// Not carried.
    Refused,
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
    pub fn credit(&self, key: &[u8; 32]) -> Value {
        let s = self.settings();
        let bytes = s.credit_bytes();
        let mut st = self.st();
        let a = st.accounts.entry(*key).or_default();
        a.balance = a.balance.saturating_add(i64::try_from(bytes).unwrap_or(i64::MAX));
        a.credited_msat = a.credited_msat.saturating_add(s.credit_msat);
        a.credited_bytes = a.credited_bytes.saturating_add(bytes);
        a.to_value(key, s.grace_bytes)
    }

    /// What `key`'s account shows; `None` without one.
    pub fn account(&self, key: &[u8; 32]) -> Option<Value> {
        let g = self.settings().grace_bytes;
        self.st().accounts.get(key).map(|a| a.to_value(key, g))
    }

    /// The account itself, for tests.
    pub fn account_raw(&self, key: &[u8; 32]) -> Option<Account> {
        self.st().accounts.get(key).cloned()
    }

    /// Decide one packet (see the module's docs).
    pub fn charge(&self, src: &[u8; 32], dst: &[u8; 32], len: usize) -> Charge {
        let s = self.settings();
        let now = (self.clock)();
        let len = len as u64;
        let mut guard = self.st();
        // the fields apart: the free allowance and its totals are borrowed together below
        let st = &mut *guard;
        if let Some(a) = st.accounts.get_mut(src) {
            a.roll(now);
            if a.covers(len, s.grace_bytes) {
                a.balance -= len as i64;
                a.charged_out += len;
                a.window_out += len;
                return Charge::Out;
            }
            a.refused += 1;
            a.refused_bytes += len;
        }
        if let Some(a) = st.accounts.get_mut(dst) {
            a.roll(now);
            let cap = u128::from(a.window_out) * u128::from(s.inbound_pct) / 100 + u128::from(s.inbound_allowance_bytes);
            if u128::from(a.window_in + len) <= cap {
                if a.covers(len, s.grace_bytes) {
                    a.balance -= len as i64;
                    a.charged_in += len;
                    a.window_in += len;
                    return Charge::In;
                }
                a.refused += 1;
                a.refused_bytes += len;
            }
        }
        let day = now / DAY_S;
        let allowance = s.free_bytes_per_day;
        let f = st.free.entry(*src).or_insert((day, 0));
        if f.0 != day {
            *f = (day, 0);
        }
        if f.1.saturating_add(len) <= allowance {
            f.1 += len;
            st.free_carried += len;
            Charge::Free
        } else {
            st.free_refused_bytes += len;
            Charge::Refused
        }
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
        json!({"version": 1, "accounts": m})
    }

    /// Accounts kept by [`Paid::saved`]; anything unreadable is skipped.
    pub fn restore(&self, v: &Value) {
        let mut st = self.st();
        for (k, a) in v.get("accounts").and_then(Value::as_object).into_iter().flatten() {
            if let Some(key) = key_from_hex(k) {
                st.accounts.insert(key, Account::from_saved(a));
            }
        }
    }

    /// Totals for the status page: accounts, bytes charged, bytes on free allowances, refused.
    pub fn totals(&self) -> Value {
        let st = self.st();
        let (mut out, mut inb, mut refused, mut credited) = (0u64, 0u64, 0u64, 0u64);
        for a in st.accounts.values() {
            out += a.charged_out;
            inb += a.charged_in;
            refused += a.refused_bytes;
            credited += a.credited_msat;
        }
        json!({"accounts": st.accounts.len(), "charged_out": out, "charged_in": inb, "refused_bytes": refused + st.free_refused_bytes,
               "free_bytes": st.free_carried, "credited_msat": credited})
    }
}

/// A link key from 64 hex characters.
pub fn key_from_hex(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s.trim()).ok()?;
    b.try_into().ok()
}

impl Meter for Paid {
    fn admit(&self, key: &[u8; 32]) -> Result<(), String> {
        // everyone may connect: a key without credit has its free allowance, and a shop out of
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

    fn forward(&self, src: &[u8; 32], dst: &[u8; 32], len: usize) -> bool {
        self.charge(src, dst, len) != Charge::Refused
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
        // 1,000,000 msat a GB (1 msat a KB) and a 1-sat credit: one credit is 1 MB
        PaidSettings { enabled: true, msat_per_gb: 1_000_000, credit_msat: 1_000, grace_bytes: 10_000, free_bytes_per_day: 5_000,
                       inbound_pct: 50, inbound_allowance_bytes: 1_000, credit_token: "t".repeat(MIN_TOKEN) }
    }

    fn meter() -> (Paid, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(1_000_000));
        let t2 = t.clone();
        (Paid::with_clock(terms(), Box::new(move || t2.load(Ordering::Relaxed))), t)
    }

    #[test]
    fn prices_and_terms() {
        assert_eq!(bytes_for(2_000, 2_000), GB);
        assert_eq!(bytes_for(20_000, DEFAULT_MSAT_PER_GB), 10 * GB);
        assert_eq!(bytes_for(1, 0), 0);
        assert!(terms().problems().is_empty());
        assert_eq!(PaidSettings::from_value(&terms().to_value()), terms());
        assert!(!PaidSettings::from_value(&Value::Null).enabled);
        let bad = PaidSettings { msat_per_gb: 0, credit_token: "short".into(), ..terms() };
        assert_eq!(bad.problems().len(), 2, "{:?}", bad.problems());
        let tiny = PaidSettings { credit_msat: 1, ..terms() };
        assert_eq!(tiny.problems().len(), 1, "a credit below a megabyte");
        assert!(terms().terms().get("credit_token").is_none(), "the token is never shown");
    }

    #[test]
    fn meters_bytes_out_and_in_with_a_running_total() {
        let (m, _) = meter();
        m.credit(&SHOP);
        assert_eq!(m.account_raw(&SHOP).unwrap().balance, 1_000_000);
        // the shop sends 300 KB to a buyer: charged out
        for _ in 0..300 {
            assert_eq!(m.charge(&SHOP, &BUYER, 1_000), Charge::Out);
        }
        // the buyer answers with 100 KB: charged in (within half of what the shop sent, plus 1 KB)
        for _ in 0..100 {
            assert_eq!(m.charge(&BUYER, &SHOP, 1_000), Charge::In);
        }
        let a = m.account_raw(&SHOP).unwrap();
        assert_eq!((a.charged_out, a.charged_in, a.balance), (300_000, 100_000, 600_000));
        assert_eq!(m.account(&SHOP).unwrap()["carrying"], true);
        assert!(m.account(&BUYER).is_none(), "the buyer has no account and paid nothing");
    }

    #[test]
    fn a_flood_into_a_shop_is_not_charged_past_the_inbound_cap() {
        let (m, _) = meter();
        m.credit(&SHOP);
        for _ in 0..10 {
            m.charge(&SHOP, &BUYER, 1_000);
        }
        // the cap this hour: 50% of 10 KB, plus 1 KB = 6 KB; the rest falls on the buyer's 5 KB
        // free allowance, and then is not carried at all
        let got: Vec<Charge> = (0..20).map(|_| m.charge(&BUYER, &SHOP, 1_000)).collect();
        assert_eq!(got.iter().filter(|c| **c == Charge::In).count(), 6);
        assert_eq!(got.iter().filter(|c| **c == Charge::Free).count(), 5);
        assert_eq!(got.iter().filter(|c| **c == Charge::Refused).count(), 9);
        assert_eq!(m.account_raw(&SHOP).unwrap().charged_in, 6_000);
    }

    #[test]
    fn the_inbound_cap_is_per_hour() {
        let (m, t) = meter();
        m.credit(&SHOP);
        m.charge(&SHOP, &BUYER, 10_000);
        t.fetch_add(INBOUND_WINDOW_S, Ordering::Relaxed);
        // a new hour: what the shop sent last hour lends no room now, only the allowance
        assert_eq!(m.charge(&BUYER, &SHOP, 1_000), Charge::In);
        assert_eq!(m.charge(&BUYER, &SHOP, 1_000), Charge::Free);
    }

    #[test]
    fn stops_after_the_grace_and_resumes_on_payment() {
        let (m, _) = meter();
        let s = PaidSettings { free_bytes_per_day: 0, ..terms() };
        m.set_settings(s);
        m.credit(&SHOP);
        // 1 MB of credit and 10 KB of grace: 1,010 packets of 1 KB, then nothing
        let carried = (0..1_100).take_while(|_| m.forward(&SHOP, &BUYER, 1_000)).count();
        assert_eq!(carried, 1_010);
        let a = m.account_raw(&SHOP).unwrap();
        assert_eq!((a.balance, a.refused), (-10_000, 1));
        assert_eq!(m.account(&SHOP).unwrap()["carrying"], false);
        // nor to it
        assert!(!m.forward(&BUYER, &SHOP, 1_000));
        // paid again: the debt is taken first, and it is carried again
        m.credit(&SHOP);
        assert_eq!(m.account_raw(&SHOP).unwrap().balance, 990_000);
        assert!(m.forward(&SHOP, &BUYER, 1_000));
    }

    #[test]
    fn keys_without_an_account_have_a_daily_free_allowance() {
        let (m, t) = meter();
        assert_eq!(m.charge(&BUYER, &OTHER, 5_000), Charge::Free);
        assert_eq!(m.charge(&BUYER, &OTHER, 1), Charge::Refused);
        // another key has its own
        assert_eq!(m.charge(&OTHER, &BUYER, 5_000), Charge::Free);
        t.fetch_add(DAY_S, Ordering::Relaxed);
        m.prune();
        assert_eq!(m.charge(&BUYER, &OTHER, 5_000), Charge::Free);
        assert_eq!(m.totals()["free_bytes"], 15_000);
    }

    #[test]
    fn a_price_change_keeps_what_was_bought() {
        let (m, _) = meter();
        m.credit(&SHOP);
        m.set_settings(PaidSettings { msat_per_gb: 2_000_000, ..terms() });
        assert_eq!(m.account_raw(&SHOP).unwrap().balance, 1_000_000);
        m.credit(&SHOP);
        assert_eq!(m.account_raw(&SHOP).unwrap().balance, 1_500_000);
    }

    #[test]
    fn accounts_survive_a_restart() {
        let (m, _) = meter();
        m.credit(&SHOP);
        m.charge(&SHOP, &BUYER, 1_234);
        let (m2, _) = meter();
        m2.restore(&serde_json::from_str(&m.saved().to_string()).unwrap());
        let (a, b) = (m.account_raw(&SHOP).unwrap(), m2.account_raw(&SHOP).unwrap());
        assert_eq!((a.balance, a.charged_out, a.credited_msat), (b.balance, b.charged_out, b.credited_msat));
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
