//! A shop paying the paid relays it uses (`docs/PAID-RELAYS.md`): for each of its link keys, keep a
//! small prepaid balance at the relay, bought one credit at a time with Stream tickets through the
//! wallet's signer, inside the owner's spending rule for relays (a ticket task, by default
//! `relays`, whose `budget_sats` over a `window_s` of a day is the "Most for relays per day").
//!
//! The shop reads its balance from the relay (`<credit>/balance`, signed with the link key, so
//! nobody else learns how much the shop sells) and buys one credit when it falls below the low
//! water mark. What it can lose to a relay that takes the money and carries nothing is what it has
//! bought ahead and not used: at most one credit and the low water mark. A relay asking more per
//! GB, or more per credit, than the owner allows is not paid.
//!
//! I/O is the caller's: [`Wallet`] is the signer's `xbt402_pay`, [`Fetch`] a GET of a free route.
//! Nothing here holds money or a wallet key.
use std::collections::HashMap;
use std::time::Duration;

use iroh::SecretKey;
use serde_json::{json, Value};

/// What a link key signs to read its balance: the relay's `credit::BALANCE_DOMAIN`.
pub const BALANCE_DOMAIN: &str = "xbt-stream-relay/balance/v1";
/// The task the owner's spending rule for relays is kept under.
pub const DEFAULT_TASK: &str = "relays";
/// After a refusal (a spending rule reached, a wallet away), wait this long before asking again.
pub const BACKOFF: Duration = Duration::from_secs(600);

/// The link key of `secret`, as hex.
pub fn link_key_hex(secret: &[u8; 32]) -> String {
    hex::encode(SecretKey::from_bytes(secret).public().as_bytes())
}

/// The query string of a signed balance read at `ts`: `key=…&ts=…&sig=…`.
pub fn balance_query(secret: &[u8; 32], ts: u64) -> String {
    let sk = SecretKey::from_bytes(secret);
    let key = hex::encode(sk.public().as_bytes());
    let sig = sk.sign(format!("{BALANCE_DOMAIN}|{key}|{ts}").as_bytes());
    format!("key={key}&ts={ts}&sig={}", hex::encode(sig.to_bytes()))
}

/// The wallet's signer: `xbt402_pay` with these params, its answer.
pub trait Wallet {
    fn pay(&self, params: &Value) -> Result<Value, String>;
}

/// A GET of a free route, its JSON body.
pub trait Fetch {
    fn get(&self, url: &str) -> Result<Value, String>;
}

/// A paid relay the shop uses: its URL, where its credit is sold, and its announced price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidRelay {
    pub relay: String,
    /// The seller route's base URL (`credit` in the announcement), no trailing `/`.
    pub credit: String,
    pub msat_per_gb: u64,
}

/// The owner's bounds for paying relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    pub task: String,
    /// The most per GB a relay may charge.
    pub max_msat_per_gb: u64,
    /// The most one credit (one paid request) may cost.
    pub max_credit_msat: u64,
    /// The most one payment may move out of the wallet (a ticket may cover several credits).
    pub max_sats: u64,
    /// Buy when the balance is below this many bytes.
    pub low_water_bytes: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        // 4 sats a GB at most; a credit of at most 100 sats; buy below 1 GB
        Self { task: DEFAULT_TASK.into(), max_msat_per_gb: 4_000, max_credit_msat: 100_000, max_sats: 1_000, low_water_bytes: 1_000_000_000 }
    }
}

/// What one look at one key's balance came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Enough left: nothing paid.
    Enough { balance: i64 },
    /// One credit bought: the balance after it.
    Paid { balance: i64, price_msat: u64 },
    /// Not paid, and why; the payer waits [`BACKOFF`] before it asks again.
    Refused(String),
    /// Waiting after a refusal.
    Waiting,
}

/// Keeps the shop's balance at one paid relay, for each of its link keys.
pub struct RelayPayer<W: Wallet, F: Fetch> {
    pub relay: PaidRelay,
    pub bounds: Bounds,
    wallet: W,
    fetch: F,
    /// After a refusal, not before this (Unix seconds), per key.
    hold: HashMap<String, u64>,
    /// msat paid to this relay since start.
    pub paid_msat: u64,
}

impl<W: Wallet, F: Fetch> RelayPayer<W, F> {
    pub fn new(relay: PaidRelay, bounds: Bounds, wallet: W, fetch: F) -> Self {
        Self { relay, bounds, wallet, fetch, hold: HashMap::new(), paid_msat: 0 }
    }

    fn balance(&self, secret: &[u8; 32], now: u64) -> Result<i64, String> {
        let v = self.fetch.get(&format!("{}/balance?{}", self.relay.credit, balance_query(secret, now)))?;
        v.get("balance_bytes").and_then(Value::as_i64).ok_or_else(|| format!("the relay's balance answer has no balance: {v}"))
    }

    fn refuse(&mut self, key: &str, now: u64, why: String) -> Step {
        self.hold.insert(key.to_string(), now + BACKOFF.as_secs());
        Step::Refused(why)
    }

    /// Look at `secret`'s balance and buy one credit if it is low and the terms are within bounds.
    pub fn step(&mut self, secret: &[u8; 32], now: u64) -> Step {
        let key = link_key_hex(secret);
        if self.hold.get(&key).is_some_and(|t| now < *t) {
            return Step::Waiting;
        }
        let balance = match self.balance(secret, now) {
            Ok(b) => b,
            Err(e) => return self.refuse(&key, now, format!("could not read the balance: {e}")),
        };
        if balance >= self.bounds.low_water_bytes as i64 {
            return Step::Enough { balance };
        }
        // the relay's own terms, checked against the announcement and the owner's bounds
        let terms = match self.fetch.get(&format!("{}/terms", self.relay.credit)) {
            Ok(t) => t,
            Err(e) => return self.refuse(&key, now, format!("could not read the relay's terms: {e}")),
        };
        let (per_gb, credit_msat) = (terms["msat_per_gb"].as_u64().unwrap_or(u64::MAX), terms["credit_msat"].as_u64().unwrap_or(u64::MAX));
        if per_gb > self.relay.msat_per_gb.max(1) || per_gb > self.bounds.max_msat_per_gb {
            return self.refuse(&key, now, format!("the relay asks {per_gb} msat per GB: more than it announced ({}) or than you allow ({})",
                                                   self.relay.msat_per_gb, self.bounds.max_msat_per_gb));
        }
        if credit_msat > self.bounds.max_credit_msat {
            return self.refuse(&key, now, format!("one credit costs {credit_msat} msat, more than you allow ({})", self.bounds.max_credit_msat));
        }
        let params = json!({
            "url": format!("{}/credit", self.relay.credit), "method": "POST", "body": json!({"key": key}).to_string(),
            "max_sats": self.bounds.max_sats, "task": self.bounds.task,
            // the route's price is one credit, nothing by the byte, second or token
            "price_ceiling": {"request_msat": credit_msat, "gib_msat": 0, "second_msat": 0, "input_per_1k_msat": 0, "output_per_1k_msat": 0},
        });
        let r = match self.wallet.pay(&params) {
            Ok(r) => r,
            Err(e) => return self.refuse(&key, now, format!("the wallet did not pay: {e}")),
        };
        let paid = r.get("status").and_then(Value::as_u64) == Some(200) && r.get("verdict").and_then(Value::as_str) == Some("allow");
        if !paid {
            let why = r.get("reason").or_else(|| r.get("rule")).and_then(Value::as_str).unwrap_or("refused").to_string();
            return self.refuse(&key, now, format!("the wallet did not pay: {why}"));
        }
        let price_msat = r.get("price_msat").and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(credit_msat);
        self.paid_msat = self.paid_msat.saturating_add(price_msat);
        let balance = self.balance(secret, now).unwrap_or(balance);
        Step::Paid { balance, price_msat }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct Relay {
        balance: Rc<RefCell<i64>>,
        terms: Rc<RefCell<Value>>,
        asked: Rc<RefCell<Vec<String>>>,
    }

    impl Fetch for Relay {
        fn get(&self, url: &str) -> Result<Value, String> {
            self.asked.borrow_mut().push(url.to_string());
            if url.contains("/terms") {
                return Ok(self.terms.borrow().clone());
            }
            Ok(json!({"balance_bytes": *self.balance.borrow()}))
        }
    }

    struct Signer {
        relay: Relay,
        allow: bool,
        calls: Rc<RefCell<Vec<Value>>>,
    }

    impl Wallet for Signer {
        fn pay(&self, params: &Value) -> Result<Value, String> {
            self.calls.borrow_mut().push(params.clone());
            if !self.allow {
                return Ok(json!({"verdict": "deny", "rule": "task_budget", "reason": "the task's budget for the day is spent"}));
            }
            *self.relay.balance.borrow_mut() += 10_000_000_000;
            Ok(json!({"verdict": "allow", "status": 200, "price_msat": "20000"}))
        }
    }

    fn payer(allow: bool, balance: i64) -> (RelayPayer<Signer, Relay>, Relay, Rc<RefCell<Vec<Value>>>) {
        let relay = Relay::default();
        *relay.balance.borrow_mut() = balance;
        *relay.terms.borrow_mut() = json!({"msat_per_gb": 2_000, "credit_msat": 20_000});
        let calls = Rc::new(RefCell::new(Vec::new()));
        let w = Signer { relay: relay.clone(), allow, calls: calls.clone() };
        let pr = PaidRelay { relay: "https://relay.example.com/".into(), credit: "https://ops.example.com/stream-relay".into(), msat_per_gb: 2_000 };
        (RelayPayer::new(pr, Bounds::default(), w, relay.clone()), relay, calls)
    }

    #[test]
    fn the_balance_query_is_signed_by_the_link_key() {
        let q = balance_query(&[5; 32], 1_700_000_000);
        let key = link_key_hex(&[5; 32]);
        assert!(q.starts_with(&format!("key={key}&ts=1700000000&sig=")));
        let sig: [u8; 64] = hex::decode(q.rsplit('=').next().unwrap()).unwrap().try_into().unwrap();
        let pk = SecretKey::from_bytes(&[5; 32]).public();
        pk.verify(format!("{BALANCE_DOMAIN}|{key}|1700000000").as_bytes(), &iroh::Signature::from_bytes(&sig)).unwrap();
    }

    #[test]
    fn pays_one_credit_when_low_and_nothing_when_not() {
        let (mut p, relay, calls) = payer(true, 5_000_000_000);
        assert_eq!(p.step(&[1; 32], 100), Step::Enough { balance: 5_000_000_000 });
        assert!(calls.borrow().is_empty());
        *relay.balance.borrow_mut() = 1_000;
        assert_eq!(p.step(&[1; 32], 100), Step::Paid { balance: 10_000_001_000, price_msat: 20_000 });
        let c = calls.borrow()[0].clone();
        assert_eq!(c["url"], "https://ops.example.com/stream-relay/credit");
        assert_eq!(c["task"], DEFAULT_TASK);
        assert_eq!(c["price_ceiling"]["request_msat"], 20_000);
        assert_eq!(serde_json::from_str::<Value>(c["body"].as_str().unwrap()).unwrap()["key"], link_key_hex(&[1; 32]));
        assert_eq!(p.paid_msat, 20_000);
    }

    #[test]
    fn a_spending_rule_stops_payment_and_the_payer_waits() {
        let (mut p, _, calls) = payer(false, 0);
        assert!(matches!(p.step(&[1; 32], 100), Step::Refused(w) if w.contains("budget")));
        assert_eq!(p.step(&[1; 32], 200), Step::Waiting);
        assert_eq!(calls.borrow().len(), 1, "not asked again while waiting");
        assert!(matches!(p.step(&[1; 32], 100 + BACKOFF.as_secs()), Step::Refused(_)));
    }

    #[test]
    fn terms_past_the_bounds_or_the_announcement_are_not_paid() {
        let (mut p, relay, calls) = payer(true, 0);
        *relay.terms.borrow_mut() = json!({"msat_per_gb": 3_000, "credit_msat": 20_000});
        assert!(matches!(p.step(&[1; 32], 0), Step::Refused(w) if w.contains("announced")));
        let (mut p, relay, _) = payer(true, 0);
        *relay.terms.borrow_mut() = json!({"msat_per_gb": 2_000, "credit_msat": 500_000});
        assert!(matches!(p.step(&[1; 32], 0), Step::Refused(w) if w.contains("credit")));
        assert!(calls.borrow().is_empty());
    }
}
