//! The service's state: its NWC connections and what each has spent, in one JSON file
//! (`connections.json` in the state dir), written atomically, mode 0600.
//!
//! A connection holds the wallet-service key it answers with (its secret is in this file and
//! nowhere else: never logged, never returned by the admin socket), the app's public key (the
//! app's secret was in the connection URI shown once and is not kept), its relays, its budget, its
//! expiry, its allowed methods, and a record of each payment it asked for.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const STATE_FILE: &str = "connections.json";
pub const DAY_S: u64 = 86_400;
/// The payment records kept per connection (the newest); older ones count only in `spent_total_sats`.
pub const MAX_RECORDS: usize = 2_000;

/// The methods a connection may be allowed. `make_invoice` is not among them: see `docs/NWC.md`.
pub const METHODS: [&str; 5] = ["pay_invoice", "get_balance", "get_info", "lookup_invoice", "list_transactions"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentRec {
    pub payment_hash: String,
    pub invoice: String,
    pub amount_msat: u64,
    /// What counts against the budget while the outcome is unknown: the most the signer may charge.
    pub booked_sats: i64,
    /// What it cost, fees included, once settled.
    pub spent_sats: i64,
    pub fees_paid_msat: u64,
    /// `pending`, `settled` or `failed`.
    pub state: String,
    #[serde(default)]
    pub preimage: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub description_hash: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub settled_at: Option<u64>,
}

impl PaymentRec {
    /// What it holds of the budget now.
    pub fn counted_sats(&self) -> i64 {
        match self.state.as_str() {
            "settled" => self.spent_sats,
            "pending" => self.booked_sats,
            _ => 0,
        }
    }

    /// NIP-47's transaction object.
    pub fn nip47(&self) -> Value {
        let mut v = json!({"type": "outgoing", "state": self.state, "invoice": self.invoice, "payment_hash": self.payment_hash,
                           "amount": self.amount_msat, "fees_paid": self.fees_paid_msat, "created_at": self.created_at});
        for (k, x) in [("description", self.description.clone().map(Value::from)), ("description_hash", self.description_hash.clone().map(Value::from)),
                       ("preimage", self.preimage.clone().map(Value::from)), ("expires_at", self.expires_at.map(Value::from)),
                       ("settled_at", self.settled_at.map(Value::from))] {
            if let Some(x) = x {
                v[k] = x;
            }
        }
        v
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connection {
    pub id: String,
    pub name: String,
    pub created_at: u64,
    /// 0: never.
    pub expires_at: u64,
    pub budget_sats_per_day: i64,
    pub methods: Vec<String>,
    pub relays: Vec<String>,
    /// The wallet-service key this connection answers with (hex). Secret.
    pub service_secret: String,
    pub service_pubkey: String,
    pub client_pubkey: String,
    #[serde(default)]
    pub last_used: u64,
    #[serde(default)]
    pub spent_total_sats: i64,
    #[serde(default)]
    pub payments: Vec<PaymentRec>,
}

impl Connection {
    pub fn expired(&self, now: u64) -> bool {
        self.expires_at != 0 && now >= self.expires_at
    }

    pub fn allows(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == method)
    }

    /// What the last 24 hours' payments hold of the budget (pending ones at their booking).
    pub fn used_24h(&self, now: u64) -> i64 {
        let since = now.saturating_sub(DAY_S);
        self.payments.iter().filter(|p| p.created_at > since).fold(0i64, |a, p| a.saturating_add(p.counted_sats()))
    }

    pub fn remaining(&self, now: u64) -> i64 {
        self.budget_sats_per_day.saturating_sub(self.used_24h(now)).max(0)
    }

    pub fn find(&self, hash: &str) -> Option<&PaymentRec> {
        self.payments.iter().find(|p| p.payment_hash == hash)
    }

    pub fn find_mut(&mut self, hash: &str) -> Option<&mut PaymentRec> {
        self.payments.iter_mut().find(|p| p.payment_hash == hash)
    }

    /// A new payment record; the oldest go once there are more than [`MAX_RECORDS`].
    pub fn push(&mut self, p: PaymentRec) {
        self.payments.retain(|x| x.payment_hash != p.payment_hash);
        self.payments.push(p);
        if self.payments.len() > MAX_RECORDS {
            let n = self.payments.len() - MAX_RECORDS;
            self.payments.drain(..n);
        }
    }

    /// What the admin socket (and so the wallet UI) sees: never the service secret.
    pub fn public(&self, now: u64) -> Value {
        let pending = self.payments.iter().filter(|p| p.state == "pending").count();
        json!({"id": self.id, "name": self.name, "created_at": self.created_at, "expires_at": self.expires_at, "expired": self.expired(now),
               "budget_sats_per_day": self.budget_sats_per_day, "spent_24h_sats": self.used_24h(now), "remaining_sats": self.remaining(now),
               "spent_total_sats": self.spent_total_sats, "methods": self.methods, "relays": self.relays,
               "service_pubkey": self.service_pubkey, "client_pubkey": self.client_pubkey, "last_used": self.last_used,
               "payments": self.payments.len(), "pending_payments": pending})
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct File {
    version: u32,
    connections: Vec<Connection>,
}

/// The state file and what it holds.
pub struct Store {
    path: PathBuf,
    pub connections: Vec<Connection>,
}

impl Store {
    /// Open (or start) the state in `dir`, made 0700 if this creates it; the file is kept 0600.
    pub fn open(dir: &Path) -> Result<Self, String> {
        xbt_svc::ensure_dir(dir, 0o700).map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = dir.join(STATE_FILE);
        let connections = match std::fs::read(&path) {
            Ok(b) => {
                // a file someone else could read is narrowed at once: it holds the service keys
                let _ = xbt_svc::set_mode(&path, 0o600);
                serde_json::from_slice::<File>(&b).map_err(|e| format!("{}: {e}", path.display()))?.connections
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(Self { path, connections })
    }

    pub fn save(&self) -> Result<(), String> {
        let f = File { version: 1, connections: self.connections.clone() };
        let bytes = serde_json::to_vec_pretty(&f).map_err(|e| e.to_string())?;
        xbt_svc::write_atomic(&self.path, &bytes, 0o600).map_err(|e| format!("{}: {e}", self.path.display()))
    }

    pub fn by_service(&self, pubkey: &str) -> Option<usize> {
        self.connections.iter().position(|c| c.service_pubkey == pubkey)
    }

    pub fn by_id(&self, id: &str) -> Option<usize> {
        self.connections.iter().position(|c| c.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(state: &str, booked: i64, spent: i64, at: u64) -> PaymentRec {
        PaymentRec { payment_hash: format!("{state}{at}"), invoice: String::new(), amount_msat: 0, booked_sats: booked, spent_sats: spent,
                     fees_paid_msat: 0, state: state.into(), preimage: None, description: None, description_hash: None, created_at: at,
                     expires_at: None, settled_at: None }
    }

    #[test]
    fn budget_counts_the_last_day_pending_at_their_booking() {
        let mut c = Connection { id: "a".into(), name: "n".into(), created_at: 0, expires_at: 0, budget_sats_per_day: 1000, methods: vec![],
                                 relays: vec![], service_secret: String::new(), service_pubkey: String::new(), client_pubkey: String::new(),
                                 last_used: 0, spent_total_sats: 0, payments: vec![] };
        let now = 10 * DAY_S;
        c.push(rec("settled", 500, 300, now - 10));
        c.push(rec("pending", 200, 0, now - 5));
        c.push(rec("failed", 0, 0, now - 4));
        c.push(rec("settled", 900, 900, now - DAY_S - 1));
        assert_eq!(c.used_24h(now), 500);
        assert_eq!(c.remaining(now), 500);
        assert!(!c.expired(now));
        c.expires_at = now;
        assert!(c.expired(now));
    }

    #[test]
    fn the_state_file_is_private() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("st")).unwrap();
        s.save().unwrap();
        assert_eq!(xbt_svc::mode_of(&d.path().join("st").join(STATE_FILE)) & 0o777, 0o600);
        assert_eq!(xbt_svc::mode_of(&d.path().join("st")) & 0o777, 0o700);
    }
}
