//! The shop paying its own home relays (`docs/PAID-RELAYS.md`, the `relay_pay` section): each app
//! pays the relay it chose as home for what it receives there. For each link key whose home relay
//! is a paid one, a [`RelayPayer`] declares that home and keeps a small prepaid balance there, paid
//! through the wallet's signer (`xbt402_pay`) under the owner's spending rule for relays.
//! The gateway holds no wallet key: what it can spend is what the signer's policy lets the task
//! spend.
use std::io::{BufRead, BufReader, Read as _, Write};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use xbt_iroh_link::relay_pay::{Fetch, PaidRelay, RelayPayer, Step, Wallet};

use crate::config::RelayPayConfig;

/// The payers' status, beside the gateway's config: what the app's relay page reads.
pub const STATUS_FILE: &str = "relay_pay.json";
/// How long a payment waits for the signer: it bounds the call itself.
const PAY_WAIT: Duration = Duration::from_secs(300);
const GET_WAIT: Duration = Duration::from_secs(15);

/// The wallet's signer on its socket: one JSON line each way.
pub struct Signer(pub PathBuf);

impl Wallet for Signer {
    #[cfg(unix)]
    fn pay(&self, params: &Value) -> Result<Value, String> {
        let mut s = std::os::unix::net::UnixStream::connect(&self.0).map_err(|e| format!("signer socket {}: {e}", self.0.display()))?;
        let _ = s.set_write_timeout(Some(GET_WAIT));
        let _ = s.set_read_timeout(Some(PAY_WAIT));
        let req = serde_json::json!({"id": 1, "method": "xbt402_pay", "params": params});
        s.write_all(format!("{req}\n").as_bytes()).map_err(|e| format!("signer socket: {e}"))?;
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).map_err(|e| format!("signer socket: {e}"))?;
        let v: Value = serde_json::from_str(line.trim()).map_err(|e| format!("signer answer: {e}"))?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            return Err(format!("signer error: {}", e.get("message").and_then(Value::as_str).unwrap_or("error")));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    #[cfg(not(unix))]
    fn pay(&self, _params: &Value) -> Result<Value, String> {
        Err("paying relays needs the signer's Unix socket".into())
    }
}

/// A GET of the relay's free routes on its operator's shop.
pub struct Http(ureq::Agent);

impl Default for Http {
    fn default() -> Self {
        Self(ureq::AgentBuilder::new().timeout(GET_WAIT).build())
    }
}

impl Fetch for Http {
    fn get(&self, url: &str) -> Result<Value, String> {
        let r = self.0.get(url).call().map_err(|e| e.to_string())?;
        serde_json::from_reader(r.into_reader().take(64 * 1024)).map_err(|e| e.to_string())
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The paid relay each key is homed on, if any: key `i` is homed on `link_relays[i % n]` (the
/// rotation `start_link` gives each key).
pub fn homes(cfg: &RelayPayConfig, link_relays: &[String], keys: usize) -> Vec<Option<PaidRelay>> {
    (0..keys)
        .map(|i| {
            let home = link_relays.get(i % link_relays.len().max(1))?;
            cfg.relays.iter().find(|r| &r.relay == home).cloned()
        })
        .collect()
}

/// What the payers found at their last round, for the owner's relay page: written to `status`
/// (`relay_pay.json` beside the gateway's config, which the app reads).
pub fn status_value(payers: &[([u8; 32], RelayPayer<Signer, Http>)], last: &[String], now: u64) -> Value {
    let keys: Vec<Value> = payers.iter().zip(last).map(|((s, p), last)| {
        let key = xbt_iroh_link::relay_pay::link_key_hex(s);
        let a = p.accounts.get(&key).cloned().unwrap_or_default();
        serde_json::json!({"relay": p.relay.relay, "key": key, "balance_bytes": a.balance, "waiting": a.waiting, "dropped_bytes": a.dropped_bytes,
                           "charged_in": a.charged_in, "charged_out": a.charged_out, "home": a.home, "paid_msat": p.paid_msat, "last": last})
    }).collect();
    serde_json::json!({"at": now, "keys": keys})
}

/// Run the payers for `secrets` (the link keys, in order) until the process ends; after each
/// round their accounts are written to `status`.
pub fn spawn(cfg: RelayPayConfig, link_relays: Vec<String>, secrets: Vec<[u8; 32]>, status: Option<PathBuf>) {
    let homes = homes(&cfg, &link_relays, secrets.len());
    let mut payers: Vec<([u8; 32], RelayPayer<Signer, Http>)> = secrets
        .into_iter()
        .zip(homes)
        .filter_map(|(s, h)| h.map(|r| (s, RelayPayer::new(r, cfg.bounds(), Signer(cfg.signer.clone()), Http::default()))))
        .collect();
    if payers.is_empty() {
        eprintln!("xbt-gateway: relay_pay: no link key is homed on a paid relay; nothing to pay");
        return;
    }
    let every = cfg.check;
    let mut last = vec![String::new(); payers.len()];
    let _ = std::thread::Builder::new().name("relay-pay".into()).spawn(move || loop {
        for (i, (secret, p)) in payers.iter_mut().enumerate() {
            match p.step(secret, now()) {
                Step::Paid { balance, price_msat } => {
                    eprintln!("xbt-gateway: relay_pay: paid {price_msat} msat to {}; balance {balance} bytes", p.relay.relay);
                    last[i] = format!("paid {price_msat} msat");
                }
                Step::Refused(why) => {
                    eprintln!("xbt-gateway: relay_pay: {} not paid: {why}", p.relay.relay);
                    last[i] = format!("not paid: {why}");
                }
                Step::Enough { .. } => last[i] = "enough credit".into(),
                Step::Waiting { .. } => {}
            }
            if p.accounts.values().any(|a| a.dropped_bytes > 0 && a.waiting) {
                eprintln!("xbt-gateway: relay_pay: {} is dropping this shop's traffic for want of credit", p.relay.relay);
            }
        }
        if let Some(path) = &status {
            let tmp = path.with_extension("json.tmp");
            let v = status_value(&payers, &last, now());
            if std::fs::write(&tmp, format!("{v}\n")).and_then(|_| std::fs::rename(&tmp, path)).is_err() {
                eprintln!("xbt-gateway: relay_pay: could not write {}", path.display());
            }
        }
        std::thread::sleep(every);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_paid_for_at_their_own_home_relay() {
        let paid = PaidRelay { relay: "https://paid.example.com".into(), credit: "https://ops.example.com/r".into(), msat_per_gb: 2_000 };
        let cfg = RelayPayConfig { signer: "/x".into(), task: "relays".into(), relays: vec![paid.clone()], max_msat_per_gb: 4_000,
                                   max_credit_msat: 100_000, max_sats: 1_000, low_water_bytes: 1, check: Duration::from_secs(60) };
        let link = vec!["https://free.example.com".to_string(), "https://paid.example.com".to_string()];
        assert_eq!(homes(&cfg, &link, 3), vec![None, Some(paid), None]);
        assert_eq!(homes(&cfg, &[], 2), vec![None, None]);
    }
}
