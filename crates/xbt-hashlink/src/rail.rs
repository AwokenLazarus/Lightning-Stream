//! How a slice is paid: Lightning Stream's held tickets, one per slice.
//!
//! The buyer makes each ticket's preimage and sends its payment hash (`lock`) before the slice
//! is mined; the hasher's node holds the buyer's payment to that hash (a hold invoice) without
//! being able to settle it. When the slice is done the buyer releases the preimage (`pay`) and
//! the hasher settles. A ticket never released is cancelled and its payment returns to the buyer.
//! So the buyer risks at most the slice in progress and the hasher at most the work done past
//! the last released ticket.
//!
//! [`BuyerRail`] and [`SellerRail`] are where the wallet's ticket machinery plugs in: the buyer's
//! signer pays the hold invoice for each locked hash under the wallet's policy and budgets (a
//! "hashrate" task), and the hasher's node makes and settles the hold invoices. [`LabBuyer`] and
//! [`LabSeller`] stand in for both in the lab: they check the preimages and keep a ledger, and
//! move no money.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Hash = [u8; 32];

pub fn sha256(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}

pub trait BuyerRail: Send {
    /// Lock the ticket for `slice` at `price_msat`: returns its payment hash. (For a real ticket,
    /// the signer pays the hasher's hold invoice for this hash before returning.)
    fn lock(&mut self, slice: u64, price_msat: u64) -> Result<Hash, String>;
    /// Release the ticket for a finished slice: returns its preimage.
    fn release(&mut self, slice: u64) -> Result<[u8; 32], String>;
    /// Give up a ticket never released (its held payment goes back to the buyer).
    fn cancel(&mut self, slice: u64);
}

pub trait SellerRail: Send {
    /// Is the buyer's payment to `hash` held by the hasher's node?
    fn held(&mut self, slice: u64, hash: &Hash, price_msat: u64) -> bool;
    /// Settle a released ticket. `preimage` has already been checked against the hash.
    fn settle(&mut self, slice: u64, preimage: &[u8; 32]) -> Result<(), String>;
}

/// The lab's buyer: fresh preimages, a ledger of locks, releases and cancels.
#[derive(Default)]
pub struct LabBuyer {
    pre: BTreeMap<u64, [u8; 32]>,
    pub locked_msat: u64,
    pub released_msat: u64,
    pub cancelled_msat: u64,
    price: BTreeMap<u64, u64>,
}

impl BuyerRail for LabBuyer {
    fn lock(&mut self, slice: u64, price_msat: u64) -> Result<Hash, String> {
        let mut p = [0u8; 32];
        getrandom::getrandom(&mut p).map_err(|e| e.to_string())?;
        self.pre.insert(slice, p);
        self.price.insert(slice, price_msat);
        self.locked_msat += price_msat;
        Ok(sha256(&p))
    }

    fn release(&mut self, slice: u64) -> Result<[u8; 32], String> {
        let p = self.pre.remove(&slice).ok_or("no ticket locked for that slice")?;
        self.released_msat += self.price.remove(&slice).unwrap_or(0);
        Ok(p)
    }

    fn cancel(&mut self, slice: u64) {
        if self.pre.remove(&slice).is_some() {
            self.cancelled_msat += self.price.remove(&slice).unwrap_or(0);
        }
    }
}

/// The buyer's slices paid through the wallet: each finished slice is one paid request to the
/// hasher's gateway (`POST <url>/<rental>/<slice>`, the signed work receipt as the body), made by
/// the wallet's signer with `xbt402_pay`. The signer keeps the owner's policy (the task's budget,
/// the seller tied to its node, the caps on locked funds), chooses the rail (held tickets, else
/// prepaid ones), locks tickets ahead and releases them; the gateway charges the slice's price
/// only when the hasher's app answers that it counted the slice. Nothing here holds a key.
pub struct SignerPayer {
    pub sock: std::path::PathBuf,
    pub url: String,
    pub task: String,
    pub max_sats: u64,
    pub session: Option<String>,
}

/// One call on the signer's socket.
pub fn signer_call(sock: &std::path::Path, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    use std::io::{BufRead, BufReader, Write};
    let mut s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| format!("signer socket {}: {e}", sock.display()))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(200))).map_err(|e| e.to_string())?;
    let req = serde_json::json!({"id": 1, "method": method, "params": params});
    s.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| format!("signer: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&line).map_err(|_| "signer: not JSON".to_string())?;
    match v.get("error").filter(|e| !e.is_null()) {
        Some(e) => Err(format!("signer: {e}")),
        None => Ok(v.get("result").cloned().unwrap_or_default()),
    }
}

impl SignerPayer {
    /// Pay one slice. `Ok` carries what the signer said (without the seller's body); `Err` why not.
    pub fn pay(&mut self, rental: &str, slice: u64, receipt: &serde_json::Value) -> Result<serde_json::Value, String> {
        let params = serde_json::json!({
            "url": format!("{}/{rental}/{slice}", self.url.trim_end_matches('/')), "method": "POST",
            "body": receipt.to_string(), "max_sats": self.max_sats, "task": self.task,
        });
        let mut r = signer_call(&self.sock, "xbt402_pay", &params)?;
        if let Some(o) = r.as_object_mut() {
            o.remove("untrusted_provider_response");
        }
        if let Some(s) = r.get("session").and_then(serde_json::Value::as_str) {
            self.session = Some(s.to_string());
        }
        let paid = r.get("status").and_then(serde_json::Value::as_u64) == Some(200) && r.get("verdict").and_then(serde_json::Value::as_str) == Some("allow");
        if paid {
            Ok(r)
        } else {
            Err(r.to_string())
        }
    }

    /// End the wallet's session with the hasher's gateway: its unused tickets are cancelled.
    pub fn stop(&mut self) -> Option<serde_json::Value> {
        let s = self.session.take()?;
        Some(signer_call(&self.sock, "ticket_stop", &serde_json::json!({"session": s})).unwrap_or_else(|e| serde_json::json!({"error": e})))
    }
}

/// The lab's seller: every lock is held; settles are counted.
#[derive(Default)]
pub struct LabSeller {
    pub settled_msat: u64,
    pub settled: u64,
    price: BTreeMap<u64, u64>,
}

impl SellerRail for LabSeller {
    fn held(&mut self, slice: u64, _hash: &Hash, price_msat: u64) -> bool {
        self.price.insert(slice, price_msat);
        true
    }

    fn settle(&mut self, slice: u64, _preimage: &[u8; 32]) -> Result<(), String> {
        self.settled_msat += self.price.remove(&slice).ok_or("settle of a ticket never held")?;
        self.settled += 1;
        Ok(())
    }
}
