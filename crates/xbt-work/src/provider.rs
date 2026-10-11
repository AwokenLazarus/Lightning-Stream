//! The provider rail (spec §4.5, §7, §9): an `xbt-work` offer beside `xbt-channel` in the xbt402
//! [`Provider`](xbt402::provider::Provider) ([`Provider::with_scheme`](xbt402::provider::Provider::with_scheme)).
//!
//! * `POST /x402/xbt-work/invoice` issues invoices (128-bit base32 id, a fresh `authKey`, both
//!   usernames), expiring while unfunded. Issuing stores nothing (AGP-091, `Issued`): the
//!   identifier carries its expiry and a MAC, and the `authKey` is derived from it again.
//! * A PAYMENT-SIGNATURE naming `xbt-work` is checked in the §9.1 order (scheme/network/payTo,
//!   grammar, identity and Prime, invoice, `auth` and a fresh `n`, the Ed25519 signature,
//!   equivocation, delta credit, balance), debited and recorded durably before the handler runs,
//!   released if the handler answers ≥ 500, and answered with the `SettlementResponse` of §9.3.
//! * [`WorkProvider::refresh`] pulls the latest receipts through the blinded relay (§11.1), and
//!   [`WorkProvider::audit`] checks a pool coinbase against the book (§10), with the carry ledger.
//! * §13.1 credit caps (AGP-043, [`WorkConfig::caps`]): unaudited credit is capped per invoice and in
//!   total; work beyond the caps is held and credited after the next passing audit. The carry the
//!   Prime owes counts too: above [`WorkConfig::max_owed_carry_sats`], or when it
//!   [keeps growing](crate::audit::CarryLedger::keeps_growing) over
//!   [`WorkConfig::carry_growth_blocks`] audited blocks, no new credit is extended until carry is
//!   released. A call the held work would have paid is refused with `credit_cap`, `carry_cap` or
//!   `carry_growing` (and the balances in `work`), never with a silent loss: the receipts stay held.
//! * AGP-079 (closure audit, P1 and P4): credit stops being unaudited only as far as coinbases paid
//!   for it. A passing audit records the work the block's coinbase paid for at the provider's own
//!   price ([`WorkProvider::paid_work`]), and that covers the oldest credit first. A deferral line,
//!   the `min_payout` clause, a window start moved over the credit and a block with no statement
//!   all leave the audit's verdict as it was and cover nothing. A statement the audit refuses is
//!   the block having no statement ([`WorkProvider::audit_chain`]). [`WorkConfig::shipped`] is what
//!   `xbt-work-provider` runs with when no flag is set.
//! * AGP-065 (review P): the audit takes the block from the provider's own node ([`ChainBlock`]) and
//!   holds the statement to the Prime's pinned [`PrimeTerms`]; window starts must not go backwards
//!   between audited blocks; a block with no statement is audited too ([`WorkProvider::audit_chain`]);
//!   a reorg undoes what an orphaned audit covered ([`WorkProvider::orphaned`]); payouts are split
//!   into liquid and locked by the node's coinbase maturity ([`WorkProvider::payouts`]). An unfunded
//!   invoice past its TTL stays dormant for [`WorkConfig::invoice_grace_secs`] (work mined just
//!   before expiry is still pulled and credited), and state is written outside the state lock,
//!   newest snapshot wins.
//! * AGP-091 (second closure audit, WORK 1 to 7), one rule each, kept in one place: the Prime is
//!   failed only on what it signed for the block, never on what a coinbase paid
//!   ([`WorkProvider::audit_chain`]); a cap in calls is in calls under the pricing rule in force
//!   ([`Cap::units_under`], [`WorkConfig::cap_rule`]); no answer of the Prime's stops the audit
//!   walk ([`crate::walk`]); the unpaid-blocks stop lifts only on a full payment
//!   ([`WorkProvider::audit`]); issuing an invoice costs no state; an admin request carries the
//!   admin token ([`admin_request`]).
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use xbt402::client::Transport;
use xbt402::json::{dumps, obj};
use xbt402::provider::HttpResponse;
use xbt402::scheme::{ProviderScheme, SchemeCharge};
use xbt402::wire::settlement_response;

use crate::audit::{audit_block, window_from_doc, AuditBounds, AuditOutcome, CarryLedger, PrimeTerms, SignedDeferral, SignedWindow, TOLERANCE};
use crate::auth::{auth_tag, request_digest, tag_eq};
use crate::book::{CreditCaps, ReceiptBook};
use crate::chain::{ChainBlock, Maturity};
use crate::error::{fail, Result, WorkError};
use crate::grammar::{canonical_identity, new_invoice, uint, valid_identity, U64};
use crate::pricing::{work_units_for_price, Pricing};
use crate::receipt::{pubkey_from_hex, sig64, Signed, WorkReceipt};
use crate::{ASSET, INVOICE_PATH, SCHEME};

/// How a call's price in sats becomes its `amount` in work units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Amount {
    /// Every call costs this many work units.
    Fixed(u64),
    /// §6.2 exact pricing of the call's sats price at the current epoch (`price_sats` is replaced
    /// by the call's price); `extra.pricing` is published.
    Priced(Pricing),
}

/// A cap on unaudited credit as an operator sets it: in work units, in sats (converted at each
/// epoch's price, no haircut) or in calls at the call price; `Off`: no cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    Work(u64),
    Sats(u64),
    Calls(u64),
    Off,
}

impl Cap {
    /// The cap in work units at this epoch (None: off).
    pub fn units(self, bits: u32, block_value_sats: u64, price_sats: u64) -> Result<Option<u64>> {
        Ok(Some(match self {
            Cap::Work(w) => w,
            Cap::Sats(s) => work_units_for_price(s, bits, block_value_sats, 0, 0)?,
            Cap::Calls(n) => work_units_for_price(price_sats, bits, block_value_sats, 0, 0)?.saturating_mul(n),
            Cap::Off => return Ok(None),
        }))
    }

    /// Whether the cap moves with the epoch.
    pub fn priced(self) -> bool {
        matches!(self, Cap::Sats(_) | Cap::Calls(_))
    }

    /// The cap in work units under the pricing rule in force (AGP-091): a cap in calls is that
    /// many calls at what one call costs under `rule`, never at a price the rule does not charge.
    /// With exact pricing it is [`Cap::units`] at the rule's epoch. With a fixed amount per call a
    /// cap in calls is `calls * amount`, and a cap in sats is turned into calls at
    /// `invoice_price_sats` (rounded down), or at the work's §6.1 value when no sats price is set.
    pub fn units_under(self, rule: &Amount, invoice_price_sats: u64) -> Result<Option<u64>> {
        Ok(Some(match (self, rule) {
            (Cap::Off, _) => return Ok(None),
            (Cap::Work(w), _) => w,
            (c, Amount::Priced(p)) => return c.units(p.bits, p.block_value_sats, p.price_sats),
            (Cap::Calls(n), Amount::Fixed(a)) => n.saturating_mul((*a).max(1)),
            (Cap::Sats(s), Amount::Fixed(a)) if invoice_price_sats > 0 => {
                let w = u128::from(s) * u128::from((*a).max(1)) / u128::from(invoice_price_sats);
                u64::try_from(w).unwrap_or(u64::MAX)
            }
            (Cap::Sats(_), Amount::Fixed(_)) => return fail("bad_pricing", "a cap in sats needs a sats price: none is set with a fixed amount per call"),
        }))
    }
}

/// The two §13.1 caps as an operator sets them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub invoice: Cap,
    pub total: Cap,
}

impl Caps {
    /// What `xbt-work-provider` runs with when the operator sets no cap (review P5): 100 calls of
    /// unaudited credit per invoice and 1,000 in total, in calls so they hold on any chain.
    pub const SHIPPED: Caps = Caps { invoice: Cap::Calls(100), total: Cap::Calls(1000) };

    /// The caps in work units at this epoch. A price that cannot be converted caps at 0 (holds
    /// everything) rather than lifting the cap.
    pub fn at(&self, bits: u32, block_value_sats: u64, price_sats: u64) -> CreditCaps {
        let units = |c: Cap| c.units(bits, block_value_sats, price_sats).unwrap_or(Some(0));
        CreditCaps { per_invoice: units(self.invoice), total: units(self.total) }
    }

    /// The caps in work units under the pricing rule in force ([`Cap::units_under`]). A cap that
    /// cannot be converted caps at 0 (holds everything) rather than lifting the cap.
    pub fn under(&self, rule: &Amount, invoice_price_sats: u64) -> CreditCaps {
        let units = |c: Cap| c.units_under(rule, invoice_price_sats).unwrap_or(Some(0));
        CreditCaps { per_invoice: units(self.invoice), total: units(self.total) }
    }
}

/// The shipped cap on owed carry, in calls at the call price: the value of the shipped total cap.
pub const SHIPPED_MAX_CARRY_CALLS: u64 = 1000;
/// The shipped audit depth (§10.3: RECOMMENDED k = 6).
pub const SHIPPED_AUDIT_DEPTH: u32 = 6;
/// The shipped haircut on the price in work (§6.2), in basis points.
pub const SHIPPED_HAIRCUT_BPS: u32 = 1000;

/// Provider settings.
#[derive(Debug, Clone)]
pub struct WorkConfig {
    /// CAIP-2 network id, as the xbt-channel offer.
    pub network: String,
    /// The payout identity (canonicalised here), `payTo`.
    pub identity: String,
    pub prime_id: u32,
    /// The pinned Prime key as advertised (`primed pubkey` output; the first 32 bytes sign).
    pub prime_pubkey_hex: String,
    /// `extra.receiptUrl`: the Prime's direct receipt query (or the relay).
    pub receipt_url: String,
    /// The blinded relay the provider pulls from and names in invoices (`relayUrl`).
    pub relay_url: Option<String>,
    pub amount: Amount,
    /// The price (sats) an invoice document quotes `amount` for. With [`Amount::Fixed`] it is also
    /// the price coinbase payments are turned into paid-for work at ([`WorkProvider::paid_work`]).
    pub invoice_price_sats: u64,
    pub invoice_ttl_secs: u64,
    pub max_timeout_secs: u64,
    /// Where the book is kept (recorded before each handler runs). None: memory only.
    pub state_path: Option<PathBuf>,
    /// §13.1: caps on unaudited credit, in work units (about one window's value each). Replaced
    /// by what [`WorkConfig::cap_rule`] gives when that is set.
    pub caps: CreditCaps,
    /// The caps as the operator sets them (calls, sats or work units). When set, the provider
    /// derives `caps` from it under the pricing rule in force, when it starts and at every epoch
    /// ([`Caps::under`]): a cap in calls is in calls whatever `amount` says a call costs (AGP-091).
    pub cap_rule: Option<Caps>,
    /// §10.3/§13.1: owed carry above this (sats) stops new credit until carry is released.
    pub max_owed_carry_sats: Option<u64>,
    /// §10.3: owed carry grew over each of the last N audited blocks: stop new credit (set it when the
    /// provider attests every tip, so growth means the Prime is not paying).
    pub carry_growth_blocks: Option<usize>,
    /// AGP-084: stop new credit once this many blocks in a row, since a coinbase last paid for
    /// credit, paid the identity nothing and had no statement while credit was unpaid
    /// ([`WorkProvider::audit_chain`]); a block that pays for credit lifts it. None (the default):
    /// never. Such blocks include every other pool's, so set it only from the rate at which the
    /// Prime's pool finds blocks.
    pub max_unpaid_blocks: Option<u32>,
    /// The chain enforces payee attestation (§13.8): the identity must be a key-path P2TR address.
    pub nta: bool,
    /// The Prime's published pool terms: every window statement is held to them (AGP-065).
    pub terms: PrimeTerms,
    /// An unfunded invoice past its TTL stays dormant this long: a first receipt that shows work
    /// on it is still accepted.
    pub invoice_grace_secs: u64,
    /// Not used since AGP-091: issuing an invoice stores nothing, so there is no per-client limit
    /// and no client to tell apart. Kept so configurations that set it still build.
    pub trust_forwarded: bool,
}

impl WorkConfig {
    pub fn new(network: &str, identity: &str, prime_id: u32, prime_pubkey_hex: &str, receipt_url: &str) -> Self {
        Self { network: network.into(), identity: canonical_identity(identity), prime_id, prime_pubkey_hex: prime_pubkey_hex.into(),
               receipt_url: receipt_url.into(), relay_url: None, amount: Amount::Fixed(1), invoice_price_sats: 0,
               invoice_ttl_secs: 3600, max_timeout_secs: 3600, state_path: None, caps: CreditCaps::default(), cap_rule: None,
               max_owed_carry_sats: None, carry_growth_blocks: None, max_unpaid_blocks: None, nta: false, terms: PrimeTerms::default(), invoice_grace_secs: 3600,
               trust_forwarded: false }
    }

    /// The settings `xbt-work-provider` runs with when no flag is set, at the node's tip (`bits`,
    /// `block_value_sats`) and a call price of `price_sats`: exact pricing with the shipped
    /// haircut, the shipped caps on unaudited credit ([`Caps::SHIPPED`]) and a cap on owed carry
    /// worth [`SHIPPED_MAX_CARRY_CALLS`] calls. The binary applies its flags on top of this.
    pub fn shipped(mut self, bits: u32, block_value_sats: u64, price_sats: u64) -> Self {
        self.invoice_price_sats = price_sats;
        self.amount = Amount::Priced(Pricing { price_sats, bits, block_value_sats, fee_bps: self.terms.fee_bps, haircut_bps: SHIPPED_HAIRCUT_BPS });
        self.caps = Caps::SHIPPED.at(bits, block_value_sats, price_sats);
        self.cap_rule = Some(Caps::SHIPPED);
        self.max_owed_carry_sats = Some(price_sats.saturating_mul(SHIPPED_MAX_CARRY_CALLS));
        self
    }
}

/// Audited blocks deeper than this below the newest one are settled ([`ReceiptBook::settle`]).
pub const SETTLE_DEPTH: u32 = 144;

/// What the provider keeps for an invoice. A record exists only once the book has seen a receipt
/// the Prime signed for the invoice (or the operator retired it): issuing one stores nothing.
#[derive(Debug, Clone)]
struct Invoice {
    key: [u8; 32],
    /// Highest `n` accepted (consumed even when the call is then refused).
    n: u64,
    spent: u64,
    expires_at: u64,
    retired: bool,
}

/// An invoice identifier this provider issued, read back from the identifier alone (AGP-091).
///
/// The rule: **issuing an invoice costs the provider no state**, so no number of requests, from
/// one address or from many, can use up issuance or push another payer's invoice out. The 16 bytes
/// of §4.1 are `expires_at` (4, big-endian seconds), a random nonce (8) and a tag (4):
/// `HMAC-SHA256(secret, "xbt-work/invoice-id|" expires_at nonce)[..4]`. The invoice's `authKey` is
/// `HMAC-SHA256(secret, "xbt-work/invoice-key|" invoice)`. The secret never leaves the provider's
/// state. The tag only tells an identifier of this provider from a stranger's (`unknown_invoice`
/// before `bad_auth`); what authenticates a call is the `authKey`.
struct Issued {
    expires_at: u64,
    key: [u8; 32],
}

/// How many invoices not yet seen in a receipt the relay pull asks for.
pub const PULL_NEW: usize = 64;

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The 16 bytes behind a §4.1 identifier in the form [`crate::grammar::new_invoice`] writes.
fn invoice_bytes(invoice: &str) -> Option<[u8; 16]> {
    if invoice.len() != 26 {
        return None;
    }
    let (mut out, mut acc, mut bits, mut at) = ([0u8; 16], 0u32, 0u32, 0usize);
    for c in invoice.bytes() {
        acc = (acc << 5) | u32::try_from(B32.iter().position(|&x| x == c)?).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(at)? = (acc >> bits) as u8;
            at += 1;
            acc &= (1 << bits) - 1;
        }
    }
    // 26 characters carry 130 bits: the last two are padding and must be zero (one spelling per id)
    (at == 16 && acc == 0).then_some(out)
}

fn hmac32(secret: &[u8; 32], label: &str, data: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(label.as_bytes());
    m.update(data);
    m.finalize().into_bytes().into()
}

impl Issued {
    const ID: &'static str = "xbt-work/invoice-id|";
    const KEY: &'static str = "xbt-work/invoice-key|";

    /// A fresh identifier that expires at `expires_at`, and its `authKey`.
    fn new(secret: &[u8; 32], expires_at: u64) -> (String, Self) {
        let mut b = [0u8; 16];
        // the identifier holds 32 bits of seconds: later than 2106 is written as 2106
        b[..4].copy_from_slice(&u32::try_from(expires_at).unwrap_or(u32::MAX).to_be_bytes());
        getrandom::getrandom(&mut b[4..12]).expect("OS randomness");
        let tag = hmac32(secret, Self::ID, &b[..12]);
        b[12..].copy_from_slice(&tag[..4]);
        let id = new_invoice(&b);
        let key = hmac32(secret, Self::KEY, id.as_bytes());
        (id, Self { expires_at: u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])), key })
    }

    /// Read an identifier back: None when this provider's secret did not issue it.
    fn read(secret: &[u8; 32], invoice: &str) -> Option<Self> {
        let b = invoice_bytes(invoice)?;
        let tag = hmac32(secret, Self::ID, &b[..12]);
        if !tag_eq(&hex::encode(&tag[..4]), &hex::encode(&b[12..])) {
            return None;
        }
        Some(Self { expires_at: u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])), key: hmac32(secret, Self::KEY, invoice.as_bytes()) })
    }

    fn record(&self) -> Invoice {
        Invoice { key: self.key, n: 0, spent: 0, expires_at: self.expires_at, retired: false }
    }
}

struct State {
    /// The secret invoices are issued under (`Issued`); kept in the state file.
    secret: [u8; 32],
    invoices: HashMap<String, Invoice>,
    /// The newest invoices issued and not seen in a receipt yet, (invoice, expires_at): the relay
    /// pull asks for them too. At most [`PULL_NEW`], in memory only, the oldest dropped first. No
    /// invoice depends on being here: one that is dropped is credited when its payer presents a
    /// receipt, as it would be after a restart.
    new: VecDeque<(String, u64)>,
    book: ReceiptBook,
    carry: CarryLedger,
    audits: Vec<Value>,
    /// Set once the Prime key equivocated or failed an audit: its receipts are no longer accepted
    /// (§9.1 step 7, §13.1).
    distrust: Option<(String, String)>,
    /// AGP-084: the run of blocks, since a coinbase last paid for credit, that paid the identity
    /// nothing and had no usable statement while credit was unpaid.
    unpaid: Option<UnpaidRun>,
    /// The next height the audit walk ([`crate::walk::Walk`]) has not passed yet: kept so a
    /// provider that was down does not skip the blocks in between.
    audit_next: Option<u32>,
}

/// Blocks `from..=to` of which `count` had no statement the Prime signed for them that the audit
/// could run on (`refused` of them had one it refused), so nothing they paid covered credit. They
/// carry no verdict: the provider cannot tell the Prime's block from another pool's, whatever the
/// coinbase paid the identity (`paid_sats` in all: anyone can pay an address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnpaidRun {
    from: u32,
    to: u32,
    count: u32,
    refused: u32,
    paid_sats: u64,
}

impl UnpaidRun {
    fn to_json(self) -> Value {
        let mut v = obj([("from", self.from.into()), ("to", self.to.into()), ("count", self.count.into()), ("refused", self.refused.into())]);
        if self.paid_sats > 0 {
            v["paidSats"] = self.paid_sats.into();
        }
        v
    }

    fn from_json(v: &Value) -> Option<Self> {
        let n = |k: &str| v.get(k).and_then(Value::as_u64).and_then(|x| u32::try_from(x).ok());
        // absent in state written before AGP-091 (such a block then failed the audit): none
        let paid_sats = match v.get("paidSats") {
            None => 0,
            Some(p) => p.as_u64()?,
        };
        Some(Self { from: n("from")?, to: n("to")?, count: n("count")?, refused: n("refused")?, paid_sats })
    }
}

/// The refusals that come after the statement verified under the pinned Prime key, for this Prime
/// and this block: the Prime itself says the block is its own (AGP-084).
const SIGNED_FOR_THE_BLOCK: [&str; 2] = ["bad_window", "window_start_regressed"];

/// The `xbt-work` rail of a provider.
pub struct WorkProvider {
    pub cfg: WorkConfig,
    pubkey: VerifyingKey,
    /// The pricing rule in force (`cfg.amount` at start, then each epoch's).
    rule: Mutex<Amount>,
    state: Mutex<State>,
    /// Bumped by each snapshot: the writer never replaces a newer snapshot with an older one.
    generation: AtomicU64,
    /// The generation last written. Lock order: `state`, then `writer`.
    writer: Mutex<u64>,
}

/// A window statement for a block, the Prime's answer that it has none, or no usable answer.
pub enum Statement<'a> {
    Found(&'a SignedWindow, &'a [SignedDeferral]),
    /// The Prime answered that it has no statement for the block (404).
    Missing,
    /// The Prime gave no answer a statement could be read from (an error status, a body that is
    /// no statement, no connection). For the audit it is a block with no statement; the audit walk
    /// asks again ([`crate::walk::Walk`]).
    Unavailable,
}

/// The codes [`WorkProvider::audit`] refuses a statement with (the statement is at fault, not the
/// provider's node or state).
pub const STATEMENT_REFUSALS: [&str; 5] = ["bad_window_sig", "wrong_prime", "wrong_block", "bad_window", "window_start_regressed"];

/// A Prime's statement document for a pool block, as served.
pub type ServedStatement = (SignedWindow, Vec<SignedDeferral>, Value);

/// The Prime's statement for a pool block (`GET <window_url>?height=H`): None when the Prime
/// answers 404 (it has none for that height); any other status is an error, never "none"
/// (review P4: an unreachable Prime must not look like a block with nothing to audit).
pub fn window_statement(t: &dyn Transport, window_url: &str, height: u32) -> Result<Option<ServedStatement>> {
    let r = t.request("GET", &format!("{window_url}?height={height}"), b"", &[])?;
    match r.status {
        200 => {}
        404 => return Ok(None),
        s => return Err(WorkError::new("prime", format!("window statement for {height}: HTTP {s}"))),
    }
    let doc = xbt402::json::parse_slice(&r.body).map_err(|_| WorkError::new("prime", "window statement is not JSON"))?;
    let (w, d) = window_from_doc(&doc).map_err(|e| WorkError::new("prime", e.0))?;
    Ok(Some((w, d, doc)))
}

/// The admin token kept in `path`: read, or made (32 random bytes in hex, mode 0600) when the
/// file does not exist. A file that is there and holds no token is an error, never a new token.
pub fn admin_token(path: &std::path::Path) -> Result<String> {
    let io = |e: std::io::Error| WorkError::new("state_io", format!("{}: {e}", path.display()));
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().len() >= 32 && t.trim().bytes().all(|b| b.is_ascii_graphic()) => Ok(t.trim().to_string()),
        Ok(_) => fail("bad_config", format!("{}: not an admin token (at least 32 printable characters)", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let t = hex::encode(random32());
            crate::fsx::write_private(path, format!("{t}\n").as_bytes()).map_err(io)?;
            Ok(t)
        }
        Err(e) => Err(io(e)),
    }
}

/// Whether a request may use the admin endpoints (AGP-091).
///
/// The rule: **an admin request proves it comes from the operator by carrying the admin token**
/// (`Authorization: Bearer <token>`, the token a file only the operator's account reads). Where
/// the request came from proves nothing: `xbt-work-provider` listens on loopback, so behind a
/// proxy on the same host every client on the internet is a loopback peer, and that was the only
/// check. The peer must still be loopback as well (`peer` is the address the server saw).
pub fn admin_request(headers: &[(String, String)], peer: Option<&str>, token: &str) -> bool {
    let local = peer.and_then(|p| p.parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback());
    let given: Vec<&str> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("Authorization")).map(|(_, v)| v.as_str()).collect();
    // exactly one Authorization header, and it is ours
    let bearer = match given.as_slice() {
        [one] => one.strip_prefix("Bearer ").unwrap_or(""),
        _ => "",
    };
    local && token.len() >= 32 && tag_eq(bearer, token)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

impl WorkProvider {
    pub fn new(mut cfg: WorkConfig) -> Result<Self> {
        if !valid_identity(&cfg.identity) {
            return fail("bad_config", "identity outside the grammar (§4.2)");
        }
        if cfg.nta {
            // §13.8 rule 1: any other script cannot be a payee; the Prime could only carry its share forever
            let spk = xbt_primitives::address::address_to_spk(&cfg.identity, None).unwrap_or_default();
            if !crate::nta::is_payee_script(&spk) {
                return fail("bad_config", "the identity is not a key-path P2TR address: it cannot be paid under payee attestation (§13.8)");
            }
        }
        let pubkey = pubkey_from_hex(&cfg.prime_pubkey_hex).map_err(|e| WorkError::new("bad_config", e.0))?;
        let mut book = ReceiptBook::new(&cfg.identity, pubkey, cfg.prime_id);
        book.caps = cfg.caps;
        cfg.terms.bounds(&ChainBlock { height: 0, hash: String::new(), value_sats: 0, paid_sats: 0, bits: 0x1d00ffff, prev_bits: 0x1d00ffff })?;
        if let Some(rule) = &cfg.cap_rule {
            cfg.caps = rule.under(&cfg.amount, cfg.invoice_price_sats);
            book.caps = cfg.caps;
        }
        let st = State { secret: random32(), invoices: HashMap::new(), new: VecDeque::new(), book, carry: CarryLedger::default(), audits: vec![], distrust: None, unpaid: None,
                         audit_next: None };
        let wp = Self { pubkey, rule: Mutex::new(cfg.amount.clone()), state: Mutex::new(st), generation: AtomicU64::new(0), writer: Mutex::new(0), cfg };
        // a state file that holds no secret yet (none, or one from before AGP-091) gets this one
        // now: an invoice issued before the first save must still be known after a restart
        if !wp.load()? {
            wp.save(&wp.lock())?;
        }
        wp.carry_rules(&mut wp.lock());
        Ok(wp)
    }

    /// §10.3/§13.1: freeze new credit while the owed carry is over its cap or keeps growing.
    fn carry_rules(&self, st: &mut State) {
        st.book.frozen = if self.cfg.max_owed_carry_sats.is_some_and(|m| st.carry.owed() > m) {
            Some("carry_cap".into())
        } else if self.cfg.carry_growth_blocks.is_some_and(|n| st.carry.keeps_growing(n)) {
            Some("carry_growing".into())
        } else if self.cfg.max_unpaid_blocks.is_some_and(|n| st.unpaid.is_some_and(|u| u.count >= n)) {
            Some("unpaid_blocks".into())
        } else {
            None
        };
    }

    /// Change the caps (e.g. re-derived from sats at a new epoch). Held work the new caps allow is
    /// credited at once.
    pub fn set_caps(&self, caps: CreditCaps) -> Result<Vec<(String, u64)>> {
        let mut st = self.lock();
        st.book.caps = caps;
        let r = st.book.release_held();
        self.save(&st)?;
        Ok(r)
    }

    /// (unaudited, held) work: credit no coinbase has paid for yet, and receipted work the caps hold back.
    pub fn exposure(&self) -> (u64, u64) {
        let st = self.lock();
        (st.book.unaudited_work(None), st.book.held_total())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn prime_pubkey(&self) -> &VerifyingKey {
        &self.pubkey
    }

    /// The advertised key: the 32-byte Ed25519 key in hex.
    pub fn prime_pubkey_hex(&self) -> String {
        hex::encode(self.pubkey.as_bytes())
    }

    /// A new epoch (§6.3): re-price new 402s at `bits` and `block_value_sats`. Balances are kept
    /// in work units and never revalued. Returns whether the price inputs changed.
    pub fn set_epoch(&self, bits: u32, block_value_sats: u64) -> bool {
        let rule = {
            let mut r = self.rule.lock().unwrap_or_else(|p| p.into_inner());
            match &mut *r {
                Amount::Priced(p) if (p.bits, p.block_value_sats) != (bits, block_value_sats) => {
                    p.bits = bits;
                    p.block_value_sats = block_value_sats;
                    r.clone()
                }
                _ => return false,
            }
        };
        // caps set in calls or sats follow the price (AGP-091: derived here, from the rule in force)
        if let Some(caps) = &self.cfg.cap_rule {
            let mut st = self.lock();
            st.book.caps = caps.under(&rule, self.cfg.invoice_price_sats);
            st.book.release_held();
            // caps are configuration, derived again at the next start; held work the new caps
            // admit is credited again then if this write fails
            let _ = self.save(&st);
        }
        true
    }

    /// The caps on unaudited credit in force, in work units.
    pub fn caps(&self) -> CreditCaps {
        self.lock().book.caps
    }

    /// The pricing rule in force.
    pub fn rule(&self) -> Amount {
        self.rule.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Work units a call priced `price_sats` costs.
    pub fn amount(&self, price_sats: u64) -> Result<u64> {
        match &self.rule() {
            Amount::Fixed(n) => Ok((*n).max(1)),
            Amount::Priced(p) => Pricing { price_sats, ..p.clone() }.amount(),
        }
    }

    /// The §7 PaymentRequirements for `amount` work units.
    pub fn requirements_for(&self, amount: u64, price_sats: u64) -> Value {
        let mut extra = obj([("invoiceUrl", INVOICE_PATH.into()), ("primeId", self.cfg.prime_id.into()),
                             ("primePubkey", self.prime_pubkey_hex().into()), ("receiptUrl", self.cfg.receipt_url.clone().into()),
                             ("usernameForms", Value::from(vec!["pw", "tilde"])), ("invoiceTtlSeconds", self.cfg.invoice_ttl_secs.into())]);
        if let Amount::Priced(p) = &self.rule() {
            extra["pricing"] = Pricing { price_sats, ..p.clone() }.to_json();
        }
        obj([("scheme", SCHEME.into()), ("network", self.cfg.network.clone().into()), ("amount", amount.to_string().into()),
             ("asset", ASSET.into()), ("payTo", self.cfg.identity.clone().into()), ("maxTimeoutSeconds", self.cfg.max_timeout_secs.into()),
             ("extra", extra)])
    }

    fn refusal(&self, url: &str, amount: u64, price_sats: u64, code: &str, work: Option<Value>) -> Value {
        let mut v = obj([("x402Version", 2.into()), ("error", code.into()), ("resource", obj([("url", url.into())])),
                         ("accepts", Value::from(vec![self.requirements_for(amount, price_sats)]))]);
        if let Some(w) = work {
            v["work"] = w;
        }
        v
    }

    /// §4.5: issue an invoice. Nothing is written and no record is kept (`Issued`): the
    /// identifier carries its expiry and the provider derives the `authKey` again when a call
    /// presents it, so issuance cannot be used up and no invoice is ever pushed out for another
    /// (AGP-091). The newest [`PULL_NEW`] are remembered for the relay pull, nothing more.
    pub fn issue_invoice(&self) -> Result<Value> {
        let amount = self.amount(self.cfg.invoice_price_sats)?;
        let mut st = self.lock();
        let (inv, issued) = Issued::new(&st.secret, now().saturating_add(self.cfg.invoice_ttl_secs));
        if st.new.len() >= PULL_NEW {
            st.new.pop_front();
        }
        st.new.push_back((inv.clone(), issued.expires_at));
        drop(st);
        let (key, exp) = (issued.key, issued.expires_at);
        let id = &self.cfg.identity;
        let mut doc = obj([("invoice", inv.clone().into()), ("identity", id.clone().into()), ("network", self.cfg.network.clone().into()),
                           ("username", format!("{id}.pw-{inv}.<worker>").into()), ("usernameAlt", format!("{id}~{inv}.<worker>").into()),
                           ("authKey", hex::encode(key).into()), ("amount", amount.to_string().into()), ("primeId", self.cfg.prime_id.into()),
                           ("primePubkey", self.prime_pubkey_hex().into()), ("expiresAt", exp.into()),
                           ("receiptUrl", format!("{}?identity={id}&invoice={inv}", self.cfg.receipt_url).into())]);
        if let Some(r) = &self.cfg.relay_url {
            doc["relayUrl"] = r.clone().into();
        }
        Ok(doc)
    }

    /// Retire an invoice: its balance can no longer be spent (§9.1 step 4).
    pub fn retire(&self, invoice: &str) -> Result<()> {
        let mut st = self.lock();
        if !st.invoices.contains_key(invoice) {
            // issued and not seen yet: the record is what remembers that it is retired
            let Some(issued) = Issued::read(&st.secret, invoice) else { return Ok(()) };
            st.invoices.insert(invoice.to_string(), issued.record());
        }
        if let Some(i) = st.invoices.get_mut(invoice) {
            i.retired = true;
        }
        self.save(&st)
    }

    /// (credited, spent) of an invoice.
    pub fn balance(&self, invoice: &str) -> Option<(u64, u64)> {
        let st = self.lock();
        let i = st.invoices.get(invoice)?;
        Some((st.book.credited.get(invoice).copied().unwrap_or(0), i.spent))
    }

    /// The invoices receipts are pulled for: those with a record (funded, or unfunded and not
    /// past TTL plus grace), and the newest [`PULL_NEW`] issued that no receipt was seen for yet.
    /// An invoice in neither set is credited when its payer presents a receipt.
    pub fn invoices(&self) -> Vec<String> {
        let st = self.lock();
        let t = now();
        let grace = self.cfg.invoice_grace_secs;
        let mut v: Vec<String> = st.invoices.iter()
            .filter(|(k, i)| !i.retired && (st.book.credited.contains_key(*k) || st.book.funded(k) || i.expires_at.saturating_add(grace) >= t))
            .map(|(k, _)| k.clone())
            .chain(st.new.iter().filter(|(k, e)| !st.invoices.contains_key(k) && e.saturating_add(grace) >= t).map(|(k, _)| k.clone()))
            .collect();
        v.sort();
        v
    }

    /// A copy of the receipt book.
    pub fn book(&self) -> ReceiptBook {
        self.lock().book.clone()
    }

    /// Offer a receipt to the book (from the relay, the Prime, or a payer): the newly credited work.
    pub fn accept(&self, s: &Signed) -> Result<u64> {
        let mut st = self.lock();
        let invoice = s.receipt.invoice.clone();
        let issued = match st.invoices.contains_key(&invoice) {
            true => None,
            // issued here and not yet seen: as at a call, not past its TTL and grace
            false => Some(Issued::read(&st.secret, &invoice).filter(|i| i.expires_at.saturating_add(self.cfg.invoice_grace_secs) >= now())
                              .ok_or_else(|| WorkError::new("unknown_invoice", "not an invoice this provider issued, or one that expired with no work on it"))?),
        };
        if issued.is_some() && s.receipt.cum_work == 0 {
            // no work yet: nothing to credit and nothing to keep
            return if s.verify(&self.pubkey) { Ok(0) } else { fail("bad_sig", "not signed by the pinned Prime key") };
        }
        let r = st.book.accept(s, &invoice);
        if let (Some(issued), Ok(_)) = (issued, &r) {
            // the Prime signed work for it: from here on the invoice has a record
            st.new.retain(|(k, _)| *k != invoice);
            st.invoices.insert(invoice, issued.record());
        }
        let snap = self.snapshot(&st);
        drop(st);
        self.write(snap)?;
        r
    }

    /// Pull the latest receipt of every live invoice through the blinded relay (§11.1) and credit
    /// it: returns (invoice, newly credited work) for each receipt that verified.
    pub fn refresh(&self, t: &dyn Transport) -> Vec<(String, Result<u64>)> {
        let Some(relay) = self.cfg.relay_url.clone() else { return vec![] };
        let mut out = vec![];
        for inv in self.invoices() {
            let r = crate::relay::fetch(t, &relay, &self.cfg.identity, &inv).and_then(|doc| match doc {
                None => Ok(0),
                Some(d) => {
                    let s = Signed::from_doc(&d).map_err(WorkError::from)?;
                    if s.receipt.invoice != inv {
                        return fail("wrong_invoice", "relay blob holds another invoice");
                    }
                    self.accept(&s)
                }
            });
            out.push((inv, r));
        }
        out
    }

    /// The bounds a statement for `block` is held to under the pinned terms.
    pub fn bounds(&self, block: &ChainBlock) -> Result<AuditBounds> {
        self.cfg.terms.bounds(block)
    }

    /// Work units the coinbase of `block` paid for (AGP-079): what it paid the identity, at the
    /// price the provider sells work for and at that block's own difficulty and value. With exact
    /// pricing it is the work `paid_sats` buys under §6.2 (the pinned fee and the haircut); with a
    /// fixed amount per call, `paid_sats` at [`WorkConfig::invoice_price_sats`] per call, or at the
    /// work's §6.1 value when no sats price is set. Nothing a Prime signs enters it.
    pub fn paid_work(&self, block: &ChainBlock) -> Result<u64> {
        if block.paid_sats == 0 {
            return Ok(0);
        }
        match self.rule() {
            Amount::Priced(p) => work_units_for_price(block.paid_sats, block.bits, block.value_sats, p.fee_bps, p.haircut_bps),
            Amount::Fixed(n) if self.cfg.invoice_price_sats > 0 => {
                let w = u128::from(block.paid_sats) * u128::from(n.max(1)) / u128::from(self.cfg.invoice_price_sats);
                Ok(u64::try_from(w).unwrap_or(u64::MAX))
            }
            Amount::Fixed(_) => work_units_for_price(block.paid_sats, block.bits, block.value_sats, self.cfg.terms.fee_bps, 0),
        }
    }

    /// §10.3 for one pool coinbase, `block` as the provider's node has it: records the verdict (and
    /// the carry it defers or releases). Auditing a block again (more receipts, the statement's
    /// lines fetched again) replaces its earlier verdict, carry and payment, so nothing is counted
    /// twice. A pass covers only the credit the coinbase paid for ([`WorkProvider::paid_work`],
    /// AGP-079), oldest first; held work is credited as far as the caps then allow. A statement
    /// whose window start is below that of an audited block beneath it (or above one over it) is
    /// refused with `window_start_regressed`, recording nothing. A refusal here is one of
    /// [`STATEMENT_REFUSALS`]; [`WorkProvider::audit_chain`] counts it against the Prime.
    pub fn audit(&self, sw: &SignedWindow, deferred: &[SignedDeferral], block: &ChainBlock) -> Result<AuditOutcome> {
        let bounds = self.bounds(block)?;
        let paid_for = self.paid_work(block)?;
        let mut st = self.lock();
        let o = audit_block(&st.book, sw, block, &bounds, deferred)?;
        let (h, ws) = (sw.stmt.height, sw.stmt.window_start);
        for a in &st.audits {
            let (Some(ah), Some(aws)) = (a.get("height").and_then(Value::as_u64), a.get("windowStart").and_then(Value::as_u64)) else { continue };
            if (ah < u64::from(h) && aws > u64::from(ws)) || (ah > u64::from(h) && aws < u64::from(ws)) {
                return fail("window_start_regressed", format!("window start {ws} at {h}, {aws} at {ah}"));
            }
        }
        st.carry.record(h, &o);
        if !o.ok && st.distrust.is_none() {
            st.distrust = Some(("wrong_prime".into(), format!("the Prime's coinbase at height {h} failed the audit")));
        }
        let paid_for = if o.ok { paid_for } else { 0 };
        let covered = st.book.pay(h, paid_for);
        // The run of unpaid blocks (AGP-084) ends when no credit is unpaid, or at a block the Prime
        // paid in full for all of it: the audit passed on what the coinbase itself paid (no
        // deferral line, no `min_payout` clause), and the statement's window holds at least the
        // credit still unpaid, so `expected` was the block's share of all of it. A passing block
        // that paid 1 sat under a window moved past the credit is not "the Prime pays again": it
        // leaves the run, and the stop it set, as they were (AGP-091).
        let left = st.book.unaudited_work(None);
        let paid_in_full = o.ok && o.expected_sats > 0 && block.paid_sats.saturating_add(TOLERANCE) >= o.expected_sats;
        // and only a block above the run ends it: an older block audited again (a restart walks
        // the last blocks again) paid before the run began
        let after_run = st.unpaid.is_none_or(|u| h > u.to);
        if left == 0 || (paid_in_full && after_run && o.proven_work >= left) {
            st.unpaid = None;
        }
        self.carry_rules(&mut st);
        st.book.release_held();
        let mut rec = obj([("height", h.into()), ("blockHash", block.hash.clone().into()), ("ok", o.ok.into()),
                           ("expectedSats", o.expected_sats.into()), ("paidSats", block.paid_sats.into()), ("deferredSats", o.deferred_sats.into()),
                           ("belowMinSats", o.below_min_sats.into()), ("provenWork", o.proven_work.into()), ("paidForWork", paid_for.into()),
                           ("coveredWork", covered.into()), ("windowStart", ws.into()), ("windowWork", o.window_work.into()),
                           ("bounded", o.bounded.into()), ("owedCarrySats", st.carry.owed().into())]);
        if let Some(p) = &o.proof {
            rec["proof"] = p.clone();
        }
        self.record(&mut st, rec)?;
        Ok(o)
    }

    /// Audit `block` whether or not the Prime published a usable statement for it (review P4).
    ///
    /// The rule (AGP-091): **the Prime is failed only on what the Prime signed for this block.**
    /// A verdict needs a statement that verifies under the pinned key for this Prime and names
    /// this block and height: one the audit runs on ([`WorkProvider::audit`]), or one it then
    /// refuses (`SIGNED_FOR_THE_BLOCK`), which fails and distrusts the Prime whatever the coinbase
    /// paid. Everything else is the block having no statement: none at all, one for another block
    /// or height, one under another key, an answer that is no statement
    /// ([`Statement::Unavailable`]). Such a block has no verdict and covers nothing, **whatever its
    /// coinbase paid the identity**: the identity is public (`payTo` of every 402) and anyone who
    /// mines a block can put an output to it in their own coinbase, so a payment says nothing
    /// about whose block it is. Before, a paid block with no statement failed the audit, and one
    /// sat in a stranger's coinbase distrusted an honest Prime for good.
    ///
    /// A Prime gains nothing by it: a block it pays in and gives no statement for covers nothing,
    /// which is less than the same block with an honest statement, and the credit stays unaudited,
    /// inside the caps, until some coinbase pays for it under a statement. Returns None for the
    /// block with no verdict. While credit is unpaid such a block is counted (AGP-084: the
    /// report's `unpaidBlocks`, and [`WorkConfig::max_unpaid_blocks`]).
    pub fn audit_chain(&self, block: &ChainBlock, stmt: Statement<'_>) -> Result<Option<AuditOutcome>> {
        let refused = match stmt {
            Statement::Found(sw, deferred) => match self.audit(sw, deferred, block) {
                Ok(o) => return Ok(Some(o)),
                Err(e) if STATEMENT_REFUSALS.contains(&e.code.as_str()) => Some(e),
                Err(e) => return Err(e),
            },
            Statement::Missing | Statement::Unavailable => None,
        };
        let Some(e) = refused.as_ref().filter(|e| SIGNED_FOR_THE_BLOCK.contains(&e.code.as_str())) else {
            self.unstated_block(block, refused.is_some())?;
            return Ok(None);
        };
        let mut st = self.lock();
        let mut rec = obj([("height", block.height.into()), ("blockHash", block.hash.clone().into()), ("ok", false.into()),
                           ("paidSats", block.paid_sats.into())]);
        rec["refusedStatement"] = e.to_string().into();
        let paid = if block.paid_sats == 0 { "paid the identity nothing" } else { "paid the identity" };
        if st.distrust.is_none() {
            st.distrust = Some(("refused_statement".into(),
                                format!("the coinbase at height {} {paid} under a window statement the Prime signed for it and the audit refuses: {e}", block.height)));
        }
        st.carry.forget(block.height);
        st.book.pay(block.height, 0);
        self.carry_rules(&mut st);
        self.record(&mut st, rec)?;
        Ok(Some(AuditOutcome { ok: false, expected_sats: 0, paid_sats: block.paid_sats, deferred_sats: 0, below_min_sats: 0, proven_work: 0,
                               window_work: 0, fee_bps: 0, min_payout: 0, bounded: false, proof: None }))
    }

    /// A block with no statement the Prime signed for it: no verdict, and nothing it paid covers
    /// credit. An audit recorded at that height for another block (the chain moved under it) is
    /// undone; one recorded for this block stands (the Prime signed it and the audit ran on it).
    /// Counted (AGP-084) only while credit is unpaid: with nothing owed it is nobody's debt. A
    /// height at or below the run's last one was counted already (the audit walks a range again
    /// after a node error, asks again for a statement it could not get, and the admin audit takes
    /// any range).
    fn unstated_block(&self, block: &ChainBlock, refused: bool) -> Result<()> {
        let mut st = self.lock();
        let height = block.height;
        let stale = st.audits.iter().any(|a| a.get("height").and_then(Value::as_u64) == Some(u64::from(height))
                                         && a.get("blockHash").and_then(Value::as_str) != Some(block.hash.as_str()));
        if stale {
            st.audits.retain(|a| a.get("height").and_then(Value::as_u64) != Some(u64::from(height)));
            st.carry.forget(height);
            st.book.uncover(height);
        }
        if st.book.unaudited_work(None) == 0 {
            if st.unpaid.take().is_some() || stale {
                self.carry_rules(&mut st);
                st.book.release_held();
                self.save(&st)?;
            }
            return Ok(());
        }
        let run = match st.unpaid {
            Some(u) if height <= u.to => {
                if stale {
                    self.carry_rules(&mut st);
                    self.save(&st)?;
                }
                return Ok(());
            }
            Some(u) => UnpaidRun { to: height, count: u.count.saturating_add(1), refused: u.refused.saturating_add(u32::from(refused)),
                                   paid_sats: u.paid_sats.saturating_add(block.paid_sats), ..u },
            None => UnpaidRun { from: height, to: height, count: 1, refused: u32::from(refused), paid_sats: block.paid_sats },
        };
        st.unpaid = Some(run);
        self.carry_rules(&mut st);
        self.save(&st)
    }

    fn record(&self, st: &mut MutexGuard<'_, State>, rec: Value) -> Result<()> {
        let h = rec.get("height").and_then(Value::as_u64);
        st.audits.retain(|a| a.get("height").and_then(Value::as_u64) != h);
        st.audits.push(rec);
        st.audits.sort_by_key(|a| a.get("height").and_then(Value::as_u64));
        // settle what lies deeper than any reorg the audit loop expects
        let newest = st.audits.last().and_then(|a| a.get("height")?.as_u64()).unwrap_or(0);
        let deep = st.audits.iter().rev().find_map(|a| {
            let h = a.get("height")?.as_u64()?;
            (h.saturating_add(u64::from(SETTLE_DEPTH)) <= newest).then_some((h, a.get("windowStart")?.as_u64()?))
        });
        if let Some((h, ws)) = deep {
            st.book.settle(u32::try_from(h).unwrap_or(u32::MAX), u32::try_from(ws).unwrap_or(u32::MAX));
        }
        self.save(st)
    }

    /// The audited blocks: (height, hash), lowest first. The audit loop checks them against its node.
    pub fn audited_blocks(&self) -> Vec<(u32, String)> {
        self.lock().audits.iter().filter_map(|a| Some((u32::try_from(a.get("height")?.as_u64()?).ok()?, a.get("blockHash")?.as_str()?.to_string()))).collect()
    }

    /// The audited block at `height` left the chain (review P6): its verdict, carry and payment are
    /// undone (the credit it covered counts against the caps again). Returns the credit that is
    /// unaudited again, or None when no audit was recorded there.
    pub fn orphaned(&self, height: u32) -> Result<Option<u64>> {
        let mut st = self.lock();
        let before = st.audits.len();
        st.audits.retain(|a| a.get("height").and_then(Value::as_u64) != Some(u64::from(height)));
        if st.audits.len() == before {
            return Ok(None);
        }
        st.carry.forget(height);
        let back = st.book.uncover(height);
        self.carry_rules(&mut st);
        self.save(&st)?;
        Ok(Some(back))
    }

    /// What the audited coinbases paid the identity at chain height `tip`, split by the node's
    /// coinbase maturity: (liquid, locked) sats. A locked payout counts as paid for the audit (the
    /// coinbase paid the identity) but cannot be spent yet: a provider that sells credit against
    /// its payouts should count only the liquid part as money in hand.
    pub fn payouts(&self, tip: u32, maturity: &Maturity) -> (u64, u64) {
        let st = self.lock();
        st.audits.iter().filter_map(|a| Some((u32::try_from(a.get("height")?.as_u64()?).ok()?, a.get("paidSats")?.as_u64()?)))
            .fold((0u64, 0u64), |(l, k), (h, p)| if maturity.relay_at(h) <= tip.saturating_add(1) { (l.saturating_add(p), k) } else { (l, k.saturating_add(p)) })
    }

    pub fn carry(&self) -> CarryLedger {
        self.lock().carry.clone()
    }

    /// Audit log, equivocations and carry, as JSON.
    pub fn report(&self) -> Value {
        let st = self.lock();
        let caps = |c: Option<u64>| c.map(Value::from).unwrap_or(Value::Null);
        let t = &self.cfg.terms;
        let credit = obj([("unauditedWork", st.book.unaudited_work(None).into()), ("heldWork", st.book.held_total().into()),
                          ("paidForWork", u64::try_from(st.book.paid_work()).unwrap_or(u64::MAX).into()),
                          ("capInvoiceWork", caps(st.book.caps.per_invoice)), ("capTotalWork", caps(st.book.caps.total)),
                          ("primeTerms", obj([("window", t.window.into()), ("windowMinWork", t.window_min_work.into()),
                                              ("windowToleranceBps", t.window_tolerance_bps.into()), ("feeBps", t.fee_bps.into()),
                                              ("maxMinPayout", t.max_min_payout.into())])),
                          ("maxOwedCarrySats", caps(self.cfg.max_owed_carry_sats)),
                          ("frozen", st.book.frozen.clone().map(Value::from).unwrap_or(Value::Null))]);
        obj([("audits", st.audits.clone().into()), ("carry", st.carry.to_json()), ("credit", credit),
             ("unpaidBlocks", st.unpaid.map(UnpaidRun::to_json).unwrap_or(Value::Null)),
             ("distrust", st.distrust.as_ref().map(|(c, m)| obj([("code", c.clone().into()), ("why", m.clone().into())])).unwrap_or(Value::Null)),
             ("equivocations", st.book.fraud.iter().map(|e| e.to_json()).collect::<Vec<_>>().into()),
             ("intervals", st.book.to_json()["intervals"].clone())])
    }

    // --- durable state ------------------------------------------------------------------------

    /// Write the state while holding the state lock (paths that keep using it after the write).
    fn save(&self, st: &State) -> Result<()> {
        self.write(self.snapshot(st))
    }

    /// Serialise the state for [`WorkProvider::write`], which may run after the state lock is
    /// released. Taken only under the state lock, so generations follow the state's order.
    fn snapshot(&self, st: &State) -> Option<(u64, String)> {
        self.cfg.state_path.as_ref()?;
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        Some((generation, dumps(&self.state_doc(st))))
    }

    /// Write a snapshot unless a newer one was written already. A failed write leaves the
    /// generation unwritten, so an older snapshot may still land; its caller gets the error.
    fn write(&self, snap: Option<(u64, String)>) -> Result<()> {
        let (Some(path), Some((generation, body))) = (&self.cfg.state_path, snap) else { return Ok(()) };
        let mut last = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        if generation <= *last {
            return Ok(());
        }
        crate::fsx::write_private(path, body.as_bytes()).map_err(|e| WorkError::new("state_io", e.to_string()))?;
        *last = generation;
        Ok(())
    }

    fn state_doc(&self, st: &State) -> Value {
        let inv: serde_json::Map<String, Value> = st.invoices.iter().map(|(k, i)| {
            (k.clone(), obj([("key", hex::encode(i.key).into()), ("n", i.n.into()), ("spent", i.spent.into()),
                             ("expiresAt", i.expires_at.into()), ("retired", i.retired.into())]))
        }).collect();
        obj([("version", 3.into()), ("identity", self.cfg.identity.clone().into()), ("invoices", Value::Object(inv)),
                       ("book", st.book.to_json()), ("audits", st.audits.clone().into()),
                       ("carry", obj([("deferred", st.carry.deferred_total.into()), ("released", st.carry.released_total.into()),
                                      ("blocks", st.carry.blocks.iter().map(|(h, e, p, d)| Value::from(vec![Value::from(*h), Value::from(*e), Value::from(*p), Value::from(*d)])).collect::<Vec<_>>().into())])),
                       ("distrust", st.distrust.as_ref().map(|(c, m)| Value::from(vec![c.clone(), m.clone()])).unwrap_or(Value::Null)),
                       ("unpaid", st.unpaid.map(UnpaidRun::to_json).unwrap_or(Value::Null)),
                       ("invoiceSecret", hex::encode(st.secret).into()),
                       ("auditNext", st.audit_next.map(Value::from).unwrap_or(Value::Null))])
    }

    /// Read the state file. Returns whether it held the invoice secret (false: no file, or one
    /// written before AGP-091, and the secret made at start has to be written).
    fn load(&self) -> Result<bool> {
        let Some(path) = &self.cfg.state_path else { return Ok(true) };
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(WorkError::new("state_io", e.to_string())),
        };
        let bad = |w: &str| WorkError::new("bad_state", w.to_string());
        let v = xbt402::json::parse_slice(&raw).map_err(|_| bad("not JSON"))?;
        if v.get("identity").and_then(Value::as_str) != Some(self.cfg.identity.as_str()) {
            return Err(bad("state is for another identity"));
        }
        // versions 1 (AGP-032/043) and 2 (AGP-065) migrate: the book rebuilds its unpaid credit
        // from `unaudited` or from the spans
        if !matches!(v.get("version").and_then(Value::as_u64), Some(1..=3)) {
            return Err(bad("unknown state version"));
        }
        let mut st = self.lock();
        for (k, i) in v.get("invoices").and_then(Value::as_object).into_iter().flatten() {
            let key: [u8; 32] = i.get("key").and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok())
                .ok_or_else(|| bad("invoice key"))?;
            let u = |f: &str| i.get(f).and_then(Value::as_u64).ok_or_else(|| bad(f));
            st.invoices.insert(k.clone(), Invoice { key, n: u("n")?, spent: u("spent")?, expires_at: u("expiresAt")?,
                                                   retired: i.get("retired").and_then(Value::as_bool).unwrap_or(false) });
        }
        // absent in state written before AGP-091: the secret made at start; present, it must read
        let secret = match v.get("invoiceSecret") {
            None => None,
            Some(h) => Some(h.as_str().and_then(|h| hex::decode(h).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| bad("invoiceSecret"))?),
        };
        if let Some(k) = secret {
            st.secret = k;
        }
        st.audit_next = match v.get("auditNext") {
            None | Some(Value::Null) => None,
            Some(n) => Some(n.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| bad("auditNext"))?),
        };
        if let Some(b) = v.get("book") {
            st.book.load(b)?;
        }
        st.audits = v.get("audits").and_then(Value::as_array).cloned().unwrap_or_default();
        if v.get("version").and_then(Value::as_u64) != Some(3) {
            // state from before AGP-079: what its audits covered is already taken as paid for, so
            // auditing those blocks again must not count their payments a second time
            let newest = st.audits.iter().filter_map(|a| a.get("height")?.as_u64()).max().unwrap_or(0);
            st.book.settled_through = u32::try_from(newest).unwrap_or(u32::MAX);
        }
        st.carry.deferred_total = v.pointer("/carry/deferred").and_then(Value::as_u64).unwrap_or(0);
        st.carry.released_total = v.pointer("/carry/released").and_then(Value::as_u64).unwrap_or(0);
        for b in v.pointer("/carry/blocks").and_then(Value::as_array).into_iter().flatten() {
            let f = |j: usize| b.get(j).and_then(Value::as_u64).ok_or_else(|| bad("carry block"));
            st.carry.blocks.push((f(0)? as u32, f(1)?, f(2)?, f(3)?));
        }
        st.distrust = v.get("distrust").and_then(Value::as_array).and_then(|a| Some((a.first()?.as_str()?.to_string(), a.get(1)?.as_str()?.to_string())));
        // absent in state written before AGP-084: no run; present, it must read
        st.unpaid = match v.get("unpaid") {
            None | Some(Value::Null) => None,
            Some(u) => Some(UnpaidRun::from_json(u).ok_or_else(|| bad("unpaid"))?),
        };
        // invoices kept before AGP-091 that never saw work and are past TTL and grace: gone, as
        // an issuance would have dropped them
        let (t, grace) = (now(), self.cfg.invoice_grace_secs);
        let State { invoices, book, .. } = &mut *st;
        invoices.retain(|k, i| i.retired || book.funded(k) || book.last.contains_key(k) || i.expires_at.saturating_add(grace) >= t);
        self.carry_rules(&mut st);
        Ok(secret.is_some())
    }

    /// Where the audit walk stands: the next height it has not passed, if it ever ran.
    pub fn audit_position(&self) -> Option<u32> {
        self.lock().audit_next
    }

    /// Keep the audit walk's position (written with the state).
    pub fn set_audit_position(&self, next: u32) -> Result<()> {
        let mut st = self.lock();
        if st.audit_next == Some(next) {
            return Ok(());
        }
        st.audit_next = Some(next);
        self.save(&st)
    }

    // --- §9.1 ----------------------------------------------------------------------------------

    /// The checks of §9.1 and the debit of §9.2 step 1. Err: (short code, `work` detail).
    fn check_and_debit(&self, pp: &Value, method: &str, path: &str, body: &[u8], amount: u64)
                       -> std::result::Result<WorkCharge, (String, Option<Value>)> {
        let refuse = |c: &str| Err((c.to_string(), None));
        // 1. version, scheme, network, payTo
        let acc = pp.get("accepted").filter(|a| a.is_object());
        let s = |v: Option<&Value>, k: &str| v.and_then(|a| a.get(k)).and_then(Value::as_str).map(str::to_string);
        if pp.get("x402Version").and_then(Value::as_u64) != Some(2) || s(acc, "scheme").as_deref() != Some(SCHEME)
            || s(acc, "network").as_deref() != Some(self.cfg.network.as_str()) || s(acc, "payTo").as_deref() != Some(self.cfg.identity.as_str())
        {
            return refuse("unsupported_scheme_or_network");
        }
        // 2. every field in its grammar, sig 64 bytes of hex, n an integer, auth a string
        let pl = pp.get("payload").filter(|p| p.is_object());
        let parsed = (|| -> Option<(WorkReceipt, [u8; 64], u64, String)> {
            let pl = pl?;
            let r = WorkReceipt::from_doc(pl.get("receipt")?).ok()?;
            Some((r, sig64(pl.get("sig")).ok()?, uint(pl.get("n"), U64, "n").ok()?, pl.get("auth")?.as_str()?.to_string()))
        })();
        let Some((r, sig, n, auth)) = parsed else { return refuse("bad_payload") };
        // 3. identity and Prime
        if r.identity != self.cfg.identity {
            return refuse("wrong_identity");
        }
        if r.prime_id != self.cfg.prime_id {
            return refuse("wrong_prime");
        }
        let mut st = self.lock();
        let t = now();
        // 4. issued here, not expired (unfunded), not retired; a dormant invoice (past TTL, within
        // the grace) is live again once a receipt shows work on it. An invoice with no record yet
        // is read back from its identifier (AGP-091): nothing was stored when it was issued.
        let had_work = st.book.funded(&r.invoice);
        let funded = had_work || r.cum_work > 0;
        let grace = self.cfg.invoice_grace_secs;
        let fresh = match st.invoices.contains_key(&r.invoice) {
            true => None,
            false => Some(Issued::read(&st.secret, &r.invoice).ok_or_else(|| ("unknown_invoice".to_string(), None))?.record()),
        };
        let live = |i: &&Invoice| !i.retired && (i.expires_at >= t || (funded && i.expires_at.saturating_add(grace) >= t) || had_work);
        let Some((key, last_n)) = fresh.as_ref().or_else(|| st.invoices.get(&r.invoice)).filter(live).map(|i| (i.key, i.n)) else {
            return refuse("unknown_invoice");
        };
        // 5. auth over this request and receipt state, n fresh; n is consumed from here on
        let req = request_digest(method, path, body);
        let want = auth_tag(&key, &r.invoice, n, r.seq, r.cum_work, &req).unwrap_or_default();
        if !tag_eq(&want, &auth) || n <= last_n {
            return refuse("bad_auth");
        }
        if let Some(fresh) = fresh {
            // The record is made only by a receipt the Prime signed that shows work: an anonymous
            // caller cannot make the provider keep anything. Until then nothing can be debited, so
            // an `n` that is not remembered buys no replay.
            if st.distrust.is_none() {
                if !(Signed { receipt: r.clone(), sig }).verify(&self.pubkey) {
                    return refuse("bad_sig");
                }
                if r.cum_work == 0 {
                    let work = obj([("invoice", r.invoice.clone().into()), ("creditedWork", "0".into()), ("spentWork", "0".into())]);
                    return Err(("insufficient_work".into(), Some(work)));
                }
                st.new.retain(|(k, _)| *k != r.invoice);
                st.invoices.insert(r.invoice.clone(), fresh);
            }
        }
        let known = match st.invoices.get_mut(&r.invoice) {
            Some(inv) => {
                inv.n = n;
                true
            }
            None => false,
        };
        // a Prime key that equivocated or failed an audit is no longer trusted
        if let Some((code, _)) = &st.distrust {
            let code = code.clone();
            // an invoice with no record changed nothing: nothing to write
            if known {
                let snap = self.snapshot(&st);
                drop(st);
                let _ = self.write(snap);
            }
            return Err((code, None));
        }
        let State { invoices, book, distrust, .. } = &mut *st;
        // 6-8. signature, equivocation, delta credit
        let invoice = r.invoice.clone();
        let delta = match book.accept(&Signed { receipt: r, sig }, &invoice) {
            Ok(d) => d,
            Err(e) => {
                if e.code == "equivocation" {
                    *distrust = Some(("equivocation".into(), e.msg.clone()));
                }
                let snap = self.snapshot(&st);
                drop(st);
                let _ = self.write(snap);
                let code = if e.code == "wrong_invoice" { "unknown_invoice".to_string() } else { e.code };
                return Err((code, None));
            }
        };
        let credited = book.credited.get(&invoice).copied().unwrap_or(0);
        let seq = book.best(&invoice).map(|b| b.receipt.seq).unwrap_or(0);
        let inv = invoices.get_mut(&invoice).expect("checked above");
        // 9. billing
        if credited.saturating_sub(inv.spent) < amount {
            let held = book.held(&invoice);
            let mut work = obj([("invoice", invoice.clone().into()), ("creditedWork", credited.to_string().into()),
                                ("spentWork", inv.spent.to_string().into())]);
            // §13.1: receipted work the caps hold back would have paid: say why, and what is held
            let code = if held > 0 {
                work["heldWork"] = held.to_string().into();
                work["unauditedWork"] = book.unaudited_work(Some(&invoice)).to_string().into();
                work["unauditedTotalWork"] = book.unaudited_work(None).to_string().into();
                if let Some(c) = book.caps.per_invoice {
                    work["capInvoiceWork"] = c.to_string().into();
                }
                if let Some(c) = book.caps.total {
                    work["capTotalWork"] = c.to_string().into();
                }
                book.frozen.clone().unwrap_or_else(|| "credit_cap".into())
            } else {
                "insufficient_work".into()
            };
            let snap = self.snapshot(&st);
            drop(st);
            let _ = self.write(snap);
            return Err((code, Some(work)));
        }
        inv.spent += amount;
        let spent = inv.spent;
        // recorded before the handler runs (§9.2 step 1), written outside the state lock; a failed
        // write refuses the call
        let snap = self.snapshot(&st);
        drop(st);
        if self.write(snap).is_err() {
            let mut st = self.lock();
            if let Some(inv) = st.invoices.get_mut(&invoice) {
                inv.spent = inv.spent.saturating_sub(amount);
            }
            let _ = self.save(&st);
            return Err(("state_io".into(), None));
        }
        Ok(WorkCharge { invoice, amount, delta, credited, spent, seq, n, req, network: self.cfg.network.clone(), provider: None })
    }
}

/// A debited call, settled after the handler (§9.2, §9.3).
pub struct WorkCharge {
    invoice: String,
    amount: u64,
    delta: u64,
    credited: u64,
    spent: u64,
    seq: u64,
    n: u64,
    req: String,
    network: String,
    provider: Option<std::sync::Arc<WorkProvider>>,
}

impl WorkCharge {
    fn response(&self, charged: u64, spent: u64, success: bool) -> Value {
        let receipt = obj([("scheme", SCHEME.into()), ("invoice", self.invoice.clone().into()), ("seq", self.seq.into()), ("n", self.n.into()),
                           ("newlyCreditedWork", self.delta.to_string().into()), ("creditedWork", self.credited.to_string().into()),
                           ("spentWork", spent.to_string().into()), ("balanceWork", self.credited.saturating_sub(spent).to_string().into()),
                           ("charged", charged.to_string().into()), ("req", self.req.clone().into())]);
        settlement_response(&receipt, &self.network, &self.invoice, success)
    }
}

impl SchemeCharge for WorkCharge {
    fn settle(self: Box<Self>, status: u16) -> Value {
        if status >= 500 {
            // not charged: release the debit
            let spent = match &self.provider {
                Some(p) => {
                    let mut st = p.lock();
                    let s = st.invoices.get_mut(&self.invoice).map(|i| {
                        i.spent = i.spent.saturating_sub(self.amount);
                        i.spent
                    });
                    let _ = p.save(&st);
                    s.unwrap_or(self.spent - self.amount)
                }
                None => self.spent - self.amount,
            };
            return self.response(0, spent, false);
        }
        self.response(self.amount, self.spent, status < 400)
    }
}

/// The scheme as an xbt402 Provider sees it. Wrap the rail in an `Arc` to share it with the
/// relay-refresh and audit loops.
pub struct WorkScheme(pub std::sync::Arc<WorkProvider>);

impl ProviderScheme for WorkScheme {
    fn scheme(&self) -> &str {
        SCHEME
    }

    fn requirements(&self, _method: &str, _path: &str, price_sats: u64) -> Option<Value> {
        self.0.amount(price_sats).ok().map(|a| self.0.requirements_for(a, price_sats))
    }

    fn control(&self, method: &str, path: &str, _headers: &[(String, String)], _body: &[u8]) -> Option<HttpResponse> {
        if path.split('?').next() != Some(INVOICE_PATH) {
            return None;
        }
        let json = |status: u16, v: &Value| HttpResponse::new(status, vec![("Content-Type".into(), "application/json".into()),
                                                                           ("Cache-Control".into(), "no-store".into())], dumps(v));
        if method != "POST" && method != "GET" {
            return Some(HttpResponse::new(405, vec![], b"method not allowed".to_vec()));
        }
        // no client is told from another: issuing stores nothing, so there is nothing to ration
        Some(match self.0.issue_invoice() {
            Ok(doc) => json(200, &doc),
            Err(e) => json(500, &obj([("error", e.code.into())])),
        })
    }

    fn authorize(&self, payment: &Value, method: &str, path: &str, body: &[u8], price_sats: u64, url: &str)
                 -> std::result::Result<Box<dyn SchemeCharge>, Value> {
        let amount = match self.0.amount(price_sats) {
            Ok(a) => a,
            Err(_) => return Err(self.0.refusal(url, 1, price_sats, "bad_pricing", None)),
        };
        match self.0.check_and_debit(payment, method, path, body, amount) {
            Ok(mut c) => {
                c.provider = Some(self.0.clone());
                Ok(Box::new(c))
            }
            Err((code, work)) => Err(self.0.refusal(url, amount, price_sats, &code, work)),
        }
    }
}
