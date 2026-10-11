//! The hub's link to its operator's Lightning node (AGP-109): two calls, `NewAddress` and
//! `SignMessage`, and what the hub keeps of their answers.
//!
//! The node gives the hub an address of its on-chain wallet, so coins above the hub's capital
//! return to the wallet the operator already has, and it signs the statement that names the hub
//! ([`crate::hub_identity`]). The hub can ask for nothing else: it holds a macaroon for those two
//! calls ([`crate::macaroon`], rule M1) and no key of the node; the node holds no key of the hub.
//! No call here can spend from the node.
//!
//! Three rules, each with every place that could break it.
//!
//! **L1. A coin goes to the Lightning wallet only at an address the linked node gave, that the
//! hub wrote to disk before handing it out, and only until the chain shows that address used.**
//!
//! | Place | What happens |
//! |---|---|
//! | the node's answer is not an address of this network, or not witness v0 | not taken; the float is refilled |
//! | the node answers with an address it gave before | not taken (it is used, or will be) |
//! | the state file cannot be written | the address is not handed out |
//! | the state file does not parse at start | the hub does not start with the link (it is never read as empty) |
//! | the process stops between the node's answer and the write | that address is never used: one gap in the node's wallet |
//! | the chain shows the address used | it is retired and the next is asked for; until the node answers, the float is refilled |
//! | the certificate setting changed, or the node now signs with another key (another node) | the address on file is not handed out; with another key it is retired |
//! | the node is down | the address on file is still the node's and is handed out; nothing is asked on a return's path |
//!
//! **L2. A return goes to the Lightning wallet only when the hub still holds its capital
//! without it.** The hub's capital is `capital_sat`; with none set, nothing is above it.
//!
//! | Place | What happens |
//! |---|---|
//! | a return whose amount is not known when its address is named (a seller channel's remainder, named at funding) | never offered here: it refills the float |
//! | what the hub holds is not known (the wallet does not answer, a funding is being reconciled) | nothing is above capital until it is |
//! | several returns between two looks at what the hub holds | each takes its amount off what is left above capital |
//! | a return handed out and not yet in the books when the hub looks again | counted against the next look too ([`Budget`]) |
//! | a return larger than what is above capital | refills the float whole (an output is not split) |
//!
//! **L3. The link never stands between the hub and the chain.** [`LnLink::return_above`] reads
//! memory only. The node is asked from [`LnLink::tick`], on the link's own thread, with no lock
//! held that a route or a return takes.
//!
//! Core logic here does no network IO: the node is the [`LnNode`] trait, and the REST client
//! ([`LndRestNode`], feature `ln-wallet`) is one implementation.
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};
use xbt_primitives::address::address_to_spk;

use crate::error::{ChannelError, Result};
use crate::hub_identity::{self, HubAddress, LIFE_SECS, RESIGN_AFTER_SECS};

/// The link's file in the hub's data directory.
pub const LINK_FILE: &str = "ln-link.json";
/// A node that failed is asked again no sooner than this.
pub const RETRY_SECS: u64 = 30;
/// The file's format.
const VERSION: u64 = 1;

/// The two calls.
pub trait LnNode: Send + Sync {
    /// `NewAddress`: a fresh P2WPKH address of the node's on-chain wallet.
    fn new_address(&self) -> Result<String>;
    /// `SignMessage`: the node key's signature over `msg`, zbase32.
    fn sign_message(&self, msg: &[u8]) -> Result<String>;
}

fn bad(msg: impl Into<String>) -> ChannelError {
    ChannelError::new("ln_link", msg)
}

/// Rule L2's arithmetic: what is above capital, less what was handed out since.
///
/// `base` is what the last look found above capital. A return taken from it is counted in `cur`.
/// A look moves `cur` to `prev` before it reads the books and sets `base` after: a return handed
/// out just before the look may or may not be in the books the look read, so it stays counted
/// for one more look. It is counted twice at worst, never not at all.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Budget {
    base: u64,
    prev: u64,
    cur: u64,
}

impl Budget {
    /// What a return may still take.
    pub fn left(&self) -> u64 {
        self.base.saturating_sub(self.prev).saturating_sub(self.cur)
    }

    /// Take `sat` if it fits whole. Zero never fits (a return of nothing names no address).
    pub fn take(&mut self, sat: u64) -> bool {
        if sat == 0 || sat > self.left() {
            return false;
        }
        self.cur = self.cur.saturating_add(sat);
        true
    }

    /// Before a look reads the books.
    pub fn begin_look(&mut self) {
        self.prev = std::mem::take(&mut self.cur);
    }

    /// After it: `above` is what the hub holds above its capital (0: not known, or none).
    pub fn end_look(&mut self, above: u64) {
        self.base = above;
    }
}

/// What the hub holds above `capital`. `held`: every coin the hub counts as its own (`None`: not
/// known now). No capital set means nothing is above it.
pub fn above_capital(held: Option<u64>, capital: u64) -> u64 {
    match held {
        Some(h) if capital > 0 => h.saturating_sub(capital),
        _ => 0,
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Signed {
    text: String,
    signature: String,
    until: u64,
    signed_at: u64,
}

/// What is on disk.
#[derive(Debug, Clone, Default, PartialEq)]
struct Saved {
    node_id: Option<String>,
    /// The certificate setting this was written under (a fingerprint; empty: none).
    cert: String,
    /// The address handed out now.
    address: Option<String>,
    /// Every address handed out before it, oldest first.
    past: Vec<String>,
    statement: Option<Signed>,
}

impl Saved {
    fn to_json(&self) -> Value {
        json!({"version": VERSION, "nodeId": self.node_id, "cert": self.cert, "address": self.address, "past": self.past,
               "statement": self.statement.as_ref().map(|s| json!({"text": s.text, "signature": s.signature, "until": s.until, "signedAt": s.signed_at}))})
    }

    fn from_json(v: &Value) -> std::result::Result<Self, String> {
        let o = v.as_object().ok_or("not an object")?;
        if o.get("version").and_then(Value::as_u64) != Some(VERSION) {
            return Err(format!("not version {VERSION}"));
        }
        let opt_str = |m: &Map<String, Value>, k: &str| match m.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("{k} is not text")),
        };
        let past = match o.get("past") {
            Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string).ok_or("past holds what is not an address")).collect::<std::result::Result<Vec<_>, _>>()?,
            _ => return Err("no past list".into()),
        };
        let statement = match o.get("statement") {
            None | Some(Value::Null) => None,
            Some(Value::Object(s)) => Some(Signed {
                text: opt_str(s, "text")?.ok_or("statement.text")?,
                signature: opt_str(s, "signature")?.ok_or("statement.signature")?,
                until: s.get("until").and_then(Value::as_u64).ok_or("statement.until")?,
                signed_at: s.get("signedAt").and_then(Value::as_u64).ok_or("statement.signedAt")?,
            }),
            Some(_) => return Err("statement is not an object".into()),
        };
        Ok(Self { node_id: opt_str(o, "nodeId")?, cert: opt_str(o, "cert")?.unwrap_or_default(), address: opt_str(o, "address")?, past, statement })
    }
}

#[derive(Default)]
struct Inner {
    saved: Saved,
    budget: Budget,
    /// The address on file is not handed out until the node has signed with the key on file:
    /// the certificate setting changed since the file was written.
    unconfirmed: bool,
    /// No request to the node before this time (after a failure).
    retry_at: u64,
    address_error: Option<String>,
    sign_error: Option<String>,
    /// Why nothing is above capital, when the reason is not an amount.
    budget_note: Option<String>,
    handed: u64,
}

/// What the link is for: the hub it names and the chain its addresses are on.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// The bech32 prefix of the hub's network.
    pub hrp: String,
    pub network: String,
    /// The hub's payTo key, hex.
    pub pay_to: String,
    /// A fingerprint of the pinned certificate (empty: plain http on loopback).
    pub cert: String,
}

/// One look at the hub, as [`LnLink::tick`] needs it.
pub struct Look<'a> {
    /// Unix seconds.
    pub now: u64,
    /// The hub's `capital_sat` (0: none set).
    pub capital: u64,
    /// Every coin the hub counts as its own, read now (`Err`: why it is not known).
    pub held: &'a dyn Fn() -> std::result::Result<u64, String>,
    /// Whether the chain shows a return paid to this script.
    pub seen: &'a dyn Fn(&[u8]) -> Result<bool>,
}

/// The link. One per hub.
pub struct LnLink {
    node: Box<dyn LnNode>,
    cfg: LinkConfig,
    path: Option<PathBuf>,
    st: Mutex<Inner>,
    /// One tick at a time (the node is asked outside `st`).
    ticking: Mutex<()>,
}

fn lk<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Witness v0 (P2WPKH or P2WSH): what a provider takes as a `payerSpk` and a sweep can pay.
fn witness_v0(spk: &[u8]) -> bool {
    (spk.len() == 22 || spk.len() == 34) && spk[0] == 0 && spk[1] as usize == spk.len() - 2
}

fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    crate::hub_keys::sync_dir(path)
}

impl LnLink {
    /// Open the link, with what `datadir` holds of it (`None`: nothing is kept, for tests and
    /// embedders). A file that is there and does not parse is an error: read as empty it would
    /// forget the address in use and every one used before.
    pub fn open(node: Box<dyn LnNode>, cfg: LinkConfig, datadir: Option<&Path>) -> Result<Self> {
        if hub_identity::key_hex(&cfg.pay_to).is_none() {
            return Err(bad("the hub's payTo key is not a public key in hex"));
        }
        let path = datadir.map(|d| d.join(LINK_FILE));
        let saved = match &path {
            Some(p) => match std::fs::read(p) {
                Ok(b) => {
                    let v: Value = serde_json::from_slice(&b).map_err(|e| bad(format!("{}: {e}: move it away to start the link afresh (the address in use is then asked for again)", p.display())))?;
                    Saved::from_json(&v).map_err(|e| bad(format!("{}: {e}: move it away to start the link afresh", p.display())))?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Saved::default(),
                Err(e) => return Err(bad(format!("{}: {e}", p.display()))),
            },
            None => Saved::default(),
        };
        // a file from another certificate setting may be another node's: its address waits for
        // the node's signature (L1)
        let unconfirmed = saved.address.is_some() && saved.cert != cfg.cert;
        Ok(Self { node, cfg, path, st: Mutex::new(Inner { saved, unconfirmed, ..Inner::default() }), ticking: Mutex::new(()) })
    }

    fn save(&self, s: &Saved) -> Result<()> {
        let Some(p) = &self.path else { return Ok(()) };
        write_file(p, s.to_json().to_string().as_bytes()).map_err(|e| bad(format!("{}: {e}", p.display())))
    }

    fn spk(&self, addr: &str) -> Result<Vec<u8>> {
        let spk = address_to_spk(addr, Some(&self.cfg.hrp)).map_err(|e| bad(format!("the node's address {addr:?}: {e}")))?;
        if !witness_v0(&spk) {
            return Err(bad(format!("the node's address {addr:?} is not a witness v0 address")));
        }
        Ok(spk)
    }

    /// Rules L1 to L3: the address a return of `sat` goes to, if it goes to the Lightning wallet.
    /// `None`: it refills the float. Reads memory only.
    pub fn return_above(&self, sat: u64) -> Option<String> {
        let mut st = lk(&self.st);
        if st.unconfirmed {
            return None;
        }
        let addr = st.saved.address.clone()?;
        if !st.budget.take(sat) {
            return None;
        }
        st.handed += 1;
        Some(addr)
    }

    /// The address the Lightning wallet takes coins at now, whatever the capital (an operator's
    /// withdrawal names its amount itself). `None`: none is on file, or it waits for the node.
    pub fn address(&self) -> Option<String> {
        let st = lk(&self.st);
        if st.unconfirmed { None } else { st.saved.address.clone() }
    }

    /// Every script the link ever handed out, the one in use last.
    pub fn scripts(&self) -> Vec<Vec<u8>> {
        let st = lk(&self.st);
        st.saved.past.iter().chain(st.saved.address.iter()).filter_map(|a| self.spk(a).ok()).collect()
    }

    /// `extra.routing.lightning` for the hub's 402: the statement, while it runs. `None` once it
    /// has run out (a hub that shows a run-out statement is refused; one that shows none is paid
    /// by URL).
    pub fn lightning_extra(&self, now: u64) -> Option<Value> {
        let st = lk(&self.st);
        let (node, s) = (st.saved.node_id.as_ref()?, st.saved.statement.as_ref()?);
        hub_identity::verify(&s.text, &s.signature, node, &self.cfg.network, &self.cfg.pay_to, now).ok()?;
        Some(hub_identity::to_extra(node, &s.text, &s.signature))
    }

    /// The node id on file.
    pub fn node_id(&self) -> Option<String> {
        lk(&self.st).saved.node_id.clone()
    }

    /// One round of upkeep, on the link's own thread: what is above capital, the statement, the
    /// address. Never called on a route's or a return's path (L3). Returns what changed, for the
    /// log.
    pub fn tick(&self, look: &Look<'_>) -> Vec<String> {
        let _one = lk(&self.ticking);
        let mut said = vec![];
        // L2: handed-out returns stay counted across this look
        lk(&self.st).budget.begin_look();
        let (above, note) = match (look.capital, (look.held)()) {
            (0, _) => (0, Some("no capital is set (capital_sat): every return refills the float".to_string())),
            (c, Ok(h)) => (above_capital(Some(h), c), None),
            (_, Err(e)) => (0, Some(format!("what the hub holds is not known ({e}): every return refills the float until it is"))),
        };
        {
            let mut st = lk(&self.st);
            st.budget.end_look(above);
            st.budget_note = note;
        }
        let (retry_at, want_sign) = {
            let st = lk(&self.st);
            let fresh = st.saved.statement.as_ref().is_some_and(|s| {
                look.now.saturating_sub(s.signed_at) < RESIGN_AFTER_SECS && s.signed_at <= look.now.saturating_add(RESIGN_AFTER_SECS)
                    && hub_identity::Statement::parse(&s.text).is_ok_and(|p| p.network == self.cfg.network && p.payto == self.cfg.pay_to && p.until > look.now)
            });
            (st.retry_at, !fresh || st.unconfirmed || st.saved.node_id.is_none())
        };
        // a wait that is longer than a wait can be is a clock that was set back: not kept
        if look.now < retry_at && retry_at - look.now <= RETRY_SECS {
            return said;
        }
        let mut failed = false;
        if want_sign {
            match self.sign(look.now) {
                Ok(Some(m)) => said.push(m),
                Ok(None) => {}
                Err(e) => {
                    failed = true;
                    let m = e.to_string();
                    if lk(&self.st).sign_error.replace(m.clone()).as_deref() != Some(m.as_str()) {
                        said.push(format!("statement: {m}"));
                    }
                }
            }
        }
        // the address (as it is after a signature that retired one): retired once the chain shows
        // it used, and the next asked for
        let cur = lk(&self.st).saved.address.clone();
        let used = match cur.as_deref().map(|a| self.spk(a).and_then(|s| (look.seen)(&s))) {
            Some(Ok(u)) => u,
            None => false,
            Some(Err(e)) => {
                lk(&self.st).address_error = Some(format!("whether the address is used is not known: {e}"));
                return said;
            }
        };
        let confirmed = !lk(&self.st).unconfirmed;
        if confirmed && (cur.is_none() || used) && !failed {
            match self.next_address(cur.filter(|_| used)) {
                Ok(a) => {
                    lk(&self.st).address_error = None;
                    said.push(format!("coins above capital return to the Lightning wallet at {a}"));
                }
                Err(e) => {
                    failed = true;
                    let m = e.to_string();
                    if lk(&self.st).address_error.replace(m.clone()).as_deref() != Some(m.as_str()) {
                        said.push(format!("address: {m}"));
                    }
                }
            }
        }
        if failed {
            lk(&self.st).retry_at = look.now.saturating_add(RETRY_SECS);
        }
        said
    }

    /// Ask the node to sign the statement, check the answer as a payer will, and keep it. A key
    /// other than the one on file is another node: its address is retired (L1).
    fn sign(&self, now: u64) -> Result<Option<String>> {
        let until = now.checked_add(LIFE_SECS).ok_or_else(|| bad("the clock"))?;
        let text = hub_identity::sign_text(&self.cfg.network, &self.cfg.pay_to, until)?;
        let signature = self.node.sign_message(text.as_bytes())?;
        let node = hub_identity::recover_node_id(text.as_bytes(), &signature).map_err(|e| bad(format!("the node's signature: {}", e.msg)))?;
        hub_identity::verify(&text, &signature, &node, &self.cfg.network, &self.cfg.pay_to, now)?;
        let mut st = lk(&self.st);
        let mut next = st.saved.clone();
        let mut said = None;
        match next.node_id.as_deref() {
            Some(was) if was != node => {
                if let Some(a) = next.address.take() {
                    next.past.push(a);
                }
                said = Some(format!("the Lightning node is now {node} (it was {was}): the address of the node before is no longer used"));
            }
            Some(_) => {}
            None => said = Some(format!("linked to Lightning node {node}")),
        }
        next.node_id = Some(node);
        next.cert = self.cfg.cert.clone();
        next.statement = Some(Signed { text, signature, until, signed_at: now });
        self.save(&next)?;
        st.saved = next;
        st.unconfirmed = false;
        st.sign_error = None;
        Ok(said)
    }

    /// L1: ask for the next address, check it, write it down, and only then hand it out. `used`:
    /// the address the chain showed used, retired whether or not the node answers.
    fn next_address(&self, used: Option<String>) -> Result<String> {
        if let Some(u) = used {
            let mut st = lk(&self.st);
            let mut next = st.saved.clone();
            if next.address.as_deref() == Some(u.as_str()) {
                next.address = None;
                next.past.push(u);
                self.save(&next)?;
                st.saved = next;
            }
        }
        let addr = self.node.new_address()?;
        self.spk(&addr)?;
        let mut st = lk(&self.st);
        if st.saved.past.iter().any(|p| p.eq_ignore_ascii_case(&addr)) {
            return Err(bad(format!("the node gave an address it gave before ({addr}): not used again")));
        }
        let mut next = st.saved.clone();
        next.address = Some(addr.clone());
        next.cert = self.cfg.cert.clone();
        self.save(&next)?;
        st.saved = next;
        Ok(addr)
    }

    /// For the hub's status. `url`: where the hub is served, for its address.
    pub fn report(&self, now: u64, url: Option<&str>) -> Value {
        let st = lk(&self.st);
        let s = &st.saved;
        let running = s.statement.as_ref().filter(|x| x.until > now);
        json!({"nodeId": s.node_id,
               "hubAddress": s.node_id.as_ref().zip(url).filter(|_| running.is_some()).map(|(n, u)| HubAddress::display(n, u)),
               "statementUntil": s.statement.as_ref().map(|x| x.until), "statementSignedAt": s.statement.as_ref().map(|x| x.signed_at),
               "statementServed": running.is_some(),
               "returnAddress": s.address.as_ref().filter(|_| !st.unconfirmed), "addressesUsed": s.past.len(),
               "aboveCapitalSat": st.budget.left(), "returnsHandedOut": st.handed, "note": st.budget_note,
               "waitingForNode": st.unconfirmed, "addressError": st.address_error, "statementError": st.sign_error})
    }
}

/// A macaroon as an operator pastes it: hex (what `lncli bakemacaroon` prints), base64, or the
/// bytes of a `.macaroon` file.
pub fn macaroon_bytes(pasted: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine;
    if pasted.first() == Some(&2) && crate::macaroon::parse(pasted).is_ok() {
        return Ok(pasted.to_vec());
    }
    let text = std::str::from_utf8(pasted).map_err(|_| bad("the macaroon is neither a macaroon file nor text"))?;
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let b = hex::decode(&t).ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(&t).ok())
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(&t).ok())
        .or_else(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&t).ok())
        .ok_or_else(|| bad("the macaroon is not hex or base64"))?;
    crate::macaroon::parse(&b).map_err(|e| bad(format!("the macaroon: {e}")))?;
    Ok(b)
}

#[cfg(feature = "ln-wallet")]
pub use rest::{cert_fingerprint, LndRestNode};

#[cfg(feature = "ln-wallet")]
mod rest {
    use std::io::Read;
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine;
    use serde_json::{json, Value};

    use super::{bad, LnNode};
    use crate::error::Result;

    /// The node's answers are short; more than this is not one.
    const MAX_ANSWER: u64 = 64 << 10;

    /// A TLS verifier that accepts exactly one certificate: the node's own (`tls.cert`,
    /// self-signed, so there is no CA path to check). The handshake signatures are verified.
    /// The name dialled is not: the certificate is the identity, so the address is the
    /// operator's to set (a container address, an onion, a name the certificate does not list).
    #[derive(Debug)]
    struct PinnedCert {
        der: Vec<u8>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl rustls::client::danger::ServerCertVerifier for PinnedCert {
        fn verify_server_cert(&self, end_entity: &rustls::pki_types::CertificateDer<'_>, _i: &[rustls::pki_types::CertificateDer<'_>],
                              _n: &rustls::pki_types::ServerName<'_>, _o: &[u8], _now: rustls::pki_types::UnixTime)
                              -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if end_entity.as_ref() == self.der.as_slice() {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General("the Lightning node's TLS certificate is not the pinned one".into()))
            }
        }

        fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct)
                                  -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
        }

        fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct)
                                  -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider.signature_verification_algorithms.supported_schemes()
        }
    }

    /// The first certificate in a PEM text, as DER.
    fn pem_cert_der(pem: &str) -> Result<Vec<u8>> {
        const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
        let start = pem.find(BEGIN).ok_or_else(|| bad("the certificate: no PEM certificate"))?;
        let body = &pem[start + BEGIN.len()..];
        let end = body.find("-----END CERTIFICATE-----").ok_or_else(|| bad("the certificate: unterminated PEM"))?;
        let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| bad("the certificate: bad base64"))
    }

    /// What names a certificate setting in the link's file: the SHA-256 of the certificate.
    pub fn cert_fingerprint(pem: &str) -> Result<String> {
        Ok(hex::encode(xbt_primitives::hash::sha256(&pem_cert_der(pem)?)))
    }

    /// Whether `base` is plain `http://` to a loopback address, as the parser ureq dials with
    /// reads it. A name, `localhost` too, is not: the resolver decides where it goes.
    fn http_loopback(base: &str) -> bool {
        let Ok(u) = url::Url::parse(base) else { return false };
        u.scheme() == "http" && match u.host() {
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|m| m.is_loopback()),
            _ => false,
        }
    }

    /// The node's REST listener: the macaroon in a header, TLS pinned to the node's certificate.
    /// It can send two requests and no other.
    pub struct LndRestNode {
        base: String,
        macaroon_hex: String,
        agent: ureq::Agent,
    }

    impl LndRestNode {
        /// `base`: `https://host:port` (plain `http://` only to a loopback address). `cert_pem`:
        /// the node's `tls.cert`, required for https. No redirect is followed: the macaroon
        /// would go with it.
        pub fn new(base: &str, macaroon: &[u8], cert_pem: Option<&str>) -> Result<Self> {
            let base = base.trim().trim_end_matches('/').to_string();
            let mut b = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout(Duration::from_secs(30)).redirects(0);
            if base.starts_with("https://") {
                let pem = cert_pem.ok_or_else(|| bad("an https Lightning node needs its certificate (XBT_HUB_LN_TLS_CERT)"))?;
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let cfg = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()
                    .map_err(|e| bad(e.to_string()))?
                    .dangerous().with_custom_certificate_verifier(Arc::new(PinnedCert { der: pem_cert_der(pem)?, provider }))
                    .with_no_client_auth();
                b = b.tls_config(Arc::new(cfg));
            } else if !http_loopback(&base) {
                return Err(bad("the Lightning node's REST address must be https (plain http only to a loopback address)"));
            }
            Ok(Self { base, macaroon_hex: hex::encode(macaroon), agent: b.build() })
        }

        fn answer(&self, r: std::result::Result<ureq::Response, ureq::Error>, field: &str) -> Result<String> {
            let resp = match r {
                Ok(resp) if (300..400).contains(&resp.status()) => return Err(bad(format!("the Lightning node answered HTTP {}: a redirect, which is never followed", resp.status()))),
                Ok(resp) => resp,
                Err(ureq::Error::Status(code, resp)) => {
                    let mut text = String::new();
                    let _ = resp.into_reader().take(MAX_ANSWER).read_to_string(&mut text);
                    let msg = serde_json::from_str::<Value>(&text).ok().and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
                        .unwrap_or_else(|| text.chars().take(200).collect());
                    return Err(bad(format!("the Lightning node answered HTTP {code}: {msg}")));
                }
                Err(e) => return Err(bad(format!("the Lightning node is not reachable: {e}"))),
            };
            let mut s = String::new();
            resp.into_reader().take(MAX_ANSWER).read_to_string(&mut s).map_err(|e| bad(e.to_string()))?;
            let v: Value = serde_json::from_str(&s).map_err(|e| bad(format!("the Lightning node's answer: {e}")))?;
            v.get(field).and_then(Value::as_str).filter(|x| !x.is_empty()).map(str::to_string)
                .ok_or_else(|| bad(format!("the Lightning node's answer has no {field}")))
        }
    }

    impl LnNode for LndRestNode {
        fn new_address(&self) -> Result<String> {
            let r = self.agent.get(&format!("{}/v1/newaddress?type=WITNESS_PUBKEY_HASH", self.base)).set("Grpc-Metadata-macaroon", &self.macaroon_hex).call();
            self.answer(r, "address")
        }

        fn sign_message(&self, msg: &[u8]) -> Result<String> {
            let body = json!({"msg": base64::engine::general_purpose::STANDARD.encode(msg)}).to_string();
            let r = self.agent.post(&format!("{}/v1/signmessage", self.base)).set("Grpc-Metadata-macaroon", &self.macaroon_hex)
                .set("Content-Type", "application/json").send_string(&body);
            self.answer(r, "signature")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn plain_http_only_to_loopback_and_https_only_with_a_certificate() {
            assert!(LndRestNode::new("http://127.0.0.1:8080", b"m", None).is_ok());
            assert!(LndRestNode::new("http://[::1]:8080/", b"m", None).is_ok());
            for base in ["http://localhost:8080", "http://10.0.0.5:8080", "http://lnd:8080", "ftp://127.0.0.1", "127.0.0.1:8080", ""] {
                assert!(LndRestNode::new(base, b"m", None).is_err(), "{base}");
            }
            assert!(LndRestNode::new("https://127.0.0.1:8080", b"m", None).err().unwrap().msg.contains("certificate"));
            assert!(LndRestNode::new("https://127.0.0.1:8080", b"m", Some("no pem")).is_err());
            assert!(cert_fingerprint("-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n").unwrap().len() == 64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, SecretKey, SECP256K1};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use xbt_primitives::address::segwit_address;

    const NET: &str = "bip122:regtest";

    /// A node in memory: addresses from a counter, signatures from a key; it can be down, and
    /// can be told to answer wrongly.
    #[derive(Clone)]
    struct Fake {
        key: Arc<Mutex<SecretKey>>,
        n: Arc<AtomicU64>,
        down: Arc<AtomicBool>,
        asked: Arc<AtomicU64>,
        answer: Arc<Mutex<Option<String>>>,
    }

    fn addr(n: u64) -> String {
        let mut spk = vec![0u8, 20];
        spk.extend_from_slice(&[n as u8; 20]);
        segwit_address("bcrt", &spk).unwrap()
    }

    impl Fake {
        fn new(key: u8) -> Self {
            Self { key: Arc::new(Mutex::new(SecretKey::from_slice(&[key; 32]).unwrap())), n: Arc::new(AtomicU64::new(1)), down: Arc::new(AtomicBool::new(false)),
                   asked: Arc::new(AtomicU64::new(0)), answer: Arc::new(Mutex::new(None)) }
        }
        fn id(&self) -> String {
            hex::encode(PublicKey::from_secret_key(SECP256K1, &self.key.lock().unwrap()).serialize())
        }
    }

    impl LnNode for Fake {
        fn new_address(&self) -> Result<String> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(bad("the Lightning node is not reachable: test"));
            }
            if let Some(a) = self.answer.lock().unwrap().clone() {
                return Ok(a);
            }
            Ok(addr(self.n.fetch_add(1, Ordering::SeqCst)))
        }
        fn sign_message(&self, msg: &[u8]) -> Result<String> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(bad("the Lightning node is not reachable: test"));
            }
            Ok(hub_identity::ln_sign(msg, &self.key.lock().unwrap()))
        }
    }

    fn cfg(cert: &str) -> LinkConfig {
        let payto = hex::encode(PublicKey::from_secret_key(SECP256K1, &SecretKey::from_slice(&[9; 32]).unwrap()).serialize());
        LinkConfig { hrp: "bcrt".into(), network: NET.into(), pay_to: payto, cert: cert.into() }
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("agp109-link-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// One tick: the hub holds `held`, its capital is `capital`, and `used` lists the scripts
    /// the chain shows paid.
    fn tick(l: &LnLink, now: u64, held: std::result::Result<u64, String>, capital: u64, used: &[String]) -> Vec<String> {
        let spks: Vec<Vec<u8>> = used.iter().map(|a| address_to_spk(a, Some("bcrt")).unwrap()).collect();
        l.tick(&Look { now, capital, held: &|| held.clone(), seen: &|s| Ok(spks.iter().any(|u| u == s)) })
    }

    const T0: u64 = 1_700_000_000;

    #[test]
    fn budget_never_hands_out_more_than_is_above_capital() {
        let mut b = Budget::default();
        assert!(!b.take(1), "nothing is above capital before a look");
        b.begin_look();
        b.end_look(100);
        assert!(!b.take(0) && !b.take(101));
        assert!(b.take(60) && !b.take(41) && b.take(40) && !b.take(1));
        // a look that does not see those returns in the books yet (the hub still holds 100 above):
        // they stay counted
        b.begin_look();
        assert!(!b.take(1), "while the look reads the books");
        b.end_look(100);
        assert_eq!(b.left(), 0);
        // the next look sees them gone: nothing is above capital, and nothing was double-spent
        b.begin_look();
        b.end_look(0);
        assert_eq!(b.left(), 0);
        // a return taken while a look is reading is counted against that look's result too
        b.begin_look();
        b.end_look(50);
        b.begin_look();
        assert!(b.take(50));
        b.end_look(50);
        assert_eq!(b.left(), 0);
        assert_eq!(above_capital(Some(150), 100), 50);
        assert_eq!(above_capital(Some(99), 100), 0);
        assert_eq!(above_capital(None, 100), 0, "not known is not above");
        assert_eq!(above_capital(Some(u64::MAX), 0), 0, "no capital set: nothing is above it");
        let mut big = Budget::default();
        big.end_look(u64::MAX);
        assert!(big.take(u64::MAX) && !big.take(1));
    }

    #[test]
    fn l2_a_return_goes_to_lightning_only_while_the_hub_keeps_its_capital() {
        let node = Fake::new(7);
        let l = LnLink::open(Box::new(node.clone()), cfg("c1"), None).unwrap();
        assert_eq!(l.return_above(1), None, "before the first tick nothing is known");
        let said = tick(&l, T0, Ok(1_050_000), 1_000_000, &[]);
        assert!(said.iter().any(|m| m.contains("linked to Lightning node")) && said.iter().any(|m| m.contains(&addr(1))), "{said:?}");
        assert_eq!(l.return_above(50_001), None, "larger than what is above capital: the float, whole");
        assert_eq!(l.return_above(0), None);
        assert_eq!(l.return_above(30_000).as_deref(), Some(addr(1).as_str()));
        assert_eq!(l.return_above(20_001), None);
        assert_eq!(l.return_above(20_000).as_deref(), Some(addr(1).as_str()), "the same address until the chain shows it used");
        assert_eq!(l.return_above(1), None);
        // the hub's books still show those 50,000 (not written yet): not handed out twice
        tick(&l, T0 + 5, Ok(1_050_000), 1_000_000, &[]);
        assert_eq!(l.return_above(1), None);
        // what the hub holds is not known, or no capital is set: the float
        tick(&l, T0 + 10, Ok(2_000_000), 1_000_000, &[]);
        assert!(l.return_above(1).is_some());
        tick(&l, T0 + 15, Err("the wallet does not answer".into()), 1_000_000, &[]);
        assert_eq!(l.return_above(1), None);
        assert!(l.report(T0 + 15, None)["note"].as_str().unwrap().contains("not known"));
        tick(&l, T0 + 20, Ok(2_000_000), 0, &[]);
        assert_eq!(l.return_above(1), None);
        assert!(l.report(T0 + 20, None)["note"].as_str().unwrap().contains("capital_sat"));
        // below capital
        tick(&l, T0 + 25, Ok(999_999), 1_000_000, &[]);
        assert_eq!(l.return_above(1), None);
    }

    #[test]
    fn l1_an_address_is_used_until_the_chain_shows_it_used_and_is_on_disk_first() {
        let d = dir("l1");
        let node = Fake::new(7);
        let l = LnLink::open(Box::new(node.clone()), cfg("c1"), Some(&d)).unwrap();
        tick(&l, T0, Ok(900), 100, &[]);
        assert_eq!(l.address().as_deref(), Some(addr(1).as_str()));
        let on_disk = |d: &Path| serde_json::from_slice::<Value>(&std::fs::read(d.join(LINK_FILE)).unwrap()).unwrap();
        assert_eq!(on_disk(&d)["address"], addr(1).as_str());
        // not used: nothing is asked, tick after tick
        let asked = node.asked.load(Ordering::SeqCst);
        for i in 1..5 {
            tick(&l, T0 + i, Ok(900), 100, &[]);
        }
        assert_eq!((node.asked.load(Ordering::SeqCst), l.address().unwrap()), (asked, addr(1)));
        // used: the next one, and the old one is kept as past
        tick(&l, T0 + 10, Ok(900), 100, &[addr(1)]);
        assert_eq!(l.address().as_deref(), Some(addr(2).as_str()));
        assert_eq!(on_disk(&d)["past"], json!([addr(1)]));
        assert_eq!(l.scripts().len(), 2);
        // a restart reads it back and asks for nothing
        drop(l);
        let asked = node.asked.load(Ordering::SeqCst);
        let l = LnLink::open(Box::new(node.clone()), cfg("c1"), Some(&d)).unwrap();
        assert_eq!(l.address().as_deref(), Some(addr(2).as_str()));
        tick(&l, T0 + 20, Ok(900), 100, &[addr(1)]);
        assert_eq!(node.asked.load(Ordering::SeqCst), asked, "a statement a few seconds old and an unused address");
        assert_eq!(l.return_above(10).as_deref(), Some(addr(2).as_str()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn l1_an_answer_that_is_no_fresh_address_of_this_network_is_not_taken() {
        // what it gave before; another network's; no address; witness v1
        let v1 = segwit_address("bcrt", &[&[0x51u8, 32][..], &[5u8; 32][..]].concat()).unwrap();
        for wrong in [addr(1), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(), "not an address".to_string(), String::new(), v1] {
            let node = Fake::new(7);
            let l = LnLink::open(Box::new(node.clone()), cfg("c1"), None).unwrap();
            tick(&l, T0, Ok(900), 100, &[]);
            assert_eq!(l.address().as_deref(), Some(addr(1).as_str()));
            *node.answer.lock().unwrap() = Some(wrong.clone());
            let said = tick(&l, T0 + 1, Ok(900), 100, &[addr(1)]);
            assert!(said.iter().any(|m| m.starts_with("address:")), "{wrong:?}: {said:?}");
            assert_eq!((l.address(), l.return_above(10)), (None, None), "{wrong:?}: the float until the node gives a good one");
            *node.answer.lock().unwrap() = None;
            tick(&l, T0 + 1 + RETRY_SECS, Ok(900), 100, &[addr(1)]);
            assert_eq!(l.return_above(10).as_deref(), Some(addr(2).as_str()), "{wrong:?}");
        }
    }

    #[test]
    fn l1_an_address_that_cannot_be_written_down_is_not_handed_out() {
        let d = dir("ro");
        let node = Fake::new(7);
        let l = LnLink::open(Box::new(node.clone()), cfg("c1"), Some(&d.join("missing-directory"))).unwrap();
        let said = tick(&l, T0, Ok(900), 100, &[]);
        assert!(said.iter().any(|m| m.contains("missing-directory")), "{said:?}");
        assert_eq!((l.address(), l.return_above(10), l.lightning_extra(T0)), (None, None, None));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn l1_a_file_that_does_not_parse_stops_the_link_and_is_not_read_as_empty() {
        let d = dir("bad");
        for body in ["", "{", "[]", r#"{"version":2,"past":[]}"#, r#"{"version":1}"#, r#"{"version":1,"past":[5]}"#, r#"{"version":1,"past":[],"address":7}"#,
                     r#"{"version":1,"past":[],"statement":{"text":"x"}}"#] {
            std::fs::write(d.join(LINK_FILE), body).unwrap();
            let e = LnLink::open(Box::new(Fake::new(7)), cfg("c1"), Some(&d)).err().unwrap_or_else(|| panic!("{body:?} was read"));
            assert!(e.code == "ln_link" && e.msg.contains("move it away"), "{e}");
        }
        std::fs::remove_file(d.join(LINK_FILE)).unwrap();
        assert!(LnLink::open(Box::new(Fake::new(7)), cfg("c1"), Some(&d)).is_ok(), "no file is a new link");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn l3_with_the_node_down_the_address_on_file_is_used_and_nothing_waits() {
        let d = dir("down");
        let node = Fake::new(7);
        let l = LnLink::open(Box::new(node.clone()), cfg("c1"), Some(&d)).unwrap();
        tick(&l, T0, Ok(900), 100, &[]);
        node.down.store(true, Ordering::SeqCst);
        // the address on file is the node's: returns go on to it
        let asked = node.asked.load(Ordering::SeqCst);
        assert_eq!(l.return_above(100).as_deref(), Some(addr(1).as_str()));
        assert_eq!(node.asked.load(Ordering::SeqCst), asked, "a return asks the node nothing");
        // used, and the node cannot give the next: the float, and one question per RETRY_SECS
        let said = tick(&l, T0 + 10, Ok(900), 100, &[addr(1)]);
        assert!(said.iter().any(|m| m.contains("not reachable")), "{said:?}");
        assert_eq!((l.address(), l.return_above(10)), (None, None));
        let asked = node.asked.load(Ordering::SeqCst);
        for i in 11..(10 + RETRY_SECS) {
            assert!(tick(&l, T0 + i, Ok(900), 100, &[addr(1)]).is_empty(), "said once");
        }
        assert_eq!(node.asked.load(Ordering::SeqCst), asked);
        assert_eq!(l.return_above(10), None);
        assert!(l.report(T0 + 20, None)["addressError"].as_str().unwrap().contains("not reachable"));
        // back: the next address, and returns go to it
        node.down.store(false, Ordering::SeqCst);
        tick(&l, T0 + 10 + RETRY_SECS, Ok(900), 100, &[addr(1)]);
        assert_eq!(l.return_above(10).as_deref(), Some(addr(2).as_str()));
        assert!(l.report(T0 + 50, None)["addressError"].is_null());
        // a restart with the node down from the start: the address on file, the statement on file
        node.down.store(true, Ordering::SeqCst);
        drop(l);
        let l = LnLink::open(Box::new(node.clone()), cfg("c1"), Some(&d)).unwrap();
        tick(&l, T0 + 100, Ok(900), 100, &[]);
        assert_eq!(l.return_above(10).as_deref(), Some(addr(2).as_str()));
        assert!(l.lightning_extra(T0 + 100).is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn l1_another_certificate_or_another_node_key_retires_the_address_on_file() {
        let d = dir("node");
        let node = Fake::new(7);
        let l = LnLink::open(Box::new(node.clone()), cfg("c1"), Some(&d)).unwrap();
        tick(&l, T0, Ok(900), 100, &[]);
        assert!(l.return_above(10).is_some());
        drop(l);
        // the certificate setting changed and the node is down: the address waits
        node.down.store(true, Ordering::SeqCst);
        let l = LnLink::open(Box::new(node.clone()), cfg("c2"), Some(&d)).unwrap();
        tick(&l, T0 + 1, Ok(900), 100, &[]);
        assert_eq!((l.address(), l.return_above(10)), (None, None));
        assert_eq!(l.report(T0 + 1, None)["waitingForNode"], true);
        // the same node signs: its address is good again
        node.down.store(false, Ordering::SeqCst);
        tick(&l, T0 + 1 + RETRY_SECS, Ok(900), 100, &[]);
        assert_eq!(l.return_above(10).as_deref(), Some(addr(1).as_str()));
        drop(l);
        // another certificate and another key: the old node's address is retired, never paid again
        let other = Fake::new(8);
        other.n.store(50, Ordering::SeqCst);
        let l = LnLink::open(Box::new(other.clone()), cfg("c3"), Some(&d)).unwrap();
        assert_eq!(l.return_above(10), None);
        let said = tick(&l, T0 + 100, Ok(900), 100, &[]);
        assert!(said.iter().any(|m| m.contains("is now") && m.contains(&other.id()) && m.contains(&node.id())), "{said:?}");
        assert_eq!(l.return_above(10).as_deref(), Some(addr(50).as_str()));
        assert_eq!(l.node_id().unwrap(), other.id());
        assert_eq!(l.scripts().len(), 2, "the old node's address is still known as one of the link's");
        // the same certificate, and the node's key changed under it (a node restored from another seed)
        *other.key.lock().unwrap() = SecretKey::from_slice(&[11; 32]).unwrap();
        tick(&l, T0 + 100 + RESIGN_AFTER_SECS, Ok(900), 100, &[]);
        assert_eq!(l.return_above(10).as_deref(), Some(addr(51).as_str()), "the address of the key before is retired at the next signature");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_statement_is_signed_checked_kept_and_signed_again_weekly() {
        let d = dir("stmt");
        let node = Fake::new(7);
        let c = cfg("c1");
        let l = LnLink::open(Box::new(node.clone()), c.clone(), Some(&d)).unwrap();
        assert_eq!(l.lightning_extra(T0), None);
        tick(&l, T0, Ok(0), 0, &[]);
        let ex = l.lightning_extra(T0).unwrap();
        assert_eq!(ex["nodeId"], node.id().as_str());
        let st = hub_identity::check_extra(Some(&ex), Some(&node.id()), NET, &c.pay_to, T0).unwrap();
        assert_eq!(st.as_deref(), Some(node.id().as_str()));
        assert!(ex["statement"].as_str().unwrap().ends_with(&format!("until={}", T0 + LIFE_SECS)));
        let r = l.report(T0, Some("http://hub.example:9480"));
        assert_eq!(r["hubAddress"], format!("{}@hub.example:9480", node.id()).as_str());
        // not signed again within the week
        let asked = node.asked.load(Ordering::SeqCst);
        tick(&l, T0 + RESIGN_AFTER_SECS - 1, Ok(0), 0, &[]);
        assert_eq!(node.asked.load(Ordering::SeqCst), asked);
        tick(&l, T0 + RESIGN_AFTER_SECS, Ok(0), 0, &[]);
        assert!(l.lightning_extra(T0 + RESIGN_AFTER_SECS).unwrap()["statement"].as_str().unwrap().ends_with(&format!("until={}", T0 + RESIGN_AFTER_SECS + LIFE_SECS)));
        // the node gone for good: the statement is shown while it runs, and not a second longer
        node.down.store(true, Ordering::SeqCst);
        let last = T0 + RESIGN_AFTER_SECS + LIFE_SECS;
        tick(&l, last - 1, Ok(0), 0, &[]);
        assert!(l.lightning_extra(last - 1).is_some());
        assert_eq!(l.lightning_extra(last), None);
        assert_eq!(l.report(last, Some("http://h:1"))["hubAddress"], Value::Null, "no address by node id without a running statement");
        assert!(l.report(last, None)["statementError"].as_str().unwrap().contains("not reachable"));
        // a clock set back does not keep an old statement for ever: it is signed again
        node.down.store(false, Ordering::SeqCst);
        tick(&l, T0 - 10 * RESIGN_AFTER_SECS, Ok(0), 0, &[]);
        assert!(l.lightning_extra(T0 - 10 * RESIGN_AFTER_SECS).is_some());
        // a hub key or network that changed under the file: signed again at once
        drop(l);
        let mut c2 = c.clone();
        c2.network = "bip122:other".into();
        let l = LnLink::open(Box::new(node.clone()), c2, Some(&d)).unwrap();
        assert_eq!(l.lightning_extra(T0), None, "the statement on file is for another network");
        tick(&l, T0, Ok(0), 0, &[]);
        assert!(l.lightning_extra(T0).unwrap()["statement"].as_str().unwrap().contains("network=bip122:other"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_signature_that_is_not_the_nodes_is_not_served() {
        struct Liar;
        impl LnNode for Liar {
            fn new_address(&self) -> Result<String> {
                Ok(addr(1))
            }
            fn sign_message(&self, _m: &[u8]) -> Result<String> {
                Ok("not zbase32 of 65 bytes".into())
            }
        }
        let l = LnLink::open(Box::new(Liar), cfg("c1"), None).unwrap();
        let said = tick(&l, T0, Ok(900), 100, &[]);
        assert!(said.iter().any(|m| m.starts_with("statement:")), "{said:?}");
        assert_eq!((l.lightning_extra(T0), l.node_id()), (None, None));
        assert_eq!(l.address(), None, "no address is asked of a node that has not shown its key");
    }

    #[test]
    fn a_pasted_macaroon_is_hex_base64_or_the_file() {
        use base64::Engine;
        let m = crate::macaroon::lnd_macaroon_for_tests(&[("uri", &["/lnrpc.Lightning/NewAddress"])], &[]);
        assert_eq!(macaroon_bytes(&m).unwrap(), m);
        assert_eq!(macaroon_bytes(format!(" {}\n", hex::encode(&m)).as_bytes()).unwrap(), m);
        assert_eq!(macaroon_bytes(hex::encode(&m).to_uppercase().as_bytes()).unwrap(), m);
        assert_eq!(macaroon_bytes(base64::engine::general_purpose::STANDARD.encode(&m).as_bytes()).unwrap(), m);
        assert_eq!(macaroon_bytes(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&m).as_bytes()).unwrap(), m);
        for wrong in [&b""[..], b"zz", b"00ff", &[2, 1, 1], &[0xff, 0xfe]] {
            assert!(macaroon_bytes(wrong).is_err(), "{wrong:?}");
        }
    }
}
