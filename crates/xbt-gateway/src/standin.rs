//! A stand-in for the seller's node, in memory: hold invoices that are made, paid, held, settled
//! and cancelled as the Lightning Fork node was seen to do it on the lab (`scripts/gateway_regtest.sh`
//! runs the same rules against the real node). For tests; no shipped binary uses it.
//!
//! What it copies from the node, each seen on the lab: a second invoice for one hash is refused;
//! settling an open or a cancelled invoice is refused; **settling a settled invoice again answers
//! success**; a held invoice is cancelled when 18 blocks or fewer are left before its HTLC expires;
//! the payer's HTLC expires 3 blocks later than the invoice's delta says.
use std::collections::HashMap;
use std::sync::{Condvar, Mutex, MutexGuard};

use sha2::{Digest, Sha256};

use crate::node::{Channel, Hash, Info, Invoice, InvoiceState, Node, NodeError, NodeOffer, OfferInvoice};

/// The node cancels a held invoice this many blocks before its HTLC expires.
pub const HOLD_EXPIRY_DELTA: u32 = xbt402::ticket::HOLD_EXPIRY_DELTA;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    inv: Invoice,
    msat: u64,
    cltv: u32,
    /// An ordinary invoice: a payment that arrives settles it at once, and no HTLC stays pending.
    ordinary: bool,
    /// How long it may be paid for, as asked: the node's own expiry is the test's to call.
    expiry_s: u32,
}

/// One settle call the stand-in answered with success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settle {
    pub hash: Hash,
    /// The invoice was held when the call arrived (false: it had been settled before).
    pub was_held: bool,
    /// Blocks left before the HTLC's expiry when the call arrived.
    pub blocks_left: u32,
}

#[derive(Debug, Default)]
struct State {
    invoices: HashMap<Hash, Held>,
    height: u32,
    down: bool,
    /// Raised on every change: watchers wake on it.
    version: u64,
    /// Raised when the node "restarts": every open stream breaks.
    generation: u64,
    settles: Vec<Settle>,
    calls: HashMap<&'static str, u64>,
    /// The next settle call is carried out and then answered as if the connection had died.
    lose_settle_answer: bool,
    /// Streams deliver nothing while this is set: a stream that has fallen behind.
    streams_held: bool,
    /// A cancel of a settled invoice answers success and changes nothing. Not what the node was
    /// seen to do: a fault, to show the gateway takes no cancel's yes for the invoice's state.
    cancel_yes_for_settled: bool,
    /// The next lookup is answered as if the connection had died.
    lose_lookup_answer: bool,
    /// The next ordinary invoice is made, and its answer lost as if the connection had died.
    lose_invoice_answer: bool,
    pubkey: String,
    networks: Vec<String>,
    /// What `channels` answers (`None`: the node was given no channels macaroon).
    channels: Option<Vec<Channel>>,
    /// The preimages of the ordinary invoices: what a payer learns when its payment settles.
    preimages: HashMap<Hash, [u8; 32]>,
    /// The node's BOLT 12 offer, once made (or as a test set it), and the invoices issued for it,
    /// in the order they were, with their preimages.
    offer: Option<NodeOffer>,
    offer_invoices: Vec<(OfferInvoice, [u8; 32])>,
}

#[derive(Debug)]
pub struct StandIn {
    state: Mutex<State>,
    changed: Condvar,
}

impl StandIn {
    pub fn new(height: u32) -> Self {
        let state = State {
            height,
            pubkey: "02".repeat(33),
            networks: vec!["regtest".into()],
            ..State::default()
        };
        Self {
            state: Mutex::new(state),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn call(&self, name: &'static str) -> Result<MutexGuard<'_, State>, NodeError> {
        let mut s = self.lock();
        *s.calls.entry(name).or_insert(0) += 1;
        if s.down {
            return Err(NodeError::Unreachable("connection refused".into()));
        }
        Ok(s)
    }

    fn touch(&self, s: &mut State) {
        s.version += 1;
        self.changed.notify_all();
    }

    // --- what a test does to the node ---------------------------------------------------------------

    /// The buyer's payment arrives: the invoice is held. False: there is no such open invoice.
    pub fn pay(&self, hash: &Hash) -> bool {
        self.pay_msat(hash, None)
    }

    /// As [`StandIn::pay`], with an amount other than the invoice's.
    pub fn pay_msat(&self, hash: &Hash, msat: Option<u64>) -> bool {
        let mut s = self.lock();
        let height = s.height;
        let Some(h) = s
            .invoices
            .get_mut(hash)
            .filter(|h| h.inv.state == InvoiceState::Open)
        else {
            return false;
        };
        h.inv = Invoice {
            state: if h.ordinary {
                InvoiceState::Settled
            } else {
                InvoiceState::Accepted
            },
            paid_msat: msat.unwrap_or(h.msat),
            expiry_height: Some(height + h.cltv + 3),
            accept_height: Some(height),
        };
        self.touch(&mut s);
        true
    }

    /// The preimage a payer of an ordinary invoice holds once its payment has settled.
    pub fn paid_preimage(&self, hash: &Hash) -> Option<[u8; 32]> {
        let s = self.lock();
        let settled = s
            .invoices
            .get(hash)
            .is_some_and(|h| h.ordinary && h.inv.state == InvoiceState::Settled);
        settled.then(|| s.preimages.get(hash).copied()).flatten()
    }

    /// What the node's channel list says from now on (`None`: no channels macaroon).
    pub fn set_channels(&self, channels: Option<Vec<Channel>>) {
        self.lock().channels = channels;
    }

    /// A new tip: held invoices with 18 blocks or fewer left are cancelled, as the node does.
    pub fn set_height(&self, height: u32) {
        let mut s = self.lock();
        s.height = height;
        for h in s.invoices.values_mut() {
            if h.inv.state == InvoiceState::Accepted
                && h.inv
                    .expiry_height
                    .is_some_and(|e| e.saturating_sub(height) <= HOLD_EXPIRY_DELTA)
            {
                h.inv.state = InvoiceState::Canceled;
            }
        }
        self.touch(&mut s);
    }

    /// Stop or start the node. Stopping breaks every stream; invoices are kept, as on disk.
    pub fn set_down(&self, down: bool) {
        let mut s = self.lock();
        s.down = down;
        s.generation += 1;
        self.touch(&mut s);
    }

    /// The node's own time expiry of an unpaid invoice.
    pub fn expire_unpaid(&self, hash: &Hash) {
        let mut s = self.lock();
        if let Some(h) = s
            .invoices
            .get_mut(hash)
            .filter(|h| h.inv.state == InvoiceState::Open)
        {
            h.inv.state = InvoiceState::Canceled;
        }
        self.touch(&mut s);
    }

    /// Hold every invoice stream back (true) or let them catch up (false). Calls are still answered.
    pub fn hold_streams(&self, held: bool) {
        let mut s = self.lock();
        s.streams_held = held;
        self.touch(&mut s);
    }

    pub fn lose_next_settle_answer(&self) {
        self.lock().lose_settle_answer = true;
    }

    /// From now on a cancel of a settled invoice answers success (and cancels nothing).
    pub fn cancel_answers_yes_for_settled(&self) {
        self.lock().cancel_yes_for_settled = true;
    }

    pub fn lose_next_lookup_answer(&self) {
        self.lock().lose_lookup_answer = true;
    }

    pub fn lose_next_invoice_answer(&self) {
        self.lock().lose_invoice_answer = true;
    }

    pub fn set_identity(&self, pubkey: &str, networks: &[&str]) {
        let mut s = self.lock();
        s.pubkey = pubkey.to_string();
        s.networks = networks.iter().map(|n| n.to_string()).collect();
    }

    /// The offer [`Node::create_offer`] answers with from now on (a test that needs a real one).
    pub fn set_offer(&self, offer: NodeOffer) {
        self.lock().offer = Some(offer);
    }

    /// A buyer fetched an invoice from the node's offer with this payer note: the invoice is
    /// issued, open, at `created_at` (unix seconds). Returns its preimage, which the payer learns
    /// when it pays ([`StandIn::pay_offer_invoice`]).
    pub fn issue_offer_invoice(&self, note: Option<&str>, created_at: u64) -> [u8; 32] {
        let mut preimage = [0u8; 32];
        preimage.copy_from_slice(&xbt_svc::random_bytes(32));
        let inv = OfferInvoice {
            payment_hash: Sha256::digest(preimage).into(),
            state: Some(InvoiceState::Open),
            paid_msat: 0,
            created_at,
            payer_note: note.map(str::to_string),
        };
        let mut s = self.lock();
        s.offer_invoices.push((inv, preimage));
        self.touch(&mut s);
        preimage
    }

    /// The payment of an offer invoice arrives, for `msat`: it is settled at once, as an ordinary
    /// invoice is. False: there is no such open invoice.
    pub fn pay_offer_invoice(&self, hash: &Hash, msat: u64) -> bool {
        let mut s = self.lock();
        let Some((inv, _)) = s
            .offer_invoices
            .iter_mut()
            .find(|(i, _)| &i.payment_hash == hash && i.state == Some(InvoiceState::Open))
        else {
            return false;
        };
        inv.state = Some(InvoiceState::Settled);
        inv.paid_msat = msat;
        self.touch(&mut s);
        true
    }

    /// A payment by offer from start to end: an invoice with `note` issued and paid for `msat`.
    /// Returns its preimage, the payer's proof.
    pub fn pay_by_offer(&self, note: Option<&str>, msat: u64, created_at: u64) -> [u8; 32] {
        let p = self.issue_offer_invoice(note, created_at);
        self.pay_offer_invoice(&Sha256::digest(p).into(), msat);
        p
    }

    /// Offer invoices issued, and of them those paid.
    pub fn offer_counts(&self) -> (usize, usize) {
        let s = self.lock();
        let paid = s.offer_invoices.iter().filter(|(i, _)| i.state == Some(InvoiceState::Settled)).count();
        (s.offer_invoices.len(), paid)
    }

    /// The preimage of a paid offer invoice: what its payer learnt.
    pub fn offer_preimage(&self, hash: &Hash) -> Option<[u8; 32]> {
        self.lock()
            .offer_invoices
            .iter()
            .find(|(i, _)| &i.payment_hash == hash && i.state == Some(InvoiceState::Settled))
            .map(|(_, p)| *p)
    }

    // --- what a test reads ----------------------------------------------------------------------------

    pub fn state_of(&self, hash: &Hash) -> Option<InvoiceState> {
        self.lock().invoices.get(hash).map(|h| h.inv.state)
    }

    /// The seconds an invoice was made payable for.
    pub fn expiry_of(&self, hash: &Hash) -> Option<u32> {
        self.lock().invoices.get(hash).map(|h| h.expiry_s)
    }

    pub fn count(&self, state: InvoiceState) -> usize {
        self.lock()
            .invoices
            .values()
            .filter(|h| h.inv.state == state)
            .count()
    }

    pub fn invoices(&self) -> usize {
        self.lock().invoices.len()
    }

    /// Every settle call answered with success, in order.
    /// Held invoices (not ordinary ones) in `state`.
    pub fn count_held(&self, state: InvoiceState) -> usize {
        self.lock()
            .invoices
            .values()
            .filter(|h| !h.ordinary && h.inv.state == state)
            .count()
    }

    pub fn settles(&self) -> Vec<Settle> {
        self.lock().settles.clone()
    }

    /// How often `name` (`add_hold`, `settle`, `cancel`, `lookup`, `watch`, `info`) was called.
    pub fn calls(&self, name: &str) -> u64 {
        self.lock().calls.get(name).copied().unwrap_or(0)
    }
}

impl Node for StandIn {
    fn add_hold(
        &self,
        hash: &Hash,
        msat: u64,
        cltv_blocks: u32,
        expiry_s: u32,
    ) -> Result<String, NodeError> {
        let mut s = self.call("add_hold")?;
        if s.invoices.contains_key(hash) {
            return Err(NodeError::Refused(
                "invoice with payment hash already exists".into(),
            ));
        }
        if cltv_blocks <= 24 {
            return Err(NodeError::Refused(
                "cltv_expiry must be greater than 24".into(),
            ));
        }
        let inv = Invoice {
            state: InvoiceState::Open,
            paid_msat: 0,
            expiry_height: None,
            accept_height: None,
        };
        s.invoices.insert(
            *hash,
            Held {
                inv,
                msat,
                cltv: cltv_blocks,
                ordinary: false,
                expiry_s,
            },
        );
        self.touch(&mut s);
        Ok(format!("lnbcrt-standin-{}", hex::encode(hash)))
    }

    fn add_invoice(
        &self,
        preimage: &[u8; 32],
        msat: u64,
        cltv_blocks: u32,
        expiry_s: u32,
    ) -> Result<String, NodeError> {
        let mut s = self.call("add_invoice")?;
        let hash: Hash = Sha256::digest(preimage).into();
        if s.invoices.contains_key(&hash) {
            return Err(NodeError::Refused(
                "invoice with payment hash already exists".into(),
            ));
        }
        let inv = Invoice {
            state: InvoiceState::Open,
            paid_msat: 0,
            expiry_height: None,
            accept_height: None,
        };
        s.invoices.insert(
            hash,
            Held {
                inv,
                msat,
                cltv: cltv_blocks,
                ordinary: true,
                expiry_s,
            },
        );
        s.preimages.insert(hash, *preimage);
        self.touch(&mut s);
        if std::mem::take(&mut s.lose_invoice_answer) {
            return Err(NodeError::Unreachable("connection reset".into()));
        }
        Ok(format!("lnbcrt-standin-{}", hex::encode(hash)))
    }

    fn channels(&self) -> Result<Vec<Channel>, NodeError> {
        let s = self.call("channels")?;
        s.channels
            .clone()
            .ok_or_else(|| NodeError::Refused("this node was given no channels macaroon".into()))
    }

    fn settle(&self, preimage: &[u8; 32]) -> Result<(), NodeError> {
        let mut s = self.call("settle")?;
        let hash: Hash = Sha256::digest(preimage).into();
        let height = s.height;
        let Some(h) = s.invoices.get_mut(&hash) else {
            return Err(NodeError::Refused("unable to locate invoice".into()));
        };
        let was_held = match h.inv.state {
            InvoiceState::Open => return Err(NodeError::Refused("invoice still open".into())),
            InvoiceState::Canceled => {
                return Err(NodeError::Refused("invoice already canceled".into()))
            }
            InvoiceState::Accepted => true,
            InvoiceState::Settled => false,
        };
        h.inv.state = InvoiceState::Settled;
        let blocks_left = h.inv.expiry_height.map_or(0, |e| e.saturating_sub(height));
        s.settles.push(Settle {
            hash,
            was_held,
            blocks_left,
        });
        let lost = std::mem::take(&mut s.lose_settle_answer);
        self.touch(&mut s);
        if lost {
            return Err(NodeError::Unreachable("connection reset".into()));
        }
        Ok(())
    }

    fn cancel(&self, hash: &Hash) -> Result<(), NodeError> {
        let mut s = self.call("cancel")?;
        let yes_for_settled = s.cancel_yes_for_settled;
        let Some(h) = s.invoices.get_mut(hash) else {
            return Err(NodeError::Refused("unable to locate invoice".into()));
        };
        match h.inv.state {
            InvoiceState::Settled if yes_for_settled => return Ok(()),
            InvoiceState::Settled => {
                return Err(NodeError::Refused("invoice already settled".into()))
            }
            InvoiceState::Canceled => return Ok(()),
            _ => h.inv.state = InvoiceState::Canceled,
        }
        self.touch(&mut s);
        Ok(())
    }

    fn lookup(&self, hash: &Hash) -> Result<Option<Invoice>, NodeError> {
        let mut s = self.call("lookup")?;
        if std::mem::take(&mut s.lose_lookup_answer) {
            return Err(NodeError::Unreachable("connection reset".into()));
        }
        Ok(s.invoices.get(hash).map(|h| h.inv))
    }

    fn watch(&self, hash: &Hash, on: &mut dyn FnMut(Invoice) -> bool) -> Result<(), NodeError> {
        let mut s = self.call("watch")?;
        let generation = s.generation;
        let mut last = None;
        loop {
            if s.down || s.generation != generation {
                return Err(NodeError::Unreachable("the invoice stream ended".into()));
            }
            let Some(inv) = s.invoices.get(hash).map(|h| h.inv) else {
                return Err(NodeError::Refused("unable to locate invoice".into()));
            };
            if last != Some(inv) && !s.streams_held {
                last = Some(inv);
                drop(s);
                if !on(inv) || inv.is_final() {
                    return Ok(());
                }
                s = self.lock();
                continue;
            }
            let version = s.version;
            while s.version == version {
                s = self.changed.wait(s).unwrap_or_else(|p| p.into_inner());
            }
        }
    }

    fn create_offer(&self, description: &str) -> Result<NodeOffer, NodeError> {
        let mut s = self.call("create_offer")?;
        // the same fields make the same offer, as the node's do
        let made = s.offer.clone().unwrap_or_else(|| {
            let id: Hash = Sha256::digest(format!("standin-offer|{description}")).into();
            NodeOffer { id, bolt12: format!("lno1standin{}", hex::encode(id)) }
        });
        s.offer = Some(made.clone());
        Ok(made)
    }

    fn offer_invoices(&self, offer_id: &Hash) -> Result<Vec<OfferInvoice>, NodeError> {
        let s = self.call("offer_invoices")?;
        if s.offer.as_ref().map(|o| &o.id) != Some(offer_id) {
            return Err(NodeError::Refused("offer not found".into()));
        }
        Ok(s.offer_invoices.iter().map(|(i, _)| i.clone()).collect())
    }

    fn info(&self) -> Result<Info, NodeError> {
        let s = self.call("info")?;
        Ok(Info {
            pubkey: s.pubkey.clone(),
            height: s.height,
            synced: true,
            networks: s.networks.clone(),
            blake2b: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_answers_as_the_node_was_seen_to() {
        let n = StandIn::new(100);
        let secret = [5u8; 32];
        let hash: Hash = Sha256::digest(secret).into();
        assert!(n
            .add_hold(&hash, 1_000_000, 24, 60)
            .unwrap_err()
            .to_string()
            .contains("greater than 24"));
        n.add_hold(&hash, 1_000_000, 40, 60).unwrap();
        assert!(n
            .add_hold(&hash, 1_000_000, 40, 60)
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        assert!(n
            .settle(&secret)
            .unwrap_err()
            .to_string()
            .contains("invoice still open"));
        assert!(n
            .settle(&[6u8; 32])
            .unwrap_err()
            .to_string()
            .contains("unable to locate"));
        assert!(n.pay(&hash) && !n.pay(&hash));
        assert_eq!(
            n.lookup(&hash).unwrap().unwrap(),
            Invoice {
                state: InvoiceState::Accepted,
                paid_msat: 1_000_000,
                expiry_height: Some(143),
                accept_height: Some(100)
            }
        );
        n.settle(&secret).unwrap();
        // the node's own behaviour: a second settle of a settled invoice is a success
        n.settle(&secret).unwrap();
        assert_eq!(
            n.settles().iter().map(|s| s.was_held).collect::<Vec<_>>(),
            vec![true, false]
        );
        assert!(n
            .cancel(&hash)
            .unwrap_err()
            .to_string()
            .contains("already settled"));
        // a held invoice is cancelled 18 blocks before its expiry
        let other: Hash = Sha256::digest([7u8; 32]).into();
        n.add_hold(&other, 1_000_000, 40, 60).unwrap();
        n.pay(&other);
        n.set_height(124);
        assert_eq!(n.state_of(&other), Some(InvoiceState::Accepted));
        n.set_height(125);
        assert_eq!(n.state_of(&other), Some(InvoiceState::Canceled));
        assert!(n
            .settle(&[7u8; 32])
            .unwrap_err()
            .to_string()
            .contains("already canceled"));
        assert_eq!(n.lookup(&[9u8; 32]).unwrap(), None);
        n.set_down(true);
        assert!(matches!(n.lookup(&hash), Err(NodeError::Unreachable(_))));
    }
}
