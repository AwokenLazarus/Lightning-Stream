//! The lottery, the buyer's rules (`docs/TICKETS.md`, section 9): what the owner sets, how a
//! seller's lottery entry is read, which way of paying a seller is used, and how large a win is.
//! No IO: [`crate::ticket_pay`] speaks to the seller, [`crate::ticket_rail`] books and pays a win.
//!
//! The rules kept here, one sentence each:
//!
//! * **The owner bounds a win and the odds before anything is paid** ([`win_size`]): a win is never
//!   above the owner's cap for that seller, never below the fee floor of the way to it, and large
//!   enough that no piece of the route wins more often than the owner's `max_odds_den` allows.
//! * **A win is sized to the session** ([`win_size`]): one sixteenth of what the call may use, so
//!   that a session expects about 16 wins and what it pays stays near its price.
//! * **Which way a seller is paid is one function** ([`choose`]): tickets for a piece worth a
//!   ticket or more and for a seller the buyer stays with when a held ticket fits; draws for
//!   anything smaller and whenever no held ticket fits; a prepaid ticket where neither does.
//! * **Terms are read strictly** ([`DrawTerms::parse`]): an entry this wallet cannot read whole is
//!   an entry it does not take.
//!
//! Every number from outside is a `u64` of decimal digits; sums and products are checked.
use serde_json::{Map, Value};

use crate::pyjson::{py_int, str_or_empty, truthy};
use crate::ticket::{outside_u64, Refusal};
use crate::ticket_http::Price;

/// A win is paid by an ordinary payment, which a routing node charges a base fee for (1 sat at the
/// forks' default policy): 64 sat keeps that at 1.6% a hop. Over a channel of the wallet's own to
/// the seller there is no hop and no fee, and the floor is what the node carries well.
pub const ROUTED_FLOOR_SATS: i64 = 64;
pub const DIRECT_FLOOR_SATS: i64 = 4;

/// policy.json `tickets.lottery`: the owner's bounds on paying by draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LotteryPolicy {
    pub enabled: bool,
    /// The largest win, in sats: for a seller the owner named, and for one it did not.
    pub max_win_sats: i64,
    pub unlisted_max_win_sats: i64,
    /// The smallest win the owner pays: below it a routing fee is most of the payment.
    pub min_win_sats: i64,
    /// The largest odds of one piece: 1 in this many (4: no piece wins more than one time in four).
    /// A piece that would win more often is priced near a whole win and is paid with tickets.
    pub max_odds_den: i64,
    /// The wins a session is sized to expect.
    pub expected_wins: i64,
    /// How far above its price a session may pay before the wallet asks for no more pieces, in
    /// tenths of a standard deviation (31: about one honest session in 1,000 reaches it).
    pub luck_tenths: i64,
    /// Values given beyond the last reveal the wallet has checked.
    pub ahead: i64,
    /// Wins paid to one seller the owner has not named, in a task's window.
    pub unlisted_max_wins: i64,
    /// The smallest win through a routing node and over a direct channel, in sats.
    pub routed_floor_sats: i64,
    pub direct_floor_sats: i64,
    /// A seller expected to earn this many tickets or more from a call is one the buyer stays with.
    pub stay_tickets: i64,
    /// A call expected to draw fewer wins than this is not paid by draws where the seller's ticket
    /// entry can pay it: with so few wins what it costs is mostly luck (nothing, or several times
    /// its price), and a ticket costs what it says.
    pub min_expected_wins: i64,
}

impl Default for LotteryPolicy {
    fn default() -> Self {
        Self { enabled: true, max_win_sats: 1_000, unlisted_max_win_sats: 250, min_win_sats: 16, max_odds_den: 4, expected_wins: 16, luck_tenths: 31, ahead: 8,
               unlisted_max_wins: 32, routed_floor_sats: ROUTED_FLOOR_SATS, direct_floor_sats: DIRECT_FLOOR_SATS, stay_tickets: 4,
               min_expected_wins: 4 }
    }
}

pub const LOTTERY_INT_KEYS: [&str; 12] = ["max_win_sats", "unlisted_max_win_sats", "min_win_sats", "max_odds_den", "expected_wins", "luck_tenths", "ahead",
                                          "unlisted_max_wins", "routed_floor_sats", "direct_floor_sats", "stay_tickets", "min_expected_wins"];

impl LotteryPolicy {
    /// From policy.json `tickets.lottery`. A number that is missing takes the default; one that is
    /// not a non-negative integer is 0 here (it refuses, never widens) and an error in [`validate`].
    pub fn from_map(m: Option<&Map<String, Value>>) -> Self {
        let d = Self::default();
        let Some(m) = m else { return d };
        let i = |k: &str, dflt: i64| match m.get(k).filter(|v| !v.is_null()) {
            None => dflt,
            Some(v) => py_int(Some(v)).filter(|n| *n >= 0).unwrap_or(0),
        };
        Self { enabled: m.get("enabled").filter(|v| !v.is_null()).map_or(d.enabled, |v| truthy(Some(v))),
               max_win_sats: i("max_win_sats", d.max_win_sats).min(i64::MAX / 1000), unlisted_max_win_sats: i("unlisted_max_win_sats", d.unlisted_max_win_sats),
               min_win_sats: i("min_win_sats", d.min_win_sats), max_odds_den: i("max_odds_den", d.max_odds_den), expected_wins: i("expected_wins", d.expected_wins),
               luck_tenths: i("luck_tenths", d.luck_tenths), ahead: i("ahead", d.ahead), unlisted_max_wins: i("unlisted_max_wins", d.unlisted_max_wins),
               routed_floor_sats: i("routed_floor_sats", d.routed_floor_sats), direct_floor_sats: i("direct_floor_sats", d.direct_floor_sats),
               stay_tickets: i("stay_tickets", d.stay_tickets), min_expected_wins: i("min_expected_wins", d.min_expected_wins) }
    }

    /// The largest win for a seller, in msat.
    pub fn max_win_msat(&self, listed: bool) -> u64 {
        let sats = if listed { self.max_win_sats } else { self.max_win_sats.min(self.unlisted_max_win_sats) };
        (sats.max(0) as u64).saturating_mul(1000)
    }
}

/// policy.json `tickets.lottery` checks for `validate_policy`.
pub fn validate(raw: &Value, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
    let Some(m) = raw.as_object() else {
        errors.push("policy.json tickets.lottery: must be an object".into());
        return;
    };
    for k in LOTTERY_INT_KEYS {
        match m.get(k).filter(|v| !v.is_null()).map(|v| py_int(Some(v))) {
            None => {}
            Some(None) => errors.push(format!("policy.json tickets.lottery.{k}: not an integer")),
            Some(Some(n)) if n < 0 => errors.push(format!("policy.json tickets.lottery.{k}: must be >= 0 (got {n})")),
            _ => {}
        }
    }
    for k in m.keys() {
        if k != "enabled" && !LOTTERY_INT_KEYS.contains(&k.as_str()) {
            warnings.push(format!("policy.json tickets.lottery.{k}: unknown key (the signer ignores it)"));
        }
    }
    let p = LotteryPolicy::from_map(Some(m));
    if p.enabled && p.max_odds_den < 2 {
        errors.push("policy.json tickets.lottery.max_odds_den: at least 2 (a piece that always wins is a payment, not a draw)".into());
    }
    if p.enabled && (p.expected_wins == 0 || p.ahead == 0) {
        errors.push("policy.json tickets.lottery: expected_wins and ahead are at least 1".into());
    }
    if p.enabled && p.min_win_sats > p.max_win_sats {
        warnings.push(format!("policy.json tickets.lottery: min_win_sats {} is above max_win_sats {}: no win size is allowed, and nothing is paid by draws",
                              p.min_win_sats, p.max_win_sats));
    }
    if p.enabled && p.routed_floor_sats < 16 {
        warnings.push(format!("policy.json tickets.lottery.routed_floor_sats {}: a routing node's base fee of 1 sat is more than 6% of a win below 16 sat",
                              p.routed_floor_sats));
    }
}

/// How a task's sellers are paid when their terms offer both tickets and the lottery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Meter {
    /// The wallet's rule ([`choose`]).
    Auto,
    /// Tickets only: the owner wants every payment exact.
    Tickets,
    /// Draws wherever a seller offers them.
    Draws,
}

impl Meter {
    /// policy.json `tickets.tasks.<name>.meter`. Left out: the wallet's rule. A word that is not
    /// one of the three is tickets: a misspelling never turns the lottery on.
    pub fn parse(v: Option<&Value>) -> Self {
        match v.filter(|v| !v.is_null()).map(|v| v.as_str()) {
            None | Some(Some("auto")) => Meter::Auto,
            Some(Some("draws")) => Meter::Draws,
            Some(_) => Meter::Tickets,
        }
    }
}

/// The lottery entry of a seller's 402, read whole and bounded.
#[derive(Debug, Clone, PartialEq)]
pub struct DrawTerms {
    /// The seller's Lightning node id: the payee of every win's invoice.
    pub payee: String,
    pub win_msat: u64,
    pub min_win_msat: u64,
    /// The final CLTV delta of every win's invoice.
    pub win_blocks: u32,
    pub window: u32,
    pub grace_seconds: u32,
    pub grace_pieces: u32,
    pub max_unpaid_wins: u32,
    pub chain_draws: u32,
    pub piece_bytes: u64,
    /// `after-verify` or `after-answer`.
    pub release: String,
    /// The key that signs the seller's receipts, 33 bytes.
    pub receipt_key: Vec<u8>,
    pub session_path: String,
    pub price: Price,
    /// The entry as the seller sent it: what `accepted` in PAYMENT-SIGNATURE repeats.
    pub accepted: Value,
}

fn refuse<T>(rule: &'static str, msg: impl Into<String>) -> Result<T, Refusal> {
    Err((rule, msg.into()))
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl DrawTerms {
    /// Read strictly: a field that is missing or of another type refuses the entry, since an entry
    /// this wallet reads differently from its seller is a draw the two would work out differently.
    pub fn parse(acc: &Value, lightning: &str) -> Result<Self, Refusal> {
        const R: &str = "lottery_terms";
        if acc.get("scheme").and_then(Value::as_str) != Some(xbt402::lottery::SCHEME) {
            return refuse(R, "not a lottery entry");
        }
        if acc.get("network").and_then(Value::as_str) != Some(lightning) {
            return refuse("ticket_network", "the entry is for another Lightning network than this wallet's");
        }
        if acc.get("asset").and_then(Value::as_str) != Some(xbt402::ticket::ASSET) {
            return refuse(R, "the asset is not XBT:msat");
        }
        let x = acc.get("extra").filter(|x| x.is_object()).ok_or((R, "the entry has no extra".to_string()))?;
        if x.get("version").and_then(Value::as_str) != Some(xbt402::lottery::VERSION) {
            return refuse(R, "the version is not lottery/0");
        }
        if x.get("features").and_then(Value::as_array).is_none_or(|f| !f.iter().any(|b| b.as_u64() == Some(xbt402::ticket::FEATURE_BLAKE2B))) {
            return refuse("ticket_feature_512", "the entry does not state feature bit 512: its invoices would not be XBT's");
        }
        if x.get("pay").and_then(Value::as_str) != Some(xbt402::lottery::PAY_ON_WIN) {
            return refuse(R, "the entry pays a win another way than by an invoice after it (pay is not on-win): this wallet builds no other");
        }
        let payee = str_or_empty(acc.get("payTo"));
        if !is_hex(&payee, 66) || xbt_primitives::secp256k1::PublicKey::from_slice(&hex::decode(&payee).unwrap_or_default()).is_err() {
            return refuse(R, "payTo is not a node id (66 lower-case hex)");
        }
        let num = |k: &str| outside_u64(x.get(k)).ok_or((R, format!("{k} is not a whole number")));
        let small = |k: &str| x.get(k).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or((R, format!("{k} is not a whole number")));
        let key = str_or_empty(x.get("receiptKey"));
        let receipt_key = hex::decode(&key).ok().filter(|b| is_hex(&key, 66) && xbt_primitives::secp256k1::PublicKey::from_slice(b).is_ok())
            .ok_or((R, "receiptKey is not a compressed public key (66 lower-case hex)".to_string()))?;
        let release = str_or_empty(x.get("release"));
        if release != xbt402::lottery::RELEASE_AFTER_VERIFY && release != xbt402::lottery::RELEASE_AFTER_ANSWER {
            return refuse(R, "release is neither after-verify nor after-answer");
        }
        let session_path = x.get("session").and_then(Value::as_str).filter(|s| s.starts_with('/')).ok_or((R, "session is not a path".to_string()))?.to_string();
        let price = Price::parse(acc).map_err(|(_, why)| (R, why))?;
        let t = Self { payee, win_msat: num("winMsat")?, min_win_msat: num("minWinMsat")?, win_blocks: small("winBlocks")?, window: small("window")?,
                       grace_seconds: small("graceSeconds")?, grace_pieces: small("gracePieces")?, max_unpaid_wins: small("maxUnpaidWins")?,
                       chain_draws: small("chainDraws")?, piece_bytes: num("pieceBytes")?, release, receipt_key, session_path, price, accepted: acc.clone() };
        if t.min_win_msat == 0 || t.min_win_msat > t.win_msat {
            return refuse(R, "minWinMsat is not between 1 and winMsat");
        }
        if t.window == 0 || t.max_unpaid_wins == 0 || t.piece_bytes == 0 || t.chain_draws == 0 || t.chain_draws > xbt402::lottery::MAX_CHAIN_DRAWS {
            return refuse(R, "window, maxUnpaidWins, pieceBytes or chainDraws is outside what a session can run on");
        }
        Ok(t)
    }

    /// Whether `other` (the entry of a later 402 from the same origin) is the same seller on the
    /// same session terms. The price is a route's and may differ from request to request.
    pub fn same_seller(&self, other: &DrawTerms) -> bool {
        self.payee == other.payee && self.receipt_key == other.receipt_key && self.session_path == other.session_path && self.win_msat == other.win_msat
            && self.min_win_msat == other.min_win_msat && self.win_blocks == other.win_blocks && self.piece_bytes == other.piece_bytes
            && self.chain_draws == other.chain_draws
    }

    /// What the dearest piece of this entry's route costs: its request, one second, or one full
    /// piece of bytes. `None`: the price does not fit an amount.
    pub fn dearest_piece(&self) -> Option<u64> {
        Some(self.price.request_msat.max(self.price.second_msat).max(self.price.for_bytes(self.piece_bytes)?))
    }
}

/// The win size of a session with this seller, in msat. `expect_msat`: what the call may use.
/// `direct`: the wallet has a channel of its own to the seller's node. `Err`: no size is inside
/// both the seller's terms and the owner's bounds, and this seller is not paid by draws.
pub fn win_size(terms: &DrawTerms, pol: &LotteryPolicy, listed: bool, expect_msat: u64, direct: bool) -> Result<u64, Refusal> {
    let sats = |n: i64| (n.max(0) as u64).saturating_mul(1000);
    let Some(dearest) = terms.dearest_piece() else { return refuse("lottery_terms", "the route's price does not fit an amount") };
    // no piece may win more often than 1 in max_odds_den: the win is at least that many times the dearest piece
    let Some(by_odds) = dearest.checked_mul(pol.max_odds_den.max(2) as u64) else { return refuse("lottery_terms", "the route's price does not fit an amount") };
    let fee_floor = sats(if direct { pol.direct_floor_sats } else { pol.routed_floor_sats });
    let floor = sats(pol.min_win_sats).max(fee_floor).max(terms.min_win_msat).max(by_odds).max(1000);
    let cap = terms.win_msat.min(pol.max_win_msat(listed));
    if floor > cap {
        let why = if by_odds > cap {
            format!("a piece of this route costs up to {dearest} msat: at the owner's largest odds (1 in {}) that needs a win of {by_odds} msat, above the {cap} msat \
                     the terms and the owner allow. Such a piece is paid with tickets", pol.max_odds_den)
        } else {
            format!("no win size fits: the smallest is {floor} msat (the owner's min_win_sats, the fee floor of {} sat {}, the seller's minWinMsat) and the largest \
                     {cap} msat (the seller's winMsat, the owner's cap for a seller it has {})", fee_floor / 1000,
                    if direct { "over a direct channel" } else { "through a routing node" }, if listed { "named" } else { "not named" })
        };
        return refuse("lottery_win_size", why);
    }
    // one sixteenth of what the seller is expected to earn, in whole sats, inside the bounds
    let target = expect_msat / (pol.expected_wins.max(1) as u64) / 1000 * 1000;
    Ok(target.clamp(floor.div_ceil(1000).saturating_mul(1000).min(cap), cap))
}

/// What [`choose`] looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choice {
    /// The seller's 402 has a ticket entry and a lottery entry the wallet can read.
    pub ticket_entry: bool,
    pub lottery_entry: bool,
    /// The owner's `tickets.lottery.enabled` and the task's `meter`.
    pub lottery_on: bool,
    pub meter: Meter,
    /// A session with this seller is open, and whether it pays by draws.
    pub open: Option<bool>,
    /// The dearest piece of the route, the size of one ticket and what the call may use, in msat.
    pub dearest_msat: u64,
    pub ticket_msat: u64,
    pub expect_msat: u64,
    /// A held ticket can be locked with one more seller now: the slot budget and the owner's caps
    /// on held tickets have room.
    pub held_fits: bool,
    pub stay_tickets: u64,
    /// The seller's ticket entry has prepaid tickets beside it (or is one).
    pub prepaid_entry: bool,
    /// The win a session with this seller would be opened with (0: none fits), and the owner's
    /// `min_expected_wins`.
    pub win_msat: u64,
    pub min_wins: u64,
}

/// Which way a seller is paid, tried first. The other is tried after it where the first is not
/// usable for this seller.
///
/// | Case | Paid by |
/// |---|---|
/// | A session with this seller is open | what that session pays by |
/// | The seller offers one of the two, or the owner turned the lottery off, or the task says | that one |
/// | A piece of the route costs one ticket or more | tickets |
/// | The call is expected to draw fewer than `min_expected_wins` wins (4), and the seller offers prepaid tickets | tickets |
/// | The call may use four tickets' worth or more with this seller, and a held ticket fits | tickets |
/// | Anything smaller, and whenever no held ticket fits | draws |
///
/// Where draws are chosen and cannot be used (no win size fits the owner's bounds), the ticket
/// entry is next, and with it the prepaid ticket that entry falls back to.
pub fn choose(c: &Choice) -> bool {
    if let Some(draws) = c.open {
        return draws;
    }
    if !c.lottery_entry || !c.lottery_on || c.meter == Meter::Tickets {
        return false;
    }
    if !c.ticket_entry || c.meter == Meter::Draws {
        return true;
    }
    if c.dearest_msat >= c.ticket_msat {
        return false;
    }
    // so few wins expected that the call's cost is mostly luck: a ticket, where one can be had without holding
    if c.prepaid_entry && c.win_msat > 0 && c.expect_msat < c.win_msat.saturating_mul(c.min_wins) {
        return false;
    }
    let stays = c.expect_msat >= c.ticket_msat.saturating_mul(c.stay_tickets.max(1));
    !(stays && c.held_fits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NET: &str = "lightning:00000000000000000000000000000001";

    fn node_id() -> String {
        let sk = xbt_primitives::secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
        hex::encode(xbt_primitives::ecdsa::pubkey(&sk))
    }

    fn accepts(price: Value) -> Value {
        let amount = price.get("requestMsat").and_then(Value::as_str).unwrap_or("0").to_string();
        json!({"scheme": "lottery", "network": NET, "asset": "XBT:msat", "amount": amount, "payTo": node_id(),
               "extra": {"version": "lottery/0", "features": [512], "winMsat": "64000", "minWinMsat": "16000", "winBlocks": 40, "pay": "on-win",
                         "release": "after-answer", "window": 8, "graceSeconds": 10, "gracePieces": 64, "maxUnpaidWins": 2, "chainDraws": 65536,
                         "pieceBytes": "262144", "receiptKey": node_id(), "session": "/x402/lottery", "price": price}})
    }

    fn terms(price: Value) -> DrawTerms {
        DrawTerms::parse(&accepts(price), NET).unwrap()
    }

    #[test]
    fn terms_are_read_exactly_as_the_draft_writes_them() {
        let t = terms(json!({"requestMsat": "100", "byteMsat": "100", "perBytes": "262144", "secondMsat": "7"}));
        assert_eq!((t.win_msat, t.min_win_msat, t.win_blocks, t.window, t.grace_seconds, t.grace_pieces, t.max_unpaid_wins), (64_000, 16_000, 40, 8, 10, 64, 2));
        assert_eq!((t.chain_draws, t.piece_bytes, t.release.as_str(), t.session_path.as_str()), (65_536, 262_144, "after-answer", "/x402/lottery"));
        assert_eq!((t.price.request_msat, t.dearest_piece()), (100, Some(100)));
        // what the gateway builds is what this reads
        let built = xbt402::lottery::Terms { network: NET.into(), pay_to: node_id(), win_msat: 64_000, min_win_msat: 16_000, win_blocks: 40, window: 8, grace_seconds: 10,
                                             grace_pieces: 64, max_unpaid_wins: 2, chain_draws: 65_536, piece_bytes: 262_144, receipt_key: node_id(),
                                             session: "/x402/lottery".into() }.accepts(100, "after-verify", &json!({"requestMsat": "100"}));
        assert_eq!(DrawTerms::parse(&built, NET).unwrap().release, "after-verify");
        type Edit = Box<dyn Fn(&mut Value)>;
        let bad: Vec<(Edit, &str)> = vec![
            (Box::new(|v| v["scheme"] = json!("ticket")), "lottery_terms"),
            (Box::new(|v| v["network"] = json!("lightning:00000000000000000000000000000002")), "ticket_network"),
            (Box::new(|v| v["asset"] = json!("BTC:msat")), "lottery_terms"),
            (Box::new(|v| v["extra"]["version"] = json!("lottery/1")), "lottery_terms"),
            (Box::new(|v| v["extra"]["features"] = json!([])), "ticket_feature_512"),
            // a way of paying a win this wallet does not build (a held ticket, a sealed draw) is not taken for the one it does
            (Box::new(|v| v["extra"]["pay"] = json!("seller-held")), "lottery_terms"),
            (Box::new(|v| v["payTo"] = json!("02".repeat(32))), "lottery_terms"),
            (Box::new(|v| v["extra"]["winMsat"] = json!("-1")), "lottery_terms"),
            (Box::new(|v| v["extra"]["minWinMsat"] = json!("64001")), "lottery_terms"),
            (Box::new(|v| v["extra"]["minWinMsat"] = json!("0")), "lottery_terms"),
            (Box::new(|v| v["extra"]["window"] = json!(0)), "lottery_terms"),
            (Box::new(|v| v["extra"]["window"] = json!("8")), "lottery_terms"),
            (Box::new(|v| v["extra"]["maxUnpaidWins"] = json!(0)), "lottery_terms"),
            (Box::new(|v| v["extra"]["chainDraws"] = json!(1_048_577)), "lottery_terms"),
            (Box::new(|v| v["extra"]["pieceBytes"] = json!("0")), "lottery_terms"),
            (Box::new(|v| v["extra"]["release"] = json!("with-request")), "lottery_terms"),
            (Box::new(|v| v["extra"]["receiptKey"] = json!("zz")), "lottery_terms"),
            (Box::new(|v| v["extra"]["session"] = json!("x402/lottery")), "lottery_terms"),
            (Box::new(|v| v["extra"]["price"]["requestMsat"] = json!("101")), "lottery_terms"),
            (Box::new(|v| { v["extra"].as_object_mut().unwrap().remove("gracePieces"); }), "lottery_terms"),
        ];
        for (i, (edit, rule)) in bad.iter().enumerate() {
            let mut a = accepts(json!({"requestMsat": "100"}));
            edit(&mut a);
            assert_eq!(DrawTerms::parse(&a, NET).unwrap_err().0, *rule, "{i}");
        }
    }

    #[test]
    fn a_later_402_is_the_same_seller_whatever_its_route_costs() {
        let a = terms(json!({"requestMsat": "100"}));
        assert!(a.same_seller(&terms(json!({"requestMsat": "2500"}))));
        let mut other = accepts(json!({"requestMsat": "100"}));
        other["extra"]["winMsat"] = json!("32000");
        assert!(!a.same_seller(&DrawTerms::parse(&other, NET).unwrap()));
    }

    #[test]
    fn a_win_is_a_sixteenth_of_what_the_call_may_use_inside_the_owners_bounds() {
        let pol = LotteryPolicy::default();
        // a download priced at a tenth of a sat a piece, through a routing node
        let t = terms(json!({"requestMsat": "0", "byteMsat": "100", "perBytes": "262144"}));
        // the call may use 1,638 sat: a sixteenth is 102 sat, inside 64 (the terms' largest): 64
        assert_eq!(win_size(&t, &pol, true, 1_638_000, false), Ok(64_000));
        // a small call: a sixteenth of 320 sat is 20 sat, below the routed floor of 64 sat
        assert_eq!(win_size(&t, &pol, true, 320_000, false), Ok(64_000));
        // over a direct channel there is no hop to pay: the floor is the seller's 16 sat
        assert_eq!(win_size(&t, &pol, true, 320_000, true), Ok(20_000));
        assert_eq!(win_size(&t, &pol, true, 100_000, true), Ok(16_000));
        // a seller whose largest win is below the routed floor is not paid by draws through a hop
        let mut small = accepts(json!({"requestMsat": "100"}));
        small["extra"]["winMsat"] = json!("32000");
        let small = DrawTerms::parse(&small, NET).unwrap();
        assert_eq!(win_size(&small, &pol, true, 1_000_000, false).unwrap_err().0, "lottery_win_size");
        assert_eq!(win_size(&small, &pol, true, 1_000_000, true), Ok(32_000));
        // the owner's cap for a seller it has not named
        let mut big = accepts(json!({"requestMsat": "100"}));
        big["extra"]["winMsat"] = json!("1000000");
        let big = DrawTerms::parse(&big, NET).unwrap();
        assert_eq!(win_size(&big, &pol, false, 100_000_000, false), Ok(250_000));
        assert_eq!(win_size(&big, &pol, true, 100_000_000, false), Ok(1_000_000));
        assert_eq!(win_size(&big, &pol, true, 8_000_000, false), Ok(500_000));
        // a size is whole sats
        assert_eq!(win_size(&big, &pol, true, 1_999_999, false), Ok(124_000));
        // the owner's smallest win
        let tight = LotteryPolicy { min_win_sats: 300, ..pol.clone() };
        assert_eq!(win_size(&big, &tight, false, 1_000_000, false).unwrap_err().0, "lottery_win_size");
        assert_eq!(win_size(&big, &tight, true, 1_000_000, false), Ok(300_000));
    }

    #[test]
    fn no_piece_wins_more_often_than_the_owner_allows() {
        let pol = LotteryPolicy::default();
        // a page of 2.5 sat: at 1 in 4 the win is at least 10 sat, and the routed floor is above that
        assert_eq!(win_size(&terms(json!({"requestMsat": "2500"})), &pol, true, 0, false), Ok(64_000));
        // a page of 16 sat on a 64-sat win is exactly 1 in 4
        assert_eq!(win_size(&terms(json!({"requestMsat": "16000"})), &pol, true, 0, false), Ok(64_000));
        // a page of 17 sat would win more than one time in four on the seller's largest win: tickets
        let (rule, why) = win_size(&terms(json!({"requestMsat": "16001"})), &pol, true, 0, false).unwrap_err();
        assert!(rule == "lottery_win_size" && why.contains("paid with tickets"), "{why}");
        // a film's piece of 50 sat, a second of 20 sat: the same
        assert!(win_size(&terms(json!({"requestMsat": "0", "byteMsat": "200000", "perBytes": "1048576"})), &pol, true, 0, false).is_err());
        assert!(win_size(&terms(json!({"requestMsat": "0", "secondMsat": "20000"})), &pol, true, 0, false).is_err());
        // an owner who allows 1 in 2
        let loose = LotteryPolicy { max_odds_den: 2, ..pol.clone() };
        assert_eq!(win_size(&terms(json!({"requestMsat": "32000"})), &loose, true, 0, false), Ok(64_000));
        // a price that does not fit is no price
        assert!(win_size(&terms(json!({"requestMsat": "0", "byteMsat": "18446744073709551615", "perBytes": "1"})), &pol, true, 0, false).is_err());
    }

    #[test]
    fn tickets_for_a_piece_worth_one_and_for_a_seller_one_stays_with_draws_for_the_rest() {
        let base = Choice { ticket_entry: true, lottery_entry: true, lottery_on: true, meter: Meter::Auto, open: None, dearest_msat: 100, ticket_msat: 1_000_000,
                            expect_msat: 1_638_000, held_fits: true, stay_tickets: 4, prepaid_entry: false, win_msat: 64_000, min_wins: 4 };
        // a download worth less than two tickets: draws
        assert!(choose(&base));
        // a call expected to draw fewer than 4 wins of 64 sat (255 sat or less): a prepaid ticket, where the seller offers them
        assert!(!choose(&Choice { expect_msat: 255_999, prepaid_entry: true, ..base }));
        assert!(choose(&Choice { expect_msat: 256_000, prepaid_entry: true, ..base }));
        assert!(choose(&Choice { expect_msat: 255_999, ..base }), "no prepaid tickets: draws");
        assert!(choose(&Choice { expect_msat: 255_999, prepaid_entry: true, min_wins: 0, ..base }), "the owner turned the rule off");
        assert!(choose(&Choice { expect_msat: 1_000, prepaid_entry: true, open: Some(true), ..base }), "an open session keeps its way");
        // a piece worth a ticket or more
        assert!(!choose(&Choice { dearest_msat: 1_000_000, ..base }));
        assert!(choose(&Choice { dearest_msat: 999_999, ..base }));
        // a seller the buyer stays with (four tickets' worth or more), when a held ticket fits
        assert!(!choose(&Choice { expect_msat: 4_000_000, ..base }));
        assert!(choose(&Choice { expect_msat: 3_999_999, ..base }));
        // more sellers than held tickets allow: draws, however much the call may use
        assert!(choose(&Choice { expect_msat: 4_000_000, held_fits: false, ..base }));
        // what the seller offers, what the owner turned off, what the task says
        assert!(!choose(&Choice { lottery_entry: false, ..base }));
        assert!(choose(&Choice { ticket_entry: false, expect_msat: 400_000_000, ..base }));
        assert!(!choose(&Choice { lottery_on: false, ..base }));
        assert!(!choose(&Choice { meter: Meter::Tickets, ..base }));
        assert!(choose(&Choice { meter: Meter::Draws, expect_msat: 400_000_000, ..base }));
        assert!(!choose(&Choice { meter: Meter::Draws, lottery_on: false, ..base }), "the owner's switch is above a task's word");
        // an open session keeps its way
        assert!(!choose(&Choice { open: Some(false), ..base }));
        assert!(choose(&Choice { open: Some(true), expect_msat: 400_000_000, ..base }));
    }

    #[test]
    fn the_policy_reads_missing_as_the_default_and_wrong_as_zero() {
        let d = LotteryPolicy::default();
        assert_eq!(LotteryPolicy::from_map(None), d);
        assert_eq!(LotteryPolicy::from_map(json!({}).as_object()), d);
        assert!(d.enabled && (d.max_win_sats, d.unlisted_max_win_sats, d.min_win_sats, d.max_odds_den, d.expected_wins) == (1_000, 250, 16, 4, 16));
        assert_eq!((d.luck_tenths, d.ahead, d.unlisted_max_wins, d.routed_floor_sats, d.direct_floor_sats, d.stay_tickets), (31, 8, 32, 64, 4, 4));
        let p = LotteryPolicy::from_map(json!({"enabled": false, "max_win_sats": 64, "max_odds_den": "four", "ahead": -1}).as_object());
        assert_eq!((p.enabled, p.max_win_sats, p.max_odds_den, p.ahead), (false, 64, 0, 0), "a wrong number refuses, it does not widen");
        assert_eq!((d.max_win_msat(true), d.max_win_msat(false)), (1_000_000, 250_000));
        assert_eq!(LotteryPolicy { unlisted_max_win_sats: 5_000, ..d.clone() }.max_win_msat(false), 1_000_000, "never above the cap for a named seller");
        let (mut errors, mut warnings) = (vec![], vec![]);
        validate(&json!({"max_odds_den": 1, "ahead": 0, "min_win_sats": 2000, "routed_floor_sats": 4, "speling": 1, "luck_tenths": "x"}), &mut errors, &mut warnings);
        assert_eq!((errors.len(), warnings.len()), (3, 3), "{errors:?} {warnings:?}");
        assert_eq!((Meter::parse(None), Meter::parse(Some(&json!("auto"))), Meter::parse(Some(&json!("draws"))), Meter::parse(Some(&json!("tickets"))),
                    Meter::parse(Some(&json!("drawz"))), Meter::parse(Some(&json!(1)))),
                   (Meter::Auto, Meter::Auto, Meter::Draws, Meter::Tickets, Meter::Tickets, Meter::Tickets));
    }
}
