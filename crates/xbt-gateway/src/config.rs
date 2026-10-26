//! The runner's one config file (JSON): where to listen, the service behind the gateway, the node,
//! the ticket terms, the caps, and a price per route. Every key is known or the file is refused: a
//! misspelled cap must not silently be the default.
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Map, Value};
use xbt402::ticket::{
    held_budget, DEFAULT_CHANNEL_SLOTS, HOLD_EXPIRY_DELTA, MAX_CHANNEL_SLOTS, MIN_HELD_TICKET_MSAT,
    MIN_TICKET_BLOCKS, SESSION_PATH, SETTLE_CHAIN_BLOCKS, SETTLE_MARGIN_BLOCKS, SETTLE_ON_ARRIVAL,
    SETTLE_ON_USE,
};

use crate::book::Caps;
use crate::lottery::LotteryConfig;
use crate::price::{Price, TokenRule};
use crate::Error;

/// What `mainnet_ack` must say, word for word, before a config with `chain: "main"` is taken (the
/// same words a wallet's policy says for its side).
pub use xbt402::ticket::MAINNET_ACK;

/// What a gateway prints when it starts on mainnet: the things its runner should know before a
/// buyer does. A short fixed text; the whole of it, with the measurements, is `docs/LIMITS.md`.
pub const MAINNET_NOTICE: [&str; 9] = [
    "chain main: this gateway has run on regtest only. Before you rely on it, read docs/LIMITS.md. In short:",
    "- A held ticket of 1,000 sat can be below a channel's dust limit at mainnet fee rates on a channel without anchors: it then has no output there, and is lost to the miners if that channel is force-closed while it is held. The gateway does not read its channels' dust limits.",
    "- Claiming settled tickets on chain after a force close cost 900 to 1,700 sat for three tickets at 1 sat/vB; at higher fee rates one ticket costs more to claim than it is worth.",
    "- Held tickets take pending-payment slots of every channel on their route for no fee, on your node and on the routing nodes before it. Nothing but this software keeps buyers to half of a channel's slots.",
    "- A session's first ticket is a prepaid one (caps.held_after_paid), so a hold invoice costs whoever asks for it one paid ticket; but a first lock still costs nothing, and whoever reaches the gateway from enough addresses can take every session place with prepaid invoices it never pays, for 20 s at a time (caps.first_lock_secs).",
    "- With a lottery section you serve first, and nothing makes a buyer pay a win.",
    "- The gateway speaks an lnd-family node's REST interface and no other; a Core Lightning seller is not supported.",
    "- The gateway speaks plain HTTP: buyers must reach it through a TLS proxy, with public_url set to the https origin they use.",
    "- A buyer's unused balance is trusted to you, and a lost state directory loses every session, key and balance.",
];

const NEEDS_NETWORK: &str = "a chain other than main needs network: \"bip122:<32 hex of its bip122 id>\" (chain is \"regtest\" where the file names none)";

/// The node adds this many blocks to a ticket's final CLTV delta when it pays.
pub const PAYER_PAD_BLOCKS: u32 = 3;
/// The most held tickets any config may allow: each has a thread and a connection to the node.
pub const MAX_HELD: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// The secret comes with the request: the buyer risks one ticket, the seller nothing.
    WithRequest,
    /// A checkable route: a piece is served on a pledged ticket and its secret follows. The seller
    /// risks up to one ticket per session.
    AfterVerify,
}

impl Release {
    pub fn name(self) -> &'static str {
        match self {
            Self::WithRequest => "with-request",
            Self::AfterVerify => "after-verify",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// A path ending in `/` covers everything under it; any other path is that path alone.
    pub path: String,
    /// Upper case.
    pub methods: Vec<String>,
    /// Served without payment.
    pub free: bool,
    pub price: Price,
    pub release: Release,
    /// Request headers passed to the service beside [`ALWAYS_FORWARDED`], lower case.
    pub forward_headers: Vec<String>,
    /// The largest request body passed on.
    pub max_body: usize,
    /// The service this route's requests go to, when not the config's `upstream`: one gateway
    /// can sell several services, each behind a path of its own.
    pub upstream: Option<String>,
    /// Pass the target on without this route's path (a route `/ai/` sends `/ai/v1/x` as `/v1/x`).
    pub strip_prefix: bool,
}

/// Request headers every route passes on: they select what is returned and carry no authority.
pub const ALWAYS_FORWARDED: [&str; 7] = [
    "accept",
    "accept-language",
    "content-type",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "range",
];

/// Request headers no route passes on, whatever the file says: the gateway's own, the payment, and
/// the ones a proxy must not relay.
pub const NEVER_FORWARDED: [&str; 17] = [
    "accept-encoding",
    "connection",
    "content-length",
    "expect",
    "forwarded",
    "host",
    "keep-alive",
    "payment-signature",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
    "x-forwarded-for",
    "x-forwarded-proto",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub rest: String,
    pub tls_cert: Option<PathBuf>,
    /// `invoices:read` and `invoices:write`.
    pub macaroon: PathBuf,
    /// `info:read`: the block height.
    pub info_macaroon: PathBuf,
    /// `offchain:read`, optional: with it the gateway reads its node's channels and sizes the cap
    /// on held tickets itself. Not the default: the permission also shows the node's balances,
    /// its payments and what it forwarded.
    pub channels_macaroon: Option<PathBuf>,
    /// How many blocks before a held ticket's expiry the node cancels it (lnd's
    /// `invoices.holdexpirydelta`): the runner's word, [`HOLD_EXPIRY_DELTA`] unless it says
    /// otherwise. The node does not tell it, and the margin rests on it.
    pub hold_expiry_delta: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: String,
    /// The origin buyers reach the gateway under (`https://seller.example`): what a payment binds.
    pub public_url: String,
    /// The service: `http://host:port`, optionally with a path prefix. `None` when every route
    /// names its own.
    pub upstream: Option<String>,
    pub state_dir: PathBuf,
    /// `regtest` unless the file says otherwise. Another test chain's name with `network` given,
    /// or `main`, which also needs `mainnet_ack` ([`MAINNET_ACK`]).
    pub chain: String,
    /// `lightning:<32 hex>`.
    pub network: String,
    pub node: NodeConfig,
    pub ticket_blocks: u32,
    /// The terms offer held tickets (`settle: "on-use"`), tickets settled on arrival
    /// (`settle: "on-arrival"`), or both: at least one.
    pub held: bool,
    pub prepaid: bool,
    /// The pending payments the seller's smallest inbound channel carries: the runner's word, or
    /// the default of 30. Held tickets take at most half of it unless the runner said more.
    pub inbound_slots: u32,
    /// The runner wrote `caps.max_held_tickets`: a gateway that reads its channels keeps to it.
    pub held_set: bool,
    pub caps: Caps,
    /// The lottery (`docs/TICKETS.md`, section 9), where the runner offers it: pieces priced below
    /// one win, paid by draws, with nothing held. Absent: not offered.
    pub lottery: Option<LotteryConfig>,
    /// Payment by BOLT 12 offer for prepaid tickets and lottery wins (`docs/TICKETS.md`, section
    /// 15), where the runner turns it on. Absent: no offer is made or named in the terms.
    pub offers: Option<OffersConfig>,
    pub routes: Vec<Route>,
    pub http: Http,
    /// Off unless the runner writes it: whose word the caps per address take for a buyer's address.
    pub forwarded: Option<Forwarded>,
    pub times: Times,
    /// The signed catalog (`docs/LISTINGS.md`). Absent: the well-known URL answers 404.
    pub listing: Option<xbt402::listing::Draft>,
    /// Publishing the listing on Nostr (`docs/NOSTR.md`). Absent: nothing is published.
    pub nostr: Option<NostrConfig>,
}

/// The `nostr` section: the relays the listing goes to, and how often it is sent again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrConfig {
    pub relays: Vec<String>,
    /// Off unless the runner writes `true`: a listing is public the moment a relay has it.
    pub publish: bool,
    /// Relays drop old events, and a relay that was down missed the last one.
    pub republish: Duration,
}

/// At most this many relays.
pub const MAX_NOSTR_RELAYS: usize = 10;

impl NostrConfig {
    fn parse(v: &Value) -> Result<Self, String> {
        let m = obj(v, "nostr", &["relays", "publish", "republish_s"])?;
        let relays = match m.get("relays") {
            None => Vec::new(),
            Some(Value::Array(a)) => a
                .iter()
                .map(|r| {
                    let r = r.as_str().ok_or("nostr.relays is a list of wss:// URLs")?;
                    xbt_nostr::ws::parse_url(r).map_err(|e| format!("nostr.relays {r}: {e}"))?;
                    Ok(r.to_string())
                })
                .collect::<Result<Vec<_>, String>>()?,
            Some(_) => return Err("nostr.relays is a list of wss:// URLs".into()),
        };
        if relays.len() > MAX_NOSTR_RELAYS {
            return Err(format!("nostr.relays: at most {MAX_NOSTR_RELAYS}"));
        }
        let publish = match m.get("publish") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err("nostr.publish is true or false".into()),
        };
        if publish && relays.is_empty() {
            return Err("nostr.publish needs at least one relay in nostr.relays".into());
        }
        let secs = num(m, "republish_s", 6 * 3600)?;
        if !(600..=7 * 86_400).contains(&secs) {
            return Err("nostr.republish_s is from 600 (ten minutes) to 604800 (a week)".into());
        }
        Ok(Self { relays, publish, republish: Duration::from_secs(secs) })
    }
}

/// The runner's `offers` section: the gateway makes one BOLT 12 offer on its node at the start, with
/// no amount (each invoice names its own), and names it in its prepaid and lottery terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffersConfig {
    /// The offer's description, shown to whoever pays it.
    pub description: String,
}

/// A reverse proxy in front of the gateway, and the header in which it reports the address it
/// took each request from (`http.forwarded_address`). Absent: the caps per address count the
/// socket's address, which behind a proxy is the proxy's for every buyer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarded {
    /// The header's name, lower case.
    pub header: String,
    /// The addresses the proxy connects from. The header is read on connections from these only.
    pub proxies: Vec<std::net::IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http {
    pub connections: usize,
    pub per_address: usize,
    pub threads: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Times {
    /// A metered response with no balance left waits this long for a release, then ends.
    pub refill_wait: Duration,
    /// The service must start its answer, and then keep sending, within this.
    pub upstream_wait: Duration,
    /// A block height older than this is not a height.
    pub height_max_age: Duration,
    /// The longest one response may stay open.
    pub max_response: Duration,
    /// How often the janitor runs: the height, the sweep, the journal's sync.
    pub tick: Duration,
}

impl Config {
    pub fn mainnet(&self) -> bool {
        self.chain == "main"
    }

    /// What is printed at a start on mainnet ([`MAINNET_NOTICE`]); nothing on any other chain.
    pub fn mainnet_notice(&self) -> &'static [&'static str] {
        if self.mainnet() {
            &MAINNET_NOTICE
        } else {
            &[]
        }
    }

    /// The route for a decoded path: the longest matching one.
    pub fn route(&self, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|r| {
                if r.path.ends_with('/') {
                    path.starts_with(&r.path)
                } else {
                    path == r.path
                }
            })
            .max_by_key(|r| r.path.len())
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        Self::from_json(&v)
    }

    pub fn from_json(v: &Value) -> Result<Self, Error> {
        Self::parse(v).map_err(Error::Config)
    }

    fn parse(v: &Value) -> Result<Self, String> {
        let top = obj(
            v,
            "the config",
            &[
                "listen",
                "public_url",
                "upstream",
                "state_dir",
                "chain",
                "mainnet_ack",
                "network",
                "node",
                "tickets",
                "lottery",
                "offers",
                "caps",
                "routes",
                "http",
                "times",
                "listing",
                "nostr",
            ],
        )?;
        // a file that names no chain is a regtest file: mainnet is never what a missing key means
        let chain = opt_str(top, "chain")?.unwrap_or("regtest").to_string();
        match (chain.as_str(), opt_str(top, "mainnet_ack")?) {
            ("main", Some(MAINNET_ACK)) => {}
            ("main", _) => return Err(format!(
                "chain \"main\" moves real funds through software that has run on regtest only (docs/LIMITS.md). To run it on mainnet all the same, add \"mainnet_ack\": \"{MAINNET_ACK}\""
            )),
            (_, Some(_)) => return Err("mainnet_ack is for chain \"main\" only: leave it out".into()),
            (_, None) => {}
        }
        let network = match (chain.as_str(), opt_str(top, "network")?) {
            ("main", None) => xbt402::ticket::network_id(xbt_primitives::network::XBT_MAINNET)
                .ok_or("no mainnet network id")?,
            ("main", Some(_)) => return Err("network is fixed on chain main: leave it out".into()),
            // the chain's CAIP-2 id; the name of before 2026-10, `lightning:` and the same 32 hex, is read for one
            // release and written the new way
            (_, Some(n)) => match xbt402::ticket::network_id(&n.replacen("lightning:", "bip122:", 1)) {
                Some(id) if n.starts_with("bip122:") || n.starts_with("lightning:") => id,
                _ => return Err(NEEDS_NETWORK.into()),
            },
            (_, None) => return Err(NEEDS_NETWORK.into()),
        };
        let public_url = req_str(top, "public_url")?
            .trim_end_matches('/')
            .to_string();
        let origin =
            xbt402::wire::sendable_url(&public_url).map_err(|e| format!("public_url: {e}"))?;
        if xbt402::wire::request_url(&origin).target != "/" {
            return Err("public_url is an origin (scheme://host[:port]), without a path".into());
        }
        // the gateway speaks plain HTTP. On a loopback address that is the machine's own business;
        // on any other, session keys and paid answers would cross a network in the clear unless a
        // TLS proxy stands in front, and public_url is what says one does
        let listen = req_str(top, "listen")?.to_string();
        let loopback = listen
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|a| a.ip().is_loopback());
        if !loopback && !origin.starts_with("https://") {
            return Err(format!("listen {listen} is not a loopback address (an address written as one: a name, even localhost, is whatever the resolver says), and public_url is not https. The gateway speaks plain HTTP: listen on 127.0.0.1 or [::1], or put a TLS proxy in front and set public_url to the https origin buyers use"));
        }
        let up = opt_str(top, "upstream")?.map(|u| upstream_url(u, "upstream")).transpose()?;

        let n = obj(
            top.get("node").ok_or("node is missing")?,
            "node",
            &[
                "rest",
                "tls_cert",
                "macaroon",
                "info_macaroon",
                "channels_macaroon",
                "hold_expiry_delta",
            ],
        )?;
        let node = NodeConfig {
            rest: req_str(n, "rest")?.to_string(),
            tls_cert: opt_str(n, "tls_cert")?.map(PathBuf::from),
            macaroon: PathBuf::from(req_str(n, "macaroon")?),
            info_macaroon: PathBuf::from(req_str(n, "info_macaroon")?),
            channels_macaroon: opt_str(n, "channels_macaroon")?.map(PathBuf::from),
            hold_expiry_delta: num32(n, "hold_expiry_delta", HOLD_EXPIRY_DELTA)?,
        };
        // the margin is one number for both sides (a buyer stops releasing a ticket a block before
        // it), so it is not moved to fit a node: a node that cancels held tickets earlier than the
        // margin allows for leaves no time for a settle that has to go on chain, and is refused
        if node.hold_expiry_delta + SETTLE_CHAIN_BLOCKS > SETTLE_MARGIN_BLOCKS {
            return Err(format!(
                "node.hold_expiry_delta {}: the gateway takes a ticket's secret only while more than {SETTLE_MARGIN_BLOCKS} blocks are left, and keeps {SETTLE_CHAIN_BLOCKS} of them for a settle that has to go on chain. A node that cancels held tickets more than {} blocks before expiry leaves too few: set its invoices.holdexpirydelta to {} or less",
                node.hold_expiry_delta,
                SETTLE_MARGIN_BLOCKS - SETTLE_CHAIN_BLOCKS,
                SETTLE_MARGIN_BLOCKS - SETTLE_CHAIN_BLOCKS
            ));
        }

        let empty = Map::new();
        let t = match top.get("tickets") {
            Some(t) => obj(
                t,
                "tickets",
                &["ticket_msat", "max_tickets", "ticket_blocks", "settle"],
            )?,
            None => &empty,
        };
        let ticket_msat = num(t, "ticket_msat", 1_000_000)?;
        let max_tickets = num32(t, "max_tickets", 2)?;
        let ticket_blocks = num32(t, "ticket_blocks", 40)?;
        // held tickets are the default way; tickets settled on arrival are offered beside them
        let (held, prepaid) = match t.get("settle") {
            None => (true, true),
            Some(Value::Array(a)) if !a.is_empty() => {
                let has = |w: &str| a.iter().any(|x| x.as_str() == Some(w));
                let known = a
                    .iter()
                    .all(|x| matches!(x.as_str(), Some(SETTLE_ON_USE | SETTLE_ON_ARRIVAL)));
                if !known || a.len() != usize::from(has(SETTLE_ON_USE)) + usize::from(has(SETTLE_ON_ARRIVAL)) {
                    return Err(format!("tickets.settle is a list of \"{SETTLE_ON_USE}\" (held tickets) and \"{SETTLE_ON_ARRIVAL}\" (prepaid tickets), each at most once"));
                }
                (has(SETTLE_ON_USE), has(SETTLE_ON_ARRIVAL))
            }
            Some(_) => {
                return Err(format!("tickets.settle is a list of \"{SETTLE_ON_USE}\" (held tickets) and \"{SETTLE_ON_ARRIVAL}\" (prepaid tickets), with at least one"))
            }
        };
        if !(1000..=100_000_000_000).contains(&ticket_msat) {
            return Err("tickets.ticket_msat is from 1000 (a node takes nothing below 1 sat) to 100000000000".into());
        }
        if held && ticket_msat < MIN_HELD_TICKET_MSAT {
            return Err(format!("tickets.ticket_msat is at least {MIN_HELD_TICKET_MSAT} (546 sat) where held tickets are offered: a held payment below a channel's dust limit has no output in that channel's transaction, and is lost to the miners if the channel is force-closed while it is held. For smaller tickets offer only prepaid ones: tickets.settle [\"{SETTLE_ON_ARRIVAL}\"]"));
        }
        // usable blocks: the delta, plus what the payer's node adds, less the margin
        let floor = (SETTLE_MARGIN_BLOCKS + 2)
            .saturating_sub(PAYER_PAD_BLOCKS)
            .max(MIN_TICKET_BLOCKS + 1);
        if !(floor..=2016).contains(&ticket_blocks) {
            return Err(format!("tickets.ticket_blocks is from {floor} to 2016: a ticket is used only while more than {SETTLE_MARGIN_BLOCKS} blocks are left"));
        }

        let c = match top.get("caps") {
            Some(c) => obj(
                c,
                "caps",
                &[
                    "max_sessions",
                    "sessions_per_address",
                    "max_kept_sessions",
                    "max_held_tickets",
                    "inbound_slots",
                    "held_over_half",
                    "slots_retry_secs",
                    "unpaid_secs",
                    "first_lock_secs",
                    "unpaid_per_address",
                    "held_after_paid",
                    "first_use_secs",
                    "idle_secs",
                    "keep_secs",
                ],
            )?,
            None => &empty,
        };
        let max_sessions = num32(c, "max_sessions", 30)?;
        if max_sessions == 0 {
            return Err("caps.max_sessions is at least 1".into());
        }
        // a held ticket takes one of the pending payments ("slots") of the channel it arrives on, and
        // a channel has between 30 (Core Lightning's default) and 483 of them, for everyone who pays
        // over it. The buyer's node chooses the channel, so the seller's own cap is the only bound
        let inbound_slots = num32(c, "inbound_slots", DEFAULT_CHANNEL_SLOTS)?;
        if !(2..=MAX_CHANNEL_SLOTS).contains(&inbound_slots) {
            return Err(format!("caps.inbound_slots is from 2 to {MAX_CHANNEL_SLOTS}: the pending payments the smallest inbound channel of the node carries (30 on a channel with a Core Lightning node, which is the default here)"));
        }
        let half = held_budget(inbound_slots);
        let over_half = match c.get("held_over_half") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err("caps.held_over_half is true or false".into()),
        };
        let held_set = c.contains_key("max_held_tickets");
        let max_held = num32(c, "max_held_tickets", half)?;
        if max_held == 0 {
            return Err("caps.max_held_tickets is at least 1".into());
        }
        if max_held > half && !over_half {
            return Err(format!(
                "caps.max_held_tickets {max_held} is more than half of caps.inbound_slots ({inbound_slots}): held tickets beyond half of a channel's pending payments leave no room for ordinary payments, and a full channel can be paid by nobody. Raise caps.inbound_slots if every inbound channel carries more, or say \"held_over_half\": true for a node with several inbound channels"
            ));
        }
        if max_held > MAX_HELD {
            return Err(format!(
                "caps.max_held_tickets is at most {MAX_HELD}: the gateway follows each held ticket on its own connection to the node"
            ));
        }
        let most = if held { max_held } else { MAX_CHANNEL_SLOTS };
        if !(1..=most).contains(&max_tickets) {
            return Err(format!("tickets.max_tickets is from 1 to {most}: one session holds no more than caps.max_held_tickets allows for all of them"));
        }
        let slots_retry_secs = num(c, "slots_retry_secs", 30)?;
        if !(1..=3600).contains(&slots_retry_secs) {
            return Err("caps.slots_retry_secs is from 1 to 3600".into());
        }
        ticket_msat
            .checked_mul(u64::from(max_held))
            .ok_or("the cap on held funds does not fit")?;
        // hold invoices only to a session that has paid something: on wherever prepaid tickets are offered
        // beside held ones, since a first ticket has to be had some way
        let held_after_paid = match c.get("held_after_paid") {
            None => held && prepaid,
            Some(Value::Bool(true)) if !(held && prepaid) => {
                return Err(format!("caps.held_after_paid needs tickets.settle to offer both \"{SETTLE_ON_USE}\" and \"{SETTLE_ON_ARRIVAL}\": a session's first ticket is a prepaid one"))
            }
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err("caps.held_after_paid is true or false".into()),
        };
        let first_lock_secs = num(c, "first_lock_secs", 20)?;
        if !(5..=u64::from(xbt402::ticket::INVOICE_EXPIRY_S)).contains(&first_lock_secs) {
            return Err(format!("caps.first_lock_secs is from 5 to {}: how long the invoices of a session's first lock stay payable", xbt402::ticket::INVOICE_EXPIRY_S));
        }
        let caps = Caps {
            ticket_msat,
            max_tickets,
            max_sessions,
            sessions_per_address: num32(c, "sessions_per_address", 2)?,
            max_kept_sessions: num32(c, "max_kept_sessions", 10_000)?.max(max_sessions),
            max_held,
            slots_retry_secs,
            margin_blocks: SETTLE_MARGIN_BLOCKS,
            unpaid_secs: num(c, "unpaid_secs", 75)?,
            first_lock_secs,
            unpaid_per_address: num32(c, "unpaid_per_address", 2)?,
            held_after_paid,
            first_use_secs: num(c, "first_use_secs", 60)?,
            idle_secs: num(c, "idle_secs", 300)?,
            keep_secs: num(c, "keep_secs", 86_400)?,
        };
        if caps.unpaid_secs < u64::from(xbt402::ticket::INVOICE_EXPIRY_S) {
            return Err(format!(
                "caps.unpaid_secs is at least the invoice's own {} seconds",
                xbt402::ticket::INVOICE_EXPIRY_S
            ));
        }

        let h = match top.get("http") {
            Some(h) => obj(h, "http", &["connections", "per_address", "threads", "forwarded_address"])?,
            None => &empty,
        };
        // bounded before they become sizes: each is a number of threads
        let small = |k: &str, default: u64, least: u64| match num(h, k, default)? {
            n if (least..=4096).contains(&n) => {
                usize::try_from(n).map_err(|_| format!("http.{k} is too large"))
            }
            _ => Err(format!("http.{k} is from {least} to 4096")),
        };
        let http = Http {
            connections: small("connections", 64, 1)?,
            per_address: small("per_address", 48, 0)?,
            threads: small("threads", 16, 1)?,
        };

        let forwarded = match h.get("forwarded_address") {
            None | Some(Value::Null) => None,
            Some(f) => {
                let f = obj(f, "http.forwarded_address", &["header", "proxies"])?;
                let header = req_str(f, "header")?.to_ascii_lowercase();
                if !header.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
                    return Err("http.forwarded_address.header is a header name".into());
                }
                let bad = "http.forwarded_address.proxies is a list of the addresses your reverse proxy connects from, at least one, each written as an address: the header is believed from these and from nobody else";
                let mut proxies = vec![];
                for p in f.get("proxies").and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or(bad)? {
                    proxies.push(p.as_str().and_then(|a| a.parse::<std::net::IpAddr>().ok()).ok_or(bad)?.to_canonical());
                }
                Some(Forwarded { header, proxies })
            }
        };
        let tm = match top.get("times") {
            Some(t) => obj(
                t,
                "times",
                &[
                    "refill_wait_ms",
                    "upstream_wait_secs",
                    "height_max_age_secs",
                    "max_response_secs",
                    "tick_ms",
                ],
            )?,
            None => &empty,
        };
        let times = Times {
            // 15 s: a proxy in front of the gateway (a TLS proxy, a CDN) can hold a paused answer's tail,
            // and the buyer pays for the next ticket only once it has read nearly all it paid for
            refill_wait: Duration::from_millis(num(tm, "refill_wait_ms", 15_000)?),
            upstream_wait: Duration::from_secs(num(tm, "upstream_wait_secs", 10)?.max(1)),
            height_max_age: Duration::from_secs(num(tm, "height_max_age_secs", 10)?.max(1)),
            max_response: Duration::from_secs(num(tm, "max_response_secs", 21_600)?.max(1)),
            tick: Duration::from_millis(num(tm, "tick_ms", 500)?.clamp(10, 5000)),
        };

        let mut routes = vec![];
        for r in top
            .get("routes")
            .and_then(Value::as_array)
            .ok_or("routes is a list, and may not be missing: a path with no route is not served")?
        {
            routes.push(route(r)?);
        }
        for (i, r) in routes.iter().enumerate() {
            if r.upstream.is_none() && up.is_none() {
                return Err(format!("route {}: no upstream, and the config names none for every route", r.path));
            }
            if routes[..i].iter().any(|o| o.path == r.path) {
                return Err(format!("route {}: named twice", r.path));
            }
            if r.path == SESSION_PATH
                || r.path.starts_with(&format!("{SESSION_PATH}/"))
                || r.path == SERVICES_PATH
                || r.path == LISTING_PATH
            {
                return Err(format!("route {}: that path is the gateway's own", r.path));
            }
            let lottery_path = xbt402::lottery::SESSION_PATH;
            if r.path == lottery_path || r.path.starts_with(&format!("{lottery_path}/")) {
                return Err(format!("route {}: that path is the gateway's own", r.path));
            }
            if r.release == Release::AfterVerify && r.price.request_msat > ticket_msat {
                return Err(format!(
                    "route {}: a piece served before its secret costs at most one ticket",
                    r.path
                ));
            }
        }
        // the lottery is offered only by a runner who says so: with it the seller serves first
        let lottery = match top.get("lottery") {
            None | Some(Value::Null) => None,
            Some(l) => Some(LotteryConfig::parse(l, ticket_blocks)?),
        };
        // payment by offer: off unless the runner turns it on, and only beside a way it pays
        let offers = match top.get("offers") {
            None | Some(Value::Null) => None,
            Some(o) => {
                let o = obj(o, "offers", &["enabled", "description"])?;
                let on = match o.get("enabled") {
                    Some(Value::Bool(b)) => *b,
                    _ => return Err("offers.enabled is true or false".into()),
                };
                if on && !prepaid && lottery.is_none() {
                    return Err(format!("offers: an offer pays prepaid tickets and lottery wins, and this config offers neither (tickets.settle has no \"{SETTLE_ON_ARRIVAL}\" and there is no lottery section)"));
                }
                let description = opt_str(o, "description")?.unwrap_or("xbt-gateway").to_string();
                if description.is_empty() || description.len() > 200 || description.chars().any(char::is_control) {
                    return Err("offers.description is 1 to 200 characters, none of them a control character".into());
                }
                on.then_some(OffersConfig { description })
            }
        };
        let listing = match top.get("listing") {
            None | Some(Value::Null) => None,
            Some(l) => Some(listing_draft(l, &routes)?),
        };
        let nostr = match top.get("nostr") {
            None | Some(Value::Null) => None,
            Some(n) => Some(NostrConfig::parse(n)?),
        };
        if nostr.as_ref().is_some_and(|n| n.publish) && listing.is_none() {
            return Err("nostr.publish publishes the listing: write a listing section, or leave publish out".into());
        }
        Ok(Self {
            listen,
            public_url: origin.trim_end_matches('/').to_string(),
            upstream: up,
            state_dir: PathBuf::from(req_str(top, "state_dir")?),
            chain,
            network,
            node,
            ticket_blocks,
            held,
            prepaid,
            inbound_slots,
            held_set,
            caps,
            lottery,
            offers,
            routes,
            http,
            forwarded,
            times,
            listing,
            nostr,
        })
    }
}

/// Where the gateway serves the list of what it sells.
pub const SERVICES_PATH: &str = "/services";
/// The signed listing (`docs/LISTINGS.md`). Free. Absent from the config: 404.
pub const LISTING_PATH: &str = xbt402::listing::PATH;

fn route(v: &Value) -> Result<Route, String> {
    let r = obj(
        v,
        "a route",
        &[
            "path",
            "methods",
            "free",
            "price",
            "release",
            "forward_headers",
            "max_body",
            "upstream",
            "strip_prefix",
            "max_output_tokens",
        ],
    )?;
    let path = req_str(r, "path")?.to_string();
    let plain = path.starts_with('/')
        && !path.contains("//")
        && path
            .bytes()
            .all(|c| c.is_ascii_graphic() && !b"%?#\\".contains(&c))
        && !path.split('/').any(|s| s == "." || s == "..");
    if !plain {
        return Err(format!("route {path:?}: a path starts with /, and has no %, ?, #, backslash, empty or dot segment"));
    }
    let bad = |what: &str| format!("route {path}: {what}");
    let methods = match r.get("methods") {
        None => vec!["GET".to_string(), "HEAD".to_string()],
        Some(Value::Array(a)) if !a.is_empty() => {
            let mut out = vec![];
            for m in a {
                match m.as_str() {
                    Some(m) if ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].contains(&m) => {
                        out.push(m.to_string())
                    }
                    _ => {
                        return Err(bad(
                            "methods are GET, HEAD, POST, PUT, PATCH or DELETE, in upper case",
                        ))
                    }
                }
            }
            out
        }
        _ => return Err(bad("methods is a list with at least one method")),
    };
    let free = match r.get("free") {
        None => false,
        Some(Value::Bool(b)) => *b,
        _ => return Err(bad("free is true or false")),
    };
    let empty = Map::new();
    let p = match r.get("price") {
        Some(p) => obj(
            p,
            "price",
            &["request_msat", "byte_msat", "per_bytes", "second_msat", "per_1k_input_msat", "per_1k_output_msat"],
        )
        .map_err(|e| bad(&e))?,
        None => &empty,
    };
    let tokens = TokenRule {
        input_per_1k_msat: num(p, "per_1k_input_msat", 0)?,
        output_per_1k_msat: num(p, "per_1k_output_msat", 0)?,
        max_output: num(r, "max_output_tokens", xbt402::tokens::DEFAULT_MAX_OUTPUT)?,
    };
    let price = Price {
        request_msat: num(p, "request_msat", 0)?,
        byte_msat: num(p, "byte_msat", 0)?,
        per_bytes: num(p, "per_bytes", 1)?,
        second_msat: num(p, "second_msat", 0)?,
        tokens: if tokens.active() { tokens } else { TokenRule::NONE },
    };
    if price.per_bytes == 0 {
        return Err(bad("price.per_bytes is at least 1"));
    }
    if r.get("max_output_tokens").is_some() && !tokens.active() {
        return Err(bad("max_output_tokens is for a route priced by the token"));
    }
    if tokens.active() {
        if price.byte_msat > 0 || price.second_msat > 0 {
            return Err(bad("a route priced by the token has no price per byte or per second beside it"));
        }
        if !(1..=1_000_000).contains(&tokens.max_output) {
            return Err(bad("max_output_tokens is from 1 to 1000000"));
        }
    }
    if free != price.is_free() {
        return Err(bad("a route has a price, or says \"free\": true, and not both: a price left out by mistake must not serve for nothing"));
    }
    let release = match opt_str(r, "release")? {
        None | Some("with-request") => Release::WithRequest,
        Some("after-verify") => Release::AfterVerify,
        Some(_) => return Err(bad("release is with-request or after-verify")),
    };
    let mut forward_headers = vec![];
    for h in r
        .get("forward_headers")
        .map(|h| h.as_array().ok_or_else(|| bad("forward_headers is a list")))
        .transpose()?
        .into_iter()
        .flatten()
    {
        let name = h
            .as_str()
            .map(str::to_ascii_lowercase)
            .filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
            .ok_or_else(|| bad("forward_headers are header names"))?;
        if NEVER_FORWARDED.contains(&name.as_str()) {
            return Err(bad(&format!("{name} is never passed to the service")));
        }
        forward_headers.push(name);
    }
    let max_body = num(r, "max_body", 0)?;
    if max_body > 64 << 20 {
        return Err(bad(
            "max_body is at most 64 MiB: a request body is read whole before it is passed on",
        ));
    }
    let upstream = opt_str(r, "upstream")?.map(|u| upstream_url(u, &format!("route {path}: upstream"))).transpose()?;
    let strip_prefix = match r.get("strip_prefix") {
        None => false,
        Some(Value::Bool(b)) => *b,
        _ => return Err(bad("strip_prefix is true or false")),
    };
    if strip_prefix && !path.ends_with('/') {
        return Err(bad("strip_prefix is for a path ending in /, which covers everything under it"));
    }
    Ok(Route {
        path,
        methods,
        free,
        price,
        release,
        forward_headers,
        max_body: max_body as usize,
        upstream,
        strip_prefix,
    })
}

/// The config's `listing`. A `listing/1` names a route per service: the route must exist, and a
/// service that names no price is given its route's, so the listing cannot say another price.
fn listing_draft(l: &Value, routes: &[Route]) -> Result<xbt402::listing::Draft, String> {
    let mut l = l.clone();
    if let Some(list) = l.get_mut("services").and_then(Value::as_array_mut) {
        for (i, s) in list.iter_mut().enumerate() {
            let path = s.get("path").and_then(Value::as_str).unwrap_or("").to_string();
            let route = routes.iter().find(|r| r.path == path)
                .ok_or_else(|| format!("listing: service {}: path {path:?} is not one of the routes", i + 1))?;
            if s.get("prices").is_none() {
                if let Some(o) = s.as_object_mut() {
                    o.insert("prices".into(), price_json(&route.price));
                }
            }
        }
    }
    xbt402::listing::parse_draft(&l).map_err(|e| format!("listing: {e}"))
}

/// A route's price as a listing writes it: the rules it sets.
fn price_json(p: &Price) -> Value {
    let mut o = Map::new();
    if p.request_msat > 0 {
        o.insert("request_msat".into(), p.request_msat.into());
    }
    if p.byte_msat > 0 {
        o.insert("byte_msat".into(), p.byte_msat.into());
        o.insert("per_bytes".into(), p.per_bytes.into());
    }
    if p.second_msat > 0 {
        o.insert("second_msat".into(), p.second_msat.into());
    }
    if p.tokens.input_per_1k_msat > 0 {
        o.insert("per_1k_input_msat".into(), p.tokens.input_per_1k_msat.into());
    }
    if p.tokens.output_per_1k_msat > 0 {
        o.insert("per_1k_output_msat".into(), p.tokens.output_per_1k_msat.into());
    }
    if o.is_empty() {
        // a free route: one rule of nothing, which a listing can state
        o.insert("request_msat".into(), 0.into());
    }
    Value::Object(o)
}

/// A service beside the gateway: `http://host[:port][/prefix]`, without the trailing `/`.
fn upstream_url(u: &str, what: &str) -> Result<String, String> {
    let up = xbt402::wire::sendable_url(u.trim_end_matches('/')).map_err(|e| format!("{what}: {e}"))?;
    if !up.starts_with("http://") || up.contains('?') || up.contains('@') {
        return Err(format!("{what} is http://host[:port][/prefix]: plain HTTP to a service beside the gateway, no query, no user name"));
    }
    Ok(up.trim_end_matches('/').to_string())
}

impl Route {
    /// The target as the route's service is sent it.
    pub fn upstream_target(&self, target: &str) -> String {
        if !self.strip_prefix {
            return target.to_string();
        }
        // by segments of the raw target: an escaped `/` is refused before a route is chosen, so the
        // route's segments are the target's first ones however the buyer spelled them
        let n = self.path.trim_matches('/').split('/').filter(|s| !s.is_empty()).count();
        let (path, query) = target.split_once('?').map(|(p, q)| (p, Some(q))).unwrap_or((target, None));
        let rest: Vec<&str> = path.trim_start_matches('/').splitn(n + 1, '/').collect();
        let tail = if rest.len() > n { rest[n] } else { "" };
        let mut out = format!("/{tail}");
        if let Some(q) = query {
            out.push('?');
            out.push_str(q);
        }
        out
    }
}

pub(crate) fn obj<'a>(v: &'a Value, what: &str, known: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let m = v
        .as_object()
        .ok_or_else(|| format!("{what} is an object"))?;
    match m.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => Err(format!(
            "{what}: unknown key {k:?} (known: {})",
            known.join(", ")
        )),
        None => Ok(m),
    }
}

fn req_str<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, String> {
    opt_str(m, k)?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{k} is missing"))
}

fn opt_str<'a>(m: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, String> {
    match m.get(k) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{k} is a string")),
    }
}

/// A whole number, or the default when the key is absent. Anything else is an error, not the default.
pub(crate) fn num(m: &Map<String, Value>, k: &str, default: u64) -> Result<u64, String> {
    match m.get(k) {
        None => Ok(default),
        Some(v) => v.as_u64().ok_or_else(|| format!("{k} is a whole number")),
    }
}

pub(crate) fn num32(m: &Map<String, Value>, k: &str, default: u32) -> Result<u32, String> {
    u32::try_from(num(m, k, u64::from(default))?).map_err(|_| format!("{k} is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn base() -> Value {
        json!({"listen": "127.0.0.1:0", "public_url": "http://127.0.0.1:8402", "upstream": "http://127.0.0.1:8080", "state_dir": "/tmp/x",
               "chain": "regtest", "network": "bip122:00000000000000000000000000000001",
               "node": {"rest": "https://127.0.0.1:8080", "tls_cert": "tls.cert", "macaroon": "a", "info_macaroon": "b"},
               "routes": [{"path": "/files/", "price": {"byte_msat": 1000, "per_bytes": 1048576}},
                          {"path": "/files/free/", "free": true},
                          {"path": "/api", "methods": ["POST"], "price": {"request_msat": 2500}, "max_body": 4096, "forward_headers": ["X-Trace"]}]})
    }

    #[test]
    fn the_defaults_are_the_drafts_numbers() {
        let c = Config::from_json(&base()).unwrap();
        assert_eq!(
            (
                c.caps.ticket_msat,
                c.caps.max_tickets,
                c.ticket_blocks,
                c.caps.margin_blocks
            ),
            (1_000_000, 2, 40, 24)
        );
        assert_eq!(
            (
                c.held,
                c.prepaid,
                c.inbound_slots,
                c.held_set,
                c.caps.slots_retry_secs
            ),
            (true, true, 30, false, 30),
            "held tickets and prepaid ones; a 30-slot channel assumed"
        );
        assert_eq!(
            c.node.channels_macaroon, None,
            "the gateway does not read channels unless asked"
        );
        assert_eq!(
            (c.node.hold_expiry_delta, c.caps.margin_blocks),
            (18, 24),
            "the fork's node cancels 18 blocks before expiry; 6 more for a settle on chain"
        );
        assert_eq!(
            (
                c.caps.max_sessions,
                c.caps.sessions_per_address,
                c.caps.max_kept_sessions,
                c.caps.max_held
            ),
            (30, 2, 10_000, 15)
        );
        assert_eq!(
            (
                c.caps.unpaid_secs,
                c.caps.first_use_secs,
                c.caps.idle_secs,
                c.caps.keep_secs
            ),
            (75, 60, 300, 86_400)
        );
        assert_eq!(
            (c.http.connections, c.http.per_address, c.http.threads),
            (64, 48, 16)
        );
        assert!(!c.mainnet());
    }

    #[test]
    fn a_file_that_names_no_chain_is_regtest_and_mainnet_is_asked_for_twice() {
        // no chain: regtest, which like every chain but main must say which network it is
        let mut none = base();
        none.as_object_mut().unwrap().remove("chain");
        let c = Config::from_json(&none).unwrap();
        assert_eq!((c.chain.as_str(), c.mainnet(), c.mainnet_notice().len()), ("regtest", false, 0));
        none.as_object_mut().unwrap().remove("network");
        let e = Config::from_json(&none).unwrap_err().to_string();
        assert!(e.contains("needs network") && e.contains("regtest"), "{e}");
        // chain main alone is refused, and the refusal says what it takes
        let mut main = none.clone();
        main["chain"] = json!("main");
        let e = Config::from_json(&main).unwrap_err().to_string();
        assert!(e.contains("mainnet_ack") && e.contains(MAINNET_ACK) && e.contains("docs/LIMITS.md"), "{e}");
        for wrong in [json!(true), json!("yes"), json!(""), json!(MAINNET_ACK.to_uppercase())] {
            main["mainnet_ack"] = wrong.clone();
            assert!(Config::from_json(&main).is_err(), "{wrong}");
        }
        main["mainnet_ack"] = json!(MAINNET_ACK);
        let m = Config::from_json(&main).unwrap();
        assert!(m.mainnet());
        assert_eq!(m.network, "bip122:0000000000000050c1e5f69672f45929");
        // and a start on mainnet says what its runner should know, and where the rest is
        let notice = m.mainnet_notice().join("\n");
        assert!(notice.contains("docs/LIMITS.md") && notice.contains("regtest only") && notice.contains("dust"), "{notice}");
        // the word means nothing on another chain, and a key that means nothing is not taken
        let mut off = base();
        off["mainnet_ack"] = json!(MAINNET_ACK);
        assert!(Config::from_json(&off).unwrap_err().to_string().contains("chain \"main\" only"));
    }

    #[test]
    fn the_gateway_listens_off_loopback_only_behind_an_https_origin() {
        let with = |listen: &str, public: &str| {
            let mut v = base();
            v["listen"] = json!(listen);
            v["public_url"] = json!(public);
            Config::from_json(&v)
        };
        for listen in ["127.0.0.1:8402", "127.0.0.9:0", "[::1]:8402"] {
            assert!(with(listen, "http://127.0.0.1:8402").is_ok(), "{listen}");
            assert!(with(listen, "https://seller.example").is_ok(), "{listen}");
        }
        // any other address, every address, and a name (which is whatever the resolver says)
        for listen in ["0.0.0.0:8402", "192.0.2.7:8402", "[::]:8402", "[2001:db8::1]:8402", "localhost:8402", "gateway:8402"] {
            let e = with(listen, "http://seller.example").unwrap_err().to_string();
            assert!(e.contains("not a loopback address") && e.contains("https"), "{listen}: {e}");
            assert!(with(listen, "https://seller.example").is_ok(), "{listen}: behind a TLS proxy");
        }
    }

    #[test]
    fn the_network_is_the_chains_id_and_the_old_name_is_read_for_one_release() {
        let c = Config::from_json(&base()).unwrap();
        assert_eq!(c.network, "bip122:00000000000000000000000000000001");
        let mut old = base();
        old["network"] = json!("lightning:00000000000000000000000000000001");
        assert_eq!(Config::from_json(&old).unwrap().network, "bip122:00000000000000000000000000000001", "read, and written the new way");
        for bad in ["bip122:0000000000000000000000000000000G", "lightning:01", "bip122:", "00000000000000000000000000000001"] {
            old["network"] = json!(bad);
            assert!(Config::from_json(&old).is_err(), "{bad}");
        }
    }

    #[test]
    fn hold_invoices_go_to_a_session_that_has_paid_by_default_where_prepaid_tickets_are_offered() {
        let c = Config::from_json(&base()).unwrap();
        assert_eq!((c.caps.held_after_paid, c.caps.first_lock_secs, c.caps.unpaid_per_address), (true, 20, 2));
        let with = |tickets: Value, caps: Value| {
            let mut v = base();
            v["tickets"] = tickets;
            v["caps"] = caps;
            Config::from_json(&v)
        };
        // only held tickets: a first ticket cannot be prepaid, so the rule is off, and cannot be asked for
        assert!(!with(json!({"settle": ["on-use"]}), json!({})).unwrap().caps.held_after_paid);
        let e = with(json!({"settle": ["on-use"]}), json!({"held_after_paid": true})).unwrap_err().to_string();
        assert!(e.contains("held_after_paid") && e.contains("on-arrival"), "{e}");
        assert!(!with(json!({}), json!({"held_after_paid": false})).unwrap().caps.held_after_paid);
        assert!(with(json!({}), json!({"held_after_paid": "yes"})).is_err());
        for bad in [4, 61] {
            assert!(with(json!({}), json!({"first_lock_secs": bad})).unwrap_err().to_string().contains("first_lock_secs"), "{bad}");
        }
        assert_eq!(with(json!({}), json!({"first_lock_secs": 15, "unpaid_per_address": 0})).unwrap().caps.unpaid_per_address, 0);
    }

    #[test]
    fn the_runner_can_raise_the_held_cap_and_only_by_saying_so() {
        let with = |f: &dyn Fn(&mut Value)| {
            let mut v = base();
            f(&mut v);
            Config::from_json(&v)
        };
        // a node whose every inbound channel carries 483: half of that, with nothing more to say
        let c = with(&|v| v["caps"] = json!({"inbound_slots": 483})).unwrap();
        assert_eq!((c.caps.max_held, c.held_set), (241, false));
        // a lower cap is always the runner's to set
        let c = with(&|v| v["caps"] = json!({"max_held_tickets": 4})).unwrap();
        assert_eq!((c.caps.max_held, c.held_set), (4, true));
        // above half only with the explicit word
        let c =
            with(&|v| v["caps"] = json!({"max_held_tickets": 60, "held_over_half": true})).unwrap();
        assert_eq!(c.caps.max_held, 60);
        let c = with(&|v| {
            v["caps"] = json!({"max_held_tickets": 60, "held_over_half": true});
            v["tickets"] = json!({"max_tickets": 8});
        })
        .unwrap();
        assert_eq!(c.caps.max_tickets, 8);
        // prepaid only: no held ticket, so a small ticket is no dust and no slot is asked for
        let c = with(&|v| v["tickets"] = json!({"ticket_msat": 64_000, "settle": ["on-arrival"]}))
            .unwrap();
        assert_eq!(
            (c.held, c.prepaid, c.caps.ticket_msat),
            (false, true, 64_000)
        );
        let c = with(&|v| v["tickets"] = json!({"settle": ["on-use"]})).unwrap();
        assert_eq!((c.held, c.prepaid), (true, false));
        let c = with(&|v| v["node"]["channels_macaroon"] = json!("c")).unwrap();
        assert_eq!(c.node.channels_macaroon, Some(PathBuf::from("c")));
    }

    #[test]
    fn the_nodes_hold_expiry_delta_is_the_runners_word_and_is_checked_against_the_margin() {
        let with = |d: Value| {
            let mut v = base();
            v["node"]["hold_expiry_delta"] = d;
            Config::from_json(&v)
        };
        // upstream lnd's 12, and anything up to the fork's 18: the margin stays 24, with room to spare
        for d in [0u32, 12, 18] {
            let c = with(json!(d)).unwrap();
            assert_eq!((c.node.hold_expiry_delta, c.caps.margin_blocks), (d, 24), "{d}");
        }
        // a node that cancels 19 or more blocks before expiry leaves fewer than 6 for a settle on chain
        for d in [19u32, 24, 40] {
            let e = with(json!(d)).unwrap_err().to_string();
            assert!(e.contains("holdexpirydelta to 18 or less") && e.contains("on chain"), "{d}: {e}");
        }
        assert!(with(json!("18")).is_err() && with(json!(-1)).is_err());
    }

    #[test]
    fn the_example_file_is_a_config() {
        let v: Value = serde_json::from_str(include_str!("../gateway.example.json")).unwrap();
        let c = Config::from_json(&v).unwrap();
        assert!(!c.mainnet() && c.chain == "regtest", "the example is a regtest config");
        assert_eq!(c.routes.len(), 6);
        assert_eq!(
            c.route("/films/a.mkv").unwrap().price.for_bytes(1 << 20),
            Some(200_000)
        );
        assert_eq!(c.route("/chunks/1").unwrap().release, Release::AfterVerify);
        // the lottery: pieces of a tenth of a sat are offered by draws, and a page of 2.5 sat. A
        // film's piece of 50 sat is more than a quarter of the 64-sat win, and a chunk of 100 sat
        // more than a whole one: tickets only
        let l = c.lottery.as_ref().unwrap();
        assert_eq!((l.win_msat, l.min_win_msat, l.piece_bytes), (64_000, 16_000, 262_144));
        assert!(l.offers(&c.route("/pieces/1").unwrap().price) && l.offers(&c.route("/api/x").unwrap().price));
        assert!(l.offers(&c.route("/live/x").unwrap().price), "5 sat a second");
        assert_eq!(l.dearest_piece(&c.route("/films/a.mkv").unwrap().price), Some(50_000));
        assert!(!l.offers(&c.route("/films/a.mkv").unwrap().price) && !l.offers(&c.route("/chunks/1").unwrap().price));
        // a file with no lottery section offers none, and a section that is not one is refused
        let mut none = v.clone();
        none.as_object_mut().unwrap().remove("lottery");
        assert_eq!(Config::from_json(&none).unwrap().lottery, None);
        let mut bad = v.clone();
        bad["lottery"]["window"] = json!(0);
        assert!(Config::from_json(&bad).is_err());
        let mut own = v;
        own["routes"][0]["path"] = json!("/x402/lottery/x");
        assert!(Config::from_json(&own).is_err(), "the lottery's endpoints are the gateway's own");
    }

    #[test]
    fn a_forwarded_address_is_believed_only_where_the_runner_names_the_proxy() {
        let with = |f: Value| {
            let mut v = base();
            v["http"] = json!({"forwarded_address": f});
            Config::from_json(&v)
        };
        assert_eq!(Config::from_json(&base()).unwrap().forwarded, None, "off unless written");
        let c = with(json!({"header": "X-Real-IP", "proxies": ["127.0.0.1", "::ffff:192.0.2.9", "2001:db8::1"]})).unwrap();
        let f = c.forwarded.unwrap();
        assert_eq!(f.header, "x-real-ip");
        assert_eq!(f.proxies, ["127.0.0.1".parse::<std::net::IpAddr>().unwrap(), "192.0.2.9".parse().unwrap(), "2001:db8::1".parse().unwrap()]);
        for bad in [
            json!({"header": "X-Real-IP"}),
            json!({"header": "X-Real-IP", "proxies": []}),
            json!({"header": "X-Real-IP", "proxies": ["proxy.internal"]}),
            json!({"header": "X-Real-IP", "proxies": ["10.0.0.0/8"]}),
            json!({"header": "X-Real-IP", "proxies": "127.0.0.1"}),
            json!({"header": "X Real IP", "proxies": ["127.0.0.1"]}),
            json!({"proxies": ["127.0.0.1"]}),
            json!({"header": "X-Real-IP", "proxies": ["127.0.0.1"], "trust": "all"}),
            json!("X-Real-IP"),
        ] {
            assert!(with(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_longest_route_wins_and_a_path_with_no_route_has_none() {
        let c = Config::from_json(&base()).unwrap();
        assert_eq!(c.route("/files/a.bin").unwrap().path, "/files/");
        assert_eq!(c.route("/files/free/a.bin").unwrap().path, "/files/free/");
        assert!(c.route("/files/free/a.bin").unwrap().free);
        assert_eq!(c.route("/api").unwrap().methods, vec!["POST"]);
        assert_eq!(c.route("/api").unwrap().forward_headers, vec!["x-trace"]);
        for none in ["/api/", "/api2", "/files", "/", "/Files/a"] {
            assert!(c.route(none).is_none(), "{none}");
        }
    }

    #[test]
    fn a_file_that_could_mean_two_things_is_refused() {
        let edit = |f: &dyn Fn(&mut Value)| {
            let mut v = base();
            f(&mut v);
            Config::from_json(&v)
        };
        type Edit = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("unknown key", Box::new(|v| v["cap"] = json!({}))),
            (
                "unknown key",
                Box::new(|v| v["caps"] = json!({"max_session": 3})),
            ),
            (
                "unknown key",
                Box::new(|v| v["routes"][0]["prices"] = json!({})),
            ),
            (
                "whole number",
                Box::new(|v| v["caps"] = json!({"max_sessions": "3"})),
            ),
            (
                "whole number",
                Box::new(|v| v["tickets"] = json!({"ticket_msat": -1})),
            ),
            (
                "whole number",
                Box::new(|v| v["routes"][0]["price"]["byte_msat"] = json!(1.5)),
            ),
            (
                "ticket_msat",
                Box::new(|v| v["tickets"] = json!({"ticket_msat": 999})),
            ),
            (
                "ticket_blocks",
                Box::new(|v| v["tickets"] = json!({"ticket_blocks": 24})),
            ),
            (
                "ticket_blocks",
                Box::new(|v| v["tickets"] = json!({"ticket_blocks": 2017})),
            ),
            (
                "546 sat",
                Box::new(|v| v["tickets"] = json!({"ticket_msat": 545_999})),
            ),
            (
                "tickets.settle",
                Box::new(|v| v["tickets"] = json!({"settle": []})),
            ),
            (
                "tickets.settle",
                Box::new(|v| v["tickets"] = json!({"settle": ["on-use", "later"]})),
            ),
            (
                "tickets.settle",
                Box::new(|v| v["tickets"] = json!({"settle": ["on-use", "on-use"]})),
            ),
            (
                "tickets.settle",
                Box::new(|v| v["tickets"] = json!({"settle": "on-use"})),
            ),
            (
                "max_tickets",
                Box::new(|v| v["tickets"] = json!({"max_tickets": 16})),
            ),
            (
                "max_tickets",
                Box::new(|v| v["tickets"] = json!({"max_tickets": 484, "settle": ["on-arrival"]})),
            ),
            (
                "more than half",
                Box::new(|v| v["caps"] = json!({"max_held_tickets": 16})),
            ),
            (
                "more than half",
                Box::new(|v| v["caps"] = json!({"max_held_tickets": 242, "inbound_slots": 483})),
            ),
            (
                "max_held_tickets is at least 1",
                Box::new(|v| v["caps"] = json!({"max_held_tickets": 0})),
            ),
            (
                "inbound_slots",
                Box::new(|v| v["caps"] = json!({"inbound_slots": 484})),
            ),
            (
                "inbound_slots",
                Box::new(|v| v["caps"] = json!({"inbound_slots": 1})),
            ),
            (
                "held_over_half",
                Box::new(|v| v["caps"] = json!({"held_over_half": 1})),
            ),
            (
                "slots_retry_secs",
                Box::new(|v| v["caps"] = json!({"slots_retry_secs": 0})),
            ),
            (
                "unpaid_secs",
                Box::new(|v| v["caps"] = json!({"unpaid_secs": 59})),
            ),
            (
                "http.connections",
                Box::new(|v| v["http"] = json!({"connections": 0})),
            ),
            (
                "http.threads",
                Box::new(|v| v["http"] = json!({"threads": 5000})),
            ),
            (
                "at most 4096",
                Box::new(|v| v["caps"] = json!({"max_held_tickets": 4097, "held_over_half": true})),
            ),
            (
                "not both",
                Box::new(|v| v["routes"][0] = json!({"path": "/x/"})),
            ),
            (
                "not both",
                Box::new(|v| v["routes"][1]["price"] = json!({"request_msat": 1})),
            ),
            (
                "per_bytes",
                Box::new(|v| v["routes"][0]["price"]["per_bytes"] = json!(0)),
            ),
            (
                "named twice",
                Box::new(|v| v["routes"][1]["path"] = json!("/files/")),
            ),
            (
                "gateway's own",
                Box::new(|v| v["routes"][1]["path"] = json!("/x402/ticket/lock")),
            ),
            (
                "gateway's own",
                Box::new(|v| v["routes"][1]["path"] = json!("/services")),
            ),
            (
                "a path starts",
                Box::new(|v| v["routes"][0]["path"] = json!("files/")),
            ),
            (
                "a path starts",
                Box::new(|v| v["routes"][0]["path"] = json!("/a/../b/")),
            ),
            (
                "a path starts",
                Box::new(|v| v["routes"][0]["path"] = json!("/a%2fb/")),
            ),
            (
                "a path starts",
                Box::new(|v| v["routes"][0]["path"] = json!("/a//b/")),
            ),
            (
                "never passed",
                Box::new(|v| v["routes"][0]["forward_headers"] = json!(["Host"])),
            ),
            (
                "never passed",
                Box::new(|v| v["routes"][0]["forward_headers"] = json!(["payment-signature"])),
            ),
            (
                "methods",
                Box::new(|v| v["routes"][0]["methods"] = json!(["get"])),
            ),
            (
                "methods",
                Box::new(|v| v["routes"][0]["methods"] = json!(["CONNECT"])),
            ),
            (
                "release",
                Box::new(|v| v["routes"][0]["release"] = json!("later")),
            ),
            (
                "at most one ticket",
                Box::new(
                    |v| v["routes"][2] = json!({"path": "/api", "price": {"request_msat": 1000001}, "release": "after-verify"}),
                ),
            ),
            (
                "routes is a list",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("routes");
                }),
            ),
            (
                "upstream",
                Box::new(|v| v["upstream"] = json!("https://127.0.0.1:8080")),
            ),
            (
                "upstream",
                Box::new(|v| v["upstream"] = json!("http://127.0.0.1:8080/?a=1")),
            ),
            (
                "upstream",
                Box::new(|v| v["upstream"] = json!("http://127.1:8080")),
            ),
            (
                "public_url",
                Box::new(|v| v["public_url"] = json!("seller.example")),
            ),
            (
                "public_url",
                Box::new(|v| v["public_url"] = json!("https://seller.example/shop")),
            ),
            (
                "network",
                Box::new(|v| v["network"] = json!("liquid:00000000000000000000000000000001")),
            ),
            (
                "network is fixed",
                Box::new(|v| {
                    v["chain"] = json!("main");
                    v["mainnet_ack"] = json!(MAINNET_ACK);
                }),
            ),
            ("mainnet_ack", Box::new(|v| v["chain"] = json!("main"))),
            (
                "network",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("network");
                }),
            ),
            (
                "info_macaroon is missing",
                Box::new(|v| {
                    v["node"].as_object_mut().unwrap().remove("info_macaroon");
                }),
            ),
        ];
        for (want, f) in cases {
            let e = edit(&*f).unwrap_err().to_string();
            assert!(e.contains(want), "wanted {want:?}, got {e:?}");
        }
    }

    #[test]
    fn a_route_may_name_its_own_service() {
        let mut v = base();
        v["routes"][2]["upstream"] = json!("http://127.0.0.1:9000/");
        v["routes"][0]["strip_prefix"] = json!(true);
        let c = Config::from_json(&v).unwrap();
        assert_eq!(c.upstream.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(c.routes[2].upstream.as_deref(), Some("http://127.0.0.1:9000"));
        assert_eq!(c.routes[0].upstream, None);
        assert_eq!(c.routes[0].upstream_target("/files/a/b.bin?x=1"), "/a/b.bin?x=1");
        assert_eq!(c.routes[0].upstream_target("/files/"), "/");
        // by segments of the raw target, however the buyer escaped them
        assert_eq!(c.routes[0].upstream_target("/fil%65s/a"), "/a");
        assert_eq!(c.routes[2].upstream_target("/api?x"), "/api?x", "without strip_prefix the target is passed as it is");
        // no service at all for a route
        let mut none = base();
        none.as_object_mut().unwrap().remove("upstream");
        assert!(Config::from_json(&none).unwrap_err().to_string().contains("no upstream"));
        for r in none["routes"].as_array_mut().unwrap() {
            r["upstream"] = json!("http://127.0.0.1:9001");
        }
        assert_eq!(Config::from_json(&none).unwrap().upstream, None);
        for (want, f) in [
            ("upstream is http://", Box::new(|v: &mut Value| v["routes"][0]["upstream"] = json!("https://127.0.0.1:1")) as Box<dyn Fn(&mut Value)>),
            ("strip_prefix is for a path ending in /", Box::new(|v: &mut Value| v["routes"][2]["strip_prefix"] = json!(true))),
            ("strip_prefix is true or false", Box::new(|v: &mut Value| v["routes"][0]["strip_prefix"] = json!("yes"))),
        ] {
            let mut v = base();
            f(&mut v);
            let e = Config::from_json(&v).unwrap_err().to_string();
            assert!(e.contains(want), "wanted {want:?}, got {e:?}");
        }
    }

    #[test]
    fn a_route_priced_by_the_token_is_read_and_its_mistakes_refused() {
        let mut v = base();
        v["routes"][0] = json!({"path": "/v1/", "methods": ["GET", "POST"], "price": {"per_1k_output_msat": 10000}, "max_body": 65536});
        let c = Config::from_json(&v).unwrap();
        let t = c.routes[0].price.tokens;
        assert_eq!((t.input_per_1k_msat, t.output_per_1k_msat, t.max_output), (0, 10_000, xbt402::tokens::DEFAULT_MAX_OUTPUT));
        assert!(c.routes[0].price.metered() && !c.routes[0].price.is_free());
        // input is priced only when the runner says so; the cap is the runner's
        v["routes"][0]["price"]["per_1k_input_msat"] = json!(2000);
        v["routes"][0]["max_output_tokens"] = json!(512);
        let t = Config::from_json(&v).unwrap().routes[0].price.tokens;
        assert_eq!((t.input_per_1k_msat, t.max_output), (2000, 512));
        assert_eq!(price_json(&Config::from_json(&v).unwrap().routes[0].price), json!({"per_1k_input_msat": 2000, "per_1k_output_msat": 10000}));
        for (want, f) in [
            ("no price per byte or per second beside it", Box::new(|v: &mut Value| v["routes"][0]["price"]["byte_msat"] = json!(5)) as Box<dyn Fn(&mut Value)>),
            ("max_output_tokens is from 1", Box::new(|v: &mut Value| v["routes"][0]["max_output_tokens"] = json!(0))),
            ("max_output_tokens is for a route priced by the token", Box::new(|v: &mut Value| v["routes"][1]["max_output_tokens"] = json!(10))),
        ] {
            let mut w = v.clone();
            f(&mut w);
            let e = Config::from_json(&w).unwrap_err().to_string();
            assert!(e.contains(want), "wanted {want:?}, got {e:?}");
        }
    }

    #[test]
    fn nostr_publishing_is_off_unless_written_and_needs_relays_and_a_listing() {
        assert!(Config::from_json(&base()).unwrap().nostr.is_none());
        let mut v = base();
        v["nostr"] = json!({"relays": ["wss://relay.example"]});
        let n = Config::from_json(&v).unwrap().nostr.unwrap();
        assert!(!n.publish);
        assert_eq!(n.republish, Duration::from_secs(6 * 3600));
        v["nostr"]["publish"] = json!(true);
        assert!(Config::from_json(&v).unwrap_err().to_string().contains("listing"));
        v["listing"] = json!({"name": "n", "kind": "video", "prices": {"request_msat": 1000}, "items": [],
                              "licence": "l", "credits": "c", "updated": "u"});
        assert!(Config::from_json(&v).unwrap().nostr.unwrap().publish);
        for bad in [json!({"relays": ["ws://relay.example"], "publish": true}), json!({"relays": [], "publish": true}),
                    json!({"relays": ["wss://r.example"], "republish_s": 5}), json!({"relays": ["wss://r.example"], "other": 1})] {
            v["nostr"] = bad;
            assert!(Config::from_json(&v).is_err());
        }
    }

    #[test]
    fn a_listing_1_takes_each_services_price_from_its_route() {
        let mut v = base();
        v["listing"] = json!({"name": "One box", "updated": "2026-10-26", "services": [
            {"name": "Files", "kind": "files", "path": "/files/", "items": []},
            {"name": "Model", "kind": "api", "path": "/api", "items": []},
        ]});
        let d = Config::from_json(&v).unwrap().listing.unwrap();
        assert_eq!(d.services[0].prices, json!({"byte_msat": "1000", "per_bytes": "1048576"}));
        assert_eq!(d.services[1].prices, json!({"request_msat": "2500"}));
        v["listing"]["services"][1]["path"] = json!("/nowhere");
        assert!(Config::from_json(&v).unwrap_err().to_string().contains("not one of the routes"));
    }

    #[test]
    fn a_listing_is_optional_and_names_only_its_own_fields() {
        assert!(Config::from_json(&base()).unwrap().listing.is_none());
        let mut v = base();
        v["listing"] = json!(null);
        assert!(Config::from_json(&v).unwrap().listing.is_none());
        v["listing"] = json!({
            "name": "Films",
            "kind": "video",
            "prices": {"byte_msat": 20, "per_bytes": 1048576},
            "items": [{"title": "Sintel", "url": "https://media.lazarus-xbt.xyz/Videos/s", "year": 2010}],
            "licence": "CC BY 3.0",
            "credits": "(c) Blender Foundation, CC BY 3.0",
            "updated": "2026-10-25",
        });
        let got = Config::from_json(&v).unwrap().listing.unwrap();
        assert_eq!(got.kind, "video");
        assert_eq!(got.prices["byte_msat"], "20");
        assert_eq!(got.items[0].year, Some(2010));
        v["listing"]["kind"] = json!("nope");
        assert!(Config::from_json(&v).is_err());
        v["listing"]["kind"] = json!("video");
        v["listing"]["extra"] = json!(1);
        assert!(Config::from_json(&v).unwrap_err().to_string().contains("unknown key"));
        let mut reserved = base();
        reserved["routes"][0]["path"] = json!("/.well-known/lightning-stream.json");
        assert!(Config::from_json(&reserved).unwrap_err().to_string().contains("gateway's own"));
    }
}
