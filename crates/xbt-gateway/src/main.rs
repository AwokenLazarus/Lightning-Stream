//! xbt-gateway: the stream-ticket seller gateway. One program beside a Lightning node of the lnd
//! family (it speaks lnd's REST interface; a Core Lightning seller is not supported): point it at
//! an HTTP service, set a price per route, and buyers pay piece by piece with stream tickets
//! (`docs/TICKETS.md`).
//!
//!     xbt-gateway <config.json>           run
//!     xbt-gateway --check <config.json>   read the config and the macaroons, say what the caps cost, and exit
//!
//! SIGTERM or SIGINT stops a run: no new connection, the requests in flight get 5 s, then what the
//! book has counted since the last tick goes into the journal, the journal is fsynced and closed,
//! and the gateway exits 0. A request still running after that is cut where a kill would cut it.
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use xbt_gateway::config::Config;
use xbt_gateway::gateway::{unix_now, Gateway};
use xbt_gateway::node::{
    checked_macaroon, LndRest, Node, NodeError, CHANNEL_OPS, INFO_OPS, INVOICE_OPS, NOT_LND,
};

fn run(args: &[String]) -> Result<(), String> {
    let (check, path) = match args {
        [flag, path] if flag == "--check" => (true, path),
        [path] if !path.starts_with('-') => (false, path),
        _ => return Err("usage: xbt-gateway [--check] <config.json>".into()),
    };
    let mut cfg = Config::load(std::path::Path::new(path)).map_err(|e| e.to_string())?;
    // mainnet is asked for twice in the file (`chain` and `mainnet_ack`); a runner who did is told,
    // at every start and every check, what is known to be open there
    for line in cfg.mainnet_notice() {
        eprintln!("xbt-gateway: {line}");
    }
    let read = |p: &std::path::Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let (invoice, info) = (read(&cfg.node.macaroon)?, read(&cfg.node.info_macaroon)?);
    // each macaroon holds its own permissions and, on mainnet, nothing else: a gateway that is
    // broken into can make, settle and cancel invoices and read the node's public state, no more
    // the third is the runner's choice: with it the gateway reads its node's channels and sizes the
    // cap on held tickets itself. It is not asked for by default, because the permission also
    // shows the node's balances, its payments and what it forwarded
    let channels = cfg
        .node
        .channels_macaroon
        .as_deref()
        .map(read)
        .transpose()?;
    let mut checked = vec![
        checked_macaroon(&invoice, "node.macaroon", &INVOICE_OPS, cfg.mainnet()),
        checked_macaroon(&info, "node.info_macaroon", &INFO_OPS, cfg.mainnet()),
    ];
    if let Some(c) = &channels {
        checked.push(checked_macaroon(
            c,
            "node.channels_macaroon",
            &CHANNEL_OPS,
            cfg.mainnet(),
        ));
    }
    for warning in checked {
        if let Some(w) = warning.map_err(|e| e.to_string())? {
            eprintln!("xbt-gateway: warning: {w} (refused on mainnet)");
        }
    }
    let held_sat = u64::from(cfg.caps.max_held).saturating_mul(cfg.caps.ticket_msat) / 1000;
    eprintln!(
        "xbt-gateway: chain {}, {} routes, tickets of {} msat living {} blocks, used while more than {} are left (the node cancels a held one {} before expiry: node.hold_expiry_delta); at most {} sessions ({} per address) of {} tickets",
        cfg.chain,
        cfg.routes.len(),
        cfg.caps.ticket_msat,
        cfg.ticket_blocks,
        cfg.caps.margin_blocks,
        cfg.node.hold_expiry_delta,
        cfg.caps.max_sessions,
        cfg.caps.sessions_per_address,
        cfg.caps.max_tickets,
    );
    if cfg.held {
        eprintln!(
            "xbt-gateway: held tickets: buyers can hold up to {} at once, all together ({} sat of this node's inbound capacity, at no cost to them until they are used or cancelled). Each takes one pending payment of the channel it arrives on, and an inbound channel is taken to carry {} of them{}; a buyer beyond the cap is told to wait{}",
            cfg.caps.max_held,
            held_sat,
            cfg.inbound_slots,
            if channels.is_some() { " until the node's own channel list is read" } else { " (caps.inbound_slots)" },
            if cfg.prepaid { " or to buy prepaid tickets" } else { "" }
        );
    }
    if cfg.prepaid {
        eprintln!("xbt-gateway: prepaid tickets: paid in full when they arrive, one at a time, with nothing held on any channel");
    }
    if cfg.offers.is_some() {
        eprintln!("xbt-gateway: payment by BOLT 12 offer: one offer of the node, made at the start with no amount, pays prepaid tickets and lottery wins; a payment is credited to the session its payer note names, once. The node's offersrpc is used with node.macaroon ({}); held tickets stay hold invoices", xbt_gateway::node::OFFER_OPS.join(" "));
    }
    eprintln!("xbt-gateway: the node at {} is spoken to over lnd's REST interface: it must be an lnd-family node (Lightning Fork, or lnd). A Core Lightning seller is not supported", cfg.node.rest);
    if check {
        return Ok(());
    }
    // SIGTERM and SIGINT before the first thread (the node client and the gateway start some):
    // a stop is answered at once, also as PID 1 (xbt_svc::shutdown)
    let signals = xbt_svc::shutdown::listen().map_err(|e| format!("signals: {e}"))?;
    let node = LndRest::new(
        &cfg.node.rest,
        &invoice,
        &info,
        cfg.node.tls_cert.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    let node = Arc::new(match &channels {
        Some(c) => node.with_channels_macaroon(c),
        None => node,
    });
    let key = xbt402::provider::load_or_create_secret(&cfg.state_dir.join("receipt.key"))
        .map_err(|e| e.to_string())?;
    // the port before anything else: a second gateway, or a port in use, stops here
    let listener =
        TcpListener::bind(&cfg.listen).map_err(|e| format!("listen {}: {e}", cfg.listen))?;
    let mut waited = 0u32;
    loop {
        match node.info() {
            Ok(_) => break,
            // another implementation's node: nothing the gateway asks of it would work, and waiting does not help
            Err(NodeError::Refused(m)) if m.starts_with(NOT_LND) => {
                return Err(format!("node.rest {}: {m}", cfg.node.rest))
            }
            Err(e) => {
                if waited.is_multiple_of(15) {
                    eprintln!("xbt-gateway: waiting for the node: {e}");
                }
                waited += 1;
                // nothing is open yet: a stop while waiting is just an exit
                if let Some(sig) = signals.wait_timeout(Duration::from_secs(2)) {
                    eprintln!("xbt-gateway: {} received while waiting for the node: stopped", xbt_svc::shutdown::name(sig));
                    return Ok(());
                }
            }
        }
    }
    let nostr = cfg.nostr.clone().filter(|n| n.publish);
    let nostr_key = match &nostr {
        Some(_) => Some(xbt_gateway::nostr::load_key(&cfg.state_dir)?),
        None => None,
    };
    // a shop reached by key only is named by its Nostr key (xbt402::shop): that name is its origin
    let link_keys = match &cfg.link {
        Some(_) => Some(xbt_gateway::nostr::load_key(&cfg.state_dir)?),
        None => None,
    };
    let nostr_pk = link_keys.as_ref().map(|k| k.public.serialize());
    // where the link is reached is told on the listing's own relays (xbt_iroh_link::nostr_lookup)
    let link_relays: Vec<String> = cfg.nostr.as_ref().map(|n| n.relays.clone()).unwrap_or_default();
    if cfg.public_url == xbt_gateway::config::LINK_ONLY {
        let pk = nostr_pk.ok_or("a shop reached by key needs its Nostr key")?;
        cfg.name_shop(xbt402::shop::origin_for(&pk));
        eprintln!("xbt-gateway: a shop without a web address, named {} ({})", cfg.public_url, xbt402::shop::npub(&pk));
    }
    let (link_cfg, state_dir) = (cfg.link.clone(), cfg.state_dir.clone());
    let (link_node, seller, sign_mac) = (node.clone(), cfg.public_url.clone(), cfg.node.macaroon.with_file_name("sign.macaroon"));
    let gw = Gateway::start(cfg, node, key, Box::new(unix_now)).map_err(|e| e.to_string())?;
    let running = gw.serve(listener).map_err(|e| e.to_string())?;
    eprintln!(
        "xbt-gateway: listening on {}; an lnd-family node, {}; receipts signed by {}",
        running.addr,
        gw.terms().pay_to,
        gw.terms().receipt_key
    );
    // the link: the same gateway, reached by key (crates/xbt-iroh-link). Its streams come in as
    // connections to the gateway's own port, so everything else is as for the web
    let _link = match &link_cfg {
        Some(l) => Some(start_link(l, &state_dir, running.addr, &link_node, &seller, &sign_mac, &gw, nostr_pk, link_keys.clone(), link_relays.clone())?),
        None => None,
    };
    // after the link, so the first listing sent already names it
    if let (Some(n), Some(k)) = (nostr, nostr_key) {
        eprintln!("xbt-gateway: publishing the listing on Nostr to {} relays every {} s, as Nostr key {}", n.relays.len(), n.republish.as_secs(), k.public_hex());
        xbt_gateway::nostr::spawn(gw.clone(), k, n).map_err(|e| format!("nostr: {e}"))?;
    }
    let sig = signals.wait();
    xbt_svc::shutdown::say_stopping("xbt-gateway", sig);
    // the listener first, so that nothing new starts; then the requests in flight; then the book.
    // Gateway::stop journals the counters the book marked since the last tick, fsyncs the journal
    // and closes it: a request still running after the bound then writes no record (a lock that
    // cannot journal is refused, as on a full disk), and a ticket it settled is credited at the
    // next start from the node's word, as every ticket the gateway does not finish is
    let drained = running.stopper().drain(xbt_svc::shutdown::DRAIN);
    gw.stop();
    xbt_svc::shutdown::say_stopped("xbt-gateway", drained);
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xbt-gateway: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Starts the gateway's link on `link.endpoints` keys and writes what the app needs to name it
/// (`link.json` in the state directory: the keys and where they are reached), then has the seller's
/// node vouch for each, again before the node's word runs out, for as long as the gateway runs.
/// Every key leads to the same gateway; each keeps its own connection to its relay, so buyers who
/// reach the shop through a relay do not all share one connection (and one relay's limit for it).
#[allow(clippy::too_many_arguments)]
fn start_link(l: &xbt_gateway::config::LinkConfig, state_dir: &std::path::Path, addr: std::net::SocketAddr,
              node: &Arc<LndRest>, seller: &str, sign_mac: &std::path::Path, gw: &Arc<Gateway>, nostr_pk: Option<[u8; 32]>,
              keys: Option<xbt_nostr::event::Keys>, nostr_relays: Vec<String>)
              -> Result<Vec<Arc<xbt_iroh_link::Link>>, String> {
    let upstream = if addr.ip().is_unspecified() { std::net::SocketAddr::from(([127, 0, 0, 1], addr.port())) } else { addr };
    let mut links = Vec::new();
    for i in 0..l.endpoints {
        // the first key is the one a gateway on one key always had
        let file = if i == 0 { "link.key".to_string() } else { format!("link-{}.key", i + 1) };
        let secret = xbt402::provider::load_or_create_secret(&state_dir.join(file)).map_err(|e| e.to_string())?;
        // no relays named: ours, with iroh's public relays beside it. Relays named: each key has
        // another of them first, as its home
        let relays = if l.relays.is_empty() {
            xbt_iroh_link::Relays::OursThenPublic(vec![xbt_iroh_link::DEFAULT_RELAY.into()])
        } else {
            let mut r = l.relays.clone();
            let k = i % r.len();
            r.rotate_left(k);
            xbt_iroh_link::Relays::Ours(r)
        };
        let lookup = Some(Arc::new(xbt_iroh_link::nostr_lookup::NostrLookup::new(keys.clone(), nostr_relays.clone())));
        let link = xbt_iroh_link::Link::start_with(secret.secret_bytes(), xbt_iroh_link::Options { relays, serving: true, private: l.private, lookup })
            .map_err(|e| format!("link: {e}"))?;
        link.serve(upstream);
        links.push(link);
    }
    let v = Vouch { links: links.clone(), private: l.private, state_dir: state_dir.to_path_buf(), node: node.clone(), seller: seller.to_string(),
                    sign_mac: sign_mac.to_path_buf(), gw: gw.clone(), nostr_pk, words: Default::default(), named: Default::default() };
    // the sign key as it is before the first try: one pasted after it is news to the loop below
    let mut key = SignKey::read(&v.sign_mac);
    let mut until = v.once()?;
    eprintln!(
        "xbt-gateway: reached by {} over {}{}",
        match links.as_slice() {
            [one] => format!("key {}", one.endpoint_id()),
            many => format!("{} keys, {} first", many.len(), many[0].endpoint_id()),
        },
        if l.private { "relays only" } else { "direct links and relays" },
        if until.is_some() { "; the node vouches for it" } else { "; the node has not vouched for it (see sign_error at /.well-known/lightning-stream-link.json), so buyers cannot check it and nothing names it" }
    );
    std::thread::Builder::new().name("link-vouch".into()).spawn(move || {
        let mut ask_at = next_ask(until, unix_now());
        loop {
            // the keys buyers can reach are looked at every REACH_CHECK, and the document made again
            // when they change; the node is asked again ten days before its word runs out, an hour
            // after a try that got no word (none yet, or a renewal refused), and at once when its sign
            // key is given or replaced (pasted on a running shop: the gateway is not restarted for it,
            // so no session is dropped)
            std::thread::sleep(REACH_CHECK);
            if v.gw.stopped() {
                return;
            }
            let new_key = key.changed();
            if unix_now() >= ask_at || new_key || v.reach_changed() {
                match v.once() {
                    Ok(u) => until = u.or(until.filter(|u| *u > unix_now())),
                    Err(e) => eprintln!("xbt-gateway: link: {e}"),
                }
                ask_at = next_ask(until, unix_now());
            }
        }
    }).map_err(|e| format!("link: {e}"))?;
    Ok(links)
}

/// The node key the gateway asks the node to sign with (`sign.macaroon`), as last seen: the owner
/// may give or replace it while the shop runs (StartOS: pasted on the Sell page), and the link is
/// looked at again at once when it changes, not at the next hourly try. A key given where the node
/// had not vouched is asked with then; one that replaces a key whose word still holds signs at the
/// next renewal.
struct SignKey {
    path: std::path::PathBuf,
    seen: Option<Vec<u8>>,
}

impl SignKey {
    fn read(path: &std::path::Path) -> Self {
        SignKey { path: path.to_path_buf(), seen: std::fs::read(path).ok() }
    }

    /// Whether the key is there now and differs from the one last seen (a key removed is no reason
    /// to ask the node).
    fn changed(&mut self) -> bool {
        let now = std::fs::read(&self.path).ok();
        let new = now.is_some() && now != self.seen;
        self.seen = now;
        new
    }
}

/// When the node is next asked for its word, after a try at `now` that left it held until `until`:
/// ten days before it runs out; or, when there is none or it is due already (the node did not vouch,
/// or refused to renew), an hour on, so a key the node refuses is not tried every REACH_CHECK.
fn next_ask(until: Option<u64>, now: u64) -> u64 {
    match until {
        Some(u) if u > now + VOUCH_AHEAD => u - VOUCH_AHEAD,
        _ => now + ASK_AGAIN,
    }
}

/// How long after a try that got no word the node is asked again.
const ASK_AGAIN: u64 = 3600;
/// How long the node's word for the link holds, and how long before its end it is asked again.
const VOUCH_FOR: u64 = 30 * 86_400;
const VOUCH_AHEAD: u64 = 10 * 86_400;
/// How often the gateway looks at which of its keys buyers can reach.
const REACH_CHECK: Duration = Duration::from_secs(15);

/// What it takes to have the node vouch for the link and to say so.
struct Vouch {
    links: Vec<Arc<xbt_iroh_link::Link>>,
    private: bool,
    state_dir: std::path::PathBuf,
    node: Arc<LndRest>,
    seller: String,
    sign_mac: std::path::PathBuf,
    gw: Arc<Gateway>,
    nostr_pk: Option<[u8; 32]>,
    /// The node's word for each key, while it holds: (until, signature), so a key named again is
    /// not signed again.
    words: std::sync::Mutex<std::collections::HashMap<String, (u64, String)>>,
    /// The keys the transport document names now.
    named: std::sync::Mutex<Vec<String>>,
}

impl Vouch {
    /// The keys buyers can reach now: connected to their home relay, or (not private) with a direct
    /// address. All of them while none is, so that a shop is never left with no key named.
    fn reachable(&self, hints: &[xbt_iroh_link::Hints]) -> Vec<String> {
        let up: Vec<String> = self.links.iter().zip(hints)
            .filter(|(l, h)| l.relay_connected() || (!self.private && !h.direct.is_empty()))
            .map(|(l, _)| l.endpoint_id())
            .collect();
        if up.is_empty() { self.links.iter().map(|l| l.endpoint_id()).collect() } else { up }
    }

    /// Whether the keys buyers can reach have changed since the document was last made.
    fn reach_changed(&self) -> bool {
        let hints: Vec<xbt_iroh_link::Hints> = self.links.iter().map(|l| l.hints(Duration::ZERO)).collect();
        self.reachable(&hints) != *self.named.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Asks the node to sign the claim for each link key (with a macaroon that allows only
    /// SignMessage, where the app baked one), checks each signature is the node's own, and publishes
    /// the result: the transport document, the link's state, `link.json`. `Some(expiry)` when the
    /// node vouched for at least one key; only the keys it vouched for are named.
    fn once(&self) -> Result<Option<u64>, String> {
        let hints: Vec<xbt_iroh_link::Hints> = std::thread::scope(|sc| {
            let hs: Vec<_> = self.links.iter().map(|l| sc.spawn(move || l.hints(Duration::from_secs(10)))).collect();
            hs.into_iter().map(|h| h.join().unwrap_or_default()).collect()
        });
        let fresh = unix_now() + VOUCH_FOR;
        let reachable = self.reachable(&hints);
        let mut sign_error: Option<String> = None;
        let mac = std::fs::read(&self.sign_mac);
        let mut each = Vec::new();
        for (link, h) in self.links.iter().zip(&hints) {
            let direct: Vec<String> = if self.private { vec![] } else { h.direct.iter().map(|a| a.to_string()).collect() };
            let kept = self.words.lock().unwrap_or_else(|e| e.into_inner()).get(&link.endpoint_id()).filter(|(u, _)| *u > unix_now() + VOUCH_AHEAD).cloned();
            let expires = kept.as_ref().map_or(fresh, |(u, _)| *u);
            let node_sig = match (&kept, &mac) {
                (Some((_, sig)), _) => Some(sig.clone()),
                (None, Ok(mac)) => {
                    let text = xbt402::claim::claim_text(&link.endpoint_id(), &self.seller, expires);
                    match self.node.sign_message(mac, text.as_bytes()) {
                        Ok(sig) => match (self.node.info(), xbt402::claim::recover(text.as_bytes(), &sig)) {
                            // the node's own key, checked before it is published
                            (Ok(info), Ok(k)) if hex::encode(k.serialize()) == info.pubkey => Some(sig),
                            _ => {
                                eprintln!("xbt-gateway: link: the node's signature is not its own key's: not published");
                                sign_error = Some("the node's signature did not check out against its own key".into());
                                None
                            }
                        },
                        Err(e) => {
                            eprintln!("xbt-gateway: link: the node did not sign the link key: {e}");
                            sign_error = Some(format!("the node did not sign: {e}"));
                            None
                        }
                    }
                }
                (None, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    sign_error = Some("no key to ask the node to sign with (sign.macaroon): buyers cannot check this link yet".into());
                    None
                }
                (None, Err(e)) => {
                    sign_error = Some(format!("cannot read sign.macaroon: {e}: buyers cannot check this link yet"));
                    None
                }
            };
            if let Some(sig) = &node_sig {
                self.words.lock().unwrap_or_else(|e| e.into_inner()).insert(link.endpoint_id(), (expires, sig.clone()));
            }
            each.push((link.endpoint_id(), h.relays.clone(), direct, node_sig.map(|s| (expires, s))));
        }
        let signed = |sig: &Option<(u64, String)>| sig.as_ref().map(|(u, _)| *u);
        // the first key's fields where a gateway on one key had them; every key under `links`
        let (id0, relays0, direct0, sig0) = each.first().cloned().ok_or("the link has no key")?;
        let all: Vec<_> = each.iter().map(|(id, relays, direct, sig)| serde_json::json!({
            "endpoint_id": id, "relays": relays, "direct": direct, "signed_until": signed(sig), "named": reachable.contains(id),
        })).collect();
        let doc = serde_json::json!({
            "endpoint_id": id0,
            "relays": relays0,
            "direct": direct0,
            "private": self.private,
            "seller": self.seller,
            "node_sig": sig0.as_ref().map(|(_, s)| s),
            "expires": signed(&sig0),
            "links": all,
        });
        std::fs::write(self.state_dir.join("link.json"), format!("{doc}\n")).map_err(|e| format!("link.json: {e}"))?;
        // only the keys buyers can reach now: a key whose relay connection is not up yet would make
        // the buyers it is first for wait; it is named once it is up (Vouch::reach_changed)
        let vouched: Vec<xbt402::transport::Link> = each.iter().filter(|(id, ..)| reachable.contains(id))
            .filter_map(|(id, relays, direct, sig)| sig.as_ref().map(|(expires, sig)| xbt402::transport::Link {
                kind: "iroh".into(),
                endpoint_id: id.clone(),
                relays: relays.clone(),
                direct: direct.clone(),
                expires: *expires,
                node_sig: sig.clone(),
            })).collect();
        *self.named.lock().unwrap_or_else(|e| e.into_inner()) = reachable.clone();
        self.gw.set_link_status(serde_json::json!({
            "seller": self.seller,
            "npub": self.nostr_pk.map(|pk| xbt402::shop::npub(&pk)),
            "endpoint_id": id0,
            "relays": relays0,
            "direct": direct0,
            "home_relay": relays0.first(),
            "signed_until": signed(&sig0),
            "sign_error": sign_error,
            "private": self.private,
            "links": all,
        }));
        if vouched.is_empty() {
            return Ok(None);
        }
        self.gw.set_link(&vouched, &unix_now().to_string());
        Ok(vouched.iter().map(|l| l.expires).min())
    }
}

#[cfg(test)]
mod tests {
    use super::{next_ask, SignKey, ASK_AGAIN, VOUCH_AHEAD, VOUCH_FOR};

    /// The node is asked ten days before its word runs out; after a try that got no word, or a
    /// renewal it refused (the word is due already), an hour on, not at every look at the link.
    #[test]
    fn a_refused_renewal_is_tried_again_an_hour_on_not_every_look() {
        let now = 1_800_000_000;
        assert_eq!(next_ask(Some(now + VOUCH_FOR), now), now + VOUCH_FOR - VOUCH_AHEAD, "a fresh word: renewed ten days before its end");
        assert_eq!(next_ask(None, now), now + ASK_AGAIN, "no word: an hour on");
        assert_eq!(next_ask(Some(now + VOUCH_AHEAD - 60), now), now + ASK_AGAIN, "a renewal refused: an hour on, while the word holds");
        assert_eq!(next_ask(Some(now + VOUCH_AHEAD), now), now + ASK_AGAIN, "due exactly now and refused: an hour on");
    }

    /// A sign key pasted on a running shop is noticed at the next look (the node then vouches within
    /// REACH_CHECK, with no restart); the same key written again, or the key removed, is not news.
    #[test]
    fn a_sign_key_given_or_replaced_while_running_is_noticed_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sign.macaroon");
        let mut k = SignKey::read(&p);
        assert!(!k.changed(), "no key yet: nothing to ask the node");
        std::fs::write(&p, b"key one").unwrap();
        assert!(k.changed(), "a key pasted while running");
        assert!(!k.changed(), "noticed once");
        std::fs::write(&p, b"key one").unwrap();
        assert!(!k.changed(), "the same key written again (a form saved twice)");
        std::fs::write(&p, b"key two").unwrap();
        assert!(k.changed(), "a key replaced");
        std::fs::remove_file(&p).unwrap();
        assert!(!k.changed(), "a key removed");
        std::fs::write(&p, b"key two").unwrap();
        assert!(k.changed(), "given back after removal");
        let mut at_start = SignKey::read(&p);
        assert!(!at_start.changed(), "a key there at start was already used for the first vouch");
    }
}
