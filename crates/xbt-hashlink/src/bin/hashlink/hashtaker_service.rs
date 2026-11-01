//! `xbt-hashlink hashtaker`: the hashtaker's side as a service, for the app's Rent page. It finds hashmakers'
//! listings on Nostr, rents whole miners from them into the hashtaker's own DATUM Gateway (the pool is
//! chosen there, not here), pays each slice through the wallet's signer under its policy, and keeps
//! every rental's live state for the app. Several rentals can run at once.
//!
//! A hashmaker whose listing names an iroh link is reached over it (no port forward on either side;
//! `--iroh off` turns it off, `--iroh-relays` names relays); one naming only a TCP address, over TCP.
//!
//! Control page: `GET /status`, `GET /offers`, `POST /rent {"linkKey", "miners", "budgetSats",
//! "minutes"}` (or `{"linkKey", "trial": true}`: one slice, to try a hashmaker first), `POST /cut
//! {"rental"}`, `POST /datum {"addr", "api"?}`, `POST /attest {"rental"}` (publish a signed delivery record
//! of a rental that ended, if the hashtaker chooses to).
//!
//! The app comes with its own gateway, the Stream Gateway (DATUM-compatible), on `127.0.0.1:23339` beside
//! this service (`--bundled-gateway`, else that address when `--datum-candidates` lists it). Its API is
//! `--gateway-api`. An install that saved another gateway before the app had one is moved to it once, at
//! start: those gateways can't open their jobs, so every rental to them would be refused. The address it was
//! moved from is kept and shown, and `POST /datum` with it goes back, for good.
//!
//! Each offer carries its hashmaker's delivery history, read from the records and summaries on the
//! relays ([`xbt_hashlink::trust`]).

use crate::http;
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xbt_hashlink::hashtaker;
use xbt_hashlink::listing::{self, Hashrate};
use xbt_hashlink::over_iroh::{self, Dialer};
use xbt_hashlink::rail::{LabHashtaker, SignerPayer};
use xbt_hashlink::trust;

const OFFERS_FRESH: Duration = Duration::from_secs(20);
/// How long the delivery records read from the relays are kept before they are read again.
const HISTORY_FRESH: Duration = Duration::from_secs(60);
/// A test slice's time limit: a few times what one slice should take at the advertised speed,
/// within these bounds.
const TRIAL_MIN_MINUTES: u64 = 5;
const TRIAL_MAX_MINUTES: u64 = 60;
const KEPT: usize = 50;

struct Rental {
    hashmaker: String,
    hashmaker_key: PublicKey,
    /// The speed the listing advertised for the machines rented.
    advertised_hs: u64,
    /// A test slice (one slice, to try the hashmaker first).
    trial: bool,
    /// What publishing its delivery record did, once asked for.
    attested: Option<Value>,
    started_ms: u64,
    miners: u32,
    budget_sats: u64,
    minutes: u64,
    live: Arc<Mutex<Value>>,
    cut: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

struct R {
    key: SecretKey,
    datum: String,
    /// The API of the gateway chosen on the app's page, when it gave one.
    datum_api: Option<String>,
    /// The gateway that comes with the app (its Stratum address), when this box has one.
    bundled: Option<String>,
    /// `--upstream`, whose API `--gateway-api` names too.
    upstream_flag: Option<String>,
    /// The gateway this install was moved from at the upgrade that brought the bundled one.
    moved_from: Option<String>,
    /// The gateway chosen on the page that the installer's changed settings overrode.
    installer_won: Option<String>,
    /// The installer's answer this start was given (`--upstream`, `--bundled-gateway`), saved with a page's choice.
    installer: Value,
    user: String,
    gateway_api: Option<String>,
    allow_unblinded: bool,
    relays: Vec<String>,
    signer: Option<PathBuf>,
    task: String,
    expect_node: Option<String>,
    state: Option<PathBuf>,
    offers: Option<(Instant, Vec<(Hashrate, String)>)>,
    /// Each listing's Nostr author, by link key (a hashmaker's summary counts only from it).
    authors: HashMap<String, String>,
    /// The delivery records and summaries on the relays, as last read.
    history: Option<(Instant, Vec<xbt_nostr::event::Event>)>,
    rentals: BTreeMap<String, Rental>,
    /// The iroh link to hashmakers, started at the first rental that needs it; `None` inside when it
    /// is turned off or did not start.
    iroh: Option<Option<Arc<Dialer>>>,
    iroh_off: bool,
    iroh_relays: Option<String>,
    /// Failed first steps in a row, by seller's link key: kept across restarts.
    failed_first: BTreeMap<String, u32>,
    /// What the upstream's jobs show, as last looked at, and for which upstream.
    shown: Option<(String, xbt_hashlink::blind::Shown, u64)>,
}

/// A gateway's API port when nothing says otherwise.
const GATEWAY_API_PORT: u16 = 7152;
/// Where the Stream Gateway that comes with the app listens for Stratum, on every platform.
pub const BUNDLED_STRATUM: &str = "127.0.0.1:23339";
/// How often an upstream's jobs are looked at again.
const LOOK_EVERY: Duration = Duration::from_secs(60);
/// How often while the last look didn't show its jobs masked: a gateway that comes back (or gets its node's work)
/// shows on the renter's page within seconds, not at the next minute.
const LOOK_SOON: Duration = Duration::from_secs(5);

/// When to look at the upstream again after this look: soon while it isn't showing masked jobs, else every minute.
fn look_interval(last: Option<&xbt_hashlink::blind::Shown>) -> Duration {
    if last.is_some_and(|s| s.may_rent()) {
        LOOK_EVERY
    } else {
        LOOK_SOON
    }
}

/// Whether the last look is too old to show for `datum` at `now_ms` (or was of another gateway, or there was none).
fn look_stale(last: Option<&(String, xbt_hashlink::blind::Shown, u64)>, datum: &str, now_ms: u64) -> bool {
    last.is_none_or(|(d, shown, at)| d != datum || now_ms.saturating_sub(*at) >= look_interval(Some(shown)).as_millis() as u64)
}

impl R {
    /// Where this upstream's jobs are opened: as configured, or the gateway's API on the same host.
    fn api(&self) -> Option<String> {
        api_of(&self.datum, self.datum_api.as_deref(), self.bundled.as_deref(), self.upstream_flag.as_deref(), self.gateway_api.as_deref())
    }

    /// A rental ended: a failed first step counts against its seller, and anything else clears the count.
    fn note_rental_end(&mut self, seller: &str, report: &Value) {
        if xbt_hashlink::order::failed_first_step(report) {
            *self.failed_first.entry(seller.to_string()).or_default() += 1;
        } else {
            self.failed_first.remove(seller);
        }
        if let Some(d) = &self.state {
            let _ = std::fs::write(d.join("failed-first-steps.json"), serde_json::to_vec(&self.failed_first).unwrap_or_default());
        }
    }

    fn refused_seller(&self, seller: &str) -> bool {
        self.failed_first.get(seller).is_some_and(|n| *n >= xbt_hashlink::order::FAILED_FIRST_STEPS)
    }
}

/// A gateway's API: the one saved with it; `--gateway-api` for the bundled gateway and for `--upstream`
/// (or for whichever gateway, when neither is known); else its host's port 7152.
fn api_of(datum: &str, saved: Option<&str>, bundled: Option<&str>, upstream_flag: Option<&str>, flag_api: Option<&str>) -> Option<String> {
    if let Some(a) = saved.filter(|a| !a.is_empty()) {
        return Some(a.to_string());
    }
    let flagged = (bundled.is_none() && upstream_flag.is_none()) || bundled == Some(datum) || upstream_flag == Some(datum);
    if let Some(a) = flag_api.filter(|_| flagged) {
        return Some(a.to_string());
    }
    let host = datum.rsplit_once(':').map(|(h, _)| h)?;
    Some(format!("{host}:{GATEWAY_API_PORT}"))
}

/// The gateway that comes with the app: `--bundled-gateway`, else [`BUNDLED_STRATUM`] when the candidates list it.
fn bundled_of(f: &HashMap<String, String>, candidates: &[String]) -> Option<String> {
    f.get("bundled-gateway").filter(|b| !b.is_empty() && b.as_str() != "off").cloned().or_else(|| {
        if f.get("bundled-gateway").map(String::as_str) == Some("off") {
            return None;
        }
        candidates.iter().find(|c| c.as_str() == BUNDLED_STRATUM).cloned()
    })
}

/// Where the renter starts: the gateway, its API, and what the page is told about how it got there.
#[derive(Debug, Default, PartialEq)]
struct Start {
    datum: String,
    api: Option<String>,
    /// Moved to the bundled gateway from this one, at the upgrade that brought it.
    moved_from: Option<String>,
    /// The installer's settings changed since this gateway was chosen on the page, so theirs won.
    installer_won: Option<String>,
    /// `renter.json` to write, when it changes.
    write: Option<Value>,
}

/// The installer's answer as this start was given it: `--upstream` and `--bundled-gateway`, as they were set.
fn installer_of(f: &HashMap<String, String>) -> Value {
    json!({"upstream": f.get("upstream").cloned().unwrap_or_default(), "bundledGateway": f.get("bundled-gateway").cloned().unwrap_or_default()})
}

/// Which gateway to start with, from `renter.json` as saved and the installer's answer (`--upstream`, the bundled gateway).
///
/// - A gateway chosen on the page (`chosen`) wins only while the installer's `--upstream` and `--bundled-gateway` are
///   what they were when it was saved. If they changed, the installer's answer wins, and the page says so.
/// - A gateway set before this app came with one (saved without `chosen`, or named by `--upstream`) is left for the
///   bundled one, once: it can't open its jobs, and every rental to it would be refused. The page offers it back.
fn start_with(saved: Option<&Value>, upstream: &str, bundled: Option<&str>, installer: &Value) -> Start {
    let s = |k: &str| saved.and_then(|v| v[k].as_str()).map(str::to_string).filter(|x| !x.is_empty());
    let chosen = saved.is_some_and(|v| v["chosen"] == true);
    // a choice saved before the installer's answer was kept with it (none was released that way) counts as made under this one
    let same_installer = saved.map(|v| &v["installer"]).filter(|i| !i.is_null()).is_none_or(|i| i == installer);
    if chosen && same_installer {
        return Start { datum: s("datum").unwrap_or_default(), api: s("api"), ..Start::default() };
    }
    let now = xbt_hashlink::now_ms();
    if chosen {
        // the installer's answer changed since: it wins over the page's choice, which is offered back
        let was = s("datum").unwrap_or_default();
        let mut st = start_with(None, upstream, bundled, installer);
        st.installer_won = Some(was).filter(|w| !w.is_empty() && *w != st.datum);
        let mut w = st.write.take().unwrap_or_else(|| json!({"datum": st.datum}));
        w["installer"] = installer.clone();
        if let Some(x) = &st.installer_won {
            w["installerWon"] = json!(x);
            w["installerWonAtMs"] = json!(now);
        }
        st.write = Some(w);
        return st;
    }
    let (datum, api, moved, won) = (s("datum"), s("api"), s("movedFrom"), s("installerWon"));
    let set = datum.clone().or_else(|| Some(upstream.to_string()).filter(|u| !u.is_empty() && u != "auto"));
    match (set, bundled) {
        (Some(d), Some(b)) if d != b => Start {
            datum: b.to_string(),
            moved_from: Some(d.clone()),
            write: Some(json!({"datum": b, "movedFrom": d, "movedAtMs": now, "installer": installer})),
            ..Start::default()
        },
        _ if datum.is_some() => Start { datum: datum.unwrap_or_default(), api, moved_from: moved, installer_won: won, write: None },
        _ => Start { datum: upstream.to_string(), ..Start::default() },
    }
}

/// `host:port`, the port a number from 1 to 65535, the host a name or an address (`[…]` for IPv6).
fn host_port(s: &str) -> bool {
    let Some((h, p)) = s.rsplit_once(':') else { return false };
    let host_ok = !h.is_empty() && h.len() <= 253
        && (h.bytes().all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
            || (h.starts_with('[') && h.ends_with(']') && h[1..h.len() - 1].parse::<std::net::Ipv6Addr>().is_ok()));
    host_ok && p.parse::<u16>().is_ok_and(|p| p > 0)
}

/// Can a Stratum endpoint be reached (a TCP connection within a second)?
fn reachable(addr: &str) -> bool {
    addr.to_socket_addrs().ok().and_then(|mut a| a.next()).is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(1)).is_ok())
}

pub fn run(f: &HashMap<String, String>) -> Result<(), String> {
    let state = f.get("state").map(PathBuf::from);
    let saved = state.as_ref().and_then(|d| std::fs::read(d.join("renter.json")).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let candidates = f.get("datum-candidates").map(|c| super::relays(c)).unwrap_or_default();
    let bundled = bundled_of(f, &candidates);
    let upstream_flag = f.get("upstream").cloned().filter(|u| !u.is_empty() && u != "auto");
    let installer = installer_of(f);
    let Start { mut datum, api: datum_api, moved_from, installer_won, write } =
        start_with(saved.as_ref(), f.get("upstream").map(String::as_str).unwrap_or(""), bundled.as_deref(), &installer);
    if let (Some(w), Some(d)) = (&write, &state) {
        let _ = std::fs::write(d.join("renter.json"), w.to_string());
        if let Some(was) = &installer_won {
            eprintln!("hashtaker: the installer's settings changed since {was} was chosen on the page: rented work goes to {datum} now, as they say");
        } else if moved_from.is_some() {
            eprintln!("hashtaker: rented work now goes to the Stream Gateway that comes with this app, at {datum}; the gateway saved before is kept, to go back to");
        }
    }
    if datum.is_empty() || datum == "auto" {
        // the gateway that comes with the app, else a DATUM-compatible gateway on this box that answers at a known address
        datum = bundled.clone().or_else(|| candidates.iter().find(|a| reachable(a)).cloned()).unwrap_or_default();
    }
    let failed_first = state.as_ref().and_then(|d| std::fs::read(d.join("failed-first-steps.json")).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let r = Arc::new(Mutex::new(R {
        shown: None,
        failed_first,
        key: crate::hashmaker_service::key_file(super::need(f, "key")?)?,
        datum,
        datum_api,
        bundled,
        upstream_flag,
        moved_from,
        installer_won,
        installer,
        user: f.get("user").cloned().unwrap_or_else(|| "rented".into()),
        gateway_api: f.get("gateway-api").cloned(),
        allow_unblinded: f.contains_key("allow-unblinded"),
        relays: f.get("relays").map(|r| super::relays(r)).unwrap_or_default(),
        signer: f.get("signer").map(PathBuf::from),
        task: f.get("task").cloned().unwrap_or_else(|| "hashrate".into()),
        expect_node: f.get("expect-node").cloned(),
        state,
        offers: None,
        authors: HashMap::new(),
        history: None,
        rentals: BTreeMap::new(),
        iroh: None,
        iroh_off: f.get("iroh").map(String::as_str) == Some("off"),
        iroh_relays: f.get("iroh-relays").cloned(),
    }));
    let addr = super::need(f, "control")?.to_string();
    let token = f.get("control-token-file").map(|p| http::token(p)).transpose()?;
    {
        // what the upstream's jobs show, kept current for the renter's page: a pool that adds a key shows here by
        // itself, and no list says so
        let r = r.clone();
        std::thread::spawn(move || loop {
            let shown = look_at_upstream(&r);
            std::thread::sleep(look_interval(shown.as_ref()));
        });
    }
    http::serve(&addr, token, Arc::new(move |method, path, body| handle(&r, &candidates, method, path, body)))?;
    eprintln!("hashtaker: control page on {addr}");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn lock(r: &Mutex<R>) -> std::sync::MutexGuard<'_, R> {
    r.lock().unwrap_or_else(|p| p.into_inner())
}

/// What must be paid before the miners move: the start fee and a slice.
fn first_payment_msat(t: &xbt_hashlink::msg::Terms) -> u64 {
    t.price_msat.saturating_mul(t.start_slices.saturating_add(1))
}

fn offer_json(h: &Hashrate, event: &str) -> Value {
    json!({
        "name": h.name, "algorithm": h.algorithm, "linkKey": hex::encode(h.link_key.serialize()), "linkAddr": h.link_addr,
        "directLink": h.iroh.is_some(),
        "priceMsat": h.terms.price_msat, "sliceWork": h.terms.slice_work.to_string(), "graceMs": h.terms.grace_ms,
        "startSlices": h.terms.start_slices, "proves": h.proves(),
        "hashrateHs": h.hashrate_hs.to_string(), "payUrl": h.pay_url, "payNode": h.pay_node,
        "miners": h.capacity.miners, "freeMiners": h.capacity.free_miners, "freeHs": h.capacity.free_hs.to_string(), "event": event,
        // what a trial may leave the wallet for: a ticket of the first step and its fee limit.
        // A longer rental's tickets grow as they are earned, so no figure stands for them
        "trialMayBuyTicketUpToSats": xbt_hashlink::rail::caps_at(xbt_hashlink::order::FIRST_STEP_MSAT, h.terms.price_msat, Some(h.terms.price_msat.saturating_mul(h.terms.start_slices + 1)), None).0,
    })
}

fn offers(r: &Mutex<R>, fresh: bool) -> Vec<(Hashrate, String)> {
    {
        let g = lock(r);
        if let Some((t, o)) = &g.offers {
            if !fresh && t.elapsed() < OFFERS_FRESH {
                return o.clone();
            }
        }
    }
    let (relays, node) = {
        let g = lock(r);
        (g.relays.clone(), g.expect_node.clone())
    };
    let (found, _) = listing::find(&relays, xbt_nostr::now());
    let found: Vec<_> = found.into_iter().filter(|(h, _)| h.algorithm == "blake2b" && node.as_ref().is_none_or(|n| *n == h.pay_node)).collect();
    let mut g = lock(r);
    for (h, e) in &found {
        g.authors.insert(hex::encode(h.link_key.serialize()), e.pubkey.clone());
    }
    let o: Vec<(Hashrate, String)> = found.into_iter().map(|(h, e)| (h, e.id)).collect();
    g.offers = Some((Instant::now(), o.clone()));
    o
}

/// The delivery records and hashmakers' summaries on the relays (read at most once a minute).
fn history_events(r: &Mutex<R>) -> Vec<xbt_nostr::event::Event> {
    {
        let g = lock(r);
        if let Some((t, e)) = &g.history {
            if t.elapsed() < HISTORY_FRESH {
                return e.clone();
            }
        }
    }
    let relays = lock(r).relays.clone();
    let (events, _) = xbt_nostr::oneshot::query(&relays, &trust::filter(500), Duration::from_secs(10));
    lock(r).history = Some((Instant::now(), events.clone()));
    events
}

/// A listing's advertised speed for each machine: its free machines' speed shared out, or its
/// whole speed shared by its machines.
fn per_miner_hs(h: &Hashrate) -> u64 {
    let c = &h.capacity;
    if c.free_miners > 0 && c.free_hs > 0 {
        c.free_hs / c.free_miners as u64
    } else if c.miners > 0 {
        h.hashrate_hs / c.miners as u64
    } else {
        h.hashrate_hs
    }
}

/// A test slice's time limit: three times what one slice takes at the advertised speed, in minutes.
fn trial_minutes(slice_work: u128, hs: u64) -> u64 {
    if hs == 0 {
        return TRIAL_MAX_MINUTES;
    }
    let secs = (slice_work as f64 / hs as f64) * 3.0;
    ((secs / 60.0).ceil() as u64).clamp(TRIAL_MIN_MINUTES, TRIAL_MAX_MINUTES)
}

/// The bundled gateway, for the renter's page: whether it runs (its API answers), whether it has work from the
/// node (it hands out a job), and whether its jobs are masked. Looked at closely only while it is the one in use.
fn bundled_status(addr: &str, api: Option<&str>, in_use: bool, stratum: Option<bool>, blinding: Option<&Value>) -> Value {
    let running = api.is_some_and(reachable);
    let stratum = stratum.unwrap_or_else(|| reachable(addr));
    if !in_use {
        return json!({"addr": addr, "api": api, "inUse": false, "running": running || stratum, "node": null, "masking": false,
                      "state": if running || stratum { "not in use" } else { "not running" }, "mode": null});
    }
    // a job came back (masked or not): the gateway has a template, so it reaches the node
    let job = blinding.and_then(|b| b["state"].as_str()).map(|s| s != "can't be checked");
    let node = match (running || stratum, job) {
        (false, _) => Value::Null,
        (true, Some(j)) => json!(j),
        (true, None) => json!(false),
    };
    let masking = blinding.is_some_and(|b| b["state"] == "blinded");
    let state = if !running && !stratum {
        "not running"
    } else if node != json!(true) {
        "waiting for the node"
    } else if !masking {
        "not masking"
    } else {
        "masking"
    };
    json!({"addr": addr, "api": api, "inUse": in_use, "running": running || stratum, "node": node, "masking": masking, "state": state,
           "mode": blinding.filter(|_| masking).and_then(|b| b["why"].as_str())})
}

/// What the renter's page says for the bundled gateway in a state that has nothing to do with its jobs' masking.
fn bundled_words(state: &str) -> Option<&'static str> {
    match state {
        "not running" => Some("The Stream Gateway (DATUM-compatible) isn't running yet: it starts a few seconds after its settings are \
                               saved on the Hashrate page. Rentals wait for it, and nothing is paid"),
        "waiting for the node" => Some("The Stream Gateway (DATUM-compatible) is waiting for your node: it has no work from it yet. Check \
                                        that your XBT node is running and synced. Rentals wait for it, and nothing is paid"),
        _ => None,
    }
}

/// Look at what the upstream's jobs show, with no lock held for it.
fn look_at_upstream(r: &Mutex<R>) -> Option<xbt_hashlink::blind::Shown> {
    let (datum, api, user) = {
        let g = lock(r);
        (g.datum.clone(), g.api(), g.user.clone())
    };
    if datum.is_empty() {
        lock(r).shown = None;
        return None;
    }
    let shown = xbt_hashlink::blind::probe(&datum, api.as_deref(), &user);
    lock(r).shown = Some((datum, shown.clone(), xbt_hashlink::now_ms()));
    Some(shown)
}

fn handle(r: &Arc<Mutex<R>>, candidates: &[String], method: &str, path: &str, body: &[u8]) -> (u16, Value) {
    let b: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    match (method, path.split('?').next().unwrap_or("")) {
        ("GET", "/status") => {
            let g = lock(r);
            let datum = g.datum.clone();
            let rentals: Vec<Value> = g
                .rentals
                .iter()
                .rev()
                .map(|(id, x)| {
                    let live = x.live.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    let result = if live.get("meter").is_some() { trust::trial_result(&live, x.started_ms, xbt_hashlink::now_ms(), x.advertised_hs) } else { Value::Null };
                    json!({
                        "rental": id, "hasher": x.hashmaker, "startedMs": x.started_ms, "miners": x.miners, "budgetSats": x.budget_sats,
                        "minutes": x.minutes, "ended": x.done.load(Ordering::Relaxed), "live": live,
                        "trial": x.trial, "advertisedHs": x.advertised_hs.to_string(), "result": result, "attested": x.attested,
                    })
                })
                .collect();
            drop(g);
            let found: Vec<&String> = candidates.iter().filter(|a| reachable(a)).collect();
            // looked at again when the renter's page asks and the last look is old or of another gateway
            let stale = look_stale(lock(r).shown.as_ref(), &datum, xbt_hashlink::now_ms());
            if stale && !datum.is_empty() && reachable(&datum) {
                look_at_upstream(r);
            }
            let blinding = lock(r).shown.as_ref().filter(|(for_datum, ..)| *for_datum == datum).map(|(_, shown, at)| {
                let mut v = shown.to_json();
                v["checkedMs"] = json!(at);
                v
            });
            let datum_reachable = !datum.is_empty() && reachable(&datum);
            let (bundled, moved_from, installer_won, api) = {
                let g = lock(r);
                let bundled_api = g.bundled.as_deref().and_then(|b| api_of(b, None, g.bundled.as_deref(), g.upstream_flag.as_deref(), g.gateway_api.as_deref()));
                (g.bundled.clone().map(|b| (b, bundled_api)), g.moved_from.clone(), g.installer_won.clone(), g.api())
            };
            let bundled = bundled.map(|(b, bapi)| {
                let in_use = b == datum;
                bundled_status(&b, bapi.as_deref(), in_use, if in_use { Some(datum_reachable) } else { None }, if in_use { blinding.as_ref() } else { None })
            });
            // the bundled gateway not up yet, or up with no work from the node: said as that, not as a job that
            // can't be checked at an address that doesn't answer
            let blinding = match bundled.as_ref().filter(|b| b["inUse"] == true).and_then(|b| bundled_words(b["state"].as_str().unwrap_or(""))) {
                Some(w) => Some(json!({"state": "can't be checked", "why": w, "words": w, "bundled": true})),
                None => blinding,
            };
            (200, json!({
                "role": "renter", "datum": {"addr": datum, "api": api, "reachable": datum_reachable, "found": found, "movedFrom": moved_from,
                          "installerWon": installer_won},
                "bundled": bundled, "blinding": blinding,
                "relays": lock(r).relays.len(), "wallet": lock(r).signer.is_some(), "rentals": rentals,
            }))
        }
        ("GET", "/offers") => {
            let o = offers(r, path.contains("fresh=1"));
            let events = history_events(r);
            let authors = lock(r).authors.clone();
            let list: Vec<Value> = o
                .iter()
                .map(|(h, e)| {
                    let mut v = offer_json(h, e);
                    let author = authors.get(&hex::encode(h.link_key.serialize())).cloned().unwrap_or_default();
                    v["history"] = trust::aggregate(&h.link_key, &author, per_miner_hs(h), &events);
                    v["perMinerHs"] = json!(per_miner_hs(h).to_string());
                    v
                })
                .collect();
            (200, json!({"offers": list}))
        }
        ("POST", "/attest") => attest(r, &b),
        ("POST", "/datum") => {
            let a = b["addr"].as_str().unwrap_or("").trim().to_string();
            if !host_port(&a) {
                return (400, json!({"error": "the address is host:port, its port a number"}));
            }
            let api = b["api"].as_str().map(str::trim).filter(|x| !x.is_empty()).map(str::to_string);
            if api.as_ref().is_some_and(|x| !host_port(x)) {
                return (400, json!({"error": "the gateway's API address is host:port, its port a number"}));
            }
            let mut g = lock(r);
            g.datum = a.clone();
            g.datum_api = api.clone();
            // chosen here: kept across restarts and upgrades, while the installer's answer stays what it is now
            g.moved_from = None;
            g.installer_won = None;
            // a look at another gateway's jobs is not this one's
            g.shown = None;
            if let Some(d) = &g.state {
                let _ = std::fs::create_dir_all(d);
                let mut saved = json!({"datum": a, "chosen": true, "installer": g.installer});
                if let Some(x) = &api {
                    saved["api"] = json!(x);
                }
                let _ = std::fs::write(d.join("renter.json"), saved.to_string());
            }
            (200, json!({"ok": true, "datum": a, "reachable": reachable(&a), "bundled": g.bundled.as_deref() == Some(a.as_str())}))
        }
        ("POST", "/cut") => {
            let id = b["rental"].as_str().unwrap_or("");
            match lock(r).rentals.get(id) {
                Some(x) => {
                    x.cut.store(true, Ordering::Relaxed);
                    (200, json!({"ok": true}))
                }
                None => (404, json!({"error": "no such rental"})),
            }
        }
        ("POST", "/rent") => rent(r, &b),
        _ => (404, json!({"error": "GET /status, GET /offers, POST /rent, POST /cut, POST /datum, POST /attest"})),
    }
}

fn rent(r: &Arc<Mutex<R>>, b: &Value) -> (u16, Value) {
    let key_hex = b["linkKey"].as_str().unwrap_or("");
    let trial = b["trial"] == true;
    if lock(r).refused_seller(key_hex) {
        return (409, json!({"error": "this hashmaker took your first payment twice and delivered little: this app won't pay it again"}));
    }
    let mut miners = b["miners"].as_u64().unwrap_or(1).clamp(1, 1000) as u32;
    let mut budget_sats = b["budgetSats"].as_u64().unwrap_or(0);
    let mut minutes = b["minutes"].as_u64().unwrap_or(60).clamp(1, 7 * 24 * 60);
    if budget_sats == 0 && !trial {
        return (400, json!({"error": "set a budget: the most this rental may cost, in sats"}));
    }
    let datum = lock(r).datum.clone();
    if datum.is_empty() {
        return (400, json!({"error": "no gateway set: rented hashrate goes to your own gateway"}));
    }
    // the bundled gateway's own words when it isn't up, or has no work from the node yet
    let bundled_said = |shown: Option<&Value>| -> Option<&'static str> {
        let g = lock(r);
        if g.bundled.as_deref() != Some(datum.as_str()) {
            return None;
        }
        let api = g.api();
        drop(g);
        bundled_words(bundled_status(&datum, api.as_deref(), true, None, shown)["state"].as_str().unwrap_or(""))
    };
    if !reachable(&datum) {
        let e = bundled_said(None).map(str::to_string).unwrap_or_else(|| format!("your gateway at {datum} does not answer"));
        return (400, json!({"error": e}));
    }
    // looked at again now: this is the money's last chance to stay home
    let allow_unblinded = lock(r).allow_unblinded;
    if !allow_unblinded {
        match look_at_upstream(r) {
            Some(shown) if !shown.may_rent() => {
                let j = shown.to_json();
                let e = bundled_said(Some(&j)).map(str::to_string).unwrap_or_else(|| shown.words());
                return (409, json!({"error": e, "blinding": j}));
            }
            _ => {}
        }
    }
    let pick = |o: Vec<(Hashrate, String)>| o.into_iter().find(|(h, _)| hex::encode(h.link_key.serialize()) == key_hex);
    let Some((h, event)) = pick(offers(r, false)).or_else(|| pick(offers(r, true))) else {
        return (404, json!({"error": "that hashmaker's listing is no longer on the relays"}));
    };
    if !h.proves() {
        return (400, json!({"error": "this hashmaker's app doesn't prove the work it sells: it needs updating"}));
    }
    if trial {
        // one machine, one slice: the budget is one slice's price with the start fee, and the time a few slices' worth
        miners = 1;
        budget_sats = first_payment_msat(&h.terms).div_ceil(1000);
        minutes = trial_minutes(h.terms.slice_work, per_miner_hs(&h));
    }
    let advertised_hs = per_miner_hs(&h).saturating_mul(miners as u64);
    if first_payment_msat(&h.terms) > budget_sats.saturating_mul(1000) {
        return (400, json!({"error": if h.terms.start_slices > 0 { "the budget is less than the start fee and one slice" } else { "the budget is less than one slice" }}));
    }
    // over iroh when the listing offers it (no port forward needed on the hashmaker's side), else over
    // TCP to the address it names
    let addr = match &h.iroh {
        Some(i) => match dialer(r) {
            Some(d) => match d.address_for(i) {
                Ok(a) => a,
                Err(e) => return (502, json!({"error": format!("the direct link to that hashmaker did not open: {e}")})),
            },
            None if !h.link_addr.is_empty() => h.link_addr.clone(),
            None => return (502, json!({"error": "that hashmaker is reached only over a direct link, and this app's direct link is off or did not start"})),
        },
        None => h.link_addr.clone(),
    };
    let id = format!("r{}", xbt_hashlink::now_ms());
    let live = Arc::new(Mutex::new(json!({"closed": null})));
    let cut = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let (key, user, signer, task, gateway_api, allow_unblinded) = {
        let g = lock(r);
        (g.key, g.user.clone(), g.signer.clone(), g.task.clone(), g.api(), g.allow_unblinded)
    };
    // the first ticket, the first step's: later ones grow as they are earned, inside the budget
    let first_ticket = xbt_hashlink::rail::caps_at(xbt_hashlink::order::FIRST_STEP_MSAT, h.terms.price_msat, Some(budget_sats.saturating_mul(1000)), None).1.unwrap_or(0);
    let payer = signer.map(|sock| SignerPayer::new(sock, h.pay_url.clone(), task, h.terms.price_msat, Some(budget_sats), None,
                                                   std::time::Duration::from_millis(h.terms.grace_ms / 2)));
    let cfg = hashtaker::Config {
        hashmaker: addr,
        hashmaker_key: h.link_key,
        key,
        upstream: datum,
        user,
        terms: h.terms.clone(),
        rental: id.clone(),
        listing: event,
        stop_paying_after: None,
        idle: Duration::from_secs(180),
        duration: Some(Duration::from_secs(minutes * 60)),
        report: None,
        payer: payer.map(|p| Box::new(p) as Box<dyn xbt_hashlink::rail::Payer>),
        miners,
        budget_msat: Some(budget_sats * 1000),
        cut: Some(cut.clone()),
        live: Some(live.clone()),
        gateway_api: gateway_api.clone(),
        allow_unblinded,
    };
    {
        let mut g = lock(r);
        if g.rentals.len() >= KEPT {
            if let Some(old) = g.rentals.iter().find(|(_, x)| x.done.load(Ordering::Relaxed)).map(|(k, _)| k.clone()) {
                g.rentals.remove(&old);
            }
        }
        g.rentals.insert(id.clone(), Rental {
            hashmaker: h.name.clone(),
            hashmaker_key: h.link_key,
            advertised_hs,
            trial,
            attested: None,
            started_ms: xbt_hashlink::now_ms(),
            miners,
            budget_sats,
            minutes,
            live: live.clone(),
            cut,
            done: done.clone(),
        });
    }
    let hashmaker_key: PublicKey = h.link_key;
    let service = r.clone();
    std::thread::spawn(move || {
        let res = hashtaker::run(cfg, Box::<LabHashtaker>::default());
        match res {
            Err(e) => *live.lock().unwrap_or_else(|p| p.into_inner()) = json!({"closed": format!("could not start: {e}")}),
            Ok(report) => lock(&service).note_rental_end(&hex::encode(hashmaker_key.serialize()), &report),
        }
        done.store(true, Ordering::Relaxed);
        eprintln!("hashtaker: rental with {} ended", hex::encode(hashmaker_key.serialize()));
    });
    // the rental may buy the shop's ticket: what of it the slices do not use stays with that shop as credit
    (200, json!({"ok": true, "rental": id, "trial": trial, "budgetSats": budget_sats, "minutes": minutes, "mayBuyTicketUpToSats": first_ticket}))
}

/// Publish the signed delivery record of a rental that ended (the hashtaker's choice, per rental).
fn attest(r: &Arc<Mutex<R>>, b: &Value) -> (u16, Value) {
    let id = b["rental"].as_str().unwrap_or("").to_string();
    let (key, relays, x) = {
        let g = lock(r);
        let Some(x) = g.rentals.get(&id) else { return (404, json!({"error": "no such rental"})) };
        if !x.done.load(Ordering::Relaxed) {
            return (400, json!({"error": "the rental has not ended yet"}));
        }
        let live = x.live.lock().unwrap_or_else(|p| p.into_inner()).clone();
        (g.key, g.relays.clone(), (live, x.started_ms, x.hashmaker_key, x.advertised_hs, x.trial))
    };
    if relays.is_empty() {
        return (400, json!({"error": "no Nostr relays are set"}));
    }
    let (live, started, maker, adv, trial) = x;
    let me = PublicKey::from_secret_key(secp256k1::SECP256K1, &key);
    let Some(a) = trust::attestation_of(&live, &id, started, &me, &maker, adv, trial, xbt_nostr::now()) else {
        return (400, json!({"error": "this rental has nothing to record"}));
    };
    if a.paid_slices == 0 {
        return (400, json!({"error": "nothing was paid in this rental, so there is nothing to record"}));
    }
    let ev = match a.event(&key, xbt_nostr::now()) {
        Ok(e) => e,
        Err(e) => return (500, json!({"error": e})),
    };
    let out = listing::publish(&relays, &ev);
    let ok = out.iter().any(|o| o["ok"] == true);
    let result = json!({"ok": ok, "relays": out, "commit": a.commit, "atMs": xbt_hashlink::now_ms()});
    if let Some(x) = lock(r).rentals.get_mut(&id) {
        x.attested = Some(result.clone());
    }
    // read again next time: the new record is on the relays now
    lock(r).history = None;
    (if ok { 200 } else { 502 }, result)
}

/// The iroh link to hashmakers, started once.
fn dialer(r: &Mutex<R>) -> Option<Arc<Dialer>> {
    let mut g = lock(r);
    if g.iroh.is_none() {
        let d = if g.iroh_off {
            None
        } else {
            match Dialer::start(over_iroh::relays(g.iroh_relays.as_deref())) {
                Ok(d) => Some(Arc::new(d)),
                Err(e) => {
                    eprintln!("hashtaker: the iroh link did not start: {e}");
                    None
                }
            }
        };
        g.iroh = Some(d);
    }
    g.iroh.clone().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_slice_takes_a_few_slices_time_within_bounds() {
        // a slice of 2^47 hashes at 4 TH/s takes about 35 s: three of them is under the floor
        assert_eq!(trial_minutes(1 << 47, 4_000_000_000_000), TRIAL_MIN_MINUTES);
        // at 0.1 TH/s about 23 minutes a slice: three of them is past the ceiling
        assert_eq!(trial_minutes(1 << 47, 100_000_000_000), TRIAL_MAX_MINUTES);
        assert_eq!(trial_minutes(1 << 47, 1_000_000_000_000), 8);
        assert_eq!(trial_minutes(1 << 47, 0), TRIAL_MAX_MINUTES);
    }

    const B: Option<&str> = Some(BUNDLED_STRATUM);

    /// The installer's answer as a start is given it.
    fn inst(upstream: &str, bundled: &str) -> Value {
        json!({"upstream": upstream, "bundledGateway": bundled})
    }

    /// An install from before the app had its own gateway is moved to it once, at start, and keeps the address it
    /// had, to go back to; one chosen on the page since is kept; a box without the bundled gateway is left as it was.
    #[test]
    fn an_old_gateway_is_left_for_the_bundled_one_once_and_a_chosen_one_is_kept() {
        let auto = inst("auto", "");
        // saved by 0.1.x: stock upstream, no `chosen`
        let old = json!({"datum": "datum_web_1:23334"});
        let st = start_with(Some(&old), "auto", B, &auto);
        assert_eq!((st.datum.as_str(), st.api.as_deref(), st.moved_from.as_deref()), (BUNDLED_STRATUM, None, Some("datum_web_1:23334")));
        let w = st.write.expect("renter.json is rewritten");
        assert_eq!((&w["datum"], &w["movedFrom"], &w["installer"]), (&json!(BUNDLED_STRATUM), &json!("datum_web_1:23334"), &auto));
        assert!(w.get("chosen").is_none());
        // the next start keeps it there and still knows where it came from, with nothing to write
        let st = start_with(Some(&w), "auto", B, &auto);
        assert_eq!((st.datum.as_str(), st.moved_from.as_deref(), st.write), (BUNDLED_STRATUM, Some("datum_web_1:23334"), None));
        // "use it again" on the page saves it as chosen, with the installer's answer: kept from then on
        let chosen = json!({"datum": "datum_web_1:23334", "chosen": true, "api": "datum_web_1:7152", "installer": auto});
        assert_eq!(start_with(Some(&chosen), "auto", B, &auto),
                   Start { datum: "datum_web_1:23334".into(), api: Some("datum_web_1:7152".into()), ..Start::default() });
        // a Linux install whose settings still name its own gateway from before (--upstream) moves the same way
        let st = start_with(None, "127.0.0.1:23334", B, &inst("127.0.0.1:23334", ""));
        assert_eq!((st.datum.as_str(), st.moved_from.as_deref()), (BUNDLED_STRATUM, Some("127.0.0.1:23334")));
        assert!(st.write.is_some());
        // a fresh install: the bundled gateway (auto finds it first)
        assert_eq!(start_with(None, "auto", B, &auto).datum, "auto");
        assert_eq!(start_with(None, BUNDLED_STRATUM, B, &inst(BUNDLED_STRATUM, "")), Start { datum: BUNDLED_STRATUM.into(), ..Start::default() });
        // no bundled gateway on this box (or the installer said --bundled-gateway off): nothing moves
        assert_eq!(start_with(Some(&old), "auto", None, &auto), Start { datum: "datum_web_1:23334".into(), ..Start::default() });
        assert_eq!(start_with(None, "10.0.0.5:23334", None, &inst("10.0.0.5:23334", "off")).datum, "10.0.0.5:23334");
    }

    /// A page's choice wins only while the installer's `--upstream` and `--bundled-gateway` are what they were when it was
    /// saved. When either changes, the installer's answer wins, the page is told which choice it overrode, and choosing it
    /// again on the page keeps it under the new answer.
    #[test]
    fn a_changed_installer_answer_wins_over_an_older_page_choice() {
        let own = inst("10.0.0.5:23334", "off");
        let bundled_now = inst("127.0.0.1:23339", "127.0.0.1:23339");
        // chosen on the page (the bundled gateway) while the installer said "my own, no bundled"
        let page = json!({"datum": BUNDLED_STRATUM, "chosen": true, "installer": own});
        // unchanged: the page's choice
        assert_eq!(start_with(Some(&page), "10.0.0.5:23334", None, &own).datum, BUNDLED_STRATUM);
        // the installer is run again and answers its own gateway at another address: the installer wins
        let own2 = inst("10.0.0.6:23334", "off");
        let st = start_with(Some(&page), "10.0.0.6:23334", None, &own2);
        assert_eq!((st.datum.as_str(), st.installer_won.as_deref(), st.moved_from.as_deref()), ("10.0.0.6:23334", Some(BUNDLED_STRATUM), None));
        let w = st.write.expect("renter.json is rewritten");
        assert_eq!((&w["datum"], &w["installerWon"], &w["installer"]), (&json!("10.0.0.6:23334"), &json!(BUNDLED_STRATUM), &own2));
        assert!(w.get("chosen").is_none(), "no longer a page choice");
        // the next start keeps the installer's answer and still says which choice it overrode
        let again = start_with(Some(&w), "10.0.0.6:23334", None, &own2);
        assert_eq!((again.datum.as_str(), again.installer_won.as_deref(), again.write), ("10.0.0.6:23334", Some(BUNDLED_STRATUM), None));
        // a page choice of the owner's gateway, then the installer switches to the bundled one (--bundled-gateway changes)
        let mine = json!({"datum": "10.0.0.5:23334", "api": "10.0.0.5:7160", "chosen": true, "installer": own});
        let st = start_with(Some(&mine), "127.0.0.1:23339", B, &bundled_now);
        assert_eq!((st.datum.as_str(), st.api, st.installer_won.as_deref()), (BUNDLED_STRATUM, None, Some("10.0.0.5:23334")));
        // only --bundled-gateway changed: still the installer's
        let st = start_with(Some(&mine), "10.0.0.5:23334", B, &inst("10.0.0.5:23334", "127.0.0.1:23339"));
        assert_eq!(st.installer_won.as_deref(), Some("10.0.0.5:23334"));
        assert_eq!(st.datum, BUNDLED_STRATUM, "a gateway named by --upstream beside the bundled one is moved to it, as at an upgrade");
        // the installer's answer is the same gateway the page chose: nothing to say
        let st = start_with(Some(&json!({"datum": "10.0.0.6:23334", "chosen": true, "installer": own})), "10.0.0.6:23334", None, &own2);
        assert_eq!((st.datum.as_str(), st.installer_won), ("10.0.0.6:23334", None));
    }

    #[test]
    fn the_bundled_gateway_is_found_by_its_address_or_named() {
        let f = |kv: &[(&str, &str)]| kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>();
        let c = vec!["127.0.0.1:23339".to_string(), "datum_web_1:23334".to_string()];
        assert_eq!(bundled_of(&f(&[]), &c).as_deref(), Some(BUNDLED_STRATUM));
        assert_eq!(bundled_of(&f(&[]), &c[1..]), None);
        assert_eq!(bundled_of(&f(&[("bundled-gateway", "127.0.0.1:24000")]), &c).as_deref(), Some("127.0.0.1:24000"));
        assert_eq!(bundled_of(&f(&[("bundled-gateway", "off")]), &c), None);
    }

    /// `--gateway-api` is the bundled gateway's API (7153 on Linux); another gateway's is its own host's 7152, or the
    /// one saved with it.
    #[test]
    fn each_gateway_is_opened_on_its_own_api() {
        let linux = Some("127.0.0.1:7153");
        assert_eq!(api_of(BUNDLED_STRATUM, None, B, None, linux).as_deref(), Some("127.0.0.1:7153"));
        assert_eq!(api_of(BUNDLED_STRATUM, None, B, None, None).as_deref(), Some("127.0.0.1:7152"));
        assert_eq!(api_of("192.0.2.7:23334", None, B, None, linux).as_deref(), Some("192.0.2.7:7152"));
        assert_eq!(api_of("192.0.2.7:23334", Some("192.0.2.7:7160"), B, None, linux).as_deref(), Some("192.0.2.7:7160"));
        // the gateway --upstream names keeps --gateway-api, as before; so does any, on a box with neither known
        assert_eq!(api_of("192.0.2.7:23334", None, B, Some("192.0.2.7:23334"), Some("192.0.2.7:9000")).as_deref(), Some("192.0.2.7:9000"));
        assert_eq!(api_of("192.0.2.7:23334", None, None, None, Some("192.0.2.7:9000")).as_deref(), Some("192.0.2.7:9000"));
    }

    #[test]
    fn the_bundled_gateways_state_reads_from_what_answers_and_what_its_jobs_show() {
        // nothing listens on these
        let dead = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), true, Some(false), None);
        assert_eq!((dead["state"].as_str(), &dead["running"], &dead["node"]), (Some("not running"), &json!(false), &Value::Null));
        // its Stratum answers, and it gave no job: it has no work from the node yet
        let waiting = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), true, Some(true),
                                     Some(&json!({"state": "can't be checked", "why": "127.0.0.1:23339 gave no job to look at"})));
        assert_eq!((waiting["state"].as_str(), &waiting["node"], &waiting["masking"]), (Some("waiting for the node"), &json!(false), &json!(false)));
        let masked = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), true, Some(true), Some(&json!({"state": "blinded", "why": "solo"})));
        assert_eq!((masked["state"].as_str(), &masked["node"], &masked["masking"], masked["mode"].as_str()), (Some("masking"), &json!(true), &json!(true), Some("solo")));
        let unmasked = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), true, Some(true), Some(&json!({"state": "not blinded", "why": "its key is null"})));
        assert_eq!((unmasked["state"].as_str(), &unmasked["node"]), (Some("not masking"), &json!(true)));
        let other = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), false, None, None);
        assert_eq!((other["state"].as_str(), &other["inUse"]), (Some("not running"), &json!(false)));
    }

    /// A gateway whose jobs weren't shown masked is looked at again within 5 s, so its coming back shows on the page at
    /// once; one that shows them masked, every minute.
    #[test]
    fn a_gateway_not_yet_masked_is_looked_at_again_within_seconds() {
        use xbt_hashlink::blind::Shown;
        let blinded = Shown::Blinded("solo".into());
        let unchecked = Shown::Unverifiable("127.0.0.1:23339 doesn't answer".into());
        let unmasked = Shown::NotBlinded("its key is null".into());
        assert_eq!(look_interval(Some(&blinded)), Duration::from_secs(60));
        for s in [&unchecked, &unmasked] {
            assert_eq!(look_interval(Some(s)), Duration::from_secs(5));
        }
        assert_eq!(look_interval(None), Duration::from_secs(5), "no gateway, or no look yet");
        let d = BUNDLED_STRATUM;
        let at = 1_000_000u64;
        // "can't be checked" 6 s ago: looked at again when the page asks
        let last = (d.to_string(), unchecked.clone(), at);
        assert!(!look_stale(Some(&last), d, at + 4_999));
        assert!(look_stale(Some(&last), d, at + 5_000));
        // masked 6 s ago: kept for the minute
        let last = (d.to_string(), blinded.clone(), at);
        assert!(!look_stale(Some(&last), d, at + 6_000));
        assert!(!look_stale(Some(&last), d, at + 59_999));
        assert!(look_stale(Some(&last), d, at + 60_000));
        // another gateway's look, or none: stale
        assert!(look_stale(Some(&last), "192.0.2.7:23334", at + 1));
        assert!(look_stale(None, d, at));
    }

    /// The bundled gateway up (its API answers) with no Stratum yet, its old look saying "doesn't answer": the status says
    /// it waits for the node, in the gateway's words; with nothing up at all, that it isn't running.
    #[test]
    fn a_bundled_gateway_waiting_for_its_node_is_said_as_that() {
        let api = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api_addr = api.local_addr().unwrap().to_string();
        // a Stratum port nothing listens on
        let stratum = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        let r = test_r(&stratum, Some(api_addr.clone()));
        lock(&r).shown = Some((stratum.clone(), xbt_hashlink::blind::Shown::Unverifiable(format!("{stratum} doesn't answer")), xbt_hashlink::now_ms()));
        let (_, st) = handle(&r, &[], "GET", "/status", b"");
        assert_eq!(st["bundled"]["state"], "waiting for the node", "{st}");
        let words = st["blinding"]["words"].as_str().unwrap();
        assert!(words.contains("is waiting for your node") && !words.contains("doesn't answer") && !words.contains("can't be checked"), "{words}");
        assert_eq!(st["blinding"]["state"], "can't be checked", "renting still waits");
        // a rent asked for anyway is refused in the same words
        let (code, v) = handle(&r, &[], "POST", "/rent", br#"{"linkKey": "02bb", "budgetSats": 100}"#);
        assert_eq!(code, 400);
        assert!(v["error"].as_str().unwrap().contains("waiting for your node"), "{v}");
        // nothing up: not running
        drop(api);
        let (_, st) = handle(&r, &[], "GET", "/status", b"");
        assert_eq!(st["bundled"]["state"], "not running");
        assert!(st["blinding"]["words"].as_str().unwrap().contains("isn't running yet"));
        // another gateway in use: its own look's words, untouched
        lock(&r).datum = "127.0.0.1:1".into();
        let (_, st) = handle(&r, &[], "GET", "/status", b"");
        assert!(st["blinding"].is_null() || st["blinding"]["bundled"].is_null(), "{st}");
    }

    fn test_r(bundled: &str, api: Option<String>) -> Arc<Mutex<R>> {
        Arc::new(Mutex::new(R {
            key: SecretKey::from_slice(&[7u8; 32]).unwrap(),
            datum: bundled.into(),
            datum_api: None,
            bundled: Some(bundled.into()),
            upstream_flag: None,
            moved_from: None,
            installer_won: None,
            installer: inst("auto", ""),
            user: "rented".into(),
            gateway_api: api,
            allow_unblinded: false,
            relays: vec![],
            signer: None,
            task: "hashrate".into(),
            expect_node: None,
            state: None,
            offers: None,
            authors: HashMap::new(),
            history: None,
            rentals: BTreeMap::new(),
            iroh: None,
            iroh_off: true,
            iroh_relays: None,
            failed_first: BTreeMap::new(),
            shown: None,
        }))
    }

    /// The page's switch: choosing a gateway saves it as chosen (kept across upgrades, under the same installer's answer),
    /// with its API when one is given, and forgets the move.
    #[test]
    fn choosing_a_gateway_on_the_page_keeps_it_with_its_api() {
        let dir = std::env::temp_dir().join(format!("hashtaker-choose-{}-{}", std::process::id(), xbt_hashlink::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let r = test_r(BUNDLED_STRATUM, None);
        {
            let mut g = lock(&r);
            g.state = Some(dir.clone());
            g.moved_from = Some("datum_web_1:23334".into());
            g.installer = inst("auto", "");
        }
        let (code, v) = handle(&r, &[], "POST", "/datum", br#"{"addr": "datum_web_1:23334"}"#);
        assert_eq!((code, &v["bundled"]), (200, &json!(false)));
        let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("renter.json")).unwrap()).unwrap();
        assert_eq!(saved, json!({"datum": "datum_web_1:23334", "chosen": true, "installer": inst("auto", "")}));
        assert!(lock(&r).moved_from.is_none());
        assert_eq!(lock(&r).api().as_deref(), Some("datum_web_1:7152"), "no API given: its host's 7152");
        assert_eq!(start_with(Some(&saved), "auto", B, &inst("auto", "")).datum, "datum_web_1:23334", "kept at the next start");
        // a gateway whose API is elsewhere: saved with it, and the renter opens its jobs there
        let (code, _) = handle(&r, &[], "POST", "/datum", br#"{"addr": "192.0.2.7:23334", "api": "192.0.2.8:7160"}"#);
        assert_eq!(code, 200);
        assert_eq!(lock(&r).api().as_deref(), Some("192.0.2.8:7160"));
        let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("renter.json")).unwrap()).unwrap();
        assert_eq!(saved["api"], "192.0.2.8:7160");
        let st = start_with(Some(&saved), "auto", B, &inst("auto", ""));
        assert_eq!((st.datum.as_str(), st.api.as_deref()), ("192.0.2.7:23334", Some("192.0.2.8:7160")), "and after a restart");
        // and back: the bundled gateway, chosen, on its own API
        let (code, v) = handle(&r, &[], "POST", "/datum", format!(r#"{{"addr": "{BUNDLED_STRATUM}"}}"#).as_bytes());
        assert_eq!((code, &v["bundled"]), (200, &json!(true)));
        assert_eq!(lock(&r).api().as_deref(), Some("127.0.0.1:7152"));
        // addresses that aren't host:port are refused, and change nothing
        for bad in [r#"{"addr": "x:1", "api": "nocolon"}"#, r#"{"addr": "x:1", "api": "x:port"}"#, r#"{"addr": "x:1", "api": "x:0"}"#,
                    r#"{"addr": "x:1", "api": "x:70000"}"#, r#"{"addr": "x:1", "api": "a b:7152"}"#, r#"{"addr": "nocolon"}"#, r#"{"addr": ":23334"}"#] {
            assert_eq!(handle(&r, &[], "POST", "/datum", bad.as_bytes()).0, 400, "{bad}");
        }
        assert_eq!(lock(&r).datum, BUNDLED_STRATUM);
        assert!(host_port("[::1]:7152") && host_port("datum-gateway_web_1:7152") && !host_port("[nope]:7152"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
