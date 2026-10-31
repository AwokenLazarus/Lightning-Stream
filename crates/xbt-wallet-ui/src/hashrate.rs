//! Hashrate, as one more kind of service.
//!
//! Sell → Hashrate (`XBT_UI_HASHER`): the owner rents out this box's miners. Miners point at the
//! app once; any miner nobody rents hashes for the owner's own pool or DATUM Gateway. The page
//! writes the hasher service's settings file, shows each miner and each rental, and stops a
//! rental. Renters pay each piece of work through this box's shop, which sells it under
//! `/hashrate/` (the route [`App::hash_route`] adds).
//!
//! Services → Hashrate (`XBT_UI_HASHRENT`): the owner rents other people's miners into their own
//! DATUM Gateway (the pool is chosen there, not here), with a budget, and can cut a rental at any
//! time. Rentals also show on Live connections.
//!
//! Both talk to their service's control page on the box's own network, with its token.
//!
//! **The hashmaker's price.** By default a piece of work costs what it is worth when mined at the chain's
//! difficulty now, `subsidy * work / (difficulty * 2^32)`, at a percent the owner sets (100%). Of the services on the
//! box only the signer reads the XBT node, so the difficulty and the block reward come from it (`mining_tip`). A
//! piece is about one share of the fastest miner here, and a renter pays a start fee, in whole pieces, before the
//! miners move. The price is worked out here, written into the hasher's settings and into the shop's route for
//! paid pieces, which must say the same: a new price waits (`holdNew`, no new rental) until the rentals going on
//! end, since the shop restarts to charge it and a rental keeps the terms it was made with
//! ([`App::hash_reprice`]). No live price: no new rental; a price the owner typed needs none.
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

use super::{App, Ctx};
use crate::html::{esc, short};
use crate::server::Resp;

const WAIT: Duration = Duration::from_secs(6);
/// What a rental pays before the miners move, in seconds of their work: it pays for moving them. The S11
/// run sets the real value.
pub const START_FEE_SECONDS: f64 = 12.0;
/// A piece of work is about one share: a gateway's vardiff aims at 8 shares a minute.
const SHARE_SECONDS: f64 = 7.5;
/// The miner speed estimates are given for, and pieces are sized to until a miner has hashed here: an S11.
const EXAMPLE_HS: f64 = 4e12;
/// The default price: what the work is worth when mined, in percent.
pub const MARKET_PCT: u64 = 100;
/// The smallest piece of work.
const MIN_SLICE_WORK: u128 = 1 << 32;
/// A node whose tip is older than this has stopped following the chain: its difficulty is not today's.
const TIP_MAX_AGE_S: u64 = 24 * 3600;
/// How often a live price is confirmed in the settings at most (the hasher takes no new rental after an
/// hour without).
const PRICE_CONFIRM_MS: u64 = 600_000;
/// A piece keeps its size until one share moves this far from it, in powers of two: a wobbling speed
/// changes nothing.
const SLICE_STAYS: f64 = 0.8;
/// The price this page once suggested: a settings file that has it was not priced by its owner.
const OLD_SUGGESTED_SAT: u64 = 40;
/// The piece of work of a settings file from before pieces were sized to the miners.
const OLD_SLICE_WORK: u128 = 1 << 47;

/// The chain's tip, as a price follows it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tip {
    pub difficulty: f64,
    pub subsidy_sats: u64,
    pub height: u64,
}

/// The signer's `mining_tip`, checked: a tip a price can follow, or why not, in the owner's words.
pub fn tip_of(v: &Value, now_s: u64) -> Result<Tip, String> {
    if v["reachable"] != true {
        return Err("your XBT node does not answer".into());
    }
    let difficulty = v["difficulty"].as_f64().filter(|d| d.is_finite() && *d > 0.0).ok_or("your XBT node did not say the difficulty")?;
    let subsidy_sats = v["subsidySats"].as_u64().filter(|s| *s > 0).ok_or("your XBT node did not say the block reward")?;
    let height = v["height"].as_u64().ok_or("your XBT node did not say its height")?;
    if v["syncing"] != false || v["headers"].as_u64().is_some_and(|h| h > height + 1) {
        return Err("your XBT node is still catching up with the chain".into());
    }
    if v["tipTime"].as_u64().is_none_or(|t| now_s.saturating_sub(t) > TIP_MAX_AGE_S) {
        return Err("your XBT node has seen no new block for over a day".into());
    }
    Ok(Tip { difficulty, subsidy_sats, height })
}

/// What `work` hashes are worth when mined at `tip`, in sats.
pub fn worth_sat(work: u128, tip: &Tip) -> f64 {
    tip.subsidy_sats as f64 * work as f64 / (tip.difficulty * 4_294_967_296.0)
}

/// A piece of work for a miner of `hs`: the power of two nearest one share, kept at `now` while a share
/// stays near it.
pub fn slice_for(hs: f64, now: Option<u128>) -> u128 {
    let target = (hs.max(1.0) * SHARE_SECONDS).log2();
    if let Some(w) = now.filter(|w| w.is_power_of_two() && *w >= MIN_SLICE_WORK) {
        if (target - w.trailing_zeros() as f64).abs() <= SLICE_STAYS {
            return w;
        }
    }
    1u128 << (target.round().clamp(32.0, 100.0) as u32)
}

/// The start fee in whole pieces: about [`START_FEE_SECONDS`] of a miner's work at `hs`, at least one. The fee
/// in force (`now`) is kept while it stays within half of that either way: a wobbling speed changes nothing.
pub fn start_slices_for(hs: f64, slice_work: u128, now: Option<u64>) -> u64 {
    let secs = |n: u64| n as f64 * slice_work.max(1) as f64 / hs.max(1.0);
    if let Some(n) = now.filter(|n| *n >= 1 && (START_FEE_SECONDS * 0.5..=START_FEE_SECONDS * 1.5).contains(&secs(*n))) {
        return n;
    }
    ((START_FEE_SECONDS * hs.max(1.0) / slice_work.max(1) as f64).round() as u64).max(1)
}

/// How a hashmaker prices: a percent of what the work is worth when mined, or sats for a piece of `per` hashes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Pricing {
    Market(u64),
    Fixed { sat: u64, per: u128 },
}

fn work_of(v: &Value) -> Option<u128> {
    v.as_str().and_then(|w| w.parse().ok()).filter(|w: &u128| *w > 0)
}

/// How the settings price. A file from before: a price its owner typed is kept, and the old suggestion goes.
pub fn pricing(s: &Value) -> Pricing {
    match s["priceMode"].as_str() {
        Some("fixed") => Pricing::Fixed { sat: s["fixedPriceSat"].as_u64().unwrap_or(1).max(1), per: work_of(&s["fixedSliceWork"]).unwrap_or(OLD_SLICE_WORK) },
        Some(_) => Pricing::Market(s["pricePct"].as_u64().unwrap_or(MARKET_PCT).max(1)),
        None => match s["priceSat"].as_u64() {
            Some(p) if p > 0 && p != OLD_SUGGESTED_SAT => Pricing::Fixed { sat: p, per: work_of(&s["sliceWork"]).unwrap_or(OLD_SLICE_WORK) },
            _ => Pricing::Market(MARKET_PCT),
        },
    }
}

/// A rental's terms as the settings ask for them: the price of a piece, its work and the start fee.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Want {
    pub price_sat: u64,
    pub slice_work: u128,
    pub start_slices: u64,
}

impl Want {
    /// What is in force, as written for the hasher. None: no price yet.
    fn applied(s: &Value) -> Option<Want> {
        let price_sat = s["priceSat"].as_u64().filter(|p| *p > 0)?;
        Some(Want { price_sat, slice_work: work_of(&s["sliceWork"])?, start_slices: s["startSlices"].as_u64().unwrap_or(0) })
    }

    fn write(&self, s: &mut Value) {
        s["priceSat"] = json!(self.price_sat);
        s["sliceWork"] = json!(self.slice_work.to_string());
        s["startSlices"] = json!(self.start_slices);
    }

    fn to_json(self) -> Value {
        json!({"priceSat": self.price_sat, "sliceWork": self.slice_work.to_string(), "startSlices": self.start_slices})
    }
}

/// The terms the settings ask for, for miners of `hs` at the most (none measured: an S11's speed), at
/// `tip`. A market price needs the tip; a fixed one scales with the piece.
pub fn want(s: &Value, tip: Result<&Tip, &str>, hs: Option<f64>) -> Result<Want, String> {
    let hs = hs.filter(|h| *h > 0.0).unwrap_or(EXAMPLE_HS);
    let now = work_of(&s["sliceWork"]);
    let slice_work = match now {
        Some(w) if s["sliceFixed"] == true => w,
        _ => slice_for(hs, now),
    };
    let price = match pricing(s) {
        Pricing::Market(pct) => worth_sat(slice_work, tip.map_err(str::to_string)?) * pct as f64 / 100.0,
        Pricing::Fixed { sat, per } => sat as f64 * slice_work as f64 / per as f64,
    };
    // the fee in force, for the piece in force
    let start_now = s["startSlices"].as_u64().filter(|_| now == Some(slice_work));
    Ok(Want { price_sat: (price.round().min(u64::MAX as f64) as u64).max(1), slice_work, start_slices: start_slices_for(hs, slice_work, start_now) })
}

/// What the hasher's status says that a price follows.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Seen {
    /// The fastest miner here, measured.
    hs: Option<f64>,
    /// Miners are here, none measured yet: a piece can't be sized to them.
    measuring: bool,
    rentals: usize,
    /// It takes no new rental now.
    paused: bool,
}

fn seen(st: &Value) -> Seen {
    let live: Vec<f64> = st["miners"].as_array().into_iter().flatten().filter(|m| m["connected"] == true).map(|m| num(&m["hashrateHs"])).collect();
    let fastest = live.iter().copied().fold(0.0, f64::max);
    Seen {
        hs: (fastest > 0.0).then_some(fastest),
        measuring: !live.is_empty() && fastest <= 0.0,
        rentals: st["rentals"].as_array().map(Vec::len).unwrap_or(0),
        paused: st["paused"].is_string(),
    }
}

/// What a re-price did.
#[derive(Clone, Debug, PartialEq)]
pub enum Repriced {
    /// Renting is off, or the hasher could not be asked.
    Off,
    /// The price in force is what the settings ask for (confirmed, if live).
    Same,
    /// A new price is written, and the shop charges it once it has restarted.
    Applied,
    /// The new price waits for this many rentals going on to end: no new rental till then.
    Held(usize),
    /// No new rental while the shop starts with the new price.
    Waiting,
    /// No live price: why.
    NoPrice(String),
}

/// One call to a service's control page.
fn call(base: &str, token: &Option<PathBuf>, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new().timeout_connect(WAIT).timeout_read(WAIT).timeout_write(WAIT).redirects(0).build();
    let mut req = agent.request(method, &format!("{}{path}", base.trim_end_matches('/')));
    if let Some(t) = token {
        let t = std::fs::read_to_string(t).map_err(|_| "The hashrate service has not started yet.".to_string())?;
        req = req.set("Authorization", &format!("Bearer {}", t.trim()));
    }
    let r = match body {
        Some(b) => req.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => req.call(),
    };
    let r = match r {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(_) => return Err("The hashrate service does not answer. It may still be starting: try again in a minute.".into()),
    };
    r.into_string().ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).ok_or_else(|| "The hashrate service gave an answer this page cannot read.".into())
}

/// A speed in words: `4.10 TH/s`, `850 GH/s`.
pub fn speed(hs: f64) -> String {
    let units = [(1e15, "PH/s"), (1e12, "TH/s"), (1e9, "GH/s"), (1e6, "MH/s")];
    for (d, u) in units {
        if hs >= d {
            return format!("{:.2} {u}", hs / d);
        }
    }
    if hs > 0.0 {
        format!("{hs:.0} H/s")
    } else {
        "—".into()
    }
}

fn num(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// What a day of 1 TH/s costs at `price_sat` a piece of `slice_work` hashes: the figure miners
/// compare prices by (sats per TH/s per day).
pub fn per_ths_day(price_sat: f64, slice_work: f64) -> f64 {
    per_hour(price_sat, slice_work, 1e12) * 24.0
}

/// What a piece of work of `slice_work` hashes at `price_sat` costs an hour at `hs`.
pub fn per_hour(price_sat: f64, slice_work: f64, hs: f64) -> f64 {
    if slice_work <= 0.0 {
        return 0.0;
    }
    price_sat * hs * 3600.0 / slice_work
}

fn sats_n(n: f64) -> String {
    let n = n.round() as i64;
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            o.push(',');
        }
        o.push(c);
    }
    format!("{o} {}", if n == 1 { "sat" } else { "sats" })
}

/// Whether a hashmaker could drop the shares that win on this upstream, as its jobs show. Nothing here names a pool:
/// a pool that adds a key shows as blinded by itself.
fn blinding_card(b: &Value) -> String {
    let Some(words) = b["words"].as_str() else { return String::new() };
    let (class, head) = match b["state"].as_str() {
        Some("blinded") => ("good", "Winning shares are hidden"),
        Some("not blinded") => ("bad", "Winning shares can be seen"),
        _ => ("warn", "Can't check your upstream"),
    };
    format!("<section class=\"card\"><p><span class=\"pill {class}\">{head}</span></p><p>{}</p></section>", esc(words))
}

/// A closed rental's reason, in words.
fn ended_words(why: &str) -> String {
    // the earlier role names too: a hashlink from before the rename words its reasons with them
    let w = ["hashmaker closed: ", "hashtaker closed: ", "hasher closed: ", "buyer closed: "].iter().fold(why, |w, p| w.trim_start_matches(p));
    match w {
        "cut by the hashtaker" | "cut by the buyer" => "You cut it.".into(),
        "budget used up" => "Its budget is used up.".into(),
        "rental time over" => "Its time is up.".into(),
        "no proven work" | "no accepted work" => "The miners stopped sending work.".into(),
        "unpaid" => "A piece of work was not paid in time.".into(),
        "stopped by the hashmaker" | "stopped by the hasher" => "The hashmaker stopped it.".into(),
        "no miners free now" => "The hashmaker has no miners free.".into(),
        "a difficulty too high for the slice" => "The hashmaker stopped it: your pool asked for harder work than its pieces of work allow.".into(),
        "no first payment" => "The first piece of work was not paid in time.".into(),
        "the first slice could not be paid" => "Your wallet could not pay for the first piece of work.".into(),
        "paid time used up" => "The hashmaker stopped it: the miners had the paid work's time and your pool gave them too little to do.".into(),
        "too many jobs" | "too many shares" => "The hashmaker stopped it: your pool sent more than a rental needs.".into(),
        "a job this app can't check" => "Your pool sent work that can't be checked, so the rental stopped.".into(),
        "the hashtaker changed the extranonce" | "the gateway changed the extranonce" => "Your pool changed the work in a way that can't be checked, so the rental stopped.".into(),
        "shares harder than the difficulty said" => "The hashmaker stopped it: its miners' work looked harder than your pool said.".into(),
        "the gateway's jobs aren't blinded" => "Your pool's jobs don't hide which shares win, so the hashmaker could drop those. The rental stopped.".into(),
        "shares on an old job" => "The miners kept working on an out-of-date job, so the rental stopped.".into(),
        "too many waits for payment" => "The hashmaker stopped it: your payments kept arriving late.".into(),
        "the route to this hashmaker is too slow for its miners' rate" => "Your wallet's payments take longer to reach this hashmaker than its miners take to use them. Rent fewer or slower miners, or from a hashmaker your node reaches faster.".into(),
        "too many resumes" => "The connection to the hashmaker came and went too often, so it stopped.".into(),
        "shares arrive too old" => "The miners' work kept arriving late, so the rental stopped.".into(),
        "shares that don't prove" => "The hashmaker sent work that doesn't check out, so the rental stopped.".into(),
        "the gateway accepted too few shares" => "Your pool turned down too much of the work, so the rental stopped.".into(),
        w if w.starts_with("link lost") => "The connection to the hashmaker was lost.".into(),
        w if w.starts_with("could not start") => format!("It could not start: {}", w.trim_start_matches("could not start: ")),
        w => format!("Ended: {w}."),
    }
}

/// The settings file, with its dir's group (the hasher service reads it by group).
pub(crate) fn write_settings(path: &std::path::Path, v: &Value) -> Result<(), String> {
    let dir = path.parent().ok_or("no folder for the settings")?;
    let name = path.file_name().and_then(|n| n.to_str()).ok_or("no file name for the settings")?;
    if !dir.is_dir() {
        std::fs::create_dir_all(dir).map_err(|e| format!("The settings could not be saved: {e}"))?;
    }
    crate::setup::write_shared(dir, name, (serde_json::to_string_pretty(v).unwrap_or_default() + "\n").as_bytes())
        .map_err(|e| format!("The settings could not be saved: {e}"))
}

impl App {
    pub(crate) fn hash_settings(&self) -> Value {
        std::fs::read_to_string(&self.cfg.hash.settings).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}))
    }

    /// The shop's route for paid pieces of work, when renting out is on: `None` otherwise.
    pub(crate) fn hash_route(&self) -> Option<Value> {
        let slices = self.cfg.hash.slices.as_ref()?;
        let s = self.hash_settings();
        if s["enabled"] != true {
            return None;
        }
        // the price of a piece, as the hasher's terms say it: no price yet, no route (a route without one would be free)
        let price = s["priceSat"].as_u64().filter(|p| *p > 0)?.checked_mul(1000)?;
        Some(json!({"path": "/hashrate/", "upstream": slices, "methods": ["POST"], "max_body": 65536, "price": {"request_msat": price}}))
    }

    /// The chain's tip, as the signer reads it from the XBT node.
    pub(crate) fn mining_tip(&self) -> Result<Tip, String> {
        let v = self.call("mining_tip", json!({})).map_err(|_| "this app's signer can't read it: update the app".to_string())?;
        tip_of(&v, crate::now().max(0) as u64)
    }

    /// Whether the shop charges `price_sat` a piece of work now (its `/services`). A shop this app can't ask
    /// (no health address) is taken at its config.
    fn shop_charges(&self, price_sat: u64) -> bool {
        let Some(origin) = self.cfg.gw.health_url.as_deref().and_then(crate::services::http_origin) else { return true };
        let Ok((200, body)) = crate::app::http_get(&format!("{origin}{}", xbt_gateway::config::SERVICES_PATH)) else { return false };
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let charged = v["routes"].as_array().into_iter().flatten().find(|r| r["path"] == "/hashrate/")
            .and_then(|r| r["price"]["requestMsat"].as_str()).and_then(|p| p.parse::<u64>().ok());
        charged == price_sat.checked_mul(1000)
    }

    /// Price the hashmaker's work again: at the chain's difficulty (a market price) and the speed its miners show.
    /// Run every minute and at each Save (`saving`). A rental keeps the terms it was made with, and the shop
    /// charges one price, which it takes by restarting (a payment then fails, and the rental ends). So a new
    /// price is put in force only with no rental going on and none starting: first the hasher is told to take
    /// no new rental (`holdNew`, with the new terms `pending`), then, its rentals ended, the terms and the
    /// shop's route are written, and new rentals start again once the shop charges the new price.
    pub fn hash_reprice(&self, saving: bool) -> Repriced {
        let mut s = self.hash_settings();
        if s["enabled"] != true {
            return Repriced::Off;
        }
        let st = match &self.cfg.hash.hasher {
            None => Value::Null,
            Some(base) => match call(base, &self.cfg.hash.hasher_token, "GET", "/status", None) {
                Ok(v) => v,
                // a hasher that does not answer runs no rental; but its rentals are not known otherwise
                Err(_) if saving => Value::Null,
                Err(_) => return Repriced::Off,
            },
        };
        let seen = seen(&st);
        let before = s.clone();
        let mode = pricing(&s);
        if s.get("priceMode").is_none() {
            match mode {
                Pricing::Market(pct) => {
                    s["priceMode"] = json!("market");
                    s["pricePct"] = json!(pct);
                }
                Pricing::Fixed { sat, per } => {
                    s["priceMode"] = json!("fixed");
                    s["fixedPriceSat"] = json!(sat);
                    s["fixedSliceWork"] = json!(per.to_string());
                }
            }
        }
        let live = matches!(mode, Pricing::Market(_));
        let now_ms = crate::now().max(0) as u64 * 1000;
        s["awaitSpeed"] = json!(seen.measuring && s["sliceFixed"] != true);
        let tip = if live { self.mining_tip() } else { Err(String::new()) };
        let applied = Want::applied(&s);
        let r = match want(&s, tip.as_ref().map_err(String::as_str), seen.hs) {
            // the price in force ages out at the hasher, within the hour; the rentals going on keep theirs
            Err(why) => Repriced::NoPrice(why),
            Ok(w) if Some(w) == applied => {
                if let Some(m) = s.as_object_mut() {
                    m.remove("pending");
                }
                if s["holdNew"] == true && self.shop_charges(w.price_sat) {
                    s["holdNew"] = json!(false);
                }
                if live && s["priceSeenMs"].as_u64().is_none_or(|t| now_ms.saturating_sub(t) >= PRICE_CONFIRM_MS) {
                    s["priceSeenMs"] = json!(now_ms);
                }
                if s["holdNew"] == true {
                    Repriced::Waiting
                } else {
                    Repriced::Same
                }
            }
            // nothing priced yet, or no rental going on and none starting (or the owner saving): in force now
            Ok(w) if applied.is_none() || (seen.rentals == 0 && (saving || seen.paused)) => {
                w.write(&mut s);
                if let Some(m) = s.as_object_mut() {
                    m.remove("pending");
                }
                // till the shop charges it, when it can be asked
                s["holdNew"] = json!(self.cfg.gw.health_url.is_some());
                if live {
                    s["priceSeenMs"] = json!(now_ms);
                }
                Repriced::Applied
            }
            Ok(w) => {
                s["pending"] = w.to_json();
                s["holdNew"] = json!(true);
                Repriced::Held(seen.rentals)
            }
        };
        if !live {
            if let Some(m) = s.as_object_mut() {
                m.remove("priceSeenMs");
            }
        }
        if s != before {
            if let Err(e) = write_settings(&self.cfg.hash.settings, &s) {
                return Repriced::NoPrice(e);
            }
        }
        if r == Repriced::Applied {
            // the shop's route at the new price: its gateway restarts to take it
            let _ = self.commit(&self.shop(), "");
        }
        r
    }

    // --- Sell → Hashrate ------------------------------------------------------------------------

    pub(crate) fn sell_hashrate_page(&self, ctx: &Ctx) -> Resp {
        let Some(base) = self.cfg.hash.hasher.clone() else {
            return self.html_page("Sell hashrate", "Sell hashrate", ctx,
                "<p class=\"empty\">Renting out miners is off in this install. On Umbrel it is part of the app; on Linux, run install.sh again and turn the hashmaker on.</p>", "");
        };
        let st = call(&base, &self.cfg.hash.hasher_token, "GET", "/status", None);
        let saved = self.hash_settings();
        let csrf = App::csrf_input(ctx);
        let mut b = String::from("<p class=\"hint\">Renting out, you are the <strong>hashmaker</strong>: your miners make the hash. \
            The people who rent them are <strong>hashtakers</strong>.</p>");
        let settings = st.as_ref().ok().map(|s| s["settings"].clone()).unwrap_or(json!({}));
        let pick = |k: &str| saved.get(k).filter(|v| !v.is_null()).cloned().or_else(|| settings.get(k).filter(|v| !v.is_null()).cloned());
        let on = pick("enabled") == Some(Value::Bool(true));
        let fallback = pick("fallback").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let miners: Vec<Value> = st.as_ref().ok().and_then(|s| s["miners"].as_array().cloned()).unwrap_or_default();
        let rentals: Vec<Value> = st.as_ref().ok().and_then(|s| s["rentals"].as_array().cloned()).unwrap_or_default();
        let live = miners.iter().filter(|m| m["connected"] == true).count();
        let rented = miners.iter().filter(|m| !m["rentedTo"].is_null()).count();
        let (class, head, next) = match &st {
            Err(e) => ("bad", "Can't reach the hashrate service".to_string(), e.clone()),
            Ok(_) if !on || fallback.is_empty() => ("warn", "Not renting out".to_string(),
                "Say where your miners hash when nobody rents them, then turn renting on below.".to_string()),
            Ok(_) if live == 0 => ("warn", "Renting is on, no miners yet".to_string(), "Point your miners at the address below.".to_string()),
            Ok(_) => ("good", format!("Renting out: {rented} of {live} miner{} rented", if live == 1 { "" } else { "s" }),
                      if rented == 0 { "The others hash for your own pool until someone rents them.".into() } else { String::new() }),
        };
        b.push_str(&format!("<section class=\"status {class}\" aria-live=\"polite\"><p class=\"status-head\">{}</p>{}</section>",
                            esc(&head), if next.is_empty() { String::new() } else { format!("<p>{}</p>", esc(&next)) }));

        // where the miners point, once
        let addr = st.as_ref().ok().and_then(|s| s["minersAddress"].as_str().map(str::to_string)).unwrap_or_default();
        if !addr.is_empty() {
            b.push_str(&format!("<section class=\"card\"><h2>Point your miners at this box</h2>\
                <p>In each miner's settings, set its first pool to this address. Keep its worker name and password as they are.</p>\
                <label>Pool address for your miners<input id=\"miners-address\" readonly class=\"mono\" value=\"stratum+tcp://{}\"></label>\
                <div class=\"row\"><button type=\"button\" class=\"secondary\" data-copy=\"miners-address\">Copy the address</button></div>\
                <p class=\"hint\">If a miner cannot find this name, use this box's IP address with the same port. Keep your own pool as the miner's second pool.</p></section>",
                esc(&addr)));
        }

        // the miners
        if !miners.is_empty() {
            b.push_str("<h2>Your miners</h2><div class=\"scroll\"><table><thead><tr><th>Miner</th><th>Speed</th><th>Now</th><th>Earned</th></tr></thead><tbody>");
            for m in &miners {
                let now = if m["connected"] != true {
                    "<span class=\"pill\">Offline</span>".to_string()
                } else if m["rentedTo"].is_null() {
                    "<span class=\"pill good\">Your pool</span>".to_string()
                } else {
                    "<span class=\"pill cat-media\">Rented out</span>".to_string()
                };
                b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{now}</td><td class=\"money\">{}</td></tr>",
                                    esc(m["name"].as_str().unwrap_or("")), speed(num(&m["hashrateHs"])), sats_n(num(&m["earnedMsat"]) / 1000.0)));
            }
            b.push_str("</tbody></table></div>");
        }

        // the rentals going on
        if !rentals.is_empty() {
            b.push_str("<h2>Rented now</h2>");
            for r in &rentals {
                let id = r["rental"].as_str().unwrap_or("");
                let names: Vec<&str> = r["miners"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
                b.push_str(&format!("<section class=\"card live\"><div class=\"offer-head\"><h3>{} miner{}: {}</h3><span class=\"pill good\">Hashing</span></div>\
                    <p>Earned so far: <span class=\"money\">{}</span> · {} piece{} of work paid</p>\
                    <form method=\"post\" action=\"./sell-hashrate\">{csrf}<input type=\"hidden\" name=\"action\" value=\"stop\"><input type=\"hidden\" name=\"rental\" value=\"{}\">\
                    <button class=\"danger\">Stop this rental</button></form>\
                    <details><summary>Details</summary><p class=\"small\">Hashtaker <code>{}</code> · rental <code>{}</code></p></details></section>",
                    names.len(), if names.len() == 1 { "" } else { "s" }, esc(&names.join(", ")),
                    sats_n(num(&r["earnedMsat"]) / 1000.0), r["paid"].as_u64().unwrap_or(0), if r["paid"].as_u64() == Some(1) { "" } else { "s" },
                    esc(id), esc(&short(r["buyer"].as_str().unwrap_or(""), 20)), esc(id)));
            }
        }

        // the main action: turn renting on, or change it
        let seen = st.as_ref().map(seen).unwrap_or_default();
        let mode = pricing(&saved);
        let tip = self.mining_tip();
        let wanted = want(&saved, tip.as_ref().map_err(String::as_str), seen.hs);
        let (pct, fixed) = match mode {
            Pricing::Market(p) => (p, String::new()),
            Pricing::Fixed { sat, .. } => (MARKET_PCT, sat.to_string()),
        };
        let price_block = price_words(&wanted, tip.as_ref().ok(), seen.hs, matches!(mode, Pricing::Market(_)));
        let paused = st.as_ref().ok().and_then(|s| s["paused"].as_str()).map(paused_words).unwrap_or_default();
        let slice_typed = saved["sliceFixed"] == true;
        let slice_now = wanted.as_ref().map(|w| w.slice_work).unwrap_or_else(|_| slice_for(seen.hs.unwrap_or(EXAMPLE_HS), None)) as f64;
        let rentable = pick("rentable").and_then(|v| v.as_u64()).map(|n| n.to_string()).unwrap_or_default();
        let name = pick("name").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let link_public = pick("linkPublic").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let link_lan = st.as_ref().ok().and_then(|s| s["linkLan"].as_str().map(str::to_string)).filter(|a| !a.is_empty()).unwrap_or_else(|| "this box's address, port 23341".into());
        let grace_s = pick("graceMs").and_then(|v| v.as_u64()).unwrap_or(45_000) / 1000;
        // a hashmaker whose direct link is up is reached by key: no port forward, no address to type
        let direct = st.as_ref().ok().is_some_and(|s| s["iroh"].is_object());
        let forwarded = format!("<label>{}<input name=\"link_public\" value=\"{}\" class=\"mono\" \
            pattern=\"[A-Za-z0-9.\\-\\[\\]:]+:[0-9]+\" title=\"An address with its port, like my-box.example.com:23341\" placeholder=\"my-box.example.com:23341\"></label>\
            <p class=\"hint\">{}</p>\
            <details><summary>How do I get this address?</summary><ol>\
            <li>On your router, forward <strong>TCP port 23341</strong> to this box ({}). Forward only 23341: your miners' port stays on your own network.</li>\
            <li>Write your router's public address with the port, like <code>203.0.113.7:23341</code>, or a name that points at it (dynamic DNS), \
            like <code>my-box.example.com:23341</code>.</li>\
            <li>Save. Your offer goes on public listings within a minute.</li></ol>\
            <p class=\"hint\">This is a plain TCP port, so https tunnels for websites cannot carry it. The link is encrypted end to end, so it needs no \
            certificate. If you cannot forward ports, a tunnel app that forwards a TCP port to this box works too.</p></details>",
            if direct { "Also reachable at a forwarded address <small>(optional)</small>" } else { "Address hashtakers use to reach your miners (needs a port forward or tunnel)" },
            esc(&link_public),
            if direct {
                "Only for hashtakers on apps from before the direct link, which cannot use it. Leave it empty if you have not forwarded a port."
            } else {
                "Hashtakers' apps connect to this box's port 23341. Leave it empty and your offer stays off public listings; hashtakers on your own network can still use this box's address."
            },
            esc(&link_lan));
        let reach = if direct {
            "<p class=\"hint\"><span class=\"pill good\">No setup</span> Hashtakers reach your miners directly through the app, encrypted end to end: \
            no port forward, address or certificate is needed. When the two routers do not allow a direct connection, it goes through a relay, which \
            sees only encrypted data.</p>".to_string()
        } else {
            forwarded.clone()
        };
        b.push_str(&format!("<section class=\"card primary\"><h2>{}</h2><form method=\"post\" action=\"./sell-hashrate\">{csrf}\
            <input type=\"hidden\" name=\"action\" value=\"save\">\
            <label>Your own pool, where your miners hash when nobody rents them<input name=\"fallback\" value=\"{}\" required class=\"mono\" \
            pattern=\"[A-Za-z0-9.\\-\\[\\]:]+:[0-9]+\" title=\"An address with its port, like 192.168.1.20:23334\" placeholder=\"192.168.1.20:23334\"></label>\
            <p class=\"hint\">Your DATUM Gateway or your pool, as your miners use it today. Every miner nobody rents keeps hashing there.</p>\
            <fieldset><legend>Price for each piece of work</legend>\
            <label class=\"choice\"><input type=\"radio\" name=\"price_mode\" value=\"market\"{}><span><strong>Follow the market</strong>\
            <small>A percent of what the work is worth when mined at today's difficulty</small></span></label>\
            <label>Percent of that<input name=\"price_pct\" value=\"{pct}\" inputmode=\"numeric\" pattern=\"[0-9]+\" title=\"A whole percent, like 100\"></label>\
            <label class=\"choice\"><input type=\"radio\" name=\"price_mode\" value=\"fixed\"{}><span><strong>A fixed price</strong>\
            <small>Sats for each piece of work, whatever the difficulty</small></span></label>\
            <label>Fixed price, in sats<input name=\"price\" value=\"{}\" inputmode=\"numeric\" pattern=\"[0-9]*\" title=\"A whole number of sats\"></label></fieldset>\
            {price_block}{paused}\
            <label>Miners to rent out at most <small>(empty: all of them)</small><input name=\"rentable\" value=\"{}\" inputmode=\"numeric\" pattern=\"[0-9]*\"></label>\
            <label>Name, as hashtakers see it<input name=\"name\" value=\"{}\" maxlength=\"80\" placeholder=\"My miners\"></label>\
            {}\
            <label class=\"check\"><input type=\"checkbox\" name=\"enabled\" value=\"1\"{}> Rent out my miners</label>\
            <p class=\"hint\">A renter gets no work it hasn't paid for. If it stops paying, your miners go back to your own pool within seconds. A renter whose payment is slow to arrive can send them back to it for up to 10 seconds while it does. Your node checks every share's hash itself, so a renter's word doesn't set what the work is worth.</p>\
            <details><summary>Advanced</summary>\
            <label>Work in each piece (hashes) <small>(empty: about one share of your fastest miner)</small><input name=\"slice_work\" value=\"{}\" placeholder=\"{:.0}\" inputmode=\"numeric\" pattern=\"[0-9]*\" class=\"mono\"></label>\
            <label>How long to wait for each payment, in seconds<input name=\"grace_s\" value=\"{grace_s}\" inputmode=\"numeric\" pattern=\"[0-9]+\"></label>\
            {}</details><div class=\"row\"><button>{}</button></div></form></section>",
            if on { "Change renting" } else { "Rent out your miners" }, esc(&fallback),
            if matches!(mode, Pricing::Market(_)) { " checked" } else { "" }, if matches!(mode, Pricing::Fixed { .. }) { " checked" } else { "" }, esc(&fixed),
            esc(&rentable), esc(&name), reach, if on { " checked" } else { "" },
            if slice_typed { format!("{slice_now:.0}") } else { String::new() }, slice_now,
            if direct { forwarded.as_str() } else { "" },
            "Save"));
        if let Ok(s) = &st {
            match s["listing"].get("ok") {
                Some(Value::Bool(true)) => b.push_str(&format!(
                    "<section class=\"card\"><p><span class=\"pill good\">Listed</span> Your offer is on public listings: {} of {} miners free.</p></section>",
                    s["listing"]["freeMiners"], s["listing"]["miners"])),
                Some(Value::Bool(false)) => b.push_str(&format!(
                    "<section class=\"card\"><p><span class=\"pill warn\">Not listed</span> {}</p></section>",
                    esc(s["listing"]["why"].as_str().unwrap_or("Your offer is not published yet.")))),
                _ => b.push_str(if direct {
                    "<section class=\"card\"><p><span class=\"pill warn\">Not listed yet</span> Your offer goes on public listings once a miner is connected.</p></section>"
                } else {
                    "<section class=\"card\"><p><span class=\"pill warn\">Not listed yet</span> Your offer goes on public listings once a miner is connected and the address hashtakers use is set.</p></section>"
                }),
            }
        }
        self.html_page("Sell hashrate", "Sell hashrate", ctx, &b, "")
    }

    pub(crate) fn sell_hashrate_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
        let r: Result<String, String> = match g("action").as_str() {
            "stop" => match &self.cfg.hash.hasher {
                None => Err("This box does not rent out miners.".into()),
                Some(base) => call(base, &self.cfg.hash.hasher_token, "POST", &format!("/stop/{}", crate::services::urlenc(&g("rental"))), None)
                    .and_then(|v| if v["ok"] == true { Ok("Stopped. Those miners hash for your own pool again.".into()) } else { Err("That rental had ended already.".into()) }),
            },
            "save" => (|| {
                let fallback = g("fallback");
                if !fallback.contains(':') || fallback.contains(['/', ' ']) {
                    return Err("Write your own pool's address with its port, like 192.168.1.20:23334.".into());
                }
                // a form from before the choice names a price only: a fixed one
                let market = g("price_mode") == "market" || (g("price_mode").is_empty() && g("price").is_empty());
                let pct: u64 = if g("price_pct").is_empty() { MARKET_PCT } else { g("price_pct").parse().map_err(|_| "The percent is a whole number, like 100.".to_string())? };
                if market && !(1..=1000).contains(&pct) {
                    return Err("Set a percent from 1 to 1000.".into());
                }
                let price: u64 = if market { 0 } else { g("price").parse().map_err(|_| "The fixed price is a whole number of sats.".to_string())? };
                if !market && price == 0 {
                    return Err("Set a fixed price above 0 sats.".into());
                }
                let rentable: Option<u64> = if g("rentable").is_empty() { None } else { Some(g("rentable").parse().map_err(|_| "Miners to rent out is a whole number, or empty.".to_string())?) };
                let slice: Option<u128> =
                    if g("slice_work").is_empty() { None } else { Some(g("slice_work").parse().map_err(|_| "The work in each piece is a whole number.".to_string())?) };
                if slice.is_some_and(|w| w < MIN_SLICE_WORK) {
                    return Err("Each piece of work is at least 4,294,967,296 hashes.".into());
                }
                let grace: u64 = if g("grace_s").is_empty() { 45 } else { g("grace_s").parse().map_err(|_| "The wait is a whole number of seconds.".to_string())? };
                let mut v = self.hash_settings();
                let shop = self.shop();
                v["enabled"] = json!(g("enabled") == "1");
                v["fallback"] = json!(fallback);
                if market {
                    v["priceMode"] = json!("market");
                    v["pricePct"] = json!(pct);
                } else {
                    // a fixed price is for a piece the size it is now, and scales with it
                    let per = slice.or_else(|| work_of(&v["sliceWork"])).unwrap_or_else(|| slice_for(EXAMPLE_HS, None));
                    v["priceMode"] = json!("fixed");
                    v["fixedPriceSat"] = json!(price);
                    v["fixedSliceWork"] = json!(per.to_string());
                }
                v["rentable"] = json!(rentable);
                v["sliceFixed"] = json!(slice.is_some());
                if let Some(w) = slice {
                    v["sliceWork"] = json!(w.to_string());
                }
                v["graceMs"] = json!(grace.clamp(5, 600) * 1000);
                v["name"] = json!(if g("name").is_empty() { "Hashrate".to_string() } else { g("name").chars().take(80).collect() });
                let link = g("link_public");
                if !link.is_empty() && (!link.contains(':') || link.contains(['/', ' '])) {
                    return Err("Write the address hashtakers use with its port, like my-box.example.com:23341.".into());
                }
                // empty clears it: no listing on public relays until it is set
                v["linkPublic"] = json!(link);
                if !shop.public_url.is_empty() {
                    v["payUrl"] = json!(format!("{}/hashrate", shop.public_url.trim_end_matches('/')));
                }
                write_settings(&self.cfg.hash.settings, &v)?;
                // priced now, unless rentals are going on: the price they pay stays till they end
                let priced = self.hash_reprice(true);
                // the shop sells each piece of work: its route follows these settings
                let words = self.commit(&shop, "")?;
                Ok(if v["enabled"] == true {
                    let price = match priced {
                        Repriced::Held(n) => format!(" The new price starts once the {n} rental{} going on end{}. No new rental starts till then.",
                                                     if n == 1 { "" } else { "s" }, if n == 1 { "s" } else { "" }),
                        Repriced::NoPrice(why) => format!(" No rental starts yet: there is no price, because {why}."),
                        _ => String::new(),
                    };
                    format!("Saved. Renting is on.{price} {}", words.trim())
                } else {
                    "Saved. Renting is off: every miner hashes for your own pool.".into()
                })
            })(),
            _ => Err("Unknown action.".into()),
        };
        match r {
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./sell-hashrate")
    }

    // --- Services → Hashrate ---------------------------------------------------------------------

    /// Rentals going on (for Live connections): cards with a Cut button, and what they spent.
    pub(crate) fn hash_live_cards(&self, ctx: &Ctx) -> (String, i64) {
        let Some(base) = &self.cfg.hash.renter else { return (String::new(), 0) };
        let Ok(st) = call(base, &self.cfg.hash.renter_token, "GET", "/status", None) else { return (String::new(), 0) };
        let mut spent = 0i64;
        let mut cards = String::new();
        for r in st["rentals"].as_array().into_iter().flatten().filter(|r| r["ended"] != true) {
            spent += (num(&r["live"]["spentMsat"]) / 1000.0) as i64;
            cards.push_str(&rental_card(ctx, r, "./connections-hashrate"));
        }
        (cards, spent)
    }

    pub(crate) fn hashrate_page(&self, ctx: &Ctx) -> Resp {
        let Some(base) = self.cfg.hash.renter.clone() else {
            return self.html_page("Hashrate", "Hashrate", ctx,
                "<p class=\"empty\">Renting miners is off in this install. The Lightning Stream app on Umbrel and on Linux has it.</p>", "");
        };
        let token = self.cfg.hash.renter_token.clone();
        let st = call(&base, &token, "GET", "/status", None);
        let csrf = App::csrf_input(ctx);
        let mut b = String::from("<p class=\"lead\">Rent miners from other people, by the piece of work they do, into your own DATUM Gateway. \
            You pay only for work both sides have checked. Paid as you use it, seconds at a time: you never have more paid for and not yet received than a minute of the miner's hashing or 546 sat, whichever is more, plus any start fee shown on the offer. You can cut a rental at any moment.</p>\
            <p class=\"hint\">Renting, you are the <strong>hashtaker</strong>: the hash comes to you. The people whose miners you rent are <strong>hashmakers</strong>.</p>");
        let st = match st {
            Ok(s) => s,
            Err(e) => {
                b.push_str(&App::error_box(&e));
                return self.html_page("Hashrate", "Hashrate", ctx, &b, "");
            }
        };
        // the buyer's own DATUM Gateway: where rented work goes
        let datum = st["datum"]["addr"].as_str().unwrap_or("");
        let reachable = st["datum"]["reachable"] == true;
        // renting needs a gateway that hides which shares win: checked from its jobs when this page loads, whatever pool
        let masked = st["blinding"]["state"] == "blinded";
        let ready = reachable && masked;
        let found: Vec<String> = st["datum"]["found"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        let (class, head, next) = if datum.is_empty() {
            ("warn", "No DATUM Gateway yet", "Rented work goes to your own DATUM Gateway, which builds the blocks and is paid through your pool. Set its address below.")
        } else if !reachable {
            ("bad", "Can't reach your DATUM Gateway", "Check that it is running, and that its address below is right.")
        } else if !masked {
            ("warn", "Renting needs a gateway that masks its jobs",
             "Rented work goes to your own DATUM Gateway, and it has to hide which shares win, so a hashmaker can't keep back the ones that would be blocks. \
              Yours doesn't do that yet. A gateway app that does is coming soon. Until then renting stays off here, and nothing is paid. \
              Renting out your own miners works now.")
        } else {
            ("good", "Ready to rent", "")
        };
        b.push_str(&format!("<section class=\"status {class}\" aria-live=\"polite\"><p class=\"status-head\">{head}</p>{}</section>",
                            if next.is_empty() { String::new() } else { format!("<p>{next}</p>") }));

        // the rentals going on and the last ones
        let rentals: Vec<Value> = st["rentals"].as_array().cloned().unwrap_or_default();
        if !rentals.is_empty() {
            b.push_str("<h2>Your rentals</h2><div class=\"stack\">");
            for r in rentals.iter().take(10) {
                b.push_str(&rental_card(ctx, r, "./hashrate"));
            }
            b.push_str("</div>");
        }

        // the offers: the main action
        b.push_str("<h2>Miners for rent</h2>");
        match call(&base, &token, "GET", "/offers", None) {
            Err(e) => b.push_str(&App::error_box(&e)),
            Ok(o) => {
                let offers: Vec<Value> = o["offers"].as_array().cloned().unwrap_or_default();
                if offers.is_empty() {
                    b.push_str("<p class=\"empty\">No miners for rent found right now. Hashmakers publish their offers on Nostr; look again in a while.</p>");
                }
                b.push_str("<div class=\"grid services\">");
                for x in &offers {
                    let price = num(&x["priceMsat"]) / 1000.0;
                    let slice = num(&x["sliceWork"]);
                    let free = x["freeMiners"].as_u64().unwrap_or(0);
                    let total = x["miners"].as_u64().unwrap_or(0);
                    let free_hs = num(&x["freeHs"]);
                    let per_miner = if free > 0 && free_hs > 0.0 { free_hs / free as f64 } else { EXAMPLE_HS };
                    let start = x["startSlices"].as_u64().unwrap_or(0);
                    let fee = price * start as f64;
                    let budget = (per_hour(price, slice, per_miner) + fee).ceil().max(price + fee) as u64;
                    let fee_words = start_fee_words(price, start, slice, per_miner);
                    // a hashmaker whose app doesn't prove its work is refused when renting: said, and Rent waits
                    let old = x["proves"] == false;
                    // the spending rules list who the app may pay: a hashmaker not on them is allowed first, with the
                    // node its signed listing names (the rules page shows the change to sign)
                    let pay_url = x["payUrl"].as_str().unwrap_or("");
                    let allowed = self.seller_allowed(pay_url);
                    let allow = match (allowed, crate::services::http_origin(pay_url), x["payNode"].as_str()) {
                        (false, Some(o), Some(n)) if !n.is_empty() => format!(
                            "<p class=\"hint\">Your spending rules list who this app may pay. Allow this hashmaker first: you sign the change with your approval key.</p>\
                             <p><a class=\"button\" href=\"./policy?allow={}&amp;node={}\">Allow this hashmaker to be paid</a></p>",
                            crate::services::urlenc(&o), esc(n)),
                        _ => String::new(),
                    };
                    let can = ready && allowed && !old && (free > 0 || total == 0);
                    let old = if old {
                        "<p class=\"hint\"><span class=\"pill warn\">Needs updating</span> This hashmaker's app doesn't prove the work it sells, so it can't be rented.</p>"
                    } else {
                        ""
                    };
                    let history = history_panel(&x["history"]);
                    // what may leave the wallet for a trial's first ticket, as the hashtaker sets it (rail::caps_at),
                    // is said beside its price; a longer rental's tickets grow with its work, so it names no figure
                    let ticket = |k: &str| match x[k].as_u64() {
                        Some(n) => format!("may buy a ticket of up to {} from this shop", sats_n(n as f64)),
                        None => "may buy a ticket from this shop".into(),
                    };
                    let trial = format!("<form method=\"post\" action=\"./hashrate\">{csrf}<input type=\"hidden\" name=\"action\" value=\"trial\">\
                        <input type=\"hidden\" name=\"key\" value=\"{}\"><p class=\"hint\">Not sure yet? Rent one machine for one piece of work{}, \
                        about {}, and see what your own DATUM Gateway accepts before renting more. It is charged at most that, but your wallet {}; \
                        unused credit stays with this seller for about 20 hours, for a later rental there.</p>\
                        <button class=\"secondary\"{}>Try one slice first</button></form>",
                        esc(x["linkKey"].as_str().unwrap_or("")), if start > 0 { " and its start fee" } else { "" }, sats_n((price + fee).ceil()),
                        ticket("trialMayBuyTicketUpToSats"), if can { "" } else { " disabled" });
                    b.push_str(&format!("<section class=\"card offer\"><span class=\"pill cat-media\">Hashrate</span><h3>{}</h3>\
                        <p class=\"price\">{} a piece of work</p><p class=\"small\">About <strong>{}</strong> an hour for each {} of speed (about {} a day) · {}</p>{fee_words}{old}{history}{allow}{trial}\
                        <form method=\"post\" action=\"./hashrate\">{csrf}<input type=\"hidden\" name=\"action\" value=\"rent\"><input type=\"hidden\" name=\"key\" value=\"{}\">\
                        <div class=\"price-row\"><label>Machines<input name=\"miners\" value=\"1\" inputmode=\"numeric\" pattern=\"[0-9]+\" required></label>\
                        <label>For how long, in minutes<input name=\"minutes\" value=\"60\" inputmode=\"numeric\" pattern=\"[0-9]+\" required></label></div>\
                        <label>The most it may cost, in sats<input name=\"budget\" value=\"{budget}\" inputmode=\"numeric\" pattern=\"[0-9]+\" required></label>\
                        <p class=\"hint\">About an hour of one machine{}. The rental ends when this much is spent, but however small it is, your wallet {}; \
                        unused credit stays with this seller for about 20 hours, for a later rental there.</p>\
                        <button{}>Rent</button></form></section>",
                        esc(x["name"].as_str().unwrap_or("Miners")), sats_n(price), sats_n(per_hour(price, slice, 1e12)), "1 TH/s", sats_n(per_ths_day(price, slice)),
                        if total > 0 { format!("{free} of {total} machines free, {}", speed(free_hs)) } else { "free machines not given".into() },
                        esc(x["linkKey"].as_str().unwrap_or("")), if start > 0 { ", with its start fee" } else { "" }, ticket("mayBuyTicketUpToSats"),
                        if can { "" } else { " disabled" }));
                }
                b.push_str("</div>");
            }
        }

        // what its jobs show, once they show it: the notice above says what's needed when they don't
        if masked {
            b.push_str(&blinding_card(&st["blinding"]));
        }
        // the DATUM Gateway's address
        b.push_str(&format!("<section class=\"card\"><h2>Your DATUM Gateway</h2><form method=\"post\" action=\"./hashrate\">{csrf}\
            <input type=\"hidden\" name=\"action\" value=\"datum\">\
            <label>Its address, with the port your miners use<input name=\"addr\" value=\"{}\" class=\"mono\" required placeholder=\"datum-gateway:23334\" \
            pattern=\"[A-Za-z0-9.\\-\\[\\]:_]+:[0-9]+\" title=\"An address with its port, like 192.168.1.20:23334\"></label>{}\
            <p class=\"hint\">The pool your rented work is paid through is chosen in your DATUM Gateway, not here.</p>\
            <button class=\"secondary\">Save</button></form>\
            <p class=\"small\">No DATUM Gateway yet? <a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">How to set one up</a> (it suggests Lazarus Pool).</p></section>",
            esc(datum), if found.is_empty() || found.iter().any(|f| f == datum) { String::new() } else { format!("<p class=\"hint\">Found on this box: <code>{}</code></p>", esc(&found.join(", "))) },
            esc(&self.cfg.hash.datum_guide)));
        self.html_page("Hashrate", "Hashrate", ctx, &b, "")
    }

    pub(crate) fn hashrate_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let back = if f.get("back").is_some_and(|b| b == "connections") { "./connections" } else { "./hashrate" };
        let Some(base) = self.cfg.hash.renter.clone() else {
            self.flash(ctx, false, "This box does not rent miners.");
            return Resp::redirect(back);
        };
        let token = self.cfg.hash.renter_token.clone();
        let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
        let n = |k: &str| g(k).parse::<u64>().unwrap_or(0);
        let r: Result<String, String> = match g("action").as_str() {
            "rent" | "trial" if call(&base, &token, "GET", "/status", None).is_ok_and(|st| st["blinding"]["state"] != "blinded") => {
                Err("Renting needs a DATUM Gateway that masks its jobs. Nothing was paid.".into())
            }
            "rent" => {
                if n("budget") == 0 {
                    Err("Set the most this rental may cost.".into())
                } else {
                    call(&base, &token, "POST", "/rent", Some(&json!({"linkKey": g("key"), "miners": n("miners").max(1), "budgetSats": n("budget"), "minutes": n("minutes").max(1)})))
                        .and_then(|v| match v["rental"].as_str() {
                            Some(_) => Ok(format!("Renting. The miners start on your DATUM Gateway in a few seconds; you pay as their work is accepted.{}", may_buy(&v))),
                            None => Err(v["error"].as_str().map(|e| format!("Not rented: {e}.")).unwrap_or_else(|| "Not rented.".into())),
                        })
                }
            }
            "trial" => call(&base, &token, "POST", "/rent", Some(&json!({"linkKey": g("key"), "trial": true})))
                .and_then(|v| match v["rental"].as_str() {
                    Some(_) => Ok(format!("Trying one slice, at most {}.{} When it is done, its result shows under Your rentals.", sats_n(num(&v["budgetSats"])), may_buy(&v))),
                    None => Err(v["error"].as_str().map(|e| format!("Not started: {e}.")).unwrap_or_else(|| "Not started.".into())),
                }),
            "attest" => call(&base, &token, "POST", "/attest", Some(&json!({"rental": g("rental")})))
                .and_then(|v| if v["ok"] == true {
                    Ok("Published. Other hashtakers see this rental in the hashmaker's delivery history.".into())
                } else {
                    Err(v["error"].as_str().map(|e| format!("Not published: {e}.")).unwrap_or_else(|| "Not published: no relay took it.".into()))
                }),
            "cut" => call(&base, &token, "POST", "/cut", Some(&json!({"rental": g("rental")})))
                .and_then(|v| if v["ok"] == true { Ok("Cut. The miners stop working for you and payments stop.".into()) } else { Err("That rental had ended already.".into()) }),
            "datum" => call(&base, &token, "POST", "/datum", Some(&json!({"addr": g("addr")}))).and_then(|v| {
                if v["ok"] != true {
                    Err(v["error"].as_str().map(|e| format!("Not saved: {e}.")).unwrap_or_else(|| "Not saved.".into()))
                } else if v["reachable"] == true {
                    Ok("Saved. Your DATUM Gateway answers.".into())
                } else {
                    Ok("Saved, but nothing answers at that address yet. Check that your DATUM Gateway is running.".into())
                }
            }),
            _ => Err("Unknown action.".into()),
        };
        match r {
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect(back)
    }
}

/// One rental, as the renter sees it.
fn rental_card(ctx: &Ctx, r: &Value, _action: &str) -> String {
    let live = &r["live"];
    let ended = r["ended"] == true || !live["closed"].is_null();
    let id = r["rental"].as_str().unwrap_or("");
    let hs = num(&live["lastRate"]["hs"]);
    let paid = live["paidSlices"].as_u64().unwrap_or(0);
    let spent = num(&live["spentMsat"]) / 1000.0;
    // a rental is "connecting" until its link to the hashmaker is up (the service then reports its
    // role and meter); one whose link never opened ended before any work, and nothing was paid
    let failed = live["closed"].as_str().is_some_and(|w| w.starts_with("could not start"));
    let connecting = !ended && live.get("role").is_none() && live.get("meter").is_none();
    let pill = if failed {
        "<span class=\"pill bad\">Could not start</span>".to_string()
    } else if ended {
        "<span class=\"pill\">Ended</span>".to_string()
    } else if connecting {
        "<span class=\"pill\">Connecting…</span>".to_string()
    } else {
        "<span class=\"pill good\">Hashing</span>".to_string()
    };
    let why = live["closed"].as_str().map(|w| format!("<p class=\"hint\">{}{}</p>", esc(&ended_words(w)),
                                                     if failed && spent == 0.0 { " Nothing was paid." } else { "" })).unwrap_or_default();
    // a payment the wallet refused: the hashmaker will only say a piece went unpaid, and the reason is this wallet's,
    // in words where it has them (xbt_hashlink::rail::BIG_TICKETS_ONLY and those beside it)
    const WORDS: [&str; 3] = ["This hashmaker's smallest ticket is", "What is left of this rental's budget", "Your wallet's rules stopped this payment"];
    let refused = live["pays"].as_array().into_iter().flatten().rev().find_map(|p| p["why"].as_str().filter(|w| WORDS.iter().any(|s| w.starts_with(s))))
        .map(|w| format!("<p class=\"hint\">{}</p>", esc(w))).unwrap_or_default();
    let cut = if ended {
        String::new()
    } else {
        format!("<form method=\"post\" action=\"./hashrate\">{}<input type=\"hidden\" name=\"action\" value=\"cut\"><input type=\"hidden\" name=\"rental\" value=\"{}\">\
                 <input type=\"hidden\" name=\"back\" value=\"{}\"><button class=\"danger\">Cut</button></form>",
                App::csrf_input(ctx), esc(id), if _action.contains("connections") { "connections" } else { "hashrate" })
    };
    let trial = r["trial"] == true;
    let result = if ended && paid > 0 { result_box(&r["result"], trial) } else { String::new() };
    let attest = match (&r["attested"], ended && paid > 0) {
        (a, _) if a["ok"] == true => "<p class=\"hint\">Its delivery record is published.</p>".to_string(),
        (_, true) => format!("<form method=\"post\" action=\"./hashrate\">{}<input type=\"hidden\" name=\"action\" value=\"attest\">\
                 <input type=\"hidden\" name=\"rental\" value=\"{}\"><p class=\"hint\">Help other hashtakers: publish a signed record of what this \
                 hashmaker delivered. It names no pool, payout or address, only this app's key, the work and what was paid.</p>\
                 <button class=\"secondary\">Publish a delivery record</button></form>", App::csrf_input(ctx), esc(id)),
        _ => String::new(),
    };
    let title = if trial { "Test slice from" } else { "Hashrate from" };
    // what left the wallet for it (a ticket bought whole, which a small rental uses only part of) and, once
    // the wallet's session with the shop stopped, what of it stays there as credit
    let moved = live["walletMovedSats"].as_u64().unwrap_or(0);
    let wallet = if moved > 0 {
        let left = match live["leftWithSellerMsat"].as_u64() {
            Some(m) if m > 0 => format!("; {} of it stays with this seller as credit for about 20 hours, for a later rental there", sats_n(m as f64 / 1000.0)),
            _ => String::new(),
        };
        format!("<p class=\"small\">Left your wallet: <span class=\"money\">{}</span>, a ticket bought whole from this shop{left}.</p>", sats_n(moved as f64))
    } else {
        String::new()
    };
    format!("<section class=\"card live\"><div class=\"offer-head\"><h3>{title} {}</h3>{pill}</div>\
             <p>Spent so far: <span class=\"money\">{}</span> of {} · {} piece{} of work paid · {} on {} machine{}</p>{wallet}{refused}{why}{result}<div class=\"row\">{cut}</div>{attest}</section>",
            esc(r["hasher"].as_str().unwrap_or("a hashmaker")), sats_n(spent), sats_n(num(&r["budgetSats"])), paid, if paid == 1 { "" } else { "s" },
            speed(hs), live["miners"].as_u64().unwrap_or(0), if live["miners"].as_u64() == Some(1) { "" } else { "s" })
}

/// A whole percentage.
fn pct(x: f64) -> String {
    format!("{:.0}%", (x * 100.0).max(0.0))
}

/// What a rental may take from the wallet beyond its budget, as the hashtaker answered it: a ticket
/// bought whole, its unused part staying with that seller as credit.
fn may_buy(v: &Value) -> String {
    match v["mayBuyTicketUpToSats"].as_u64() {
        Some(n) if n > v["budgetSats"].as_u64().unwrap_or(0) => {
            format!(" Your wallet may buy a ticket of up to {} from this shop for it; unused credit stays with this seller for about 20 hours, for a later rental there.", sats_n(n as f64))
        }
        _ => String::new(),
    }
}

/// A rental's start fee on the renter's offer: in sats, and in seconds of a machine's work.
fn start_fee_words(price_sat: f64, start: u64, slice_work: f64, per_miner_hs: f64) -> String {
    if start == 0 {
        return String::new();
    }
    let secs = if per_miner_hs > 0.0 { format!(", about {:.0} seconds of a machine's work", start as f64 * slice_work / per_miner_hs) } else { String::new() };
    format!("<p class=\"fee\">Start fee: <strong>{}</strong>{secs}. It is paid first, with the first piece of work, and pays the hashmaker \
             for moving the miners to you. They don't move until it arrives.</p>", sats_n(price_sat * start as f64))
}

/// The price, its start fee and what the work is worth when mined, as the hashmaker's form says them, and a
/// warning when the price is below that worth. `market`: the price follows the difficulty.
fn price_words(w: &Result<Want, String>, tip: Option<&Tip>, hs: Option<f64>, market: bool) -> String {
    let w = match w {
        Ok(w) => w,
        Err(why) => {
            let fixed = if market { " A fixed price works without it." } else { "" };
            return format!("<p class=\"hint\"><span class=\"pill warn\">No live price</span> This app can't read today's difficulty: {}. \
                            Following the market needs it, so no new rental starts until it can. Rentals going on keep their price.{fixed}</p>", esc(why));
        }
    };
    let (miner, at) = match hs {
        Some(h) => (format!("your fastest miner ({})", speed(h)), h),
        None => (format!("a {} miner, until one of yours has hashed here", speed(EXAMPLE_HS)), EXAMPLE_HS),
    };
    let slice = w.slice_work as f64;
    let worth = tip.map(|t| worth_sat(w.slice_work, t));
    let mined = worth.map(|v| format!(" Mined at today's difficulty it is worth about {}.", sats_n(v))).unwrap_or_default();
    let mut b = format!("<p class=\"hint\">A piece of work is about one share of {miner}, about {:.0} seconds of its work. It costs <strong>{}</strong>.{mined} \
        While rented, a {} miner earns about <strong>{}</strong> an hour, about <strong>{}</strong> a day for each 1 TH/s of speed.</p>\
        <p class=\"hint\">Renters also pay a start fee of <strong>{}</strong> ({} piece{} of work, about {:.0} seconds of a miner's work) before your \
        miners move. It pays for moving them.</p>",
        slice / at, sats_n(w.price_sat as f64), speed(at), sats_n(per_hour(w.price_sat as f64, slice, at)), sats_n(per_ths_day(w.price_sat as f64, slice)),
        sats_n((w.price_sat * w.start_slices) as f64), w.start_slices, if w.start_slices == 1 { "" } else { "s" }, w.start_slices as f64 * slice / at);
    // a price rounded to the sat is not below it
    if let Some(v) = worth.filter(|v| w.price_sat as f64 + 0.5 < *v) {
        b.push_str(&format!("<p><span class=\"pill warn\">Below mining value</span> This price is below what the work is worth when mined at today's \
            difficulty, about {} a piece. Your own pool likely pays close to that, less its fee, so renting at this price may earn you less than \
            mining. This app can't see what your pool pays you, so it compares your price with the mining value only.</p>", sats_n(v)));
    }
    b
}

/// Why the hasher takes no new rental, in the owner's words.
fn paused_words(why: &str) -> String {
    let w = match why {
        "no price yet" => "There is no price yet, so no rental starts.",
        "no miner measured yet" => "Your miners are being measured, to size the pieces of work to them. Renting starts in a couple of minutes.",
        "a new price waits for the rentals going on to end" => {
            "Your new price starts once the rentals going on end and your shop has restarted with it. No new rental starts till then."
        }
        w if w.contains("not been confirmed") => "The live price could not be checked against your XBT node for over an hour, so no new rental starts until it can.",
        _ => "No new rental starts for now.",
    };
    format!("<p><span class=\"pill warn\">No new rentals</span> {w}</p>")
}

/// What a finished rental, or a test slice, showed: delivered against advertised speed, stale and
/// rejected shares, and the share round trip.
fn result_box(r: &Value, trial: bool) -> String {
    if r.is_null() {
        return String::new();
    }
    let delivered = num(&r["deliveredHs"]);
    let advertised = num(&r["advertisedHs"]);
    let vs = match r["ratio"].as_f64() {
        Some(x) => format!(" against {} advertised ({})", speed(advertised), pct(x)),
        None => String::new(),
    };
    let rt = match (r["latencyMsP50"].as_u64(), r["latencyMsP95"].as_u64()) {
        (Some(a), Some(b)) => format!(" · share round trip {a} ms, {b} ms at worst"),
        (Some(a), None) => format!(" · share round trip {a} ms"),
        _ => String::new(),
    };
    let head = if trial { "What the test slice showed" } else { "What this rental delivered" };
    let after = if trial { "<p class=\"hint\">Your own DATUM Gateway checked every share. If this looks right, rent for longer below.</p>" } else { "" };
    format!("<div class=\"result\"><p><strong>{head}:</strong> {}{vs} · stale shares {} · rejected {}{rt}</p>{after}</div>",
            speed(delivered), pct(r["staleShare"].as_f64().unwrap_or(0.0)), pct(r["rejectedShare"].as_f64().unwrap_or(0.0)))
}

/// A hashmaker's delivery history, as the offer shows it.
fn history_panel(h: &Value) -> String {
    let records = h["records"].as_u64().unwrap_or(0);
    let says = &h["hashmakerSays"];
    if records == 0 {
        let own = if says.is_null() { String::new() } else {
            format!(" The hashmaker says it served {} rental{} ({} TH-hours), but no hashtaker has published a record yet.",
                    says["rentals"].as_u64().unwrap_or(0), if says["rentals"].as_u64() == Some(1) { "" } else { "s" }, th_hours(says["thHours"].as_f64().unwrap_or(0.0)))
        };
        return format!("<p class=\"small history\">No delivery history yet.{own} Try one slice first to see for yourself.</p>");
    }
    let confirmed = h["confirmed"].as_u64().unwrap_or(0);
    let vs = h["deliveredVsAdvertised"].as_f64().map(|x| format!(" · delivered about {} of what it advertised", pct(x))).unwrap_or_default();
    let disputed = match h["disputed"].as_u64().unwrap_or(0) {
        0 => String::new(),
        n => format!(" · <strong>{n} disputed</strong> (the hashtaker and the hashmaker disagree on what was paid)"),
    };
    let recent: Vec<String> = h["recent"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| format!("{}{} ({}{})", speed(num(&r["deliveredHs"])), if r["trial"] == true { " test slice" } else { "" },
                                 pct(r["ratio"].as_f64().unwrap_or(0.0)), if r["confirmed"] == true { ", confirmed" } else { "" }))
                .collect()
        })
        .unwrap_or_default();
    format!("<details class=\"history\"><summary>Delivery history: {} TH-hours confirmed by both sides · {records} record{} ({confirmed} confirmed){vs}{disputed}</summary>\
             <p class=\"small\">Recent: {}.</p><p class=\"hint\">Records are signed by the hashtakers who rented, and confirmed when the hashmaker's \
             own signed summary agrees. Lightning payments are private, so this is a signal, not proof: records the hashmaker did not confirm, \
             and records from keys that never rented elsewhere, count for less.</p></details>",
            th_hours(h["verifiedThHours"].as_f64().unwrap_or(0.0)), if records == 1 { "" } else { "s" }, esc(&recent.join("; ")))
}

fn th_hours(x: f64) -> String {
    if x >= 10.0 {
        format!("{x:.0}")
    } else {
        format!("{x:.1}")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_rental_refused_for_a_shops_big_tickets_says_so_and_no_other_reason_is_shown_raw() {
        let ctx = Ctx { sid: String::new(), csrf: "c".into(), flash: None };
        let card = |pays: Value| rental_card(&ctx, &json!({"rental": "r1", "hasher": "Hashrate", "budgetSats": 1500, "ended": true,
                                                          "live": {"role": "buyer", "meter": {}, "closed": "hashmaker closed: unpaid", "pays": pays}}), "hashrate");
        let c = card(json!([{"slice": 1, "ok": false, "why": "This hashmaker's smallest ticket is 900 sats, and 559 sats may leave your wallet for this payment. Nothing was paid for this piece of work."}]));
        assert!(c.contains("smallest ticket is 900 sats") && c.contains("Nothing was paid") && c.contains("not paid in time"), "{c}");
        let c = card(json!([{"slice": 9, "ok": false, "why": "Your wallet's rules stopped this payment: the task's budget_sats. Nothing more was paid."}]));
        assert!(c.contains("budget_sats"), "{c}");
        let c = card(json!([{"slice": 1, "ok": false, "why": "{\"verdict\":\"deny\",\"rule\":\"price_ceiling\"}"}]));
        assert!(!c.contains("price_ceiling"), "{c}");
    }

    #[test]
    fn a_rental_is_connecting_until_its_link_opens_and_one_that_never_opens_says_why() {
        let ctx = Ctx { sid: String::new(), csrf: "c".into(), flash: None };
        let card = |live: Value, ended: bool| rental_card(&ctx, &json!({"rental": "r1", "hasher": "Hashrate", "budgetSats": 1500, "ended": ended, "live": live}), "hashrate");
        let c = card(json!({"closed": null}), false);
        assert!(c.contains("Connecting…") && !c.contains("Hashing"), "{c}");
        let c = card(json!({"role": "buyer", "meter": {"accepted": 3}, "closed": null}), false);
        assert!(c.contains("Hashing"), "{c}");
        let c = card(json!({"closed": "could not start: link i/o: Operation timed out (os error 110)"}), true);
        assert!(c.contains("Could not start") && c.contains("It could not start: link i/o: Operation timed out") && c.contains("Nothing was paid."), "{c}");
        assert!(!c.contains("Hashing") && !c.contains(">Cut<"), "{c}");
    }

    use super::*;

    #[test]
    fn a_history_and_a_test_slice_read_plainly() {
        assert!(history_panel(&json!({"records": 0})).contains("No delivery history yet"));
        let says = history_panel(&json!({"records": 0, "hashmakerSays": {"rentals": 3, "thHours": 12.4}}));
        assert!(says.contains("served 3 rentals (12 TH-hours)"), "{says}");
        let h = history_panel(&json!({
            "records": 4, "confirmed": 3, "disputed": 1, "verifiedThHours": 2.5, "deliveredVsAdvertised": 0.97,
            "recent": [{"deliveredHs": "3900000000000", "ratio": 0.97, "confirmed": true, "trial": true}],
        }));
        assert!(h.contains("2.5 TH-hours confirmed by both sides"), "{h}");
        assert!(h.contains("4 records (3 confirmed)"));
        assert!(h.contains("delivered about 97% of what it advertised"));
        assert!(h.contains("1 disputed"));
        assert!(h.contains("3.90 TH/s test slice (97%, confirmed)"), "{h}");
        let r = result_box(&json!({"deliveredHs": 3_900_000_000_000u64, "advertisedHs": 4_000_000_000_000u64, "ratio": 0.975,
                                    "staleShare": 0.01, "rejectedShare": 0.02, "latencyMsP50": 110, "latencyMsP95": 300}), true);
        assert!(r.contains("What the test slice showed"), "{r}");
        assert!(r.contains("3.90 TH/s against 4.00 TH/s advertised (98%)"), "{r}");
        assert!(r.contains("stale shares 1% · rejected 2%"));
        assert!(r.contains("share round trip 110 ms, 300 ms at worst"));
        assert_eq!(result_box(&Value::Null, true), "");
    }

    #[test]
    fn the_upstreams_blinding_is_said_plainly_and_names_no_pool() {
        assert_eq!(blinding_card(&Value::Null), "", "not looked at yet");
        let c = blinding_card(&json!({"state": "blinded", "why": "solo", "words": "Blinded: a hashmaker can't tell which shares win, so it can't drop those."}));
        assert!(c.contains("pill good") && c.contains("Winning shares are hidden") && c.contains("Blinded:"), "{c}");
        let c = blinding_card(&json!({"state": "not blinded", "words": "Not blinded: its key is null. <refused>"}));
        assert!(c.contains("pill bad") && c.contains("&lt;refused&gt;"), "{c}");
        assert!(blinding_card(&json!({"state": "can't be checked", "words": "w"})).contains("pill warn"));
    }

    const MAINNET: Tip = Tip { difficulty: 6.33e9, subsidy_sats: 312_500_000, height: 970_000 };

    fn tip_json(now: u64) -> Value {
        json!({"reachable": true, "chain": "main", "height": 970_000, "headers": 970_000, "difficulty": 6.33e9, "tipTime": now - 600,
               "syncing": false, "subsidySats": 312_500_000u64})
    }

    #[test]
    fn a_piece_is_priced_at_what_it_is_worth_when_mined() {
        // subsidy * work / (difficulty * 2^32): 1,617.7 sat for 2^47 at 6.33e9 and 3.125 XBT, 404.4 for 2^45
        assert!((worth_sat(1 << 47, &MAINNET) - 1617.69).abs() < 0.01);
        assert!((worth_sat(1 << 45, &MAINNET) - 404.42).abs() < 0.01);
        let market = json!({"priceMode": "market", "pricePct": 100});
        assert_eq!(want(&market, Ok(&MAINNET), Some(4e12)).unwrap(), Want { price_sat: 404, slice_work: 1 << 45, start_slices: 1 });
        // a percent of it
        let half = json!({"priceMode": "market", "pricePct": 50});
        assert_eq!(want(&half, Ok(&MAINNET), Some(4e12)).unwrap().price_sat, 202);
        // the default, and a settings file from before (the old 40 sat suggestion goes)
        assert_eq!(pricing(&json!({})), Pricing::Market(100));
        assert_eq!(pricing(&json!({"priceSat": 40, "sliceWork": "140737488355328"})), Pricing::Market(100));
        // a price an owner typed before is kept, for the piece it was typed for
        assert_eq!(pricing(&json!({"priceSat": 60, "sliceWork": "140737488355328"})), Pricing::Fixed { sat: 60, per: 1 << 47 });
    }

    #[test]
    fn a_new_difficulty_gives_a_new_price() {
        let market = json!({"priceMode": "market", "sliceWork": "35184372088832"});
        let at = |d: f64| want(&market, Ok(&Tip { difficulty: d, ..MAINNET }), Some(4e12)).unwrap();
        assert_eq!(at(6.33e9).price_sat, 404);
        assert_eq!(at(7.0e9).price_sat, 366, "harder: worth less");
        assert_eq!(at(5.0e9).price_sat, 512);
        // and a halving halves it
        assert_eq!(want(&market, Ok(&Tip { subsidy_sats: 156_250_000, ..MAINNET }), Some(4e12)).unwrap().price_sat, 202);
    }

    #[test]
    fn with_no_live_difficulty_a_market_price_is_none_and_a_fixed_one_is_kept() {
        let now = 2_000_000_000;
        assert_eq!(tip_of(&tip_json(now), now).unwrap(), MAINNET);
        let bad = |k: &str, v: Value| {
            let mut t = tip_json(now);
            t[k] = v;
            tip_of(&t, now).unwrap_err()
        };
        assert!(bad("reachable", json!(false)).contains("does not answer"));
        assert!(bad("difficulty", Value::Null).contains("difficulty"));
        assert!(bad("difficulty", json!(0.0)).contains("difficulty"));
        assert!(bad("subsidySats", Value::Null).contains("block reward"), "no subsidy is no price: none is made up");
        assert!(bad("syncing", json!(true)).contains("catching up"));
        assert!(bad("syncing", Value::Null).contains("catching up"), "a node that doesn't say is not taken as synced");
        assert!(bad("headers", json!(970_010)).contains("catching up"));
        assert!(bad("tipTime", json!(now - 2 * 86_400)).contains("no new block"));
        // an older signer has no `mining_tip`: what it answers instead is no tip
        assert!(tip_of(&json!({"error": "unknown method"}), now).is_err());
        let market = json!({"priceMode": "market"});
        assert_eq!(want(&market, Err("your XBT node does not answer"), Some(4e12)).unwrap_err(), "your XBT node does not answer");
        let fixed = json!({"priceMode": "fixed", "fixedPriceSat": 300, "fixedSliceWork": "35184372088832"});
        assert_eq!(want(&fixed, Err("down"), Some(4e12)).unwrap(), Want { price_sat: 300, slice_work: 1 << 45, start_slices: 1 });
        let words = price_words(&Err("your XBT node does not answer".into()), None, None, true);
        assert!(words.contains("No live price") && words.contains("no new rental starts") && words.contains("A fixed price works without it"), "{words}");
    }

    #[test]
    fn a_fixed_price_is_kept_and_scales_with_the_piece() {
        let fixed = json!({"priceMode": "fixed", "fixedPriceSat": 300, "fixedSliceWork": "35184372088832"});
        // whatever the difficulty
        for d in [1e9, 6.33e9, 9e9] {
            assert_eq!(want(&fixed, Ok(&Tip { difficulty: d, ..MAINNET }), Some(4e12)).unwrap().price_sat, 300);
        }
        // a faster miner: a piece eight times bigger, at eight times the price (the same price per hash)
        assert_eq!(want(&fixed, Ok(&MAINNET), Some(41e12)).unwrap(), Want { price_sat: 2400, slice_work: 1 << 48, start_slices: 2 });
        // a piece the owner typed stays its size
        let typed = json!({"priceMode": "fixed", "fixedPriceSat": 300, "fixedSliceWork": "35184372088832", "sliceFixed": true, "sliceWork": "35184372088832"});
        assert_eq!(want(&typed, Ok(&MAINNET), Some(100e12)).unwrap().slice_work, 1 << 45);
    }

    #[test]
    fn the_piece_and_the_start_fee_at_1_4_41_and_100_th() {
        let market = json!({"priceMode": "market"});
        let at = |ths: f64| want(&market, Ok(&MAINNET), Some(ths * 1e12)).unwrap();
        // (piece, price, start fee in pieces): a piece is about 7.5 s, the fee about 12 s in whole pieces
        assert_eq!(at(1.0), Want { price_sat: 101, slice_work: 1 << 43, start_slices: 1 });
        assert_eq!(at(4.0), Want { price_sat: 404, slice_work: 1 << 45, start_slices: 1 });
        assert_eq!(at(41.0), Want { price_sat: 3235, slice_work: 1 << 48, start_slices: 2 });
        assert_eq!(at(100.0), Want { price_sat: 6471, slice_work: 1 << 49, start_slices: 2 });
        // the fee in seconds of the miner's work
        for (ths, lo, hi) in [(1.0, 8.0, 9.0), (4.0, 8.0, 9.0), (41.0, 13.0, 14.0), (100.0, 11.0, 12.0)] {
            let w = at(ths);
            let secs = w.start_slices as f64 * w.slice_work as f64 / (ths * 1e12);
            assert!((lo..hi).contains(&secs), "{ths} TH/s: {secs} s");
        }
        // not measured yet: sized as for an S11
        assert_eq!(want(&market, Ok(&MAINNET), None).unwrap(), at(4.0));
        // what the owner reads
        let words = price_words(&Ok(at(41.0)), Some(&MAINNET), Some(41e12), true);
        assert!(words.contains("It costs <strong>3,235 sats</strong>") && words.contains("start fee of <strong>6,470 sats</strong> (2 pieces of work, about 14 seconds"), "{words}");
    }

    #[test]
    fn a_speed_that_wobbles_keeps_the_piece_its_size() {
        let now = Some(1u128 << 45);
        for hs in [2.8e12, 3.3e12, 4.1e12, 4.9e12, 5.5e12] {
            assert_eq!(slice_for(hs, now), 1 << 45, "{hs}");
        }
        // a miner far off it: resized
        assert_eq!(slice_for(2.0e12, now), 1 << 44);
        assert_eq!(slice_for(41e12, now), 1 << 48);
        // and the price with it: a wobble changes neither
        let market = json!({"priceMode": "market", "sliceWork": "35184372088832", "startSlices": 1});
        for hs in [2.8e12, 3.0e12, 4.1e12, 5.0e12, 5.5e12] {
            assert_eq!(want(&market, Ok(&MAINNET), Some(hs)).unwrap(), Want { price_sat: 404, slice_work: 1 << 45, start_slices: 1 }, "{hs}");
        }
        // the fee alone, far off its seconds: set again
        assert_eq!(start_slices_for(4e12, 1 << 45, Some(5)), 1);
        assert_eq!(start_slices_for(5e12, 1 << 45, None), 2, "with nothing in force, the nearest");
    }

    #[test]
    fn the_hashmaker_is_warned_below_mining_value_and_not_at_it() {
        let worth_404 = Want { price_sat: 404, slice_work: 1 << 45, start_slices: 1 };
        let at = price_words(&Ok(worth_404), Some(&MAINNET), Some(4e12), true);
        assert!(!at.contains("Below mining value"), "rounded to the sat is not below: {at}");
        assert!(at.contains("worth about 404 sats"), "{at}");
        let low = price_words(&Ok(Want { price_sat: 40, ..worth_404 }), Some(&MAINNET), Some(4e12), false);
        assert!(low.contains("Below mining value") && low.contains("about 404 sats a piece") && low.contains("compares your price with the mining value only"), "{low}");
        assert!(!low.contains('\u{2014}'), "no em dash: {low}");
        assert!(!price_words(&Ok(Want { price_sat: 500, ..worth_404 }), Some(&MAINNET), Some(4e12), false).contains("Below mining value"));
        // with no tip there is nothing to compare with
        assert!(!price_words(&Ok(Want { price_sat: 40, ..worth_404 }), None, None, false).contains("Below mining value"));
    }

    #[test]
    fn the_offer_shows_its_start_fee() {
        assert_eq!(start_fee_words(404.0, 0, (1u128 << 45) as f64, 4e12), "");
        let f = start_fee_words(3235.0, 2, (1u128 << 48) as f64, 41e12);
        assert!(f.contains("Start fee: <strong>6,470 sats</strong>, about 14 seconds of a machine") && f.contains("paid first"), "{f}");
    }

    #[test]
    fn what_the_hasher_shows_sizes_the_piece() {
        let st = json!({"miners": [{"connected": true, "hashrateHs": 4.1e12}, {"connected": true, "hashrateHs": 41e12}, {"connected": false, "hashrateHs": 99e12}],
                        "rentals": [{"rental": "r1"}], "paused": null});
        assert_eq!(seen(&st), Seen { hs: Some(41e12), measuring: false, rentals: 1, paused: false });
        let new = json!({"miners": [{"connected": true, "hashrateHs": 0.0}], "rentals": [], "paused": "no miner measured yet"});
        assert_eq!(seen(&new), Seen { hs: None, measuring: true, rentals: 0, paused: true });
        assert_eq!(seen(&Value::Null), Seen::default());
    }

    #[test]
    fn speeds_and_prices_read_plainly() {
        assert_eq!(speed(4.1e12), "4.10 TH/s");
        assert_eq!(speed(8.5e11), "850.00 GH/s");
        assert_eq!(speed(0.0), "—");
        // 12 sats a piece of 2^47 hashes: about 307 sats an hour for 1 TH/s, about 7,367 a day
        assert_eq!(per_ths_day(12.0, OLD_SLICE_WORK as f64).round(), 7367.0);
        // 40 sats a piece of 2^47 hashes, at 4 TH/s: about 4,093 sats an hour
        let h = per_hour(40.0, OLD_SLICE_WORK as f64, 4e12);
        assert!((h - 4093.0).abs() < 1.0, "{h}");
        assert_eq!(sats_n(4093.4), "4,093 sats");
        assert_eq!(sats_n(1.0), "1 sat");
        assert_eq!(ended_words("hasher closed: unpaid"), "A piece of work was not paid in time.");
        assert_eq!(ended_words("cut by the buyer"), "You cut it.");
        assert_eq!(ended_words("hashtaker closed: cut by the hashtaker"), "You cut it.");
        assert_eq!(ended_words("hashmaker closed: stopped by the hashmaker"), "The hashmaker stopped it.");
        // the words xbt_hashlink::hashmaker ends these with
        assert_eq!(ended_words("hashmaker closed: no first payment"), "The first piece of work was not paid in time.");
        assert_eq!(ended_words("the gateway's jobs aren't blinded"), "Your pool's jobs don't hide which shares win, so the hashmaker could drop those. The rental stopped.");
        assert_eq!(ended_words("hashmaker closed: a difficulty too high for the slice"), "The hashmaker stopped it: your pool asked for harder work than its pieces of work allow.");
    }
}
