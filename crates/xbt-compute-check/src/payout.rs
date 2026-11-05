//! Paying the machines of a split by the work they do, from what the seller's gateway earned.
//!
//! The seller's box runs a gateway that sells one model by the token, and a Mesh-LLM node that serves
//! it, split over machines. Each round reads what the gateway has earned in all and the stage plan
//! now, splits what is new by each stage's active parameters ([`crate::meter`]), and pays each lender
//! what it is owed through the owner's wallet: `ln_pay` of one BOLT 12 offer of the lender's own node,
//! under the owner's policy.
//!
//! **Paid is what the wallet says settled, and nothing else.** A payment is noted in the ledger, on
//! disk, before the wallet is asked. A note still open at the next round (the tool was killed, or
//! lost the answer) is not retried: the tool first takes the wallet's spend lock, which waits for
//! anything the wallet is still doing with the note's payment, then credits what the wallet settled.
//! The wallet's own retry guards an unpaid invoice only: once one has settled, the same call
//! would fetch another and pay it, so a blind retry here would pay a lender twice.
//!
//! Every msat the gateway earned is in exactly one place: split (a party's accrual) or `unsplit` (what
//! the gateway earned while it sold something other than the model, which stays the operator's). Each
//! plan's earnings are split as a whole, not round by round, so that rounding never leans the same
//! way for ever. Routing fees are the operator's, so a lender receives its amounts exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::meter::{split, Work};

/// The party a stage on the operator's own machines, and the operator's cut, accrue to.
pub const OPERATOR: &str = "operator";
/// How many of the wallet's newest audit events are read for payments that settled.
const HISTORY_EVENTS: u64 = 5000;
/// Longest a payment can keep the wallet busy before it answers.
const PAY_WAIT: Duration = Duration::from_secs(20 * 60);

#[derive(Clone, Debug, Deserialize)]
pub struct Lender {
    #[serde(default)]
    pub name: String,
    /// A BOLT 12 offer of the lender's node, with no amount.
    pub offer: String,
    /// The wallet's name for what pays that offer (`ln-offer:<id>`), read from the offer at the start.
    #[serde(default)]
    pub dest: String,
}

fn default_floor() -> u64 {
    1000
}
fn default_fee_base() -> u64 {
    10
}
fn default_fee_ppm() -> u64 {
    5000
}
fn default_interval() -> u64 {
    60
}
fn default_retry() -> u64 {
    600
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The gateway, on this machine: its health is the operator's view, for loopback only.
    pub gateway_url: String,
    /// Its `health_token`, where the gateway is in another container.
    #[serde(default)]
    pub gateway_health_token: Option<String>,
    /// The Mesh-LLM node's console, on this machine.
    pub mesh_console_url: String,
    /// The model's id in Mesh-LLM, when it serves more than one.
    #[serde(default)]
    pub model: Option<String>,
    /// The model's GGUF file: its header is enough.
    pub gguf: PathBuf,
    pub signer_sock: PathBuf,
    pub ledger: PathBuf,
    #[serde(default)]
    pub report: Option<PathBuf>,
    /// The operator's cut of each msat earned, in millionths, before the split.
    #[serde(default)]
    pub operator_cut_ppm: u32,
    /// Mesh-LLM node ids of the operator's own machines: their stages accrue to the operator, unpaid.
    #[serde(default)]
    pub own_nodes: Vec<String>,
    /// By Mesh-LLM node id.
    #[serde(default)]
    pub lenders: BTreeMap<String, Lender>,
    /// A lender is paid when it is owed this many sats.
    #[serde(default = "default_floor")]
    pub min_payout_sats: u64,
    /// The most routing one payment may cost: a base and millionths of the amount. The wallet refuses a
    /// payment under its own `ln.max_fee_base_sats` and `ln.max_fee_ppm`, whose defaults these are.
    #[serde(default = "default_fee_base")]
    pub fee_base_sats: u64,
    #[serde(default = "default_fee_ppm")]
    pub fee_ppm: u64,
    #[serde(default = "default_interval")]
    pub interval_s: u64,
    /// How long a refused lender is left before the wallet is asked again.
    #[serde(default = "default_retry")]
    pub retry_s: u64,
}

/// One stage of Mesh-LLM's plan.
#[derive(Clone, Debug, PartialEq)]
pub struct Stage {
    pub node: String,
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    pub id: String,
    pub stages: Vec<Stage>,
}

/// The plan of `model` in Mesh-LLM's `/api/runtime/stages`. `None`: no split, the whole model on the
/// node itself.
pub fn parse_plan(v: &Value, model: Option<&str>) -> Result<Option<Plan>, String> {
    let all = v.get("topologies").and_then(Value::as_array).ok_or("the stage report has no topologies")?;
    let of: Vec<&Value> = all.iter().filter(|t| model.is_none_or(|m| t.get("model_id").and_then(Value::as_str) == Some(m))).collect();
    let t = match of.as_slice() {
        [] => return Ok(None),
        [t] => t,
        more => return Err(format!("{} topologies at once: name the model, or wait for the node to finish changing them", more.len())),
    };
    let id = t.get("topology_id").and_then(Value::as_str).ok_or("a topology with no id")?.to_string();
    let mut stages = vec![];
    for s in t.get("stages").and_then(Value::as_array).ok_or("a topology with no stages")? {
        let layer = |k: &str| s.get(k).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or_else(|| format!("a stage with no {k}"));
        stages.push(Stage { node: s.get("node_id").and_then(Value::as_str).ok_or("a stage with no node")?.to_string(), start: layer("layer_start")?, end: layer("layer_end")? });
    }
    stages.sort_by_key(|s| s.start);
    Ok(Some(Plan { id, stages }))
}

/// What a plan's earnings are split by, and what it has earned. Fixed when the plan starts, so a
/// change of the config or the plan closes it and starts another.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Epoch {
    pub plan: String,
    pub cut_ppm: u32,
    /// Each party's active parameters, in stage order.
    pub stages: Vec<(String, u64)>,
    pub earned_msat: u64,
}

impl Epoch {
    fn of(cfg: &Config, work: &Work, plan: Option<&Plan>) -> Result<Epoch, String> {
        let mut stages: Vec<(String, u64)> = vec![];
        let id = plan.map_or_else(|| "whole".to_string(), |p| p.id.clone());
        if let Some(p) = plan {
            let mut at = 0;
            for s in &p.stages {
                if s.start != at || s.end <= s.start || s.end as usize > work.layers.len() {
                    return Err(format!("stage {}..{} after layer {at}: not this model's layers ({})", s.start, s.end, work.layers.len()));
                }
                at = s.end;
                let party = if cfg.own_nodes.contains(&s.node) { OPERATOR.to_string() } else { s.node.clone() };
                let w = u64::try_from(work.stage(s.start, s.end)).map_err(|_| "a stage too big to count")?;
                match stages.iter_mut().find(|(n, _)| *n == party) {
                    Some((_, sum)) => *sum += w,
                    None => stages.push((party, w)),
                }
            }
            if at as usize != work.layers.len() {
                return Err(format!("the stages end at layer {at} of {}", work.layers.len()));
            }
        }
        Ok(Epoch { plan: id, cut_ppm: cfg.operator_cut_ppm, stages, earned_msat: 0 })
    }

    fn same_terms(&self, o: &Epoch) -> bool {
        (&self.plan, self.cut_ppm, &self.stages) == (&o.plan, o.cut_ppm, &o.stages)
    }

    /// What each party has of this plan's earnings: they sum to them exactly.
    fn parts(&self) -> BTreeMap<String, u64> {
        let cut = (self.earned_msat as u128 * self.cut_ppm as u128 / 1_000_000) as u64;
        let rest = self.earned_msat - cut;
        let weights: Vec<u128> = self.stages.iter().map(|(_, w)| *w as u128).collect();
        let mut out = BTreeMap::new();
        *out.entry(OPERATOR.to_string()).or_insert(0) += cut;
        match split(rest, &weights) {
            Some(parts) => self.stages.iter().zip(parts).for_each(|((n, _), p)| *out.entry(n.clone()).or_insert(0) += p),
            None => *out.entry(OPERATOR.to_string()).or_insert(0) += rest,
        }
        out
    }
}

/// A payment the wallet was or is about to be asked for, on disk before it is asked.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Intent {
    pub party: String,
    pub sats: u64,
    pub ts: f64,
    /// The wallet's name for the payment, once it has said.
    pub hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Refusal {
    pub rule: String,
    pub reason: String,
    /// Not asked again before this.
    pub until: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Ledger {
    /// What the gateway had earned in all when last read; `None` until first read. Earnings from
    /// before that are not split.
    pub last_charged_msat: Option<u64>,
    /// Everything taken in since: the accruals and `unsplit_msat` sum to it.
    pub earned_msat: u64,
    /// Earned while the gateway sold something beside the model: the operator's, not split.
    pub unsplit_msat: u64,
    /// By party, of plans that have ended.
    pub closed: BTreeMap<String, u64>,
    pub epoch: Option<Epoch>,
    /// By party, as the wallet recorded it.
    pub paid_msat: BTreeMap<String, u64>,
    pub fees_msat: u64,
    /// The wallet's payments already counted in `paid_msat`.
    pub credited: BTreeSet<String>,
    pub intent: Option<Intent>,
    pub refused: BTreeMap<String, Refusal>,
}

impl Ledger {
    /// What each party has earned so far.
    pub fn accrued(&self) -> BTreeMap<String, u64> {
        let mut out = self.closed.clone();
        if let Some(e) = &self.epoch {
            e.parts().into_iter().for_each(|(k, v)| *out.entry(k).or_insert(0) += v);
        }
        out
    }

    /// Accrued and not yet paid. Below zero by a msat at most: a plan's parts are worked out anew as
    /// its earnings grow.
    pub fn owed(&self, party: &str) -> i128 {
        *self.accrued().get(party).unwrap_or(&0) as i128 - *self.paid_msat.get(party).unwrap_or(&0) as i128
    }
}

/// How the wallet answered `ln_pay`.
#[derive(Clone, Debug, PartialEq)]
pub enum Paid {
    Settled { hash: String },
    /// In flight: the booked amount stays until the node settles or fails it.
    Pending { hash: String },
    /// Nothing was paid, and the wallet said why.
    Refused { rule: String, reason: String },
    /// Nothing was paid, and it can be asked again at once: it is busy, or its socket is not there.
    NotAsked(String),
    /// The question may have reached the wallet, and no answer came.
    Unknown(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Looked {
    pub settled: bool,
    pub failed: bool,
    pub value_msat: u64,
    pub fee_msat: u64,
}

/// What the tool reads and asks of the gateway, Mesh-LLM and the wallet.
pub trait World {
    /// What the gateway has earned in all.
    fn charged_msat(&self) -> Result<u64, String>;
    /// `Ok(Err(what))`: it sells `what` beside the model.
    fn sells_only_the_model(&self) -> Result<Result<(), String>, String>;
    fn plan(&self) -> Result<Option<Plan>, String>;
    fn pay(&self, offer: &str, sats: u64, max_sats: u64) -> Paid;
    /// Waits until the wallet has done with what it was doing; how many payments are then in flight.
    fn barrier(&self) -> Result<usize, String>;
    /// The payments the wallet recorded as settled, as `(dest, hash)`.
    fn settled(&self) -> Result<Vec<(String, String)>, String>;
    fn lookup(&self, hash: &str) -> Result<Looked, String>;
}

fn credit_one(led: &mut Ledger, party: &str, hash: &str, l: &Looked) {
    if l.settled && led.credited.insert(hash.to_string()) {
        *led.paid_msat.entry(party.to_string()).or_insert(0) += l.value_msat;
        led.fees_msat += l.fee_msat;
    }
}

/// Counts every payment to a lender the wallet recorded as settled and the ledger has not counted.
fn credit(cfg: &Config, led: &mut Ledger, w: &dyn World) -> Result<(), String> {
    let by_dest: BTreeMap<&str, &str> = cfg.lenders.iter().map(|(n, l)| (l.dest.as_str(), n.as_str())).collect();
    for (dest, hash) in w.settled()? {
        if let (Some(party), false) = (by_dest.get(dest.as_str()), led.credited.contains(&hash)) {
            let l = w.lookup(&hash)?;
            credit_one(led, party, &hash, &l);
        }
    }
    Ok(())
}

/// The wallet's word first. An open note is closed only once the wallet has done with it. `Ok(true)`:
/// no note is open, so a new payment can be asked for.
fn settle(cfg: &Config, led: &mut Ledger, w: &dyn World, save: &mut dyn FnMut(&Ledger) -> Result<(), String>) -> Result<bool, String> {
    let in_flight = if led.intent.is_some() { Some(w.barrier()?) } else { None };
    credit(cfg, led, w)?;
    if let (Some(n), Some(i)) = (in_flight, led.intent.clone()) {
        let done = match &i.hash {
            Some(h) => {
                let l = w.lookup(h)?;
                credit_one(led, &i.party, h, &l);
                l.settled || l.failed
            }
            // no name for it: with nothing in flight behind the lock, what it did is in the records by now
            None => n == 0,
        };
        if done {
            led.intent = None;
        }
    }
    save(led)?;
    Ok(led.intent.is_none())
}

/// Takes in what the gateway earned since the last round. Something that cannot be read leaves
/// the earnings for the next round; nothing is lost.
fn earn(cfg: &Config, work: &Work, led: &mut Ledger, w: &dyn World, notes: &mut Vec<String>) {
    let charged = match w.charged_msat() {
        Ok(c) => c,
        Err(e) => return notes.push(format!("the gateway's earnings could not be read: {e}")),
    };
    let Some(last) = led.last_charged_msat else {
        led.last_charged_msat = Some(charged);
        return;
    };
    if charged < last {
        notes.push(format!("the gateway says {charged} msat earned in all, below the {last} last read: a new state directory? Counting from here"));
        led.last_charged_msat = Some(charged);
        return;
    }
    let delta = charged - last;
    match w.sells_only_the_model() {
        Err(e) => return notes.push(format!("what the gateway sells could not be read: {e}")),
        Ok(Err(what)) => {
            notes.push(format!("the gateway sells {what} beside the model, so its {delta} msat earned since the last round are not split"));
            led.unsplit_msat += delta;
            led.earned_msat += delta;
            led.last_charged_msat = Some(charged);
            return;
        }
        Ok(Ok(())) => {}
    }
    let plan = match w.plan() {
        Ok(p) => p,
        Err(e) => return notes.push(format!("the stage plan could not be read: {e}")),
    };
    let next = match Epoch::of(cfg, work, plan.as_ref()) {
        Ok(e) => e,
        Err(e) => return notes.push(format!("the stage plan cannot be used: {e}")),
    };
    // what came in since the last round went to the plan in force then; the new one counts from here
    let mut current = led.epoch.take().unwrap_or_else(|| next.clone());
    current.earned_msat += delta;
    if current.same_terms(&next) {
        led.epoch = Some(current);
    } else {
        current.parts().into_iter().for_each(|(k, v)| *led.closed.entry(k).or_insert(0) += v);
        led.epoch = Some(next);
    }
    led.earned_msat += delta;
    led.last_charged_msat = Some(charged);
}

/// Pays each lender owed at least the floor, one at a time, each noted before the wallet is asked.
fn pay_round(cfg: &Config, led: &mut Ledger, w: &dyn World, save: &mut dyn FnMut(&Ledger) -> Result<(), String>, now: f64, notes: &mut Vec<String>) -> Result<(), String> {
    for (node, lender) in &cfg.lenders {
        let owed = led.owed(node);
        if owed < cfg.min_payout_sats as i128 * 1000 || led.refused.get(node).is_some_and(|r| now < r.until) {
            continue;
        }
        let sats = (owed / 1000) as u64;
        led.intent = Some(Intent { party: node.clone(), sats, ts: now, hash: None });
        save(led)?;
        match w.pay(&lender.offer, sats, sats + cfg.fee_base_sats + (sats * cfg.fee_ppm).div_ceil(1_000_000)) {
            Paid::Settled { hash } => {
                if let Some(i) = &mut led.intent {
                    i.hash = Some(hash.clone());
                }
                save(led)?;
                let l = w.lookup(&hash)?;
                if !l.settled {
                    // it said settled and its book does not yet: the note stays, and no one else is asked
                    return Err(format!("the wallet said {hash} settled, and its record says otherwise"));
                }
                credit_one(led, node, &hash, &l);
                led.intent = None;
                led.refused.remove(node);
                save(led)?;
            }
            Paid::Refused { rule, reason } => {
                notes.push(format!("{}: refused ({rule}): {reason}", display(node, lender)));
                led.intent = None;
                led.refused.insert(node.clone(), Refusal { rule, reason, until: now + cfg.retry_s as f64 });
                save(led)?;
            }
            Paid::NotAsked(e) => {
                notes.push(format!("{}: not paid this round: {e}", display(node, lender)));
                led.intent = None;
                save(led)?;
                return Ok(());
            }
            Paid::Pending { hash } => {
                // with no name for it, the note closes when nothing is in flight
                if let Some(i) = &mut led.intent {
                    i.hash = Some(hash).filter(|h| !h.is_empty());
                }
                save(led)?;
                return Ok(());
            }
            Paid::Unknown(e) => {
                notes.push(format!("{}: no answer from the wallet, the note stays: {e}", display(node, lender)));
                return Ok(());
            }
        }
    }
    Ok(())
}

fn display<'a>(node: &'a str, lender: &'a Lender) -> &'a str {
    if lender.name.is_empty() { node } else { &lender.name }
}

/// One round: the wallet's word, then the earnings, then the payments. What it could not do it says.
pub fn tick(cfg: &Config, work: &Work, led: &mut Ledger, w: &dyn World, save: &mut dyn FnMut(&Ledger) -> Result<(), String>, now: f64) -> Result<Vec<String>, String> {
    let mut notes = vec![];
    let clear = match settle(cfg, led, w, save) {
        Ok(c) => c,
        Err(e) => {
            // the wallet is not answering: the earnings still count, and nothing is paid
            notes.push(format!("the wallet's records could not be read: {e}"));
            false
        }
    };
    earn(cfg, work, led, w, &mut notes);
    save(led)?;
    if clear {
        if let Err(e) = pay_round(cfg, led, w, save, now, &mut notes) {
            notes.push(e);
        }
    } else if let Some(i) = &led.intent {
        notes.push(format!("waiting for the wallet on {} sats to {}", i.sats, i.party));
    }
    Ok(notes)
}

/// The ledger as the operator and the lenders read it.
pub fn report(cfg: &Config, led: &Ledger, notes: &[String]) -> Value {
    let accrued = led.accrued();
    let mut parties = serde_json::Map::new();
    for (party, a) in &accrued {
        let lender = cfg.lenders.get(party);
        parties.insert(party.clone(), json!({
            "name": lender.map(|l| l.name.as_str()).unwrap_or(""), "accrued_msat": a, "paid_msat": led.paid_msat.get(party).copied().unwrap_or(0),
            "owed_msat": led.owed(party).to_string(), "can_be_paid": party != OPERATOR && lender.is_some(), "refused": led.refused.get(party),
        }));
    }
    json!({"earned_msat": led.earned_msat, "unsplit_msat": led.unsplit_msat, "fees_msat": led.fees_msat, "parties": parties, "plan": led.epoch, "open_note": led.intent, "notes": notes})
}

/// Writes the ledger whole, on disk before it returns: a crash leaves the last one or this one.
pub fn save_ledger(path: &Path, led: &Ledger) -> Result<(), String> {
    use std::io::Write;
    let say = |e: std::io::Error| format!("{}: {e}", path.display());
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(say)?;
    f.write_all(&serde_json::to_vec_pretty(led).map_err(|e| e.to_string())?).map_err(say)?;
    f.sync_all().map_err(say)?;
    std::fs::rename(&tmp, path).map_err(say)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(say)?;
    }
    Ok(())
}

pub fn load_ledger(path: &Path) -> Result<Ledger, String> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn number(v: Option<&Value>) -> u64 {
    match v {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

/// The gateway, Mesh-LLM and the wallet of this machine.
pub struct Live {
    pub cfg: Config,
}

impl Live {
    fn get(&self, url: &str, token: Option<&str>) -> Result<Value, String> {
        let mut r = ureq::get(url).timeout(Duration::from_secs(10));
        if let Some(t) = token {
            r = r.set("X-Xbt402-Health-Token", t);
        }
        let text = r.call().map_err(|e| format!("{url}: {e}"))?.into_string().map_err(|e| format!("{url}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{url}: {e}"))
    }

    fn signer(&self, wait: Duration, method: &str, params: &Value) -> Result<Value, (bool, String)> {
        xbt_wallet_mcp::wallet::signer_call_waiting(&self.cfg.signer_sock, Duration::from_secs(30), Some(wait), method, params)
    }
}

/// What a route of the gateway's `/services` sells, if it is not a model by the token.
pub fn other_sales(services: &Value) -> Option<String> {
    services.get("routes").and_then(Value::as_array)?.iter().find_map(|r| {
        let free = r.get("free").and_then(Value::as_bool) == Some(true);
        let by_token = r.get("price").and_then(|p| p.get("outputPer1kMsat")).is_some();
        (!free && !by_token).then(|| r.get("path").and_then(Value::as_str).unwrap_or("a route").to_string())
    })
}

impl World for Live {
    fn charged_msat(&self) -> Result<u64, String> {
        let url = format!("{}/x402/ticket/health", self.cfg.gateway_url.trim_end_matches('/'));
        let v = self.get(&url, self.cfg.gateway_health_token.as_deref())?;
        v.get("chargedMsat").and_then(Value::as_str).and_then(|s| s.parse().ok()).ok_or_else(|| "the gateway's health has no chargedMsat".to_string())
    }

    fn sells_only_the_model(&self) -> Result<Result<(), String>, String> {
        let v = self.get(&format!("{}/services", self.cfg.gateway_url.trim_end_matches('/')), None)?;
        if v.get("routes").and_then(Value::as_array).is_none() {
            return Err("the gateway's /services lists no routes".into());
        }
        Ok(other_sales(&v).map_or(Ok(()), Err))
    }

    fn plan(&self) -> Result<Option<Plan>, String> {
        let v = self.get(&format!("{}/api/runtime/stages", self.cfg.mesh_console_url.trim_end_matches('/')), None)?;
        parse_plan(&v, self.cfg.model.as_deref())
    }

    fn pay(&self, offer: &str, sats: u64, max_sats: u64) -> Paid {
        match self.signer(PAY_WAIT, "ln_pay", &json!({"invoice": offer, "amount_sats": sats, "max_sats": max_sats})) {
            // the signer's socket was never reached: nothing can have been paid
            Err((false, e)) => Paid::NotAsked(e),
            Err((true, e)) => Paid::Unknown(e),
            Ok(v) => paid_of(&v),
        }
    }

    fn barrier(&self) -> Result<usize, String> {
        let v = self.signer(PAY_WAIT, "ln_status", &json!({})).map_err(|(_, e)| e)?;
        // a wallet that does not say (its rail is off, or not ready) cannot close a note
        v.get("in_flight").and_then(Value::as_u64).map(|n| n as usize)
            .ok_or_else(|| format!("the wallet does not say what is in flight: {}", v.get("reason").and_then(Value::as_str).unwrap_or("no reason given")))
    }

    fn settled(&self) -> Result<Vec<(String, String)>, String> {
        let v = self.signer(Duration::from_secs(30), "history", &json!({"limit": HISTORY_EVENTS})).map_err(|(_, e)| e)?;
        let events = v.get("events").and_then(Value::as_array).ok_or("the wallet's history has no events")?;
        Ok(events.iter().filter(|e| e.get("type").and_then(Value::as_str) == Some("ln_settled"))
            .filter_map(|e| Some((e.get("dest")?.as_str()?.to_string(), e.get("payment_hash")?.as_str()?.to_string()))).collect())
    }

    fn lookup(&self, hash: &str) -> Result<Looked, String> {
        let v = self.signer(Duration::from_secs(30), "ln_lookup", &json!({"payment_hash": hash})).map_err(|(_, e)| e)?;
        let state = v.get("state").and_then(Value::as_str).unwrap_or("");
        Ok(Looked { settled: state == "settled", failed: state == "failed", value_msat: number(v.get("value_msat")), fee_msat: number(v.get("fee_msat")) })
    }
}

/// The wallet's answer to `ln_pay`.
pub fn paid_of(v: &Value) -> Paid {
    let hash = v.get("payment_hash").and_then(Value::as_str).unwrap_or("").to_string();
    let verdict = v.get("verdict").and_then(Value::as_str);
    let rule = v.get("rule").and_then(Value::as_str).or(verdict).unwrap_or("").to_string();
    let reason = v.get("reason").and_then(Value::as_str).unwrap_or("").to_string();
    match verdict {
        Some("allow") if v.get("status").and_then(Value::as_str) == Some("SUCCEEDED") => Paid::Settled { hash },
        Some("pending") => Paid::Pending { hash },
        Some("deny") if rule == "ln_in_flight" => Paid::NotAsked(reason),
        // for the owner to approve: asked again after the wait, as a refusal is
        Some("deny" | "needs_human") => Paid::Refused { rule, reason },
        // whatever else it means, a retry on top of it could pay twice
        _ => Paid::Unknown(format!("the wallet answered {verdict:?} with status {:?}", v.get("status"))),
    }
}

/// Reads the config and fills in each lender's name for the wallet.
pub fn load_config(path: &Path) -> Result<Config, String> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut cfg: Config = serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?;
    for (node, l) in &mut cfg.lenders {
        let o = xbt_signer::bolt12::decode_offer(&l.offer).map_err(|e| format!("lender {node}: not a BOLT 12 offer: {e}"))?;
        l.dest = format!("ln-offer:{}", o.id_hex());
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// How the stand-in wallet takes the next payment.
    #[derive(Clone, Copy, PartialEq)]
    enum Next {
        Settle,
        /// Paid, and the answer never reaches the tool (it was killed, or the socket went).
        SettleAnswerLost,
        /// The tool died before the question reached the wallet.
        NeverReached,
        Refuse,
        Busy,
        Hold,
    }

    /// The gateway, the plan and the wallet and its node, with what each lender's node received.
    struct Fake {
        charged: RefCell<u64>,
        other: RefCell<Option<String>>,
        plan: RefCell<Result<Option<Plan>, String>>,
        script: RefCell<VecDeque<Next>>,
        received: RefCell<BTreeMap<String, u64>>,
        book: RefCell<Vec<(String, String, u64, &'static str)>>,
        asked: RefCell<u64>,
    }

    impl Fake {
        fn new(plan: Plan) -> Fake {
            Fake { charged: RefCell::new(0), other: RefCell::new(None), plan: RefCell::new(Ok(Some(plan))), script: RefCell::new(VecDeque::new()),
                   received: RefCell::new(BTreeMap::new()), book: RefCell::new(vec![]), asked: RefCell::new(0) }
        }
        fn earn(&self, msat: u64) {
            *self.charged.borrow_mut() += msat;
        }
        fn next(&self, n: Next) {
            self.script.borrow_mut().push_back(n);
        }
        /// A payment held in flight reaches the end of its road.
        fn hold_settles(&self) {
            for b in self.book.borrow_mut().iter_mut().filter(|b| b.3 == "sending") {
                b.3 = "settled";
                *self.received.borrow_mut().entry(b.0.clone()).or_insert(0) += b.2;
            }
        }
        fn node_received(&self, offer: &str) -> u64 {
            *self.received.borrow().get(offer).unwrap_or(&0)
        }
    }

    impl World for Fake {
        fn charged_msat(&self) -> Result<u64, String> {
            Ok(*self.charged.borrow())
        }
        fn sells_only_the_model(&self) -> Result<Result<(), String>, String> {
            Ok(self.other.borrow().clone().map_or(Ok(()), Err))
        }
        fn plan(&self) -> Result<Option<Plan>, String> {
            self.plan.borrow().clone()
        }
        fn pay(&self, offer: &str, sats: u64, _max: u64) -> Paid {
            *self.asked.borrow_mut() += 1;
            let hash = format!("hash{}", self.book.borrow().len());
            let mode = self.script.borrow_mut().pop_front().unwrap_or(Next::Settle);
            let settle = |state: &'static str| {
                self.book.borrow_mut().push((offer.to_string(), hash.clone(), sats * 1000, state));
                if state == "settled" {
                    *self.received.borrow_mut().entry(offer.to_string()).or_insert(0) += sats * 1000;
                }
            };
            match mode {
                Next::Settle => {
                    settle("settled");
                    Paid::Settled { hash }
                }
                Next::SettleAnswerLost => {
                    settle("settled");
                    Paid::Unknown("the socket went".into())
                }
                Next::NeverReached => Paid::Unknown("the socket went".into()),
                Next::Refuse => Paid::Refused { rule: "daily_budget".into(), reason: "over the owner's budget".into() },
                Next::Busy => Paid::NotAsked("another payment is in flight".into()),
                Next::Hold => {
                    settle("sending");
                    Paid::Pending { hash }
                }
            }
        }
        fn barrier(&self) -> Result<usize, String> {
            Ok(self.book.borrow().iter().filter(|b| b.3 == "sending").count())
        }
        fn settled(&self) -> Result<Vec<(String, String)>, String> {
            Ok(self.book.borrow().iter().filter(|b| b.3 == "settled").map(|b| (format!("dest-{}", b.0), b.1.clone())).collect())
        }
        fn lookup(&self, hash: &str) -> Result<Looked, String> {
            Ok(self.book.borrow().iter().find(|b| b.1 == hash).map_or(Looked { settled: false, failed: false, value_msat: 0, fee_msat: 0 }, |b| {
                Looked { settled: b.3 == "settled", failed: b.3 == "failed", value_msat: b.2, fee_msat: 7 }
            }))
        }
    }

    // two layers of 300 parameters, a row of 10, a head of 1010: 310 and 1310 for the two stages
    fn work() -> Work {
        Work { layers: vec![300, 300, 300, 300], embed: 10, head: 1010 }
    }

    fn plan(id: &str, stages: &[(&str, u32, u32)]) -> Plan {
        Plan { id: id.into(), stages: stages.iter().map(|(n, s, e)| Stage { node: (*n).into(), start: *s, end: *e }).collect() }
    }

    fn cfg() -> Config {
        let lender = |o: &str| Lender { name: String::new(), offer: o.into(), dest: format!("dest-{o}") };
        Config { gateway_url: String::new(), gateway_health_token: None, mesh_console_url: String::new(), model: None, gguf: PathBuf::new(), signer_sock: PathBuf::new(),
                 ledger: PathBuf::new(), report: None, operator_cut_ppm: 100_000, own_nodes: vec!["own".into()],
                 lenders: [("a".to_string(), lender("offer-a")), ("b".to_string(), lender("offer-b"))].into(), min_payout_sats: 10, fee_base_sats: 5, fee_ppm: 0, interval_s: 1, retry_s: 100 }
    }

    /// A round, with the ledger saved as a real run saves it: `disk` is what a restart would read.
    fn round(c: &Config, led: &mut Ledger, f: &Fake, disk: &RefCell<Ledger>, now: f64) -> Vec<String> {
        tick(c, &work(), led, f, &mut |l| {
            *disk.borrow_mut() = l.clone();
            Ok(())
        }, now).unwrap()
    }

    /// W-2: every msat earned is in one place, and each lender's accrual is what it was paid and is owed.
    fn balanced(led: &Ledger, f: &Fake) {
        let acc: u64 = led.accrued().values().sum();
        assert_eq!(acc + led.unsplit_msat, led.earned_msat, "{led:?}");
        assert_eq!(led.earned_msat, *f.charged.borrow(), "every msat the gateway earned since the start");
        for (party, offer) in [("a", "offer-a"), ("b", "offer-b")] {
            assert_eq!(*led.paid_msat.get(party).unwrap_or(&0), f.node_received(offer), "the ledger and {party}'s node");
            assert!(led.owed(party) >= -1, "{party}: {}", led.owed(party));
        }
    }

    fn start(c: &Config, f: &Fake) -> (Ledger, RefCell<Ledger>) {
        let mut led = Ledger::default();
        let disk = RefCell::new(Ledger::default());
        round(c, &mut led, f, &disk, 0.0);
        (led, disk)
    }

    #[test]
    fn earnings_split_by_work_and_lenders_are_paid_exactly() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(1_000_000);
        round(&c, &mut led, &f, &disk, 1.0);
        // 10% to the operator, the rest as 610 to 1610 of 2220
        let rest = 900_000u128;
        let a = (rest * 610).div_ceil(2220) as u64;
        assert_eq!(led.accrued()["operator"], 100_000);
        assert!(led.accrued()["a"] == a || led.accrued()["a"] + 1 == a, "{:?}", led.accrued());
        assert_eq!(led.accrued().values().sum::<u64>(), 1_000_000);
        // whole sats are paid and the odd msats stay owed
        assert_eq!(f.node_received("offer-a") % 1000, 0);
        assert!((0..1000).contains(&led.owed("a")) && (0..1000).contains(&led.owed("b")), "{:?}", led);
        assert_eq!(led.fees_msat, 14);
        balanced(&led, &f);
        // a round with nothing new asks for nothing
        let asked = *f.asked.borrow();
        round(&c, &mut led, &f, &disk, 2.0);
        assert_eq!(*f.asked.borrow(), asked);
    }

    #[test]
    fn below_the_floor_nothing_is_paid_and_nothing_is_lost() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        // 1 msat at a time for many rounds: rounding must not lean one way for ever
        for i in 0..2000 {
            f.earn(1);
            round(&c, &mut led, &f, &disk, i as f64);
        }
        assert_eq!(*f.asked.borrow(), 0, "under the 10 sat floor");
        let acc = led.accrued();
        assert_eq!(acc.values().sum::<u64>(), 2000);
        assert_eq!(acc["operator"], 200);
        assert!((acc["a"] as i64 - (1800 * 610 / 2220)).abs() <= 1, "{acc:?}");
        balanced(&led, &f);
    }

    /// W-4: paid, and the answer lost: the restart counts it and does not pay again.
    #[test]
    fn killed_after_the_wallet_paid_never_pays_twice() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(1_000_000);
        f.next(Next::SettleAnswerLost);
        round(&c, &mut led, &f, &disk, 1.0);
        assert!(disk.borrow().intent.is_some(), "the note is on disk");
        let paid_a = f.node_received("offer-a");
        assert!(paid_a > 0);
        // the process dies: what is on disk is all there is
        let mut led = disk.borrow().clone();
        round(&c, &mut led, &f, &disk, 2.0);
        assert_eq!(f.node_received("offer-a"), paid_a, "not paid twice");
        assert_eq!(led.paid_msat["a"], paid_a, "counted from the wallet's record");
        assert!(led.intent.is_none());
        assert!(f.node_received("offer-b") > 0, "and the next lender is paid once the wallet is clear");
        balanced(&led, &f);
    }

    /// W-4: killed before the question reached the wallet: nothing was paid, so it is paid at the restart, once.
    #[test]
    fn killed_before_the_wallet_heard_pays_once_at_the_restart() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(1_000_000);
        f.next(Next::NeverReached);
        round(&c, &mut led, &f, &disk, 1.0);
        assert_eq!(f.node_received("offer-a"), 0);
        assert!(disk.borrow().intent.is_some());
        let mut led = disk.borrow().clone();
        round(&c, &mut led, &f, &disk, 2.0);
        assert!(led.intent.is_none());
        assert_eq!(f.node_received("offer-a"), led.paid_msat["a"]);
        assert!(led.paid_msat["a"] > 0);
        balanced(&led, &f);
    }

    /// W-4: a payment in flight holds everything behind it until it ends; killed meanwhile, the same.
    #[test]
    fn a_payment_in_flight_is_waited_for_and_never_paid_beside() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(1_000_000);
        f.next(Next::Hold);
        round(&c, &mut led, &f, &disk, 1.0);
        assert_eq!(*f.asked.borrow(), 1);
        let mut led = disk.borrow().clone();
        let notes = round(&c, &mut led, &f, &disk, 2.0);
        assert_eq!(*f.asked.borrow(), 1, "nothing new while it is in flight: {notes:?}");
        assert!(led.intent.is_some());
        f.hold_settles();
        round(&c, &mut led, &f, &disk, 3.0);
        assert!(led.intent.is_none());
        assert_eq!(led.paid_msat["a"], f.node_received("offer-a"));
        assert!(led.paid_msat["a"] > 0);
        balanced(&led, &f);
    }

    /// W-5: refused by the owner's policy: owed still, not asked again until the wait is over, then paid once.
    #[test]
    fn a_refused_payment_stays_owed_and_is_paid_once_when_allowed() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(1_000_000);
        f.next(Next::Refuse);
        let notes = round(&c, &mut led, &f, &disk, 1.0);
        assert!(notes.iter().any(|n| n.contains("daily_budget")), "{notes:?}");
        assert_eq!(f.node_received("offer-a"), 0);
        assert!(led.owed("a") > 200 * 1000, "it stays owed: {}", led.owed("a"));
        assert!(f.node_received("offer-b") > 0, "the other lender is not held up");
        let asked = *f.asked.borrow();
        round(&c, &mut led, &f, &disk, 50.0);
        assert_eq!(*f.asked.borrow(), asked, "not asked again inside the wait");
        round(&c, &mut led, &f, &disk, 200.0);
        assert_eq!(*f.asked.borrow(), asked + 1);
        assert_eq!(f.node_received("offer-a"), led.paid_msat["a"]);
        assert!((0..1000).contains(&led.owed("a")));
        assert!(!led.refused.contains_key("a"));
        balanced(&led, &f);
    }

    #[test]
    fn a_busy_wallet_is_asked_again_next_round_with_no_wait() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(1_000_000);
        f.next(Next::Busy);
        let notes = round(&c, &mut led, &f, &disk, 1.0);
        assert!(notes.iter().any(|n| n.contains("in flight")), "{notes:?}");
        assert_eq!(*f.asked.borrow(), 1, "the round stops there");
        assert!(led.intent.is_none() && led.refused.is_empty(), "{led:?}");
        round(&c, &mut led, &f, &disk, 1.5);
        assert!(f.node_received("offer-a") > 0 && f.node_received("offer-b") > 0);
        balanced(&led, &f);
    }

    /// W-6: a new plan: what was earned before it goes by the old one, and no msat is lost.
    #[test]
    fn a_new_plan_splits_from_when_it_starts() {
        let c = cfg();
        let f = Fake::new(plan("one", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(100_000);
        round(&c, &mut led, &f, &disk, 1.0);
        // b takes more of the work; what was earned since the last round still goes by the plan in force then
        *f.plan.borrow_mut() = Ok(Some(plan("two", &[("a", 0, 1), ("b", 1, 4)])));
        f.earn(50_000);
        round(&c, &mut led, &f, &disk, 2.0);
        let old = split(135_000, &[610, 1610]).unwrap();
        assert_eq!(led.accrued()["a"], old[0], "150,000 earned under the old plan, less the operator's 10%");
        assert_eq!(led.accrued().values().sum::<u64>(), 150_000);
        f.earn(50_000);
        round(&c, &mut led, &f, &disk, 3.0);
        let new = split(45_000, &[310, 1910]).unwrap();
        assert_eq!(led.accrued()["a"], old[0] + new[0], "and the next 50,000 by the new one");
        assert_eq!(led.accrued()["b"], old[1] + new[1]);
        assert_eq!(led.accrued().values().sum::<u64>(), 200_000);
        balanced(&led, &f);
    }

    #[test]
    fn the_operators_own_machine_accrues_to_it_and_a_stranger_waits_to_be_registered() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("own", 0, 1), ("a", 1, 2), ("unknown", 2, 3), ("b", 3, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(1_000_000);
        round(&c, &mut led, &f, &disk, 1.0);
        let acc = led.accrued();
        assert!(acc["operator"] > 100_000, "its cut and its stage");
        assert!(acc["unknown"] > 0);
        assert!(!led.paid_msat.contains_key("unknown"), "no offer: nothing to pay it at, and its accrual waits");
        assert_eq!(acc.values().sum::<u64>(), 1_000_000);
    }

    #[test]
    fn earnings_from_something_else_are_not_split_and_an_unreadable_plan_loses_nothing() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        *f.other.borrow_mut() = Some("/film/".into());
        f.earn(70_000);
        let notes = round(&c, &mut led, &f, &disk, 1.0);
        assert!(notes.iter().any(|n| n.contains("/film/")), "{notes:?}");
        assert_eq!(led.unsplit_msat, 70_000);
        *f.other.borrow_mut() = None;
        // the node is down: the earnings wait, and go by the plan when it is back
        *f.plan.borrow_mut() = Err("no answer".into());
        f.earn(30_000);
        round(&c, &mut led, &f, &disk, 2.0);
        assert_eq!(led.earned_msat, 70_000);
        *f.plan.borrow_mut() = Ok(Some(plan("p", &[("a", 0, 2), ("b", 2, 4)])));
        round(&c, &mut led, &f, &disk, 3.0);
        assert_eq!(led.earned_msat, 100_000);
        assert_eq!(led.accrued().values().sum::<u64>() + led.unsplit_msat, 100_000);
        // a stage plan that is not this model's: the same
        *f.plan.borrow_mut() = Ok(Some(plan("q", &[("a", 0, 2)])));
        f.earn(5);
        let notes = round(&c, &mut led, &f, &disk, 4.0);
        assert!(notes.iter().any(|n| n.contains("cannot be used")), "{notes:?}");
        assert_eq!(led.earned_msat, 100_000);
    }

    #[test]
    fn a_gateway_that_starts_again_from_nothing_takes_nothing_back() {
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(50_000);
        round(&c, &mut led, &f, &disk, 1.0);
        let acc = led.accrued();
        *f.charged.borrow_mut() = 10;
        let notes = round(&c, &mut led, &f, &disk, 2.0);
        assert!(notes.iter().any(|n| n.contains("below")), "{notes:?}");
        assert_eq!(led.accrued(), acc);
        f.earn(1000);
        round(&c, &mut led, &f, &disk, 3.0);
        assert_eq!(led.earned_msat, 51_000);
    }

    #[test]
    fn the_ledger_survives_a_restart_whole() {
        let dir = std::env::temp_dir().join(format!("compute-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        assert_eq!(load_ledger(&path).unwrap(), Ledger::default());
        let c = cfg();
        let f = Fake::new(plan("p", &[("a", 0, 2), ("b", 2, 4)]));
        let (mut led, disk) = start(&c, &f);
        f.earn(1_234_567);
        f.next(Next::Hold);
        round(&c, &mut led, &f, &disk, 1.0);
        save_ledger(&path, &led).unwrap();
        assert_eq!(load_ledger(&path).unwrap(), led);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_stage_report_and_the_services_list_read_as_mesh_llm_and_the_gateway_write_them() {
        let v = json!({"stages": [], "statuses": [], "topologies": [{"model_id": "m", "topology_id": "t1", "stages": [
            {"node_id": "n2", "layer_start": 6, "layer_end": 28, "stage_index": 1}, {"node_id": "n1", "layer_start": 0, "layer_end": 6, "stage_index": 0}]}]});
        let p = parse_plan(&v, None).unwrap().unwrap();
        assert_eq!(p, Plan { id: "t1".into(), stages: vec![Stage { node: "n1".into(), start: 0, end: 6 }, Stage { node: "n2".into(), start: 6, end: 28 }] });
        assert_eq!(parse_plan(&v, Some("other")).unwrap(), None, "no split of that model");
        assert_eq!(parse_plan(&json!({"topologies": []}), None).unwrap(), None);
        assert!(parse_plan(&json!({}), None).is_err());
        let two = json!({"topologies": [{"model_id": "m", "topology_id": "a", "stages": []}, {"model_id": "m", "topology_id": "b", "stages": []}]});
        assert!(parse_plan(&two, None).is_err(), "changing over: the earnings wait");

        let model = json!({"path": "/ai/", "free": false, "price": {"requestMsat": "0", "inputPer1kMsat": "2000", "outputPer1kMsat": "10000", "maxOutputTokens": "128"}});
        assert_eq!(other_sales(&json!({"routes": [model.clone(), {"path": "/free/", "free": true, "price": {}}]})), None);
        assert_eq!(other_sales(&json!({"routes": [model, {"path": "/film/", "free": false, "price": {"byteMsat": "1"}}]})).as_deref(), Some("/film/"));
    }

    #[test]
    fn the_wallets_answers_read_as_it_writes_them() {
        assert_eq!(paid_of(&json!({"verdict": "allow", "rail": "ln", "status": "SUCCEEDED", "payment_hash": "h"})), Paid::Settled { hash: "h".into() });
        assert_eq!(paid_of(&json!({"verdict": "pending", "status": "IN_FLIGHT", "payment_hash": "h"})), Paid::Pending { hash: "h".into() });
        assert_eq!(paid_of(&json!({"verdict": "deny", "rule": "allowlist", "reason": "no"})), Paid::Refused { rule: "allowlist".into(), reason: "no".into() });
        assert_eq!(paid_of(&json!({"verdict": "deny", "rule": "ln_in_flight", "reason": "another"})), Paid::NotAsked("another".into()));
        assert!(matches!(paid_of(&json!({"verdict": "needs_human", "reason": "over the threshold"})), Paid::Refused { .. }));
        for odd in [json!({"verdict": "allow", "status": "ODD"}), json!({"verdict": "unknown", "rule": "signer_no_answer"}), json!({})] {
            assert!(matches!(paid_of(&odd), Paid::Unknown(_)), "never taken as unpaid: {odd}");
        }
    }
}
