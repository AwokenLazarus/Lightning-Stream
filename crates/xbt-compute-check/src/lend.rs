//! Lending a machine to a seller's split, and the lender's own check that it is paid for the work.
//!
//! An operator's invite says how to join its split and on what terms. `stream-compute-check lend` shows
//! that, asks, fetches a checked build of Mesh-LLM and the model, makes an offer on the lender's own
//! Lightning node, and serves. It gives the operator a card with the node's id and the offer.
//!
//! **An invite is the operator's word, and nothing it says is run.** The build must be one this tool
//! pins, whatever hash the invite names, or one the lender allowed by hand; the model is only data; and
//! the invite picks no flags of the command line.
//!
//! The lender then checks its pay from what it can see itself. Every generated token passes through
//! every stage, so its own node's count of them is a figure the operator cannot change. With its own
//! layers and the model's header it works out what it is due at least, by the invite's terms, and
//! compares that with the settled invoices of its offer on its own node. When what it is due passes
//! what it received by more than its credit limit, it stops serving, and it starts again once paid.
//! So the most an operator can take from a lender is about that limit.
//!
//! The figure is a floor. It counts generated tokens only, as prompt tokens reach a stage in batches and
//! may come from a cache, and it leaves a slack for tokens nobody paid for, such as an answer its buyer
//! abandoned.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::meter::Work;

/// A build of Mesh-LLM this tool will run, by the hash of its bundle: one published on our fork of
/// Mesh-LLM with the commit it was built from, usage reporting absent from the build.
pub struct PinnedBuild {
    pub sha256: &'static str,
    pub commit: &'static str,
}

pub const PINNED_BUILDS: &[PinnedBuild] = &[
    // stream-0.78.0-2: Mesh-LLM main 668285a5b, its pull requests 2901 and 2902, and the count of speculative work
    // a lender reads (build 1 does not report it, so a lender can't tell that the split drafted), CPU, Linux x86_64
    PinnedBuild { sha256: "9d69fb836ae88d042d53ad03606be32253b9f15b5d598f7f23b684794adafd39", commit: "65999ac51f561237c7abd1708055144b70f647ab" },
];

const INVITE_VERSION: u32 = 1;
const CARD_PREFIX: &str = "lendcard1.";
/// What the lender leaves free on its disk beyond the downloads.
pub const DISK_MARGIN_BYTES: u64 = 1 << 30;
/// How long a stage stays out of a split before it joins again. Mesh-LLM's coordinator holds a lost stage's
/// place for 75 seconds, acting on it at its next half-minute round, and takes a stage back in that time as
/// recovered, with its work intact. One that restarted has none, and is left waiting for good. Past that
/// time it is planned in anew.
pub const REJOIN_WAIT_S: u64 = 120;

/// The lender's Mesh-LLM settings. The build is pinned, so no asking after new versions, whose
/// `mesh-llm update` would replace it. And no speculative decoding: tokens a verify window commits
/// take no decode step, so the stage's count would fall short of its work. `--no-draft` does not
/// turn it off, as nothing reads it (Mesh-LLM issue 2903).
const MESH_CONFIG: &str = "[updates]\ncheck = false\n\n[defaults.speculative]\nspec_default = false\n";
/// What earlier versions wrote, replaced by the above. Any other file is the lender's, and kept.
const MESH_CONFIG_BEFORE: &str = "[updates]\ncheck = false\n";

/// The settings file to write over what the lender's Mesh-LLM home holds, if anything.
pub fn mesh_config(existing: Option<&str>) -> Option<&'static str> {
    match existing {
        None => Some(MESH_CONFIG),
        Some(text) if text == MESH_CONFIG_BEFORE => Some(MESH_CONFIG),
        Some(_) => None,
    }
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Terms {
    pub per_1k_input_msat: u64,
    pub per_1k_output_msat: u64,
    pub operator_cut_ppm: u32,
    pub min_payout_sats: u64,
}

/// A file to fetch: where from, and what it must be.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Fetch {
    pub url: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Invite {
    pub version: u32,
    /// Who the lender is lending to, in the operator's words.
    pub operator: String,
    pub mesh_token: String,
    /// The iroh relay to use. None: none at all, on one network.
    #[serde(default)]
    pub relay: Option<String>,
    pub terms: Terms,
    pub build: Fetch,
    pub model: Fetch,
    /// What this machine offers the split, in GB. Below the operator's own, so its machine leads.
    pub max_vram_gb: u32,
}

impl Invite {
    pub fn parse(text: &str) -> Result<Invite, String> {
        let i: Invite = serde_json::from_str(text).map_err(|e| format!("the invite: {e}"))?;
        if i.version != INVITE_VERSION {
            return Err(format!("an invite of version {}, this tool reads {INVITE_VERSION}", i.version));
        }
        // these reach a command line or a screen, one value each
        if i.mesh_token.is_empty() || !i.mesh_token.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_=+/".contains(&b)) {
            return Err("the invite's mesh token is not a token".into());
        }
        if let Some(r) = &i.relay {
            if !r.starts_with("https://") || r.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) {
                return Err("the invite's relay is not an https address".into());
            }
        }
        if i.operator.is_empty() || i.operator.len() > 80 || i.operator.chars().any(char::is_control) {
            return Err("the invite does not name its operator in a line of text".into());
        }
        for (what, f) in [("build", &i.build), ("model", &i.model)] {
            if !is_sha256(&f.sha256) || f.bytes == 0 {
                return Err(format!("the invite's {what} has no sha256 and size"));
            }
        }
        if i.terms.operator_cut_ppm > 1_000_000 || i.terms.per_1k_output_msat == 0 {
            return Err("the invite's terms make no sense".into());
        }
        if i.max_vram_gb == 0 || i.max_vram_gb > 4096 {
            return Err(format!("the invite offers {} GB", i.max_vram_gb));
        }
        Ok(i)
    }
}

/// Whether this tool will run the build the invite names: only one it pins, or one the lender allowed.
pub fn build_allowed(sha256: &str, allowed_by_hand: Option<&str>) -> Result<(), String> {
    if PINNED_BUILDS.iter().any(|b| b.sha256 == sha256) || allowed_by_hand == Some(sha256) {
        return Ok(());
    }
    Err(format!("the invite names a build this tool does not pin ({sha256}). An invite cannot choose what runs on your machine"))
}

/// What the operator needs from a lender, on one line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Card {
    pub node: String,
    pub name: String,
    pub offer: String,
}

impl Card {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        format!("{CARD_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode(text: &str) -> Result<Card, String> {
        let body = text.trim().strip_prefix(CARD_PREFIX).ok_or("not a lender's card")?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).map_err(|_| "a damaged card")?;
        let c: Card = serde_json::from_slice(&json).map_err(|_| "a damaged card")?;
        if !is_sha256(&c.node) {
            return Err("the card's node is not a full node id".into());
        }
        if !c.offer.starts_with("lno1") {
            return Err("the card's offer is not a BOLT 12 offer".into());
        }
        Ok(c)
    }
}

/// The node's full id, from its own invite token: base64 of a JSON whose `id` it is. `/api/status` gives
/// only a short form, which a lock does not match.
pub fn node_id_of_token(token: &str) -> Result<String, String> {
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let json = e.decode(token.trim_end_matches('=')).or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(token.trim_end_matches('=')));
    let v: Value = json.ok().and_then(|j| serde_json::from_slice(&j).ok()).ok_or("the node's token could not be read")?;
    let id = v.get("id").and_then(Value::as_str).ok_or("the node's token names no id")?;
    if is_sha256(id) { Ok(id.to_string()) } else { Err("the node's token holds no full id".into()) }
}

/// A stage this node is serving now, with its count of generated tokens since that stage started, and of
/// token positions it ran in speculative verify windows, whose committed tokens the first count leaves out.
#[derive(Clone, Debug, PartialEq)]
pub struct OwnStage {
    pub key: String,
    pub start: u32,
    pub end: u32,
    pub tokens: u64,
    pub drafted: u64,
}

/// This node's serving stages, from its own `/api/runtime/stages`. A build that does not report either
/// count is an error: a lender must not take it for no work done, or for no drafting.
pub fn own_stages(v: &Value, me: &str) -> Result<Vec<OwnStage>, String> {
    let list = v.get("statuses").and_then(Value::as_array).ok_or("the stage report has no statuses")?;
    let mut out = vec![];
    for s in list {
        if s.get("node_id").and_then(Value::as_str) != Some(me) || s.get("state").and_then(Value::as_str) != Some("ready") {
            continue;
        }
        let number = |k: &str| s.get(k).and_then(Value::as_u64);
        let tokens = number("compute_decode_tokens").ok_or("this build of Mesh-LLM does not report its stages' tokens")?;
        let drafted = number("compute_verify_tokens").ok_or("this build of Mesh-LLM does not report its stages' speculative work")?;
        let text = |k: &str| s.get(k).and_then(Value::as_str).unwrap_or("");
        let layer = |k: &str| number(k).and_then(|n| u32::try_from(n).ok()).ok_or_else(|| format!("a stage with no {k}"));
        out.push(OwnStage { key: format!("{}/{}", text("run_id"), text("stage_id")), start: layer("layer_start")?, end: layer("layer_end")?, tokens, drafted });
    }
    Ok(out)
}

/// Why a lender stopped serving.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Stop {
    pub due_at_least_msat: u64,
    pub received_msat: u64,
    pub ts: f64,
}

/// What the lender has counted, kept on disk: all its work, whatever became of the runs that did it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Watch {
    /// The count last seen of each stage run: it starts from zero when the stage starts again.
    pub seen: BTreeMap<String, u64>,
    /// Generated tokens this machine worked on, by the layers it held, as "start-end".
    pub tokens: BTreeMap<String, u64>,
    #[serde(default)]
    pub stopped: Option<Stop>,
    /// When its Mesh-LLM was last seen running, in unix seconds, which says when it may start again.
    #[serde(default)]
    pub mesh_seen_ts: f64,
    /// The drafted count last seen of each stage run.
    #[serde(default)]
    pub drafted_seen: BTreeMap<String, u64>,
    /// Token positions this machine ran in speculative verify windows: work no count of tokens includes.
    #[serde(default)]
    pub drafted: u64,
}

impl Watch {
    /// Counts what is new. Each stage's figure is cumulative, so a sample missed loses nothing.
    pub fn observe(&mut self, stages: &[OwnStage]) {
        for s in stages {
            let was = self.seen.get(&s.key).copied().unwrap_or(0);
            // lower than last seen, the same stage's count started again
            let new = if s.tokens < was { s.tokens } else { s.tokens - was };
            self.seen.insert(s.key.clone(), s.tokens);
            if new > 0 {
                *self.tokens.entry(format!("{}-{}", s.start, s.end)).or_insert(0) += new;
            }
            let was = self.drafted_seen.get(&s.key).copied().unwrap_or(0);
            self.drafted += if s.drafted < was { s.drafted } else { s.drafted - was };
            self.drafted_seen.insert(s.key.clone(), s.drafted);
        }
    }

    pub fn total_tokens(&self) -> u64 {
        self.tokens.values().sum()
    }

    /// What these tokens earn this machine at the invite's rate, after the operator's cut, by its share
    /// of the work, before any slack.
    pub fn due_msat(&self, terms: &Terms, work: &Work) -> Result<u64, String> {
        let total = work.total();
        if total == 0 {
            return Err("a model with no work in it".into());
        }
        let mut due: u128 = 0;
        for (layers, tokens) in &self.tokens {
            let (a, b) = layers.split_once('-').ok_or("a damaged count")?;
            let (a, b): (u32, u32) = (a.parse().map_err(|_| "a damaged count")?, b.parse().map_err(|_| "a damaged count")?);
            if a >= b || b as usize > work.layers.len() {
                return Err(format!("layers {layers} are not this model's"));
            }
            let earned = *tokens as u128 * terms.per_1k_output_msat as u128 * (1_000_000 - terms.operator_cut_ppm as u128);
            due += earned / 1_000_000 * work.stage(a, b) / total / 1000;
        }
        u64::try_from(due).map_err(|_| "more due than can be counted".to_string())
    }
}

/// Whether its Mesh-LLM may start now: at once the first time, and else only once it has been gone long enough
/// for the coordinator to plan it in anew.
pub fn may_rejoin(mesh_seen_ts: f64, now: f64, wait_s: u64) -> bool {
    mesh_seen_ts == 0.0 || now >= mesh_seen_ts + wait_s as f64
}

/// The least the lender is sure it is due: its figure, less the slack for tokens nobody paid for.
pub fn floor_msat(due: u64, slack_ppm: u32) -> u64 {
    (due as u128 * (1_000_000 - slack_ppm.min(1_000_000) as u128) / 1_000_000) as u64
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    Serve,
    Stop,
    StayStopped,
    Resume,
}

/// Stops when what it is due passes what it received by more than the credit limit, and starts again
/// when that gap is down to half the limit, so that a payment right at the limit does not flap it.
pub fn decide(floor: u64, received: u64, credit_msat: u64, serving: bool) -> Action {
    let gap = floor.saturating_sub(received);
    match (serving, gap > credit_msat, gap <= credit_msat / 2) {
        (true, true, _) => Action::Stop,
        (true, false, _) => Action::Serve,
        (false, _, true) => Action::Resume,
        (false, _, false) => Action::StayStopped,
    }
}

/// The file at `path` as an invite names it.
pub fn describe_file(path: &Path, url: &str) -> Result<Fetch, String> {
    let say = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = std::fs::File::open(path).map_err(say)?;
    let mut h = Sha256::new();
    let bytes = std::io::copy(&mut f, &mut h).map_err(say)?;
    Ok(Fetch { url: url.to_string(), sha256: hex::encode(h.finalize()), bytes })
}

/// Stages for these machines in order, even but for the first ones taking what is left over.
pub fn even_stages(nodes: &[String], layers: u32) -> Vec<(String, u32, u32)> {
    let n = nodes.len() as u32;
    let mut at = 0;
    nodes.iter().enumerate().map(|(i, node)| {
        let size = layers / n + u32::from((i as u32) < layers % n);
        let stage = (node.clone(), at, at + size);
        at += size;
        stage
    }).collect()
}

/// The command line of the lender's Mesh-LLM. Of the invite, only its token and relay reach it, one
/// value each, and `Invite::parse` holds those to their shape.
pub fn mesh_args(i: &Invite, model: &Path, ports: (u16, u16, u16), bind_ip: Option<&str>, max_vram_gb: u32) -> Vec<String> {
    let mut a: Vec<String> = ["--log-format", "json", "serve", "--gguf"].map(String::from).to_vec();
    a.push(model.display().to_string());
    a.extend(["--split", "--join"].map(String::from));
    a.push(i.mesh_token.clone());
    a.extend(["--headless", "--llama-flavor", "cpu", "--no-draft", "--parallel", "1", "--ctx-size", "2048", "--kv-cache-disk", "off", "--max-vram"].map(String::from));
    a.push(max_vram_gb.to_string());
    for (flag, port) in [("--port", ports.0), ("--console", ports.1), ("--bind-port", ports.2)] {
        a.push(flag.to_string());
        a.push(port.to_string());
    }
    match &i.relay {
        Some(r) => a.extend(["--relay".to_string(), r.clone()]),
        None => a.push("--disable-iroh-relays".to_string()),
    }
    if let Some(ip) = bind_ip {
        a.extend(["--bind-ip".to_string(), ip.to_string()]);
    }
    a
}

/// Whether the file at `path` is this one. A file of another size is not read through.
pub fn matches(path: &Path, want: &Fetch) -> Result<bool, String> {
    let say = |e: std::io::Error| format!("{}: {e}", path.display());
    let before = match std::fs::metadata(path) {
        Ok(m) if m.len() != want.bytes => return Ok(false),
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(say(e)),
    };
    let note = checked_path(path);
    let read_note = std::fs::read(&note).ok().and_then(|b| serde_json::from_slice::<Checked>(&b).ok());
    if read_note.as_ref() == Some(&Checked::of(&before, &want.sha256)) {
        return Ok(true);
    }
    let mut f = std::fs::File::open(path).map_err(say)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(say)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    if hex::encode(h.finalize()) != want.sha256 {
        let _ = std::fs::remove_file(&note);
        return Ok(false);
    }
    // noted only for a file that did not change while it was read
    let checked = Checked::of(&before, &want.sha256);
    if std::fs::metadata(path).is_ok_and(|after| Checked::of(&after, &want.sha256) == checked) {
        keep_note(&note, &checked);
    }
    Ok(true)
}

/// A file found to be the one named, kept beside it as `<name>.checked`, so that `lend` starting again need
/// not read a model it has read before. Reading all of a big one again pushes the running stage's layers out
/// of memory and slows the answers in flight: an 18.6 GB model on a 12 GB machine decoded at a fifth of its
/// speed meanwhile, and a buyer gave the answer up. The file is taken to be unchanged while its device,
/// inode, size and times are: a write moves its change time, which nothing can set back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Checked {
    sha256: String,
    bytes: u64,
    dev: u64,
    ino: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl Checked {
    fn of(m: &std::fs::Metadata, sha256: &str) -> Checked {
        use std::os::unix::fs::MetadataExt;
        let ns = |s: i64, n: i64| s as i128 * 1_000_000_000 + n as i128;
        Checked { sha256: sha256.to_string(), bytes: m.len(), dev: m.dev(), ino: m.ino(), mtime_ns: ns(m.mtime(), m.mtime_nsec()), ctime_ns: ns(m.ctime(), m.ctime_nsec()) }
    }
}

fn checked_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".checked");
    name.into()
}

/// A note that cannot be written (a model of the lender's own, in a directory it cannot write) only means
/// reading the file again next time.
fn keep_note(note: &Path, c: &Checked) {
    let tmp = note.with_extension("checked.tmp");
    if serde_json::to_vec(c).ok().is_some_and(|b| std::fs::write(&tmp, b).is_ok()) {
        let _ = std::fs::rename(&tmp, note);
    }
}

/// Puts the file at `to`, from its URL or a path. `Ok(true)`: it was fetched; `Ok(false)`: it was already
/// there. It is written under another name, and takes its own only once its sha256 is right, so a
/// wrong file is never at `to`. No more than its size is ever taken.
pub fn fetch_checked(want: &Fetch, to: &Path) -> Result<bool, String> {
    if matches(to, want)? {
        return Ok(false);
    }
    let part = to.with_extension("part");
    let say = |e: std::io::Error| format!("{}: {e}", part.display());
    let mut source: Box<dyn Read> = if want.url.starts_with("http://") || want.url.starts_with("https://") {
        let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(30)).timeout_read(Duration::from_secs(120)).build();
        let r = agent.get(&want.url).call().map_err(|e| format!("{}: {e}", want.url))?;
        Box::new(r.into_reader())
    } else {
        let path = want.url.strip_prefix("file://").unwrap_or(&want.url);
        Box::new(std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?)
    };
    let mut out = std::fs::File::create(&part).map_err(say)?;
    let mut h = Sha256::new();
    let (mut got, mut buf) = (0u64, vec![0u8; 1 << 20]);
    let result = loop {
        let n = match source.read(&mut buf) {
            Ok(n) => n,
            Err(e) => break Err(format!("{}: {e}", want.url)),
        };
        if n == 0 {
            break Ok(());
        }
        got += n as u64;
        if got > want.bytes {
            break Err(format!("{} is larger than the {} bytes it should be", want.url, want.bytes));
        }
        h.update(&buf[..n]);
        if let Err(e) = out.write_all(&buf[..n]) {
            break Err(say(e));
        }
    };
    let hash = hex::encode(h.finalize());
    let result = result.and_then(|_| {
        if got == want.bytes && hash == want.sha256 { Ok(()) } else { Err(format!("{} is not the file named: {got} bytes, sha256 {hash}. Refused", want.url)) }
    });
    if let Err(e) = result {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    out.sync_all().map_err(say)?;
    std::fs::rename(&part, to).map_err(say)?;
    if let Ok(m) = std::fs::metadata(to) {
        keep_note(&checked_path(to), &Checked::of(&m, &want.sha256));
    }
    Ok(true)
}

/// Writes the watch whole, on disk before it returns: a crash leaves the last one or this one.
pub fn save_watch(path: &Path, w: &Watch) -> Result<(), String> {
    let say = |e: std::io::Error| format!("{}: {e}", path.display());
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(say)?;
    f.write_all(&serde_json::to_vec_pretty(w).map_err(|e| e.to_string())?).map_err(say)?;
    f.sync_all().map_err(say)?;
    std::fs::rename(&tmp, path).map_err(say)
}

/// Keeps the watch on disk without the watch loop waiting for the disk: `save` hands over a snapshot and returns,
/// a thread of its own writes it (temp file, fsync, rename), and a snapshot not yet written when a newer one
/// comes is dropped, so a stalled disk holds at most one. A failed write is reported by the next `save`.
pub struct WatchWriter {
    slot: std::sync::Arc<(std::sync::Mutex<WriterSlot>, std::sync::Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[derive(Default)]
struct WriterSlot {
    next: Option<Watch>,
    err: Option<String>,
    closed: bool,
}

impl WatchWriter {
    pub fn start(path: std::path::PathBuf) -> Self {
        Self::with(move |w| save_watch(&path, w))
    }

    /// A writer that persists with `write`: the tests give it a slow one.
    pub fn with(mut write: impl FnMut(&Watch) -> Result<(), String> + Send + 'static) -> Self {
        let slot = std::sync::Arc::new((std::sync::Mutex::new(WriterSlot::default()), std::sync::Condvar::new()));
        let mine = slot.clone();
        let thread = std::thread::spawn(move || loop {
            let w = {
                let mut s = mine.0.lock().unwrap_or_else(|e| e.into_inner());
                while s.next.is_none() && !s.closed {
                    s = mine.1.wait(s).unwrap_or_else(|e| e.into_inner());
                }
                match s.next.take() {
                    Some(w) => w,
                    None => return,
                }
            };
            let r = write(&w);
            mine.0.lock().unwrap_or_else(|e| e.into_inner()).err = r.err();
        });
        WatchWriter { slot, thread: Some(thread) }
    }

    /// Hands over the latest watch and returns at once, with the error of the last write that failed.
    pub fn save(&self, w: &Watch) -> Result<(), String> {
        let mut s = self.slot.0.lock().unwrap_or_else(|e| e.into_inner());
        s.next = Some(w.clone());
        let err = s.err.take();
        drop(s);
        self.slot.1.notify_one();
        err.map_or(Ok(()), Err)
    }

    /// Waits for the last snapshot to be on disk: for the end, once the loop has no decision left to make.
    pub fn finish(mut self) -> Result<(), String> {
        self.close();
        self.slot.0.lock().unwrap_or_else(|e| e.into_inner()).err.take().map_or(Ok(()), Err)
    }

    fn close(&mut self) {
        self.slot.0.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        self.slot.1.notify_one();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for WatchWriter {
    fn drop(&mut self) {
        self.close();
    }
}

pub fn load_watch(path: &Path) -> Result<Watch, String> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Watch::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// An offer this machine gave out, kept in `offers.json` in its directory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SavedOffer {
    /// The node's offer id, in hex.
    pub id: String,
    pub bolt12: String,
}

impl SavedOffer {
    pub fn hash(&self) -> Result<[u8; 32], String> {
        let b = hex::decode(&self.id).map_err(|_| "a damaged offer id")?;
        b.try_into().map_err(|_| "a damaged offer id".to_string())
    }
}

/// The offers given out so far, the card's last. Each start pays to the same one: the node mints another
/// for the same fields once its channels change (one with no path while it has no channel, one with a path
/// once it has), and the operator pays the offer on the card it was given. A directory from before this
/// list was kept has its card, and the offer on that.
pub fn load_offers(path: &Path, card: &Path) -> Result<Vec<SavedOffer>, String> {
    match std::fs::read(path) {
        Ok(b) => return serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{}: {e}", path.display())),
        Err(_) => {}
    }
    let text = match std::fs::read_to_string(card) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(format!("{}: {e}", card.display())),
    };
    let c = Card::decode(&text).map_err(|e| format!("{}: {e}", card.display()))?;
    let o = xbt_signer::bolt12::decode_offer(&c.offer).map_err(|e| format!("{}: {e}", card.display()))?;
    Ok(vec![SavedOffer { id: hex::encode(o.id), bolt12: c.offer }])
}

pub fn save_offers(path: &Path, offers: &[SavedOffer]) -> Result<(), String> {
    let say = |e: std::io::Error| format!("{}: {e}", path.display());
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(say)?;
    f.write_all(&serde_json::to_vec_pretty(offers).map_err(|e| e.to_string())?).map_err(say)?;
    f.sync_all().map_err(say)?;
    std::fs::rename(&tmp, path).map_err(say)
}

/// The offers once the node has minted `minted`, if it was asked to, and whether the card's offer changed.
/// What it minted goes on the card; the earlier ones are still counted, as an operator pays them until it
/// has the new card.
pub fn offers_after(mut saved: Vec<SavedOffer>, minted: Option<SavedOffer>) -> (Vec<SavedOffer>, bool) {
    let Some(m) = minted else { return (saved, false) };
    if saved.last().is_some_and(|l| l.id == m.id) {
        return (saved, false);
    }
    saved.retain(|o| o.id != m.id);
    saved.push(m);
    (saved, true)
}

/// What the owner should know of an offer that holds no path to its node, if this one holds none.
pub fn offer_note(bolt12: &str) -> Option<String> {
    let o = xbt_signer::bolt12::decode_offer(bolt12).ok()?;
    o.paths.is_empty().then(|| {
        "Your offer holds no path to your node. Unless your node announces an address, only a node already connected to yours can ask it for an invoice. \
         A node with no channel can make no path: once you have one, start again with --new-offer and give the operator the new card."
            .to_string()
    })
}

/// What the owner is shown before anything happens.
pub fn terms_text(i: &Invite, dir: &Path, credit_sats: u64) -> String {
    let t = &i.terms;
    let gb = |b: u64| b as f64 / (1u64 << 30) as f64;
    format!(
        "Lending this machine to: {}\n\n\
         Pay: {} msat per 1,000 tokens generated and {} msat per 1,000 tokens of prompt, less the operator's {:.1}%, by your machine's share of the work.\n\
         Paid to an offer on your own Lightning node once you are owed {} sats.\n\
         You stop serving by yourself if you are owed more than {credit_sats} sats by your own count.\n\n\
         It will download, to {}:\n  the Mesh-LLM build, {:.2} GB, sha256 {}\n  the model, {:.2} GB, sha256 {}\n\n\
         It will then run Mesh-LLM from that build as a {} GB node of the operator's split, using this machine's CPU and memory for as long as this runs.\n\
         It sends no usage reports and does not ask after new versions. The operator learns your node's id and your offer, from the card you give it.\n",
        i.operator,
        t.per_1k_output_msat,
        t.per_1k_input_msat,
        t.operator_cut_ppm as f64 / 10_000.0,
        t.min_payout_sats,
        dir.display(),
        gb(i.build.bytes),
        i.build.sha256,
        gb(i.model.bytes),
        i.model.sha256,
        i.max_vram_gb,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn terms() -> Terms {
        Terms { per_1k_input_msat: 2_000, per_1k_output_msat: 1_000_000, operator_cut_ppm: 100_000, min_payout_sats: 20 }
    }

    #[test]
    fn the_mesh_config_turns_speculation_off_and_keeps_a_lenders_own_file() {
        let written = mesh_config(None).unwrap();
        assert!(written.contains("[updates]\ncheck = false") && written.contains("[defaults.speculative]\nspec_default = false"));
        assert_eq!(mesh_config(Some("[updates]\ncheck = false\n")), Some(written), "an earlier version's file is brought up to date");
        assert_eq!(mesh_config(Some(written)), None, "nothing to change");
        assert_eq!(mesh_config(Some("[updates]\ncheck = true\n")), None, "a file the lender changed is theirs");
    }

    fn invite() -> Invite {
        let f = |c: char| Fetch { url: "https://example.com/f".into(), sha256: c.to_string().repeat(64), bytes: 10 };
        Invite { version: 1, operator: "An operator".into(), mesh_token: "eyJpZCI6ImEifQ".into(), relay: None, terms: terms(), build: f('a'), model: f('b'), max_vram_gb: 4 }
    }

    fn parse(i: &Invite) -> Result<Invite, String> {
        Invite::parse(&serde_json::to_string(i).unwrap())
    }

    // layers of 300, a row of 10, a head of 1010: 610 and 1610 for two stages of two layers
    fn work() -> Work {
        Work { layers: vec![300, 300, 300, 300], embed: 10, head: 1010 }
    }

    #[test]
    fn an_invite_reads_and_nothing_can_be_smuggled_through_it() {
        assert_eq!(parse(&invite()).unwrap(), invite());
        let bad = |change: &dyn Fn(&mut Invite)| {
            let mut i = invite();
            change(&mut i);
            parse(&i).is_err()
        };
        assert!(bad(&|i| i.version = 2));
        assert!(bad(&|i| i.mesh_token = "abc --plugin /tmp/x".into()), "a token that is two arguments");
        assert!(bad(&|i| i.relay = Some("http://relay".into())));
        assert!(bad(&|i| i.relay = Some("https://relay --plugin x".into())));
        assert!(bad(&|i| i.operator = "line one\nline two".into()), "a name that forges what the owner reads");
        assert!(bad(&|i| i.build.sha256 = "short".into()));
        assert!(bad(&|i| i.model.bytes = 0));
        assert!(bad(&|i| i.terms.operator_cut_ppm = 1_000_001));
        assert!(bad(&|i| i.max_vram_gb = 0));
    }

    #[test]
    fn an_invite_cannot_choose_what_runs() {
        let sha = "c".repeat(64);
        assert!(build_allowed(&sha, None).is_err(), "named by the invite alone");
        assert!(build_allowed(&sha, Some(&"d".repeat(64))).is_err());
        assert!(build_allowed(&sha, Some(&sha)).is_ok(), "the owner allowed this one by hand");
        for pinned in PINNED_BUILDS {
            assert!(is_sha256(pinned.sha256) && pinned.commit.len() == 40, "{}", pinned.sha256);
            assert!(build_allowed(pinned.sha256, None).is_ok(), "a pinned build needs no allowing by hand");
        }
        assert!(!PINNED_BUILDS.is_empty(), "lenders have a published build to run");
    }

    #[test]
    fn a_card_reads_back_and_a_damaged_one_does_not() {
        let c = Card { node: "a".repeat(64), name: "a lender".into(), offer: "lno1abc".into() };
        assert_eq!(Card::decode(&format!("  {}\n", c.encode())).unwrap(), c);
        assert!(Card::decode("lno1abc").is_err());
        assert!(Card::decode("lendcard1.@@@").is_err());
        let short = Card { node: "abc".into(), ..c.clone() };
        assert!(Card::decode(&short.encode()).is_err(), "a short id, which a lock would not match");
        let not_offer = Card { offer: "lnbc1".into(), ..c };
        assert!(Card::decode(&not_offer.encode()).is_err());
    }

    #[test]
    fn a_nodes_full_id_comes_from_its_token() {
        let id = "26e22c49df7f51fa21bce1d70af3a56e63f3df2bf6577331c31176649c81626d";
        for e in [base64::engine::general_purpose::URL_SAFE_NO_PAD, base64::engine::general_purpose::STANDARD_NO_PAD] {
            let token = e.encode(json!({"id": id, "addrs": ["1.2.3.4:5"]}).to_string());
            assert_eq!(node_id_of_token(&token).unwrap(), id);
        }
        assert!(node_id_of_token("!!!").is_err());
        assert!(node_id_of_token(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"id":"26e22c49df"}"#)).is_err());
    }

    #[test]
    fn only_this_nodes_serving_stages_count_and_a_build_with_no_count_is_refused() {
        let me = "a".repeat(64);
        let v = json!({"statuses": [
            {"node_id": me, "state": "ready", "run_id": "r1", "stage_id": "s1", "layer_start": 14, "layer_end": 28, "compute_decode_tokens": 7, "compute_verify_tokens": 3},
            {"node_id": me, "state": "stopped", "run_id": "r0", "stage_id": "s1", "layer_start": 27, "layer_end": 28, "compute_decode_tokens": 0, "compute_verify_tokens": 0},
            {"node_id": "b".repeat(64), "state": "ready", "run_id": "r1", "stage_id": "s0", "layer_start": 0, "layer_end": 14, "compute_decode_tokens": 9, "compute_verify_tokens": 0}]});
        assert_eq!(own_stages(&v, &me).unwrap(), vec![OwnStage { key: "r1/s1".into(), start: 14, end: 28, tokens: 7, drafted: 3 }]);
        let stock = json!({"statuses": [{"node_id": me, "state": "ready", "run_id": "r", "stage_id": "s", "layer_start": 0, "layer_end": 1}]});
        assert!(own_stages(&stock, &me).is_err(), "no count is not no work");
        let no_drafts = json!({"statuses": [{"node_id": me, "state": "ready", "run_id": "r", "stage_id": "s", "layer_start": 0, "layer_end": 1, "compute_decode_tokens": 2}]});
        assert!(own_stages(&no_drafts, &me).is_err(), "a build that cannot say it drafted is not one that did not");
        assert!(own_stages(&json!({}), &me).is_err());
    }

    fn stage(key: &str, start: u32, end: u32, tokens: u64) -> OwnStage {
        OwnStage { key: key.into(), start, end, tokens, drafted: 0 }
    }

    #[test]
    fn drafted_work_is_counted_like_tokens_across_restarts() {
        let mut w = Watch::default();
        w.observe(&[OwnStage { drafted: 0, ..stage("r1/s", 0, 2, 10) }]);
        assert_eq!(w.drafted, 0);
        w.observe(&[OwnStage { drafted: 12, ..stage("r1/s", 0, 2, 14) }]);
        w.observe(&[OwnStage { drafted: 12, ..stage("r1/s", 0, 2, 14) }]);
        assert_eq!(w.drafted, 12, "the same figure twice is not new drafting");
        // the stage starts again from zero
        w.observe(&[OwnStage { drafted: 5, ..stage("r1/s", 0, 2, 3) }]);
        assert_eq!((w.drafted, w.total_tokens()), (17, 17));
        // a watch saved before drafting was counted reads as none
        let old: Watch = serde_json::from_value(json!({"seen": {}, "tokens": {}})).unwrap();
        assert_eq!(old.drafted, 0);
    }

    /// V-6: the count survives a sample missed, a restart of the watch and of the stage.
    #[test]
    fn the_watch_loses_nothing_and_counts_nothing_twice() {
        let mut w = Watch::default();
        w.observe(&[stage("r1/s", 0, 2, 10)]);
        w.observe(&[stage("r1/s", 0, 2, 10)]);
        assert_eq!(w.total_tokens(), 10, "the same figure twice is not new work");
        w.observe(&[stage("r1/s", 0, 2, 25)]);
        assert_eq!(w.total_tokens(), 25, "it is cumulative, so what came between samples is there");
        // the watch is killed and started again on what it saved
        let dir = std::env::temp_dir().join(format!("lend-watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("watch.json");
        assert_eq!(load_watch(&path).unwrap(), Watch::default());
        save_watch(&path, &w).unwrap();
        let mut w = load_watch(&path).unwrap();
        w.observe(&[stage("r1/s", 0, 2, 25)]);
        assert_eq!(w.total_tokens(), 25, "nothing counted twice over a restart");
        std::fs::remove_dir_all(&dir).unwrap();
        // Mesh-LLM's stage starts again under the same name, from zero
        w.observe(&[stage("r1/s", 0, 2, 4)]);
        assert_eq!(w.total_tokens(), 29);
        // a new run, on other layers: its count starts from nothing, and goes by its own share
        w.observe(&[stage("r2/s", 2, 4, 6)]);
        assert_eq!(w.total_tokens(), 35);
        assert_eq!(w.tokens["0-2"], 29);
        assert_eq!(w.tokens["2-4"], 6);
    }

    /// The watch loop never waits for the disk: while a write is stalled, saves return, newer ones replace
    /// older ones, and once the disk answers the latest is what is written.
    #[test]
    fn a_stalled_write_does_not_hold_the_watch_up() {
        use std::sync::{mpsc, Arc, Mutex};
        let (release, gate) = mpsc::channel::<()>();
        let (started_tx, started) = mpsc::channel::<()>();
        let written: Arc<Mutex<Vec<u64>>> = Arc::default();
        let log = written.clone();
        let writer = WatchWriter::with(move |w| {
            let _ = started_tx.send(());
            gate.recv().ok();
            log.lock().unwrap().push(w.drafted);
            Ok(())
        });
        let mut w = Watch { drafted: 1, ..Watch::default() };
        writer.save(&w).unwrap();
        started.recv_timeout(Duration::from_secs(5)).expect("the writer took the first snapshot");
        // the disk is stuck inside the first write: the loop still saves, and reads and decides on
        let t = std::time::Instant::now();
        for n in 2..=1000 {
            w.drafted = n;
            writer.save(&w).unwrap();
        }
        assert!(t.elapsed() < Duration::from_secs(2), "saves waited for the stalled write");
        assert!(written.lock().unwrap().is_empty(), "the write is still stalled");
        release.send(()).unwrap();
        release.send(()).unwrap();
        writer.finish().unwrap();
        assert_eq!(*written.lock().unwrap(), vec![1, 1000], "one stalled, then only the latest: nothing queued up");
    }

    #[test]
    fn a_failed_write_is_told_by_the_next_save() {
        let writer = WatchWriter::with(|_| Err("disk full".to_string()));
        writer.save(&Watch::default()).unwrap();
        let mut told = None;
        for _ in 0..500 {
            if let Err(e) = writer.save(&Watch::default()) {
                told = Some(e);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(told.as_deref(), Some("disk full"));
    }

    /// V-2: the share is the meter's, the same the operator's ledger pays by.
    #[test]
    fn what_is_due_follows_the_terms_and_the_share_of_the_work() {
        let mut w = Watch::default();
        w.tokens.insert("0-2".into(), 2220);
        // 2,220 tokens at 1,000 msat each, less 10%, by 610 of 2,220
        assert_eq!(w.due_msat(&terms(), &work()).unwrap(), 2220 * 1000 * 9 / 10 * 610 / 2220);
        assert_eq!(w.due_msat(&terms(), &work()).unwrap(), 549_000);
        w.tokens.insert("2-4".into(), 2220);
        assert_eq!(w.due_msat(&terms(), &work()).unwrap(), 549_000 + 1_449_000, "the head is on the last stage");
        w.tokens.insert("0-9".into(), 1);
        assert!(w.due_msat(&terms(), &work()).is_err(), "layers the model does not have");
        assert_eq!(floor_msat(1000, 100_000), 900);
        assert_eq!(floor_msat(1000, 2_000_000), 0);
    }

    #[test]
    fn it_stays_out_long_enough_to_be_planned_in_anew() {
        assert!(may_rejoin(0.0, 1000.0, REJOIN_WAIT_S), "the first start waits for nothing");
        assert!(!may_rejoin(1000.0, 1000.0, REJOIN_WAIT_S));
        assert!(!may_rejoin(1000.0, 1119.0, REJOIN_WAIT_S), "inside the coordinator's hold it would be left waiting");
        assert!(may_rejoin(1000.0, 1120.0, REJOIN_WAIT_S));
        assert!(may_rejoin(1000.0, 1000.0, 0), "the lab's stand-in has no coordinator");
    }

    /// V-4 and V-5: the decision itself.
    #[test]
    fn it_stops_past_the_limit_and_resumes_once_paid() {
        let c = 10_000;
        assert_eq!(decide(5_000, 0, c, true), Action::Serve);
        assert_eq!(decide(10_000, 0, c, true), Action::Serve, "at the limit is within it");
        assert_eq!(decide(10_001, 0, c, true), Action::Stop);
        assert_eq!(decide(50_000, 45_000, c, true), Action::Serve);
        assert_eq!(decide(3_000, 50_000, c, true), Action::Serve, "paid ahead");
        assert_eq!(decide(20_000, 0, c, false), Action::StayStopped);
        assert_eq!(decide(20_000, 12_000, c, false), Action::StayStopped, "paid to just under the limit, it could stop at once again");
        assert_eq!(decide(20_000, 15_000, c, false), Action::Resume);
        assert_eq!(decide(20_000, 25_000, c, false), Action::Resume);
    }

    #[test]
    fn a_file_is_only_ever_taken_if_it_is_the_one_named() {
        let dir = std::env::temp_dir().join(format!("lend-fetch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (src, to) = (dir.join("source"), dir.join("taken"));
        std::fs::write(&src, b"the real file").unwrap();
        let good = Fetch { url: src.display().to_string(), sha256: hex::encode(Sha256::digest(b"the real file")), bytes: 13 };
        assert!(fetch_checked(&good, &to).unwrap(), "fetched");
        assert_eq!(std::fs::read(&to).unwrap(), b"the real file");
        assert!(!fetch_checked(&good, &to).unwrap(), "already there: nothing fetched again");

        // a tampered source: same size, another hash
        std::fs::write(&src, b"the fake file").unwrap();
        let to2 = dir.join("taken2");
        let e = fetch_checked(&good, &to2).unwrap_err();
        assert!(e.contains("Refused"), "{e}");
        assert!(!to2.exists() && !to2.with_extension("part").exists(), "nothing of it is left");
        // a source that would run on for ever is cut at the size named
        std::fs::write(&src, b"the real file and more").unwrap();
        let e = fetch_checked(&good, &to2).unwrap_err();
        assert!(e.contains("larger"), "{e}");
        assert!(!to2.exists());
        // something else at the name is replaced by the right file, not trusted
        std::fs::write(&src, b"the real file").unwrap();
        std::fs::write(&to, b"something else").unwrap();
        assert!(fetch_checked(&good, &to).unwrap());
        assert_eq!(std::fs::read(&to).unwrap(), b"the real file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_checked_once_is_not_read_again_until_it_changes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("lend-checked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (src, to, note) = (dir.join("source"), dir.join("model.gguf"), dir.join("model.gguf.checked"));
        std::fs::write(&src, b"the real file").unwrap();
        let good = Fetch { url: src.display().to_string(), sha256: hex::encode(Sha256::digest(b"the real file")), bytes: 13 };
        assert!(fetch_checked(&good, &to).unwrap());
        assert!(note.exists(), "noted as it was fetched");
        // with the note the file is not read: one nobody may read still checks
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(matches(&to, &good).unwrap(), "the note answers");
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o644)).unwrap();
        // changed in place, at its size: read again, and found out
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&to, b"the fake file").unwrap();
        assert!(!matches(&to, &good).unwrap());
        assert!(!note.exists(), "the note of a file that no longer matches is dropped");
        // put right, it is read once and noted again
        std::fs::write(&to, b"the real file").unwrap();
        assert!(matches(&to, &good).unwrap());
        assert!(note.exists());
        // a note says what the file was found to be, and answers for no other hash
        let other = Fetch { sha256: hex::encode(Sha256::digest(b"the fake file")), ..good };
        assert!(!matches(&to, &other).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stages_are_even_and_cover_the_model() {
        let nodes = |n: usize| (0..n).map(|i| format!("n{i}")).collect::<Vec<_>>();
        assert_eq!(even_stages(&nodes(2), 28), vec![("n0".to_string(), 0, 14), ("n1".to_string(), 14, 28)]);
        let three = even_stages(&nodes(3), 28);
        assert_eq!(three.iter().map(|s| (s.1, s.2)).collect::<Vec<_>>(), vec![(0, 10), (10, 19), (19, 28)]);
    }

    #[test]
    fn the_command_line_takes_only_the_token_and_relay_from_the_invite() {
        let i = invite();
        let a = mesh_args(&i, Path::new("/m.gguf"), (1, 2, 3), Some("10.0.0.1"), 4);
        let at = |flag: &str| a[a.iter().position(|x| x == flag).unwrap() + 1].clone();
        assert_eq!(at("--join"), i.mesh_token);
        assert_eq!(at("--gguf"), "/m.gguf");
        assert_eq!(at("--max-vram"), "4");
        assert_eq!(at("--bind-ip"), "10.0.0.1");
        assert!(a.iter().any(|x| x == "--disable-iroh-relays"));
        assert!(a.iter().any(|x| x == "--split") && a.iter().any(|x| x == "--headless"));
        assert!(!a.iter().any(|x| x == "--split-topology-lock"), "the operator's node places it");
        let mut relayed = invite();
        relayed.relay = Some("https://relay.example".into());
        let a = mesh_args(&relayed, Path::new("/m.gguf"), (1, 2, 3), None, 4);
        assert!(a.iter().any(|x| x == "https://relay.example") && !a.iter().any(|x| x == "--disable-iroh-relays" || x == "--bind-ip"));
    }

    #[test]
    fn the_owner_is_told_the_sizes_terms_and_what_runs() {
        let t = terms_text(&invite(), Path::new("/lend"), 60);
        for word in ["An operator", "1000000 msat", "10.0%", "60 sats", "/lend", "Mesh-LLM", "sends no usage reports", "4 GB"] {
            assert!(t.contains(word), "{word} in: {t}");
        }
    }

    /// An offer as Lightning Fork mints them: with no path while the node has no channel, with one after.
    fn an_offer(with_path: bool) -> String {
        use xbt_signer::bolt12::encode;
        // the generator point: any valid key will do
        let g: [u8; 33] = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap().try_into().unwrap();
        let mut fields = vec![(10, b"Compute lent to an operator".to_vec())];
        if with_path {
            fields.push((16, encode::path(&g, &g, 2)));
        }
        fields.push((22, g.to_vec()));
        encode::offer(fields)
    }

    fn saved(bolt12: &str) -> SavedOffer {
        SavedOffer { id: hex::encode(xbt_signer::bolt12::decode_offer(bolt12).unwrap().id), bolt12: bolt12.into() }
    }

    /// The node mints another offer for the same fields once it has a channel, and a restart that took it
    /// would count pay to an offer the operator does not know, and stop serving with the card's paid.
    #[test]
    fn each_start_keeps_the_cards_offer_and_counts_every_offer_given_out() {
        let (a, b) = (saved(&an_offer(false)), saved(&an_offer(true)));
        assert_ne!(a.id, b.id, "the same fields, another offer, once there is a path");
        assert_eq!(offers_after(vec![], Some(a.clone())), (vec![a.clone()], true), "the first start mints the card's");
        assert_eq!(offers_after(vec![a.clone()], None), (vec![a.clone()], false), "a later start keeps it");
        assert_eq!(offers_after(vec![a.clone()], Some(a.clone())), (vec![a.clone()], false), "--new-offer, and the node gave the same");
        assert_eq!(offers_after(vec![a.clone()], Some(b.clone())), (vec![a.clone(), b.clone()], true), "a new card; the old offer still counts");
        assert_eq!(offers_after(vec![a.clone(), b.clone()], Some(a.clone())), (vec![b.clone(), a.clone()], true), "one given out before goes back on the card, once");
        assert_eq!(a.hash().unwrap().to_vec(), hex::decode(&a.id).unwrap());
        assert!(SavedOffer { id: "ab".into(), bolt12: String::new() }.hash().is_err());
    }

    #[test]
    fn a_directory_from_before_the_list_keeps_the_offer_on_its_card() {
        let dir = std::env::temp_dir().join(format!("lend-offers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (list, card) = (dir.join("offers.json"), dir.join("card.txt"));
        assert_eq!(load_offers(&list, &card).unwrap(), vec![], "nothing given out yet: the node mints one");
        let a = saved(&an_offer(false));
        std::fs::write(&card, Card { node: "a".repeat(64), name: "a lender".into(), offer: a.bolt12.clone() }.encode()).unwrap();
        assert_eq!(load_offers(&list, &card).unwrap(), vec![a.clone()]);
        let b = saved(&an_offer(true));
        save_offers(&list, &[a.clone(), b.clone()]).unwrap();
        assert_eq!(load_offers(&list, &card).unwrap(), vec![a, b], "the list, once there is one");
        std::fs::write(&list, "[{").unwrap();
        assert!(load_offers(&list, &card).is_err(), "a damaged list is said, not taken for none");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_offer_with_no_path_is_said() {
        let note = offer_note(&an_offer(false)).expect("no path");
        assert!(note.contains("--new-offer"), "{note}");
        assert_eq!(offer_note(&an_offer(true)), None);
        assert_eq!(offer_note("lno1notanoffer"), None, "what cannot be read is the node's to say");
    }
}
