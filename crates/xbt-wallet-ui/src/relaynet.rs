//! Stream relays (`docs/RUN-A-RELAY.md`): the iroh relays a direct link falls back to when two
//! routers will not let it punch through. This keeps what the owner chose (pinned, blocked, their
//! own relays, only their own), the relays announced on the owner's Nostr relays
//! ([`xbt_nostr::relays`]), and what a probe of each measured, and writes the choice to
//! `relays.json` in the data directory, where the link reads it.
//!
//! `relays.json`: `{"pinned": [...], "blocked": [...], "own": [...], "only_own": false,
//! "selected": [...], "selected_throughput": [...], "observed": {"<relay>": <Mbit/s>}}`.
//! `selected` is the relays to use for AI, hashrate and pages, best first; `selected_throughput`
//! the same for video, files and VPN exits ([`xbt_nostr::relays::select_for`]). The first of each
//! is the home relay for that purpose, and the link adds iroh's public relays after them unless
//! `only_own`. `observed` is written by the link: what real sessions through each relay reached;
//! the app keeps it and ranks by it. Both lists are written when the owner changes a choice and
//! each time the page probes.
//!
//! The Nostr relays are asked, and the relays probed, only when the owner opens the page. The page
//! shows the last snapshot at once, and when it is older than [`FRESH`] makes a new one behind it
//! for the next visit; only the first visit waits for one, at most [`crate::nostr::FIRST_WAIT`].
//! A probe is one TLS WebSocket upgrade on `/relay`, closed at once.
//!
//! An owner who runs a relay can announce it from here. The announcement is signed with a key of
//! its own, `secrets/relay-operator.key` (mode 600), made the first time; it is not the shop's key
//! and not the wallet's.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_nostr::event::Keys;
use xbt_nostr::oneshot::{self, Outcome};
use xbt_nostr::relays::{self, Announcement, Offer, Prefs, Probe, Purpose};

/// Our relay: the last resort unless the owner blocks it.
pub const DEFAULT_RELAY: &str = "https://iroh.lazarus-xbt.xyz/";
/// A snapshot older than this is made again when the page opens.
pub const FRESH: Duration = Duration::from_secs(120);
pub const QUERY_WAIT: Duration = Duration::from_secs(8);
pub const QUERY_LIMIT: usize = 200;
pub const PROBE_WAIT: Duration = Duration::from_secs(5);
/// At most this many relays are probed (and so used).
pub const MAX_PROBED: usize = 24;
/// How many relays `selected` holds.
pub const MAX_SELECTED: usize = 4;

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub at: Instant,
    pub announced: Vec<Announcement>,
    pub refused: usize,
    pub probes: HashMap<String, Probe>,
    /// Why each probe that failed did.
    pub errors: HashMap<String, String>,
    pub nostr: Vec<Outcome>,
}

#[derive(Clone)]
pub struct RelayNet {
    nostr_relays: Vec<String>,
    file: PathBuf,
    key_file: PathBuf,
    default_relay: String,
    snap: Arc<Mutex<Option<Snapshot>>>,
    /// Who makes the next snapshot, and when (in the background once there is one).
    making: crate::perf::Swr<Snapshot>,
}

fn list(v: &Value, k: &str) -> Vec<String> {
    v.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).filter_map(|s| relays::canonical_relay(s).ok()).collect()).unwrap_or_default()
}

impl RelayNet {
    pub fn new(nostr_relays: Vec<String>, data_dir: &std::path::Path) -> Self {
        Self::with_default(nostr_relays, data_dir, DEFAULT_RELAY)
    }

    pub fn with_default(nostr_relays: Vec<String>, data_dir: &std::path::Path, default_relay: &str) -> Self {
        Self { nostr_relays, file: data_dir.join("relays.json"), key_file: data_dir.join("secrets").join("relay-operator.key"),
               default_relay: relays::canonical_relay(default_relay).unwrap_or_else(|_| DEFAULT_RELAY.into()), snap: Default::default(),
               making: crate::perf::Swr::new() }
    }

    pub fn default_relay(&self) -> &str {
        &self.default_relay
    }

    pub fn nostr_enabled(&self) -> bool {
        !self.nostr_relays.is_empty()
    }

    pub fn prefs(&self) -> Prefs {
        let v: Value = std::fs::read_to_string(&self.file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
        Prefs { pinned: list(&v, "pinned"), blocked: list(&v, "blocked"), own: list(&v, "own"),
                only_own: v.get("only_own").and_then(Value::as_bool).unwrap_or(false) }
    }

    /// The relays to use now for AI, hashrate and pages, from the last snapshot (none yet:
    /// nothing measured, so the default relay alone, or the owner's own when only own).
    pub fn selected(&self, prefs: &Prefs) -> Vec<String> {
        self.selected_for(prefs, Purpose::Latency)
    }

    /// [`Self::selected`] for a purpose: video, files and VPN exits rank by throughput.
    pub fn selected_for(&self, prefs: &Prefs, purpose: Purpose) -> Vec<String> {
        let g = self.snap.lock().unwrap_or_else(|p| p.into_inner());
        let (ann, mut probes) = g.as_ref().map(|s| (s.announced.clone(), s.probes.clone())).unwrap_or_default();
        drop(g);
        for (u, mbit) in self.observed() {
            probes.entry(u).or_default().mbit = Some(mbit);
        }
        relays::select_for(&ann, &probes, prefs, &self.default_relay, MAX_SELECTED, purpose)
    }

    /// What the link reported real sessions reached through each relay (`observed` in
    /// `relays.json`, Mbit/s), which ranks relays for throughput.
    pub fn observed(&self) -> HashMap<String, u32> {
        let v: Value = std::fs::read_to_string(&self.file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
        v.get("observed").and_then(Value::as_object).map(|m| m.iter().filter_map(|(k, x)| {
            Some((relays::canonical_relay(k).ok()?, x.as_u64()?.min(u32::MAX as u64) as u32))
        }).collect()).unwrap_or_default()
    }

    /// Save the owner's choices and the relays they select.
    pub fn save(&self, prefs: &Prefs) -> Result<(), String> {
        let selected = self.selected(prefs);
        let throughput = self.selected_for(prefs, Purpose::Throughput);
        let observed: serde_json::Map<String, Value> = self.observed().into_iter().map(|(k, v)| (k, json!(v))).collect();
        let v = json!({"pinned": prefs.pinned, "blocked": prefs.blocked, "own": prefs.own, "only_own": prefs.only_own,
                       "selected": selected, "selected_throughput": throughput, "observed": observed});
        let tmp = self.file.with_extension("json.tmp");
        std::fs::write(&tmp, format!("{v:#}\n")).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.file).map_err(|e| format!("{}: {e}", self.file.display()))
    }

    /// The announcements and the probes: the last snapshot at once, a new one made behind it when
    /// it is older than [`FRESH`]. `refresh` (the owner asked to look again) waits for a new one.
    pub fn get(&self, refresh: bool) -> Snapshot {
        if refresh {
            return self.making.refresh(|| self.make());
        }
        let me = self.clone();
        self.making.get(FRESH, crate::nostr::FIRST_WAIT, move || me.make()).unwrap_or_else(|| Snapshot {
            at: Instant::now(), announced: vec![], refused: 0, probes: HashMap::new(), errors: HashMap::new(),
            nostr: self.nostr_relays.iter().map(|r| Outcome { relay: r.clone(), result: Err(crate::nostr::STILL_ASKING.into()) }).collect(),
        })
    }

    /// Ask the Nostr relays and probe the relays, keep the snapshot and write the choice.
    fn make(&self) -> Snapshot {
        let (announced, refused, nostr) = if self.nostr_relays.is_empty() {
            (Vec::new(), 0, Vec::new())
        } else {
            let (events, outcomes) = oneshot::query(&self.nostr_relays, &relays::filter(QUERY_LIMIT), QUERY_WAIT);
            let (a, r) = relays::collect(&events, xbt_nostr::now());
            (a, r, outcomes)
        };
        let prefs = self.prefs();
        let mut targets: Vec<String> = vec![self.default_relay.clone()];
        for u in prefs.own.iter().chain(&prefs.pinned).cloned().chain(announced.iter().map(|a| a.relay.clone())) {
            if !targets.contains(&u) && !prefs.blocked.contains(&u) {
                targets.push(u);
            }
        }
        targets.truncate(MAX_PROBED);
        let old: HashMap<String, Probe> = self.snap.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|s| s.probes.clone()).unwrap_or_default();
        let handles: Vec<_> = targets.into_iter().map(|u| std::thread::spawn(move || {
            let r = relays::probe(&u, PROBE_WAIT);
            (u, r)
        })).collect();
        let mut probes = HashMap::new();
        let mut errors = HashMap::new();
        for h in handles {
            let Ok((u, r)) = h.join() else { continue };
            let before = old.get(&u).copied().unwrap_or_default();
            let p = match r {
                Ok(ms) => Probe { rtt_ms: Some(ms), fail_streak: 0, mbit: before.mbit },
                Err(e) => {
                    errors.insert(u.clone(), e);
                    // a relay that does not answer now is not used now
                    Probe { rtt_ms: None, fail_streak: before.fail_streak.saturating_add(1), mbit: before.mbit }
                }
            };
            probes.insert(u, p);
        }
        let s = Snapshot { at: Instant::now(), announced, refused, probes, errors, nostr };
        *self.snap.lock().unwrap_or_else(|p| p.into_inner()) = Some(s.clone());
        let _ = self.save(&prefs);
        s
    }

    /// The key relay announcements are signed with, made the first time.
    pub fn operator_key(&self) -> Result<Keys, String> {
        match std::fs::read_to_string(&self.key_file) {
            Ok(s) => Keys::from_hex(s.trim()).ok_or_else(|| "the relay operator key file is damaged".to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let k = Keys::generate();
                if let Some(d) = self.key_file.parent() {
                    std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
                }
                let mut o = std::fs::OpenOptions::new();
                o.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
                let mut f = o.open(&self.key_file).map_err(|e| format!("{}: {e}", self.key_file.display()))?;
                std::io::Write::write_all(&mut f, format!("{}\n", k.secret_hex()).as_bytes()).map_err(|e| e.to_string())?;
                Ok(k)
            }
            Err(e) => Err(format!("{}: {e}", self.key_file.display())),
        }
    }

    /// Announce a relay the owner runs on the owner's Nostr relays. `Ok` with how many accepted.
    pub fn publish(&self, offer: &Offer) -> Result<(usize, Vec<Outcome>), String> {
        if self.nostr_relays.is_empty() {
            return Err("no Nostr relays are set, so there is nowhere to announce it".into());
        }
        let ev = relays::announcement_event(&self.operator_key()?, offer, xbt_nostr::now())?;
        let outcomes = oneshot::publish(&self.nostr_relays, &ev, Duration::from_secs(10));
        let ok = outcomes.iter().filter(|o| o.result.is_ok()).count();
        // the owner's own relay becomes one of theirs
        let mut prefs = self.prefs();
        let relay = relays::canonical_relay(&offer.relay)?;
        if !prefs.own.contains(&relay) {
            prefs.own.push(relay);
            self.save(&prefs)?;
        }
        *self.snap.lock().unwrap_or_else(|p| p.into_inner()) = None;
        Ok((ok, outcomes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_round_trip_and_selected_is_written() {
        let d = std::env::temp_dir().join(format!("relaynet-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let n = RelayNet::new(Vec::new(), &d);
        assert_eq!(n.prefs(), Prefs::default());
        let p = Prefs { pinned: vec!["https://a.example.com/".into()], blocked: vec!["https://b.example.com/".into()],
                        own: vec!["https://mine.example.com/".into()], only_own: false };
        n.save(&p).unwrap();
        assert_eq!(n.prefs(), p);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(d.join("relays.json")).unwrap()).unwrap();
        // nothing probed yet: only the default relay is selected
        assert_eq!(v["selected"], json!([DEFAULT_RELAY]));
        let k1 = n.operator_key().unwrap();
        assert_eq!(n.operator_key().unwrap().public_hex(), k1.public_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(d.join("secrets/relay-operator.key")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(n.publish(&Offer { relay: "https://mine.example.com".into(), region: "eu".into(), capacity_mbit: None, udp: false,
                                   contact: String::new(), note: String::new(), ttl_s: 86_400 }).unwrap_err().contains("no Nostr relays"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
