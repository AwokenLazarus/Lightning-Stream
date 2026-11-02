//! The VPN service's settings: what the app's pages write (`devices.json`, `exit.json` in the VPN
//! directory) read into the buyer's devices and this box's exit, and what the service writes back for
//! the pages (`endpoint.json`, `status.json`, `exit-status.json`).
//!
//! The pages own the settings files and the service only reads them; the service owns the status
//! files and the pages only read them. A device's limit is in sats: it applies once exits are paid
//! (until then the service carries traffic for the device without a limit, and says so in
//! `status.json`).

use std::net::Ipv4Addr;
use std::path::Path;

use base64::Engine;
use serde_json::{json, Value};

use crate::content::{ContentFilter, DomainSet, LiveLists};
use crate::exit::{ExitConfig, ExitKind};
use crate::filter::Policy;
use crate::region::RegionCheck;
use crate::router::{ExitInfo, Requirements, Want};

/// A device from `devices.json`.
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceEntry {
    pub id: String,
    pub name: String,
    pub public: [u8; 32],
    pub tunnel_ip: Ipv4Addr,
    pub limit_sats: Option<u64>,
    pub requirements: Requirements,
}

/// The device policy the pages write (`kind`, `country`, `two_hop`, `max_sat_per_gb`, `min_mbit`,
/// `no_logs`, `mode`) as the router's requirements. Anything missing takes the default: a private
/// exit, the best one.
pub fn requirements_from(p: &Value) -> Requirements {
    let kind = match p["kind"].as_str() {
        Some("filtered") => Want::Filtered(Vec::new()),
        Some("any") => Want::Any,
        _ => Want::Private,
    };
    Requirements {
        kind,
        region: p["country"].as_str().filter(|c| c.len() == 2).map(|c| c.to_ascii_uppercase()),
        two_hop: p["two_hop"].as_bool().unwrap_or(false),
        max_price_msat_per_gb: p["max_sat_per_gb"].as_u64().map(|s| s.saturating_mul(1000)),
        min_mbit_s: p["min_mbit"].as_f64(),
        must_not_log: p["no_logs"].as_bool().unwrap_or(false),
        sticky: p["mode"].as_str() == Some("sticky"),
        spread: p["mode"].as_str() == Some("spread"),
        ..Requirements::default()
    }
}

/// The most exits the owner may add by hand.
pub const MAX_ADDED_EXITS: usize = 16;

/// The exits the owner added by hand (`exits` in `devices.json`): each one's signed announcement, as
/// the app found it on Nostr. The service reads them with the ones its own relays give, through the same
/// checks ([`crate::announce::collect`]): an event that does not hold is not used, and a newer
/// announcement of the same exit replaces it.
pub fn added_exits(v: &Value) -> Vec<xbt_nostr::event::Event> {
    v["exits"].as_array().map(|a| a.iter().take(MAX_ADDED_EXITS).filter_map(xbt_nostr::event::Event::from_value).collect()).unwrap_or_default()
}

/// The exit keys of the exits the owner added: every device prefers them among the exits that meet its
/// rules (a preference, never a way around a rule).
pub fn added_exit_ids(v: &Value) -> Vec<String> {
    added_exits(v).iter().filter_map(|e| e.tag("exit").map(str::to_string)).collect()
}

/// The devices of `devices.json`, without the removed ones and any entry that does not hold
/// together (a bad key or address is skipped, never guessed at). Each prefers the exits the owner
/// added ([`added_exit_ids`]).
pub fn devices_from(v: &Value) -> Vec<DeviceEntry> {
    let Some(list) = v["devices"].as_array() else { return Vec::new() };
    let prefer = added_exit_ids(v);
    list.iter()
        .filter(|d| !d["revoked"].as_bool().unwrap_or(false))
        .filter_map(|d| {
            let public: [u8; 32] = base64::engine::general_purpose::STANDARD.decode(d["public_key"].as_str()?).ok()?.try_into().ok()?;
            let tunnel_ip: Ipv4Addr = d["tunnel_ip"].as_str()?.parse().ok()?;
            Some(DeviceEntry {
                id: d["id"].as_str()?.to_string(),
                name: d["name"].as_str().unwrap_or("").to_string(),
                public,
                tunnel_ip,
                limit_sats: d["limit_sats"].as_u64(),
                requirements: Requirements { prefer: prefer.clone(), ..requirements_from(&d["policy"]) },
            })
        })
        .collect()
}

/// The exits for the page (`exits` of `status.json`): every exit the service found and may use, each
/// with its country check where one was made. Before 0.2.3 only exits whose country had been checked
/// were listed, and a priced exit is checked only once a device asks for its country, so a priced exit
/// in use or at hand never showed (Mike's Umbrel: the Pi Demo exit, SV, 1,000 sat/GB).
pub fn exits_status(known: &[ExitInfo], checks: &[(String, String, RegionCheck, std::time::SystemTime)], added: &[String]) -> Vec<Value> {
    let mut rows: Vec<Value> = known.iter().map(|e| {
        let check = checks.iter().find(|c| c.0 == e.id);
        let region = &e.region;
        let words = match check.map(|c| &c.2) {
            Some(RegionCheck::Verified) => format!("Checked: its traffic comes out in {region}."),
            Some(RegionCheck::Elsewhere(cc)) => format!("Its traffic comes out in {cc}, not {region}: not used for {region}."),
            Some(RegionCheck::TooFast) => format!("It answers faster than {region} is from here: not used for {region}."),
            Some(RegionCheck::Unknown) => "Not checked yet: no country table, or the address checks didn't agree.".to_string(),
            None if e.price_msat_per_gb > 0 => format!("Not checked: a paid exit's country is checked once a device asks for {region}."),
            None => "Not checked yet.".to_string(),
        };
        let at = check.and_then(|c| c.3.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        json!({"exit": e.id, "operator": e.operator, "region": region, "verified": check.is_some_and(|c| c.2 == RegionCheck::Verified),
               "region_check": words, "checked_at": at, "price_msat_gb": e.price_msat_per_gb, "kind": if e.filtered { "filtered" } else { "private" },
               "added": added.contains(&e.id)})
    }).collect();
    rows.sort_by(|a, b| a["exit"].as_str().cmp(&b["exit"].as_str()));
    rows
}

/// This box's exit, as `exit.json` sets it.
#[derive(Clone, Debug, PartialEq)]
pub struct ExitSettings {
    pub filtered: bool,
    pub categories: Vec<String>,
    pub own_blocklist: Vec<String>,
    pub sat_per_gb: u64,
    /// The country the exit's connection is in, as its owner says (two letters). Buyers choose by it,
    /// so without one the exit is not announced.
    pub country: Option<String>,
    pub buyer_mbit: Option<u64>,
    pub max_connections: usize,
    pub blocked_ports: Vec<u16>,
    /// Where buyers' wallets open paid tunnels to this exit (`https://<shop>/vpn/tunnel`), as the
    /// exit page found it from the owner's shop; announced with the exit.
    pub tunnel_url: Option<String>,
}

/// The exit's settings, if `exit.json` offers one.
pub fn exit_from(v: &Value) -> Option<ExitSettings> {
    if !v["offer"].as_bool().unwrap_or(false) {
        return None;
    }
    let strings = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let filtered = v["kind"].as_str() == Some("filtered");
    Some(ExitSettings {
        filtered,
        categories: if filtered { strings("categories") } else { Vec::new() },
        own_blocklist: if filtered { strings("own_blocklist") } else { Vec::new() },
        sat_per_gb: v["sat_per_gb"].as_u64().filter(|n| *n > 0).unwrap_or(20),
        country: v["country"].as_str().filter(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic())).map(|c| c.to_ascii_uppercase()),
        buyer_mbit: v["buyer_mbit"].as_u64().filter(|n| *n > 0),
        max_connections: v["max_connections"].as_u64().filter(|n| *n > 0).map(|n| n as usize).unwrap_or(512),
        blocked_ports: v["blocked_ports"].as_array().map(|a| a.iter().filter_map(|p| p.as_u64().and_then(|p| u16::try_from(p).ok())).collect()).unwrap_or_else(|| vec![25]),
        tunnel_url: v["tunnel_url"].as_str().filter(|u| (u.starts_with("https://") || u.starts_with("http://")) && u.len() <= 512).map(str::to_string),
    })
}

/// The exit's configuration from its settings: this machine's own networks always refused, the
/// operator's ports, speed and connection caps, and for a filtered exit its own list and
/// categories (`lists`, kept up to date by [`crate::lists::keep_updated`]).
pub fn exit_config(s: &ExitSettings, lists: LiveLists) -> ExitConfig {
    let mut policy = Policy::for_exit();
    policy.blocked_ports = s.blocked_ports.iter().copied().collect();
    let kind = if s.filtered {
        let mut domains = DomainSet::default();
        for d in &s.own_blocklist {
            domains.insert(d);
        }
        ExitKind::Filtered { filter: std::sync::Arc::new(ContentFilter { domains, nets: Vec::new(), categories: s.categories.clone(), lists }), resolver: None }
    } else {
        ExitKind::Private
    };
    ExitConfig { policy, buyer_bytes_per_sec: s.buyer_mbit.map(|m| m.saturating_mul(125_000)), max_tcp_flows: s.max_connections, kind, ..ExitConfig::default() }
}

/// A device's line in `status.json`.
pub fn device_status(d: &DeviceEntry, up: u64, down: u64, why_blocked: Option<String>) -> Value {
    json!({
        "id": d.id,
        "name": d.name,
        "up_bytes": up,
        "down_bytes": down,
        "blocked": why_blocked,
        "limit": if d.limit_sats.is_some() { "applies once exits are paid" } else { "none" },
    })
}

/// A device's line with where it goes out and what it has spent: `exit` (the exit its latest flow
/// took, none before its first) and `used_msat` (its paid tunnels' cost so far,
/// [`crate::buyer::Buyer::device_use`]), which the buyer's VPN page shows.
pub fn with_use(mut line: Value, exit: Option<&str>, used_msat: u64) -> Value {
    line["exit"] = json!(exit);
    line["used_msat"] = json!(used_msat);
    line
}

/// Writes `v` to `path` whole (a new file renamed over the old one, so a page never reads half), with
/// the folder's group (the one the app's pages read by) and mode 0640.
pub fn write_json(path: &Path, v: &Value) -> std::io::Result<()> {
    let tmp = path.with_extension("json.part");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode_600().open(&tmp)?;
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            std::os::unix::fs::fchown(&f, None, Some(std::fs::metadata(dir)?.gid()))?;
            f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        }
        f.write_all(&serde_json::to_vec_pretty(v).map_err(std::io::Error::other)?)?;
    }
    std::fs::rename(&tmp, path)
}

/// A 32-byte secret kept in `path` (hex, readable by its owner only), made on first use.
pub fn secret_in(path: &Path) -> std::io::Result<[u8; 32]> {
    if let Ok(s) = std::fs::read_to_string(path) {
        if let Some(k) = hex::decode(s.trim()).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
            return Ok(k);
        }
        return Err(std::io::Error::other(format!("{} is not a 32-byte hex key", path.display())));
    }
    let mut k = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut k).map_err(|_| std::io::Error::other("no random source"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("part");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode_600().open(&tmp)?;
        f.write_all(hex::encode(k).as_bytes())?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(k)
}

trait Mode600 {
    fn mode_600(&mut self) -> &mut Self;
}

impl Mode600 for std::fs::OpenOptions {
    fn mode_600(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Pi Demo exit as the relays carried it on 2026-11-02 (SV, 1,000 sat/GB, paid through its shop).
    const PI_DEMO: &str = include_str!("../tests/data/pi-demo-exit.json");
    const PI_DEMO_EXIT: &str = "81b90e5d31777fc0a405dc83d5219e9007ee5b80775ab99850db77247155340d";

    /// Mike's Umbrel: the VPN page listed no exit while the relays carried the Pi Demo exit. Its
    /// announcement reads (relays, filter and parse were right); the page's list held only exits whose
    /// country had been checked, which a paid exit no device asks a country of never is.
    #[test]
    fn the_pi_demo_exit_reads_and_every_exit_found_is_listed_checked_or_not() {
        let ev = xbt_nostr::event::Event::from_value(&serde_json::from_str(PI_DEMO).unwrap()).unwrap();
        let now = 1_793_597_749;
        let a = crate::announce::read_event(&ev, now).expect("the announcement holds");
        assert_eq!((a.exit.id.as_str(), a.exit.region.as_str(), a.exit.price_msat_per_gb), (PI_DEMO_EXIT, "SV", 1_000_000));
        assert!(a.tunnel.as_deref().is_some_and(|t| t.ends_with(".shop.invalid/vpn/tunnel")), "a paid exit, with where to pay it");
        assert!(crate::announce::filter(500)["#t"][0] == crate::announce::TOPIC && crate::announce::filter(500)["kinds"][0] == 30078);

        let free = ExitInfo { id: "aa".repeat(32), region: "DE".into(), healthy: true, ..ExitInfo::default() };
        let checked = vec![(free.id.clone(), "DE".to_string(), RegionCheck::Verified, std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000))];
        let rows = exits_status(&[a.exit.clone(), free.clone()], &checked, &[PI_DEMO_EXIT.to_string()]);
        assert_eq!(rows.len(), 2, "the paid exit is listed with no check made: {rows:?}");
        let pi = rows.iter().find(|r| r["exit"] == PI_DEMO_EXIT).unwrap();
        assert_eq!((pi["region"].as_str(), pi["verified"].as_bool(), pi["price_msat_gb"].as_u64(), pi["added"].as_bool()), (Some("SV"), Some(false), Some(1_000_000), Some(true)));
        assert!(pi["region_check"].as_str().unwrap().contains("once a device asks for SV"), "{pi}");
        let de = rows.iter().find(|r| r["exit"] == free.id).unwrap();
        assert_eq!((de["verified"].as_bool(), de["checked_at"].as_u64(), de["added"].as_bool()), (Some(true), Some(1000), Some(false)));
        assert_eq!(de["region_check"], "Checked: its traffic comes out in DE.");
    }

    /// An exit added by hand on the VPN page: its signed announcement in devices.json, read with the ones
    /// the relays give and preferred by every device; a broken one is left out.
    #[test]
    fn exits_added_by_hand_are_read_from_devices_json_and_preferred() {
        let key = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        let pi: Value = serde_json::from_str(PI_DEMO).unwrap();
        let v = json!({"devices": [{"id": "a", "name": "tv", "public_key": key, "tunnel_ip": "10.66.0.2", "policy": {"country": "DE"}}],
                       "exits": [pi, {"not": "an event"}]});
        let added = added_exits(&v);
        assert_eq!(added.len(), 1);
        let (found, refused) = crate::announce::collect(&added, 1_793_597_749);
        assert_eq!((found.len(), refused), (1, 0), "checked like any announcement");
        assert_eq!(added_exit_ids(&v), vec![PI_DEMO_EXIT.to_string()]);
        let d = devices_from(&v);
        assert_eq!(d[0].requirements.prefer, vec![PI_DEMO_EXIT.to_string()]);
        assert_eq!(d[0].requirements.region.as_deref(), Some("DE"), "the device's own rules stay");
        // a tampered copy does not hold
        let mut bad = pi.clone();
        bad["tags"][4][1] = json!("DE");
        let (found, refused) = crate::announce::collect(&added_exits(&json!({"exits": [bad]})), 1_793_597_749);
        assert_eq!((found.len(), refused), (0, 1));
        assert!(devices_from(&json!({"devices": []})).is_empty() && added_exits(&json!({})).is_empty());
    }

    #[test]
    fn a_device_policy_reads_as_the_routers_requirements() {
        let r = requirements_from(&json!({"kind": "filtered", "country": "de", "two_hop": true, "max_sat_per_gb": 30, "min_mbit": 50, "no_logs": true, "mode": "spread"}));
        assert_eq!(r.kind, Want::Filtered(Vec::new()));
        assert_eq!(r.region.as_deref(), Some("DE"));
        assert!(r.two_hop && r.must_not_log && r.spread && !r.sticky);
        assert_eq!(r.max_price_msat_per_gb, Some(30_000));
        assert_eq!(r.min_mbit_s, Some(50.0));
        assert_eq!(requirements_from(&json!({})), Requirements::default(), "nothing set: a private exit, the best one");
    }

    #[test]
    fn removed_or_broken_devices_are_skipped() {
        let key = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        let v = json!({"devices": [
            {"id": "a", "name": "tv", "public_key": key, "tunnel_ip": "10.66.0.2", "limit_sats": 500, "policy": {"country": "DE"}},
            {"id": "b", "name": "old", "public_key": key, "tunnel_ip": "10.66.0.3", "revoked": true, "policy": {}},
            {"id": "c", "name": "bad key", "public_key": "short", "tunnel_ip": "10.66.0.4", "policy": {}},
            {"id": "d", "name": "bad address", "public_key": key, "tunnel_ip": "nowhere", "policy": {}},
        ]});
        let d = devices_from(&v);
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].id.as_str(), d[0].tunnel_ip, d[0].limit_sats), ("a", Ipv4Addr::new(10, 66, 0, 2), Some(500)));
        assert_eq!(d[0].requirements.region.as_deref(), Some("DE"));
        assert!(devices_from(&json!(null)).is_empty());
    }

    #[test]
    fn an_exit_is_run_only_when_offered_and_as_set() {
        assert!(exit_from(&json!({"offer": false, "kind": "filtered"})).is_none());
        let s = exit_from(&json!({"offer": true, "kind": "filtered", "categories": ["adult"], "own_blocklist": ["x.example"], "sat_per_gb": 30, "buyer_mbit": 40, "max_connections": 100, "blocked_ports": [25, 6667]})).unwrap();
        assert!(s.filtered && s.categories == ["adult"] && s.own_blocklist == ["x.example"]);
        assert_eq!(s.country, None, "no country: not announced");
        assert_eq!(exit_from(&json!({"offer": true, "country": "nl"})).unwrap().country.as_deref(), Some("NL"));
        let cfg = exit_config(&s, LiveLists::default());
        assert_eq!(cfg.buyer_bytes_per_sec, Some(5_000_000));
        assert_eq!(cfg.max_tcp_flows, 100);
        assert!(cfg.policy.blocked_ports.contains(&6667) && !cfg.policy.allow_non_public);
        let ExitKind::Filtered { filter, .. } = &cfg.kind else { panic!("a filtered exit") };
        assert!(filter.blocks_name("www.x.example").is_some());
        // a private exit never gets a site filter, even if the file lists one
        let p = exit_from(&json!({"offer": true, "kind": "private", "own_blocklist": ["x.example"]})).unwrap();
        assert!(matches!(exit_config(&p, LiveLists::default()).kind, ExitKind::Private));
        assert_eq!(p.blocked_ports, vec![25], "port 25 blocked unless the operator says otherwise");
    }

    #[test]
    fn a_secret_is_made_once_and_kept_private_and_status_is_readable_by_group() {
        let dir = std::env::temp_dir().join(format!("xbt-vpn-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("exit.key");
        let a = secret_in(&p).unwrap();
        assert_eq!(secret_in(&p).unwrap(), a, "the same key every start");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let status = dir.join("status.json");
        write_json(&status, &json!({"devices": []})).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&status).unwrap().permissions().mode() & 0o777, 0o640, "status: the pages read it by group");
        }
        std::fs::write(&p, "not hex").unwrap();
        assert!(secret_in(&p).is_err(), "a damaged key is an error, never replaced silently");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
