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
use crate::router::{Requirements, Want};

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

/// The devices of `devices.json`, without the removed ones and any entry that does not hold
/// together (a bad key or address is skipped, never guessed at).
pub fn devices_from(v: &Value) -> Vec<DeviceEntry> {
    let Some(list) = v["devices"].as_array() else { return Vec::new() };
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
                requirements: requirements_from(&d["policy"]),
            })
        })
        .collect()
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
