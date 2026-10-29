//! What the owner chose (`relay.json`, written by the app) and the fixed defaults, which match our
//! own relay's: a client may connect at 10 a second (bursts of 50), and send 6 MB/s (bursts of
//! 12 MB); certificates come from Let's Encrypt by TLS-ALPN-01 on 443; the captive-portal and
//! metrics listeners stay on loopback; QUIC address discovery listens on UDP 7842 when chosen.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde_json::Value;

/// The port certificates are validated on, and buyers' and sellers' apps connect to.
pub const PUBLIC_PORT: u16 = 443;
/// QUIC address discovery.
pub const QUIC_PORT: u16 = 7842;
pub const ACCEPT_CONN_LIMIT: f64 = 10.0;
pub const ACCEPT_CONN_BURST: usize = 50;
pub const CLIENT_RX_BYTES_PER_S: u32 = 6_000_000;
pub const CLIENT_RX_BURST_BYTES: u32 = 12_000_000;
pub const CAPTIVE_PORTAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3340);
pub const METRICS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9091);
pub const MAX_CONTACT: usize = 128;

/// The owner's choices.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    pub enabled: bool,
    /// The relay's name, the one its certificate is for.
    pub domain: String,
    /// The e-mail address Let's Encrypt writes to about the certificate.
    pub contact: String,
    /// Also answer QUIC address discovery on UDP [`QUIC_PORT`].
    pub udp: bool,
    /// The owner says TCP 443 is forwarded to this box (a box behind a router, which cannot check
    /// that from the inside).
    pub port_forwarded: bool,
    /// Bumped by the app's Try again button: a new attempt after a failed one.
    pub attempt: u64,
}

impl Settings {
    pub fn from_value(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();
        let b = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        Self { enabled: b("enabled"), domain: s("domain").to_ascii_lowercase(), contact: s("contact"), udp: b("udp"),
               port_forwarded: b("port_forwarded"), attempt: v.get("attempt").and_then(Value::as_u64).unwrap_or(0) }
    }

    pub fn to_value(&self) -> Value {
        serde_json::json!({"enabled": self.enabled, "domain": self.domain, "contact": self.contact, "udp": self.udp,
                           "port_forwarded": self.port_forwarded, "attempt": self.attempt})
    }

    /// The reasons these settings cannot run, in words; empty when they can.
    pub fn problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Err(e) = check_domain(&self.domain) {
            v.push(e);
        }
        if let Err(e) = check_contact(&self.contact) {
            v.push(e);
        }
        v
    }
}

/// A public DNS name: letters, digits and hyphens in dot-separated labels, at least two labels,
/// no IP address (Let's Encrypt does not certify one).
pub fn check_domain(d: &str) -> Result<(), String> {
    if d.is_empty() {
        return Err("Enter the domain name that points at this box.".into());
    }
    if d.parse::<IpAddr>().is_ok() {
        return Err("Enter a domain name, not an IP address: certificates are issued for names.".into());
    }
    if d.len() > 253 || !d.contains('.') {
        return Err("That isn't a full domain name, such as relay.example.com.".into());
    }
    for label in d.split('.') {
        let ok = !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok {
            return Err(format!("“{label}” can't be part of a domain name."));
        }
    }
    if d.ends_with(".local") || d.ends_with(".lan") || d.ends_with(".internal") || d.ends_with(".home.arpa") {
        return Err("That name only works on your home network: a relay needs a public domain name.".into());
    }
    Ok(())
}

/// An e-mail address, as Let's Encrypt asks for one.
pub fn check_contact(c: &str) -> Result<(), String> {
    let ok = c.len() <= MAX_CONTACT && c.split_once('@').is_some_and(|(u, h)| !u.is_empty() && h.contains('.') && !h.starts_with('.'))
        && !c.chars().any(|ch| ch.is_whitespace() || ch.is_control());
    if ok { Ok(()) } else { Err("Enter an e-mail address Let's Encrypt can write to about the certificate.".into()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert!(check_domain("relay.example.com").is_ok());
        assert!(check_domain("a-1.b.example").is_ok());
        for bad in ["", "relay", "203.0.113.7", "-x.example.com", "x_y.example.com", "box.local", "relay..example.com", "relay.example.com/"] {
            assert!(check_domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn contacts() {
        assert!(check_contact("ops@example.com").is_ok());
        for bad in ["", "ops", "ops@", "@example.com", "ops@example", "o ps@example.com"] {
            assert!(check_contact(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_round_trip_and_problems() {
        let v = serde_json::json!({"enabled": true, "domain": " Relay.Example.com ", "contact": "ops@example.com", "udp": true, "attempt": 3});
        let s = Settings::from_value(&v);
        assert_eq!(s.domain, "relay.example.com");
        assert!(s.problems().is_empty());
        assert_eq!(Settings::from_value(&s.to_value()), s);
        assert_eq!(Settings::from_value(&serde_json::json!({})).problems().len(), 2);
    }
}
