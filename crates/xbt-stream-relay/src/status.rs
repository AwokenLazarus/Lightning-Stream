//! The status file the app shows: what the relay is doing, the pre-flight checks, the certificate,
//! traffic and clients. Written atomically; the app only reads it.
use std::path::Path;

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Off,
    /// The settings can't run (a bad domain or contact).
    Invalid,
    Checking,
    /// A pre-flight check failed: nothing was asked of Let's Encrypt.
    NotReady,
    /// Running, waiting for the certificate.
    Certifying,
    Running,
    /// The certificate didn't come: stopped, waiting for the owner to try again.
    Failed,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Invalid => "invalid",
            Self::Checking => "checking",
            Self::NotReady => "not_ready",
            Self::Certifying => "certifying",
            Self::Running => "running",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub state: State,
    pub domain: String,
    pub since: u64,
    pub message: String,
    pub preflight: Value,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub clients: usize,
    pub udp: bool,
    /// A paid relay's terms and totals (`null` for a free one).
    pub paid: Value,
}

impl Status {
    pub fn new(state: State, domain: &str, message: impl Into<String>) -> Self {
        Self { state, domain: domain.into(), since: now(), message: message.into(), preflight: Value::Null, bytes_sent: 0, bytes_recv: 0,
               clients: 0, udp: false, paid: Value::Null }
    }

    pub fn to_value(&self) -> Value {
        json!({"state": self.state.word(), "domain": self.domain, "since": self.since, "message": self.message,
               "preflight": self.preflight, "bytes_sent": self.bytes_sent, "bytes_recv": self.bytes_recv, "clients": self.clients,
               "udp": self.udp, "paid": self.paid, "written": now()})
    }

    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, format!("{:#}\n", self.to_value()))?;
        std::fs::rename(&tmp, path)
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The relay's byte counters from its Prometheus text (`bytes_sent`, `bytes_recv`).
pub fn traffic(metrics: &str) -> (u64, u64) {
    let find = |name: &str| metrics.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        let (k, v) = l.rsplit_once(' ')?;
        let k = k.split('{').next()?;
        (k.ends_with(name) || k.ends_with(&format!("{name}_total"))).then(|| v.trim().parse::<f64>().ok().map(|f| f as u64)).flatten()
    }).unwrap_or(0);
    (find("bytes_sent"), find("bytes_recv"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_byte_counters() {
        let m = "# HELP relayserver_bytes_sent Number of bytes sent.\n# TYPE relayserver_bytes_sent counter\nrelayserver_bytes_sent_total 12345\n\
                 relayserver_bytes_recv_total{x=\"y\"} 678\nrelayserver_send_packets_sent_total 9\n";
        assert_eq!(traffic(m), (12345, 678));
        assert_eq!(traffic(""), (0, 0));
    }

    #[test]
    fn writes_atomically() {
        let d = std::env::temp_dir().join(format!("relay-status-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("status.json");
        Status::new(State::Running, "relay.example.com", "ok").write(&p).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["state"], "running");
        let _ = std::fs::remove_dir_all(&d);
    }
}
