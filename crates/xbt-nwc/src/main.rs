//! `xbt-nwc`: the NWC wallet service (see the library and `docs/NWC.md`).
//!
//!   xbt-nwc [serve]       serve (configuration from the environment)
//!   xbt-nwc healthcheck   ask the admin socket for `nwc_status`: the image's HEALTHCHECK; exit 0 when it answers
//!
//! Environment:
//!
//! | variable | default | meaning |
//! |---|---|---|
//! | `NWC_STATE_DIR` | `$XBT_DATA_DIR/nwc`, else `./xbt-nwc` | the connections file (0600) in a 0700 directory |
//! | `NWC_ADMIN_SOCK` | `$XBT_DATA_DIR/run/nwc/admin.sock`, else `<state dir>/admin.sock` | the socket the wallet UI makes and revokes connections on |
//! | `NWC_ADMIN_SOCK_MODE` | `600` | its mode, at most `660` |
//! | `B2_SIGNER_SOCK` | `$B2_ROOT/.run/signer.sock` | the signer's socket |
//! | `NWC_RELAYS` | | the relays a new connection uses unless the UI names others, comma-separated (`wss://...`) |
//! | `NWC_APPROVAL_WAIT_S` | `0` | how long a payment above the human threshold waits for the owner's approval |
//! | `NWC_SIGNER_TIMEOUT_S` | `120` | how long one signer call may take (a payment included) |
//! | `NWC_RATE_PER_MIN` | `60` | requests per connection per minute |
use std::path::PathBuf;
use std::time::Duration;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn secs(k: &str, d: f64) -> Duration {
    Duration::from_secs_f64(env(k).and_then(|v| v.parse::<f64>().ok()).filter(|v| v.is_finite() && *v >= 0.0).unwrap_or(d).min(86_400.0))
}

fn state_dir() -> PathBuf {
    env("NWC_STATE_DIR").map(PathBuf::from).or_else(|| env("XBT_DATA_DIR").map(|d| PathBuf::from(d).join("nwc"))).unwrap_or_else(|| PathBuf::from("xbt-nwc"))
}

fn admin_sock() -> PathBuf {
    env("NWC_ADMIN_SOCK").map(PathBuf::from)
        .or_else(|| env("XBT_DATA_DIR").map(|d| PathBuf::from(d).join("run").join("nwc").join("admin.sock")))
        .unwrap_or_else(|| state_dir().join("admin.sock"))
}

fn signer_sock() -> PathBuf {
    env("B2_SIGNER_SOCK").map(PathBuf::from)
        .unwrap_or_else(|| env("B2_ROOT").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join(".run").join("signer.sock"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("serve") => std::process::exit(serve()),
        Some("healthcheck") => std::process::exit(healthcheck()),
        Some("-h") | Some("--help") => {
            println!("usage: xbt-nwc [serve] | healthcheck\n\
                      serve reads NWC_STATE_DIR, NWC_ADMIN_SOCK, B2_SIGNER_SOCK, NWC_RELAYS, NWC_APPROVAL_WAIT_S, ... (docs/NWC.md)");
        }
        Some(o) => {
            eprintln!("xbt-nwc: unknown command {o} (try --help)");
            std::process::exit(2);
        }
    }
}

fn serve() -> i32 {
    let signals = match xbt_svc::shutdown::listen() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xbt-nwc: signals: {e}");
            return 2;
        }
    };
    let mode = match xbt_nwc::admin::sock_mode() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("xbt-nwc: {e}");
            return 2;
        }
    };
    let mut cfg = xbt_nwc::service::Config::new(state_dir(), signer_sock());
    cfg.default_relays = env("NWC_RELAYS").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
    for r in &cfg.default_relays {
        if let Err(e) = xbt_nwc::ws::parse_url(r) {
            eprintln!("xbt-nwc: NWC_RELAYS {r}: {e}");
            return 2;
        }
    }
    cfg.approval_wait = secs("NWC_APPROVAL_WAIT_S", 0.0);
    cfg.signer_timeout = secs("NWC_SIGNER_TIMEOUT_S", 120.0).max(Duration::from_secs(5));
    cfg.rate_per_min = env("NWC_RATE_PER_MIN").and_then(|v| v.parse().ok()).filter(|n| *n > 0).unwrap_or(60);
    let svc = match xbt_nwc::service::Service::new(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xbt-nwc: {e}");
            return 2;
        }
    };
    let sock = admin_sock();
    let admin = match xbt_nwc::admin::spawn(svc.clone(), &sock, mode) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("xbt-nwc: admin socket {e}");
            return 1;
        }
    };
    svc.start();
    // counts only: never a key, a URI or a relay's answer to a request
    eprintln!("xbt-nwc: serving {} connection(s); admin socket {}", svc.list()["connections"].as_array().map(Vec::len).unwrap_or(0), sock.display());
    let sig = signals.wait();
    xbt_svc::shutdown::say_stopping("xbt-nwc", sig);
    drop(admin);
    svc.stop();
    0
}

fn healthcheck() -> i32 {
    let c = xbt_signer::client::SignerClient { sock_path: admin_sock(), timeout: Duration::from_secs(5) };
    match c.call("nwc_status", serde_json::json!({})) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("xbt-nwc healthcheck: {}", e.msg);
            1
        }
    }
}
