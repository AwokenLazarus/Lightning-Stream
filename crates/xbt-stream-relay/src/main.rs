//! `xbt-stream-relay`: the package's Stream relay service. Off until the owner switches it on in
//! the app; see the crate docs and `docs/RUN-A-RELAY.md`.
//!
//! | Variable | Default | |
//! | --- | --- | --- |
//! | `XBT_RELAY_SETTINGS` | `/data/run/relay/relay.json` | the owner's choices, written by the app |
//! | `XBT_RELAY_STATUS` | `/data/run/relay-status/status.json` | what the relay is doing, for the app |
//! | `XBT_RELAY_STATE` | `/data/stream-relay` | certificates and the attempt log (this service's own) |
//! | `XBT_RELAY_LISTEN` | `0.0.0.0:443` | where HTTPS listens (a container may map 443 to another port) |
//! | `XBT_RELAY_QUIC_LISTEN` | `0.0.0.0:7842` | where QUIC address discovery listens, when chosen |
//! | `XBT_RELAY_STUN` | Cloudflare's and Google's | STUN servers asked for the public address, comma-separated |
//! | `XBT_RELAY_ACME_STAGING` | unset | `1`: Let's Encrypt's staging server (for tests) |
//! | `XBT_RELAY_CREDIT_LISTEN` | `127.0.0.1:3341` | a paid relay's credit API, for the operator's own gateway only (`docs/PAID-RELAYS.md`) |
//!
//! Logs: warnings and errors only, and never from inside a client's connection, whose lines carry
//! the client's address.
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use iroh_relay::server::{self as relay, AcmeConfig, CertConfig, ClientRateLimit, QuicConfig, RelayConfig, ServerConfig};
use xbt_stream_relay::config::{self, Settings};
use xbt_stream_relay::meter::{Free, Gate, Meter};
use xbt_stream_relay::paid::Paid;
use xbt_stream_relay::preflight;
use xbt_stream_relay::status::{self, State, Status};

/// How long a new relay waits for its certificate before it stops and waits for the owner.
const CERT_WAIT: Duration = Duration::from_secs(150);
const POLL: Duration = Duration::from_secs(5);

fn env_path(k: &str, d: &str) -> PathBuf {
    std::env::var_os(k).map(PathBuf::from).unwrap_or_else(|| d.into())
}

fn env_addr(k: &str, d: &str) -> SocketAddr {
    std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| d.parse().expect("default address"))
}

struct Paths {
    settings: PathBuf,
    status: PathBuf,
    state: PathBuf,
}

impl Paths {
    fn certs(&self) -> PathBuf {
        self.state.join("certs")
    }
    fn attempts(&self) -> PathBuf {
        self.state.join("attempts.json")
    }
    /// A paid relay's accounts: what shops have bought and used.
    fn accounts(&self) -> PathBuf {
        self.state.join("accounts.json")
    }
}

fn save_accounts(p: &Paths, paid: &Paid) {
    let _ = std::fs::create_dir_all(&p.state);
    let tmp = p.accounts().with_extension("json.tmp");
    if std::fs::write(&tmp, paid.saved().to_string()).and_then(|_| std::fs::rename(&tmp, p.accounts())).is_err() {
        eprintln!("xbt-stream-relay: {}: could not keep the accounts", p.accounts().display());
    }
}

fn read_settings(p: &Paths) -> Settings {
    std::fs::read_to_string(&p.settings).ok().and_then(|s| serde_json::from_str(&s).ok()).map(|v| Settings::from_value(&v)).unwrap_or_default()
}

/// Certificate attempts in the last hour, from the log.
fn attempts_last_hour(p: &Paths) -> Vec<u64> {
    let now = status::now();
    std::fs::read_to_string(p.attempts()).ok().and_then(|s| serde_json::from_str::<Vec<u64>>(&s).ok()).unwrap_or_default()
        .into_iter().filter(|t| now.saturating_sub(*t) < 3600).collect()
}

fn log_attempt(p: &Paths) {
    let mut v = attempts_last_hour(p);
    v.push(status::now());
    let _ = std::fs::create_dir_all(&p.state);
    let _ = std::fs::write(p.attempts(), serde_json::to_string(&v).unwrap_or_default());
}

fn write(p: &Paths, s: &Status) {
    if let Err(e) = s.write(&p.status) {
        eprintln!("xbt-stream-relay: {}: {e}", p.status.display());
    }
}

fn server_config(s: &Settings, p: &Paths, meter: Arc<dyn Meter>) -> ServerConfig {
    let tls_builder = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
        .with_no_client_auth();
    let acme = AcmeConfig::letsencrypt(std::env::var("XBT_RELAY_ACME_STAGING").as_deref() != Ok("1"))
        .domains(vec![s.domain.clone()])
        .contact(vec![format!("mailto:{}", s.contact)])
        .cache_path(p.certs());
    let cert = CertConfig::LetsEncrypt { acme_config: acme, server_config_builder: tls_builder };
    let mut limits = relay::Limits::default();
    limits.accept_conn_limit = Some(config::ACCEPT_CONN_LIMIT);
    limits.accept_conn_burst = Some(config::ACCEPT_CONN_BURST);
    let mut rx = ClientRateLimit::new(NonZeroU32::new(config::CLIENT_RX_BYTES_PER_S).expect("non-zero"));
    rx.max_burst_bytes = NonZeroU32::new(config::CLIENT_RX_BURST_BYTES);
    limits.client_rx = Some(rx);
    let mut rc = RelayConfig::new(config::CAPTIVE_PORTAL);
    rc.tls = Some(relay::TlsConfig::new(env_addr("XBT_RELAY_LISTEN", "0.0.0.0:443"), cert));
    rc.limits = limits;
    rc.access = Arc::new(Gate(meter));
    let mut sc = ServerConfig::default();
    sc.relay = Some(rc);
    sc.quic = s.udp.then(|| QuicConfig::new(env_addr("XBT_RELAY_QUIC_LISTEN", "0.0.0.0:7842")));
    sc.metrics_addr = Some(config::METRICS);
    sc
}

/// The relay answers with a certificate for `domain` that the public roots trust.
fn certificate_ok(domain: &str, listen: SocketAddr) -> bool {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().expect("ring").with_root_certificates(roots).with_no_client_auth();
    let Ok(name) = rustls::pki_types::ServerName::try_from(domain.to_string()) else { return false };
    let target = SocketAddr::new(if listen.ip().is_unspecified() { [127, 0, 0, 1].into() } else { listen.ip() }, listen.port());
    let Ok(tcp) = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(3)) else { return false };
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(conn) = rustls::ClientConnection::new(Arc::new(cfg), name) else { return false };
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        if tls.conn.complete_io(&mut tls.sock).is_err() {
            return false;
        }
    }
    true
}

fn metrics_text() -> String {
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&config::METRICS, Duration::from_secs(2)) else { return String::new() };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = std::io::Write::write_all(&mut s, b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n");
    let mut out = String::new();
    let _ = std::io::Read::read_to_string(&mut s, &mut out);
    out
}

/// The default log filter: warnings and errors, but nothing logged inside a client's connection
/// (iroh-relay names the client's address in that span).
pub const LOG_FILTER: &str = "warn,[conn]=off";

/// The container's health check: the service rewrites its status file every [`POLL`], on or off,
/// so a status file younger than this means its loop is alive.
const HEALTHY_WITHIN: Duration = Duration::from_secs(120);

/// `xbt-stream-relay healthcheck`: 0 when the status file was written within [`HEALTHY_WITHIN`].
fn healthcheck() -> i32 {
    let status = env_path("XBT_RELAY_STATUS", "/data/run/relay-status/status.json");
    let fresh = std::fs::metadata(&status).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age <= HEALTHY_WITHIN);
    if fresh { 0 } else { 1 }
}

#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(healthcheck());
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(LOG_FILTER));
    tracing_subscriber::fmt().with_env_filter(filter).with_ansi(std::env::var_os("NO_COLOR").is_none()).with_writer(std::io::stderr).init();
    let p = Paths {
        settings: env_path("XBT_RELAY_SETTINGS", "/data/run/relay/relay.json"),
        status: env_path("XBT_RELAY_STATUS", "/data/run/relay-status/status.json"),
        state: env_path("XBT_RELAY_STATE", "/data/stream-relay"),
    };
    let listen = env_addr("XBT_RELAY_LISTEN", "0.0.0.0:443");
    let stun: Vec<String> = std::env::var("XBT_RELAY_STUN").ok().map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
    let mut running: Option<(relay::Server, Settings, Arc<dyn Meter>, Status)> = None;
    // a paid relay's meter outlives restarts of the server, and its accounts restarts of the service
    let paid = Arc::new(Paid::new(Default::default()));
    if let Some(v) = std::fs::read_to_string(p.accounts()).ok().and_then(|s| serde_json::from_str(&s).ok()) {
        paid.restore(&v);
    }
    let mut credit_api: Option<SocketAddr> = None;
    // the settings an attempt was last made with: a failed attempt is not repeated until they change
    let mut tried: Option<Settings> = None;
    loop {
        let s = read_settings(&p);
        // stop when switched off or changed
        if running.as_ref().is_some_and(|(_, was, ..)| !s.enabled || *was != s) {
            let (srv, ..) = running.take().expect("running");
            let _ = srv.shutdown().await;
            save_accounts(&p, &paid);
        }
        if !s.enabled {
            tried = None;
            write(&p, &Status::new(State::Off, &s.domain, "The relay is off."));
        } else if let Some((_, ref was, ref meter, ref mut st)) = running {
            let (sent, recv) = status::traffic(&tokio::task::spawn_blocking(metrics_text).await.unwrap_or_default());
            st.bytes_sent = sent;
            st.bytes_recv = recv;
            st.clients = meter.connected();
            st.udp = was.udp;
            if was.paid.enabled {
                let mut v = was.paid.terms();
                v["totals"] = paid.totals();
                v["credit_api"] = credit_api.map(|a| a.to_string()).into();
                st.paid = v;
                paid.prune();
                save_accounts(&p, &paid);
            }
            write(&p, st);
        } else if !s.problems().is_empty() {
            write(&p, &Status::new(State::Invalid, &s.domain, s.problems().join(" ")));
        } else if tried.as_ref() != Some(&s) {
            tried = Some(s.clone());
            write(&p, &Status::new(State::Checking, &s.domain, "Checking the domain and port 443 before asking for a certificate."));
            let (dom, fwd, n, stun2) = (s.domain.clone(), s.port_forwarded, attempts_last_hour(&p).len() as u32, stun.clone());
            let observed = tokio::task::spawn_blocking(move || preflight::observe(&dom, listen, fwd, n, &stun2)).await.unwrap_or_default();
            let report = preflight::evaluate(&s.domain, &observed);
            if !report.ready {
                let mut st = Status::new(State::NotReady, &s.domain, "Not ready: nothing was asked of Let's Encrypt. Fix what is marked, then try again.");
                st.preflight = report.to_value();
                write(&p, &st);
            } else {
                log_attempt(&p);
                let meter: Arc<dyn Meter> = if s.paid.enabled {
                    paid.set_settings(s.paid.clone());
                    if credit_api.is_none() {
                        let at = env_addr("XBT_RELAY_CREDIT_LISTEN", "127.0.0.1:3341");
                        match xbt_stream_relay::credit::spawn(paid.clone(), at) {
                            Ok(a) => credit_api = Some(a),
                            Err(e) => eprintln!("xbt-stream-relay: the credit API could not listen on {at}: {e}"),
                        }
                    }
                    paid.clone()
                } else {
                    // a credit API already listening answers that this relay is free
                    paid.set_settings(Default::default());
                    Arc::new(Free::default())
                };
                match relay::Server::spawn(server_config(&s, &p, meter.clone())).await {
                    Err(e) => {
                        let mut st = Status::new(State::Failed, &s.domain, format!("The relay couldn't start: {e}"));
                        st.preflight = report.to_value();
                        write(&p, &st);
                    }
                    Ok(srv) => {
                        let mut st = Status::new(State::Certifying, &s.domain, "Running; asking Let's Encrypt for the certificate.");
                        st.preflight = report.to_value();
                        write(&p, &st);
                        let deadline = tokio::time::Instant::now() + CERT_WAIT;
                        let mut ok = false;
                        while tokio::time::Instant::now() < deadline {
                            tokio::time::sleep(POLL).await;
                            let d = s.domain.clone();
                            if tokio::task::spawn_blocking(move || certificate_ok(&d, listen)).await.unwrap_or(false) {
                                ok = true;
                                break;
                            }
                        }
                        if ok {
                            st.state = State::Running;
                            st.since = status::now();
                            st.message = "Running. Announce it so apps can find it.".into();
                            st.udp = s.udp;
                            write(&p, &st);
                            running = Some((srv, s.clone(), meter, st));
                        } else {
                            let _ = srv.shutdown().await;
                            st.state = State::Failed;
                            st.message = "The certificate didn't come, so the relay stopped (it won't keep asking: Let's Encrypt allows 5 \
                                          failures an hour). Check that TCP 443 reaches this box from the internet, then try again.".into();
                            write(&p, &st);
                        }
                    }
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    if let Some((srv, ..)) = running {
        let _ = srv.shutdown().await;
    }
    save_accounts(&p, &paid);
}
