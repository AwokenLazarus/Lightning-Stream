//! Configuration: environment first (containers), then flags (`xbt-wallet-ui --help`).
//!
//! | variable | default | meaning |
//! |---|---|---|
//! | `XBT_UI_BIND` | `127.0.0.1:8480` | listen address; any non-loopback bind still needs the login |
//! | `XBT_UI_SIGNER_SOCK` | `B2_SIGNER_SOCK`, else `$B2_ROOT/.run/signer.sock` | the signer socket (path or `tcp://127.0.0.1:PORT`) |
//! | `XBT_UI_DATA_DIR` | `$XBT_DATA_DIR/ui`, else `./xbt-wallet-ui` | the login hash and the first-run setup code |
//! | `XBT_UI_PASSWORD_FILE` | | a file holding the login password (StartOS config, a Docker secret) |
//! | `$CREDENTIALS_DIRECTORY/xbt-ui-password` | | systemd `LoadCredential=` |
//! | `XBT_UI_PASSWORD` | | the password itself (Umbrel `${APP_PASSWORD}`); removed from the environment once read |
//! | `XBT_UI_BASE_PATH` | `/` | the path prefix a proxy serves the UI under (cookie path; a prefixed request path is also accepted) |
//! | `XBT_UI_SESSION_IDLE_S` / `XBT_UI_SESSION_MAX_S` | 900 / 28800 | session idle and absolute lifetimes |
//! | `XBT_UI_SECURE_COOKIE` | `auto` | `1`: always `Secure`; `0`: never; `auto`: when the request came over https (`X-Forwarded-Proto`) |
//! | `XBT_UI_ALLOW_IPS` | (all) | comma-separated peer IPs or prefixes (`10.21.0.`) allowed to connect, e.g. only the box's app proxy |
//! | `XBT_UI_ALLOWED_HOSTS` | | extra host names the UI answers to, comma-separated (`wallet.example.com`; `*`: any). Always allowed: IP literals, single-label names (`localhost`, a container name), `*.local`, `*.localhost`, `*.onion` (AGP-063 W4: a DNS rebinding of the box's address is refused) |
//! | `XBT_UI_SETUP_OPEN` | `0` | `1`: the first-run password setup needs no setup code (a proxy already authenticated the owner) |
//! | `XBT_UI_CMP_URL` | | xbt-compute's node status page: a link on the Overview page (one dashboard for an operator) |
//! | `XBT_UI_CMP_STATUS_URL` | | xbt-compute's status JSON (`http://…/readyz`, CONTRACT §U), read server-side for a compact tile |
//! | `XBT_UI_MCP_URL` | | the MCP endpoint(s) agents connect to, comma-separated (`http://umbrel.local:33510/mcp`), shown on the Agents page |
//! | `XBT_UI_ROLE` | `wallet` | `wallet`: the wallet's pages; `gateway`: the seller gateway's setup page only (the gateway package; no signer) |
//! | `XBT_UI_LN_DIR` | `$XBT_DATA_DIR/run/ln` | where the Lightning page writes the rail macaroon (`rail.macaroon`) and the mainnet acknowledgement (`mainnet-ack`); the signer reads them |
//! | `XBT_UI_LN_REST` / `XBT_UI_LN_TLS_CERT` | | the Lightning node's REST address and the certificate the package pins (set by the platform; shown, never typed) |
//! | `XBT_UI_GW_DIR` | `$XBT_DATA_DIR/run/gateway` | where the gateway page writes `config.json`, `invoices.macaroon` and `info.macaroon` (the same path in the gateway's container) |
//! | `XBT_UI_GW_NODE_REST` / `XBT_UI_GW_NODE_TLS_CERT` | | the Lightning node's REST address and the certificate path, as the gateway's container sees them (set by the platform) |
//! | `XBT_UI_GW_STATE_DIR` | `/data/gateway` | the gateway's state dir, written into its config |
//! | `XBT_UI_GW_PORT` | `8402` | the port the gateway listens on |
//! | `XBT_UI_GW_HEALTH_URL` | | the gateway's `/x402/ticket/health`, read server-side for the page (plain http on the box network) |
//! | `XBT_UI_GW_PROXIES` | | the addresses of the box's own proxy in front of the gateway (StartOS), offered as the default for the forwarded-address setting |
//! | `XBT_UI_MCP_TOKEN_FILE` | `$XBT_DATA_DIR/run/ui/mcp-http-token` when `XBT_DATA_DIR` is set, else `<data dir>/secrets/mcp-http-token` | the MCP bearer token, shown to the logged-in owner on the Agents page and rotated there (AGP-042). The UI owns it; the MCP only reads it (`xbt-init` makes it 0640, group `xbt-wallet-ui`). |
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub signer_sock: PathBuf,
    pub data_dir: PathBuf,
    /// A password given by the platform; otherwise the stored hash (set on first run).
    pub password: Option<String>,
    pub base_path: String,
    pub session_idle: Duration,
    pub session_max: Duration,
    pub secure_cookie: Option<bool>,
    pub allow_ips: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub setup_open: bool,
    pub cmp_url: Option<String>,
    pub cmp_status_url: Option<String>,
    pub mcp_urls: Vec<String>,
    pub mcp_token_file: PathBuf,
    pub threads: usize,
    pub role: Role,
    pub ln: LnSetup,
    pub gw: GatewaySetup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Wallet,
    Gateway,
}

/// The wallet's Lightning page: where it writes, and what the platform said about the node.
#[derive(Debug, Clone, Default)]
pub struct LnSetup {
    pub dir: PathBuf,
    pub rest: Option<String>,
    pub tls_cert: Option<PathBuf>,
}

/// The gateway page: where it writes, and the node and paths as the gateway's container sees them.
#[derive(Debug, Clone, Default)]
pub struct GatewaySetup {
    pub dir: PathBuf,
    pub node_rest: Option<String>,
    pub node_tls_cert: Option<PathBuf>,
    pub state_dir: String,
    pub port: u16,
    pub health_url: Option<String>,
    pub proxies: Vec<String>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

pub fn normalize_base(b: &str) -> String {
    let t = b.trim().trim_matches('/');
    if t.is_empty() {
        "/".into()
    } else {
        format!("/{t}/")
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let signer_sock = env("XBT_UI_SIGNER_SOCK").or_else(|| env("B2_SIGNER_SOCK")).map(PathBuf::from).unwrap_or_else(|| {
            env("B2_ROOT").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")).join(".run").join("signer.sock")
        });
        let data_dir = env("XBT_UI_DATA_DIR").map(PathBuf::from)
            .or_else(|| env("XBT_DATA_DIR").map(|d| PathBuf::from(d).join("ui")))
            .unwrap_or_else(|| PathBuf::from("xbt-wallet-ui"));
        let mut password = None;
        if let Some(f) = env("XBT_UI_PASSWORD_FILE") {
            password = Some(std::fs::read_to_string(&f).map_err(|e| format!("XBT_UI_PASSWORD_FILE {f}: {e}"))?.trim_end_matches(['\r', '\n']).to_string());
        } else if let Some(dir) = env("CREDENTIALS_DIRECTORY") {
            let p = PathBuf::from(dir).join("xbt-ui-password");
            if p.exists() {
                password = Some(std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?.trim_end_matches(['\r', '\n']).to_string());
            }
        }
        if let Some(p) = env("XBT_UI_PASSWORD") {
            std::env::remove_var("XBT_UI_PASSWORD");
            if password.is_none() {
                password = Some(p);
            }
        }
        if password.as_deref().is_some_and(|p| p.chars().count() < 8) {
            return Err("the configured UI password is shorter than 8 characters".into());
        }
        let secs = |k: &str, d: u64| env(k).and_then(|v| v.parse::<u64>().ok()).filter(|v| *v > 0).unwrap_or(d);
        let role = match env("XBT_UI_ROLE").as_deref() {
            None | Some("wallet") => Role::Wallet,
            Some("gateway") => Role::Gateway,
            Some(o) => return Err(format!("XBT_UI_ROLE {o}: wallet or gateway")),
        };
        let run_dir = |name: &str| env("XBT_DATA_DIR").map(|d| PathBuf::from(d).join("run").join(name)).unwrap_or_else(|| data_dir.join(name));
        let ln = LnSetup {
            dir: env("XBT_UI_LN_DIR").map(PathBuf::from).unwrap_or_else(|| run_dir("ln")),
            rest: env("XBT_UI_LN_REST"),
            tls_cert: env("XBT_UI_LN_TLS_CERT").map(PathBuf::from),
        };
        let gw = GatewaySetup {
            dir: env("XBT_UI_GW_DIR").map(PathBuf::from).unwrap_or_else(|| run_dir("gateway")),
            node_rest: env("XBT_UI_GW_NODE_REST"),
            node_tls_cert: env("XBT_UI_GW_NODE_TLS_CERT").map(PathBuf::from),
            state_dir: env("XBT_UI_GW_STATE_DIR").unwrap_or_else(|| "/data/gateway".into()),
            port: env("XBT_UI_GW_PORT").and_then(|p| p.parse().ok()).filter(|p| *p > 0).unwrap_or(8402),
            health_url: env("XBT_UI_GW_HEALTH_URL").filter(|u| u.starts_with("http://")),
            proxies: env("XBT_UI_GW_PROXIES").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
        };
        let secure_cookie = match env("XBT_UI_SECURE_COOKIE").as_deref() {
            Some("1") | Some("true") => Some(true),
            Some("0") | Some("false") => Some(false),
            _ => None,
        };
        Ok(Self {
            bind: env("XBT_UI_BIND").unwrap_or_else(|| "127.0.0.1:8480".into()),
            signer_sock,
            password,
            base_path: normalize_base(&env("XBT_UI_BASE_PATH").unwrap_or_default()),
            session_idle: Duration::from_secs(secs("XBT_UI_SESSION_IDLE_S", 900)),
            session_max: Duration::from_secs(secs("XBT_UI_SESSION_MAX_S", 28_800)),
            secure_cookie,
            allow_ips: env("XBT_UI_ALLOW_IPS").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
            allowed_hosts: env("XBT_UI_ALLOWED_HOSTS").map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
            setup_open: env("XBT_UI_SETUP_OPEN").as_deref() == Some("1"),
            cmp_url: env("XBT_UI_CMP_URL").filter(|u| u.starts_with("http://") || u.starts_with("https://") || u.starts_with('/')),
            cmp_status_url: env("XBT_UI_CMP_STATUS_URL"),
            mcp_urls: env("XBT_UI_MCP_URL").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
            mcp_token_file: env("XBT_UI_MCP_TOKEN_FILE").map(PathBuf::from)
                .or_else(|| env("XBT_DATA_DIR").map(|d| PathBuf::from(d).join("run").join("ui").join("mcp-http-token")))
                .unwrap_or_else(|| data_dir.join("secrets").join("mcp-http-token")),
            data_dir,
            threads: secs("XBT_UI_THREADS", 4) as usize,
            role,
            ln,
            gw,
        })
    }

    /// A test or embedding configuration.
    pub fn for_test(signer_sock: PathBuf, data_dir: PathBuf, bind: &str) -> Self {
        Self { bind: bind.into(), signer_sock, data_dir, password: None, base_path: "/".into(), session_idle: Duration::from_secs(900),
               session_max: Duration::from_secs(28_800), secure_cookie: None, allow_ips: vec![], allowed_hosts: vec![], setup_open: false, cmp_url: None,
               cmp_status_url: None, mcp_urls: vec![], mcp_token_file: PathBuf::from("/nonexistent/mcp-http-token"), threads: 4, role: Role::Wallet,
               ln: LnSetup::default(), gw: GatewaySetup { state_dir: "/data/gateway".into(), port: 8402, ..Default::default() } }
    }
}
