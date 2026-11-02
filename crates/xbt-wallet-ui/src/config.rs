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
//! | `XBT_UI_SERVICES` | `<data dir>/services.json` | path of the services JSON Browse reads (a list of `{name, kind, seller, price_text, items}`); the Services page writes it |
//! | `XBT_UI_SELL` | `0` | `1`: the wallet's UI also has the Sell page (`/sell`), which sets up the gateway beside it (the `XBT_UI_GW_*` settings); the app is then branded Lightning Stream |
//! | `XBT_UI_SUGGESTED_SELLERS` | | sellers' addresses (`https://`) or shop keys (`npub1…`), comma-separated, the Sellers page and an empty Browse offer to add in one click. Nothing is fetched until the owner adds one |
//! | `XBT_UI_NOSTR_RELAYS` | | Nostr relays to read sellers' signed listings from (`wss://`, comma-separated), for Browse's Nostr page. Unset: no relay is ever asked |
//! | `XBT_UI_STREAM_RELAY` | our relay, `https://iroh.lazarus-xbt.xyz/` | the Stream relay a direct link falls back to last; the Stream relays page (Settings) keeps the owner's other choices in `<data dir>/relays.json` (`docs/RUN-A-RELAY.md`) |
//! | `XBT_UI_RELAY_DIR`, `XBT_UI_RELAY_STATUS` | | the package's own relay service: the folder it reads the owner's `relay.json` from, and its status file. Unset: the page offers no built-in relay |
//! | `XBT_UI_RELAY_UNAVAILABLE` | | why this platform can't run the built-in relay, shown instead of the switch |
//! | `XBT_UI_VPN_DIR` | `<data dir>/run/vpn` | the folder the VPN pages write `devices.json` and `exit.json` to, for the VPN service |
//! | `XBT_UI_VPN_STATUS_DIR` | `XBT_UI_VPN_DIR` | the folder the VPN service writes `endpoint.json`, `status.json` and `exit-status.json` to, for the pages |
//! | `XBT_UI_VPN_ENDPOINT` | | where devices reach this box's WireGuard endpoint (`host:port`), put in each device's config; unset: no devices can be added |
//! | `XBT_UI_RELAY_START_HINT` | | how to start the relay service, shown when it is switched on but isn't running |
//! | `XBT_UI_NWC_SOCK` | | the NWC wallet service's admin socket (`xbt-nwc`'s `NWC_ADMIN_SOCK`): the Connected apps page makes, lists and revokes NWC connections there |
//! | `XBT_UI_CONNECTOR` | `http://127.0.0.1:8480` | the connector a seller's web app opens through (`<connector>/visits`). That is also the connector's default listen address, and the UI's own default bind: on one machine set one of the two ports. |
//! | `XBT_UI_APP_PORTS` | | ports (comma-separated) a seller's own web page is served on, one origin each, when the owner opens it inside the app (docs/SELLER-APPS.md); empty: off. The browser must reach them on the same host as this page |
//! | `XBT_UI_PLATFORM_LOGIN` | | the host name of the platform's own login proxy (Umbrel: `<app id>_app_proxy_1`). A request from that peer is the owner's, already logged in by the platform: no app password is asked. Every other peer still needs the password. Set it only where no other app can take that name on the network: umbrelOS 2.0 runs no app-proxy container, so the Umbrel package leaves it unset |
//! | `XBT_UI_ENROLL_CODE_FILE` | | the signer's one-time enrolment code, where the signer writes a copy for the UI (`B2_ENROLL_CODE_COPY`): the setup page fills it in, so the owner reads no log |
//! | `XBT_UI_RESTART_HINT` | restart Lightning Stream from your Umbrel or StartOS dashboard | how the owner restarts the app on this platform, said where a signed change waits for a restart |
//! | `XBT_UI_LOCAL_SERVICES` | | services on this box the Sell page offers, `Name=http://host:port`, comma-separated, beside the ones it finds by their usual names |
//! | `XBT_UI_HASHER` | | the hasher service's control page (`http://…`): turns on Sell → Hashrate, renting out this box's miners |
//! | `XBT_UI_HASHER_SETTINGS` | `$XBT_DATA_DIR/run/hashrate/settings.json` | the settings file the Hashrate page writes and the hasher service reads |
//! | `XBT_UI_HASHER_SLICES` | | where the shop passes paid slices of work to the hasher service (`http://…`): the shop then sells them under `/hashrate/` |
//! | `XBT_UI_HASHER_TOKEN_FILE` | | the hasher service's control token (its `--control-token-file`) |
//! | `XBT_UI_HASHRENT` | | the renter service's control page (`http://…`): turns on Buy → Hashrate, renting other people's miners |
//! | `XBT_UI_HASHRENT_TOKEN_FILE` | | the renter service's control token |
//! | `XBT_UI_AI_ENDPOINT` | | the AI endpoint's address for programs on the owner's network (`http://umbrel.local:33540/v1`): turns on the AI page's address and keys |
//! | `XBT_UI_AI_SELLERS` | `$XBT_DATA_DIR/run/ai/sellers.json` | the AI sellers and the owner's pins and blocks, written by the AI page, read by the endpoint |
//! | `XBT_UI_CREDENTIALS` | `$XBT_DATA_DIR/run/ai/credentials.json` | the store of AI keys and local links (hashed secrets, limits, spend), shared with the connector |
//! | `XBT_UI_AI_STATE` | `$XBT_DATA_DIR/run/ai/state.json` | the endpoint's record of the sellers' health, shown on the AI page |
//! | `XBT_UI_RELAY_LINK_S` | `21600` (6 hours) | how long a link for the buyer's own player (VLC, mpv, a TV app) made on a Files service's page lives (60 s to 7 days) |
//! | `XBT_UI_FILES_DIR` | `<data dir>/files` | the folder a Files service shares (Sell, "Files"): the UI serves it to the shop's gateway only (`docs/FILES.md`) |
//! | `XBT_UI_FILES_ROOT_WORDS` | "the folder this box shares with the app" | what the Sell page calls `XBT_UI_FILES_ROOT` ("the Downloads folder in Umbrel's Files app") |
//! | `XBT_UI_FILES_ROOT` | unset | a folder the box shares with the app (Umbrel's Downloads, read-only): the owner chooses the shared folder under it on the Sell page, instead of `XBT_UI_FILES_DIR` |
//! | `XBT_UI_FILES_BIND` | `127.0.0.1:8486` | where the UI serves that folder; on a platform whose gateway runs in another container, the app's private network |
//! | `XBT_UI_FILES_UPSTREAM` | `http://<XBT_UI_FILES_BIND>` | how the gateway reaches the folder, as its container sees the UI |
//! | `XBT_UI_DATUM_GUIDE` | the project's guide | where a renter without a gateway is sent to set one up |
//! | `XBT_UI_DATUM_RPCURL` | | the XBT node's RPC address (`http://host:port`) as the bundled Stream Gateway reaches it. Set: the Hashrate page has the gateway's settings ("Your gateway") and writes its config. Unset: this install has no bundled gateway |
//! | `XBT_UI_DATUM_DIR` | `$XBT_DATA_DIR/run/datum` | where the Hashrate page writes the Stream Gateway's `config.json` (no secret in it) |
//! | `XBT_UI_DATUM_API_PORT` | `7152` | the Stream Gateway's API port, on 127.0.0.1 only (Linux: `7153`) |
//! | `XBT_UI_DATUM_GATEWAY_RUN_DIR` | `/data/run/datum` | that folder as the gateway's container sees it: its config names `rpc.cookie` there, which init writes |
//! | `XBT_UI_DATUM_GATEWAY_STATE_DIR` | `/data/datum` | the gateway's own folder as its container sees it: the blocks it submits are kept in `submitblocks/` |
use std::path::PathBuf;
use std::time::Duration;

/// How the owner restarts the app where the platform does not say (`XBT_UI_RESTART_HINT`).
pub const RESTART_HINT: &str = "restart Lightning Stream from your Umbrel or StartOS dashboard";

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
    /// `XBT_UI_CACHE_S` (default 3, 0 to turn it off): how long the signer's slow-changing reads
    /// (the node's state, balances, the rules) serve later pages ([`crate::link::SignerLink::keep`]).
    /// Zero also asks the renter for its offers on each Hashrate page instead of keeping them.
    pub read_cache: Duration,
    pub role: Role,
    pub ln: LnSetup,
    pub gw: GatewaySetup,
    /// `XBT_UI_SERVICES`: the services file, read on each Browse request. `None`:
    /// `services.json` in the data dir ([`Config::services_path`]).
    pub services_file: Option<PathBuf>,
    /// `XBT_UI_SELL=1`: the wallet's UI also sets up the gateway, on the Sell page.
    pub sell: bool,
    /// `XBT_UI_CONNECTOR`: base URL of the connector, no trailing slash required.
    pub connector: String,
    /// The ports sellers' own web pages are served on, one origin each (`XBT_UI_APP_PORTS`).
    pub app_ports: Vec<u16>,
    /// `XBT_UI_RELAY_LINK_S`: how long a link for the buyer's own player lives.
    pub relay_ttl: Duration,
    /// The folder a Files service shares, where the UI serves it, and how the gateway reaches it.
    pub files: FilesSetup,
    /// `XBT_UI_NWC_SOCK`: the NWC wallet service's admin socket, when the box runs it.
    pub nwc_sock: Option<PathBuf>,
    /// `XBT_UI_NOSTR_RELAYS`: where Browse's Nostr page reads listings; empty: it reads none.
    pub nostr_relays: Vec<String>,
    /// `XBT_UI_STREAM_RELAY`: the Stream relay a direct link falls back to last
    /// (`docs/RUN-A-RELAY.md`); ours by default.
    pub stream_relay: String,
    /// `XBT_UI_RELAY_DIR`: where the package's own relay service reads the owner's settings
    /// (`relay.json`) and writes its status (`XBT_UI_RELAY_STATUS`); unset: this box has no relay
    /// service.
    pub relay_dir: Option<PathBuf>,
    pub relay_status: Option<PathBuf>,
    /// `XBT_UI_RELAY_START_HINT`: how to start the relay service when it isn't running.
    pub relay_start_hint: Option<String>,
    /// `XBT_UI_RELAY_UNAVAILABLE`: why this platform can't run the relay, said on the page.
    pub relay_unavailable: Option<String>,
    /// `XBT_UI_SUGGESTED_SELLERS`: sellers offered to add in one click.
    pub suggested_sellers: Vec<String>,
    /// `XBT_UI_PLATFORM_LOGIN`: the platform's login proxy, whose requests need no app password.
    pub platform_login: Option<String>,
    /// `XBT_UI_ENROLL_CODE_FILE`: the signer's enrolment code, for the setup page.
    pub enroll_code_file: Option<PathBuf>,
    /// `XBT_UI_RESTART_HINT`: how the owner restarts the app on this platform.
    pub restart_hint: String,
    /// `XBT_UI_LOCAL_SERVICES`: services on this box to offer on the Sell page, (name, address).
    pub local_services: Vec<(String, String)>,
    /// Hashrate: the hasher's and the renter's services, when this box runs them.
    pub hash: HashSetup,
    /// The AI endpoint: the files the AI page writes and reads, and the address it shows.
    pub ai: AiSetup,
    pub vpn: VpnSetup,
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
    /// The owner pins the node's certificate on the Lightning page (`XBT_UI_LN_TLS_PIN=1`): for a
    /// platform that cannot mount the certificate alone, the page writes it to `tls_cert`.
    pub pin: bool,
    /// The node's own app grants this app its key when the owner approves a request there
    /// (`XBT_UI_LN_GRANT=1`: StartOS with Lightning Fork's grant-app-access); the page says so.
    pub grant: bool,
    /// The box has its node bake this app's keys once the owner has made the node's wallet
    /// (`XBT_UI_LN_AUTO=1`: Umbrel, `node-keys-bake`); with no key yet, the page says to make the wallet.
    pub auto: bool,
}

/// The gateway page: where it writes, and the node and paths as the gateway's container sees them.
#[derive(Debug, Clone, Default)]
pub struct GatewaySetup {
    pub dir: PathBuf,
    pub node_rest: Option<String>,
    pub node_tls_cert: Option<PathBuf>,
    /// As [`LnSetup::pin`], for the gateway's node certificate (`XBT_UI_GW_NODE_TLS_PIN=1`).
    pub node_pin: bool,
    pub state_dir: String,
    pub port: u16,
    pub health_url: Option<String>,
    pub proxies: Vec<String>,
}

impl GatewaySetup {
    /// The gateway's health (`health_url`), asked with the token this app wrote into the gateway's
    /// config: on Umbrel and StartOS the app reaches it over the app's private network, where the
    /// gateway answers its operator's view only to that token (loopback needs none). `None`: no URL.
    pub fn health(&self) -> Option<Result<(u16, String), String>> {
        let url = self.health_url.as_deref()?;
        let token = std::fs::read_to_string(self.dir.join(crate::setup::GW_CONFIG)).ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| v.get("health_token").and_then(|t| t.as_str()).map(str::to_string));
        Some(match token {
            Some(t) => crate::app::http_get_with(url, &[("X-Xbt402-Health-Token", &t)]),
            None => crate::app::http_get(url),
        })
    }
}

/// The folder a Files service shares (`docs/FILES.md`).
#[derive(Debug, Clone, Default)]
pub struct FilesSetup {
    /// `XBT_UI_FILES_DIR`: the shared folder, when the owner has no folder to choose from ([`Self::root`] unset).
    pub dir: PathBuf,
    /// `XBT_UI_FILES_ROOT`: a folder the box shares with the app (Umbrel's Downloads, mounted read-only),
    /// under which the owner chooses the shared folder on the Sell page ([`crate::files::shared_dir`]).
    pub root: Option<PathBuf>,
    /// Where that choice is kept (`<data dir>/files-folder`): a path relative to [`Self::root`].
    pub choice: PathBuf,
    /// `XBT_UI_FILES_ROOT_WORDS`: what the owner calls [`Self::root`] ("the Downloads folder in Umbrel's Files app").
    pub root_words: String,
    /// `XBT_UI_FILES_BIND`: where the UI serves it (`127.0.0.1:0` in tests: any free port).
    pub bind: String,
    /// `XBT_UI_FILES_UPSTREAM`: how the gateway reaches it. Empty: the address the UI bound.
    pub upstream: String,
}

/// The AI endpoint the connector serves (`LS_AI_LISTEN`), as the AI page sees it.
#[derive(Debug, Clone, Default)]
pub struct AiSetup {
    /// `XBT_UI_AI_ENDPOINT`: the address programs on the owner's network use (`http://umbrel.local:33540/v1`).
    /// Unset: the box does not serve it, and the AI page says so.
    pub endpoint: Option<String>,
    /// `XBT_UI_AI_SELLERS`: the sellers file the page writes and the endpoint reads.
    pub sellers: PathBuf,
    /// `XBT_UI_CREDENTIALS`: the store of AI keys and local links.
    pub credentials: PathBuf,
    /// `XBT_UI_AI_STATE`: the endpoint's record of the sellers' health (read only here).
    pub state: PathBuf,
}

/// VPN exits: the buyer's devices and policies, and this box's own exit if its owner offers one.
#[derive(Debug, Clone, Default)]
pub struct VpnSetup {
    /// `XBT_UI_VPN_DIR`: the files the VPN pages write (devices, exit settings), which the VPN service
    /// reads.
    pub dir: PathBuf,
    /// `XBT_UI_VPN_STATUS_DIR`: the files the VPN service writes (its WireGuard key's public half, its
    /// status), which the pages read. Unset: the same dir as `XBT_UI_VPN_DIR`.
    pub status_dir: PathBuf,
    /// `XBT_UI_VPN_ENDPOINT`: where devices reach this box's WireGuard endpoint (`192.168.1.20:51830`),
    /// put in each device's config. Unset: the box does not run the buyer's VPN, and the page says so.
    pub endpoint: Option<String>,
    /// `XBT_UI_VPN_TUNNEL_UPSTREAM`: where the shop's gateway reaches the VPN service's tunnel endpoint
    /// (`http://vpn:51880`), to sell this box's exit. Unset: the exit can't be sold from this install.
    pub tunnel_upstream: Option<String>,
}

/// Renting out this box's miners (the hasher service) and renting other people's (the renter).
#[derive(Debug, Clone, Default)]
pub struct HashSetup {
    pub hasher: Option<String>,
    pub settings: PathBuf,
    pub slices: Option<String>,
    pub hasher_token: Option<PathBuf>,
    pub renter: Option<String>,
    pub renter_token: Option<PathBuf>,
    pub datum_guide: String,
    /// The Stream Gateway (DATUM-compatible) that comes with the app, when this install has it.
    pub stream_gw: StreamGwSetup,
}

/// The bundled Stream Gateway's settings: where its config goes, and what goes in it besides the owner's choices.
#[derive(Debug, Clone)]
pub struct StreamGwSetup {
    /// The node's RPC URL as the gateway reaches it; `None`: no bundled gateway in this install.
    pub rpcurl: Option<String>,
    /// Where the UI writes `config.json`.
    pub dir: PathBuf,
    pub api_port: u16,
    pub stratum_port: u16,
    /// `dir` and the gateway's own folder, as the gateway's container sees them.
    pub gateway_run_dir: String,
    pub gateway_state_dir: String,
}

impl Default for StreamGwSetup {
    fn default() -> Self {
        Self { rpcurl: None, dir: PathBuf::from("/nonexistent/run/datum"), api_port: 7152, stratum_port: 23339,
               gateway_run_dir: "/data/run/datum".into(), gateway_state_dir: "/data/datum".into() }
    }
}

/// The guide a renter is sent to about gateways.
pub const DATUM_GUIDE: &str = "https://github.com/AwokenLazarus/Lightning-Stream/blob/main/docs/P2P-HASH-TRY-IT.md#your-gateway";

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The relays of `XBT_UI_NOSTR_RELAYS`: each a `wss://` URL (`ws://` only to this machine), at most ten.
pub fn nostr_relays(v: Option<&str>) -> Result<Vec<String>, String> {
    let list: Vec<String> = v.unwrap_or("").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if list.len() > 10 {
        return Err("XBT_UI_NOSTR_RELAYS: at most 10 relays".into());
    }
    for r in &list {
        xbt_nostr::ws::parse_url(r).map_err(|e| format!("XBT_UI_NOSTR_RELAYS {r}: {e}"))?;
    }
    Ok(list)
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
        let files_default = data_dir.join("files");
        let files_choice = data_dir.join("files-folder");
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
        let datum_dir = env("XBT_UI_DATUM_DIR").map(PathBuf::from).unwrap_or_else(|| run_dir("datum"));
        let ln = LnSetup {
            dir: env("XBT_UI_LN_DIR").map(PathBuf::from).unwrap_or_else(|| run_dir("ln")),
            rest: env("XBT_UI_LN_REST"),
            tls_cert: env("XBT_UI_LN_TLS_CERT").map(PathBuf::from),
            pin: env("XBT_UI_LN_TLS_PIN").as_deref() == Some("1"),
            grant: env("XBT_UI_LN_GRANT").as_deref() == Some("1"),
            auto: env("XBT_UI_LN_AUTO").as_deref() == Some("1"),
        };
        let gw = GatewaySetup {
            dir: env("XBT_UI_GW_DIR").map(PathBuf::from).unwrap_or_else(|| run_dir("gateway")),
            node_rest: env("XBT_UI_GW_NODE_REST"),
            node_tls_cert: env("XBT_UI_GW_NODE_TLS_CERT").map(PathBuf::from),
            node_pin: env("XBT_UI_GW_NODE_TLS_PIN").as_deref() == Some("1"),
            state_dir: env("XBT_UI_GW_STATE_DIR").unwrap_or_else(|| "/data/gateway".into()),
            port: env("XBT_UI_GW_PORT").and_then(|p| p.parse().ok()).filter(|p| *p > 0).unwrap_or(8402),
            health_url: env("XBT_UI_GW_HEALTH_URL").filter(|u| u.starts_with("http://")),
            proxies: env("XBT_UI_GW_PROXIES").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
        };
        let ai = AiSetup {
            endpoint: env("XBT_UI_AI_ENDPOINT").filter(|u| u.starts_with("http://") || u.starts_with("https://")),
            sellers: env("XBT_UI_AI_SELLERS").map(PathBuf::from).unwrap_or_else(|| run_dir("ai").join("sellers.json")),
            credentials: env("XBT_UI_CREDENTIALS").map(PathBuf::from).unwrap_or_else(|| run_dir("ai").join("credentials.json")),
            state: env("XBT_UI_AI_STATE").map(PathBuf::from).unwrap_or_else(|| run_dir("ai").join("state.json")),
        };
        let vpn_dir = env("XBT_UI_VPN_DIR").map(PathBuf::from).unwrap_or_else(|| run_dir("vpn"));
        let vpn = VpnSetup {
            status_dir: env("XBT_UI_VPN_STATUS_DIR").map(PathBuf::from).unwrap_or_else(|| vpn_dir.clone()),
            dir: vpn_dir,
            endpoint: env("XBT_UI_VPN_ENDPOINT").filter(|e| !e.is_empty()),
            tunnel_upstream: env("XBT_UI_VPN_TUNNEL_UPSTREAM").filter(|u| u.starts_with("http://")),
        };
        let hash_settings = env("XBT_UI_HASHER_SETTINGS").map(PathBuf::from).unwrap_or_else(|| run_dir("hashrate").join("settings.json"));
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
            read_cache: Duration::from_secs(env("XBT_UI_CACHE_S").and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(3).min(60)),
            role,
            ln,
            gw,
            services_file: env("XBT_UI_SERVICES").map(PathBuf::from),
            sell: env("XBT_UI_SELL").as_deref() == Some("1"),
            connector: env("XBT_UI_CONNECTOR").unwrap_or_else(|| "http://127.0.0.1:8480".into()),
            app_ports: env("XBT_UI_APP_PORTS").map(|v| v.split(',').filter_map(|p| p.trim().parse::<u16>().ok()).filter(|p| *p > 0).take(16).collect())
                .unwrap_or_default(),
            relay_ttl: Duration::from_secs(secs("XBT_UI_RELAY_LINK_S", 6 * 3600).clamp(60, 7 * 86_400)),
            files: {
                let bind = env("XBT_UI_FILES_BIND").unwrap_or_else(|| "127.0.0.1:8486".into());
                FilesSetup { dir: env("XBT_UI_FILES_DIR").map(PathBuf::from).unwrap_or_else(|| files_default.clone()),
                             root: env("XBT_UI_FILES_ROOT").filter(|s| !s.trim().is_empty()).map(PathBuf::from),
                             choice: files_choice,
                             root_words: env("XBT_UI_FILES_ROOT_WORDS").filter(|s| !s.trim().is_empty())
                                 .unwrap_or_else(|| "the folder this box shares with the app".into()),
                             upstream: env("XBT_UI_FILES_UPSTREAM").unwrap_or_else(|| format!("http://{bind}")), bind }
            },
            nwc_sock: env("XBT_UI_NWC_SOCK").map(PathBuf::from),
            nostr_relays: nostr_relays(env("XBT_UI_NOSTR_RELAYS").as_deref())?,
            relay_dir: env("XBT_UI_RELAY_DIR").map(PathBuf::from),
            relay_status: env("XBT_UI_RELAY_STATUS").map(PathBuf::from),
            relay_unavailable: env("XBT_UI_RELAY_UNAVAILABLE").filter(|s| !s.trim().is_empty()),
            relay_start_hint: env("XBT_UI_RELAY_START_HINT").filter(|s| !s.trim().is_empty()),
            stream_relay: match env("XBT_UI_STREAM_RELAY") {
                Some(u) => xbt_nostr::relays::canonical_relay(&u).map_err(|e| format!("XBT_UI_STREAM_RELAY: {e}"))?,
                None => crate::relaynet::DEFAULT_RELAY.to_string(),
            },
            suggested_sellers: env("XBT_UI_SUGGESTED_SELLERS").map(|v| v.split(',').map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| suggested_seller_ok(s)).take(10).collect()).unwrap_or_default(),
            platform_login: env("XBT_UI_PLATFORM_LOGIN").filter(|h| h.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))),
            enroll_code_file: env("XBT_UI_ENROLL_CODE_FILE").map(PathBuf::from),
            restart_hint: env("XBT_UI_RESTART_HINT").map(|h| h.chars().take(300).collect()).unwrap_or_else(|| RESTART_HINT.into()),
            local_services: env("XBT_UI_LOCAL_SERVICES").map(|v| v.split(',').filter_map(|e| {
                let (n, u) = e.split_once('=')?;
                let (n, u) = (n.trim(), u.trim().trim_end_matches('/'));
                (!n.is_empty() && u.starts_with("http://")).then(|| (n.to_string(), u.to_string()))
            }).take(20).collect()).unwrap_or_default(),
            ai,
            vpn,
            hash: HashSetup {
                hasher: env("XBT_UI_HASHER").filter(|u| u.starts_with("http://")),
                settings: hash_settings,
                slices: env("XBT_UI_HASHER_SLICES").filter(|u| u.starts_with("http://")),
                hasher_token: env("XBT_UI_HASHER_TOKEN_FILE").map(PathBuf::from),
                renter: env("XBT_UI_HASHRENT").filter(|u| u.starts_with("http://")),
                renter_token: env("XBT_UI_HASHRENT_TOKEN_FILE").map(PathBuf::from),
                datum_guide: env("XBT_UI_DATUM_GUIDE").filter(|u| u.starts_with("https://")).unwrap_or_else(|| DATUM_GUIDE.into()),
                stream_gw: StreamGwSetup {
                    rpcurl: match env("XBT_UI_DATUM_RPCURL") {
                        Some(u) if u.starts_with("http://") && u.len() > 7 => Some(u.trim_end_matches('/').to_string()),
                        Some(_) => return Err("XBT_UI_DATUM_RPCURL: the node's RPC address, http://host:port".into()),
                        None => None,
                    },
                    dir: datum_dir,
                    api_port: match env("XBT_UI_DATUM_API_PORT") {
                        Some(p) => p.parse().ok().filter(|p| *p > 0).ok_or("XBT_UI_DATUM_API_PORT: a port")?,
                        None => 7152,
                    },
                    stratum_port: 23339,
                    gateway_run_dir: env("XBT_UI_DATUM_GATEWAY_RUN_DIR").unwrap_or_else(|| "/data/run/datum".into()),
                    gateway_state_dir: env("XBT_UI_DATUM_GATEWAY_STATE_DIR").unwrap_or_else(|| "/data/datum".into()),
                },
            },
        })
    }

    /// The services file: `XBT_UI_SERVICES`, else `services.json` in the data dir.
    pub fn services_path(&self) -> PathBuf {
        self.services_file.clone().unwrap_or_else(|| self.data_dir.join("services.json"))
    }

    /// The shops without a web address the owner added: `shops.json` beside the services file.
    pub fn shops_path(&self) -> PathBuf {
        // where the connector and the MCP read it too, to hand a shop's transport document to the
        // signer (XBT_SHOPS_FILE): that file when it is set, else run/shops under the platform's data
        // directory, else beside the services file
        if let Some(f) = std::env::var_os("XBT_SHOPS_FILE") {
            return PathBuf::from(f);
        }
        match std::env::var_os("XBT_DATA_DIR") {
            Some(d) => PathBuf::from(d).join("run").join("shops").join("shops.json"),
            None => self.services_path().with_file_name("shops.json"),
        }
    }

    /// A test or embedding configuration.
    pub fn for_test(signer_sock: PathBuf, data_dir: PathBuf, bind: &str) -> Self {
        let files_dir = data_dir.join("files");
        let files_choice = data_dir.join("files-folder");
        Self { bind: bind.into(), signer_sock, data_dir, password: None, base_path: "/".into(), session_idle: Duration::from_secs(900),
               session_max: Duration::from_secs(28_800), secure_cookie: None, allow_ips: vec![], allowed_hosts: vec![], setup_open: false, cmp_url: None,
               cmp_status_url: None, mcp_urls: vec![], mcp_token_file: PathBuf::from("/nonexistent/mcp-http-token"), threads: 4,
               read_cache: Duration::ZERO, role: Role::Wallet,
               ln: LnSetup::default(), gw: GatewaySetup { state_dir: "/data/gateway".into(), port: 8402, ..Default::default() },
               services_file: None, sell: false, connector: "http://127.0.0.1:8480".into(), app_ports: vec![],
               relay_ttl: Duration::from_secs(6 * 3600),
               files: FilesSetup { dir: files_dir, bind: "127.0.0.1:0".into(), choice: files_choice, ..Default::default() },
               nwc_sock: None, nostr_relays: vec![], stream_relay: crate::relaynet::DEFAULT_RELAY.to_string(), relay_dir: None, relay_status: None,
               relay_unavailable: None, relay_start_hint: None, suggested_sellers: vec![], platform_login: None, enroll_code_file: None,
               restart_hint: RESTART_HINT.into(), local_services: vec![],
               ai: AiSetup { endpoint: None, sellers: PathBuf::from("/nonexistent/ai/sellers.json"), credentials: PathBuf::from("/nonexistent/ai/credentials.json"),
                             state: PathBuf::from("/nonexistent/ai/state.json") },
               vpn: VpnSetup { dir: PathBuf::from("/nonexistent/vpn"), status_dir: PathBuf::from("/nonexistent/vpn"), endpoint: None, tunnel_upstream: None },
               hash: HashSetup { settings: PathBuf::from("/nonexistent/hashrate/settings.json"), datum_guide: DATUM_GUIDE.into(), ..Default::default() } }
    }
}

/// Whether a `XBT_UI_SUGGESTED_SELLERS` entry is one the Sellers page can add: a web address, or a shop
/// key (`npub1…`) that is a valid one.
pub(crate) fn suggested_seller_ok(s: &str) -> bool {
    xbt402::shop::parse(s).is_some_and(|o| crate::services::http_origin(&o).is_some())
}

#[cfg(test)]
mod suggested_seller_tests {
    #[test]
    fn a_suggested_seller_may_be_a_web_address_or_a_valid_shop_key() {
        assert!(super::suggested_seller_ok("https://shop.example.com"));
        assert!(super::suggested_seller_ok("npub1kqdrfmfg6mg52sy3ehu4vv7m3fjpa0830rhjdmvqrf09u3t3724q8cwr6a"));
        // one wrong letter, or not an address at all
        assert!(!super::suggested_seller_ok("npub1kqdrfmfg6mg52sy3ehu4vv7m3fjpa0830rhjdmvqrf09u3t3724q8cwr6b"));
        assert!(!super::suggested_seller_ok("not a seller"));
    }
}

#[cfg(test)]
mod health_token_tests {
    use super::GatewaySetup;
    use std::io::{Read, Write};

    /// A gateway stand-in that, like the real one from another container, answers its health
    /// only to the token: 200 with it, 404 without.
    fn gateway(token: &'static str) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().take(4) {
                let mut s = s.unwrap();
                let mut b = [0u8; 4096];
                let n = s.read(&mut b).unwrap_or(0);
                let req = String::from_utf8_lossy(&b[..n]).to_ascii_lowercase();
                let ok = req.contains(&format!("x-xbt402-health-token: {}", token.to_ascii_lowercase()));
                let status = if ok { "200 OK" } else { "404 Not Found" };
                let _ = s.write_all(format!("HTTP/1.0 {status}\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes());
            }
        });
        format!("http://{addr}/x402/ticket/health")
    }

    #[test]
    fn the_app_reads_its_gateways_health_with_the_token_it_wrote() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
        let dir = tempfile::tempdir().unwrap();
        let gw = GatewaySetup { dir: dir.path().into(), health_url: Some(gateway(TOKEN)), ..Default::default() };
        // no token written yet: the gateway's operator view is closed to another container
        assert_eq!(gw.health().unwrap().unwrap().0, 404);
        std::fs::write(dir.path().join(crate::setup::GW_CONFIG), format!(r#"{{"health_token":"{TOKEN}"}}"#)).unwrap();
        assert_eq!(gw.health().unwrap().unwrap().0, 200);
    }

    #[test]
    fn a_gateway_config_keeps_its_health_token_and_gets_one_when_new() {
        let mut fresh = serde_json::Map::new();
        crate::setup::keep_health_token(&mut fresh, None);
        let made = fresh["health_token"].as_str().unwrap().to_string();
        assert!(made.len() >= 32 && made.chars().all(|c| c.is_ascii_hexdigit()));
        // rewriting the config (a new form, or Sell's rebuild) keeps the token the gateway already has
        let mut next = serde_json::Map::new();
        crate::setup::keep_health_token(&mut next, Some(&serde_json::Value::Object(fresh)));
        assert_eq!(next["health_token"].as_str(), Some(made.as_str()));
    }
}
