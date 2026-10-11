//! The xbt402 routing hub as a service: `xbt402-hub --config hub.json` (the config of B1's
//! `python -m xbt402.hub`).
//!
//! ```json
//! {"node": {"rpcport": 8332, "cookie": "~/.xbt/.cookie", "wallet": "hub", "host": "127.0.0.1"},
//!  "network": "bip122:...", "port": 9480, "bind": "127.0.0.1", "datadir": "~/xbt-hub",
//!  "pay_to_key_file": "~/.config/xbt-hub/payto.key",
//!  "connect": ["http://provider:port"], "hub": {HubConfig fields}, "watch_interval": 5, "threads": 16}
//! ```
//! The fund hook is the node wallet named in `node` (sendtoaddress; this never mines). The payTo
//! key file holds a hex secret and is never logged.
//!
//! `xbt402-hub --config hub.json --close-all`: the operator tool (the service stopped): ask every
//! provider with a signed ch2 to close it, print the closes as JSON, and exit.
//! `xbt402-hub healthcheck [--ready]`: GET our own `/healthz` (`/readyz`), the image's HEALTHCHECK.
//!
//! Container-ready (AGP-038, `docs/CONTAINER.md`): the config file is `--config`, `XBT_HUB_CONFIG`, or
//! `$XBT_DATA_DIR/hub/hub.json` when present, and may be absent: every field has an env override
//! (`XBT_NODE_RPC_HOST`, `XBT_NODE_RPC_PORT`, `XBT_HUB_WALLET`, `XBT_HUB_NETWORK` (else derived from the
//! node's anchor block), `XBT_HUB_BIND`, `XBT_HUB_PORT`, `XBT_HUB_DATADIR`, `XBT_HUB_CONNECT` (comma
//! separated), `XBT_HUB_JSON` (HubConfig fields), `XBT_HUB_WATCH_INTERVAL`, `XBT_HUB_THREADS`). Node
//! credentials: `node.cookie`, else the secret `node-rpc-auth` (`user:password`). The payTo key:
//! `pay_to_key_file`, else the secret `hub-payto-key` (generated 0600 on first run). The key that
//! seals the ch2 keys in the state file (AGP-073): `wrap_key_file`, else the secret `hub-wrap-key`
//! (generated likewise), else `<datadir>/hub-wrap-key`. Behind a proxy:
//! `XBT_BASE_PATH`, `XBT_PUBLIC_URL` (the 402's `resource.url` base), `XBT_TRUST_FORWARDED=1`
//! (`X-Forwarded-Proto/Host/Prefix`). `GET /healthz`: the process; `GET /readyz`: the node reachable
//! and synced. AGP-042: `/readyz` also reports the node wallet named `hub` (created and loaded on
//! start), a stable receive address, its balance, and an Umbrel Tor onion when `XBT_HUB_ONION` /
//! `APP_HIDDEN_SERVICE` is set.
//!
//! AGP-104:
//! * Start-up: the hub refuses a node that is not on XBT ([`xbt402::node_check`]: mainnet's block
//!   961,640 by its pinned hash, any other chain by the form of a block), waiting while the node
//!   is below that block, and refuses a configured `network` that is not the node's.
//! * Returns: every coin the hub gets back is paid to a fresh address of the node wallet (the
//!   remainder of a ch2, a refund, the sweep of a closed ch1).
//! * Funding states its fee rate: `node.fee_rate` / `XBT_HUB_FEE_RATE` (sat/vB), else the node's
//!   estimate for `node.fee_conf_target` blocks (default 6). With neither, nothing is funded and
//!   the error says so.
//! * `/readyz` is not ready while the wallet does not answer.
//! * `GET /status`: where the hub's coins are, as JSON; `GET /`: the same as a page.
//!   `XBT_HUB_STATUS=off` serves neither (they are on the hub's public port).
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::adaptor::Sc;
use xbt402::client::{Wallet, WalletSend};
use xbt402::error::ChannelError;
use xbt402::funding::ChainBackend;
use xbt402::http::{serve_service, HttpService, UreqTransport};
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::hub_keys::{WrapKey, WRAP_KEY_FILE};
use xbt402::provider::HttpResponse;
use xbt402::rpc::Rpc;
use xbt_svc::{env, env_bool, health, probe, proxy, DataDir, Mode, Secrets};

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(rest),
        None => PathBuf::from(p),
    }
}

fn die(msg: String) -> ! {
    eprintln!("xbt402-hub: {msg}");
    std::process::exit(2);
}

/// The config file (if any) with every env override applied.
fn load_config(args: &[String], data: Option<&DataDir>) -> Value {
    let path = args.iter().position(|a| a == "--config").and_then(|i| args.get(i + 1)).cloned().or_else(|| env("XBT_HUB_CONFIG"))
        .map(|p| expand(&p))
        .or_else(|| data.map(|d| d.component(xbt_svc::HUB).join("hub.json")).filter(|p| p.exists()));
    let mut conf = match &path {
        Some(p) => xbt402::json::parse(&std::fs::read_to_string(p).unwrap_or_else(|e| die(format!("config {}: {e}", p.display()))))
            .unwrap_or_else(|e| die(format!("config: {e}"))),
        None if data.is_some() => json!({}),
        None => die("usage: xbt402-hub --config hub.json [--close-all] | healthcheck [--ready] (or set XBT_DATA_DIR)".into()),
    };
    if !conf.get("node").is_some_and(Value::is_object) {
        conf["node"] = json!({});
    }
    let num = |k: &str| env(k).map(|v| env_number(&v).unwrap_or_else(|| die(format!("{k}={v}: not a number"))));
    for (k, slot) in [("XBT_NODE_RPC_HOST", "host"), ("XBT_HUB_WALLET", "wallet")] {
        if let Some(v) = env(k) {
            conf["node"][slot] = v.into();
        }
    }
    if let Some(v) = env("XBT_HUB_FEE_RATE") {
        conf["node"]["fee_rate"] = v.parse::<f64>().ok().filter(|r| r.is_finite() && *r > 0.0).map(Value::from)
            .unwrap_or_else(|| die(format!("XBT_HUB_FEE_RATE={v}: a fee rate in sat/vB")));
    }
    if let Some(v) = env("XBT_NODE_RPC_PORT") {
        conf["node"]["rpcport"] = v.parse::<u64>().map(Value::from).unwrap_or_else(|_| die(format!("XBT_NODE_RPC_PORT={v}")));
    }
    for (k, slot) in [("XBT_HUB_NETWORK", "network"), ("XBT_HUB_BIND", "bind"), ("XBT_HUB_DATADIR", "datadir")] {
        if let Some(v) = env(k) {
            conf[slot] = v.into();
        }
    }
    for (k, slot) in [("XBT_HUB_PORT", "port"), ("XBT_HUB_WATCH_INTERVAL", "watch_interval"), ("XBT_HUB_THREADS", "threads")] {
        if let Some(v) = num(k) {
            conf[slot] = v;
        }
    }
    if let Some(c) = env("XBT_HUB_CONNECT") {
        conf["connect"] = c.split(',').map(str::trim).filter(|s| !s.is_empty()).map(Value::from).collect::<Vec<_>>().into();
    }
    if let Some(h) = env("XBT_HUB_JSON") {
        let v = xbt402::json::parse(&h).unwrap_or_else(|e| die(format!("XBT_HUB_JSON: {e}")));
        let Value::Object(m) = v else { die("XBT_HUB_JSON: not a JSON object".into()) };
        if !conf.get("hub").is_some_and(Value::is_object) {
            conf["hub"] = json!({});
        }
        conf["hub"].as_object_mut().expect("object").extend(m);
    }
    if let Some(d) = data {
        let defaults = [("bind", json!("0.0.0.0")), ("port", json!(9480)),
                        ("datadir", json!(d.component(xbt_svc::HUB).join("state").to_string_lossy()))];
        for (k, v) in defaults {
            if conf.get(k).is_none_or(Value::is_null) {
                conf[k] = v;
            }
        }
    }
    conf
}

/// An env override's number: an integer stays an integer (`XBT_HUB_PORT=9480` must not become `9480.0`, and
/// `XBT_HUB_THREADS` is read with `as_u64`); anything else numeric is a float (`XBT_HUB_WATCH_INTERVAL=0.5`).
fn env_number(v: &str) -> Option<Value> {
    v.parse::<u64>().map(Value::from).ok().or_else(|| v.parse::<f64>().ok().filter(|f| f.is_finite()).map(Value::from))
}

/// The key that seals the ch2 keys in `ch2.json` (AGP-073 K1): `wrap_key_file`, else the secret
/// `hub-wrap-key` (generated 0600 on first run in a container), else `<datadir>/hub-wrap-key`.
fn wrap_key(conf: &Value, secrets: &Secrets, container: bool, datadir: &std::path::Path) -> WrapKey {
    if let Some(f) = conf.get("wrap_key_file").and_then(Value::as_str) {
        return WrapKey::load_or_create(&expand(f)).unwrap_or_else(|e| die(format!("wrap_key_file: {e}")));
    }
    let found = if container || env("XBT_SECRETS_DIR").is_some() {
        Some(secrets.get_or_create(WRAP_KEY_FILE, || xbt_svc::to_hex(&xbt_svc::random_bytes(32)).into_bytes()).unwrap_or_else(|e| die(e)))
    } else {
        secrets.get(WRAP_KEY_FILE).unwrap_or_else(|e| die(e))
    };
    match found {
        Some(s) => {
            eprintln!("xbt402-hub: ch2 wrap key from {}", s.origin);
            WrapKey::parse(&s.bytes).unwrap_or_else(|e| die(format!("{WRAP_KEY_FILE}: {e}")))
        }
        None => {
            let p = datadir.join(WRAP_KEY_FILE);
            eprintln!("xbt402-hub: ch2 wrap key {} (beside the state it seals: set wrap_key_file to keep it apart)", p.display());
            WrapKey::load_or_create(&p).unwrap_or_else(|e| die(format!("{e}")))
        }
    }
}

fn bind_addr(conf: &Value) -> String {
    format!("{}:{}", conf.get("bind").and_then(Value::as_str).unwrap_or("127.0.0.1"), conf["port"])
}

/// The node's RPC: `node.cookie`, else the secret `node-rpc-auth`.
fn node_rpc(conf: &Value, secrets: &Secrets) -> Rpc {
    let node = &conf["node"];
    let host = node.get("host").and_then(Value::as_str).unwrap_or("127.0.0.1");
    let url = format!("http://{host}:{}", node.get("rpcport").cloned().unwrap_or(json!(8332)));
    if let Some(c) = node.get("cookie").and_then(Value::as_str) {
        return Rpc::from_cookie(&url, &expand(c)).unwrap_or_else(|e| die(format!("node: {e}")));
    }
    let auth = secrets.get("node-rpc-auth").unwrap_or_else(|e| die(e))
        .unwrap_or_else(|| die("node: set node.cookie in the config or the secret node-rpc-auth (user:password)".into()));
    let text = auth.text().unwrap_or_else(|e| die(e));
    let (u, p) = text.split_once(':').unwrap_or_else(|| die(format!("node-rpc-auth ({}): expected user:password", auth.origin)));
    Rpc::new(&url, u, p)
}

/// The network id: from the node's anchor block (mainnet 961,640, regtest 101). A configured one
/// must be that (AGP-104: a hub would otherwise sign quotes for one network and fund channels on
/// another); on a chain with no anchor block the configured one is all there is.
fn network(conf: &Value, rpc: &Rpc) -> String {
    let set = conf.get("network").and_then(Value::as_str);
    let chain = rpc.call("getblockchaininfo", json!([])).unwrap_or_else(|e| die(format!("node: {e}")))["chain"].as_str().unwrap_or("").to_string();
    let height = match (chain.as_str(), set) {
        ("main", _) => 961_640,
        ("regtest", _) => 101,
        (_, Some(n)) => return n.to_string(),
        (c, None) => die(format!("chain {c:?}: set XBT_HUB_NETWORK")),
    };
    let hash = rpc.call("getblockhash", json!([height])).unwrap_or_else(|e| die(format!("node: anchor block {height}: {e}")));
    let id = xbt_primitives::network::network_id(hash.as_str().unwrap_or(""));
    match network_choice(set, &id) {
        Ok(n) => n,
        Err(e) => die(e),
    }
}

/// The node's network id, unless another one is configured.
fn network_choice(set: Option<&str>, node: &str) -> Result<String, String> {
    match set {
        Some(n) if n != node => Err(format!("network {n} is configured, and the node is on {node}: point the hub at the right node or remove the setting")),
        _ => Ok(node.to_string()),
    }
}

/// AGP-104: refuse a node that is not on XBT, before anything is served or funded
/// ([`xbt402::node_check`]). While the node is below the block the check needs (a node still
/// syncing), wait and say so: the hub has nothing to serve until then.
fn check_node_chain(rpc: &Rpc) {
    let mut said = 0u64;
    loop {
        let info = rpc.call("getblockchaininfo", json!([])).unwrap_or_else(|e| die(format!("node: {e}")));
        let (chain, blocks) = (info["chain"].as_str().unwrap_or("").to_string(), info["blocks"].as_u64().unwrap_or(0));
        let height = xbt402::node_check::check_height(&chain).map(u64::from).unwrap_or(blocks);
        if blocks < height {
            if said.is_multiple_of(20) {
                eprintln!("xbt402-hub: the node is at block {blocks}; waiting for block {height} to check that it is on XBT");
            }
            said += 1;
            std::thread::sleep(Duration::from_secs(15));
            continue;
        }
        let hash = rpc.call("getblockhash", json!([height])).unwrap_or_else(|e| die(format!("node: block {height}: {e}")));
        let hash = hash.as_str().unwrap_or("").to_string();
        let header = if chain == "main" { Value::Null } else { rpc.call("getblockheader", json!([hash, false])).unwrap_or_else(|e| die(format!("node: header {height}: {e}"))) };
        if let Err(e) = xbt402::node_check::check_chain(&chain, height as u32, &hash, header.as_str().unwrap_or("")) {
            die(format!("wrong chain: {e}"));
        }
        return;
    }
}

/// Whether `name` is already in `listwallets`.
fn wallet_is_loaded(loaded: &Value, name: &str) -> bool {
    loaded.as_array().is_some_and(|a| a.iter().any(|w| w.as_str() == Some(name)))
}

/// Create or load the node's wallet named `name` (the hub funds routes from it). AGP-104: with
/// `load_on_startup`, so a node that restarts loads it again (a wallet made over RPC is otherwise
/// left unloaded, and the hub would fund nothing until someone loaded it).
fn ensure_named_wallet(rpc: &Rpc, name: &str) -> Result<(), String> {
    let loaded = rpc.call("listwallets", json!([])).map_err(|e| e.to_string())?;
    if wallet_is_loaded(&loaded, name) {
        return Ok(());
    }
    match rpc.call("loadwallet", json!([name, true])) {
        Ok(_) => Ok(()),
        Err(e) => {
            let load_err = e.to_string();
            if load_err.contains("already loaded") {
                return Ok(());
            }
            match rpc.call("createwallet", json!({"wallet_name": name, "load_on_startup": true})) {
                Ok(_) => Ok(()),
                Err(ce) => {
                    let create_err = ce.to_string();
                    if create_err.contains("already exists") {
                        rpc.call("loadwallet", json!([name, true])).map(|_| ()).map_err(|e| e.to_string())
                    } else {
                        Err(format!("loadwallet: {load_err}; createwallet: {create_err}"))
                    }
                }
            }
        }
    }
}

fn funding_address(wallet: &Rpc) -> Result<String, String> {
    wallet.call("getnewaddress", json!(["funding", "bech32"])).map_err(|e| e.to_string())?
        .as_str().map(str::to_string).ok_or_else(|| "getnewaddress: not a string".into())
}

/// A stable receive address: the file if present, else `getnewaddress` and persist.
fn persist_receive_address(path: &std::path::Path, new_addr: impl FnOnce() -> Result<String, String>) -> Result<String, String> {
    if let Ok(a) = std::fs::read_to_string(path) {
        let a = a.trim().to_string();
        if !a.is_empty() {
            return Ok(a);
        }
    }
    let a = new_addr()?;
    if let Some(d) = path.parent() {
        xbt_svc::ensure_dir(d, 0o700).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    std::fs::write(path, format!("{a}\n")).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(a)
}

/// AGP-104: `loaded` is the wallet answering now. (It was also true whenever a receive address
/// was on file, so a wallet the node no longer had loaded still read as ready.)
fn wallet_status(wallet: &Rpc, name: &str, receive: Option<&str>) -> Value {
    let bal = wallet.call("getbalance", json!([])).map_err(|e| e.to_string())
        .and_then(|v| v.as_f64().and_then(|btc| xbt_primitives::amount::Amount::from_btc_f64(btc).ok()).map(|a| a.to_sat()).ok_or_else(|| "getbalance: not an amount".to_string()));
    json!({"name": name, "loaded": bal.is_ok(), "receive_address": receive, "balance_sats": bal.as_ref().ok(), "error": bal.as_ref().err()})
}

/// What the wallet holds, in sats: `getbalances`' trusted and pending coins of its own (a return
/// from a close is pending until it confirms, and is the hub's all the same).
fn wallet_sats(wallet: &Rpc) -> Result<u64, String> {
    let b = wallet.call("getbalances", json!([])).map_err(|e| e.to_string())?;
    let coin = |k: &str| b["mine"][k].as_f64().and_then(|v| xbt_primitives::amount::Amount::from_btc_f64(v).ok()).map(|a| a.to_sat());
    match (coin("trusted"), coin("untrusted_pending")) {
        (Some(t), p) => Ok(t.saturating_add(p.unwrap_or(0))),
        _ => Err("getbalances: no mine.trusted".into()),
    }
}

/// The node wallet as the hub's fund hook, with the fee rate stated on every funding (AGP-104).
/// Rule: a funding never leaves the rate to the wallet. `fee_rate` (sat/vB) when the operator set
/// one, else the node's estimate for `conf_target` blocks; with neither, nothing is funded.
struct NodeWallet {
    wallet: Rpc,
    fee_rate: Option<f64>,
    conf_target: u32,
}

impl NodeWallet {
    fn rate(&self) -> xbt402::Result<f64> {
        if let Some(r) = self.fee_rate {
            return Ok(r);
        }
        self.wallet.estimate_fee_rate(self.conf_target)?.ok_or_else(|| {
            ChannelError::new("no_fee_rate", format!("the node has no fee estimate for {} blocks (estimatesmartfee): set node.fee_rate or XBT_HUB_FEE_RATE (sat/vB), or wait until the node has seen enough blocks", self.conf_target))
        })
    }
}

impl Wallet for NodeWallet {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        self.wallet.fund_at(address, sats, self.rate()?)
    }

    fn preflight(&self) -> xbt402::Result<()> {
        self.rate().map(|_| ())
    }

    fn wallet_sends_to(&self, address: &str) -> xbt402::Result<Vec<String>> {
        self.wallet.wallet_sends_to(address)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> xbt402::Result<Option<WalletSend>> {
        self.wallet.wallet_send(txid, address)
    }

    fn send_fee(&self, txid: &str) -> xbt402::Result<Option<u64>> {
        self.wallet.send_fee(txid)
    }
}

/// The hub behind a reverse proxy: health endpoints, the base path, the public URL.
struct Front {
    hub: Arc<RouteHub>,
    rpc: Arc<Rpc>,
    wallet: Arc<Rpc>,
    wallet_name: String,
    receive_address: Option<String>,
    onion: Option<String>,
    base: String,
    public: Option<String>,
    trust_forwarded: bool,
    /// `/status` and the page at `/` are served (AGP-104; `XBT_HUB_STATUS=off` turns them off).
    status: bool,
}

impl Front {
    /// [`RouteHub::status`] with what this service knows beside it: the wallet, the hub's address.
    fn status_doc(&self) -> Value {
        let held = wallet_sats(&self.wallet);
        let mut v = self.hub.status(held.as_ref().ok().copied());
        v["wallet"] = json!({"name": self.wallet_name, "receiveAddress": self.receive_address, "error": held.err()});
        v["url"] = self.public.clone().into();
        v["tor"] = self.onion.clone().into();
        v["experimental"] = true.into();
        v
    }
}

fn json_resp(status: u16, v: Value) -> HttpResponse {
    HttpResponse::new(status, vec![("Content-Type".into(), "application/json".into())], v.to_string().into_bytes())
}

impl HttpService for Front {
    fn body_limit(&self, path: &str) -> usize {
        self.hub.body_limit(&proxy::strip_base(path, &self.base).unwrap_or_else(|| path.into()), None)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], _url: &str) -> HttpResponse {
        // with the base path (a proxy that keeps it) or without (one that strips it)
        let inner = proxy::strip_base(path, &self.base).unwrap_or_else(|| path.to_string());
        match (method, inner.split('?').next().unwrap_or("")) {
            ("GET" | "HEAD", "/healthz") => {
                // AGP-094: the process answers, and its watcher's last tick did not panic
                let watcher = self.hub.watch_health();
                let ok = watcher["ok"] == true;
                json_resp(if ok { 200 } else { 503 }, json!({"ok": ok, "service": "xbt402-hub", "watcher": watcher}))
            }
            ("GET" | "HEAD", "/readyz") => {
                let node = health::node_status(self.rpc.call("getblockchaininfo", json!([])).map_err(|e| e.to_string()));
                let wallet = wallet_status(&self.wallet, &self.wallet_name, self.receive_address.as_deref());
                let ok = ready(&node, &wallet);
                json_resp(if ok { 200 } else { 503 }, json!({"ok": ok, "service": "xbt402-hub", "node": node,
                                                             "pay_to": self.hub.pay_to(), "providers": self.hub.out_channels().len(),
                                                             "wallet": wallet, "tor": self.onion}))
            }
            ("GET" | "HEAD", "/status") if self.status => json_resp(200, self.status_doc()),
            ("GET" | "HEAD", "/" | "") if self.status => {
                HttpResponse::new(200, vec![("Content-Type".into(), "text/html; charset=utf-8".into()), ("Cache-Control".into(), "no-store".into()),
                                            ("Content-Security-Policy".into(), "default-src 'none'; style-src 'unsafe-inline'".into()),
                                            ("X-Frame-Options".into(), "DENY".into())],
                                  xbt402::status_page::render(&self.status_doc()).into_bytes())
            }
            _ => {
                let url = proxy::public_url(headers, path, &self.base, self.public.as_deref(), self.trust_forwarded);
                self.hub.serve(method, &inner, headers, body, &url, None)
            }
        }
    }
}

/// Ready: the node is reachable and synced, and the wallet the hub funds from answers (AGP-104:
/// without it the hub can quote and route over what it has, and can fund and return nothing).
fn ready(node: &Value, wallet: &Value) -> bool {
    node["reachable"] == true && node["synced"] == true && wallet["loaded"] == true
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = DataDir::from_env();
    let conf = load_config(&args, data.as_ref());
    let base = env("XBT_BASE_PATH").unwrap_or_default();
    if args.get(1).map(String::as_str) == Some("healthcheck") {
        let which = if args.iter().any(|a| a == "--ready") { "/readyz" } else { "/healthz" };
        match probe::get(&probe::local_addr(&bind_addr(&conf)), &format!("{}{which}", proxy::normalize_base(&base)), Duration::from_secs(5)) {
            Ok((200, b)) => {
                println!("{}", b.trim());
                return;
            }
            Ok((code, b)) => die(format!("{which} {code} {}", b.trim())),
            Err(e) => die(format!("{which}: {e}")),
        }
    }
    let mode = Mode::from_env().unwrap_or_else(|e| die(e));
    let secrets = Secrets::for_component(data.as_ref(), xbt_svc::HUB, mode);
    let rpc = node_rpc(&conf, &secrets);
    check_node_chain(&rpc);
    let wallet_name = conf["node"].get("wallet").and_then(Value::as_str).unwrap_or("hub").to_string();
    if let Err(e) = ensure_named_wallet(&rpc, &wallet_name) {
        eprintln!("xbt402-hub: wallet {wallet_name}: {e} (quotes and routing still work; funding and returns need this wallet, and /readyz says not ready)");
    }
    let wallet = rpc.wallet(&wallet_name);
    let returns = wallet.clone();
    let fee_rate = conf["node"].get("fee_rate").filter(|v| !v.is_null())
        .map(|v| v.as_f64().filter(|r| r.is_finite() && *r > 0.0).unwrap_or_else(|| die("node.fee_rate: a fee rate in sat/vB".into())));
    let conf_target = conf["node"].get("fee_conf_target").filter(|v| !v.is_null())
        .map(|v| v.as_u64().filter(|t| (1..=1008).contains(t)).unwrap_or_else(|| die("node.fee_conf_target: 1 to 1008 blocks".into())) as u32).unwrap_or(6);
    let fund = NodeWallet { wallet: wallet.clone(), fee_rate, conf_target };
    match fund.rate() {
        Ok(r) => eprintln!("xbt402-hub: fundings pay {r} sat/vB{}", if fee_rate.is_some() { " (set)" } else { " now (the node's estimate)" }),
        Err(e) => eprintln!("xbt402-hub: {e}: nothing is funded until then"),
    }
    let key = match conf.get("pay_to_key_file").and_then(Value::as_str) {
        Some(f) => std::fs::read_to_string(expand(f)).unwrap_or_else(|e| die(format!("pay_to_key_file: {e}"))),
        None => {
            let s = secrets.get_or_create("hub-payto-key", || {
                // a scalar in [1, n): 32 random bytes are one with overwhelming probability; retry otherwise
                loop {
                    let h = xbt_svc::to_hex(&xbt_svc::random_bytes(32));
                    if Sc::from_hex_mod_n(&h).and_then(|s| s.secret()).is_some() {
                        return h.into_bytes();
                    }
                }
            }).unwrap_or_else(|e| die(e));
            eprintln!("xbt402-hub: payTo key from {}", s.origin);
            s.text().unwrap_or_else(|e| die(e))
        }
    };
    let secret = Sc::from_hex_mod_n(key.trim()).and_then(|s| s.secret()).unwrap_or_else(|| die("pay_to_key_file: not a hex secret".into()));
    let cfg = HubConfig::from_json(conf.get("hub").unwrap_or(&json!({}))).unwrap_or_else(|e| die(format!("hub config: {e}")));
    let network = network(&conf, &rpc);
    let datadir = expand(conf["datadir"].as_str().unwrap_or_else(|| die("datadir".into())));
    if data.is_some() {
        xbt_svc::ensure_dir(&datadir, 0o700).unwrap_or_else(|e| die(format!("{}: {e}", datadir.display())));
    }
    let receive_address = persist_receive_address(&datadir.join("receive-address"), || funding_address(&wallet))
        .map_err(|e| { eprintln!("xbt402-hub: receive address: {e}"); e }).ok();
    if let Some(a) = &receive_address {
        eprintln!("xbt402-hub: fund the hub wallet '{wallet_name}' at {a}");
    }
    let wrap = wrap_key(&conf, &secrets, data.is_some(), &datadir);
    let rpc = Arc::new(rpc);
    let hub = RouteHub::new_with_wrap_key(rpc.clone(), rpc.clone(), Box::new(fund), Box::new(UreqTransport::default()), secret, &network,
                                          Some(&datadir), cfg, Some(wrap))
        .unwrap_or_else(|e| die(format!("{e}")));
    // AGP-104: every coin the hub gets back is paid to the hub's wallet: a ch2's remainder and its
    // refund (AGP-037), the sweep of a closed ch1. THE one place that names where returns go: a
    // later link to a Lightning wallet changes this hook. bech32, whatever the wallet's default
    // address type (a legacy default made every refund fail, AGP-044)
    hub.set_return_to(Some(Box::new(move || {
        returns.call("getnewaddress", json!(["", "bech32"]))?.as_str().map(str::to_string)
            .ok_or_else(|| ChannelError::new("rpc_error", "getnewaddress"))
    })));
    if args.iter().any(|a| a == "--close-all") {
        let mut closes = vec![];
        for (origin, oc) in hub.out_channels() {
            if oc.state != "open" {
                continue;
            }
            let rec = json!({"origin": origin, "chan": oc.params.channel_id(), "routed": oc.routed, "signed": oc.signed,
                             "params": oc.params.to_json()});
            match hub.close_ch2(&oc, false) {
                Ok(ev) => closes.push(json!({"close": ev, "ch2": rec})),
                Err(e) => closes.push(json!({"error": e.to_string(), "ch2": rec})),
            }
        }
        println!("{}", json!({"closes": closes, "events": *hub.events.lock().unwrap()}));
        return;
    }
    let hub = Arc::new(hub);
    for origin in conf.get("connect").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        if !hub.out_channels().contains_key(origin.trim_end_matches('/')) {
            if let Err(e) = hub.connect(origin, None, None) {
                eprintln!("hub: connect {origin}: {e}");
            }
        }
    }
    let _stop = hub.watch(Duration::from_secs_f64(conf.get("watch_interval").and_then(Value::as_f64).unwrap_or(5.0)));
    let bind = bind_addr(&conf);
    let threads = conf.get("threads").and_then(Value::as_u64).unwrap_or(16) as usize;
    let onion = env("XBT_HUB_ONION").or_else(|| env("APP_HIDDEN_SERVICE")).map(|h| {
        let h = h.trim().trim_end_matches('/');
        if h.starts_with("http://") || h.starts_with("https://") { h.to_string() } else { format!("http://{h}") }
    }).filter(|h| h.contains('.'));
    let wallet = Arc::new(wallet);
    let front = Arc::new(Front { hub: hub.clone(), rpc: rpc.clone(), wallet, wallet_name, receive_address, onion,
                                 base, public: env("XBT_PUBLIC_URL"), trust_forwarded: env_bool("XBT_TRUST_FORWARDED", false),
                                 status: env("XBT_HUB_STATUS").is_none_or(|v| !["off", "0", "false", "no"].contains(&v.trim().to_ascii_lowercase().as_str())) });
    let handles = serve_service(front, &bind, threads).unwrap_or_else(|e| die(format!("bind {bind}: {e}")));
    eprintln!("xbt402 hub {} on {bind} ({network})", hub.pay_to());
    eprintln!("xbt402 hub: EXPERIMENTAL - routing is not production-ready; do not route funds you cannot lose");
    for h in handles {
        let _ = h.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_numbers_keep_integers() {
        assert_eq!(bind_addr(&json!({"bind": "0.0.0.0", "port": env_number("9480").unwrap()})), "0.0.0.0:9480");
        assert_eq!(env_number("16").unwrap().as_u64(), Some(16));
        assert_eq!(env_number("0.5").unwrap().as_f64(), Some(0.5));
        assert!(env_number("x").is_none() && env_number("inf").is_none());
    }

    #[test]
    fn wallet_list_and_stable_receive_address() {
        assert!(wallet_is_loaded(&json!(["hub", "agent"]), "hub"));
        assert!(!wallet_is_loaded(&json!(["agent"]), "hub"));
        assert!(!wallet_is_loaded(&json!([]), "hub"));
        let t = std::env::temp_dir().join(format!("agp042-hub-addr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        let p = t.join("receive-address");
        let first = persist_receive_address(&p, || Ok("bcrt1qfirst".into())).unwrap();
        let again = persist_receive_address(&p, || Ok("bcrt1qsecond".into())).unwrap();
        assert_eq!((first.as_str(), again.as_str()), ("bcrt1qfirst", "bcrt1qfirst"));
        assert_eq!(std::fs::read_to_string(&p).unwrap().trim(), "bcrt1qfirst");
        // AGP-104: a wallet that does not answer is not loaded, whatever address is on file
        let st = wallet_status(&Rpc::new("http://127.0.0.1:1", "u", "p"), "hub", Some("bcrt1qfirst"));
        assert_eq!(st["name"], "hub");
        assert_eq!(st["receive_address"], "bcrt1qfirst");
        assert_eq!(st["loaded"], false);
        assert!(st["error"].is_string() && st["balance_sats"].is_null(), "{st}");
        let _ = std::fs::remove_dir_all(&t);
    }

    #[test]
    fn ready_needs_the_node_and_the_wallet() {
        let node = json!({"reachable": true, "synced": true});
        assert!(ready(&node, &json!({"loaded": true})));
        assert!(!ready(&node, &json!({"loaded": false, "receive_address": "bcrt1qfirst"})), "the wallet is missing");
        assert!(!ready(&json!({"reachable": true, "synced": false}), &json!({"loaded": true})));
        assert!(!ready(&json!({"reachable": false}), &json!({"loaded": true})));
    }

    #[test]
    fn a_funding_states_its_fee_rate_or_says_why_not() {
        // no node behind it: the estimate fails, and a set rate needs no node
        let w = Rpc::new("http://127.0.0.1:1", "u", "p");
        let set = NodeWallet { wallet: w.clone(), fee_rate: Some(2.5), conf_target: 6 };
        assert_eq!(set.rate().unwrap(), 2.5);
        assert!(set.preflight().is_ok());
        let unset = NodeWallet { wallet: w, fee_rate: None, conf_target: 6 };
        assert!(unset.preflight().is_err() && unset.fund("bcrt1qx", 1_000).is_err());
    }

    #[test]
    fn a_configured_network_must_be_the_nodes() {
        assert_eq!(network_choice(None, "bip122:aa").unwrap(), "bip122:aa");
        assert_eq!(network_choice(Some("bip122:aa"), "bip122:aa").unwrap(), "bip122:aa");
        let e = network_choice(Some("bip122:bb"), "bip122:aa").unwrap_err();
        assert!(e.contains("bip122:bb") && e.contains("bip122:aa"), "{e}");
    }
}
