//! The runner's one config file (JSON): where to listen, the service behind the gateway, the node,
//! the ticket terms, the caps, and a price per route. Every key is known or the file is refused: a
//! misspelled cap must not silently be the default.
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Map, Value};
use xbt402::ticket::{MIN_TICKET_BLOCKS, SESSION_PATH, SETTLE_MARGIN_BLOCKS};

use crate::book::Caps;
use crate::price::Price;
use crate::Error;

/// The node adds this many blocks to a ticket's final CLTV delta when it pays.
pub const PAYER_PAD_BLOCKS: u32 = 3;
/// The most HTLCs one channel holds: a seller with one channel can hold no more tickets than this.
pub const CHANNEL_SLOTS: u32 = 483;
/// The most unreleased tickets any config may allow: each has a thread and a connection to the node.
pub const MAX_HELD: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// The secret comes with the request: the buyer risks one ticket, the seller nothing.
    WithRequest,
    /// A checkable route: a piece is served on a pledged ticket and its secret follows. The seller
    /// risks up to one ticket per session.
    AfterVerify,
}

impl Release {
    pub fn name(self) -> &'static str {
        match self {
            Self::WithRequest => "with-request",
            Self::AfterVerify => "after-verify",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// A path ending in `/` covers everything under it; any other path is that path alone.
    pub path: String,
    /// Upper case.
    pub methods: Vec<String>,
    /// Served without payment.
    pub free: bool,
    pub price: Price,
    pub release: Release,
    /// Request headers passed to the service beside [`ALWAYS_FORWARDED`], lower case.
    pub forward_headers: Vec<String>,
    /// The largest request body passed on.
    pub max_body: usize,
}

/// Request headers every route passes on: they select what is returned and carry no authority.
pub const ALWAYS_FORWARDED: [&str; 7] = [
    "accept",
    "accept-language",
    "content-type",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "range",
];

/// Request headers no route passes on, whatever the file says: the gateway's own, the payment, and
/// the ones a proxy must not relay.
pub const NEVER_FORWARDED: [&str; 17] = [
    "accept-encoding",
    "connection",
    "content-length",
    "expect",
    "forwarded",
    "host",
    "keep-alive",
    "payment-signature",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
    "x-forwarded-for",
    "x-forwarded-proto",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub rest: String,
    pub tls_cert: Option<PathBuf>,
    /// `invoices:read` and `invoices:write`.
    pub macaroon: PathBuf,
    /// `info:read`: the block height.
    pub info_macaroon: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: String,
    /// The origin buyers reach the gateway under (`https://seller.example`): what a payment binds.
    pub public_url: String,
    /// The service: `http://host:port`, optionally with a path prefix.
    pub upstream: String,
    pub state_dir: PathBuf,
    /// `main`, or another chain's name with `network` given.
    pub chain: String,
    /// `lightning:<32 hex>`.
    pub network: String,
    pub node: NodeConfig,
    pub ticket_blocks: u32,
    pub caps: Caps,
    pub routes: Vec<Route>,
    pub http: Http,
    pub times: Times,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http {
    pub connections: usize,
    pub per_address: usize,
    pub threads: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Times {
    /// A metered response with no balance left waits this long for a release, then ends.
    pub refill_wait: Duration,
    /// The service must start its answer, and then keep sending, within this.
    pub upstream_wait: Duration,
    /// A block height older than this is not a height.
    pub height_max_age: Duration,
    /// The longest one response may stay open.
    pub max_response: Duration,
    /// How often the janitor runs: the height, the sweep, the journal's sync.
    pub tick: Duration,
}

impl Config {
    pub fn mainnet(&self) -> bool {
        self.chain == "main"
    }

    /// The route for a decoded path: the longest matching one.
    pub fn route(&self, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|r| {
                if r.path.ends_with('/') {
                    path.starts_with(&r.path)
                } else {
                    path == r.path
                }
            })
            .max_by_key(|r| r.path.len())
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        Self::from_json(&v)
    }

    pub fn from_json(v: &Value) -> Result<Self, Error> {
        Self::parse(v).map_err(Error::Config)
    }

    fn parse(v: &Value) -> Result<Self, String> {
        let top = obj(
            v,
            "the config",
            &[
                "listen",
                "public_url",
                "upstream",
                "state_dir",
                "chain",
                "network",
                "node",
                "tickets",
                "caps",
                "routes",
                "http",
                "times",
            ],
        )?;
        let chain = opt_str(top, "chain")?.unwrap_or("main").to_string();
        let network = match (chain.as_str(), opt_str(top, "network")?) {
            ("main", None) => xbt402::ticket::network_id(xbt_primitives::network::XBT_MAINNET)
                .ok_or("no mainnet network id")?,
            ("main", Some(_)) => return Err("network is fixed on chain main: leave it out".into()),
            (_, Some(n))
                if n.strip_prefix("lightning:").is_some_and(|id| {
                    id.len() == 32
                        && id
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                }) =>
            {
                n.to_string()
            }
            _ => return Err(
                "a chain other than main needs network: \"lightning:<32 hex of its bip122 id>\""
                    .into(),
            ),
        };
        let public_url = req_str(top, "public_url")?
            .trim_end_matches('/')
            .to_string();
        let origin =
            xbt402::wire::sendable_url(&public_url).map_err(|e| format!("public_url: {e}"))?;
        if xbt402::wire::request_url(&origin).target != "/" {
            return Err("public_url is an origin (scheme://host[:port]), without a path".into());
        }
        let upstream = req_str(top, "upstream")?.trim_end_matches('/').to_string();
        let up = xbt402::wire::sendable_url(&upstream).map_err(|e| format!("upstream: {e}"))?;
        if !up.starts_with("http://") || up.contains('?') || up.contains('@') {
            return Err("upstream is http://host[:port][/prefix]: plain HTTP to a service beside the gateway, no query, no user name".into());
        }

        let n = obj(
            top.get("node").ok_or("node is missing")?,
            "node",
            &["rest", "tls_cert", "macaroon", "info_macaroon"],
        )?;
        let node = NodeConfig {
            rest: req_str(n, "rest")?.to_string(),
            tls_cert: opt_str(n, "tls_cert")?.map(PathBuf::from),
            macaroon: PathBuf::from(req_str(n, "macaroon")?),
            info_macaroon: PathBuf::from(req_str(n, "info_macaroon")?),
        };

        let empty = Map::new();
        let t = match top.get("tickets") {
            Some(t) => obj(
                t,
                "tickets",
                &["ticket_msat", "max_tickets", "ticket_blocks"],
            )?,
            None => &empty,
        };
        let ticket_msat = num(t, "ticket_msat", 1_000_000)?;
        let max_tickets = num32(t, "max_tickets", 8)?;
        let ticket_blocks = num32(t, "ticket_blocks", 40)?;
        if !(1000..=100_000_000_000).contains(&ticket_msat) {
            return Err("tickets.ticket_msat is from 1000 (a node takes nothing below 1 sat) to 100000000000".into());
        }
        if !(1..=CHANNEL_SLOTS).contains(&max_tickets) {
            return Err(format!("tickets.max_tickets is from 1 to {CHANNEL_SLOTS}"));
        }
        // usable blocks: the delta, plus what the payer's node adds, less the margin
        let floor = (SETTLE_MARGIN_BLOCKS + 2)
            .saturating_sub(PAYER_PAD_BLOCKS)
            .max(MIN_TICKET_BLOCKS + 1);
        if !(floor..=2016).contains(&ticket_blocks) {
            return Err(format!("tickets.ticket_blocks is from {floor} to 2016: a ticket is used only while more than {SETTLE_MARGIN_BLOCKS} blocks are left"));
        }

        let c = match top.get("caps") {
            Some(c) => obj(
                c,
                "caps",
                &[
                    "max_sessions",
                    "sessions_per_address",
                    "max_kept_sessions",
                    "max_held_tickets",
                    "unpaid_secs",
                    "first_use_secs",
                    "idle_secs",
                    "keep_secs",
                ],
            )?,
            None => &empty,
        };
        let max_sessions = num32(c, "max_sessions", 30)?;
        if max_sessions == 0 {
            return Err("caps.max_sessions is at least 1".into());
        }
        let all = max_sessions
            .checked_mul(max_tickets)
            .ok_or("caps.max_sessions times tickets.max_tickets does not fit")?;
        let max_held = num32(c, "max_held_tickets", all)?;
        if max_held == 0 || max_held > all {
            return Err(format!(
                "caps.max_held_tickets is from 1 to max_sessions times max_tickets ({all})"
            ));
        }
        if max_held > MAX_HELD {
            return Err(format!(
                "caps.max_held_tickets is at most {MAX_HELD} (it is max_sessions times max_tickets unless set): the gateway follows each unreleased ticket on its own connection to the node"
            ));
        }
        ticket_msat
            .checked_mul(u64::from(max_held))
            .ok_or("the cap on held funds does not fit")?;
        let caps = Caps {
            ticket_msat,
            max_tickets,
            max_sessions,
            sessions_per_address: num32(c, "sessions_per_address", 4)?,
            max_kept_sessions: num32(c, "max_kept_sessions", 10_000)?.max(max_sessions),
            max_held,
            margin_blocks: SETTLE_MARGIN_BLOCKS,
            unpaid_secs: num(c, "unpaid_secs", 75)?,
            first_use_secs: num(c, "first_use_secs", 60)?,
            idle_secs: num(c, "idle_secs", 300)?,
            keep_secs: num(c, "keep_secs", 86_400)?,
        };
        if caps.unpaid_secs < u64::from(xbt402::ticket::INVOICE_EXPIRY_S) {
            return Err(format!(
                "caps.unpaid_secs is at least the invoice's own {} seconds",
                xbt402::ticket::INVOICE_EXPIRY_S
            ));
        }

        let h = match top.get("http") {
            Some(h) => obj(h, "http", &["connections", "per_address", "threads"])?,
            None => &empty,
        };
        // bounded before they become sizes: each is a number of threads
        let small = |k: &str, default: u64, least: u64| match num(h, k, default)? {
            n if (least..=4096).contains(&n) => {
                usize::try_from(n).map_err(|_| format!("http.{k} is too large"))
            }
            _ => Err(format!("http.{k} is from {least} to 4096")),
        };
        let http = Http {
            connections: small("connections", 64, 1)?,
            per_address: small("per_address", 48, 0)?,
            threads: small("threads", 16, 1)?,
        };

        let tm = match top.get("times") {
            Some(t) => obj(
                t,
                "times",
                &[
                    "refill_wait_ms",
                    "upstream_wait_secs",
                    "height_max_age_secs",
                    "max_response_secs",
                    "tick_ms",
                ],
            )?,
            None => &empty,
        };
        let times = Times {
            refill_wait: Duration::from_millis(num(tm, "refill_wait_ms", 3000)?),
            upstream_wait: Duration::from_secs(num(tm, "upstream_wait_secs", 10)?.max(1)),
            height_max_age: Duration::from_secs(num(tm, "height_max_age_secs", 10)?.max(1)),
            max_response: Duration::from_secs(num(tm, "max_response_secs", 21_600)?.max(1)),
            tick: Duration::from_millis(num(tm, "tick_ms", 500)?.clamp(10, 5000)),
        };

        let mut routes = vec![];
        for r in top
            .get("routes")
            .and_then(Value::as_array)
            .ok_or("routes is a list, and may not be missing: a path with no route is not served")?
        {
            routes.push(route(r)?);
        }
        for (i, r) in routes.iter().enumerate() {
            if routes[..i].iter().any(|o| o.path == r.path) {
                return Err(format!("route {}: named twice", r.path));
            }
            if r.path == SESSION_PATH
                || r.path.starts_with(&format!("{SESSION_PATH}/"))
                || r.path == SERVICES_PATH
            {
                return Err(format!("route {}: that path is the gateway's own", r.path));
            }
            if r.release == Release::AfterVerify && r.price.request_msat > ticket_msat {
                return Err(format!(
                    "route {}: a piece served before its secret costs at most one ticket",
                    r.path
                ));
            }
        }
        Ok(Self {
            listen: req_str(top, "listen")?.to_string(),
            public_url: origin.trim_end_matches('/').to_string(),
            upstream: up.trim_end_matches('/').to_string(),
            state_dir: PathBuf::from(req_str(top, "state_dir")?),
            chain,
            network,
            node,
            ticket_blocks,
            caps,
            routes,
            http,
            times,
        })
    }
}

/// Where the gateway serves the list of what it sells.
pub const SERVICES_PATH: &str = "/services";

fn route(v: &Value) -> Result<Route, String> {
    let r = obj(
        v,
        "a route",
        &[
            "path",
            "methods",
            "free",
            "price",
            "release",
            "forward_headers",
            "max_body",
        ],
    )?;
    let path = req_str(r, "path")?.to_string();
    let plain = path.starts_with('/')
        && !path.contains("//")
        && path
            .bytes()
            .all(|c| c.is_ascii_graphic() && !b"%?#\\".contains(&c))
        && !path.split('/').any(|s| s == "." || s == "..");
    if !plain {
        return Err(format!("route {path:?}: a path starts with /, and has no %, ?, #, backslash, empty or dot segment"));
    }
    let bad = |what: &str| format!("route {path}: {what}");
    let methods = match r.get("methods") {
        None => vec!["GET".to_string(), "HEAD".to_string()],
        Some(Value::Array(a)) if !a.is_empty() => {
            let mut out = vec![];
            for m in a {
                match m.as_str() {
                    Some(m) if ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].contains(&m) => {
                        out.push(m.to_string())
                    }
                    _ => {
                        return Err(bad(
                            "methods are GET, HEAD, POST, PUT, PATCH or DELETE, in upper case",
                        ))
                    }
                }
            }
            out
        }
        _ => return Err(bad("methods is a list with at least one method")),
    };
    let free = match r.get("free") {
        None => false,
        Some(Value::Bool(b)) => *b,
        _ => return Err(bad("free is true or false")),
    };
    let empty = Map::new();
    let p = match r.get("price") {
        Some(p) => obj(
            p,
            "price",
            &["request_msat", "byte_msat", "per_bytes", "second_msat"],
        )
        .map_err(|e| bad(&e))?,
        None => &empty,
    };
    let price = Price {
        request_msat: num(p, "request_msat", 0)?,
        byte_msat: num(p, "byte_msat", 0)?,
        per_bytes: num(p, "per_bytes", 1)?,
        second_msat: num(p, "second_msat", 0)?,
    };
    if price.per_bytes == 0 {
        return Err(bad("price.per_bytes is at least 1"));
    }
    if free != price.is_free() {
        return Err(bad("a route has a price, or says \"free\": true, and not both: a price left out by mistake must not serve for nothing"));
    }
    let release = match opt_str(r, "release")? {
        None | Some("with-request") => Release::WithRequest,
        Some("after-verify") => Release::AfterVerify,
        Some(_) => return Err(bad("release is with-request or after-verify")),
    };
    let mut forward_headers = vec![];
    for h in r
        .get("forward_headers")
        .map(|h| h.as_array().ok_or_else(|| bad("forward_headers is a list")))
        .transpose()?
        .into_iter()
        .flatten()
    {
        let name = h
            .as_str()
            .map(str::to_ascii_lowercase)
            .filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
            .ok_or_else(|| bad("forward_headers are header names"))?;
        if NEVER_FORWARDED.contains(&name.as_str()) {
            return Err(bad(&format!("{name} is never passed to the service")));
        }
        forward_headers.push(name);
    }
    let max_body = num(r, "max_body", 0)?;
    if max_body > 64 << 20 {
        return Err(bad(
            "max_body is at most 64 MiB: a request body is read whole before it is passed on",
        ));
    }
    Ok(Route {
        path,
        methods,
        free,
        price,
        release,
        forward_headers,
        max_body: max_body as usize,
    })
}

fn obj<'a>(v: &'a Value, what: &str, known: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let m = v
        .as_object()
        .ok_or_else(|| format!("{what} is an object"))?;
    match m.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => Err(format!(
            "{what}: unknown key {k:?} (known: {})",
            known.join(", ")
        )),
        None => Ok(m),
    }
}

fn req_str<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, String> {
    opt_str(m, k)?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{k} is missing"))
}

fn opt_str<'a>(m: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, String> {
    match m.get(k) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{k} is a string")),
    }
}

/// A whole number, or the default when the key is absent. Anything else is an error, not the default.
fn num(m: &Map<String, Value>, k: &str, default: u64) -> Result<u64, String> {
    match m.get(k) {
        None => Ok(default),
        Some(v) => v.as_u64().ok_or_else(|| format!("{k} is a whole number")),
    }
}

fn num32(m: &Map<String, Value>, k: &str, default: u32) -> Result<u32, String> {
    u32::try_from(num(m, k, u64::from(default))?).map_err(|_| format!("{k} is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn base() -> Value {
        json!({"listen": "127.0.0.1:0", "public_url": "http://127.0.0.1:8402", "upstream": "http://127.0.0.1:8080", "state_dir": "/tmp/x",
               "chain": "regtest", "network": "lightning:00000000000000000000000000000001",
               "node": {"rest": "https://127.0.0.1:8080", "tls_cert": "tls.cert", "macaroon": "a", "info_macaroon": "b"},
               "routes": [{"path": "/files/", "price": {"byte_msat": 1000, "per_bytes": 1048576}},
                          {"path": "/files/free/", "free": true},
                          {"path": "/api", "methods": ["POST"], "price": {"request_msat": 2500}, "max_body": 4096, "forward_headers": ["X-Trace"]}]})
    }

    #[test]
    fn the_defaults_are_the_drafts_numbers() {
        let c = Config::from_json(&base()).unwrap();
        assert_eq!(
            (
                c.caps.ticket_msat,
                c.caps.max_tickets,
                c.ticket_blocks,
                c.caps.margin_blocks
            ),
            (1_000_000, 8, 40, 24)
        );
        assert_eq!(
            (
                c.caps.max_sessions,
                c.caps.sessions_per_address,
                c.caps.max_kept_sessions,
                c.caps.max_held
            ),
            (30, 4, 10_000, 240)
        );
        assert_eq!(
            (
                c.caps.unpaid_secs,
                c.caps.first_use_secs,
                c.caps.idle_secs,
                c.caps.keep_secs
            ),
            (75, 60, 300, 86_400)
        );
        assert_eq!(
            (c.http.connections, c.http.per_address, c.http.threads),
            (64, 48, 16)
        );
        assert!(!c.mainnet());
        let mut main = base();
        main.as_object_mut().unwrap().remove("chain");
        main.as_object_mut().unwrap().remove("network");
        let m = Config::from_json(&main).unwrap();
        assert!(m.mainnet());
        assert_eq!(m.network, "lightning:0000000000000050c1e5f69672f45929");
    }

    #[test]
    fn the_example_file_is_a_config() {
        let v: Value = serde_json::from_str(include_str!("../gateway.example.json")).unwrap();
        let c = Config::from_json(&v).unwrap();
        assert!(c.mainnet());
        assert_eq!(c.routes.len(), 5);
        assert_eq!(
            c.route("/films/a.mkv").unwrap().price.for_bytes(1 << 20),
            Some(200_000)
        );
        assert_eq!(c.route("/chunks/1").unwrap().release, Release::AfterVerify);
    }

    #[test]
    fn the_longest_route_wins_and_a_path_with_no_route_has_none() {
        let c = Config::from_json(&base()).unwrap();
        assert_eq!(c.route("/files/a.bin").unwrap().path, "/files/");
        assert_eq!(c.route("/files/free/a.bin").unwrap().path, "/files/free/");
        assert!(c.route("/files/free/a.bin").unwrap().free);
        assert_eq!(c.route("/api").unwrap().methods, vec!["POST"]);
        assert_eq!(c.route("/api").unwrap().forward_headers, vec!["x-trace"]);
        for none in ["/api/", "/api2", "/files", "/", "/Files/a"] {
            assert!(c.route(none).is_none(), "{none}");
        }
    }

    #[test]
    fn a_file_that_could_mean_two_things_is_refused() {
        let edit = |f: &dyn Fn(&mut Value)| {
            let mut v = base();
            f(&mut v);
            Config::from_json(&v)
        };
        type Edit = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("unknown key", Box::new(|v| v["cap"] = json!({}))),
            (
                "unknown key",
                Box::new(|v| v["caps"] = json!({"max_session": 3})),
            ),
            (
                "unknown key",
                Box::new(|v| v["routes"][0]["prices"] = json!({})),
            ),
            (
                "whole number",
                Box::new(|v| v["caps"] = json!({"max_sessions": "3"})),
            ),
            (
                "whole number",
                Box::new(|v| v["tickets"] = json!({"ticket_msat": -1})),
            ),
            (
                "whole number",
                Box::new(|v| v["routes"][0]["price"]["byte_msat"] = json!(1.5)),
            ),
            (
                "ticket_msat",
                Box::new(|v| v["tickets"] = json!({"ticket_msat": 999})),
            ),
            (
                "ticket_blocks",
                Box::new(|v| v["tickets"] = json!({"ticket_blocks": 24})),
            ),
            (
                "ticket_blocks",
                Box::new(|v| v["tickets"] = json!({"ticket_blocks": 2017})),
            ),
            (
                "max_tickets",
                Box::new(|v| v["tickets"] = json!({"max_tickets": 484})),
            ),
            (
                "max_held_tickets",
                Box::new(|v| v["caps"] = json!({"max_held_tickets": 241})),
            ),
            (
                "unpaid_secs",
                Box::new(|v| v["caps"] = json!({"unpaid_secs": 59})),
            ),
            (
                "http.connections",
                Box::new(|v| v["http"] = json!({"connections": 0})),
            ),
            (
                "http.threads",
                Box::new(|v| v["http"] = json!({"threads": 5000})),
            ),
            (
                "at most 4096",
                Box::new(|v| v["caps"] = json!({"max_sessions": 513})),
            ),
            (
                "not both",
                Box::new(|v| v["routes"][0] = json!({"path": "/x/"})),
            ),
            (
                "not both",
                Box::new(|v| v["routes"][1]["price"] = json!({"request_msat": 1})),
            ),
            (
                "per_bytes",
                Box::new(|v| v["routes"][0]["price"]["per_bytes"] = json!(0)),
            ),
            (
                "named twice",
                Box::new(|v| v["routes"][1]["path"] = json!("/files/")),
            ),
            (
                "gateway's own",
                Box::new(|v| v["routes"][1]["path"] = json!("/x402/ticket/lock")),
            ),
            (
                "gateway's own",
                Box::new(|v| v["routes"][1]["path"] = json!("/services")),
            ),
            (
                "a path starts",
                Box::new(|v| v["routes"][0]["path"] = json!("files/")),
            ),
            (
                "a path starts",
                Box::new(|v| v["routes"][0]["path"] = json!("/a/../b/")),
            ),
            (
                "a path starts",
                Box::new(|v| v["routes"][0]["path"] = json!("/a%2fb/")),
            ),
            (
                "a path starts",
                Box::new(|v| v["routes"][0]["path"] = json!("/a//b/")),
            ),
            (
                "never passed",
                Box::new(|v| v["routes"][0]["forward_headers"] = json!(["Host"])),
            ),
            (
                "never passed",
                Box::new(|v| v["routes"][0]["forward_headers"] = json!(["payment-signature"])),
            ),
            (
                "methods",
                Box::new(|v| v["routes"][0]["methods"] = json!(["get"])),
            ),
            (
                "methods",
                Box::new(|v| v["routes"][0]["methods"] = json!(["CONNECT"])),
            ),
            (
                "release",
                Box::new(|v| v["routes"][0]["release"] = json!("later")),
            ),
            (
                "at most one ticket",
                Box::new(
                    |v| v["routes"][2] = json!({"path": "/api", "price": {"request_msat": 1000001}, "release": "after-verify"}),
                ),
            ),
            (
                "routes is a list",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("routes");
                }),
            ),
            (
                "upstream",
                Box::new(|v| v["upstream"] = json!("https://127.0.0.1:8080")),
            ),
            (
                "upstream",
                Box::new(|v| v["upstream"] = json!("http://127.0.0.1:8080/?a=1")),
            ),
            (
                "upstream",
                Box::new(|v| v["upstream"] = json!("http://127.1:8080")),
            ),
            (
                "public_url",
                Box::new(|v| v["public_url"] = json!("seller.example")),
            ),
            (
                "public_url",
                Box::new(|v| v["public_url"] = json!("https://seller.example/shop")),
            ),
            (
                "network",
                Box::new(|v| v["network"] = json!("bip122:00000000000000000000000000000001")),
            ),
            ("network is fixed", Box::new(|v| v["chain"] = json!("main"))),
            (
                "network",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("network");
                }),
            ),
            (
                "info_macaroon is missing",
                Box::new(|v| {
                    v["node"].as_object_mut().unwrap().remove("info_macaroon");
                }),
            ),
        ];
        for (want, f) in cases {
            let e = edit(&*f).unwrap_err().to_string();
            assert!(e.contains(want), "wanted {want:?}, got {e:?}");
        }
    }
}
