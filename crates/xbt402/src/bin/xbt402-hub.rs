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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::adaptor::Sc;
use xbt402::http::{serve_service, UreqTransport};
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::rpc::Rpc;

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let conf_path = args.iter().position(|a| a == "--config").and_then(|i| args.get(i + 1)).unwrap_or_else(|| die("usage: xbt402-hub --config hub.json [--close-all]".into()));
    let conf: Value = serde_json::from_str(&std::fs::read_to_string(expand(conf_path)).unwrap_or_else(|e| die(format!("config: {e}"))))
        .unwrap_or_else(|e| die(format!("config: {e}")));
    let node = &conf["node"];
    let host = node.get("host").and_then(Value::as_str).unwrap_or("127.0.0.1");
    let rpc = Rpc::from_cookie(&format!("http://{host}:{}", node["rpcport"]), &expand(node["cookie"].as_str().unwrap_or("")))
        .unwrap_or_else(|e| die(format!("node: {e}")));
    let wallet = rpc.wallet(node.get("wallet").and_then(Value::as_str).unwrap_or("hub"));
    let key = std::fs::read_to_string(expand(conf["pay_to_key_file"].as_str().unwrap_or(""))).unwrap_or_else(|e| die(format!("pay_to_key_file: {e}")));
    let secret = Sc::from_hex_mod_n(key.trim()).and_then(|s| s.secret()).unwrap_or_else(|| die("pay_to_key_file: not a hex secret".into()));
    let cfg = HubConfig::from_json(conf.get("hub").unwrap_or(&json!({}))).unwrap_or_else(|e| die(format!("hub config: {e}")));
    let network = conf["network"].as_str().unwrap_or_else(|| die("network".into()));
    let datadir = expand(conf["datadir"].as_str().unwrap_or_else(|| die("datadir".into())));
    let rpc = Arc::new(rpc);
    let hub = RouteHub::new(rpc.clone(), rpc.clone(), Box::new(wallet), Box::new(UreqTransport::default()), secret, network, Some(&datadir), cfg)
        .unwrap_or_else(|e| die(format!("{e}")));
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
    let bind = format!("{}:{}", conf.get("bind").and_then(Value::as_str).unwrap_or("127.0.0.1"), conf["port"]);
    let threads = conf.get("threads").and_then(Value::as_u64).unwrap_or(16) as usize;
    let handles = serve_service(hub.clone(), &bind, threads).unwrap_or_else(|e| die(format!("bind {bind}: {e}")));
    eprintln!("xbt402 hub {} on {bind} ({network})", hub.pay_to());
    for h in handles {
        let _ = h.join();
    }
}
