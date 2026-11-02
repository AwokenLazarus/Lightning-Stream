//! A gateway held open in front of a real web app, for driving that app through it by hand or with
//! a browser script: the app's paths a buyer must not reach refused, as a seller lists them. Not
//! run by default; it serves until `HOLD_SECS` (600) pass.
//!
//! ```text
//! APP_UPSTREAM=http://127.0.0.1:8096 APP_GUEST_ID=<the guest user's id> HOLD_PORT=18403 \
//!   cargo test -p xbt-gateway --test app_hold -- --ignored --nocapture
//! ```
//!
//! The routes are free: what is tested is which paths the app may serve, not the payment, which
//! the signer's tests drive through the same gateway.

mod common;

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use xbt_gateway::config::Config;
use xbt_gateway::gateway::Gateway;
use xbt_gateway::standin::StandIn;

/// Jellyfin, sold whole: its admin, its sessions and every buyer's shared progress refused, and of
/// `/Users/` only what the guest's own login and pages use.
fn jellyfin_routes(guest: &str) -> serde_json::Value {
    json!([
        {"path": "/", "free": true, "methods": ["GET", "HEAD", "POST", "DELETE"], "max_body": 1_048_576, "websocket": true,
         "forward_headers": ["authorization", "x-emby-authorization", "x-mediabrowser-token", "x-emby-token"],
         // the longest prefix decides, ignoring case: all of the app, but none of `/users` except the guest's own login and pages,
         // and of `/system/` only what the client asks before it logs in
         "allow_paths": ["/", "/users/public", "/users/authenticatebyname", "/users/me", format!("/users/{guest}"), "/system/info/public", "/system/endpoint",
                         // what this client can play (asked once a session starts): its progress reports stay refused below
                         "/sessions/capabilities",
                         // what Jellyfin answers anyone before a login: whether Quick Connect is on, and the login page's branding
                         "/quickconnect/enabled", "/branding/configuration"],
         "deny_paths": ["/users", "/sessions", "/system/", "/devices", "/quickconnect/", "/auth/", "/startup/", "/plugins/", "/packages/",
                        "/scheduledtasks/", "/library/", "/environment/", "/branding/", "/userplayeditems", "/useritems/"]}
    ])
}

#[test]
#[ignore]
fn hold_a_gateway_in_front_of_a_real_app() {
    let upstream = std::env::var("APP_UPSTREAM").unwrap_or_else(|_| "http://127.0.0.1:8096".into());
    let guest = std::env::var("APP_GUEST_ID").expect("APP_GUEST_ID: the guest user's id");
    let port: u16 = std::env::var("HOLD_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(18403);
    let secs: u64 = std::env::var("HOLD_SECS").ok().and_then(|p| p.parse().ok()).unwrap_or(600);
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path(), &upstream, &|v| {
        v["public_url"] = json!(format!("http://127.0.0.1:{port}"));
        v["times"]["upstream_wait_secs"] = json!(30);
        v["routes"] = jellyfin_routes(&guest.to_ascii_lowercase());
    });
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let c = clock.clone();
    let gw = Gateway::start(Config::from_json(&cfg).unwrap(), Arc::new(StandIn::new(100)), common::receipt_secret(), Box::new(move || c.load(Ordering::SeqCst)))
        .unwrap();
    let running = gw.serve(TcpListener::bind(("127.0.0.1", port)).unwrap()).unwrap();
    println!("gateway at http://{} in front of {upstream} for {secs} s", running.addr);
    std::thread::sleep(Duration::from_secs(secs));
}
