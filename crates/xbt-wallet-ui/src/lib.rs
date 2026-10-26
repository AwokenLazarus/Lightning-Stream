//! xbt-wallet-ui (AGP-039): the agent wallet's web UI for a box with no terminal (Umbrel, StartOS).
//!
//! A separate process that talks only to the signer's socket, like the MCP server. It renders plain
//! HTML on the server; the one script that does anything, `assets/ui.js`, holds the human's ed25519 key in the browser
//! and signs there, so approvals keep B2's human-key property: the box never holds the approving key.
//!
//! * [`config`]: environment and data directory.
//! * [`auth`]: the login (scrypt), sessions, CSRF tokens, the login throttle.
//! * [`link`]: the signer socket client.
//! * [`msg`]: the signed message formats (the same bytes as `xbt_signer::approval` and `ui.js`).
//! * [`html`]: escaping, the page layout, formatting.
//! * [`app`]: the routes and pages; [`server`]: the HTTP server.
//! * [`services`]: the services file Browse and the player read (`XBT_UI_SERVICES`).
//! * [`relay`]: the links an external player (VLC, mpv) plays one item through.
//! * [`setup`]: the Lightning rail page (wallet) and the seller gateway's page (`XBT_UI_ROLE=gateway`).
pub mod app;
pub mod services;
pub mod auth;
pub mod config;
pub mod html;
pub mod link;
pub mod msg;
pub mod relay;
pub mod server;
pub mod setup;

pub const UI_JS: &str = include_str!("../assets/ui.js");
pub const UI_CSS: &str = include_str!("../assets/ui.css");
/// The river drawn behind every page: decoration only, it reads and sends nothing.
pub const RIVER_JS_SOURCE: &str = include_str!("../assets/river.js");

/// The river as served: its source without indentation, blank lines and comment lines.
pub fn river_js() -> &'static str {
    static SERVED: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        RIVER_JS_SOURCE.lines().map(str::trim_start).filter(|l| !l.is_empty() && !l.starts_with("//")).collect::<Vec<_>>().join("\n")
    });
    &SERVED
}

/// OS randomness.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

/// Seconds since the epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Constant-time equality for secrets of public length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
