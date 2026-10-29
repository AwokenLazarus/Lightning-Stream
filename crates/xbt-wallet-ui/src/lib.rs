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
pub mod node_keys;
pub mod own_shop;
pub mod msg;
pub mod nostr;
pub mod relay;
pub mod server;
pub mod setup;

pub const UI_JS: &str = include_str!("../assets/ui.js");
pub const UI_CSS: &str = include_str!("../assets/ui.css");
pub const VT_JS: &str = include_str!("../assets/vt.js");
/// The app's mark: the header logo and the page icon.
pub const MARK_SVG: &str = include_str!("../assets/mark.svg");
/// The theme's fonts, served from the box itself (never fetched from elsewhere): name and bytes.
pub static FONTS: &[(&str, &[u8])] = &[
    ("inter-var.woff2", include_bytes!("../assets/fonts/inter-var.woff2")),
    ("jetbrains-mono-var.woff2", include_bytes!("../assets/fonts/jetbrains-mono-var.woff2")),
];

/// A theme font by its file name.
pub fn font(name: &str) -> Option<&'static [u8]> {
    FONTS.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
}
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
