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
//! * [`services`]: the services file Browse reads (`XBT_UI_SERVICES`).
//! * [`relay`]: the links a buyer's own player (VLC, mpv, a TV app) opens one file through.
//! * [`files`]: the folder a Files service shares, served to the shop's gateway.
//! * [`setup`]: the Lightning rail page (wallet) and the seller gateway's page (`XBT_UI_ROLE=gateway`).
pub mod app;
pub mod services;
pub mod auth;
pub mod config;
pub mod files;
pub mod html;
pub mod link;
pub mod node_keys;
pub mod own_shop;
pub mod pay_feedback;
pub mod msg;
pub mod nostr;
pub mod relay;
pub mod relaynet;
pub mod server;
pub mod seller_app;
pub mod setup;
pub mod shops;
pub mod stream_gateway;

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

/// The Umbrel package's manifest, read when this crate is built: its `version` is the release.
const UMBREL_APP_YML: &str = include_str!("../../../packaging/umbrel/lazarus-lightning-stream/umbrel-app.yml");

/// The release this app is part of (`0.2.2`), as the footer and Settings show it. It is the
/// version of the Umbrel package (`packaging/umbrel/lazarus-lightning-stream/umbrel-app.yml`),
/// read at build time: the release bumps that file in any case, and every package (Umbrel,
/// StartOS, Linux) is built from the same tree, so the number cannot drift from what the owner
/// installed. The crate's own version (`CARGO_PKG_VERSION`) is the workspace's, not the release.
pub fn release_version() -> &'static str {
    static V: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| version_in(UMBREL_APP_YML).unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()));
    &V
}

/// The top-level `version:` of a manifest, without quotes.
fn version_in(yml: &str) -> Option<String> {
    yml.lines().find_map(|l| l.strip_prefix("version:")).map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string()).filter(|v| !v.is_empty())
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

#[cfg(test)]
mod version_tests {
    /// The footer and Settings name the release, not the crate's 0.1.0 (#37 item 10).
    ///
    /// FAILS with `env!("CARGO_PKG_VERSION")`: 0.1.0.
    #[test]
    fn the_release_version_is_the_umbrel_package_s() {
        assert_eq!(super::version_in("manifestVersion: 1.1\nid: x\nversion: \"0.2.2\"\ntagline: t\n").as_deref(), Some("0.2.2"));
        assert_eq!(super::version_in("version: 0.3.0\n").as_deref(), Some("0.3.0"));
        let v = super::release_version();
        assert_ne!(v, env!("CARGO_PKG_VERSION"), "the release, not the crate's version");
        let parts: Vec<&str> = v.split('.').collect();
        assert!(parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()), "{v}");
    }
}
