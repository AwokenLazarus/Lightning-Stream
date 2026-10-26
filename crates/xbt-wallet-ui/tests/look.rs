//! The look: the stylesheet and the river background are served from the box itself, cached by
//! content hash, under a self-only CSP; and (with `XBT_UI_LOOK=1`) the pages in headless Chrome:
//! screenshots in light, dark and at phone width, the river's CPU and frame cost, and text
//! contrast over it (tests/js/look_test.mjs). Shots: `$XBT_UI_LOOK_DIR` (default
//! `target/ui-look`).
#[path = "../../xbt-signer/tests/common/mod.rs"]
mod common;

use common::*;
use serde_json::json;
use xbt_wallet_ui::app::App;
use xbt_wallet_ui::config::{Config, Role};

fn get(url: &str) -> (u16, std::collections::HashMap<String, String>, String) {
    let r = match ureq::AgentBuilder::new().redirects(0).build().get(url).call() {
        Ok(r) | Err(ureq::Error::Status(_, r)) => r,
        Err(e) => panic!("{url}: {e}"),
    };
    let h = r.headers_names().into_iter().map(|k| (k.to_ascii_lowercase(), r.header(&k).unwrap_or("").to_string())).collect();
    (r.status(), h, r.into_string().unwrap())
}

#[test]
fn the_river_and_the_stylesheet_are_local_cached_by_hash_and_the_csp_stays_self_only() {
    let data = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_test(data.path().join("no-signer.sock"), data.path().join("ui"), "127.0.0.1:0");
    cfg.role = Role::Gateway;
    let srv = xbt_wallet_ui::server::spawn(App::new(cfg).unwrap()).unwrap();
    let base = format!("http://{}", srv.addr);

    let (status, h, page) = get(&format!("{base}/"));
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("<canvas id=\"river\" aria-hidden=\"true\">") && page.contains("class=\"glow\" aria-hidden=\"true\""), "{page}");
    let v = xbt_wallet_ui::html::asset_version(xbt_wallet_ui::river_js());
    assert!(page.contains(&format!("<script src=\"./river.js?v={v}\">")), "{page}");
    let csp = &h["content-security-policy"];
    assert!(csp.contains("script-src 'self'") && csp.contains("style-src 'self'") && csp.contains("default-src 'none'"), "{csp}");
    assert!(!csp.contains("unsafe") && !csp.contains("http") && !csp.contains('*'), "nothing from elsewhere, nothing inline: {csp}");

    let (status, h, js) = get(&format!("{base}/river.js?v={v}"));
    assert_eq!(status, 200);
    assert!(h["content-type"].starts_with("text/javascript"));
    assert_eq!(h["cache-control"], "public, max-age=31536000, immutable", "the hashed URL never changes meaning");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(js, xbt_wallet_ui::river_js());
    assert!(js.len() < 8 * 1024, "the river as served stays small: {} bytes", js.len());
    // stripping indentation and comment lines leaves a script that still parses
    let home = std::env::var("HOME").unwrap_or_default();
    if let Some(node) = ["node".to_string(), format!("{home}/.local/share/nodejs/bin/node")].into_iter()
        .find(|n| std::process::Command::new(n).arg("--version").output().is_ok_and(|o| o.status.success())) {
        let f = data.path().join("river.js");
        std::fs::write(&f, &js).unwrap();
        let o = std::process::Command::new(node).arg("--check").arg(&f).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    for net in ["fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "localStorage", "eval(", "innerHTML"] {
        assert!(!js.contains(net), "the river reads and sends nothing: {net}");
    }
    let (_, h, _) = get(&format!("{base}/river.js"));
    assert_eq!(h["cache-control"], "public, max-age=86400", "an unhashed request is cached for a day only");
    let (_, h, _) = get(&format!("{base}/river.js?v=000000000000"));
    assert_eq!(h["cache-control"], "public, max-age=86400", "a stale hash is not cached for a year");

    let cv = xbt_wallet_ui::html::asset_version(xbt_wallet_ui::UI_CSS);
    let (status, h, css) = get(&format!("{base}/ui.css?v={cv}"));
    assert_eq!(status, 200);
    assert!(h["content-type"].starts_with("text/css"));
    assert_eq!(h["cache-control"], "public, max-age=31536000, immutable");
    assert!(!css.contains("url(http") && !css.contains("@import"), "the stylesheet loads nothing from elsewhere");
    for token in ["--river-a", "--river-b", "--river-spark", "--river-arc", "--river-blend", "prefers-color-scheme: dark"] {
        assert!(css.contains(token), "{token}");
    }
}

#[test]
fn the_look_in_headless_chrome() {
    if std::env::var("XBT_UI_LOOK").ok().as_deref() != Some("1") {
        return eprintln!("set XBT_UI_LOOK=1 to take the screenshots and measure the river: skipped");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let find = |c: &[String]| c.iter().find(|c| std::process::Command::new(c).arg("--version").output().is_ok_and(|o| o.status.success())).cloned();
    let (Some(node), Some(chrome)) = (find(&["node".into(), format!("{home}/.local/share/nodejs/bin/node")]),
                                      find(&[std::env::var("CHROME").unwrap_or_else(|_| "google-chrome".into()), "chromium".into()])) else {
        return eprintln!("node or chrome not found: skipped");
    };
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"human_pubkey": ""}), true);
    let sock_path = rig.dir.path().join("signer.sock");
    let _sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let film = "https://media.example/Videos/1/stream?static=true";
    let data = tempfile::tempdir().unwrap();
    let services = data.path().join("services.json");
    std::fs::write(&services, json!([
        {"name": "Creative Commons films", "kind": "video", "seller": "https://media.example", "price_text": "20 sat a MiB",
         "items": [{"title": "Big Buck Bunny", "year": 2008, "url": film, "credit": "(c) Blender Foundation, CC BY 3.0"},
                   {"title": "Elephants Dream", "year": 2006, "url": "https://media.example/Videos/2/stream", "credit": "(c) Blender Foundation, CC BY 2.5"},
                   {"title": "Sintel", "year": 2010, "url": "https://media.example/Videos/3/stream", "credit": "(c) Blender Foundation, CC BY 3.0"}]},
        {"name": "Open lectures", "kind": "video", "seller": "https://lectures.example", "price_text": "12 sat a MiB",
         "items": [{"title": "Tears of Steel", "year": 2012, "url": "https://lectures.example/v/4", "credit": "(c) Blender Foundation, CC BY 3.0"}]}
    ]).to_string()).unwrap();
    let mut cfg = Config::for_test(sock_path, data.path().join("ui"), "127.0.0.1:0");
    cfg.services_file = Some(services);
    let srv = xbt_wallet_ui::server::spawn(App::new(cfg).unwrap()).unwrap();
    let gdata = tempfile::tempdir().unwrap();
    let mut gcfg = Config::for_test(gdata.path().join("no-signer.sock"), gdata.path().join("ui"), "127.0.0.1:0");
    gcfg.role = Role::Gateway;
    gcfg.gw.dir = gdata.path().join("gateway");
    std::fs::create_dir_all(&gcfg.gw.dir).unwrap();
    let gsrv = xbt_wallet_ui::server::spawn(App::new(gcfg).unwrap()).unwrap();
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    let gcode = std::fs::read_to_string(gdata.path().join("ui/setup-code")).unwrap();
    let out = std::env::var("XBT_UI_LOOK_DIR").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/ui-look").into());
    let play = format!("/play?item={}", film.replace('/', "%2F").replace(':', "%3A").replace('?', "%3F").replace('=', "%3D"));
    let secs = std::env::var("XBT_UI_LOOK_SECONDS").unwrap_or_else(|_| "30".into());
    let o = std::process::Command::new(node).env("CHROME", chrome)
        .args([concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js/look_test.mjs"), &format!("http://{}", srv.addr), code.trim(),
               &format!("http://{}", gsrv.addr), gcode.trim(), &out, &play, &secs])
        .output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    eprintln!("{text}{}", String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success());
    let line = text.lines().find_map(|l| l.strip_prefix("LOOK ")).expect("a LOOK line");
    let r: serde_json::Value = serde_json::from_str(line).unwrap();
    assert!(r["shots"].as_array().is_some_and(|s| s.len() >= 20), "{r}");
    for s in ["dark", "light"] {
        assert!(r["contrast"][s]["text"].as_f64().unwrap() >= 7.0, "body text over the brightest river point: {r}");
        assert!(r["contrast"][s]["muted"].as_f64().unwrap() >= 4.5, "secondary text over the brightest river point: {r}");
    }
    let f = &r["cost"]["with_river"]["frames"];
    assert!(f["frames"].as_u64().unwrap() > 0, "{r}");
    assert!(f["max_ms"].as_f64().unwrap() <= 4.0, "a river frame never takes the main thread for more than 4 ms: {r}");
    let extra = r["cost"]["with_river"]["still"]["cpu_pct_one_core"].as_f64().unwrap() - r["cost"]["without_river"]["still"]["cpu_pct_one_core"].as_f64().unwrap();
    assert!(extra < 3.0, "the river at rest costs under 3% of one core: {r}");
}
