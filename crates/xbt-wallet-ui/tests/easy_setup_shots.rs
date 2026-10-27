//! Screenshots of the setup a box needs no step for, the player's messages and the owner's own shop,
//! in headless Chrome: light, dark and phone width. Runs only with `XBT_UI_SHOTS_DIR` set (the
//! directory the PNGs go to) and Chrome on the PATH (or `CHROME`); otherwise it says so and passes.
//! The box's login proxy is the loopback peer here, so Chrome is the logged-in owner.
#[path = "../../xbt-signer/tests/common/mod.rs"]
mod common;

use common::*;
use serde_json::json;
use xbt_wallet_ui::app::App;
use xbt_wallet_ui::config::Config;

fn shoot(chrome: &str, out: &std::path::Path, name: &str, url: &str) {
    for (suffix, size, dark) in [("light", "1280,900", false), ("dark", "1280,900", true), ("phone-light", "390,844", false)] {
        let file = out.join(format!("{name}-{suffix}.png"));
        let profile = tempfile::tempdir().unwrap();
        let mut c = std::process::Command::new(chrome);
        c.args(["--headless=new", "--disable-gpu", "--no-first-run", "--hide-scrollbars", "--virtual-time-budget=6000",
                &format!("--user-data-dir={}", profile.path().display()), &format!("--window-size={size}"),
                &format!("--screenshot={}", file.display())]);
        if dark {
            c.arg("--force-dark-mode").arg("--blink-settings=preferredColorScheme=0");
        }
        let o = c.arg(url).output().unwrap();
        assert!(file.is_file(), "{name}: {}", String::from_utf8_lossy(&o.stderr));
    }
}

#[test]
fn easy_setup_screenshots() {
    let (Ok(out), Some(chrome)) = (std::env::var("XBT_UI_SHOTS_DIR"), [std::env::var("CHROME").unwrap_or_else(|_| "google-chrome".into())]
        .into_iter().find(|c| std::process::Command::new(c).arg("--version").output().is_ok_and(|o| o.status.success()))) else {
        return eprintln!("XBT_UI_SHOTS_DIR unset or Chrome missing: skipped");
    };
    let out = std::path::PathBuf::from(out);
    std::fs::create_dir_all(&out).unwrap();
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());

    // a new box: no approval key yet, the code given by the box, the node connected by itself
    let rig = Rig::new(json!({"human_pubkey": ""}), false);
    let sock = rig.dir.path().join("signer.sock");
    let _s = xbt_signer::server::spawn(rig.s.clone(), &sock, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    let code = data.path().join("enroll-code");
    std::fs::write(&code, std::fs::read_to_string(rig.root.join(".run/enroll-code")).unwrap()).unwrap();
    let ln = data.path().join("ln");
    std::fs::create_dir_all(&ln).unwrap();
    let rail = xbt402::macaroon::lnd_macaroon_for_tests(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read"])], &[]);
    let keys = xbt_wallet_ui::node_keys::Settings { rest: "https://10.21.21.66:8180".into(), tls_cert: None, admin: ln.join("none"), grant: None,
                                                    rail_dir: Some(ln.clone()), gw_dir: None };
    xbt_wallet_ui::node_keys::make_keys(&keys, &mut |_, _| Ok(rail.clone())).unwrap();
    let film = "https://stream.lazarus-xbt.xyz/Videos/0f0967c6719ebc0951976655686df3bc/stream?static=true";
    let services = data.path().join("services.json");
    std::fs::write(&services, json!([
        {"name": "Creative Commons films", "kind": "video", "seller": "https://stream.lazarus-xbt.xyz", "price_text": "20 sat a MiB",
         "items": [{"title": "Elephants Dream", "year": 2006, "url": film, "credit": "(c) Blender Foundation, CC BY 2.5"}]},
        {"name": "My films", "kind": "video", "seller": "https://shop.example", "price_text": "20 sat a MiB",
         "items": [{"title": "Sintel", "year": 2010, "url": "https://shop.example/Videos/abc/stream", "credit": "(c) Blender Foundation, CC BY 3.0"}]}
    ]).to_string()).unwrap();
    let gw = data.path().join("gateway");
    std::fs::create_dir_all(&gw).unwrap();
    // the gateway's two keys, made by the box too
    let gw_keys = xbt_wallet_ui::node_keys::Settings { rest: "https://10.21.21.66:8180".into(), tls_cert: None, admin: gw.join("none"), grant: None,
                                                       rail_dir: None, gw_dir: Some(gw.clone()) };
    xbt_wallet_ui::node_keys::make_keys(&gw_keys, &mut |ops, _| {
        let pairs: Vec<(&str, Vec<&str>)> = ops.iter().map(|o| o.split_once(':').unwrap()).fold(vec![], |mut v: Vec<(&str, Vec<&str>)>, (e, a)| {
            match v.iter_mut().find(|(x, _)| *x == e) { Some((_, acts)) => acts.push(a), None => v.push((e, vec![a])) }
            v
        });
        let refs: Vec<(&str, &[&str])> = pairs.iter().map(|(e, a)| (*e, a.as_slice())).collect();
        Ok(xbt402::macaroon::lnd_macaroon_for_tests(&refs, &[]))
    }).unwrap();
    std::fs::write(gw.join("config.json"), json!({"public_url": "https://shop.example", "upstream": "http://127.0.0.1:9",
        "routes": [{"path": "/Videos/abc/"}]}).to_string()).unwrap();
    let mut cfg = Config::for_test(sock.clone(), data.path().join("ui"), "127.0.0.1:0");
    cfg.platform_login = Some("localhost".into());
    cfg.enroll_code_file = Some(code);
    cfg.ln.dir = ln;
    cfg.ln.rest = Some("https://10.21.21.66:8180".into());
    cfg.services_file = Some(services);
    cfg.sell = true;
    cfg.gw.dir = gw;
    cfg.gw.port = 8402;
    cfg.gw.node_rest = Some("https://10.21.21.66:8180".into());
    cfg.local_services = vec![("Jellyfin".into(), "http://127.0.0.1:9".into())];
    // the connector is not running: a play fails, and the player says why
    cfg.connector = "http://127.0.0.1:9".into();
    let app = App::new(cfg).unwrap();
    let srv = xbt_wallet_ui::server::spawn(app).unwrap();
    let base = format!("http://{}", srv.addr);
    shoot(&chrome, &out, "setup-first-run", &format!("{base}/setup"));
    shoot(&chrome, &out, "node-connected-by-itself", &format!("{base}/lightning"));
    shoot(&chrome, &out, "player-wallet-not-set-up", &format!("{base}/play?item={}", xbt_wallet_ui::services::urlenc(film)));
    shoot(&chrome, &out, "browse-your-shop", &format!("{base}/browse"));
    shoot(&chrome, &out, "preview-your-shop", &format!("{base}/play?item={}", xbt_wallet_ui::services::urlenc("https://shop.example/Videos/abc/stream")));
    shoot(&chrome, &out, "sell-found-and-https-help", &format!("{base}/sell"));
    shoot(&chrome, &out, "sellers-allow", &format!("{base}/services"));

    // a box with a key: the player tries, and says why it failed
    let rig2 = Rig::new(json!({}), false);
    let sock2 = rig2.dir.path().join("signer.sock");
    let _s2 = xbt_signer::server::spawn(rig2.s.clone(), &sock2, false).unwrap();
    let data2 = tempfile::tempdir().unwrap();
    let services2 = data2.path().join("services.json");
    std::fs::write(&services2, json!([{"name": "Creative Commons films", "kind": "video", "seller": "https://stream.lazarus-xbt.xyz",
        "price_text": "20 sat a MiB", "items": [{"title": "Elephants Dream", "year": 2006, "url": film, "credit": "CC BY 2.5"}]}]).to_string()).unwrap();
    let mut cfg2 = Config::for_test(sock2, data2.path().join("ui"), "127.0.0.1:0");
    cfg2.platform_login = Some("localhost".into());
    cfg2.services_file = Some(services2);
    // a connector that answers as the wallet does when the rules refuse the seller
    struct Refuse;
    impl xbt_svc::http::Handler for Refuse {
        fn body_limit(&self, _: &str, _: &str) -> usize {
            0
        }
        fn handle(&self, _: xbt_svc::http::Request) -> xbt_svc::http::Response {
            xbt_svc::http::Response::text(402, "application/json", r#"{"error": "the seller is not on the allowlist", "rule": "allowlist"}"#)
        }
    }
    let refuse = xbt_svc::http::serve(std::sync::Arc::new(Refuse), std::net::TcpListener::bind("127.0.0.1:0").unwrap(), 2).unwrap();
    cfg2.connector = format!("http://{}", refuse.addr);
    let app2 = App::new(cfg2).unwrap();
    let srv2 = xbt_wallet_ui::server::spawn(app2).unwrap();
    shoot(&chrome, &out, "player-says-why", &format!("http://{}/play?item={}", srv2.addr, xbt_wallet_ui::services::urlenc(film)));
}
