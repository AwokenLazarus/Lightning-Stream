//! The shipped binary's own start, up to the point where it would ask its node for anything:
//! `xbt-gateway --check` reads the config and the macaroons, says what it will do and exits. What
//! a runner is told there, and what stops the start, is tested on the binary itself.
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};
use xbt402::macaroon::lnd_macaroon_for_tests as macaroon;
use xbt_gateway::config::MAINNET_ACK;

const BIN: &str = env!("CARGO_BIN_EXE_xbt-gateway");

/// A config in `dir` with the two narrow macaroons beside it; `edit` changes it before it is written.
fn config(dir: &Path, edit: &dyn Fn(&mut Value)) -> std::path::PathBuf {
    std::fs::write(dir.join("invoices.macaroon"), macaroon(&[("invoices", &["read", "write"])], &[])).unwrap();
    std::fs::write(dir.join("info.macaroon"), macaroon(&[("info", &["read"])], &[])).unwrap();
    let mut v = json!({"listen": "127.0.0.1:0", "public_url": "https://seller.example", "upstream": "http://127.0.0.1:8080", "state_dir": dir.join("state"),
        "chain": "regtest", "network": "lightning:00000000000000000000000000000001",
        "node": {"rest": "http://127.0.0.1:1", "macaroon": dir.join("invoices.macaroon"), "info_macaroon": dir.join("info.macaroon")},
        "routes": [{"path": "/files/", "price": {"byte_msat": 1000, "per_bytes": 1048576}}]});
    edit(&mut v);
    let path = dir.join("gateway.json");
    std::fs::write(&path, v.to_string()).unwrap();
    path
}

/// `xbt-gateway --check <config>`: whether it succeeded, and what it wrote to standard error.
fn check(path: &Path) -> (bool, String) {
    let out = Command::new(BIN).arg("--check").arg(path).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn mainnet(v: &mut Value) {
    v["chain"] = json!("main");
    v.as_object_mut().unwrap().remove("network");
}

#[test]
fn mainnet_is_asked_for_twice_and_a_start_on_it_says_what_is_open() {
    let d = tempfile::tempdir().unwrap();
    // a regtest file starts with no notice
    let (ok, said) = check(&config(d.path(), &|_| {}));
    assert!(ok && said.contains("chain regtest") && !said.contains("docs/LIMITS.md"), "{said}");
    // a file that names no chain is a regtest file too
    let (ok, said) = check(&config(d.path(), &|v| {
        v.as_object_mut().unwrap().remove("chain");
    }));
    assert!(ok && said.contains("chain regtest"), "{said}");
    // chain main alone: nothing starts, and the runner is told the second key
    let (ok, said) = check(&config(d.path(), &mainnet));
    assert!(!ok && said.contains("mainnet_ack") && said.contains(MAINNET_ACK), "{said}");
    // with it, the open items are printed before anything else is said
    let (ok, said) = check(&config(d.path(), &|v| {
        mainnet(v);
        v["mainnet_ack"] = json!(MAINNET_ACK);
    }));
    assert!(ok, "{said}");
    let (notice, summary) = (said.find("docs/LIMITS.md").expect("the notice"), said.find("chain main, 1 routes").expect("the summary"));
    assert!(notice < summary && said.contains("regtest only") && said.contains("dust limit") && said.contains("TLS proxy"), "{said}");
}

#[test]
fn the_binary_does_not_listen_off_loopback_without_an_https_origin() {
    let d = tempfile::tempdir().unwrap();
    let (ok, said) = check(&config(d.path(), &|v| {
        v["listen"] = json!("0.0.0.0:8402");
        v["public_url"] = json!("http://seller.example");
    }));
    assert!(!ok && said.contains("not a loopback address"), "{said}");
    let (ok, said) = check(&config(d.path(), &|v| v["listen"] = json!("0.0.0.0:8402")));
    assert!(ok, "{said}");
}

#[test]
fn a_node_that_is_not_of_the_lnd_family_stops_the_start_with_a_reason() {
    // a node that answers getinfo in Core Lightning's names
    struct Cln;
    impl xbt_svc::http::Handler for Cln {
        fn body_limit(&self, _m: &str, _t: &str) -> usize {
            0
        }
        fn handle(&self, _req: xbt_svc::http::Request) -> xbt_svc::http::Response {
            xbt_svc::http::Response::text(200, "application/json", r#"{"id": "02", "alias": "seller", "blockheight": 7, "network": "regtest"}"#)
        }
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let node = xbt_svc::http::serve(std::sync::Arc::new(Cln), l, 2).unwrap();
    let d = tempfile::tempdir().unwrap();
    let path = config(d.path(), &|v| v["node"]["rest"] = json!(format!("http://{}", node.addr)));
    // the check says what kind of node it must be; the start finds it is not, and says so, at once
    let (ok, said) = check(&path);
    assert!(ok && said.contains("lnd-family node") && said.contains("Core Lightning seller is not supported"), "{said}");
    let mut child = Command::new(BIN).arg(&path).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            panic!("the gateway waited for a node that will never answer as one it can use");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let mut said = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut said).unwrap();
    assert!(!status.success() && said.contains("not an lnd-family node") && said.contains("Core Lightning's names"), "{said}");
    node.stopper().stop();
}
