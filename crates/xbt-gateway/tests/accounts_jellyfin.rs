//! Buyers' own accounts in a real Jellyfin (docs/BUYER-ACCOUNTS.md), through the gateway. Not run
//! by default: it needs a Jellyfin, the seller's API key in a file, and the id of a library and of
//! an item in it.
//!
//! ```text
//! JF_URL=http://127.0.0.1:8096 JF_ADMIN_KEY_FILE=… JF_LIBRARY=… JF_ITEM=… \
//!   cargo test -p xbt-gateway --test accounts_jellyfin -- --ignored --nocapture
//! ```
//!
//! The accounts it makes are deleted at the end, with the seller's key.

mod common;

use common::*;
use serde_json::{json, Value};
use xbt402::xbt_primitives::{ecdsa, secp256k1};

struct Env {
    url: String,
    key_file: String,
    library: String,
    item: String,
}

fn env() -> Env {
    let v = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set"));
    Env { url: std::env::var("JF_URL").unwrap_or_else(|_| "http://127.0.0.1:8096".into()), key_file: v("JF_ADMIN_KEY_FILE"), library: v("JF_LIBRARY"), item: v("JF_ITEM") }
}

/// The buyer key of wallet `n`: a stand-in for what a wallet derives for this seller.
fn buyer_key(n: u8) -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&[n; 32]).unwrap()
}

/// Tell the seller, for this session, who the buyer is.
fn identify(b: &mut Buyer, n: u8) -> Got {
    let sk = buyer_key(n);
    let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::signing_only(), &sk);
    let msg = xbt402::ticket::buyer_message(&b.receipt_key, &b.session);
    b.call("identify", &json!({"buyer": hex::encode(pk.serialize()), "sig": hex::encode(ecdsa::sign(&sk, &msg))}))
}

/// A paid request of the buyer's, with a body.
fn ask(b: &mut Buyer, method: &str, target: &str, body: &[u8], secret: Option<&[u8; 32]>) -> Got {
    let sig = b.sign(method, target, body, secret, None);
    let ct = if body.is_empty() { vec![] } else { vec![("Content-Type", "application/json")] };
    let mut h: Vec<(&str, &str)> = vec![("PAYMENT-SIGNATURE", &sig)];
    h.extend(ct);
    let got = http(&b.addr, method, target, &h, body, None);
    b.used(&got);
    got
}

fn position(b: &mut Buyer, item: &str) -> u64 {
    let got = ask(b, "GET", &format!("/UserItems/{item}/UserData"), b"", None);
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    got.json()["PlaybackPositionTicks"].as_u64().unwrap_or(0)
}

fn set_position(b: &mut Buyer, item: &str, ticks: u64) {
    let got = ask(b, "POST", &format!("/UserItems/{item}/UserData"), json!({"PlaybackPositionTicks": ticks}).to_string().as_bytes(), None);
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
}

#[test]
#[ignore]
fn each_buyer_has_an_account_of_their_own_in_jellyfin() {
    let e = env();
    let admin = std::fs::read_to_string(&e.key_file).unwrap().lines().find(|l| !l.trim().is_empty()).unwrap().rsplit('=').next().unwrap().trim().to_string();
    // buyers' users left by an earlier run that stopped short
    let users: Value = ureq::get(&format!("{}/Users", e.url)).set("X-Emby-Token", &admin).call().unwrap().into_string().ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap();
    for u in users.as_array().unwrap().iter().filter(|u| u["Name"].as_str().unwrap_or("").starts_with("buyer-")) {
        let _ = ureq::delete(&format!("{}/Users/{}", e.url, u["Id"].as_str().unwrap())).set("X-Emby-Token", &admin).call();
    }
    let key_copy = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(&e.key_file, key_copy.path()).unwrap();
    let key_path = key_copy.path().to_string_lossy().to_string();
    let (rig, dir) = start(&|v| {
        v["upstream"] = json!(e.url);
        v["routes"] = json!([{"path": "/", "methods": ["GET", "HEAD", "POST", "DELETE"], "price": {"request_msat": 100}, "max_body": 65536, "websocket": true,
            "forward_headers": ["authorization", "x-emby-authorization", "x-mediabrowser-token", "x-emby-token"],
            "accounts": {"kind": "jellyfin", "admin_key_file": key_path, "libraries": [e.library]},
            "allow_paths": ["/", "/users/"], "deny_paths": ["/users", "/system/", "/devices", "/plugins/", "/packages/", "/scheduledtasks/", "/startup/", "/environment/"]}]);
    });
    // an anonymous session on a route with no guest: asked to say who it is first
    let mut anon = Buyer::new(&rig, 9);
    let s = anon.lock(&rig, 1);
    let got = ask(&mut anon, "GET", &format!("/UserItems/{}/UserData", e.item), b"", Some(&s[0]));
    assert_eq!((got.status, got.error()), (403, "identify_first".to_string()), "{}", String::from_utf8_lossy(&got.body));
    // a proof for another session is no good
    let mut a1 = Buyer::new(&rig, 1);
    let s1 = a1.lock(&rig, 1);
    let mut stolen = Buyer::new(&rig, 8);
    stolen.lock(&rig, 1);
    let sk = buyer_key(1);
    let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::signing_only(), &sk);
    let other_msg = xbt402::ticket::buyer_message(&a1.receipt_key, &a1.session);
    let got = stolen.call("identify", &json!({"buyer": hex::encode(pk.serialize()), "sig": hex::encode(ecdsa::sign(&sk, &other_msg))}));
    assert_eq!(got.status, 400, "a proof made for another session: {}", String::from_utf8_lossy(&got.body));
    // buyer 1: their own account, made at the first request; their resume point is theirs
    assert_eq!(identify(&mut a1, 1).status, 200);
    let first = ask(&mut a1, "GET", &format!("/UserItems/{}/UserData", e.item), b"", Some(&s1[0]));
    assert_eq!(first.status, 200, "{}", String::from_utf8_lossy(&first.body));
    set_position(&mut a1, &e.item, 1_111_000_000);
    assert_eq!(position(&mut a1, &e.item), 1_111_000_000);
    // the login page shows buyer 1 their own user only, without a password
    let public = ask(&mut a1, "GET", "/Users/Public", b"", None).json();
    let me = public.as_array().unwrap();
    assert_eq!(me.len(), 1, "{public}");
    assert_eq!(me[0]["HasPassword"], false);
    let my_id = me[0]["Id"].as_str().unwrap().to_string();
    // any login is buyer 1's own
    let login = ask(&mut a1, "POST", "/Users/AuthenticateByName", br#"{"Username":"seller-admin","Pw":"guess"}"#, None);
    assert_eq!(login.status, 200, "{}", String::from_utf8_lossy(&login.body));
    assert_eq!(login.json()["User"]["Id"], my_id.as_str(), "the login is the buyer's own account");
    assert_eq!(login.json()["User"]["Policy"]["IsAdministrator"], false);
    // buyer 2, on the same shop: another account, another resume point
    let mut a2 = Buyer::new(&rig, 2);
    let s2 = a2.lock(&rig, 1);
    assert_eq!(identify(&mut a2, 2).status, 200);
    assert_eq!(ask(&mut a2, "GET", &format!("/UserItems/{}/UserData", e.item), b"", Some(&s2[0])).status, 200);
    set_position(&mut a2, &e.item, 2_222_000_000);
    assert_eq!(position(&mut a1, &e.item), 1_111_000_000, "buyer 2's resume point is not buyer 1's");
    // another user's path is refused, whatever the client asks
    let other = ask(&mut a2, "GET", &format!("/Users/{my_id}/Items/{}", e.item), b"", None);
    assert_eq!(other.status, 403);
    // buyer 1 again, in a new session (another device with the same seed): the same account, the same history
    let mut again = Buyer::new(&rig, 3);
    let s3 = again.lock(&rig, 1);
    assert_eq!(identify(&mut again, 1).status, 200);
    assert_eq!(ask(&mut again, "GET", &format!("/UserItems/{}/UserData", e.item), b"", Some(&s3[0])).status, 200);
    assert_eq!(position(&mut again, &e.item), 1_111_000_000, "the same buyer, the same history");
    assert_eq!(position(&mut a2, &e.item), 2_222_000_000);
    // one account a buyer, made once
    let kept: Value = serde_json::from_str(&std::fs::read_to_string(dir.path().join("accounts.json")).unwrap()).unwrap();
    assert_eq!(kept.as_object().unwrap().len(), 2, "{kept}");
    let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(dir.path().join("accounts.json")).unwrap().permissions()) & 0o777;
    assert_eq!(mode, 0o600);
    // the seller's key rotated away: a new buyer's account is not made (and nothing falls back to the key or a guest);
    // the accounts already made keep working on their own logins
    std::fs::write(key_copy.path(), "JF_ADMIN_TOKEN=00000000000000000000000000000000\n").unwrap();
    let mut a4 = Buyer::new(&rig, 4);
    let s4 = a4.lock(&rig, 1);
    assert_eq!(identify(&mut a4, 4).status, 200);
    let refused = ask(&mut a4, "GET", &format!("/UserItems/{}/UserData", e.item), b"", Some(&s4[0]));
    assert_eq!((refused.status, refused.error()), (503, "accounts_unavailable".to_string()), "{}", String::from_utf8_lossy(&refused.body));
    assert_eq!(position(&mut again, &e.item), 1_111_000_000);
    // the key back; the seller removes buyer 2's user in Jellyfin itself: buyer 2's next request makes it anew
    // (a fresh account, its history gone with the old one) instead of a login that no longer works
    std::fs::copy(&e.key_file, key_copy.path()).unwrap();
    let id2 = kept.as_object().unwrap().values().map(|a| a["user_id"].as_str().unwrap().to_string())
        .find(|id| ureq::get(&format!("{}/Users/{id}", e.url)).set("X-Emby-Token", &admin).call().ok()
            .and_then(|r| r.into_string().ok()).and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .is_some_and(|u| u["Name"].as_str().is_some_and(|n| n.starts_with("buyer-")) && position_of(&e, &admin, &u, &e.item) == 2_222_000_000))
        .unwrap();
    ureq::delete(&format!("{}/Users/{id2}", e.url)).set("X-Emby-Token", &admin).call().unwrap();
    let back = ask(&mut a2, "GET", &format!("/UserItems/{}/UserData", e.item), b"", None);
    assert_eq!(back.status, 200, "made anew: {}", String::from_utf8_lossy(&back.body));
    // the accounts made here, deleted with the seller's real key
    let kept: Value = serde_json::from_str(&std::fs::read_to_string(dir.path().join("accounts.json")).unwrap()).unwrap();
    for (_, a) in kept.as_object().unwrap() {
        let id = a["user_id"].as_str().unwrap();
        let _ = ureq::delete(&format!("{}/Users/{id}", e.url)).set("X-Emby-Token", &admin).call();
    }
}

/// A user's resume point for `item`, asked with the seller's key.
fn position_of(e: &Env, admin: &str, user: &Value, item: &str) -> u64 {
    let id = user["Id"].as_str().unwrap_or("");
    ureq::get(&format!("{}/Users/{id}/Items/{item}", e.url)).set("X-Emby-Token", admin).call().ok()
        .and_then(|r| r.into_string().ok()).and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v["UserData"]["PlaybackPositionTicks"].as_u64()).unwrap_or(0)
}
