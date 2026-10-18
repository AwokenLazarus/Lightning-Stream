//! A seller on a LAN: the owner's `tickets.seller_tls` names, for a seller it names, the CA file or
//! the one certificate its https is checked against in place of the public certificate
//! authorities. Here the wire itself, over real TLS on loopback: with nothing named, a certificate
//! no public authority issued is refused, as before; with the seller's CA it is taken, and with
//! another CA it is not; with the certificate's pin it is taken, and with another pin it is not.
//! (That the signer names an entry for a named seller only is `ticket_pay.rs`.)
//!
//! `tests/data/seller-tls/` was made once with openssl, valid for 100 years: `ca.pem` a test CA,
//! `seller.pem` and `seller.key` a certificate for 127.0.0.1 and localhost that `ca.pem` issued,
//! `other-ca.pem` a CA that did not. Test data only: the keys are public here and protect nothing.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256};
use xbt_signer::ticket::SellerTls;
use xbt_signer::ticket_pay::{TicketWire, UreqWire};

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/seller-tls").join(name)
}

/// The base64 body of the first PEM block of `name`.
fn der(name: &str) -> Vec<u8> {
    let pem = std::fs::read_to_string(data(name)).unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(body).unwrap()
}

/// A seller over https on loopback, with `seller.pem`: every request is answered 200 "paid page".
fn seller() -> u16 {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = Arc::new(rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(der("seller.pem"))],
                          rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(der("seller.key"))))
        .unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for sock in l.incoming().flatten() {
            let cfg = cfg.clone();
            std::thread::spawn(move || {
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), sock);
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match tls.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return, // the client refused the certificate, or went away
                    }
                }
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\npaid page");
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

fn get(wire: &UreqWire, port: u16, tls: Option<&SellerTls>) -> Result<String, String> {
    let ans = wire.send_with("GET", &format!("https://127.0.0.1:{port}/page"), b"", &[], Duration::from_secs(5), tls).map_err(|e| format!("{}: {}", e.code, e.msg))?;
    let mut body = String::new();
    let mut r = ans.body;
    r.read_to_string(&mut body).map_err(|e| e.to_string())?;
    Ok(format!("{} {body}", ans.status))
}

#[test]
fn a_named_sellers_own_ca_or_pinned_certificate_is_taken_and_nothing_else_is() {
    let port = seller();
    let wire = UreqWire::default();
    // nothing named: the public authorities, which did not issue this certificate
    let no = get(&wire, port, None);
    assert!(no.is_err(), "a certificate of a private CA was taken with the public roots: {no:?}");
    assert!(wire.send("GET", &format!("https://127.0.0.1:{port}/page"), b"", &[], Duration::from_secs(5)).is_err());
    // the CA that issued it
    assert_eq!(get(&wire, port, Some(&SellerTls::CaFile(data("ca.pem")))).unwrap(), "200 paid page");
    // another CA, and a CA file that is not there
    assert!(get(&wire, port, Some(&SellerTls::CaFile(data("other-ca.pem")))).is_err());
    let gone = get(&wire, port, Some(&SellerTls::CaFile(data("no-such.pem")))).unwrap_err();
    assert!(gone.starts_with("seller_tls:"), "{gone}");
    // the certificate's own pin, and another
    let pin: [u8; 32] = Sha256::digest(der("seller.pem")).into();
    assert_eq!(get(&wire, port, Some(&SellerTls::CertSha256(pin))).unwrap(), "200 paid page");
    let mut other = pin;
    other[0] ^= 1;
    assert!(get(&wire, port, Some(&SellerTls::CertSha256(other))).is_err());
    // and with the public roots again, after the others were cached: still refused
    assert!(get(&wire, port, None).is_err());
}

#[test]
fn the_policy_takes_a_seller_tls_entry_only_well_formed_and_says_it_is_a_test_aid() {
    let pin = "ab".repeat(32);
    let base = |tls: serde_json::Value| json!({"allowlist": ["https://seller.lan:8443"], "tickets": {"seller_tls": tls}});
    let (errors, warnings) = xbt_signer::policy::validate_policy(&base(json!({"https://seller.lan:8443": {"cert_sha256": pin}})));
    assert!(errors.is_empty(), "{errors:?}");
    assert!(warnings.iter().any(|w| w.contains("test aid") && w.contains("stand in for the seller")), "{warnings:?}");
    // an entry for an origin off the allowlist is never used, and the owner is told
    let (errors, warnings) = xbt_signer::policy::validate_policy(&base(json!({"https://other.lan": {"ca_file": "/etc/lan-ca.pem"}})));
    assert!(errors.is_empty() && warnings.iter().any(|w| w.contains("not on the allowlist, so never used")), "{errors:?} {warnings:?}");
    for (bad, why) in [(json!({"http://seller.lan:8443": {"cert_sha256": pin}}), "not an https origin"),
                       (json!({"https://seller.lan:8443/path": {"cert_sha256": pin}}), "not an https origin"),
                       (json!({"https://seller.lan:8443": {"cert_sha256": "abc"}}), "64 hex"),
                       (json!({"https://seller.lan:8443": {"ca_file": "lan-ca.pem"}}), "absolute path"),
                       (json!({"https://seller.lan:8443": {"ca_file": "/a.pem", "cert_sha256": pin}}), "exactly one key"),
                       (json!({"https://seller.lan:8443": "/a.pem"}), "must be an object"),
                       (json!(["https://seller.lan:8443"]), "must be an object")] {
        let (errors, _) = xbt_signer::policy::validate_policy(&base(bad.clone()));
        assert!(errors.iter().any(|e| e.contains(why)), "{bad}: {errors:?}");
    }
    // what the signer reads: the well-formed entries for https origins, nothing else
    let m = json!({"seller_tls": {"https://seller.lan:8443": {"cert_sha256": pin}, "https://bad.lan": {"cert_sha256": "x"},
                                  "http://plain.lan": {"ca_file": "/a.pem"}, "https://ca.lan/": {"ca_file": "/etc/lan-ca.pem"}}});
    let p = xbt_signer::ticket::TicketPolicy::from_map(m.as_object().unwrap());
    let keys: Vec<&String> = p.seller_tls.keys().collect();
    assert_eq!(keys, ["https://ca.lan", "https://seller.lan:8443"]);
    assert_eq!(p.seller_tls["https://ca.lan"], SellerTls::CaFile("/etc/lan-ca.pem".into()));
}
