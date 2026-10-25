//! A package with no certificate file learns the node's from one TLS handshake, for the owner to
//! confirm and pin. `tests/data/node-tls/` holds a test certificate for 127.0.0.1 and its key (the
//! same as the signer's seller test data): test data only, public, protecting nothing.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

fn der(name: &str) -> Vec<u8> {
    use base64::Engine;
    let pem = std::fs::read_to_string(format!("{}/tests/data/node-tls/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(body).unwrap()
}

/// A TLS server on loopback with the test certificate, answering nothing.
fn node() -> u16 {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(der("seller.pem"))],
                rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(der("seller.key"))),
            )
            .unwrap(),
    );
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for sock in l.incoming().flatten() {
            let cfg = cfg.clone();
            std::thread::spawn(move || {
                let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), sock);
                let mut b = [0u8; 1];
                let _ = tls.read(&mut b);
                let _ = tls.flush();
            });
        }
    });
    port
}

#[test]
fn the_node_certificate_is_read_from_a_handshake_and_written_as_a_pinnable_pem() {
    let port = node();
    let got = xbt_gateway::node::peer_certificate(&format!("https://127.0.0.1:{port}"), Duration::from_secs(5)).unwrap();
    assert_eq!(got, der("seller.pem"));
    let pem = xbt_gateway::node::cert_pem(&got);
    assert_eq!(xbt_gateway::node::pem_cert_der(&pem).unwrap(), got, "the PEM is what the pinned client reads");
    assert!(xbt_gateway::node::peer_certificate("http://127.0.0.1:1", Duration::from_secs(1)).is_err(), "only https");
}
