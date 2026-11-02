//! Two hops: a buyer's flow sealed for the exit, so the first hop carries bytes it cannot read.
//!
//! Through a first hop, each flow is one TLS 1.3 session between the buyer's app and the exit,
//! inside a stream the hop only joins to another. Both ends are authenticated by raw public keys
//! (RFC 7250): the exit by its link key, which the buyer already knows from the exit's listing, and
//! the buyer by a key of its own that names no person or address. So:
//! - the **first hop** sees the buyer's address and which exit it asked for, but neither the
//!   destination nor the bytes;
//! - the **exit** sees the destination and the bytes, and the hop's address, never the buyer's.
//!
//! No certificate authority takes part: a key is checked byte for byte against the one expected.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32-byte key follows it.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// The DER prefix of an Ed25519 PKCS#8 (v1) private key; the 32-byte seed follows it.
const ED25519_PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

/// The name a buyer puts in its ClientHello. Nothing checks it: the exit's key is what counts.
pub const SEALED_NAME: &str = "exit.stream.invalid";

/// An Ed25519 public key as a SubjectPublicKeyInfo, the form a raw public key travels in.
pub fn spki(public: &[u8; 32]) -> Vec<u8> {
    let mut v = ED25519_SPKI_PREFIX.to_vec();
    v.extend_from_slice(public);
    v
}

/// The Ed25519 public key of a SubjectPublicKeyInfo, if it is one.
pub fn key_of(spki_der: &[u8]) -> Option<[u8; 32]> {
    let rest = spki_der.strip_prefix(&ED25519_SPKI_PREFIX[..])?;
    rest.try_into().ok()
}

/// The Ed25519 public key of a 32-byte secret (seed).
pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    use ring::signature::KeyPair;
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(secret).expect("any 32 bytes are an Ed25519 seed");
    kp.public_key().as_ref().try_into().expect("an Ed25519 public key is 32 bytes")
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn certified(secret: &[u8; 32]) -> Arc<CertifiedKey> {
    let mut der = ED25519_PKCS8_PREFIX.to_vec();
    der.extend_from_slice(secret);
    let key = rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(der)).expect("an Ed25519 key");
    Arc::new(CertifiedKey::new(vec![CertificateDer::from(spki(&public_of(secret)))], key))
}

fn algs() -> WebPkiSupportedAlgorithms {
    provider().signature_verification_algorithms
}

fn check13(message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
    verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(cert.as_ref()), dss, &algs())
}

/// The exit's side: it shows its link key, and requires a key from the buyer (any key: the buyer's
/// key names nobody; the exit counts and limits flows by it).
pub fn exit_config(exit_secret: &[u8; 32]) -> Arc<ServerConfig> {
    let resolver = Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified(exit_secret)));
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 with ring")
        .with_client_cert_verifier(Arc::new(AnyBuyerKey))
        .with_cert_resolver(resolver);
    Arc::new(cfg)
}

/// The buyer's side: it accepts only the exit whose link key is `exit_public`, and shows its own key.
pub fn buyer_config(buyer_secret: &[u8; 32], exit_public: &[u8; 32]) -> Arc<ClientConfig> {
    let resolver = Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified(buyer_secret)));
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 with ring")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedExit { spki: spki(exit_public) }))
        .with_client_cert_resolver(resolver);
    Arc::new(cfg)
}

/// The buyer's key an exit's TLS session was made with.
pub fn buyer_key<T>(conn: &rustls::ConnectionCommon<T>) -> Option<[u8; 32]> {
    key_of(conn.peer_certificates()?.first()?.as_ref())
}

/// Accepts the one exit key it was given, nothing else.
#[derive(Debug)]
struct PinnedExit {
    spki: Vec<u8>,
}

impl ServerCertVerifier for PinnedExit {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if intermediates.is_empty() && end_entity.as_ref() == self.spki.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        check13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Requires a buyer key and checks the buyer holds it; which key it is, is the exit's to count.
#[derive(Debug)]
struct AnyBuyerKey;

impl ClientCertVerifier for AnyBuyerKey {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], _now: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        if intermediates.is_empty() && key_of(end_entity.as_ref()).is_some() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        check13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_round_trips_through_its_spki() {
        let p = public_of(&[7; 32]);
        assert_eq!(key_of(&spki(&p)), Some(p));
        assert_eq!(key_of(&[0u8; 44]), None);
    }
}
