//! The hashrate link over iroh: no port forward on either side.
//!
//! The hashlink itself does not change. It is still one TCP connection per rental carrying a BOLT 8
//! Noise_XK handshake and messages, keyed to the hashmaker's static key that its listing names. Only
//! the road under it changes: instead of the hashtaker connecting to an address the hashmaker has
//! forwarded through its router, both apps open an iroh link (QUIC, through our relay or directly
//! where the two routers allow it) and each Noise connection rides one stream on it.
//!
//! * The hashmaker runs [`serve`]: its iroh key is derived from its hashmaker key, and every stream a
//!   hashtaker opens becomes a TCP connection to its own link listener on loopback, which answers
//!   the Noise handshake exactly as it does for a hashtaker on its LAN.
//! * The hashtaker runs a [`Dialer`] and asks it for a loopback address that leads to a listing's
//!   iroh key; it then dials that address with the Noise handshake as before.
//!
//! What the iroh key does not need: a vouching signature. The Noise handshake inside the stream
//! proves the hashmaker's key; a listing naming the wrong iroh key leads to a handshake that fails.
//! And a relay carries only QUIC's ciphertext, inside which the Noise ciphertext is again sealed: it
//! can delay or drop traffic, never read or alter a job or a share.

use crate::listing::IrohLink;
use secp256k1::SecretKey;
use sha2::{Digest, Sha256};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
pub use xbt_iroh_link::{Link, Options, Relays, DEFAULT_RELAY};

/// The iroh key of a hashmaker's link: derived from its hashmaker key, so it is stable without a
/// file of its own and a hashmaker that moves keeps it.
pub fn link_secret(hashmaker: &SecretKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"xbt-hashlink/iroh-key/0|");
    h.update(hashmaker.secret_bytes());
    h.finalize().into()
}

/// Where the relays come from: `ours` names relays (our own by default), `none` turns relays off
/// (direct only: for a LAN or a test).
pub fn relays(spec: Option<&str>) -> Relays {
    match spec.map(str::trim) {
        Some("none") => Relays::None,
        Some(list) if !list.is_empty() => Relays::OursThenPublic(list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()),
        _ => Relays::OursThenPublic(vec![DEFAULT_RELAY.to_string()]),
    }
}

/// The loopback form of a listen address: a link listener bound to every address (`0.0.0.0:23341`)
/// is reached on `127.0.0.1:23341`.
fn loopback(listen: &str) -> io::Result<SocketAddr> {
    let a = listen.to_socket_addrs()?.next().ok_or_else(|| io::Error::other("no address"))?;
    Ok(if a.ip().is_unspecified() { (Ipv4Addr::LOCALHOST, a.port()).into() } else { a })
}

/// A hashmaker's link: serves hashtakers' streams into its own link listener at `link_listen`.
pub fn serve(hashmaker: &SecretKey, relays: Relays, link_listen: &str) -> io::Result<Arc<Link>> {
    let link = Link::start_alpn(link_secret(hashmaker), Options { relays, serving: true, private: false, lookup: None }, xbt_iroh_link::ALPN_HASHLINK)?;
    link.serve(loopback(link_listen)?);
    Ok(link)
}

/// What a hashmaker's listing says of its link: its iroh key and the relay it can be found through.
/// Direct addresses are left out: they change, they would tell every reader the hashmaker's address,
/// and iroh finds the direct path itself once both ends meet at the relay.
pub fn advertise(link: &Link, wait: Duration) -> IrohLink {
    let h = link.hints(wait);
    IrohLink { id: link.endpoint_id(), relays: h.relays, direct: Vec::new() }
}

/// A hashtaker's side: one iroh link for all its rentals.
pub struct Dialer {
    link: Arc<Link>,
}

impl Dialer {
    /// A hashtaker's link. Its iroh key is a fresh one each start: the hashmaker knows the hashtaker
    /// by the key of its Noise handshake, not by this.
    pub fn start(relays: Relays) -> io::Result<Dialer> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Dialer { link: Link::start_alpn(secret, Options { relays, serving: false, private: false, lookup: None }, xbt_iroh_link::ALPN_HASHLINK)? })
    }

    /// A hashtaker's link that never takes a direct path: relays only. Neither end learns the
    /// other's IP address; the relay sees both, and the volume, never the content.
    pub fn start_private(relays: Relays) -> io::Result<Dialer> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Dialer { link: Link::start_alpn(secret, Options { relays, serving: false, private: true, lookup: None }, xbt_iroh_link::ALPN_HASHLINK)? })
    }

    /// A loopback address that leads to the hashmaker this listing names: give it to the hashlink
    /// in place of a TCP address.
    pub fn address_for(&self, iroh: &IrohLink) -> io::Result<String> {
        let direct = iroh.direct.iter().filter_map(|d| d.parse().ok()).collect();
        self.link.learn(&iroh.id, xbt_iroh_link::Hints { relays: iroh.relays.clone(), direct })?;
        let port = self.link.local_port(&iroh.id)?;
        Ok(format!("127.0.0.1:{port}"))
    }

    /// Whether the link to this hashmaker runs direct or through a relay now, for display.
    pub fn path(&self, iroh: &IrohLink) -> Option<xbt_iroh_link::Path> {
        self.link.path(&iroh.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hashmakers_iroh_key_is_stable_and_not_its_hashmaker_key() {
        let k = crate::noise::fresh_key();
        assert_eq!(link_secret(&k), link_secret(&k));
        assert_ne!(link_secret(&k), k.secret_bytes());
        assert_ne!(link_secret(&k), link_secret(&crate::noise::fresh_key()));
    }

    #[test]
    fn relays_default_to_ours_and_none_turns_them_off() {
        assert!(matches!(relays(None), Relays::OursThenPublic(r) if r == vec![DEFAULT_RELAY.to_string()]));
        assert!(matches!(relays(Some("none")), Relays::None));
        assert!(matches!(relays(Some("https://a.example, https://b.example")), Relays::OursThenPublic(r) if r.len() == 2));
    }

    #[test]
    fn a_listener_on_every_address_is_reached_on_loopback() {
        assert_eq!(loopback("0.0.0.0:23341").unwrap(), SocketAddr::from((Ipv4Addr::LOCALHOST, 23341)));
        assert_eq!(loopback("127.0.0.1:5").unwrap().port(), 5);
    }
}
