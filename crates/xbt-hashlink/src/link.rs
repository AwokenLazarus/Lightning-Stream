//! A link: the Noise transport over one TCP stream, split into a reader (owned by one thread)
//! and a writer that any thread may use.

use crate::msg::Msg;
use crate::noise::{self, Cipher, Error};
use secp256k1::{PublicKey, SecretKey};
use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The sending half. Cloning shares it.
#[derive(Clone)]
pub struct Sender {
    inner: Arc<Mutex<(TcpStream, Cipher)>>,
}

impl Sender {
    pub fn send(&self, m: &Msg) -> Result<(), Error> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let frame = g.1.encrypt(&m.to_bytes())?;
        g.0.write_all(&frame)?;
        Ok(())
    }

    /// Whether `other` sends on the same link as this one.
    pub fn same(&self, other: &Sender) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Take over `other`'s stream: after a link dropped and a new one was made, every clone of
    /// this sender sends on the new one. The old stream goes with `other`.
    pub fn adopt(&self, other: Sender) {
        if Arc::ptr_eq(&self.inner, &other.inner) {
            return;
        }
        let mut mine = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut theirs = other.inner.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::swap(&mut *mine, &mut *theirs);
        let _ = theirs.0.shutdown(std::net::Shutdown::Both);
    }

    /// Close the stream both ways (the reader then ends).
    pub fn shutdown(&self) {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let _ = g.0.shutdown(std::net::Shutdown::Both);
    }
}

/// The receiving half.
pub struct Receiver {
    stream: TcpStream,
    cipher: Cipher,
}

impl Receiver {
    /// The next message; `Ok(None)` for one that does not parse (it is skipped).
    pub fn recv(&mut self) -> Result<Option<Msg>, Error> {
        let b = noise::read_msg(&mut self.stream, &mut self.cipher)?;
        Ok(Msg::from_bytes(&b))
    }
}

/// A link made: both halves and the peer's static key.
pub struct Link {
    pub tx: Sender,
    pub rx: Receiver,
    pub remote: PublicKey,
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the hashtaker waits for the hashmaker's address to answer. Without it a link that never
/// opens (an address that drops packets, a router without NAT reflection) waits on the system's TCP
/// timeout, minutes, and the rental looks live all that time.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// A TCP connection to `addr` (host:port), each of its addresses tried for at most `wait`.
pub fn connect_within(addr: &str, wait: Duration) -> std::io::Result<TcpStream> {
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, format!("{addr} resolves to nothing"));
    for a in std::net::ToSocketAddrs::to_socket_addrs(addr)? {
        match TcpStream::connect_timeout(&a, wait) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn split(stream: TcpStream, t: noise::Transport) -> Result<Link, Error> {
    stream.set_read_timeout(None)?;
    stream.set_nodelay(true)?;
    let w = stream.try_clone()?;
    Ok(Link {
        tx: Sender { inner: Arc::new(Mutex::new((w, t.send))) },
        rx: Receiver { stream, cipher: t.recv },
        remote: t.remote,
    })
}

/// The hashtaker's side: connect to the hashmaker, whose static key is known.
pub fn dial(addr: &str, me: SecretKey, hashmaker: PublicKey) -> Result<Link, Error> {
    let mut s = connect_within(addr, CONNECT_TIMEOUT)?;
    s.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let t = noise::connect(&mut s, noise::PROLOGUE, me, hashmaker)?;
    split(s, t)
}

/// The hashmaker's side: complete the handshake on an accepted stream.
pub fn answer(mut s: TcpStream, me: SecretKey) -> Result<Link, Error> {
    s.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let t = noise::accept(&mut s, noise::PROLOGUE, me)?;
    split(s, t)
}

#[cfg(test)]
mod connect_tests {
    use super::*;

    #[test]
    fn an_address_that_never_answers_fails_within_the_wait_not_the_systems_timeout() {
        // TEST-NET-1 (RFC 5737): routed nowhere, so it either drops (timeout) or is refused at once
        let t = std::time::Instant::now();
        assert!(connect_within("192.0.2.1:23341", Duration::from_millis(300)).is_err());
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(connect_within(&l.local_addr().unwrap().to_string(), Duration::from_secs(1)).is_ok());
    }
}

