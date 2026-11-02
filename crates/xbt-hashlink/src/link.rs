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
        if let Err(e) = g.0.write_all(&frame) {
            // past WRITE_TIMEOUT, or a closed link: part of a frame may have gone, so nothing more can follow it
            let _ = g.0.shutdown(std::net::Shutdown::Both);
            return Err(e.into());
        }
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

    /// As [`Receiver::recv`], for an answer that is due: past `wait` it is an error, and the link is
    /// closed, however the bytes came (a read's own timeout starts afresh with each byte).
    pub fn recv_within(&mut self, wait: Duration) -> Result<Option<Msg>, Error> {
        let done = close_after(self.stream.try_clone()?, wait);
        let r = self.recv();
        drop(done);
        r
    }
}

/// A link made: both halves and the peer's static key.
pub struct Link {
    pub tx: Sender,
    pub rx: Receiver,
    pub remote: PublicKey,
}

/// The most a handshake, and the answer that follows it, may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// A send that makes no progress for this long fails and closes the link. Each side sends while
/// holding its one lock, the hashmaker's over all its rentals and miners, and a link that stalled
/// with its buffers full would otherwise hold that lock for good.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
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

/// Closes `s` once `wait` is over, unless what this returns is dropped first.
fn close_after(s: TcpStream, wait: Duration) -> std::sync::mpsc::Sender<()> {
    let (done, over) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if over.recv_timeout(wait) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    });
    done
}

fn split(stream: TcpStream, t: noise::Transport) -> Result<Link, Error> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
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
    dial_within(addr, me, hashmaker, HANDSHAKE_TIMEOUT.max(CONNECT_TIMEOUT))
}

/// As [`dial`], with the connection and the handshake each given at most `wait`.
pub fn dial_within(addr: &str, me: SecretKey, hashmaker: PublicKey, wait: Duration) -> Result<Link, Error> {
    let wait = wait.max(Duration::from_millis(1));
    let mut s = connect_within(addr, wait.min(CONNECT_TIMEOUT))?;
    s.set_read_timeout(Some(wait.min(HANDSHAKE_TIMEOUT)))?;
    let done = close_after(s.try_clone()?, wait.min(HANDSHAKE_TIMEOUT));
    let t = noise::connect(&mut s, noise::PROLOGUE, me, hashmaker)?;
    drop(done);
    split(s, t)
}

/// The hashmaker's side: complete the handshake on an accepted stream.
pub fn answer(mut s: TcpStream, me: SecretKey) -> Result<Link, Error> {
    s.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let done = close_after(s.try_clone()?, HANDSHAKE_TIMEOUT);
    let t = noise::accept(&mut s, noise::PROLOGUE, me)?;
    drop(done);
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

    /// A peer that stops reading, with the connection open: sending ends in an error within a bound
    /// instead of blocking for good (each side sends while holding its one lock), and the link is closed,
    /// since a frame may have gone half out.
    #[test]
    fn a_send_to_a_peer_that_stopped_reading_fails_within_a_bound_and_closes_the_link() {
        let hk = noise::fresh_key();
        let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        // answers the handshake and never reads again
        let _peer = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let lk = answer(s, hk).unwrap();
            std::thread::sleep(Duration::from_secs(60));
            drop(lk);
        });
        let Link { tx, mut rx, .. } = dial(&addr, noise::fresh_key(), hpub).unwrap();
        let (done, ended) = std::sync::mpsc::channel();
        let sender = tx.clone();
        std::thread::spawn(move || {
            let line = "x".repeat(60_000);
            while sender.send(&Msg::Up { chan: 1, line: line.clone() }).is_ok() {}
            let _ = done.send(());
        });
        assert!(ended.recv_timeout(Duration::from_secs(30)).is_ok(), "a send to a peer that stopped reading is still blocked");
        assert!(tx.send(&Msg::Ping { n: 1 }).is_err(), "the link is closed after that");
        assert!(rx.recv().is_err(), "and its reader ends");
    }
}

