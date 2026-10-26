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

/// The buyer's side: connect to the hasher, whose static key is known.
pub fn dial(addr: &str, me: SecretKey, hasher: PublicKey) -> Result<Link, Error> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let t = noise::connect(&mut s, noise::PROLOGUE, me, hasher)?;
    split(s, t)
}

/// The hasher's side: complete the handshake on an accepted stream.
pub fn answer(mut s: TcpStream, me: SecretKey) -> Result<Link, Error> {
    s.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let t = noise::accept(&mut s, noise::PROLOGUE, me)?;
    split(s, t)
}
