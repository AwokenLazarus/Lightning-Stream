//! A minimal WebSocket (RFC 6455) over std TCP, with rustls for `wss://`: blocking, no async runtime.
//!
//! Enough for Nostr relays: the client's opening handshake (with the `Sec-WebSocket-Accept` check),
//! text messages (fragmented or not), ping/pong and close; masked frames from a client, unmasked from
//! a server; no extensions (a frame with a reserved bit set is refused). The server side
//! ([`WebSocket::accept`]) exists for the in-process stand-in relay the tests use.
//!
//! `ws://` (no TLS) is allowed only to a loopback address; anything else must be `wss://`, checked
//! against the Mozilla root list (`webpki-roots`).
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The largest message (all its fragments) this side accepts.
pub const MAX_MESSAGE: usize = 1 << 20;
const MAX_HEAD: usize = 16 * 1024;

pub trait Io: Read + Write + Send {}
impl<T: Read + Write + Send> Io for T {}

/// A received message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

/// A relay URL, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

fn is_loopback_host(h: &str) -> bool {
    let h = h.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost") || h.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// `wss://host[:port][/path][?query]`, or `ws://` to a loopback address. The host is kept as given
/// (a bracketed IPv6 literal keeps its brackets).
pub fn parse_url(url: &str) -> Result<WsUrl, String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (false, r)
    } else {
        return Err("a relay URL starts with wss://".into());
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return Err("a relay URL needs a host (and no user name)".into());
    }
    let (host, port) = if let Some(h) = authority.strip_prefix('[') {
        let close = h.find(']').ok_or("an IPv6 address needs its closing ]")?;
        let after = &h[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err("unexpected text after the IPv6 address".into()),
        };
        (format!("[{}]", &h[..close]), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.to_string(), None),
        }
    };
    let port = match port {
        Some(p) => p.parse::<u16>().map_err(|_| "the port is not a number")?,
        None if tls => 443,
        None => 80,
    };
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')) {
        return Err("the relay's host name has characters a host name cannot have".into());
    }
    if !tls && !is_loopback_host(&host) {
        return Err("ws:// (no TLS) only to this machine: a relay elsewhere is wss://".into());
    }
    let path = tail.split('#').next().unwrap_or("");
    let path = if path.is_empty() { "/".to_string() } else if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
    if path.bytes().any(|b| b <= b' ' || b >= 0x7f) {
        return Err("the relay URL's path has spaces or control characters".into());
    }
    Ok(WsUrl { tls, host: host.to_ascii_lowercase(), port, path })
}

fn accept_key(key: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, format!("{key}{GUID}").as_bytes());
    B64.encode(d.as_ref())
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("the ring provider's protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    }).clone()
}

/// Read an HTTP head (to the blank line), byte by byte so nothing after it is consumed.
fn read_head(io: &mut dyn Io) -> io::Result<String> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP head too long"));
        }
        if io.read(&mut b)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the connection closed during the handshake"));
        }
        head.push(b[0]);
    }
    String::from_utf8(head).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP head is not UTF-8"))
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

pub struct WebSocket {
    io: Box<dyn Io>,
    tcp: TcpStream,
    /// We are the client: our frames are masked, the peer's must not be.
    client: bool,
    buf: Vec<u8>,
    frag: Option<(u8, Vec<u8>)>,
}

impl WebSocket {
    /// Open `url` (TCP connect bounded by `timeout`, then the TLS and WebSocket handshakes).
    pub fn connect(url: &str, timeout: Duration) -> io::Result<Self> {
        let u = parse_url(url).map_err(bad)?;
        let bare = u.host.trim_start_matches('[').trim_end_matches(']').to_string();
        let addrs: Vec<_> = (bare.as_str(), u.port).to_socket_addrs()?.collect();
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address for the relay's host");
        let mut tcp = None;
        for a in addrs {
            match TcpStream::connect_timeout(&a, timeout) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let tcp = tcp.ok_or(last)?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        let mut io: Box<dyn Io> = if u.tls {
            let name = rustls::pki_types::ServerName::try_from(bare.clone()).map_err(|_| bad("the relay's host is not a valid TLS name"))?;
            let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| bad(format!("TLS: {e}")))?;
            Box::new(rustls::StreamOwned::new(conn, tcp.try_clone()?))
        } else {
            Box::new(tcp.try_clone()?)
        };
        let mut k = [0u8; 16];
        getrandom::getrandom(&mut k).expect("OS randomness");
        let key = B64.encode(k);
        let host = if (u.tls && u.port == 443) || (!u.tls && u.port == 80) { u.host.clone() } else { format!("{}:{}", u.host, u.port) };
        let req = format!("GET {} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n\
                           Sec-WebSocket-Version: 13\r\nUser-Agent: xbt-nostr\r\n\r\n", u.path);
        io.write_all(req.as_bytes())?;
        io.flush()?;
        let head = read_head(&mut *io)?;
        let status = head.lines().next().unwrap_or("");
        if status.split_whitespace().nth(1) != Some("101") {
            return Err(bad(format!("the relay refused the WebSocket upgrade: {}", status.chars().take(80).collect::<String>())));
        }
        if !header(&head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
            return Err(bad("the relay's answer has no Upgrade: websocket"));
        }
        if header(&head, "sec-websocket-accept") != Some(accept_key(&key).as_str()) {
            return Err(bad("the relay's Sec-WebSocket-Accept does not match our key"));
        }
        if header(&head, "sec-websocket-extensions").is_some_and(|v| !v.is_empty()) {
            return Err(bad("the relay chose a WebSocket extension we did not offer"));
        }
        Ok(Self { io, tcp, client: true, buf: Vec::new(), frag: None })
    }

    /// The server side of the handshake on an accepted TCP stream (the stand-in relay).
    pub fn accept(tcp: TcpStream) -> io::Result<Self> {
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut io: Box<dyn Io> = Box::new(tcp.try_clone()?);
        let head = read_head(&mut *io)?;
        let key = header(&head, "sec-websocket-key").ok_or_else(|| bad("no Sec-WebSocket-Key"))?.to_string();
        if !header(&head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
            return Err(bad("not a WebSocket upgrade"));
        }
        io.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                             accept_key(&key)).as_bytes())?;
        io.flush()?;
        Ok(Self { io, tcp, client: false, buf: Vec::new(), frag: None })
    }

    /// How long one [`Self::read`] waits for bytes before it answers `Ok(None)`.
    pub fn set_read_timeout(&self, t: Duration) -> io::Result<()> {
        self.tcp.set_read_timeout(Some(t))
    }

    /// Shut the TCP stream both ways (wakes a thread blocked on it).
    pub fn shutdown(&self) {
        let _ = self.tcp.shutdown(std::net::Shutdown::Both);
    }

    fn frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut f = Vec::with_capacity(payload.len() + 14);
        f.push(0x80 | opcode);
        let mask = if self.client { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => f.push(mask | n as u8),
            n if n <= 0xffff => {
                f.push(mask | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(mask | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        if self.client {
            let mut key = [0u8; 4];
            getrandom::getrandom(&mut key).expect("OS randomness");
            f.extend_from_slice(&key);
            f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        } else {
            f.extend_from_slice(payload);
        }
        self.io.write_all(&f)?;
        self.io.flush()
    }

    pub fn send_text(&mut self, s: &str) -> io::Result<()> {
        self.frame(0x1, s.as_bytes())
    }

    pub fn send_ping(&mut self, data: &[u8]) -> io::Result<()> {
        self.frame(0x9, data)
    }

    pub fn close(&mut self) {
        let _ = self.frame(0x8, &1000u16.to_be_bytes());
        self.shutdown();
    }

    /// One frame from the buffer, if a whole one is there: `(fin, opcode, payload)`.
    fn take_frame(&mut self) -> io::Result<Option<(bool, u8, Vec<u8>)>> {
        let b = &self.buf;
        if b.len() < 2 {
            return Ok(None);
        }
        if b[0] & 0x70 != 0 {
            return Err(bad("a WebSocket frame with a reserved bit set (no extension was agreed)"));
        }
        let (fin, opcode, masked) = (b[0] & 0x80 != 0, b[0] & 0x0f, b[1] & 0x80 != 0);
        if masked == self.client {
            return Err(bad(if self.client { "a masked frame from the server" } else { "an unmasked frame from the client" }));
        }
        let (len, mut at) = match b[1] & 0x7f {
            126 if b.len() >= 4 => (u16::from_be_bytes([b[2], b[3]]) as u64, 4),
            127 if b.len() >= 10 => (u64::from_be_bytes(b[2..10].try_into().expect("8 bytes")), 10),
            126 | 127 => return Ok(None),
            n => (n as u64, 2),
        };
        if len > MAX_MESSAGE as u64 {
            return Err(bad("a WebSocket frame larger than this side accepts"));
        }
        let key = if masked {
            if b.len() < at + 4 {
                return Ok(None);
            }
            at += 4;
            Some([b[at - 4], b[at - 3], b[at - 2], b[at - 1]])
        } else {
            None
        };
        let end = at + len as usize;
        if b.len() < end {
            return Ok(None);
        }
        let mut payload = b[at..end].to_vec();
        if let Some(k) = key {
            for (i, x) in payload.iter_mut().enumerate() {
                *x ^= k[i % 4];
            }
        }
        self.buf.drain(..end);
        Ok(Some((fin, opcode, payload)))
    }

    /// The next message; `Ok(None)` when none came within the read timeout. A ping is answered here
    /// (and also returned); a close is answered and returned as [`Msg::Close`].
    pub fn read(&mut self) -> io::Result<Option<Msg>> {
        loop {
            while let Some((fin, op, payload)) = self.take_frame()? {
                match op {
                    0x8 => {
                        let _ = self.frame(0x8, payload.get(..2).unwrap_or(&[]));
                        return Ok(Some(Msg::Close));
                    }
                    0x9 | 0xA if !fin || payload.len() > 125 => return Err(bad("a fragmented or oversized control frame")),
                    0x9 => {
                        self.frame(0xA, &payload)?;
                        return Ok(Some(Msg::Ping(payload)));
                    }
                    0xA => return Ok(Some(Msg::Pong(payload))),
                    0x0 => {
                        let Some((first, mut acc)) = self.frag.take() else { return Err(bad("a continuation frame with nothing to continue")) };
                        if acc.len() + payload.len() > MAX_MESSAGE {
                            return Err(bad("a WebSocket message larger than this side accepts"));
                        }
                        acc.extend(payload);
                        if fin {
                            return Self::whole(first, acc).map(Some);
                        }
                        self.frag = Some((first, acc));
                    }
                    0x1 | 0x2 => {
                        if self.frag.is_some() {
                            return Err(bad("a new message in the middle of a fragmented one"));
                        }
                        if fin {
                            return Self::whole(op, payload).map(Some);
                        }
                        self.frag = Some((op, payload));
                    }
                    _ => return Err(bad("an unknown WebSocket opcode")),
                }
            }
            let mut tmp = [0u8; 16 * 1024];
            match self.io.read(&mut tmp) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the connection closed")),
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                    if self.buf.len() > MAX_MESSAGE + 16 {
                        return Err(bad("a WebSocket frame larger than this side accepts"));
                    }
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    fn whole(op: u8, data: Vec<u8>) -> io::Result<Msg> {
        if op == 0x1 {
            String::from_utf8(data).map(Msg::Text).map_err(|_| bad("a text message that is not UTF-8"))
        } else {
            Ok(Msg::Binary(data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_rfc6455_example() {
        // RFC 6455 section 1.3
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn urls() {
        let u = parse_url("wss://relay.example.com").unwrap();
        assert_eq!((u.tls, u.host.as_str(), u.port, u.path.as_str()), (true, "relay.example.com", 443, "/"));
        let u = parse_url("wss://relay.example.com:7447/nostr?x=1").unwrap();
        assert_eq!((u.port, u.path.as_str()), (7447, "/nostr?x=1"));
        let u = parse_url("ws://127.0.0.1:9000").unwrap();
        assert_eq!((u.tls, u.port), (false, 9000));
        assert!(parse_url("ws://[::1]:9000").is_ok());
        assert!(parse_url("ws://relay.example.com").is_err(), "plain ws only on loopback");
        assert!(parse_url("https://relay.example.com").is_err());
        assert!(parse_url("wss://user@relay.example.com").is_err());
        assert!(parse_url("wss://relay.example.com/a b").is_err());
    }

    #[test]
    fn frames_both_ways_and_fragments() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut ws = WebSocket::accept(s).unwrap();
            let mut got = vec![];
            while got.len() < 2 {
                if let Some(m) = ws.read().unwrap() {
                    got.push(m);
                }
            }
            // a fragmented text message, unmasked from the server
            ws.io.write_all(&[0x01, 3, b'a', b'b', b'c', 0x80, 2, b'd', b'e']).unwrap();
            ws.send_text(&"x".repeat(70_000)).unwrap();
            got
        });
        let mut c = WebSocket::connect(&format!("ws://{addr}"), Duration::from_secs(5)).unwrap();
        c.send_text("hello").unwrap();
        c.send_text(&"y".repeat(300)).unwrap();
        let got = srv.join().unwrap();
        assert_eq!(got, vec![Msg::Text("hello".into()), Msg::Text("y".repeat(300))]);
        let mut msgs = vec![];
        while msgs.len() < 2 {
            if let Some(m) = c.read().unwrap() {
                msgs.push(m);
            }
        }
        assert_eq!(msgs[0], Msg::Text("abcde".into()));
        assert_eq!(msgs[1], Msg::Text("x".repeat(70_000)));
    }
}
