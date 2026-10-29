//! The packet tunnel on one link connection.
//!
//! The buyer's side opens one stream on the connection and says hello: the protocol version and
//! whether packets may ride in QUIC datagrams. The stream stays open as the tunnel's control channel
//! and its fallback. Each packet goes in a datagram (one IP packet behind a one-byte kind) when the
//! path carries a datagram that big at that moment, and on the stream (behind a two-byte length)
//! when it does not. QUIC starts with small datagrams and raises the size as it discovers the path,
//! so the choice is made per packet; the receiving side reads both.
//!
//! A packet bigger than [`TUNNEL_MTU`] is refused, never fragmented: the buyer's interface is set to
//! that MTU so its own stack sizes packets to fit.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, Mutex};
use xbt_iroh_link::{LinkConnection, LinkRecvStream, LinkSendStream};

/// The largest IP packet the tunnel carries: IPv6's minimum link MTU.
pub const TUNNEL_MTU: usize = 1280;

const HELLO: &[u8; 3] = b"XV0";
const FLAG_DATAGRAMS: u8 = 1;
const KIND_IP: u8 = 1;
/// Packets received but not yet taken by [`Tunnel::recv`]; beyond this, reading waits.
const QUEUE: usize = 4096;

/// How many packets went each way of sending.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sent {
    pub in_datagrams: u64,
    pub on_stream: u64,
}

/// One buyer's tunnel to one exit.
pub struct Tunnel {
    conn: LinkConnection,
    datagrams: bool,
    send: Mutex<LinkSendStream>,
    incoming: Mutex<mpsc::Receiver<io::Result<Bytes>>>,
    sent_dgram: AtomicU64,
    sent_stream: AtomicU64,
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// Reads the connection's datagrams and the control stream's frames into one queue.
fn spawn_readers(conn: &LinkConnection, mut recv: LinkRecvStream, datagrams: bool) -> mpsc::Receiver<io::Result<Bytes>> {
    let (tx, rx) = mpsc::channel(QUEUE);
    let tx = Arc::new(tx);
    if datagrams {
        let (conn, tx) = (conn.clone(), tx.clone());
        tokio::spawn(async move {
            loop {
                match conn.read_datagram().await {
                    Ok(d) if d.first() == Some(&KIND_IP) => {
                        if tx.send(Ok(d.slice(1..))).await.is_err() {
                            return;
                        }
                    }
                    // a kind this version does not know is skipped, so a later one can add control frames
                    Ok(_) => {}
                    Err(e) => {
                        let _ = tx.send(Err(io_err(e))).await;
                        return;
                    }
                }
            }
        });
    }
    tokio::spawn(async move {
        loop {
            let mut len = [0u8; 2];
            let frame = async {
                recv.read_exact(&mut len).await.map_err(io_err)?;
                let mut f = vec![0u8; usize::from(u16::from_be_bytes(len))];
                recv.read_exact(&mut f).await.map_err(io_err)?;
                Ok::<_, io::Error>(Bytes::from(f))
            }
            .await;
            match frame {
                Ok(f) if f.first() == Some(&KIND_IP) => {
                    if tx.send(Ok(f.slice(1..))).await.is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
    });
    rx
}

impl Tunnel {
    /// The buyer's side: opens the control stream and says hello. `allow_datagrams: false` keeps every
    /// packet on the stream (for measuring it, or for a path known to drop datagrams). Call it inside a
    /// tokio runtime: the tunnel's readers run as tasks on it.
    pub async fn open(conn: LinkConnection, allow_datagrams: bool) -> io::Result<Tunnel> {
        let (mut send, recv) = conn.open_bi().await.map_err(io_err)?;
        send.write_all(&[HELLO[0], HELLO[1], HELLO[2], if allow_datagrams { FLAG_DATAGRAMS } else { 0 }]).await.map_err(io_err)?;
        Ok(Self::new(conn, allow_datagrams, send, recv))
    }

    /// The exit's side: takes the control stream and the buyer's hello.
    pub async fn accept(conn: LinkConnection) -> io::Result<Tunnel> {
        let (send, mut recv) = conn.accept_bi().await.map_err(io_err)?;
        let mut hello = [0u8; 4];
        recv.read_exact(&mut hello).await.map_err(io_err)?;
        if &hello[..3] != HELLO {
            return Err(io_err("not a VPN tunnel hello"));
        }
        Ok(Self::new(conn, hello[3] & FLAG_DATAGRAMS != 0, send, recv))
    }

    fn new(conn: LinkConnection, datagrams: bool, send: LinkSendStream, recv: LinkRecvStream) -> Tunnel {
        let incoming = spawn_readers(&conn, recv, datagrams);
        Tunnel { conn, datagrams, send: Mutex::new(send), incoming: Mutex::new(incoming), sent_dgram: AtomicU64::new(0), sent_stream: AtomicU64::new(0) }
    }

    /// The largest datagram the connection's path carries now, if any.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// How many packets this side sent in datagrams and on the stream.
    pub fn sent(&self) -> Sent {
        Sent { in_datagrams: self.sent_dgram.load(Ordering::Relaxed), on_stream: self.sent_stream.load(Ordering::Relaxed) }
    }

    /// Sends one IP packet. Waits while the connection's send buffer is full, so a fast sender is
    /// paced by the path instead of losing packets locally.
    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > TUNNEL_MTU {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet bigger than the tunnel MTU"));
        }
        if self.datagrams && self.conn.max_datagram_size().is_some_and(|n| n > packet.len()) {
            let mut d = BytesMut::with_capacity(packet.len() + 1);
            d.extend_from_slice(&[KIND_IP]);
            d.extend_from_slice(packet);
            match self.conn.send_datagram_wait(d.freeze()).await {
                Ok(()) => {
                    self.sent_dgram.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                // the path's datagram size can shrink between the check and the send (a path change):
                // this packet goes on the stream instead
                Err(xbt_iroh_link::SendDatagramError::TooLarge) => {}
                Err(e) => return Err(io_err(e)),
            }
        }
        {
            let mut f = Vec::with_capacity(packet.len() + 3);
            f.extend_from_slice(&(packet.len() as u16 + 1).to_be_bytes());
            f.push(KIND_IP);
            f.extend_from_slice(packet);
            self.send.lock().await.write_all(&f).await.map_err(io_err)?;
            self.sent_stream.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Receives the next IP packet, from a datagram or the stream.
    pub async fn recv(&self) -> io::Result<Bytes> {
        self.incoming.lock().await.recv().await.unwrap_or_else(|| Err(io_err("the tunnel has closed")))
    }

    /// Closes the tunnel's connection.
    pub fn close(&self, why: &str) {
        self.conn.close(0u32.into(), why.as_bytes());
    }
}
