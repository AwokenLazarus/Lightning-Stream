//! The flow protocol between a buyer's app and an exit, on one link connection
//! ([`xbt_iroh_link::ALPN_VPN`]).
//!
//! The buyer's app ends each device's connection on its own side and carries the flow, not the
//! packets:
//! - **A TCP connection** is one QUIC stream. The buyer writes a header naming the destination; the
//!   exit answers one status byte (opened, refused, unreachable), then the stream carries the
//!   connection's bytes each way. QUIC's own reliability and congestion control carry them, so no
//!   TCP ever runs on top of a lossy tunnel, and a relay costs only its speed.
//! - **UDP** goes in QUIC datagrams, each with a flow number; the first carries the destination.
//!
//! Each flow can go to a different exit, which is what lets a buyer spread its flows over several
//! exits while keeping each destination on one.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, Bytes, BytesMut};
use xbt_iroh_link::{LinkConnection, LinkRecvStream, LinkSendStream};

const MAGIC: &[u8; 3] = b"XF0";
const KIND_TCP: u8 = 1;
/// A UDP datagram, buyer to exit: flow number, destination, payload.
pub(crate) const KIND_UDP_OUT: u8 = 2;
/// A UDP datagram, exit to buyer: flow number, payload.
pub(crate) const KIND_UDP_BACK: u8 = 3;

/// The exit's answer to a TCP flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    Yes,
    /// The exit's policy refuses the destination (a blocked port, the seller's own network, IPv6 off).
    Refused,
    /// The exit could not reach the destination.
    Unreachable,
}

impl Opened {
    pub(crate) fn byte(self) -> u8 {
        match self {
            Opened::Yes => 0,
            Opened::Refused => 1,
            Opened::Unreachable => 2,
        }
    }

    fn from_byte(b: u8) -> Opened {
        match b {
            0 => Opened::Yes,
            1 => Opened::Refused,
            _ => Opened::Unreachable,
        }
    }
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

pub(crate) fn put_addr(b: &mut BytesMut, a: SocketAddr) {
    match a.ip() {
        IpAddr::V4(v4) => {
            b.put_u8(4);
            b.put_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            b.put_u8(6);
            b.put_slice(&v6.octets());
        }
    }
    b.put_u16(a.port());
}

/// Reads an address written by [`put_addr`] from the front of `b`; returns it and what follows.
pub(crate) fn take_addr(b: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let (ip, rest) = match *b.first()? {
        4 => (IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.get(1..5)?).ok()?)), &b[5..]),
        6 => (IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(1..17)?).ok()?)), &b[17..]),
        _ => return None,
    };
    let port = u16::from_be_bytes(<[u8; 2]>::try_from(rest.get(..2)?).ok()?);
    Some((SocketAddr::new(ip, port), &rest[2..]))
}

fn tcp_header(to: SocketAddr) -> BytesMut {
    let mut h = BytesMut::with_capacity(24);
    h.put_slice(MAGIC);
    h.put_u8(KIND_TCP);
    put_addr(&mut h, to);
    h
}

/// Opens a TCP flow to `to` through the exit. On [`Opened::Yes`] the streams carry the connection's
/// bytes; otherwise they are already closed.
pub async fn open_tcp(conn: &LinkConnection, to: SocketAddr) -> io::Result<(Opened, LinkSendStream, LinkRecvStream)> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(io_err)?;
    send.write_all(&tcp_header(to)).await.map_err(io_err)?;
    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await.map_err(io_err)?;
    Ok((Opened::from_byte(status[0]), send, recv))
}

/// Opens a TCP flow to `to` on a stream already joined to the exit (a sealed session through a
/// first hop, [`crate::hop`]).
pub async fn open_tcp_on<S>(s: &mut S, to: SocketAddr) -> io::Result<Opened>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(&tcp_header(to)).await?;
    s.flush().await?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).await?;
    Ok(Opened::from_byte(status[0]))
}

/// The exit's side: reads a TCP flow's header from a stream the buyer opened.
pub(crate) async fn read_tcp_header<R: tokio::io::AsyncRead + Unpin>(recv: &mut R) -> io::Result<SocketAddr> {
    use tokio::io::AsyncReadExt;
    let mut h = [0u8; 4];
    recv.read_exact(&mut h).await.map_err(io_err)?;
    if &h[..3] != MAGIC || h[3] != KIND_TCP {
        return Err(io_err("not a VPN flow"));
    }
    let mut fam = [0u8; 1];
    recv.read_exact(&mut fam).await.map_err(io_err)?;
    let len = match fam[0] {
        4 => 4,
        6 => 16,
        _ => return Err(io_err("not an address family")),
    };
    let mut rest = vec![0u8; len + 2];
    recv.read_exact(&mut rest).await.map_err(io_err)?;
    let mut all = vec![fam[0]];
    all.extend_from_slice(&rest);
    take_addr(&all).map(|(a, _)| a).ok_or_else(|| io_err("a bad address"))
}

/// Sends one UDP datagram of flow `flow` to `to` through the exit.
pub fn send_udp(conn: &LinkConnection, flow: u32, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let mut d = BytesMut::with_capacity(payload.len() + 24);
    d.put_u8(KIND_UDP_OUT);
    d.put_u32(flow);
    put_addr(&mut d, to);
    d.put_slice(payload);
    conn.send_datagram(d.freeze()).map_err(io_err)
}

/// The next UDP datagram the exit sent back: its flow number and payload.
pub async fn recv_udp(conn: &LinkConnection) -> io::Result<(u32, Bytes)> {
    loop {
        let d = conn.read_datagram().await.map_err(io_err)?;
        if d.len() >= 5 && d[0] == KIND_UDP_BACK {
            let flow = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
            return Ok((flow, d.slice(5..)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip() {
        for a in ["93.184.216.34:443", "[2606:4700::1111]:53"] {
            let a: SocketAddr = a.parse().unwrap();
            let mut b = BytesMut::new();
            put_addr(&mut b, a);
            b.put_slice(b"rest");
            let (back, rest) = take_addr(&b).unwrap();
            assert_eq!((back, rest), (a, &b"rest"[..]));
        }
        assert!(take_addr(&[4, 1, 2]).is_none());
        assert!(take_addr(&[9, 0, 0, 0, 0, 0, 0]).is_none());
    }
}
