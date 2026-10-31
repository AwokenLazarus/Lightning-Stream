//! Many flows over one byte stream: how a **paid tunnel** carries a device's flows.
//!
//! A paid exit is reached through the buyer's wallet: one Stream call per device, a two-way byte
//! stream (a WebSocket the wallet pays for as its bytes pass, docs/VPN-EXITS.md). On it, this
//! multiplexer carries what the link connection carries straight ([`crate::flow`]): each TCP flow
//! as a stream of its own, each UDP datagram as a frame.
//!
//! Frames: kind (1 byte), stream id (4), length (4), then that many bytes.
//! - `OPEN`: the opener's new stream (no payload). The buyer opens odd ids, the exit even ones.
//! - `DATA`: bytes on a stream, at most [`MAX_FRAME`].
//! - `FIN`: the sender will write no more on the stream; `RST`: the stream is gone either way.
//! - `WINDOW`: the receiver read this many more bytes of the stream (4-byte count): the sender may
//!   have that much more in flight. Each stream starts with [`WINDOW`] bytes, so one slow flow
//!   never holds up the others on the same stream.
//! - `DGRAM`: a datagram (a UDP frame of [`crate::flow`]); dropped, as UDP is, when the way out
//!   is backed up.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

const OPEN: u8 = 1;
const DATA: u8 = 2;
const FIN: u8 = 3;
const RST: u8 = 4;
const WINDOW_UPDATE: u8 = 5;
const DGRAM: u8 = 6;
/// Never sent: tells this side's writer to end the byte stream.
const CLOSE: u8 = 0;

/// The most bytes in one frame.
pub const MAX_FRAME: usize = 32 * 1024;
/// What each stream may have in flight before its reader takes some.
pub const WINDOW: u32 = 512 * 1024;
/// Datagrams waiting to go out past this many bytes are dropped.
const DGRAM_QUEUE: usize = 1 << 20;
/// Streams the other side opened that nobody has accepted yet.
const ACCEPT_QUEUE: usize = 256;

struct Frame {
    kind: u8,
    id: u32,
    payload: Bytes,
}

/// One stream's shared state.
#[derive(Default)]
struct Slot {
    /// Bytes arrived and not read yet; `fin`: no more will come.
    buf: BytesMut,
    fin: bool,
    reset: bool,
    read_waker: Option<Waker>,
    /// How many more bytes the other side lets this one send.
    credit: u64,
    write_waker: Option<Waker>,
}

struct Inner {
    out: mpsc::UnboundedSender<Frame>,
    slots: Mutex<HashMap<u32, Arc<Mutex<Slot>>>>,
    next_id: AtomicU32,
    dgram_queued: AtomicUsize,
    closed: AtomicBool,
    /// Bytes read from the other side, frames and all.
    received: std::sync::atomic::AtomicU64,
    /// Bytes written to the other side, frames and all.
    sent: std::sync::atomic::AtomicU64,
}

impl Inner {
    fn send(&self, kind: u8, id: u32, payload: Bytes) -> bool {
        self.out.send(Frame { kind, id, payload }).is_ok()
    }

    fn close_all(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // the writer ends too, and with it this side's byte stream
        let _ = self.out.send(Frame { kind: CLOSE, id: 0, payload: Bytes::new() });
        for (_, s) in self.slots.lock().unwrap_or_else(|p| p.into_inner()).drain() {
            let mut s = s.lock().unwrap_or_else(|p| p.into_inner());
            s.fin = true;
            s.reset = true;
            if let Some(w) = s.read_waker.take() {
                w.wake();
            }
            if let Some(w) = s.write_waker.take() {
                w.wake();
            }
        }
    }
}

/// One end of a multiplexed byte stream. Cheap to clone; the stream is closed when either side's
/// byte stream ends.
#[derive(Clone)]
pub struct Mux {
    inner: Arc<Inner>,
    accept: Arc<tokio::sync::Mutex<mpsc::Receiver<MuxStream>>>,
    dgrams: Arc<tokio::sync::Mutex<mpsc::Receiver<Bytes>>>,
}

impl Mux {
    /// Runs the multiplexer over `io`; `opener` is the buyer's side (it opens odd stream ids).
    pub fn new<S>(io: S, early: Vec<u8>, opener: bool) -> Mux
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (rd, wr) = tokio::io::split(io);
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (acc_tx, acc_rx) = mpsc::channel(ACCEPT_QUEUE);
        let (dg_tx, dg_rx) = mpsc::channel(1024);
        let inner = Arc::new(Inner {
            out: out_tx,
            slots: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(if opener { 1 } else { 2 }),
            dgram_queued: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            received: std::sync::atomic::AtomicU64::new(0),
            sent: std::sync::atomic::AtomicU64::new(0),
        });
        tokio::spawn(write_loop(wr, out_rx, inner.clone()));
        tokio::spawn(read_loop(rd, early, inner.clone(), acc_tx, dg_tx));
        Mux { inner, accept: Arc::new(tokio::sync::Mutex::new(acc_rx)), dgrams: Arc::new(tokio::sync::Mutex::new(dg_rx)) }
    }

    fn slot(&self, id: u32) -> Arc<Mutex<Slot>> {
        let s = Arc::new(Mutex::new(Slot { credit: u64::from(WINDOW), ..Slot::default() }));
        self.inner.slots.lock().unwrap_or_else(|p| p.into_inner()).insert(id, s.clone());
        s
    }

    /// A new stream to the other side.
    pub fn open(&self) -> io::Result<MuxStream> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "the tunnel is closed"));
        }
        let id = self.inner.next_id.fetch_add(2, Ordering::SeqCst);
        let slot = self.slot(id);
        if !self.inner.send(OPEN, id, Bytes::new()) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "the tunnel is closed"));
        }
        Ok(MuxStream { id, slot, inner: self.inner.clone(), fin_sent: false })
    }

    /// The next stream the other side opened; `None` once the tunnel has closed.
    pub async fn accept(&self) -> Option<MuxStream> {
        self.accept.lock().await.recv().await
    }

    /// Sends one datagram; dropped (as UDP is) when the way out is backed up.
    pub fn send_datagram(&self, d: Bytes) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "the tunnel is closed"));
        }
        let n = d.len();
        if self.inner.dgram_queued.fetch_add(n, Ordering::SeqCst) + n > DGRAM_QUEUE {
            self.inner.dgram_queued.fetch_sub(n, Ordering::SeqCst);
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "the tunnel is backed up"));
        }
        if self.inner.send(DGRAM, 0, d) {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "the tunnel is closed"))
        }
    }

    /// The next datagram from the other side; `Err` once the tunnel has closed.
    pub async fn read_datagram(&self) -> io::Result<Bytes> {
        self.dgrams.lock().await.recv().await.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "the tunnel is closed"))
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// The bytes read from the other side so far (frames and all).
    pub fn received(&self) -> u64 {
        self.inner.received.load(Ordering::Relaxed)
    }

    /// The bytes written to the other side so far (frames and all).
    pub fn sent(&self) -> u64 {
        self.inner.sent.load(Ordering::Relaxed)
    }

    /// Ends the tunnel: every flow on it ends, and the byte stream with them (for a paid tunnel,
    /// the wallet's call ends and nothing more is paid).
    pub fn close(&self) {
        self.inner.close_all();
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::UnboundedReceiver<Frame>, inner: Arc<Inner>) {
    let mut buf = BytesMut::with_capacity(64 * 1024);
    'outer: while let Some(f) = rx.recv().await {
        let mut next = Some(f);
        // as many frames as are waiting, in one write
        while let Some(f) = next.take() {
            if f.kind == CLOSE {
                let _ = wr.write_all(&buf).await;
                break 'outer;
            }
            if f.kind == DGRAM {
                inner.dgram_queued.fetch_sub(f.payload.len(), Ordering::SeqCst);
            }
            buf.put_u8(f.kind);
            buf.put_u32(f.id);
            buf.put_u32(f.payload.len() as u32);
            buf.put_slice(&f.payload);
            if buf.len() >= 256 * 1024 {
                break;
            }
            next = rx.try_recv().ok();
        }
        if wr.write_all(&buf).await.is_err() || wr.flush().await.is_err() {
            break 'outer;
        }
        inner.sent.fetch_add(buf.len() as u64, Ordering::Relaxed);
        buf.clear();
    }
    let _ = wr.shutdown().await;
    inner.close_all();
}

async fn read_loop<R: AsyncRead + Unpin>(mut rd: R, early: Vec<u8>, inner: Arc<Inner>, acc: mpsc::Sender<MuxStream>, dg: mpsc::Sender<Bytes>) {
    let mut buf = BytesMut::from(&early[..]);
    loop {
        while buf.len() >= 9 {
            let kind = buf[0];
            let id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
            let len = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
            if len > MAX_FRAME.max(64 * 1024) {
                // not this protocol: the tunnel ends
                inner.close_all();
                return;
            }
            if buf.len() < 9 + len {
                break;
            }
            buf.advance(9);
            let payload = buf.split_to(len).freeze();
            if !dispatch(&inner, &acc, &dg, kind, id, payload) {
                inner.close_all();
                return;
            }
        }
        let mut chunk = [0u8; 64 * 1024];
        match rd.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                inner.received.fetch_add(n as u64, Ordering::Relaxed);
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    }
    inner.close_all();
}

/// One frame from the other side; `false`: a frame this protocol never sends, and the tunnel ends.
fn dispatch(inner: &Arc<Inner>, acc: &mpsc::Sender<MuxStream>, dg: &mpsc::Sender<Bytes>, kind: u8, id: u32, payload: Bytes) -> bool {
    let get = |id: u32| inner.slots.lock().unwrap_or_else(|p| p.into_inner()).get(&id).cloned();
    match kind {
        OPEN => {
            let slot = Arc::new(Mutex::new(Slot { credit: u64::from(WINDOW), ..Slot::default() }));
            inner.slots.lock().unwrap_or_else(|p| p.into_inner()).insert(id, slot.clone());
            let s = MuxStream { id, slot, inner: inner.clone(), fin_sent: false };
            if let Err(mpsc::error::TrySendError::Full(s)) = acc.try_send(s) {
                // too many streams waiting: refused
                drop(s);
            }
        }
        DATA => {
            if let Some(s) = get(id) {
                let mut s = s.lock().unwrap_or_else(|p| p.into_inner());
                if s.buf.len() + payload.len() > WINDOW as usize * 2 {
                    // past the window it was given: not this protocol
                    return false;
                }
                s.buf.extend_from_slice(&payload);
                if let Some(w) = s.read_waker.take() {
                    w.wake();
                }
            }
        }
        FIN | RST => {
            if let Some(s) = get(id) {
                let mut s = s.lock().unwrap_or_else(|p| p.into_inner());
                s.fin = true;
                if kind == RST {
                    s.reset = true;
                    if let Some(w) = s.write_waker.take() {
                        w.wake();
                    }
                }
                if let Some(w) = s.read_waker.take() {
                    w.wake();
                }
            }
        }
        WINDOW_UPDATE => {
            if payload.len() == 4 {
                let n = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                if let Some(s) = get(id) {
                    let mut s = s.lock().unwrap_or_else(|p| p.into_inner());
                    s.credit = s.credit.saturating_add(u64::from(n));
                    if let Some(w) = s.write_waker.take() {
                        w.wake();
                    }
                }
            }
        }
        DGRAM => {
            let _ = dg.try_send(payload);
        }
        _ => return false,
    }
    true
}

/// One flow on a [`Mux`]: read and write like a TCP connection.
pub struct MuxStream {
    id: u32,
    slot: Arc<Mutex<Slot>>,
    inner: Arc<Inner>,
    fin_sent: bool,
}

impl AsyncRead for MuxStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut s = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        if s.buf.is_empty() {
            if s.fin {
                return Poll::Ready(Ok(()));
            }
            s.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = s.buf.len().min(out.remaining());
        out.put_slice(&s.buf.split_to(n));
        drop(s);
        // the other side may send this much more
        self.inner.send(WINDOW_UPDATE, self.id, Bytes::copy_from_slice(&(n as u32).to_be_bytes()));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut s = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        if s.reset || self.inner.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the flow was closed")));
        }
        if s.credit == 0 {
            s.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = data.len().min(MAX_FRAME).min(usize::try_from(s.credit).unwrap_or(usize::MAX));
        s.credit -= n as u64;
        drop(s);
        if !self.inner.send(DATA, self.id, Bytes::copy_from_slice(&data[..n])) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the tunnel is closed")));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.fin_sent {
            self.fin_sent = true;
            self.inner.send(FIN, self.id, Bytes::new());
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let done = {
            let s = self.slot.lock().unwrap_or_else(|p| p.into_inner());
            s.fin && self.fin_sent
        };
        if !done {
            // given up before both ways ended: gone either way
            self.inner.send(RST, self.id, Bytes::new());
        }
        self.inner.slots.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Mux, Mux) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        (Mux::new(a, vec![], true), Mux::new(b, vec![], false))
    }

    #[tokio::test]
    async fn streams_carry_bytes_both_ways_and_end() {
        let (buyer, exit) = pair();
        let server = tokio::spawn(async move {
            let mut s = exit.accept().await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            s.write_all(&got).await.unwrap();
            s.shutdown().await.unwrap();
            got.len()
        });
        let mut c = buyer.open().unwrap();
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
        let (mut r, mut w) = tokio::io::split(&mut c);
        let send = async {
            w.write_all(&data).await.unwrap();
            w.shutdown().await.unwrap();
        };
        let mut back = Vec::new();
        let recv = r.read_to_end(&mut back);
        let (_, n) = tokio::join!(send, recv);
        n.unwrap();
        assert_eq!(back, data);
        assert_eq!(server.await.unwrap(), data.len());
    }

    #[tokio::test]
    async fn a_slow_flow_does_not_hold_up_another() {
        let (buyer, exit) = pair();
        tokio::spawn(async move {
            while let Some(mut s) = exit.accept().await {
                tokio::spawn(async move {
                    let mut h = [0u8; 1];
                    s.read_exact(&mut h).await.unwrap();
                    if h[0] == b's' {
                        // the slow flow: sends far more than its reader takes, and its reader never reads
                        let big = vec![7u8; 4 << 20];
                        let _ = s.write_all(&big).await;
                    } else {
                        s.write_all(b"fast").await.unwrap();
                        s.shutdown().await.unwrap();
                    }
                });
            }
        });
        let mut slow = buyer.open().unwrap();
        slow.write_all(b"s").await.unwrap();
        let mut fast = buyer.open().unwrap();
        fast.write_all(b"f").await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), fast.read_to_end(&mut got)).await.expect("the fast flow is not held up").unwrap();
        assert_eq!(got, b"fast");
    }

    #[tokio::test]
    async fn datagrams_go_both_ways() {
        let (buyer, exit) = pair();
        buyer.send_datagram(Bytes::from_static(b"ping")).unwrap();
        assert_eq!(&exit.read_datagram().await.unwrap()[..], b"ping");
        exit.send_datagram(Bytes::from_static(b"pong")).unwrap();
        assert_eq!(&buyer.read_datagram().await.unwrap()[..], b"pong");
    }

    #[tokio::test]
    async fn a_tunnel_whose_byte_stream_ends_ends_every_flow() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let buyer = Mux::new(a, vec![], true);
        let mut s = buyer.open().unwrap();
        // the other end of the byte stream goes away (the wallet stopped paying, the exit went)
        drop(b);
        let mut buf = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut buf)).await.expect("the flow ends").unwrap();
        assert!(buyer.is_closed());
        assert!(buyer.open().is_err());
        assert!(buyer.read_datagram().await.is_err());
        assert!(s.write_all(b"x").await.is_err());
    }
}
