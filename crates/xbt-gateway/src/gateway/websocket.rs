//! WebSockets on a route that carries them (`websocket`, docs/SELLER-APPS.md): a `GET` that asks
//! to upgrade is passed to the service as one, and when the service agrees (`101`) the two
//! connections are joined into one two-way byte stream. Nothing here reads the WebSocket's frames.
//!
//! On a priced route the request's price is charged before the service is asked, as for any
//! request, and every byte after the head, in either direction, is paid for before it is passed
//! on, at the route's price per byte: the same book, meter and wait for a refill as a body's. When
//! the balance stops covering the next byte and no refill comes, both connections are closed. The
//! last receipt, kept with the session's finals, counts what was charged; its body hash is that of
//! the bytes the service sent.
//!
//! While it is open, the seller signs **interim receipts** (`xbt402::ticket::interim_body_hash`):
//! one each time what it charged grows by the price of [`INTERIM_BYTES`], or every
//! [`INTERIM_EVERY`] while bytes pass, none while it is idle. Each counts the bytes passed each
//! way and what they cost so far. The latest one of each open answer is listed in `status`
//! (`interim`), so the buyer can check the seller's count against its own as the answer runs, not
//! only at its end (docs/VPN-EXITS.md).

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use xbt_svc::http::{Reply, Request, Response, Upgraded};

use super::{b64json, error, settlement_response, Authed, Gateway, Metered, OpenResponse, CHUNK, FINALS_KEPT};
use crate::config::Route;
use crate::price::Meter;
use crate::upstream::{forwarded, WEBSOCKET_HEADERS};

/// Whether `req` asks to become a WebSocket: a `GET` with `Upgrade: websocket` and `Connection:
/// upgrade`.
pub(super) fn asks_upgrade(req: &Request) -> bool {
    let has = |name: &str, token: &str| {
        req.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    req.method == "GET" && has("upgrade", "websocket") && has("connection", "upgrade")
}

/// An interim receipt goes each time the answer's charge grows by the price of this many bytes,
pub(crate) const INTERIM_BYTES: u64 = 1 << 20;
/// or this long after the last one while bytes pass.
pub(crate) const INTERIM_EVERY: Duration = Duration::from_secs(10);

/// An open answer's count for its interim receipts.
struct Counted {
    part: u64,
    up: u64,
    down: u64,
    /// What the last interim receipt charged, and when it was signed.
    charged: u64,
    at: Instant,
}

/// The service's headers of a `101` that go to the buyer.
const ANSWERED: [&str; 3] = ["sec-websocket-accept", "sec-websocket-protocol", "sec-websocket-extensions"];

/// The service's `101`: its headers for the buyer, the connection, and what it sent after the head.
type Opened = (Vec<(String, String)>, TcpStream, Vec<u8>);

impl Gateway {
    /// Ask the service to upgrade, with the route's headers and the opening's own. `Err`: the
    /// answer for the buyer (the service said no, or gave none).
    fn upgrade_upstream(&self, route: &Route, req: &Request, account: Option<&super::accounts::Account>) -> Result<Opened, Response> {
        let base = route.upstream.as_ref().or(self.cfg.upstream.as_ref());
        let up = base.and_then(|b| self.upstreams.get(b)).ok_or_else(|| error(502, "upstream_unavailable", "no service for this route"))?;
        let mut headers = forwarded(route, &req.headers);
        headers.retain(|(k, _)| !route.upstream_headers.iter().any(|(n, _)| k.eq_ignore_ascii_case(n)));
        headers.extend(route.upstream_headers.iter().cloned());
        headers.extend(req.headers.iter().filter(|(k, _)| WEBSOCKET_HEADERS.contains(&k.to_ascii_lowercase().as_str())).cloned());
        let mut target = route.upstream_target(&req.target);
        // a buyer's own account: its token in place of the client's, in the headers and in the URL
        if let Some(a) = account {
            match self.as_account(route, a, "GET", &target, &headers) {
                super::accounts::AsAccount::Send { target: t, headers: h, .. } => {
                    target = t;
                    headers = h;
                }
                super::accounts::AsAccount::Answer(status, _) => return Err(Response::new(status, vec![], vec![])),
            }
        }
        let u = up.upgrade(&target, &headers)
            .map_err(|_| error(502, "upstream_unavailable", "the service gave no answer to the WebSocket; nothing was charged"))?;
        match u.stream {
            Some(s) => {
                let passed = u.headers.into_iter().filter(|(k, _)| ANSWERED.contains(&k.to_ascii_lowercase().as_str())).collect();
                Ok((passed, s, u.early))
            }
            // the service's refusal, as it said it, with no body: nothing was carried
            None => Err(Response::new(u.status.clamp(400, 599), vec![], vec![])),
        }
    }

    /// A free route's WebSocket: joined as it is, nothing counted.
    pub(super) fn free_upgrade(self: &Arc<Self>, req: &Request, route: &Route) -> Reply {
        let (mut headers, up, up_early) = match self.upgrade_upstream(route, req, None) {
            Ok(u) => u,
            Err(r) => return Reply::Whole(r),
        };
        headers.push(("Upgrade".into(), "websocket".into()));
        Reply::Upgrade(Upgraded {
            headers,
            run: Box::new(move |buyer, early| {
                let _ = join(buyer, early, up, up_early, &|_| Some(u64::MAX), &mut |_, _| {});
            }),
        })
    }

    /// A priced route's WebSocket, after its request's price was charged (`reserve`, refunded
    /// here if the service does not agree).
    pub(super) fn paid_upgrade(self: &Arc<Self>, a: Authed, route: &Route, req: &Request, reserve: u64, slot: Option<super::admission::Slot>) -> Reply {
        let account = match self.account_for(route, &a.session) {
            Ok(acc) => acc,
            Err(r) => {
                self.lock().book.refund(&a.session, reserve);
                return Reply::Whole(self.answered(&a, r, 0));
            }
        };
        let (mut headers, up, up_early) = match self.upgrade_upstream(route, req, account.as_ref()) {
            Ok(u) => u,
            Err(r) => {
                self.lock().book.refund(&a.session, reserve);
                return Reply::Whole(self.answered(&a, r, 0));
            }
        };
        self.lock().book.response(&a.session, true, self.now());
        let open = OpenResponse { gw: self.clone(), session: a.session.clone(), slot };
        self.flush();
        if let Some(head) = self.receipt(&a.session, a.seq, reserve, &a.digest, 101, "") {
            let mut sr = settlement_response(&head, &self.cfg.network, "", true);
            sr["extra"]["stream"] = true.into();
            headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
        }
        headers.push(("Upgrade".into(), "websocket".into()));
        let m = Metered {
            session: a.session,
            seq: a.seq,
            digest: a.digest,
            status: 101,
            route: route.clone(),
            at_head: route.price.request_msat,
            first_second: 0,
            started: Instant::now(),
            tokens: None,
            cap_msat: None,
        };
        let gw = self.clone();
        Reply::Upgrade(Upgraded {
            headers,
            run: Box::new(move |buyer, early| gw.carry_paid(m, buyer, early, up, up_early, open)),
        })
    }

    /// Both directions, every chunk paid for before it is passed on; the last receipt at the end.
    fn carry_paid(&self, m: Metered, buyer: TcpStream, early: Vec<u8>, up: TcpStream, up_early: Vec<u8>, _open: OpenResponse) {
        let meter = Mutex::new(Meter::new(m.route.price));
        let hash = Mutex::new(Sha256::new());
        let step = m.route.price.for_bytes(INTERIM_BYTES).unwrap_or(u64::MAX).max(1);
        let mut counted = Counted { part: 0, up: 0, down: 0, charged: m.at_head, at: Instant::now() };
        // how many of `want` bytes may go now, paid for; None: none, the stream ends
        let pay = |want: u64| -> Option<u64> {
            let mut mt = meter.lock().unwrap_or_else(|p| p.into_inner());
            let (take, due) = self.pay_bytes(&m, &mt, want, &mut || false);
            if take == 0 {
                return None;
            }
            mt.sent(take, due);
            Some(take)
        };
        let ended = join(buyer, early, up, up_early, &pay, &mut |from_service, bytes| {
            if from_service {
                hash.lock().unwrap_or_else(|p| p.into_inner()).update(bytes);
                counted.down = counted.down.saturating_add(bytes.len() as u64);
            } else {
                counted.up = counted.up.saturating_add(bytes.len() as u64);
            }
            // signed for the bytes counted here, never for a chunk paid for and still being written
            // (the other direction's write may be blocked on it): the buyer checks the charge against
            // these counts
            let paid = m.at_head.saturating_add(meter.lock().unwrap_or_else(|p| p.into_inner()).charged());
            let counted_cost = m.at_head.saturating_add(m.route.price.for_bytes(counted.up.saturating_add(counted.down)).unwrap_or(u64::MAX));
            let charged = paid.min(counted_cost);
            if charged > counted.charged && (charged - counted.charged >= step || counted.at.elapsed() >= INTERIM_EVERY) {
                counted.part += 1;
                (counted.charged, counted.at) = (charged, Instant::now());
                let body = xbt402::ticket::interim_body_hash(counted.part, counted.up, counted.down);
                if let Some(r) = self.receipt(&m.session, m.seq, charged, &m.digest, m.status, &body) {
                    self.lock().interim.entry(m.session.clone()).or_default().insert(m.seq, r);
                }
            }
        });
        let charged = m.at_head.saturating_add(meter.lock().unwrap_or_else(|p| p.into_inner()).charged());
        let digest = hex::encode(hash.into_inner().unwrap_or_else(|p| p.into_inner()).finalize());
        let last = self.receipt(&m.session, m.seq, charged, &m.digest, m.status, &digest);
        let mut st = self.lock();
        // closed: its last receipt replaces the interim ones
        if let Some(open) = st.interim.get_mut(&m.session) {
            open.remove(&m.seq);
            if open.is_empty() {
                st.interim.remove(&m.session);
            }
        }
        if let Some(mut r) = last {
            r["bytes"] = meter.lock().unwrap_or_else(|p| p.into_inner()).bytes().into();
            r["complete"] = ended.is_ok().into();
            let finals = st.finals.entry(m.session.clone()).or_default();
            if finals.len() >= FINALS_KEPT {
                finals.pop_front();
            }
            finals.push_back(r);
        }
        let marks = st.book.take_marks();
        self.journal(&mut st, &marks);
    }
}

/// How many of `n` bytes may pass now; `None`: none, the stream ends.
type Pay<'a> = &'a (dyn Fn(u64) -> Option<u64> + Sync);
/// Told each chunk that passed, and whether it came from the service.
type Seen<'a> = &'a mut (dyn FnMut(bool, &[u8]) + Send);

/// Join two connections into one two-way stream, each side's early bytes first. `pay(n)`: how many
/// of `n` bytes may pass now (`None`: the stream ends, both connections are closed). `seen` is told
/// each chunk that passed, and whether it came from the service. Ends when both directions have
/// ended; `Err` when it was cut (payment, a write that failed).
fn join(
    buyer: TcpStream,
    early: Vec<u8>,
    service: TcpStream,
    service_early: Vec<u8>,
    pay: Pay<'_>,
    seen: Seen<'_>,
) -> io::Result<()> {
    let (Ok(b2), Ok(s2)) = (buyer.try_clone(), service.try_clone()) else {
        return Err(io::Error::other("could not share the connections"));
    };
    let seen = Mutex::new(seen);
    let cut = std::sync::atomic::AtomicBool::new(false);
    // one direction: from `src` to `dst`, its early bytes first
    let carry = |mut src: TcpStream, mut dst: TcpStream, first: Vec<u8>, from_service: bool| -> io::Result<()> {
        let mut buf = vec![0u8; CHUNK];
        let mut pending = first;
        loop {
            if pending.is_empty() {
                let n = src.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    // this direction is over; the other goes on until it ends too
                    let _ = dst.shutdown(Shutdown::Write);
                    return Ok(());
                }
                pending = buf[..n].to_vec();
            }
            let mut off = 0;
            while off < pending.len() {
                let Some(take) = pay((pending.len() - off) as u64) else {
                    cut.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = src.shutdown(Shutdown::Both);
                    let _ = dst.shutdown(Shutdown::Both);
                    return Err(io::Error::other("no balance for another byte"));
                };
                let end = off + (take as usize).min(pending.len() - off);
                if let Err(e) = dst.write_all(&pending[off..end]) {
                    let _ = src.shutdown(Shutdown::Both);
                    return Err(e);
                }
                (seen.lock().unwrap_or_else(|p| p.into_inner()))(from_service, &pending[off..end]);
                off = end;
            }
            pending.clear();
        }
    };
    let (to_service, to_buyer) = std::thread::scope(|scope| {
        let c = &carry;
        let t = scope.spawn(move || c(buyer, s2, early, false));
        let from = c(service, b2, service_early, true);
        (t.join().unwrap_or_else(|_| Err(io::Error::other("a direction panicked"))), from)
    });
    if cut.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(io::Error::other("no balance for another byte"));
    }
    to_service.and(to_buyer)
}
