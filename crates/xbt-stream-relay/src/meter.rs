//! Who may use the relay. iroh-relay asks its access control once per connecting client, with the
//! client's iroh key, and says when the connection ends; [`Gate`] puts a [`Meter`] behind those
//! two calls.
//!
//! A free relay uses [`Free`]: it admits everyone, carries everything and counts the clients
//! connected now, for the status page. A paid relay (`docs/PAID-RELAYS.md`) uses
//! [`crate::paid::Paid`], which meters every relayed packet by the keys it is from and to through
//! [`Meter::forward`] (iroh-relay's `on_forward`, a hook our vendored copy adds:
//! `vendor/iroh-relay/XBT-PATCH.md`), and stops carrying for a shop whose credit has run out.
use std::collections::HashMap;
use std::sync::Mutex;

use iroh_relay::server::{Access, AccessControl, ClientRequest};

/// A decision about one client, by its iroh key.
pub trait Meter: std::fmt::Debug + Send + Sync + 'static {
    /// May this client connect? `Err` with a reason it is told.
    fn admit(&self, key: &[u8; 32]) -> Result<(), String>;
    /// A connection this meter admitted has ended.
    fn ended(&self, key: &[u8; 32]);
    /// How many clients are connected now.
    fn connected(&self) -> usize;
    /// Carry `len` bytes of datagrams from `src` to `dst`? Called for every relayed packet; it must
    /// not block. Everything is carried unless a meter says otherwise.
    fn forward(&self, src: &[u8; 32], dst: &[u8; 32], len: usize) -> bool {
        let _ = (src, dst, len);
        true
    }
}

/// Everyone is admitted; clients are counted.
#[derive(Debug, Default)]
pub struct Free {
    now: Mutex<HashMap<[u8; 32], usize>>,
}

impl Meter for Free {
    fn admit(&self, key: &[u8; 32]) -> Result<(), String> {
        *self.now.lock().unwrap_or_else(|p| p.into_inner()).entry(*key).or_insert(0) += 1;
        Ok(())
    }

    fn ended(&self, key: &[u8; 32]) {
        let mut m = self.now.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = m.get_mut(key) {
            *n -= 1;
            if *n == 0 {
                m.remove(key);
            }
        }
    }

    fn connected(&self) -> usize {
        self.now.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

/// iroh-relay's access control, deciding through a [`Meter`].
#[derive(Debug)]
pub struct Gate<M: Meter + ?Sized>(pub std::sync::Arc<M>);

impl<M: Meter + ?Sized> AccessControl for Gate<M> {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        match self.0.admit(request.endpoint_id().as_bytes()) {
            Ok(()) => Access::Allow,
            Err(reason) => Access::Deny { reason: Some(reason) },
        }
    }

    fn on_disconnect(&self, endpoint_id: iroh_base::EndpointId, _connection_id: iroh_relay::server::ConnectionId) {
        self.0.ended(endpoint_id.as_bytes());
    }

    fn on_forward(&self, src: iroh_base::EndpointId, dst: iroh_base::EndpointId, len: usize) -> bool {
        self.0.forward(src.as_bytes(), dst.as_bytes(), len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_admits_and_counts_clients() {
        let m = Free::default();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        m.admit(&a).unwrap();
        m.admit(&a).unwrap();
        m.admit(&b).unwrap();
        assert_eq!(m.connected(), 2);
        m.ended(&a);
        assert_eq!(m.connected(), 2);
        m.ended(&a);
        m.ended(&b);
        assert_eq!(m.connected(), 0);
        m.ended(&b);
        assert_eq!(m.connected(), 0);
    }

    #[test]
    fn free_carries_everything() {
        let m = Free::default();
        assert!((0..1_000).all(|_| m.forward(&[1; 32], &[2; 32], 1 << 20)));
    }
}
