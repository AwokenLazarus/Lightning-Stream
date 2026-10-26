//! The control page of the hasher's and the renter's services: JSON over plain HTTP, for the app
//! beside them (on loopback, or the app's own private network). It holds no key and moves no money
//! by itself: renting still pays through the wallet, under its policy.

use serde_json::Value;
use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

pub type Handler = Arc<dyn Fn(&str, &str, &[u8]) -> (u16, Value) + Send + Sync>;

/// Answer requests on `addr` with `h(method, path, body)`, in the background.
pub fn serve(addr: &str, h: Handler) -> Result<(), String> {
    let l = TcpListener::bind(addr).map_err(|e| format!("control listen {addr}: {e}"))?;
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let h = h.clone();
            std::thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
                let Some((method, path, body)) = xbt_hashlink::hasher::read_request(&mut c) else { return };
                let (code, v) = h(&method, &path, &body);
                let body = v.to_string();
                let reason = match code {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Error",
                };
                let _ = c.write_all(
                    format!("HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                        .as_bytes(),
                );
            });
        }
    });
    Ok(())
}
