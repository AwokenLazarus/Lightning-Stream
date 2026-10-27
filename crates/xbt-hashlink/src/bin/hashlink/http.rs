//! The control page of the hashmaker's and the hashtaker's services: JSON over plain HTTP, for the app
//! beside them (on loopback, or the app's own private network). With a token file, every request
//! carries `Authorization: Bearer <token>` (the app reads the same file), so another service on that
//! network cannot stop a rental or start one. It holds no key and moves no money by itself: renting
//! still pays through the wallet, under its policy.

use serde_json::Value;
use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

pub type Handler = Arc<dyn Fn(&str, &str, &[u8]) -> (u16, Value) + Send + Sync>;

/// The control token in `path`, made (32 random bytes, hex, mode 0640) when the file is missing.
pub fn token(path: &str) -> Result<String, String> {
    if let Ok(t) = std::fs::read_to_string(path) {
        let t = t.trim().to_string();
        if t.len() >= 32 {
            return Ok(t);
        }
    }
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    let t = hex::encode(b);
    let tmp = format!("{path}.new");
    std::fs::write(&tmp, &t).map_err(|e| format!("{path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640));
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("{path}: {e}"))?;
    Ok(t)
}

/// Answer requests on `addr` with `h(method, path, body)`, in the background. With `token`, a
/// request without it is refused.
pub fn serve(addr: &str, token: Option<String>, h: Handler) -> Result<(), String> {
    let l = TcpListener::bind(addr).map_err(|e| format!("control listen {addr}: {e}"))?;
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let (h, token) = (h.clone(), token.clone());
            std::thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
                let Some((method, path, body, auth)) = xbt_hashlink::hashmaker::read_request_auth(&mut c) else { return };
                let (code, v) = match &token {
                    Some(t) if auth.strip_prefix("Bearer ").map(str::trim) != Some(t.as_str()) => (401, serde_json::json!({"error": "the control token is missing or wrong"})),
                    _ => h(&method, &path, &body),
                };
                let body = v.to_string();
                let reason = match code {
                    200 => "OK",
                    404 => "Not Found",
                    401 => "Unauthorized",
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
