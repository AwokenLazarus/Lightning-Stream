//! The service behind the gateway, and what may reach it. One reading of a request target: the
//! gateway refuses every spelling that it and the service could read differently, matches its
//! route on the decoded path, and passes on the target exactly as it arrived.
use std::io::Read;
use std::time::Duration;

use crate::config::{Route, ALWAYS_FORWARDED, NEVER_FORWARDED};
use crate::price::UNITS_HEADER;
use crate::Error;

/// The decoded path of a request target, or why the target is refused. Refused: a target that does
/// not start with one `/`; an empty, `.` or `..` segment; a backslash; a byte outside visible
/// ASCII; a `%` that is not followed by two hex digits; and an escaped `/`, `\`, `.`, `%`, or
/// control character. What is left has one reading: its escapes decoded, nothing else changed.
pub fn decoded_path(target: &str) -> Result<String, &'static str> {
    let path = target.split('?').next().unwrap_or("");
    if !path.starts_with('/') {
        return Err("a request target starts with /");
    }
    if !target.bytes().all(|c| c.is_ascii_graphic())
        || target.contains('\\')
        || target.contains('#')
    {
        return Err("a request target is visible ASCII with no backslash and no #");
    }
    let mut out = Vec::with_capacity(path.len());
    let b = path.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()));
        let Some(c) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) else {
            return Err("a % in the path is followed by two hex digits");
        };
        if matches!(c, b'/' | b'\\' | b'.' | b'%') || c < 0x20 || c == 0x7f {
            return Err(
                "an escaped /, \\, ., % or control character in the path could be read two ways",
            );
        }
        out.push(c);
        i += 3;
    }
    let path = String::from_utf8(out).map_err(|_| "the path's escapes are not UTF-8")?;
    if path[1..]
        .split('/')
        .enumerate()
        .any(|(i, s)| s == "." || s == ".." || s.is_empty() && i + 1 < path[1..].split('/').count())
    {
        return Err("the path has an empty, . or .. segment");
    }
    Ok(path)
}

/// The request headers `route` passes on, in the order they arrived.
pub fn forwarded(route: &Route, headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| {
            let k = k.to_ascii_lowercase();
            !NEVER_FORWARDED.contains(&k.as_str())
                && (ALWAYS_FORWARDED.contains(&k.as_str()) || route.forward_headers.contains(&k))
        })
        .cloned()
        .collect()
}

/// Whether a header of the service's answer goes to the buyer. Not the framing (the gateway
/// frames its own answer), and nothing that speaks of payment: what the service says is never
/// read for money and must not look as if the gateway said it.
pub fn returned(name: &str) -> bool {
    let k = name.to_ascii_lowercase();
    !([
        "connection",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-encoding",
    ]
    .contains(&k.as_str())
        || k.starts_with("payment-")
        || k.eq_ignore_ascii_case(UNITS_HEADER))
}

/// How the gateway names itself to the service, as a proxy does: a service can tell a request
/// that came through the gateway from one that reached it another way.
pub const VIA: &str = "1.1 xbt-gateway";

pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// The body's length, when the service stated one.
    pub length: Option<u64>,
    pub body: Box<dyn Read + Send>,
}

pub struct Upstream {
    base: String,
    agent: ureq::Agent,
}

impl Upstream {
    /// `base` is the config's `upstream`, already checked. `wait`: the longest the service may
    /// take to connect, to start its answer, and between two reads of its body.
    pub fn new(base: &str, wait: Duration) -> Self {
        // No redirect is followed: a 3xx goes to the buyer as it is, and the gateway asks no one
        // but the service the runner named.
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(wait.min(Duration::from_secs(5)))
            .timeout_read(wait)
            .timeout_write(wait)
            .redirects(0)
            .build();
        Self {
            base: base.to_string(),
            agent,
        }
    }

    /// Pass one request on. `target` has been through [`decoded_path`]. `Err`: the service gave no
    /// answer (down, or too slow to start one).
    pub fn send(
        &self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Answer, Error> {
        // identity: the bytes metered are the bytes the service sent
        let mut req = self
            .agent
            .request(method, &format!("{}{target}", self.base))
            .set("Accept-Encoding", "identity")
            .set("Via", VIA);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let sent = if body.is_empty() {
            req.call()
        } else {
            req.send_bytes(body)
        };
        let resp = match sent {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(Error::Upstream(e.to_string())),
        };
        let mut headers = vec![];
        for name in resp.headers_names() {
            for v in resp.all(&name) {
                headers.push((name.clone(), v.to_string()));
            }
        }
        let chunked = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
        let lengths: Vec<&str> = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.as_str())
            .collect();
        let length = match (chunked, lengths.as_slice()) {
            (false, [one]) if !one.is_empty() && one.bytes().all(|c| c.is_ascii_digit()) => {
                one.parse().ok()
            }
            _ => None,
        };
        Ok(Answer {
            status: resp.status(),
            headers,
            length,
            body: Box::new(resp.into_reader()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Release;
    use crate::price::Price;

    #[test]
    fn a_target_has_one_reading_or_is_refused() {
        for (target, path) in [
            ("/", "/"),
            ("/a", "/a"),
            ("/a/b.bin?x=1&y=%2F", "/a/b.bin"),
            ("/p%61id/f", "/paid/f"),
            ("/a/", "/a/"),
            ("/caf%C3%A9", "/caf\u{e9}"),
            ("/a;v=1/b", "/a;v=1/b"),
            ("/a?b=/../c", "/a"),
        ] {
            assert_eq!(decoded_path(target).as_deref(), Ok(path), "{target}");
        }
        for bad in [
            "",
            "a",
            "//a",
            "/a//b",
            "/a/./b",
            "/a/../b",
            "/..",
            "/.",
            "/a/..",
            "/a\\b",
            "/a b",
            "/a\tb",
            "/a\u{e9}",
            "/a%2fb",
            "/a%2Fb",
            "/a%5cb",
            "/%2e%2e/a",
            "/a/%2E/b",
            "/a%00",
            "/a%0a",
            "/a%7f",
            "/a%25%32%65",
            "/a%",
            "/a%2",
            "/a%zz",
            "/a%ff",
            "/a?b c",
            "/a#b",
            "http://other/a",
            "*",
        ] {
            assert!(decoded_path(bad).is_err(), "{bad:?}");
        }
    }

    /// A small generator with a fixed seed: the same targets on every run.
    fn targets(count: usize) -> Vec<String> {
        const ALPHABET: &[u8] = b"/.%\\ab25ef?#;~ ";
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        (0..count)
            .map(|_| {
                let len = (next() % 14) as usize;
                let tail: Vec<u8> = (0..len)
                    .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize])
                    .collect();
                format!("/{}", String::from_utf8_lossy(&tail))
            })
            .collect()
    }

    #[test]
    fn whatever_the_target_an_accepted_path_is_in_one_plain_form() {
        let mut accepted = 0;
        for target in targets(200_000) {
            let Ok(path) = decoded_path(&target) else {
                continue;
            };
            accepted += 1;
            let raw = target.split('?').next().unwrap();
            assert!(
                path.starts_with('/') && !path.contains("//"),
                "{target:?} -> {path:?}"
            );
            assert!(
                !path.split('/').any(|s| s == "." || s == ".."),
                "{target:?} -> {path:?}"
            );
            assert!(
                !path.contains('\\') && !path.bytes().any(|c| c < 0x20 || c == 0x7f),
                "{target:?} -> {path:?}"
            );
            // decoding changed nothing a route is matched on: the same number of segments, and
            // every escape stood for one byte that is neither a separator nor a dot
            assert_eq!(
                path.split('/').count(),
                raw.split('/').count(),
                "{target:?} -> {path:?}"
            );
            assert!(
                !raw.contains('%') || path.len() < raw.len(),
                "{target:?} -> {path:?}"
            );
            // decoding an accepted path's own plain spelling gives it back
            if !raw.contains('%') {
                assert_eq!(path, raw, "{target:?}");
            }
        }
        assert!(
            accepted > 1000,
            "the generator made only {accepted} acceptable targets"
        );
    }

    #[test]
    fn only_what_the_runner_allowed_reaches_the_service() {
        let route = Route {
            path: "/".into(),
            methods: vec!["GET".into()],
            free: false,
            price: Price::default(),
            release: Release::WithRequest,
            forward_headers: vec!["x-trace".into()],
            max_body: 0,
        };
        let h = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>()
        };
        let sent = forwarded(
            &route,
            &h(&[
                ("Host", "evil"),
                ("Range", "bytes=0-9"),
                ("PAYMENT-SIGNATURE", "x"),
                ("Authorization", "Bearer buyer"),
                ("Cookie", "a=b"),
                ("X-Trace", "1"),
                ("X-Forwarded-For", "10.0.0.1"),
                ("Accept-Encoding", "gzip"),
                ("Transfer-Encoding", "chunked"),
                ("accept", "*/*"),
                ("X-Other", "2"),
            ]),
        );
        assert_eq!(
            sent,
            h(&[("Range", "bytes=0-9"), ("X-Trace", "1"), ("accept", "*/*")])
        );
        for kept in [
            "Content-Type",
            "ETag",
            "Content-Range",
            "Accept-Ranges",
            "Location",
            "Last-Modified",
        ] {
            assert!(returned(kept), "{kept}");
        }
        for dropped in [
            "Content-Length",
            "transfer-encoding",
            "Connection",
            "PAYMENT-RESPONSE",
            "Payment-Required",
            "payment-signature",
            "Ticket-Units",
            "ticket-units",
        ] {
            assert!(!returned(dropped), "{dropped}");
        }
    }
}
