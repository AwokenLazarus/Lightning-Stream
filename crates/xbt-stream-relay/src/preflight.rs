//! The checks made before Let's Encrypt is asked for a certificate. Let's Encrypt allows 5 failed
//! validations per name an hour; a relay that asks while its domain points elsewhere, or while
//! 443 is closed, uses them up and must then wait. So the relay asks only when every check
//! passes, and never more than [`MAX_ATTEMPTS_PER_HOUR`] times an hour itself.
//!
//! [`evaluate`] decides from what was observed; [`observe`] observes. A box cannot fully test
//! from the inside that the internet reaches it: it can resolve its domain, learn its public
//! address (STUN), and connect to itself through that address. On a server with a public address
//! that connection takes the real path. Behind a home router it may not (routers differ), so
//! there the owner confirms the port forward.
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{json, Value};

/// Our own cap on certificate attempts an hour, below Let's Encrypt's 5 failures.
pub const MAX_ATTEMPTS_PER_HOUR: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Pass,
    /// Not proven, but not a reason to stop.
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: &'static str,
    pub level: Level,
    pub words: String,
}

/// What the box observed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observed {
    /// The addresses the domain resolves to.
    pub resolved: Vec<IpAddr>,
    /// This box's public address, as a STUN server saw it.
    pub public: Option<IpAddr>,
    /// The relay's listening port could be bound.
    pub port_free: bool,
    /// A connection from this box to the domain on 443 reached this box's listener (`None`: not
    /// tried, because an earlier check failed).
    pub self_reach: Option<bool>,
    /// The owner says TCP 443 is forwarded to this box.
    pub port_forwarded: bool,
    /// Certificate attempts in the last hour.
    pub attempts_last_hour: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub checks: Vec<Check>,
    /// Every check passed or only warned: a certificate may be asked for.
    pub ready: bool,
}

impl Report {
    pub fn to_value(&self) -> Value {
        json!({"ready": self.ready, "checks": self.checks.iter().map(|c| json!({"id": c.id, "level": match c.level {
            Level::Pass => "pass", Level::Warn => "warn", Level::Fail => "fail" }, "words": c.words})).collect::<Vec<_>>()})
    }
}

fn list(ips: &[IpAddr]) -> String {
    ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

/// Decide from what was observed.
pub fn evaluate(domain: &str, o: &Observed) -> Report {
    let mut c = Vec::new();
    let mut push = |id, level, words: String| c.push(Check { id, level, words });
    let here = match o.public {
        Some(p) => format!("this box's public address, {p}"),
        None => "this box's public address".to_string(),
    };
    if o.resolved.is_empty() {
        push("dns", Level::Fail, format!("{domain} doesn't resolve yet. Add an A record for it pointing at {here}, then try again \
              (new records can take a few minutes to appear)."));
    } else {
        push("dns", Level::Pass, format!("{domain} resolves to {}.", list(&o.resolved)));
        match o.public {
            Some(p) if o.resolved.contains(&p) => push("here", Level::Pass, format!("It points at this box ({p}).")),
            Some(p) => push("here", Level::Fail, format!("It points at {}, but this box is reached at {p}. Change the A record to {p}. \
                         If you use Cloudflare, set the record to DNS only (not proxied).", list(&o.resolved))),
            None => push("here", Level::Warn, "This box's public address couldn't be learned, so it isn't known whether the domain points here.".into()),
        }
    }
    if o.port_free {
        push("port", Level::Pass, "Port 443 is free on this box.".into());
    } else {
        push("port", Level::Fail, "Something else on this box already uses port 443 (a web server?). The relay needs it for itself.".into());
    }
    match (o.self_reach, o.port_forwarded) {
        (Some(true), _) => push("reach", Level::Pass, "This box answered on port 443 through its public address.".into()),
        (Some(false), true) => push("reach", Level::Warn, "This box couldn't reach itself through its public address, which many home routers \
             don't allow even when the port forward works. Going ahead on your word that TCP 443 is forwarded here.".into()),
        (Some(false), false) => push("reach", Level::Fail, "Port 443 isn't reachable through this box's public address. On a rented server, \
             open TCP 443 in its firewall (and the provider's, if it has one). Behind a home router, forward TCP 443 to this box, \
             then tick “TCP 443 is forwarded to this box”.".into()),
        (None, _) => {}
    }
    if o.attempts_last_hour >= MAX_ATTEMPTS_PER_HOUR {
        push("budget", Level::Fail, format!("{} certificate attempts in the last hour. Let's Encrypt refuses a name after 5 failures in an hour, \
             so wait before trying again.", o.attempts_last_hour));
    }
    let ready = !c.iter().any(|x| x.level == Level::Fail);
    Report { checks: c, ready }
}

/// Resolve `domain` (A and AAAA).
pub fn resolve(domain: &str) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = (domain, 443).to_socket_addrs().map(|a| a.map(|s| s.ip()).collect()).unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

/// Connect to each of `targets` on `public_port` and check the connection lands on `listener`,
/// by passing a random token through it. `true` when one does.
pub fn reaches_itself(listener: &TcpListener, targets: &[IpAddr], public_port: u16, timeout: Duration) -> bool {
    let mut token = [0u8; 16];
    getrandom::getrandom(&mut token).expect("OS randomness");
    let _ = listener.set_nonblocking(true);
    for ip in targets {
        let Ok(mut out) = TcpStream::connect_timeout(&SocketAddr::new(*ip, public_port), timeout) else { continue };
        let _ = out.write_all(&token);
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut inc, _)) => {
                    let _ = inc.set_nonblocking(false);
                    let _ = inc.set_read_timeout(Some(timeout));
                    let mut got = [0u8; 16];
                    if inc.read_exact(&mut got).is_ok() && got == token {
                        return true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
    }
    false
}

/// Observe everything [`evaluate`] needs. `listen` is where the relay will listen (443, or the
/// port a container maps 443 to); `stun` the STUN servers asked for the public address.
pub fn observe(domain: &str, listen: SocketAddr, port_forwarded: bool, attempts_last_hour: u32, stun: &[String]) -> Observed {
    let resolved = resolve(domain);
    let public = crate::stun::public_ip(stun, Duration::from_secs(3));
    let listener = TcpListener::bind(listen).ok();
    let port_free = listener.is_some();
    let self_reach = match (&listener, resolved.is_empty()) {
        (Some(l), false) => Some(reaches_itself(l, &resolved, crate::config::PUBLIC_PORT, Duration::from_secs(4))),
        _ => None,
    };
    Observed { resolved, public, port_free, self_reach, port_forwarded, attempts_last_hour }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ok() -> Observed {
        Observed { resolved: vec![ip("203.0.113.7")], public: Some(ip("203.0.113.7")), port_free: true, self_reach: Some(true),
                   port_forwarded: false, attempts_last_hour: 0 }
    }

    fn level(r: &Report, id: &str) -> Level {
        r.checks.iter().find(|c| c.id == id).unwrap().level
    }

    #[test]
    fn all_good_is_ready() {
        let r = evaluate("relay.example.com", &ok());
        assert!(r.ready);
        assert!(r.checks.iter().all(|c| c.level == Level::Pass));
    }

    #[test]
    fn each_failure_stops_the_certificate_and_says_what_to_do() {
        let mut o = ok();
        o.resolved.clear();
        o.self_reach = None;
        let r = evaluate("relay.example.com", &o);
        assert!(!r.ready && level(&r, "dns") == Level::Fail);
        assert!(r.checks[0].words.contains("A record") && r.checks[0].words.contains("203.0.113.7"));

        let mut o = ok();
        o.resolved = vec![ip("198.51.100.9")];
        let r = evaluate("relay.example.com", &o);
        assert!(!r.ready && level(&r, "here") == Level::Fail);
        assert!(r.checks.iter().any(|c| c.words.contains("DNS only")));

        let mut o = ok();
        o.port_free = false;
        assert!(!evaluate("relay.example.com", &o).ready);

        let mut o = ok();
        o.self_reach = Some(false);
        let r = evaluate("relay.example.com", &o);
        assert!(!r.ready && level(&r, "reach") == Level::Fail);
        assert!(r.checks.iter().any(|c| c.words.contains("forward TCP 443")));

        let mut o = ok();
        o.attempts_last_hour = MAX_ATTEMPTS_PER_HOUR;
        let r = evaluate("relay.example.com", &o);
        assert!(!r.ready && level(&r, "budget") == Level::Fail);
    }

    #[test]
    fn behind_a_router_the_owner_s_word_on_the_forward_is_enough() {
        let mut o = ok();
        o.self_reach = Some(false);
        o.port_forwarded = true;
        let r = evaluate("relay.example.com", &o);
        assert!(r.ready);
        assert_eq!(level(&r, "reach"), Level::Warn);
    }

    #[test]
    fn an_unknown_public_address_warns_but_does_not_stop() {
        let mut o = ok();
        o.public = None;
        let r = evaluate("relay.example.com", &o);
        assert!(r.ready);
        assert_eq!(level(&r, "here"), Level::Warn);
    }

    #[test]
    fn a_box_reaches_its_own_listener_and_not_another() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(reaches_itself(&l, &[ip("127.0.0.1")], port, Duration::from_secs(2)));
        // something else answers on the public port: the token never reaches our listener
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let other_port = other.local_addr().unwrap().port();
        std::thread::spawn(move || { let _ = other.accept(); std::thread::sleep(Duration::from_secs(3)); });
        assert!(!reaches_itself(&l, &[ip("127.0.0.1")], other_port, Duration::from_secs(1)));
    }
}
