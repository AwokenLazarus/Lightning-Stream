//! What an exit's operator chooses not to carry: sites by name, and optionally addresses.
//!
//! An operator may block sites (adult content, gambling, malware) from their own blocklist entries
//! and from well-known public category lists. The exit checks a site's name where it is visible:
//! - **DNS:** a buyer's DNS goes through the tunnel; a question for a blocked name or any name under
//!   it is answered "no such domain" by the exit itself and never forwarded.
//! - **TLS:** the name a client asks for in its TLS ClientHello (SNI); a blocked name's connection is
//!   closed before the exit connects anywhere. Plain HTTP's Host header likewise.
//! - **QUIC (HTTP/3):** its name is encrypted in a way this exit does not read, so a filtering exit
//!   refuses UDP 443 and browsers fall back to TLS over TCP, where the name is checked.
//! - **Encrypted DNS:** with filtering on, DNS over TLS (853) and the well-known DNS-over-HTTPS
//!   services are refused, so the filter is not bypassed by simply switching resolver.
//!
//! It is not airtight: Encrypted ClientHello, sites reached by bare address, other DNS-over-HTTPS
//! services and other tunnels can still get past it. Exits announce what they block, and buyers see
//! it before they choose an exit.
//!
//! Nothing records what was blocked or who asked: only a count.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use crate::filter::Net;

/// A set of domain names; a name matches if it or any domain above it is in the set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainSet {
    names: HashSet<String>,
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl DomainSet {
    pub fn insert(&mut self, name: &str) {
        let n = normalize(name);
        if !n.is_empty() && n.contains('.') {
            self.names.insert(n);
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Whether `name` or a domain above it is in the set.
    pub fn matches(&self, name: &str) -> bool {
        let n = normalize(name);
        let mut rest = n.as_str();
        loop {
            if self.names.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, up)) if up.contains('.') => rest = up,
                _ => return false,
            }
        }
    }

    /// Adds the names of a blocklist file in any of the common formats: one domain a line, a hosts
    /// file (`0.0.0.0 example.com`), or adblock style (`||example.com^`). Comments are skipped.
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() || line.starts_with('!') {
                continue;
            }
            let name = if let Some(r) = line.strip_prefix("||") {
                r.trim_end_matches('^')
            } else {
                let mut f = line.split_whitespace();
                let first = f.next().unwrap_or("");
                match f.next() {
                    // a hosts file line: the address first, then the name
                    Some(second) if first.parse::<IpAddr>().is_ok() => second,
                    _ => first,
                }
            };
            if name != "localhost" && !name.ends_with(".localdomain") && name.parse::<IpAddr>().is_err() {
                self.insert(name);
            }
        }
    }
}

/// Category lists an exit keeps up to date while it runs ([`crate::lists`]): replaced whole on each
/// update, read by every flow.
#[derive(Clone, Debug, Default)]
pub struct LiveLists(Arc<RwLock<DomainSet>>);

impl LiveLists {
    /// Replaces the lists with a freshly loaded set.
    pub fn replace(&self, d: DomainSet) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = d;
    }

    pub fn matches(&self, name: &str) -> bool {
        self.0.read().unwrap_or_else(|e| e.into_inner()).matches(name)
    }

    pub fn len(&self) -> usize {
        self.0.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Well-known DNS-over-HTTPS services: refused while filtering is on.
pub const DOH_HOSTS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "1dot1dot1dot1.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "doh.opendns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "doh.mullvad.net",
    "dns.mullvad.net",
    "freedns.controld.com",
];

/// The addresses of well-known public resolvers: HTTPS (443) to them is refused while filtering is
/// on, since that is DNS over HTTPS by address.
pub const DOH_ADDRS: &[&str] = &[
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "94.140.14.14",
    "94.140.15.15", "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe",
];

/// An exit's content filter.
#[derive(Clone, Debug, Default)]
pub struct ContentFilter {
    /// Names blocked (the operator's own entries and category lists).
    pub domains: DomainSet,
    /// Addresses blocked, optionally.
    pub nets: Vec<Net>,
    /// The categories this exit blocks, announced in its listing ("adult", "gambling", "malware"…).
    pub categories: Vec<String>,
    /// The category lists' names, kept up to date while the exit runs.
    pub lists: LiveLists,
}

/// Why the filter refused a flow. It carries no name or address, so nothing can log one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// A blocked site's name (DNS question, TLS name or HTTP Host).
    Site,
    /// A blocked address.
    Address,
    /// Encrypted DNS that would get round the filter.
    EncryptedDns,
    /// QUIC, whose name this exit cannot read.
    Quic,
}

impl ContentFilter {
    /// Whether the filter does anything. An exit without one carries everything its policy allows.
    pub fn is_active(&self) -> bool {
        !self.domains.is_empty() || !self.nets.is_empty() || !self.categories.is_empty()
    }

    /// Whether a site name is blocked, including the encrypted-DNS services.
    pub fn blocks_name(&self, name: &str) -> Option<Blocked> {
        if !self.is_active() {
            return None;
        }
        let n = normalize(name);
        if DOH_HOSTS.iter().any(|h| n == *h || n.ends_with(&format!(".{h}"))) {
            return Some(Blocked::EncryptedDns);
        }
        (self.domains.matches(&n) || self.lists.matches(&n)).then_some(Blocked::Site)
    }

    /// Whether a flow to `to` is refused before anything is read from it.
    pub fn blocks_dst(&self, to: std::net::SocketAddr, udp: bool) -> Option<Blocked> {
        if !self.is_active() {
            return None;
        }
        if self.nets.iter().any(|n| n.contains(to.ip())) {
            return Some(Blocked::Address);
        }
        if !udp && to.port() == 853 {
            return Some(Blocked::EncryptedDns);
        }
        if to.port() == 443 && DOH_ADDRS.iter().any(|a| a.parse::<IpAddr>().ok() == Some(to.ip())) {
            return Some(Blocked::EncryptedDns);
        }
        if udp && to.port() == 443 {
            return Some(Blocked::Quic);
        }
        None
    }
}

/// The server name in a TLS ClientHello (the first bytes a TLS client sends), if there is one.
pub fn tls_sni(b: &[u8]) -> Option<String> {
    // record header: handshake (22), version, length; then handshake header: ClientHello (1), length
    if b.len() < 9 || b[0] != 22 || b[5] != 1 {
        return None;
    }
    let mut i = 9 + 2 + 32; // client version, random
    let sid = usize::from(*b.get(i)?);
    i += 1 + sid;
    let suites = usize::from(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]));
    i += 2 + suites;
    let comp = usize::from(*b.get(i)?);
    i += 1 + comp;
    let ext_end = i + 2 + usize::from(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]));
    i += 2;
    while i + 4 <= ext_end.min(b.len()) {
        let ty = u16::from_be_bytes([b[i], b[i + 1]]);
        let len = usize::from(u16::from_be_bytes([b[i + 2], b[i + 3]]));
        let body = b.get(i + 4..i + 4 + len)?;
        if ty == 0 {
            // server_name list: list length, then entries of type (0 = host name), length, name
            let mut j = 2;
            while j + 3 <= body.len() {
                let kind = body[j];
                let n = usize::from(u16::from_be_bytes([body[j + 1], body[j + 2]]));
                let name = body.get(j + 3..j + 3 + n)?;
                if kind == 0 {
                    return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase());
                }
                j += 3 + n;
            }
            return None;
        }
        i += 4 + len;
    }
    None
}

/// The Host header of a plain HTTP request, if the bytes start one.
pub fn http_host(b: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(b.get(..b.len().min(4096))?).ok()?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    if !first.contains(" HTTP/1.") {
        return None;
    }
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                let host = v.trim();
                let host = host.rsplit_once(':').filter(|(_, p)| p.parse::<u16>().is_ok()).map_or(host, |(h, _)| h);
                return Some(host.trim_matches(['[', ']']).to_ascii_lowercase());
            }
        }
    }
    None
}

/// The name asked in a DNS query, if it is one question.
pub fn dns_question(q: &[u8]) -> Option<String> {
    if q.len() < 12 || q[2] & 0x80 != 0 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*q.get(i)?);
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        labels.push(std::str::from_utf8(q.get(i + 1..i + 1 + len)?).ok()?.to_ascii_lowercase());
        i += 1 + len;
    }
    Some(labels.join("."))
}

/// An answer to a DNS query: no such domain, with the question echoed and nothing else.
pub fn dns_nxdomain(q: &[u8]) -> Option<Vec<u8>> {
    dns_question(q)?;
    let mut end = 12;
    while q[end] != 0 {
        end += 1 + usize::from(q[end]);
    }
    end += 1 + 4; // the root label, then type and class
    let mut r = q.get(..end)?.to_vec();
    // a response, recursion desired as asked, recursion available, rcode 3 (no such domain)
    r[2] = 0x80 | (q[2] & 0x01);
    r[3] = 0x80 | 3;
    r[6..12].fill(0);
    Some(r)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal TLS ClientHello naming `host`.
    pub(crate) fn client_hello(host: &str) -> Vec<u8> {
        let mut sni = vec![0u8, 0]; // list length, filled below
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let l = (sni.len() - 2) as u16;
        sni[..2].copy_from_slice(&l.to_be_bytes());
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[7u8; 32]);
        hello.push(0); // no session id
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        hello.extend_from_slice(&[1, 0]); // no compression
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&hello);
        let mut rec = vec![22, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// A DNS query for `name`, type A.
    pub(crate) fn dns_query(name: &str) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    fn filter() -> ContentFilter {
        let mut d = DomainSet::default();
        d.add_list("# a hosts file\n0.0.0.0 blocked.example\n127.0.0.1 localhost\n||ads.example^\nplain.example\n");
        ContentFilter { domains: d, nets: Vec::new(), categories: vec!["adult".into()], ..ContentFilter::default() }
    }

    #[test]
    fn a_blocked_domain_covers_its_subdomains_only() {
        let f = filter();
        assert_eq!(f.domains.len(), 3);
        assert_eq!(f.blocks_name("blocked.example"), Some(Blocked::Site));
        assert_eq!(f.blocks_name("WWW.Blocked.Example."), Some(Blocked::Site));
        assert_eq!(f.blocks_name("a.b.ads.example"), Some(Blocked::Site));
        assert_eq!(f.blocks_name("notblocked.example"), None);
        assert_eq!(f.blocks_name("example"), None);
        assert_eq!(f.blocks_name("localhost"), None);
    }

    #[test]
    fn encrypted_dns_is_refused_only_while_filtering() {
        let f = filter();
        assert_eq!(f.blocks_name("dns.google"), Some(Blocked::EncryptedDns));
        assert_eq!(f.blocks_name("mozilla.cloudflare-dns.com"), Some(Blocked::EncryptedDns));
        assert_eq!(f.blocks_dst("1.1.1.1:443".parse().unwrap(), false), Some(Blocked::EncryptedDns));
        assert_eq!(f.blocks_dst("93.184.216.34:853".parse().unwrap(), false), Some(Blocked::EncryptedDns));
        assert_eq!(f.blocks_dst("93.184.216.34:443".parse().unwrap(), true), Some(Blocked::Quic));
        assert_eq!(f.blocks_dst("93.184.216.34:443".parse().unwrap(), false), None);
        assert_eq!(f.blocks_dst("1.1.1.1:53".parse().unwrap(), true), None, "plain DNS goes to the exit's checks");
        let off = ContentFilter::default();
        assert!(!off.is_active());
        assert_eq!(off.blocks_name("dns.google"), None);
        assert_eq!(off.blocks_dst("93.184.216.34:443".parse().unwrap(), true), None);
    }

    #[test]
    fn reads_the_name_from_a_tls_client_hello_and_an_http_request() {
        assert_eq!(tls_sni(&client_hello("www.Blocked.example")).as_deref(), Some("www.blocked.example"));
        assert_eq!(tls_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(tls_sni(&client_hello("x.example")[..20]), None, "a cut-off hello reads as none");
        assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: Plain.Example:8080\r\n\r\n").as_deref(), Some("plain.example"));
        assert_eq!(http_host(b"\x16\x03\x01"), None);
    }

    #[test]
    fn a_blocked_dns_question_is_answered_no_such_domain() {
        let q = dns_query("www.blocked.example");
        assert_eq!(dns_question(&q).as_deref(), Some("www.blocked.example"));
        let r = dns_nxdomain(&q).unwrap();
        assert_eq!(&r[..2], &q[..2], "the same query id");
        assert_eq!(r[2] & 0x80, 0x80, "a response");
        assert_eq!(r[3] & 0x0f, 3, "no such domain");
        assert_eq!(&r[4..6], &[0, 1], "the question echoed");
        assert_eq!(&r[6..12], &[0; 6], "and no answers");
        assert_eq!(dns_question(&r), None, "a response is not a question");
    }
}
