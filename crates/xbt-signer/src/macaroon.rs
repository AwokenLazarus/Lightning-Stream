//! AGP-049: what the LN node's macaroon allows, read from the macaroon itself (the v2 binary format
//! and LND's identifier), so `ln_status` can show it and `ln_pay` can refuse an over-broad one on
//! mainnet. Nothing here verifies the macaroon's HMAC: that is the LN node's job, and the signer does
//! not hold the root key.
//!
//! LND's `ipaddr` / `iprange` caveats are checked against the **gRPC** peer address. LND's REST
//! gateway is an in-process gRPC client that dials `127.0.0.1` (lnd.go, `restProxyDest`), so over
//! REST every call arrives from loopback: a caveat locked to the signer's own address makes every REST
//! call fail ("macaroon locked to different IP address"), and `ipaddr 127.0.0.1` passes any REST
//! caller. An IP caveat binds only gRPC callers; for this REST client the restriction is the REST
//! listener's own address (`restlisten` on a private interface) or a firewall. Shown on the lab
//! (`scripts/ln_rail_regtest.sh`, S12).
use serde_json::{json, Value};

/// The reader lives in `xbt402::macaroon`: one parser of the format.
pub use xbt402::macaroon::{parse, Macaroon};

/// What `rail=ln` needs, and nothing else (the README's baked macaroon).
pub const NEEDED_OPS: [&str; 4] = ["info:read", "offchain:read", "offchain:write", "onchain:read"];

/// Permissions that let a holder move funds on chain, sign arbitrary data or mint new macaroons, named in
/// `ln_status`. Mainnet refuses every permission outside [`NEEDED_OPS`], not only these (AGP-066).
pub const DANGEROUS_OPS: [&str; 4] = ["onchain:write", "macaroon:generate", "macaroon:write", "signer:generate"];

/// What the rail asks of a macaroon (the reader itself is `xbt402::macaroon`).
pub trait RailMacaroon {
    fn excess_ops(&self) -> Vec<String>;
    fn dangerous_ops(&self) -> Vec<String>;
    fn beyond_needed(&self) -> Option<String>;
    fn report(&self) -> Value;
}

impl RailMacaroon for Macaroon {
    fn excess_ops(&self) -> Vec<String> {
        self.ops.iter().filter(|o| !NEEDED_OPS.contains(&o.as_str())).cloned().collect()
    }

    fn dangerous_ops(&self) -> Vec<String> {
        self.ops.iter().filter(|o| DANGEROUS_OPS.contains(&o.as_str()) || o.ends_with(":*")).cloned().collect()
    }

    /// AGP-066 (review L2): why this macaroon is more than `rail=ln` needs, if it is. An allowlist: any
    /// permission outside [`NEEDED_OPS`] (a `uri:` one such as `uri:/lnrpc.Lightning/SendCoins` included),
    /// or permissions that cannot be read from the identifier.
    fn beyond_needed(&self) -> Option<String> {
        let need = NEEDED_OPS.join(" ");
        // AGP-109: an identifier that does not read to its end may hold more than was read
        if !self.readable() {
            return Some(format!("the LN macaroon's permissions cannot be read (not an LND identifier): bake one with only {need}"));
        }
        let excess = self.excess_ops();
        (!excess.is_empty()).then(|| format!("the LN macaroon grants {}: bake one with only {need}", excess.join(", ")))
    }

    /// For `ln_status`: the permissions and caveats, with what each means for a REST client.
    fn report(&self) -> Value {
        let ip = self.caveat("ipaddr").or_else(|| self.caveat("iprange"));
        let ip_note = match &ip {
            None => "no IP caveat: the macaroon works from any address that reaches the REST listener".to_string(),
            Some(a) if a == "127.0.0.1" || a == "::1" || a.starts_with("127.") => {
                format!("IP caveat {a}: LND's REST gateway dials gRPC from 127.0.0.1, so this passes every REST caller; \
                         restrict the REST listener (restlisten) or firewall it")
            }
            Some(a) => format!("IP caveat {a}: over REST LND sees 127.0.0.1, so REST calls fail unless {a} covers loopback"),
        };
        json!({"ops": self.ops, "excess_ops": self.excess_ops(), "dangerous_ops": self.dangerous_ops(), "only_needed": self.beyond_needed().is_none(),
               "caveats": self.caveats,
               "ip_caveat": ip, "ip_note": ip_note, "time_before": self.caveat("time-before")})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use xbt402::macaroon::lnd_macaroon_for_tests as lnd_macaroon;

    #[test]
    fn reads_lnd_ops_and_caveats() {
        let b = lnd_macaroon(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read"])], &["ipaddr 127.0.0.1"]);
        let m = parse(&b).unwrap();
        assert_eq!(m.location, "lnd");
        assert_eq!(m.ops, vec!["info:read", "offchain:read", "offchain:write", "onchain:read"]);
        assert_eq!(m.caveat("ipaddr").as_deref(), Some("127.0.0.1"));
        assert!(m.excess_ops().is_empty() && m.dangerous_ops().is_empty() && m.beyond_needed().is_none());
        // AGP-066: a URI-scoped permission is no "dangerous" entity, and the allowlist still refuses it
        let uri = parse(&lnd_macaroon(&[("info", &["read"]), ("uri", &["/lnrpc.Lightning/SendCoins"])], &[])).unwrap();
        assert!(uri.dangerous_ops().is_empty());
        assert!(uri.beyond_needed().unwrap().contains("grants uri:/lnrpc.Lightning/SendCoins"));
        assert!(parse(&lnd_macaroon(&[], &[])).unwrap().beyond_needed().unwrap().contains("cannot be read"));
        assert!(m.report()["ip_note"].as_str().unwrap().contains("passes every REST caller"));
        let admin = parse(&lnd_macaroon(&[("onchain", &["read", "write"]), ("macaroon", &["generate"])], &[])).unwrap();
        assert_eq!(admin.dangerous_ops(), vec!["macaroon:generate", "onchain:write"]);
        assert!(admin.report()["ip_note"].as_str().unwrap().starts_with("no IP caveat"));
        let locked = parse(&lnd_macaroon(&[("info", &["read"])], &["ipaddr 172.18.0.1", "time-before 2030-01-01T00:00:00Z"])).unwrap();
        assert!(locked.report()["ip_note"].as_str().unwrap().contains("REST calls fail"));
        assert_eq!(locked.caveat("time-before").as_deref(), Some("2030-01-01T00:00:00Z"));
    }

    #[test]
    fn refuses_garbage() {
        assert!(parse(b"").is_err());
        assert!(parse(&[1, 2, 3]).is_err());
        let mut b = lnd_macaroon(&[("info", &["read"])], &[]);
        b.truncate(b.len() - 10);
        assert!(parse(&b).is_err());
    }
}
