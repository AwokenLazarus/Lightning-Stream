//! Checking an exit's region.
//!
//! An exit announces a region on Nostr. The buyer's app does not take its word: it looks up the
//! exit's observed public egress address in an offline geo-IP table (DB-IP's "IP to Country Lite"
//! CSV or similar, bundled with the app and refreshed with it, so no lookup ever leaves the buyer's
//! box), and checks that the round trip is not faster than light allows for the distance. A
//! mismatch is flagged and the exit is not offered for that region.

use std::net::IpAddr;

/// An offline table of address ranges and their country codes.
#[derive(Debug, Default)]
pub struct GeoTable {
    v4: Vec<(u32, u32, [u8; 2])>,
    v6: Vec<(u128, u128, [u8; 2])>,
}

impl GeoTable {
    /// Reads `first,last,CC` lines (DB-IP's country CSV); lines it cannot read are skipped.
    pub fn from_csv(text: &str) -> GeoTable {
        let mut t = GeoTable::default();
        for line in text.lines() {
            let mut f = line.split(',').map(|s| s.trim().trim_matches('"'));
            let (Some(a), Some(b), Some(cc)) = (f.next(), f.next(), f.next()) else { continue };
            let cc: [u8; 2] = match cc.as_bytes() {
                [x, y] => [x.to_ascii_uppercase(), y.to_ascii_uppercase()],
                _ => continue,
            };
            match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
                (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) => t.v4.push((u32::from(a), u32::from(b), cc)),
                (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) => t.v6.push((u128::from(a), u128::from(b), cc)),
                _ => {}
            }
        }
        t.v4.sort_unstable();
        t.v6.sort_unstable();
        t
    }

    /// The country code of an address, if the table has it.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        fn find<T: Ord + Copy>(ranges: &[(T, T, [u8; 2])], x: T) -> Option<[u8; 2]> {
            let i = ranges.partition_point(|r| r.0 <= x);
            let r = ranges.get(i.checked_sub(1)?)?;
            (x <= r.1).then_some(r.2)
        }
        let cc = match ip {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => find(&self.v6, u128::from(a)),
        }?;
        Some(String::from_utf8_lossy(&cc).into_owned())
    }
}

/// What the check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegionCheck {
    /// The egress address is in the announced region, and the round trip is plausible.
    Verified,
    /// The egress address is in another country.
    Elsewhere(String),
    /// The round trip is faster than the distance allows: the exit is nearer than it claims.
    TooFast,
    /// The table does not know the address.
    Unknown,
}

/// Light in fibre covers about 200 km a millisecond; a round trip covers the distance twice.
const KM_PER_MS_FIBRE: f64 = 200.0;

/// Whether a round trip of `rtt_ms` is possible over `km` (allowing 20% for measurement).
pub fn rtt_plausible(rtt_ms: f64, km: f64) -> bool {
    rtt_ms >= 0.8 * 2.0 * km / KM_PER_MS_FIBRE
}

/// Checks an exit's announced region against its egress address and, if the buyer knows its own
/// distance to that region, the round trip.
pub fn check(table: &GeoTable, announced: &str, egress: IpAddr, rtt_ms: Option<f64>, km_to_region: Option<f64>) -> RegionCheck {
    match table.country(egress) {
        None => RegionCheck::Unknown,
        Some(cc) if !cc.eq_ignore_ascii_case(announced) => RegionCheck::Elsewhere(cc),
        Some(_) => match (rtt_ms, km_to_region) {
            (Some(rtt), Some(km)) if !rtt_plausible(rtt, km) => RegionCheck::TooFast,
            _ => RegionCheck::Verified,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "\
1.0.0.0,1.0.0.255,AU
5.9.0.0,5.9.255.255,DE
8.8.8.0,8.8.8.255,US
2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US
bad line
";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn looks_up_countries_offline() {
        let t = GeoTable::from_csv(CSV);
        assert_eq!(t.country(ip("5.9.1.2")).as_deref(), Some("DE"));
        assert_eq!(t.country(ip("8.8.8.8")).as_deref(), Some("US"));
        assert_eq!(t.country(ip("2001:4860::8888")).as_deref(), Some("US"));
        assert_eq!(t.country(ip("9.9.9.9")), None);
        assert_eq!(t.country(ip("0.0.0.1")), None);
    }

    #[test]
    fn a_region_that_does_not_match_the_egress_is_flagged() {
        let t = GeoTable::from_csv(CSV);
        assert_eq!(check(&t, "DE", ip("5.9.1.2"), None, None), RegionCheck::Verified);
        assert_eq!(check(&t, "de", ip("5.9.1.2"), None, None), RegionCheck::Verified);
        assert_eq!(check(&t, "DE", ip("8.8.8.8"), None, None), RegionCheck::Elsewhere("US".into()));
        assert_eq!(check(&t, "DE", ip("9.9.9.9"), None, None), RegionCheck::Unknown);
    }

    #[test]
    fn a_round_trip_faster_than_light_allows_is_flagged() {
        let t = GeoTable::from_csv(CSV);
        // Germany is about 8,000 km from the US west coast: at least ~64 ms round trip
        assert_eq!(check(&t, "DE", ip("5.9.1.2"), Some(5.0), Some(8000.0)), RegionCheck::TooFast);
        assert_eq!(check(&t, "DE", ip("5.9.1.2"), Some(140.0), Some(8000.0)), RegionCheck::Verified);
        assert!(rtt_plausible(0.5, 10.0));
    }
}
