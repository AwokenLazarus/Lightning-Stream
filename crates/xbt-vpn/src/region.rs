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

    /// Whether it holds no ranges (a file that was not a table).
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
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

/// Reads the egress address out of an `ip=` line, as a trace page through the exit answers it
/// (`/cdn-cgi/trace` on 1.1.1.1 prints `ip=<the address the request came from>`).
pub fn parse_trace(body: &str) -> Option<IpAddr> {
    body.lines().find_map(|l| l.strip_prefix("ip=")).and_then(|v| v.trim().parse().ok())
}

/// Where an exit's egress address is read, through the exit: HTTPS pages run by different
/// operators, each printing the address the request came from. Over TLS, so the exit can't
/// change what they say (a plain page, or STUN, it could). Each: address, TLS name, path, and
/// whether the body is a trace (`ip=` line) or the bare address.
pub const EGRESS_SOURCES: &[(&str, &str, &str, bool)] = &[
    ("one.one.one.one:443", "one.one.one.one", "/cdn-cgi/trace", true),
    ("checkip.amazonaws.com:443", "checkip.amazonaws.com", "/", false),
    ("ifconfig.co:443", "ifconfig.co", "/ip", false),
    ("api64.ipify.org:443", "api64.ipify.org", "/", false),
    ("ipinfo.io:443", "ipinfo.io", "/ip", false),
    ("ident.me:443", "ident.me", "/", false),
    ("ifconfig.me:443", "ifconfig.me", "/ip", false),
    ("www.cloudflare.com:443", "www.cloudflare.com", "/cdn-cgi/trace", true),
];

/// How many of [`EGRESS_SOURCES`] one check asks, drawn at random: an exit can't know in advance
/// which sites to route apart from its buyers' traffic. Best-effort all the same: an exit that
/// routes every one of them elsewhere is not caught.
pub const SOURCES_PER_CHECK: usize = 4;

/// `n` distinct indexes into [`EGRESS_SOURCES`], drawn with `rand(i)` (a source of random numbers).
pub fn pick_sources(n: usize, mut rand: impl FnMut() -> u64) -> Vec<usize> {
    let mut all: Vec<usize> = (0..EGRESS_SOURCES.len()).collect();
    // a partial Fisher-Yates shuffle
    let n = n.min(all.len());
    for i in 0..n {
        let j = i + (rand() as usize) % (all.len() - i);
        all.swap(i, j);
    }
    all.truncate(n);
    all
}

/// One check over both address families: the IPv4 result stands, unless the exit's IPv6 traffic
/// (where it has any that the sources agree on) comes out elsewhere, which it then reports.
pub fn both_families(v4: RegionCheck, v6: Option<RegionCheck>) -> RegionCheck {
    match (v4, v6) {
        (RegionCheck::Verified, Some(v6)) if v6 != RegionCheck::Verified && v6 != RegionCheck::Unknown => v6,
        (v4, _) => v4,
    }
}

/// The address the sources agree on: at least `need` of them answered, and every one that
/// answered said the same. Sources that disagree mean nothing is believed (one of them was lied
/// to, or the exit's traffic leaves by more than one address).
pub fn egress_quorum(answers: &[Option<IpAddr>], need: usize) -> Option<IpAddr> {
    let got: Vec<IpAddr> = answers.iter().flatten().copied().collect();
    let first = *got.first()?;
    (got.len() >= need.max(1) && got.iter().all(|a| *a == first)).then_some(first)
}

/// An address from a source's body: a trace's `ip=` line, or the bare address.
pub fn parse_egress(body: &str, trace: bool) -> Option<IpAddr> {
    if trace {
        parse_trace(body)
    } else {
        body.trim().parse().ok()
    }
}

/// Rough centres of countries (latitude, longitude), for a lower bound on the distance to a region.
/// Countries not listed get no round-trip check; their egress address is still checked.
const CENTRES: &[(&str, f64, f64)] = &[
    ("AE", 24.0, 54.0), ("AR", -34.0, -64.0), ("AT", 47.5, 14.5), ("AU", -25.0, 134.0), ("BE", 50.6, 4.6),
    ("BG", 42.7, 25.5), ("BR", -10.0, -52.0), ("CA", 56.0, -96.0), ("CH", 46.8, 8.2), ("CL", -35.0, -71.0),
    ("CN", 35.0, 104.0), ("CO", 4.0, -73.0), ("CZ", 49.8, 15.5), ("DE", 51.2, 10.4), ("DK", 56.0, 10.0),
    ("EE", 58.6, 25.0), ("EG", 26.8, 30.8), ("ES", 40.4, -3.7), ("FI", 64.0, 26.0), ("FR", 46.6, 2.4),
    ("GB", 54.0, -2.0), ("GR", 39.0, 22.0), ("HK", 22.3, 114.2), ("HR", 45.1, 15.2), ("HU", 47.2, 19.5),
    ("ID", -2.5, 118.0), ("IE", 53.4, -8.2), ("IL", 31.0, 35.0), ("IN", 22.0, 79.0), ("IS", 65.0, -18.0),
    ("IT", 42.8, 12.8), ("JP", 36.2, 138.3), ("KE", 0.0, 38.0), ("KR", 36.5, 127.9), ("KZ", 48.0, 67.0),
    ("LT", 55.2, 23.9), ("LU", 49.8, 6.1), ("LV", 56.9, 24.6), ("MD", 47.4, 28.4), ("MX", 23.6, -102.5),
    ("MY", 4.2, 102.0), ("NG", 9.1, 8.7), ("NL", 52.1, 5.3), ("NO", 61.0, 8.5), ("NZ", -41.0, 174.0),
    ("PE", -9.2, -75.0), ("PH", 12.9, 121.8), ("PK", 30.4, 69.3), ("PL", 52.0, 19.1), ("PT", 39.6, -8.0),
    ("RO", 45.9, 24.9), ("RS", 44.0, 21.0), ("RU", 60.0, 90.0), ("SA", 24.0, 45.0), ("SE", 62.0, 15.0),
    ("SG", 1.35, 103.8), ("SI", 46.1, 14.9), ("SK", 48.7, 19.7), ("TH", 15.9, 101.0), ("TR", 39.0, 35.2),
    ("TW", 23.7, 121.0), ("UA", 49.0, 31.4), ("US", 39.8, -98.6), ("VN", 16.0, 107.8), ("ZA", -29.0, 24.0),
];

/// Slack taken off the distance between two country centres, so the bound stays below the true
/// distance even between the near edges of large countries.
const CENTRE_SLACK_KM: f64 = 2500.0;

/// A lower bound on the distance from `home` to `region` (country codes), if both are known.
pub fn km_between(home: &str, region: &str) -> Option<f64> {
    let at = |cc: &str| CENTRES.iter().find(|c| c.0.eq_ignore_ascii_case(cc)).map(|c| (c.1, c.2));
    let ((la1, lo1), (la2, lo2)) = (at(home)?, at(region)?);
    let (p1, p2) = (la1.to_radians(), la2.to_radians());
    let (dp, dl) = ((la2 - la1).to_radians(), (lo2 - lo1).to_radians());
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    let km = 2.0 * 6371.0 * a.sqrt().asin();
    Some((km - CENTRE_SLACK_KM).max(0.0))
}

/// DB-IP's free "IP to Country Lite" table (CC BY 4.0, <https://db-ip.com>): one file a month.
pub const DBIP_URL: &str = "https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.csv.gz";

/// How long a downloaded table is used before a newer month is fetched.
pub const TABLE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(35 * 86400);

/// Where the image keeps the table it ships with (refreshed at each release).
pub const BUNDLED: &str = "/usr/share/xbt-vpn/dbip-country-lite.csv.gz";

/// The geo-IP table: a copy fetched into `dir` while it is under [`TABLE_MAX_AGE`]; else a newer
/// month fetched from `url`, if one is set; else the copy in `dir` however old; else the table
/// the app shipped with (`bundled`, gzipped). Nothing here needs the network: a box that never
/// reaches `url` (or has none set) uses the bundled table from install.
pub fn load(dir: &std::path::Path, bundled: Option<&std::path::Path>, url: Option<&str>) -> std::io::Result<GeoTable> {
    use std::io::Read;
    let path = dir.join("dbip-country-lite.csv");
    let fetched = match url.filter(|u| !u.trim().is_empty()) {
        Some(u) => load_or_fetch(dir, u).ok(),
        None => std::fs::read_to_string(&path).ok().map(|t| GeoTable::from_csv(&t)),
    };
    if let Some(t) = fetched.filter(|t| !t.is_empty()) {
        return Ok(t);
    }
    let b = bundled.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no geo-IP table: none fetched and none bundled"))?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(b)?).take(512 << 20).read_to_string(&mut text)?;
    Ok(GeoTable::from_csv(&text))
}

/// The geo-IP table kept in `dir` (`dbip-country-lite.csv`), fetched when missing or older than
/// [`TABLE_MAX_AGE`] (this month's file, else last month's). A failed fetch keeps the old copy.
pub fn load_or_fetch(dir: &std::path::Path, url: &str) -> std::io::Result<GeoTable> {
    use std::io::Read;
    std::fs::create_dir_all(dir)?;
    let path = dir.join("dbip-country-lite.csv");
    let fresh = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age < TABLE_MAX_AGE);
    if !fresh {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        for months_back in 0..2 {
            let ym = year_month(now, months_back);
            let resp = match ureq::get(&url.replace("{YYYY-MM}", &ym)).timeout(std::time::Duration::from_secs(300)).call() {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut gz = Vec::new();
            if resp.into_reader().take(64 << 20).read_to_end(&mut gz).is_err() {
                continue;
            }
            let mut text = String::new();
            if flate2::read::GzDecoder::new(&gz[..]).take(512 << 20).read_to_string(&mut text).is_err() || text.lines().count() < 1000 {
                continue;
            }
            let tmp = dir.join("dbip-country-lite.csv.tmp");
            std::fs::write(&tmp, &text)?;
            std::fs::rename(&tmp, &path)?;
            break;
        }
    }
    Ok(GeoTable::from_csv(&std::fs::read_to_string(&path)?))
}

/// `YYYY-MM` for the month `months_back` before the one holding `unix_secs` (UTC).
fn year_month(unix_secs: u64, months_back: u32) -> String {
    // civil-from-days (Howard Hinnant)
    let z = (unix_secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let total = y * 12 + (m - 1) - i64::from(months_back);
    format!("{:04}-{:02}", total.div_euclid(12), total.rem_euclid(12) + 1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn sources_are_drawn_at_random_and_never_twice() {
        let mut seed = 7u64;
        let mut rand = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        let a = super::pick_sources(super::SOURCES_PER_CHECK, &mut rand);
        assert_eq!(a.len(), super::SOURCES_PER_CHECK);
        assert!(a.iter().all(|i| *i < super::EGRESS_SOURCES.len()));
        let mut d = a.clone();
        d.sort();
        d.dedup();
        assert_eq!(d.len(), a.len(), "no source twice");
        let draws: std::collections::HashSet<Vec<usize>> = (0..20).map(|_| super::pick_sources(super::SOURCES_PER_CHECK, &mut rand)).collect();
        assert!(draws.len() > 1, "not the same four every time");
        assert_eq!(super::pick_sources(99, &mut rand).len(), super::EGRESS_SOURCES.len());
    }

    #[test]
    fn an_exits_ipv6_traffic_elsewhere_is_caught() {
        use super::RegionCheck::*;
        assert_eq!(super::both_families(Verified, None), Verified, "no IPv6 out of the exit: the IPv4 check stands");
        assert_eq!(super::both_families(Verified, Some(Unknown)), Verified);
        assert_eq!(super::both_families(Verified, Some(Elsewhere("US".into()))), Elsewhere("US".into()));
        assert_eq!(super::both_families(Elsewhere("FR".into()), Some(Verified)), Elsewhere("FR".into()));
    }

    use super::*;

    #[test]
    fn the_egress_address_is_read_from_a_trace_page() {
        let body = "fl=12f\nh=1.1.1.1\nip=203.0.113.7\nts=1\nloc=DE\n";
        assert_eq!(parse_trace(body), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(parse_trace("ip=2001:db8::5\n"), Some("2001:db8::5".parse().unwrap()));
        assert_eq!(parse_trace("nothing here"), None);
    }

    #[test]
    fn the_egress_address_is_believed_only_where_independent_sources_agree() {
        let (a, b) = (Some(ip("203.0.113.7")), Some(ip("198.51.100.9")));
        assert_eq!(egress_quorum(&[a, a, None], 2), a);
        assert_eq!(egress_quorum(&[a, None, None], 2), None, "one source is not enough");
        assert_eq!(egress_quorum(&[a, b, a], 2), None, "sources that disagree: nothing is believed");
        assert_eq!(egress_quorum(&[None, None], 2), None);
        assert_eq!(egress_quorum(&[a], 1), a, "a single configured source (a test) needs one");
        assert_eq!(parse_egress("203.0.113.7\n", false), a);
        assert_eq!(parse_egress("ip=203.0.113.7\n", true), a);
        assert_eq!(parse_egress("<html>", false), None);
    }

    #[test]
    fn a_distance_bound_is_below_the_true_distance_and_zero_nearby() {
        let us_jp = km_between("US", "JP").unwrap();
        assert!(us_jp > 5000.0 && us_jp < 10_500.0, "{us_jp}");
        assert_eq!(km_between("DE", "NL"), Some(0.0), "neighbours are within the slack");
        assert_eq!(km_between("DE", "XX"), None);
        // a claim of Japan with a 5 ms round trip from the US cannot be true
        assert!(!rtt_plausible(5.0, us_jp));
        assert!(rtt_plausible(140.0, us_jp));
    }

    #[test]
    fn months_count_back_across_a_new_year() {
        // 2026-01-15
        let t = 1_768_435_200;
        assert_eq!(year_month(t, 0), "2026-01");
        assert_eq!(year_month(t, 1), "2025-12");
    }

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
    fn the_table_shipped_with_the_app_is_used_with_no_network() {
        use std::io::Write;
        let dir = tempfile_dir();
        let bundled = dir.join("bundled.csv.gz");
        let mut gz = flate2::write::GzEncoder::new(std::fs::File::create(&bundled).unwrap(), flate2::Compression::fast());
        gz.write_all(CSV.as_bytes()).unwrap();
        gz.finish().unwrap();
        // no download source set: the bundled table, and nothing fetched
        let t = load(&dir.join("geo"), Some(&bundled), None).unwrap();
        assert_eq!(t.country(ip("5.9.1.2")).as_deref(), Some("DE"));
        // a source that can't be reached: the bundled table still
        let t = load(&dir.join("geo"), Some(&bundled), Some("http://127.0.0.1:9/{YYYY-MM}.csv.gz")).unwrap();
        assert_eq!(t.country(ip("8.8.8.8")).as_deref(), Some("US"));
        assert!(load(&dir.join("geo"), None, None).is_err(), "no table at all is said, not guessed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("xbt-vpn-geo-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&d).unwrap();
        d
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
