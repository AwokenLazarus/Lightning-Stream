//! Escaping, the page layout and value formatting. Every URL is relative (`./x`), so the UI works
//! under any proxy prefix and on an .onion; nothing is loaded from elsewhere.
use serde_json::Value;

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// A JSON value as display text (strings unquoted).
pub fn txt(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
    }
}

pub fn escv(v: Option<&Value>) -> String {
    esc(&txt(v))
}

pub fn int(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

pub(crate) fn group3(n: u64) -> String {
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            o.push(',');
        }
        o.push(c);
    }
    o
}

/// `150,000 sats (0.00150000 XBT)`.
pub fn sats(n: i64) -> String {
    let sign = if n < 0 { "-" } else { "" };
    let a = n.unsigned_abs();
    format!("{sign}{} sats <span class=\"xbt\">({sign}{}.{:08} XBT)</span>", group3(a), a / 100_000_000, a % 100_000_000)
}

/// Millisats as sats, without a unit, with the fraction where there is one: `900`, `2.009`, `1,250.5`.
pub fn msat_num(m: u64) -> String {
    let whole = group3(m / 1000);
    if m.is_multiple_of(1000) { whole } else { format!("{whole}.{}", format!("{:03}", m % 1000).trim_end_matches('0')) }
}

/// What a payment cost, said one way on every page (0.2.3: Wallet, Live connections and the visit
/// showed three figures for one payment). **Paid** is what left the node: the amount the payee got
/// plus the routing fee, from the signer's settled record, exactly (`902.009`), with its two parts,
/// where the record has them; else the whole sats the signer booked (`paid_sats`). The total is the
/// sum of its parts, never the booked figure rounded up per payment beside them (0.2.5 said "903 sats
/// (900 + 2.009 fee)"). The other two figures a page names are **used** (what the seller drew) and
/// **credit left** (paid and not used yet); a reservation before a payment settles is **reserved**,
/// never paid.
pub fn paid_html(paid_sats: i64, parts_msat: Option<(u64, u64)>) -> String {
    match parts_msat {
        Some((v, f)) => format!("<span class=\"money\">{} sats</span> <span class=\"small\">({} + {} fee)</span>", msat_num(v.saturating_add(f)), msat_num(v), msat_num(f)),
        None => format!("<span class=\"money\">{} sats</span>", group3(paid_sats.max(0).unsigned_abs())),
    }
}

/// UTC `YYYY-MM-DD HH:MM:SS` from Unix seconds.
pub fn utc(t: i64) -> String {
    if t <= 0 {
        return "-".into();
    }
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // civil_from_days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", secs / 3600, secs % 3600 / 60, secs % 60)
}

pub fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

pub struct Nav<'a> {
    pub active: &'a str,
    pub csrf: &'a str,
    pub pending: usize,
    pub logged_in: bool,
    pub sections: &'a [&'static Section],
    pub brand: &'a str,
    /// The switch between the simple view and every page: `None` where there is none (the gateway,
    /// a page before the login), else whether every page is shown now.
    pub advanced: Option<bool>,
}

/// One page in a section: its address, the title it is shown under (and found by), the tab's words.
pub struct Tab {
    pub href: &'static str,
    pub title: &'static str,
    pub label: &'static str,
}

/// A top-level entry of the menu, with its pages as tabs. A page whose title no tab names (a
/// service's own page) still marks its section through `also`. `advanced`: pages most owners never
/// need, behind one Advanced tab, with their own row of tabs once there.
pub struct Section {
    pub label: &'static str,
    pub tabs: &'static [Tab],
    pub also: &'static [&'static str],
    pub advanced: &'static [Tab],
}

impl Section {
    fn has(&self, title: &str) -> bool {
        self.tabs.iter().any(|t| t.title == title) || self.also.contains(&title) || self.in_advanced(title)
    }

    fn in_advanced(&self, title: &str) -> bool {
        self.advanced.iter().any(|t| t.title == title)
    }
}

/// The tab that leads to a section's advanced pages.
pub const ADVANCED: &str = "Advanced";

/// Buying: paired with Sell.
/// Two tabs: what there is to buy, and what is being paid for now. AI, Hashrate and VPN are chips of Browse, beside the
/// other kinds of service, and the Sellers page is linked from Browse and Wallet.
pub const SERVICES: Section = Section {
    label: "Buy",
    tabs: &[Tab { href: "./browse", title: "Browse", label: "Browse" }, Tab { href: "./connections", title: "Live connections", label: "Live connections" }],
    also: &["Service", "AI", "VPN", "Sellers"],
    advanced: &[],
};
pub const SELL: Section = Section {
    label: "Sell",
    tabs: &[Tab { href: "./sell", title: "Sell", label: "Your services" }, Tab { href: "./sell-vpn", title: "VPN exit", label: "VPN exit" }],
    also: &[],
    advanced: &[],
};
pub const WALLET: Section = Section {
    label: "Wallet",
    tabs: &[Tab { href: "./wallet", title: "Wallet", label: "Balance and activity" }, Tab { href: "./approvals", title: "Approvals", label: "Approvals" }],
    also: &[],
    advanced: &[],
};
pub const APPS: Section = Section {
    label: "Apps & agents",
    tabs: &[Tab { href: "./apps", title: "Apps", label: "Apps" }, Tab { href: "./agents", title: "AI agents", label: "AI agents" }],
    also: &[],
    advanced: &[],
};
pub const SETTINGS: Section = Section {
    label: "Settings",
    tabs: &[Tab { href: "./setup", title: "Setup", label: "Setup" }, Tab { href: "./lightning", title: "Your node", label: "Your node" },
            Tab { href: "./policy", title: "Spending rules", label: "Spending rules" }, Tab { href: "./keys", title: "Keys and backup", label: "Keys and backup" }],
    also: &[],
    advanced: &[Tab { href: "./signatures", title: "Records", label: "Records" }, Tab { href: "./relays", title: "Stream relays", label: "Stream relays" },
                Tab { href: "./channels", title: "Old channels", label: "Old channels" }],
};
/// With hashrate: the gateway rented work goes to, beside the node.
pub const SETTINGS_HASH: Section = Section {
    label: "Settings",
    tabs: &[Tab { href: "./setup", title: "Setup", label: "Setup" }, Tab { href: "./lightning", title: "Your node", label: "Your node" },
            Tab { href: "./your-gateway", title: "Your gateway", label: "Your gateway" },
            Tab { href: "./policy", title: "Spending rules", label: "Spending rules" }, Tab { href: "./keys", title: "Keys and backup", label: "Keys and backup" }],
    also: &[],
    advanced: SETTINGS.advanced,
};
/// With hashrate (the box runs the hasher's or the renter's service): renting miners is one
/// more kind of service, beside the others.
pub const SERVICES_HASH: Section = Section {
    label: "Buy",
    tabs: &[Tab { href: "./browse", title: "Browse", label: "Browse" }, Tab { href: "./connections", title: "Live connections", label: "Live connections" }],
    also: &["Service", "AI", "Hashrate", "VPN", "Sellers"],
    advanced: &[],
};
pub const SELL_HASH: Section = Section {
    label: "Sell",
    tabs: &[Tab { href: "./sell", title: "Sell", label: "Your services" }, Tab { href: "./sell-hashrate", title: "Sell hashrate", label: "Hashrate" },
            Tab { href: "./sell-vpn", title: "VPN exit", label: "VPN exit" }],
    also: &[],
    advanced: &[],
};
/// The simple view: four entries, one page each, for an owner who buys. Selling, setup and the other
/// pages stay where they are, behind the Advanced switch.
pub const SIMPLE_WALLET: Section = Section { label: "Wallet", tabs: &[Tab { href: "./wallet", title: "Wallet", label: "Wallet" }], also: &["Approvals"], advanced: &[] };
pub const SIMPLE_SHOPS: Section = Section {
    label: "Shops",
    tabs: &[Tab { href: "./browse", title: "Browse", label: "Shops" }],
    also: &["Service", "AI", "Hashrate", "VPN", "Sellers", "Live connections"],
    advanced: &[],
};
pub const SIMPLE_LIMITS: Section = Section { label: "Limits", tabs: &[Tab { href: "./limits", title: "Limits", label: "Limits" }], also: &["Spending rules"], advanced: &[] };
pub const SIMPLE_ACTIVITY: Section = Section { label: "Activity", tabs: &[Tab { href: "./activity", title: "Activity", label: "Activity" }], also: &[], advanced: &[] };
pub const SIMPLE_SECTIONS: [&Section; 4] = [&SIMPLE_WALLET, &SIMPLE_SHOPS, &SIMPLE_LIMITS, &SIMPLE_ACTIVITY];
/// The app with Sell (`XBT_UI_SELL=1`): buying and selling.
pub const STREAM_SECTIONS: [&Section; 5] = [&SERVICES, &SELL, &WALLET, &APPS, &SETTINGS];
pub const STREAM_SECTIONS_HASH: [&Section; 5] = [&SERVICES_HASH, &SELL_HASH, &WALLET, &APPS, &SETTINGS_HASH];
/// The wallet alone: buying.
pub const WALLET_SECTIONS: [&Section; 4] = [&SERVICES, &WALLET, &APPS, &SETTINGS];
pub const WALLET_SECTIONS_HASH: [&Section; 4] = [&SERVICES_HASH, &WALLET, &APPS, &SETTINGS_HASH];
pub const GATEWAY_SECTIONS: [&Section; 0] = [];
pub const STREAM_BRAND: &str = "Lightning Stream";
pub const WALLET_BRAND: &str = "Lightning Stream";
pub const GATEWAY_BRAND: &str = "Lightning Stream";

pub fn page(title: &str, nav: &Nav, flash: Option<(bool, String)>, body: &str) -> String {
    page_head(title, nav, flash, body, "")
}

/// As [`page`], with extra markup inside `<head>` (a refresh, for the connections page). `head` is
/// this crate's own markup, never a value from a request or from a seller.
pub fn page_head(title: &str, nav: &Nav, flash: Option<(bool, String)>, body: &str, head: &str) -> String {
    let mut links = String::new();
    let mut tabs = String::new();
    let mut banner = String::new();
    // the simple view's four entries again, as a bar at the bottom of a phone's screen
    let mut bar = String::new();
    let simple = nav.logged_in && nav.advanced == Some(false);
    if nav.logged_in {
        for sec in nav.sections {
            let here = sec.has(nav.active);
            let cur = if here { " aria-current=\"page\"" } else { "" };
            let badge = if std::ptr::eq(*sec, &WALLET) || sec.label == WALLET.label {
                format!(" <span id=\"pending-badge\" class=\"badge\" title=\"waiting for your approval\"{}>{}</span>", if nav.pending == 0 { " hidden" } else { "" },
                        if nav.pending == 0 { String::new() } else { nav.pending.to_string() })
            } else {
                String::new()
            };
            links.push_str(&format!("<a href=\"{}\"{cur}>{}{badge}</a>", sec.tabs[0].href, esc(sec.label)));
            if simple {
                bar.push_str(&format!("<a href=\"{}\"{cur}>{}</a>", sec.tabs[0].href, esc(sec.label)));
            }
            if here && sec.tabs.len() + sec.advanced.len() > 1 {
                tabs.push_str(&format!("<nav class=\"tabs\" aria-label=\"{}\">", esc(sec.label)));
                for t in sec.tabs {
                    let cur = if t.title == nav.active { " aria-current=\"page\"" } else { "" };
                    tabs.push_str(&format!("<a href=\"{}\"{cur}>{}</a>", t.href, esc(t.label)));
                }
                let in_adv = sec.in_advanced(nav.active);
                if let Some(first) = sec.advanced.first() {
                    let cur = if in_adv { " aria-current=\"page\"" } else { "" };
                    tabs.push_str(&format!("<a href=\"{}\"{cur}>{ADVANCED}</a>", first.href));
                }
                tabs.push_str("</nav>");
                if in_adv {
                    tabs.push_str(&format!("<nav class=\"tabs sub\" aria-label=\"{ADVANCED}\">"));
                    for t in sec.advanced {
                        let cur = if t.title == nav.active { " aria-current=\"page\"" } else { "" };
                        tabs.push_str(&format!("<a href=\"{}\"{cur}>{}</a>", t.href, esc(t.label)));
                    }
                    tabs.push_str("</nav>");
                }
            }
        }
        if let Some(on) = nav.advanced {
            let (to, words, title) = if on { ("0", "Simple view", "Show only Wallet, Shops, Limits and Activity") }
                                     else { ("1", "Advanced", "Show every page: selling, setup, keys and the rest") };
            links.push_str(&format!("<form method=\"post\" action=\"./advanced\" class=\"inline\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                                     <input type=\"hidden\" name=\"on\" value=\"{to}\"><button class=\"link view-switch\" title=\"{title}\">{words}</button></form>", esc(nav.csrf)));
        }
        links.push_str(&format!("<form method=\"post\" action=\"./logout\" class=\"inline\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                                 <button class=\"link\">Log out</button></form>", esc(nav.csrf)));
        if nav.pending > 0 && nav.active != "Approvals" {
            banner = format!("<div class=\"flash warn banner\"><a href=\"./approvals\">{} payment{} wait{} for your approval. Review {} →</a></div>",
                             nav.pending, if nav.pending == 1 { "" } else { "s" }, if nav.pending == 1 { "s" } else { "" },
                             if nav.pending == 1 { "it" } else { "them" });
        }
    }
    let menu = if nav.logged_in && !nav.sections.is_empty() {
        format!("<button type=\"button\" class=\"menu-toggle\" aria-expanded=\"false\" aria-controls=\"site-nav\">Menu</button>\
                 <nav id=\"site-nav\" aria-label=\"Main\">{links}</nav>")
    } else if nav.logged_in {
        format!("<nav id=\"site-nav\" class=\"bare\" aria-label=\"Main\">{links}</nav>")
    } else {
        String::new()
    };
    let mark = MARK.trim_end();
    let brand = if nav.logged_in { format!("<a class=\"brand\" href=\"./\">{mark}{}</a>", esc(nav.brand)) } else { format!("<div class=\"brand\">{mark}{}</div>", esc(nav.brand)) };
    let flash = flash.map(|(ok, m)| format!("<div class=\"flash {}\" role=\"status\">{}</div>", if ok { "ok" } else { "bad" }, esc(&m))).unwrap_or_default();
    format!("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <meta name=\"referrer\" content=\"no-referrer\">{head}<link rel=\"icon\" type=\"image/svg+xml\" href=\"./mark.svg?v={}\"><title>{} · {}</title>\
             <link rel=\"stylesheet\" href=\"./ui.css?v={}\"><script src=\"./vt.js?v={}\"></script></head><body{}>\
             <div class=\"glow\" aria-hidden=\"true\"></div><canvas id=\"river\" aria-hidden=\"true\"></canvas>\
             <header>{brand}{menu}{THEME_TOGGLE}</header>\
             <main>{tabs}{flash}{banner}<h1>{}</h1>{body}</main>{}\
             <footer>Your money stays on your own Lightning node. Nobody else holds it. <span class=\"version\">Lightning Stream {}</span></footer>\
             <script src=\"./ui.js?v={}\"></script><script src=\"./river.js?v={}\"></script></body></html>\n",
            asset_version(crate::MARK_SVG), esc(title), esc(nav.brand), asset_version(crate::UI_CSS), asset_version(crate::VT_JS),
            if simple { " class=\"simple\"" } else { "" }, esc(title),
            if simple { format!("<nav class=\"bottom-bar\" aria-label=\"Main, at the bottom\">{bar}</nav>") } else { String::new() },
            esc(crate::release_version()), asset_version(crate::UI_JS), asset_version(crate::river_js()))
}

/// The app's mark in the header and as the page icon: assets/mark.svg, the website's mark.
const MARK: &str = crate::MARK_SVG;

/// The bar's theme button: dark is the default, light is the owner's choice, kept in this browser
/// (ui.js switches it, vt.js applies it before the first paint). Shown only with scripts on.
const THEME_TOGGLE: &str = "<button type=\"button\" class=\"theme-toggle\" aria-label=\"Light theme\" aria-pressed=\"false\" title=\"Light or dark\">\
    <svg class=\"sun\" viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\"><circle cx=\"12\" cy=\"12\" r=\"4\"/>\
    <path d=\"M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6\"/></svg>\
    <svg class=\"moon\" viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\"><path d=\"M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z\"/></svg></button>";

/// A short content hash for cache busting.
pub fn asset_version(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(s.as_bytes())[..6])
}

pub fn kv(rows: &[(&str, String)]) -> String {
    let mut o = String::from("<dl class=\"kv\">");
    for (k, v) in rows {
        o.push_str(&format!("<dt>{}</dt><dd>{v}</dd>", esc(k)));
    }
    o.push_str("</dl>");
    o
}

/// The JSON a signer returned, for a details box.
pub fn json_block(v: &Value) -> String {
    format!("<pre class=\"json\">{}</pre>", esc(&serde_json::to_string_pretty(v).unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payment's total is the sum of its parts, exactly: 900 sat to the shop and a fee of 2.009 is 902.009, not the
    /// 903 the signer books for it. Two such payments are 1,804.018.
    ///
    /// FAILS before: "903 sats (900 + 2.009 fee)".
    #[test]
    fn a_payment_is_shown_as_the_sum_of_its_parts() {
        assert_eq!(paid_html(903, Some((900_000, 2_009))), "<span class=\"money\">902.009 sats</span> <span class=\"small\">(900 + 2.009 fee)</span>");
        assert_eq!(paid_html(1_806, Some((1_800_000, 4_018))), "<span class=\"money\">1,804.018 sats</span> <span class=\"small\">(1,800 + 4.018 fee)</span>");
        assert_eq!(paid_html(903, None), "<span class=\"money\">903 sats</span>");
    }
}
