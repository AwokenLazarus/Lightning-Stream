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
}

/// One page in a section: its address, the title it is shown under (and found by), the tab's words.
pub struct Tab {
    pub href: &'static str,
    pub title: &'static str,
    pub label: &'static str,
}

/// A top-level entry of the menu, with its pages as tabs. A page whose title no tab names (the
/// player, a service's own page) still marks its section through `also`.
pub struct Section {
    pub label: &'static str,
    pub tabs: &'static [Tab],
    pub also: &'static [&'static str],
}

impl Section {
    fn has(&self, title: &str) -> bool {
        self.tabs.iter().any(|t| t.title == title) || self.also.contains(&title)
    }
}

pub const SERVICES: Section = Section {
    label: "Services",
    tabs: &[Tab { href: "./browse", title: "Browse", label: "Browse" }, Tab { href: "./ai", title: "AI", label: "AI" },
            Tab { href: "./services", title: "Sellers", label: "Sellers" }, Tab { href: "./connections", title: "Live connections", label: "Live connections" }],
    also: &["Service", "Player"],
};
pub const SELL: Section = Section { label: "Sell", tabs: &[Tab { href: "./sell", title: "Sell", label: "Sell" }], also: &[] };
pub const WALLET: Section = Section {
    label: "Wallet",
    tabs: &[Tab { href: "./wallet", title: "Wallet", label: "Balance and activity" }, Tab { href: "./approvals", title: "Approvals", label: "Approvals" }],
    also: &[],
};
pub const APPS: Section = Section {
    label: "Apps & agents",
    tabs: &[Tab { href: "./apps", title: "Apps", label: "Apps" }, Tab { href: "./agents", title: "AI agents", label: "AI agents" }],
    also: &[],
};
pub const SETTINGS: Section = Section {
    label: "Settings",
    tabs: &[Tab { href: "./setup", title: "Setup", label: "Setup" }, Tab { href: "./lightning", title: "Your node", label: "Your node" },
            Tab { href: "./policy", title: "Spending rules", label: "Spending rules" }, Tab { href: "./keys", title: "Keys and backup", label: "Keys and backup" },
            Tab { href: "./signatures", title: "Records", label: "Records" }, Tab { href: "./channels", title: "Old channels", label: "Old channels" }],
    also: &[],
};
/// With hashrate (the box runs the hasher's or the renter's service): renting miners is one
/// more kind of service, beside the others.
pub const SERVICES_HASH: Section = Section {
    label: "Services",
    tabs: &[Tab { href: "./browse", title: "Browse", label: "Browse" }, Tab { href: "./ai", title: "AI", label: "AI" },
            Tab { href: "./hashrate", title: "Hashrate", label: "Hashrate" }, Tab { href: "./services", title: "Sellers", label: "Sellers" }, Tab { href: "./connections", title: "Live connections", label: "Live connections" }],
    also: &["Service", "Player"],
};
pub const SELL_HASH: Section = Section {
    label: "Sell",
    tabs: &[Tab { href: "./sell", title: "Sell", label: "Your services" }, Tab { href: "./sell-hashrate", title: "Sell hashrate", label: "Hashrate" }],
    also: &[],
};
/// The app with Sell (`XBT_UI_SELL=1`): buying and selling.
pub const STREAM_SECTIONS: [&Section; 5] = [&SERVICES, &SELL, &WALLET, &APPS, &SETTINGS];
pub const STREAM_SECTIONS_HASH: [&Section; 5] = [&SERVICES_HASH, &SELL_HASH, &WALLET, &APPS, &SETTINGS];
/// The wallet alone: buying.
pub const WALLET_SECTIONS: [&Section; 4] = [&SERVICES, &WALLET, &APPS, &SETTINGS];
pub const WALLET_SECTIONS_HASH: [&Section; 4] = [&SERVICES_HASH, &WALLET, &APPS, &SETTINGS];
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
            if here && sec.tabs.len() > 1 {
                tabs.push_str(&format!("<nav class=\"tabs\" aria-label=\"{}\">", esc(sec.label)));
                for t in sec.tabs {
                    let cur = if t.title == nav.active { " aria-current=\"page\"" } else { "" };
                    tabs.push_str(&format!("<a href=\"{}\"{cur}>{}</a>", t.href, esc(t.label)));
                }
                tabs.push_str("</nav>");
            }
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
    let brand = if nav.logged_in { format!("<a class=\"brand\" href=\"./\">{MARK}{}</a>", esc(nav.brand)) } else { format!("<div class=\"brand\">{MARK}{}</div>", esc(nav.brand)) };
    let flash = flash.map(|(ok, m)| format!("<div class=\"flash {}\" role=\"status\">{}</div>", if ok { "ok" } else { "bad" }, esc(&m))).unwrap_or_default();
    format!("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <meta name=\"referrer\" content=\"no-referrer\">{head}<link rel=\"icon\" href=\"data:,\"><title>{} · {}</title>\
             <link rel=\"stylesheet\" href=\"./ui.css?v={}\"><script src=\"./vt.js?v={}\"></script></head><body>\
             <div class=\"glow\" aria-hidden=\"true\"></div><canvas id=\"river\" aria-hidden=\"true\"></canvas>\
             <header>{brand}{menu}</header>\
             <main>{tabs}{flash}{banner}<h1>{}</h1>{body}</main>\
             <footer>Your money stays on your own Lightning node. Nobody else holds it.</footer>\
             <script src=\"./ui.js?v={}\"></script><script src=\"./river.js?v={}\"></script></body></html>\n",
            esc(title), esc(nav.brand), asset_version(crate::UI_CSS), asset_version(crate::VT_JS), esc(title),
            asset_version(crate::UI_JS), asset_version(crate::river_js()))
}

/// The app's mark in the header: a lightning river, the app icon at header size.
const MARK: &str = "<svg viewBox=\"0 0 32 32\" aria-hidden=\"true\"><rect x=\".5\" y=\".5\" width=\"31\" height=\"31\" rx=\"8\" fill=\"#05081c\" stroke=\"#2a3a80\"/>\
    <path d=\"M17.5 3 14 11.5h4.5L12 19.5h4.5L10 29\" fill=\"none\" stroke=\"#38bdf8\" stroke-width=\"6\" stroke-linecap=\"round\" stroke-linejoin=\"round\" opacity=\".22\"/>\
    <path d=\"M17.5 3 14 11.5h4.5L12 19.5h4.5L10 29\" fill=\"none\" stroke=\"#7dd3fc\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\" opacity=\".55\"/>\
    <path d=\"M17.5 3 14 11.5h4.5L12 19.5h4.5L10 29\" fill=\"none\" stroke=\"#f0f9ff\" stroke-width=\"1.3\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>";

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
