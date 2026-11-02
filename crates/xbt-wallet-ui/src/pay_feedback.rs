//! What a buyer sees when a payment can't happen: the wallet's refusals in plain words, with the fix
//! and a way back, and a warning before paying when the Lightning node can't send.
//!
//! The wallet refuses a call with a rule and its own words (`{"error": ..., "rule": ...}`). The common
//! rules get a page of their own here: the shop not allowed yet, no route to the shop's node, a limit,
//! a daily cap. The wallet's words stay under Details.

use serde_json::Value;

use crate::html::{esc, group3};

/// The guide's section on getting a channel that can send.
pub const GUIDE_CHANNEL: &str = "https://lightning-stream.com/download/#channel";

/// The kinds of refusal a buyer is told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The spending rules don't name the shop.
    Admission,
    /// The node found no route to the shop's node (or can't send at all).
    NoRoute,
    /// The call's own limit, or the rules' most per payment.
    Limit,
    /// A daily (or weekly) cap of the rules.
    Cap,
    /// The visit's limit is reached, or it was stopped.
    Visit,
    /// The shop is busy: nothing was charged.
    Busy,
    Other,
}

/// The kind of a refusal, by its rule and, where the rule is a general one, its words.
pub fn kind_of(rule: &str, words: &str) -> Kind {
    let w = words.to_ascii_lowercase();
    match rule {
        "ticket_admission" | "allowlist" | "dest" => Kind::Admission,
        "ln_no_route" => Kind::NoRoute,
        "max_sats" | "max_per_tx" | "max_payment_sats" | "split_bypass" => Kind::Limit,
        "daily_budget" | "weekly_budget" | "per_counterparty_daily" | "per_counterparty" => Kind::Cap,
        "visit" => Kind::Visit,
        "seller_busy" => Kind::Busy,
        _ if w.contains("pays only named sellers") || w.contains("not on allowlist") => Kind::Admission,
        _ if w.contains("no route") => Kind::NoRoute,
        _ if w.contains("exceeds budget") || w.contains("daily cap") => Kind::Cap,
        _ => Kind::Other,
    }
}

/// A refusal in words: what happened, what fixes it, where to go, and the wallet's own words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explained {
    pub kind: Kind,
    pub title: String,
    pub words: String,
    pub fix: String,
    /// Pages of the app (`services`, `policy`, `lightning`, `browse`: below the app's base) or the guide
    /// ([`GUIDE_CHANNEL`]), with their words.
    pub links: Vec<(String, String)>,
    /// The wallet's own words, for Details.
    pub raw: String,
}

/// `N sat` with thousands grouped.
fn sat(n: i64) -> String {
    format!("{}{} sat", if n < 0 { "-" } else { "" }, group3(n.unsigned_abs()))
}

/// What the node can send, in words, where it can't send `need`: the warning shown before paying.
/// `None` where it can, or where what it holds is not known.
pub fn cant_send_words(spendable: Option<i64>, need: i64, to: &str) -> Option<String> {
    let n = spendable?;
    (n < need).then(|| format!("Your Lightning node can't send to {to} right now: your channels hold about {} you can spend \
                                (the rest is on the other side, or held as reserve).", sat(n)))
}

/// The remedies for a node that can't send.
pub const CANT_SEND_FIX: &str = "Add sending balance, or open a small channel to the shop's node.";

/// The links that go with [`CANT_SEND_FIX`].
fn node_links() -> Vec<(String, String)> {
    vec![("lightning".into(), "Your node and channels".into()), (GUIDE_CHANNEL.into(), "Get a channel".into())]
}

/// The wallet's refusal `body` (the connector's JSON, or any text) in words. `spendable`: what the
/// node can send now ([`spendable_sats`]), said with a no-route refusal where known. `file`: a
/// download or a player's link, rather than a page of a shop's app.
pub fn explain(body: &str, spendable: Option<i64>, file: bool) -> Explained {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let raw = v.get("error").or(v.get("reason")).and_then(Value::as_str).filter(|w| !w.is_empty()).map(str::to_string)
        .unwrap_or_else(|| if v.is_null() && !body.trim().is_empty() && body.len() <= 2000 { body.trim().to_string() } else { String::new() });
    let rule = v.get("rule").and_then(Value::as_str).unwrap_or("");
    let kind = kind_of(rule, &raw);
    let rules = || vec![("policy".to_string(), "Spending rules".to_string())];
    let (title, words, fix, links): (&str, String, String, Vec<(String, String)>) = match kind {
        Kind::Admission => ("This shop isn't allowed yet", "Your spending rules don't allow this shop yet. Nothing was paid.".into(),
                            "Go to Sellers and choose Allow this seller to be paid.".into(),
                            vec![("services".into(), "Sellers".into()), ("policy".into(), "Spending rules".into())]),
        Kind::NoRoute => match cant_send_words(spendable, crate::app::MIN_CALL_SATS, "this shop") {
            Some(w) => ("Your node can't send to this shop", format!("{w} Nothing was paid."), CANT_SEND_FIX.into(), node_links()),
            None => ("Your node can't reach this shop", "Your Lightning node found no route to this shop's node right now. Nothing was paid.".into(),
                     format!("{CANT_SEND_FIX} Or try again in a few minutes."), node_links()),
        },
        Kind::Limit if rule == "max_sats" && file => ("Over this download's limit",
            "This download needs more than its limit allows. Nothing was paid.".into(),
            format!("A download from Lightning Stream pays at most {} for its first ticket with a shop, and what it does not use stays as credit \
                     with the shop. Your spending rules apply as well.", sat(crate::server::RETRY_MOST_SATS)), rules()),
        Kind::Limit if rule == "max_sats" => ("Over this visit's limit", "The next ticket costs more than is left of this visit's limit. Nothing more was paid.".into(),
            "Open the app again with a higher limit. What you don't use stays as credit with the shop.".into(), vec![("browse".into(), "Browse".into())]),
        Kind::Limit => ("Over your limit", "This payment is larger than your spending rules allow for one payment. Nothing was paid.".into(),
                        "Raise the most per payment in Spending rules, if you want to allow it.".into(), rules()),
        Kind::Cap => {
            let when = if rule == "weekly_budget" { "this week's" } else { "today's" };
            ("Spending cap reached", format!("You've reached {when} spending cap in your rules. Nothing was paid."),
             format!("Raise the cap in Spending rules, or wait until {}.", if rule == "weekly_budget" { "next week" } else { "tomorrow" }), rules())
        }
        Kind::Visit => ("This visit has ended", if raw.is_empty() { "This visit has ended.".into() } else { raw.clone() },
                        "Open the app again with a new limit. What you don't use stays as credit with the shop.".into(), vec![("browse".into(), "Browse".into())]),
        Kind::Busy => ("This shop is busy", "The shop's service is full right now. Nothing was charged.".into(), "Reload the page to try again.".into(), vec![]),
        Kind::Other => ("Not paid", if file { "The wallet did not pay for this file.".into() } else { "The wallet did not pay for this.".into() },
                        "Your spending rules decide what the wallet pays.".into(), rules()),
    };
    Explained { kind, title: title.into(), words, fix, links, raw }
}

/// What the Lightning node can send now, about, from the signer's `ln_status`: over the channels the
/// wallet pays through, each one's local balance less its channel reserve, never below 0. The
/// status does not give the reserve, so it is taken as LND sets it by default: 1% of the channel, at
/// least 354 sat. `None` where the status lists no channels (the node is not connected, or its
/// channels could not be read).
pub fn spendable_sats(ln: &Value) -> Option<i64> {
    let chans = ln.get("channels")?.as_array()?;
    if ln.get("configured") == Some(&Value::Bool(false)) {
        return None;
    }
    Some(chans.iter().filter(|c| c.get("usable") == Some(&Value::Bool(true))).map(|c| {
        let n = |k: &str| c.get(k).and_then(Value::as_i64).unwrap_or(0);
        let reserve = c.get("local_reserve_sats").and_then(Value::as_i64).unwrap_or_else(|| (n("capacity_sats") / 100).max(354));
        (n("local_sats") - reserve).max(0)
    }).sum())
}

/// The warning shown before paying, as a card, where the node can't send `need`; empty where it can
/// or where that is not known.
pub fn cant_send_card(spendable: Option<i64>, need: i64, to: &str) -> String {
    let Some(w) = cant_send_words(spendable, need, to) else { return String::new() };
    format!("<section class=\"flash warn\" data-cant-send><p><strong>{}</strong></p><p>{}</p><p><a href=\"./lightning\">Your node and channels</a> · \
             <a href=\"{GUIDE_CHANNEL}\" target=\"_blank\" rel=\"noopener noreferrer\">Get a channel</a></p></section>",
            esc(&w), esc(CANT_SEND_FIX))
}

/// A link's address: an app page below `base`, or the guide as it is.
fn href(base: &str, to: &str) -> String {
    if to.starts_with("https://") { to.to_string() } else { format!("{base}{to}") }
}

/// The card of a refusal, as the app's pages show it. `base`: what the app's own pages are below.
pub fn card(e: &Explained, base: &str) -> String {
    let links: String = e.links.iter().map(|(to, label)| {
        let out = if to.starts_with("https://") { " target=\"_blank\" rel=\"noopener noreferrer\"" } else { "" };
        format!("<a class=\"button-link\" href=\"{}\"{out}>{}</a>", esc(&href(base, to)), esc(label))
    }).collect::<Vec<_>>().join(" ");
    let details = if e.raw.is_empty() { String::new() } else {
        format!("<details><summary>Details</summary><p class=\"small\"><code>{}</code></p></details>", esc(&e.raw))
    };
    format!("<section class=\"card primary refusal\"><h2>{}</h2><p>{}</p><p>{}</p>{}{details}</section>",
            esc(&e.title), esc(&e.words), esc(&e.fix), if links.is_empty() { String::new() } else { format!("<p class=\"row\">{links}</p>") })
}

/// A whole page for a refusal, on the app's own address (a download, a player's link): the app's
/// look and a way back. `base`: the app's base path, ending in `/`. `heading`: the page's title.
pub fn page(e: &Explained, base: &str, heading: &str) -> String {
    let v = |s: &str| crate::html::asset_version(s);
    format!("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <meta name=\"referrer\" content=\"no-referrer\"><link rel=\"icon\" type=\"image/svg+xml\" href=\"{base}mark.svg?v={}\">\
             <title>{} · Lightning Stream</title><link rel=\"stylesheet\" href=\"{base}ui.css?v={}\"></head><body>\
             <header><a class=\"brand\" href=\"{base}\">{}Lightning Stream</a></header>\
             <main><h1>{}</h1>{}<p><a href=\"{base}browse\">← Back to Browse</a></p></main></body></html>\n",
            v(crate::MARK_SVG), esc(heading), v(crate::UI_CSS), crate::MARK_SVG.trim_end(), esc(heading), card(e, base))
}

/// The page a shop's app shows in its frame (another address than the app's: no stylesheet of the
/// app's, no link that leaves the frame). The app's look, inline; the links are above the frame.
pub fn frame_page(title: &str, words: &str, fix: &str, raw: &str) -> String {
    let details = if raw.is_empty() { String::new() } else { format!("<details><summary>Details</summary><p><code>{}</code></p></details>", esc(raw)) };
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Lightning Stream</title>\
             <style>{FRAME_CSS}</style></head><body><main><section class=\"card\">{}<p>{}</p>{}{details}</section></main></body></html>",
            if title.is_empty() { String::new() } else { format!("<h1>{}</h1>", esc(title)) }, esc(words), if fix.is_empty() { String::new() } else { format!("<p>{}</p>", esc(fix)) })
}

/// The app's look for [`frame_page`]: its colors (light and dark) and its card.
const FRAME_CSS: &str = ":root{--bg:#f6f7f9;--fg:#111418;--muted:#4f5763;--card:#fff;--edge:#e3e6eb;--mono:#eef0f3;color-scheme:light}\
@media (prefers-color-scheme:dark){:root{--bg:#0d0f12;--fg:#e8eaed;--muted:#a0a8b3;--card:#15181d;--edge:#23272e;--mono:#1b1f25;color-scheme:dark}}\
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif}\
main{max-width:640px;margin:0 auto;padding:24px 16px}.card{background:var(--card);border:1px solid var(--edge);border-radius:10px;padding:20px}\
h1{font-size:1.2rem;margin:0 0 8px}p{margin:0 0 10px}details{color:var(--muted);font-size:.92em}\
code{background:var(--mono);border-radius:4px;padding:1px 4px;overflow-wrap:anywhere}";

/// A refusal as `/api/visit` gives it to the visit's page, which shows it above the frame.
pub fn as_json(e: &Explained) -> Value {
    serde_json::json!({"title": e.title, "words": e.words, "fix": e.fix, "details": e.raw,
                       "links": e.links.iter().map(|(to, label)| serde_json::json!([href("./", to), label])).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ADMISSION: &str = r#"{"error": "the owner has not named the seller 03ab... and task \"stream\" pays only named sellers: allow it", "rule": "ticket_admission"}"#;
    const NO_ROUTE: &str = r#"{"error": "the wallet's node has found no route to the seller for 8.0 s: nothing was sent", "rule": "ln_no_route"}"#;

    /// The shop not named in the rules: the words say so, and the fix is under Sellers.
    ///
    /// FAILS before: a bare white page with the wallet's words alone.
    #[test]
    fn a_shop_not_allowed_is_told_with_the_fix() {
        let e = explain(ADMISSION, None, false);
        assert_eq!(e.kind, Kind::Admission);
        assert!(e.words.contains("Your spending rules don't allow this shop yet"), "{e:?}");
        assert!(e.fix.contains("Sellers") && e.fix.contains("Allow this seller to be paid"), "{e:?}");
        assert_eq!(e.links[0].0, "services");
        assert!(e.raw.contains("pays only named sellers"));
        // with its rule lost, its words still say what it is
        assert_eq!(explain(r#"{"error": "the owner no longer names the seller x and task \"t\" pays only named sellers"}"#, None, false).kind, Kind::Admission);
        let page = page(&e, "/ls/", "This file was not paid for");
        assert!(page.contains("href=\"/ls/ui.css") && page.contains("href=\"/ls/services\"") && page.contains("Back to Browse"), "{page}");
        assert!(page.contains("<details><summary>Details</summary>") && page.contains("pays only named sellers"));
    }

    /// No route to the shop's node: with what the node can spend, where it is too little, and the
    /// way to more; without it, the words for a node that found no route.
    #[test]
    fn no_route_is_told_with_what_the_node_can_spend() {
        let e = explain(NO_ROUTE, Some(0), false);
        assert_eq!(e.kind, Kind::NoRoute);
        assert!(e.words.starts_with("Your Lightning node can't send to this shop right now: your channels hold about 0 sat you can spend"), "{e:?}");
        assert!(e.fix.contains("Add sending balance") && e.fix.contains("open a small channel"));
        assert!(e.links.iter().any(|(to, _)| to == GUIDE_CHANNEL) && e.links.iter().any(|(to, _)| to == "lightning"));
        assert!(e.raw.contains("8.0 s"));
        let e = explain(NO_ROUTE, Some(50_000), false);
        assert!(e.words.contains("found no route to this shop's node"), "{e:?}");
        assert_eq!(explain(r#"{"error": "the wallet's node has found no route to the seller for 8.0 s: nothing was sent"}"#, None, true).kind, Kind::NoRoute);
    }

    #[test]
    fn limits_and_caps_are_told_apart() {
        assert_eq!(explain(r#"{"error": "daily spend 5000 exceeds budget 4000", "rule": "daily_budget"}"#, None, false).title, "Spending cap reached");
        assert!(explain(r#"{"error": "x", "rule": "daily_budget"}"#, None, false).words.contains("today's spending cap"));
        assert!(explain(r#"{"error": "x", "rule": "max_sats"}"#, None, true).fix.contains("at most 2,000 sat for its first ticket"));
        assert!(explain(r#"{"error": "x", "rule": "max_per_tx"}"#, None, false).fix.contains("most per payment"));
        assert_eq!(explain("not json", None, true).words, "The wallet did not pay for this file.");
    }

    /// The node's channels: what it can send is its local balance less the reserve, on the channels
    /// the wallet pays through. Mike's Umbrel: 7,085 sat on its side of a 1M channel, under the
    /// 10,000 sat reserve: nothing.
    #[test]
    fn what_the_node_can_send_is_its_local_balance_less_the_reserve() {
        let ln = |chans: Value| json!({"configured": true, "channels": chans});
        let umbrel = ln(json!([{"usable": true, "capacity_sats": 1_000_000, "local_sats": 7_085}]));
        assert_eq!(spendable_sats(&umbrel), Some(0));
        let two = ln(json!([{"usable": true, "capacity_sats": 100_000, "local_sats": 50_000}, {"usable": false, "capacity_sats": 100_000, "local_sats": 90_000},
                           {"usable": true, "capacity_sats": 20_000, "local_sats": 500}]));
        assert_eq!(spendable_sats(&two), Some(49_000 + 146));
        assert_eq!(spendable_sats(&json!({"ready": false, "reason": "no key"})), None);
    }

    /// The warning before paying: shown where what the node can send is under the ticket, with the
    /// remedies and the links; not where it can, or where it is not known.
    ///
    /// FAILS before: nothing was said until the payment failed on a white page.
    #[test]
    fn the_cant_send_warning_shows_under_the_ticket_size() {
        let umbrel = json!({"configured": true, "channels": [{"usable": true, "capacity_sats": 1_000_000, "local_sats": 10_300}]});
        let card = cant_send_card(spendable_sats(&umbrel), 559, "this shop");
        assert!(card.contains("Your Lightning node can&#39;t send to this shop right now: your channels hold about 0 sat you can spend"), "{card}");
        assert!(card.contains("Add sending balance") && card.contains("./lightning") && card.contains(GUIDE_CHANNEL));
        let rich = json!({"configured": true, "channels": [{"usable": true, "capacity_sats": 1_000_000, "local_sats": 20_000}]});
        assert_eq!(cant_send_card(spendable_sats(&rich), 559, "this shop"), "");
        assert_eq!(cant_send_card(None, 559, "this shop"), "");
        assert!(cant_send_words(Some(558), 559, "your sellers").is_some_and(|w| w.contains("about 558 sat")));
    }

    #[test]
    fn the_frame_page_has_the_apps_look_and_details() {
        let p = frame_page("This shop isn't allowed yet", "Your <rules>", "Go to Sellers", "raw & words");
        assert!(p.contains("<style>") && p.contains("prefers-color-scheme:dark") && p.contains("Your &lt;rules&gt;") && p.contains("raw &amp; words"));
    }
}
