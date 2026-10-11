//! The hub's status as one page (AGP-104): [`render`] turns [`crate::hub::RouteHub::status`]'s
//! JSON (with what the service adds: its address, its wallet's receive address) into HTML. No
//! script, nothing loaded from elsewhere, and every value is escaped: seller origins and lock ids
//! are other people's text.
use serde_json::Value;

/// `&`, `<`, `>`, `"` and `'` as entities.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() => o.push(' '),
            c => o.push(c),
        }
    }
    o
}

/// An amount with thousands separators, `-` when it is not known.
fn sats(v: &Value) -> String {
    let Some(n) = v.as_i64() else { return "-".into() };
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    format!("{}{out}", if n < 0 { "-" } else { "" })
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => esc(s),
        Value::Null => "-".into(),
        other => esc(&other.to_string()),
    }
}

/// A unix time as a UTC date, `2026-10-11` (`-` when it is not a time).
fn date(v: &Value) -> String {
    let Some(t) = v.as_u64().filter(|t| *t < 253_402_300_800) else { return "-".into() };
    // days since 1970-01-01 to a civil date (the proleptic Gregorian calendar, by eras of 400 years)
    let z = (t / 86_400) as i64 + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    format!("{:04}-{m:02}-{d:02}", yoe + era * 400 + i64::from(m <= 2))
}

/// The Lightning link (AGP-109): `v` is the status JSON's `lightning`. Nothing when there is no
/// link and none was asked for.
fn lightning(v: &Value) -> String {
    if v.is_null() {
        return String::new();
    }
    let mut h = String::from("<h2>Lightning node</h2>");
    if v["linked"] != true {
        h.push_str(&format!("<div class=warn>The Lightning link is not set up: {}. Returns go to the hub's own wallet, and the hub is named by its address only.</div>", text(&v["error"])));
        return h;
    }
    for (key, msg) in [("statementError", "The Lightning node did not sign the hub's statement"), ("addressError", "The Lightning node gave no address"),
                       ("returnedError", "What was returned could not be summed")] {
        if let Some(e) = v[key].as_str() {
            h.push_str(&format!("<div class=warn>{msg}: {}</div>", esc(e)));
        }
    }
    if v["waitingForNode"] == true {
        h.push_str("<div class=warn>The node's certificate changed: nothing is returned to the Lightning wallet until the node has signed again.</div>");
    }
    if v["macaroon"]["onlyTheTwoCalls"] == false {
        h.push_str(&format!("<div class=warn>The macaroon allows more than a new address and a signed message ({}). On mainnet it would not be used.</div>", text(&v["macaroon"]["ops"])));
    }
    if v["nodeId"].is_string() && v["statementServed"] != true {
        h.push_str("<div class=warn>The node's statement naming this hub has run out: buyers who know the hub by its node are refused until the node signs again.</div>");
    }
    h.push_str("<div class=scroll><table>");
    h.push_str(&format!("<tr><td>Returned to the Lightning wallet</td><td class=n>{}</td></tr>", sats(&v["returnedSat"])));
    h.push_str(&format!("<tr><td>Above capital now</td><td class=n>{}</td></tr>", sats(&v["aboveCapitalSat"])));
    for (name, val) in [("Hub address", text(&v["hubAddress"])), ("Node", text(&v["nodeId"])), ("Returns go to", text(&v["returnAddress"])),
                        ("Statement runs to", date(&v["statementUntil"])), ("Note", text(&v["note"]))] {
        if val != "-" {
            h.push_str(&format!("<tr><td>{name}</td><td><code>{val}</code></td></tr>"));
        }
    }
    h.push_str("</table></div><div class=note>The Lightning wallet's coins and the hub's capital are two amounts, at risk in two ways: the hub holds no key of the Lightning node and can spend nothing of it.</div>");
    h
}

/// The page. `v`: the status JSON.
pub fn render(v: &Value) -> String {
    let card = |name: &str, key: &str, note: &str| {
        format!("<div class=card><div class=name>{name}</div><div class=num>{}</div><div class=note>{note}</div></div>", sats(&v[key]))
    };
    let mut h = String::from("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
        <meta http-equiv=refresh content=30><title>Lightning Stream Hub</title><style>\
        body{font:15px/1.45 system-ui,sans-serif;margin:0;padding:16px;background:#f6f7f9;color:#16181d}\
        h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:22px 0 8px}\
        .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:14px}\
        .card{background:#fff;border:1px solid #dcdfe5;border-radius:8px;padding:12px}\
        .name{font-size:13px;color:#555b66}.num{font-size:22px;font-variant-numeric:tabular-nums}.note{font-size:12px;color:#555b66}\
        table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #dcdfe5}\
        th,td{text-align:left;padding:6px 8px;border-top:1px solid #e8eaee;font-size:13px;overflow-wrap:anywhere}th{border-top:0;color:#555b66}\
        td.n{text-align:right;font-variant-numeric:tabular-nums}.warn{background:#fff4d6;border:1px solid #e6c860;border-radius:8px;padding:8px 10px;margin-top:10px}\
        code{overflow-wrap:anywhere}.scroll{overflow-x:auto}\
        @media(prefers-color-scheme:dark){body{background:#14161a;color:#e8eaee}.card,table{background:#1d2026;border-color:#33373f}\
        th,td{border-color:#2a2e35}.name,.note,th{color:#a3a9b5}.warn{background:#3a3115;border-color:#7a6620}}\
        </style></head><body><h1>Lightning Stream Hub</h1>");
    h.push_str("<div class=note>Experimental. Amounts in sats. This page reloads every 30 seconds.</div>");
    for (flag, msg) in [("unsettled", "A funding is being checked against the chain: the numbers can be off by one channel until it is found."),
                        ("estimated", "Part of the sum is an estimate: a channel or a fee from before this version, or a wallet that did not report a fee.")] {
        if v[flag] == true {
            h.push_str(&format!("<div class=warn>{msg}</div>"));
        }
    }
    if v["returns"] == false {
        h.push_str("<div class=warn>No return address is set: what closes pay stays on per-channel keys.</div>");
    }
    if let Some(e) = v["wallet"]["error"].as_str() {
        h.push_str(&format!("<div class=warn>The hub's wallet does not answer: {}</div>", esc(e)));
    }
    h.push_str("<div class=cards>");
    h.push_str(&card("Capital", "capitalSat", "free, in the hub's wallet"));
    h.push_str(&card("In channels", "inChannelsSat", "the hub's side of its seller channels"));
    h.push_str(&card("Earned", "earnedSat", "signed to the hub by buyers, not in the wallet yet"));
    h.push_str(&card("Stuck", "stuckSat", "waiting on a payment without an answer"));
    h.push_str("</div><h2>How it adds up</h2><div class=scroll><table>");
    for (name, key) in [("Capital + in channels + earned + stuck", "totalSat"), ("Sent in, less taken out", "depositsSat"),
                        ("Fees earned (buyers paid, less sellers were paid)", "feesEarnedSat"), ("Paid to the chain", "chainFeesSat"),
                        ("Left on channel keys (under the cost of collecting it)", "dustSat")] {
        h.push_str(&format!("<tr><td>{name}</td><td class=n>{}</td></tr>", sats(&v[key])));
    }
    h.push_str(&format!("<tr><td>Capital setting</td><td class=n>{}</td></tr>", sats(&v["capitalSetting"])));
    h.push_str(&format!("<tr><td>Sweeps on their way to the wallet</td><td class=n>{}</td></tr></table></div>", sats(&v["sweepsPending"])));
    h.push_str("<h2>Stuck payments</h2>");
    match v["stuck"].as_array().filter(|a| !a.is_empty()) {
        None => h.push_str("<div class=note>None.</div>"),
        Some(rows) => {
            h.push_str("<div class=scroll><table><tr><th>Seller</th><th>Amount</th><th>What</th><th>Resolves by block</th></tr>");
            for r in rows {
                h.push_str(&format!("<tr><td>{}</td><td class=n>{}</td><td>{}</td><td class=n>{}</td></tr>",
                                    text(&r["seller"]), sats(&r["amountSat"]), text(&r["kind"]), text(&r["resolvesBy"])));
            }
            h.push_str("</table></div>");
        }
    }
    h.push_str("<h2>Sellers</h2>");
    match v["sellers"].as_array().filter(|a| !a.is_empty()) {
        None => h.push_str("<div class=note>None yet.</div>"),
        Some(rows) => {
            h.push_str("<div class=scroll><table><tr><th>Seller</th><th>Channel</th><th>Capacity</th><th>Paid</th><th>Ends at block</th><th>Note</th></tr>");
            for r in rows {
                let next = if r["next"].is_object() { format!("next channel {}", text(&r["next"]["state"])) } else { String::new() };
                let note = [text(&r["blocked"]).replace('-', ""), next].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("; ");
                h.push_str(&format!("<tr><td>{}</td><td>{}</td><td class=n>{}</td><td class=n>{}</td><td class=n>{}</td><td>{note}</td></tr>",
                                    text(&r["origin"]), text(&r["state"]), sats(&r["capacitySat"]), sats(&r["paidSat"]), text(&r["expiry"])));
            }
            h.push_str("</table></div>");
        }
    }
    h.push_str(&lightning(&v["lightning"]));
    h.push_str("<h2>This hub</h2><div class=scroll><table>");
    for (name, val) in [("Address", &v["url"]), ("Tor", &v["tor"]), ("Key", &v["payTo"]), ("Network", &v["network"]),
                        ("Send capital to", &v["wallet"]["receiveAddress"]), ("Block", &v["tip"]), ("A spend is final after blocks", &v["spendFinalDepth"])] {
        if !val.is_null() {
            h.push_str(&format!("<tr><td>{name}</td><td><code>{}</code></td></tr>", text(val)));
        }
    }
    h.push_str("</table></div></body></html>");
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_page_shows_the_four_numbers_and_escapes_other_peoples_text() {
        let v = json!({"capitalSat": 899_847, "inChannelsSat": 98_854, "earnedSat": 0, "stuckSat": 5_000, "totalSat": 1_003_701, "depositsSat": 1_000_000,
                       "feesEarnedSat": -600, "chainFeesSat": 153, "dustSat": 546, "estimated": false, "unsettled": true, "sweepsPending": 1,
                       "stuck": [{"lockId": "x", "seller": "http://<script>alert(1)</script>", "amountSat": 5_000, "kind": "written off", "resolvesBy": 2012}],
                       "sellers": [{"origin": "http://p0.test/\"><img src=x>", "state": "open", "capacitySat": 100_000, "paidSat": 1_146, "expiry": 2000,
                                    "blocked": "", "next": {"state": "funded"}}],
                       "payTo": "02ab", "network": "bip122:00", "url": "http://hub.test", "tip": 1007, "spendFinalDepth": 6,
                       "wallet": {"receiveAddress": "bcrt1qxyz"}, "returns": true});
        let h = render(&v);
        for want in ["899,847", "98,854", "5,000", "1,000,000", "-600", "written off", "2012", "next channel funded", "bcrt1qxyz", "being checked"] {
            assert!(h.contains(want), "{want} not in the page");
        }
        assert!(!h.contains("<script>alert") && !h.contains("<img"), "unescaped");
        assert!(h.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        // a status without the wallet's number
        let h = render(&json!({"capitalSat": null, "stuck": [], "sellers": [], "returns": false, "wallet": {"error": "no <wallet>"}}));
        assert!(h.contains("No return address") && h.contains("no &lt;wallet&gt;") && h.contains("None yet."));
    }

    #[test]
    fn the_lightning_link_is_on_the_page_when_there_is_one() {
        let base = json!({"capitalSat": 1, "stuck": [], "sellers": [], "returns": true, "wallet": {}});
        assert!(!render(&base).contains("Lightning node"), "no link, no section");
        let mut v = base.clone();
        v["lightning"] = json!({"linked": true, "nodeId": "02ab", "hubAddress": "02ab@hub.example:9480", "returnedSat": 10_417, "aboveCapitalSat": 89_430,
                                "returnAddress": "bcrt1qln", "statementUntil": 1_791_590_400u64, "statementServed": true, "macaroon": {"onlyTheTwoCalls": true}});
        let h = render(&v);
        for want in ["Lightning node", "02ab@hub.example:9480", "10,417", "89,430", "bcrt1qln", "2026-10-10", "two amounts"] {
            assert!(h.contains(want), "{want} not in the page");
        }
        assert!(!h.contains("class=warn"), "{h}");
        // what an operator must see: no link, a node that does not answer, a wide macaroon, a statement run out
        v["lightning"] = json!({"linked": false, "error": "the Lightning macaroon grants <onchain:write>"});
        let h = render(&v);
        assert!(h.contains("not set up") && h.contains("&lt;onchain:write&gt;") && !h.contains("<onchain"));
        v["lightning"] = json!({"linked": true, "nodeId": "02ab", "statementServed": false, "statementError": "not reachable", "addressError": "no <address>",
                                "waitingForNode": true, "macaroon": {"onlyTheTwoCalls": false, "ops": ["onchain:write"]}, "note": "no capital is set"});
        let h = render(&v);
        for want in ["did not sign", "not reachable", "no &lt;address&gt;", "certificate changed", "allows more than", "has run out", "no capital is set"] {
            assert!(h.contains(want), "{want} not in the page");
        }
    }

    #[test]
    fn dates() {
        assert_eq!((date(&json!(0)), date(&json!(951_782_400)), date(&json!(1_709_164_800)), date(&json!(1_791_590_399u64))),
                   ("1970-01-01".into(), "2000-02-29".into(), "2024-02-29".into(), "2026-10-09".into()));
        assert_eq!((date(&json!(null)), date(&json!(-5)), date(&json!(u64::MAX))), ("-".to_string(), "-".to_string(), "-".to_string()));
    }

    #[test]
    fn amounts_and_escapes() {
        assert_eq!((sats(&json!(0)), sats(&json!(999)), sats(&json!(1_000)), sats(&json!(-1_234_567)), sats(&json!(null))),
                   ("0".into(), "999".into(), "1,000".into(), "-1,234,567".into(), "-".into()));
        assert_eq!(esc("a&b<c>\"d'\n"), "a&amp;b&lt;c&gt;&quot;d&#39; ");
    }
}
