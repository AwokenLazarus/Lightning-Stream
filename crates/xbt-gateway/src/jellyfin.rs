//! How Lightning Stream says who it is to a Jellyfin: the `Authorization: MediaBrowser …` header.
//!
//! Jellyfin 10.11 and later turn the older ways off by default (`X-Emby-Token`, `X-MediaBrowser-Token`
//! and the `api_key` of a URL answer 401 to a valid key). The `Authorization` header with a
//! `MediaBrowser` scheme works on every Jellyfin since 10.7, 10.10 included, so it is the one way used.
//! Its fields are `Name="value"`, comma-separated: `Client`, `Device`, `DeviceId`, `Version` and
//! `Token`.

/// The name Lightning Stream gives itself to a Jellyfin.
pub const CLIENT: &str = "Lightning Stream";

/// The client fields a buyer's own Jellyfin client sent, kept when its token is replaced.
const KEPT: [&str; 4] = ["Client", "Device", "DeviceId", "Version"];

/// A field's value as it may go inside the header's quotes: no quote, comma, backslash or
/// control character, at most 128 characters.
fn clean(v: &str) -> String {
    v.chars().filter(|c| !matches!(c, '"' | ',' | '\\') && !c.is_control()).take(128).collect::<String>().trim().to_string()
}

/// The fields of a `MediaBrowser` (or `Emby`) authorization value, by name as given, values
/// unquoted. `None` for a value of another scheme (`Bearer …`, `Basic …`).
pub fn fields(value: &str) -> Option<Vec<(String, String)>> {
    let v = value.trim();
    let rest = ["MediaBrowser", "Emby"].iter().find_map(|s| {
        let head = v.get(..s.len())?;
        (head.eq_ignore_ascii_case(s) && v[s.len()..].starts_with(|c: char| c.is_whitespace() || c == ',')).then(|| &v[s.len()..])
    })?;
    let mut out = vec![];
    let (mut field, mut quoted) = (String::new(), false);
    let mut push = |f: &str| {
        if let Some((k, val)) = f.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                out.push((k.to_string(), val.trim().trim_matches('"').to_string()));
            }
        }
    };
    for c in rest.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                field.push(c);
            }
            ',' if !quoted => push(&std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    push(&field);
    Some(out)
}

/// The `Authorization` value that says `token`: the client fields of `client` (a buyer's own
/// client's `Authorization` or `X-Emby-Authorization` value, where it is a `MediaBrowser` one) kept,
/// and ours where it gave none (`DeviceId` the given `device_id`). Any token `client` carried is
/// left out: the one token is `token`.
pub fn authorization(client: Option<&str>, token: &str, device_id: &str) -> String {
    let theirs = client.and_then(fields).unwrap_or_default();
    let field = |name: &str, default: &str| {
        theirs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| clean(v)).filter(|v| !v.is_empty()).unwrap_or_else(|| clean(default))
    };
    let parts: Vec<String> = KEPT.iter().map(|k| {
        let default = match *k { "Client" | "Device" => CLIENT, "DeviceId" => device_id, _ => "1" };
        format!("{k}=\"{}\"", field(k, default))
    }).collect();
    format!("MediaBrowser {}, Token=\"{}\"", parts.join(", "), clean(token))
}

/// The `Authorization` value for a call made with the seller's API key (its libraries, the buyers'
/// accounts): never sent with a buyer's request.
pub fn admin_authorization(key: &str) -> String {
    authorization(None, key, "lightning-stream-seller")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clients_fields_are_kept_and_its_token_replaced() {
        let web = r#"MediaBrowser Client="Jellyfin Web", Device="Firefox", DeviceId="TW96aWxsYQ", Version="10.11.0", Token="theirs""#;
        assert_eq!(authorization(Some(web), "buyer-tok", "ls-x"),
                   r#"MediaBrowser Client="Jellyfin Web", Device="Firefox", DeviceId="TW96aWxsYQ", Version="10.11.0", Token="buyer-tok""#);
        // the token first, unquoted, and odd spacing: still one token, the buyer's
        let a = authorization(Some("mediabrowser Token=theirs,Client=\"x\""), "b", "ls-x");
        assert_eq!(a, r#"MediaBrowser Client="x", Device="Lightning Stream", DeviceId="ls-x", Version="1", Token="b""#);
        assert_eq!(a.matches("Token=").count(), 1);
        // a quoted comma or quote cannot add a field
        let a = authorization(Some(r#"MediaBrowser Client="a, Token=evil", Device="d\"x""#), "b", "ls-x");
        let tokens: Vec<(String, String)> = fields(&a).unwrap().into_iter().filter(|(k, _)| k.eq_ignore_ascii_case("token")).collect();
        assert_eq!(tokens, vec![("Token".to_string(), "b".to_string())], "{a}");
        // another scheme is not read
        assert!(authorization(Some("Bearer abc"), "b", "d").starts_with(r#"MediaBrowser Client="Lightning Stream""#));
        assert_eq!(admin_authorization("k"), r#"MediaBrowser Client="Lightning Stream", Device="Lightning Stream", DeviceId="lightning-stream-seller", Version="1", Token="k""#);
    }
}
