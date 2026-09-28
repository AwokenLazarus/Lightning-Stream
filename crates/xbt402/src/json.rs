//! JSON exactly as Python's `json.dumps` writes it (key order kept, `ensure_ascii`), so a header
//! built here is byte-identical to the reference implementation's, plus the loose readers the
//! reference's `int(...)`/`str(...)` conversions amount to.
use serde_json::{Map, Value};

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7E => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(out: &mut String, v: &Value, item_sep: &str, key_sep: &str) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write(out, x, item_sep, key_sep);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write_str(out, k);
                out.push_str(key_sep);
                write(out, x, item_sep, key_sep);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(v)`: separators `", "` and `": "`.
pub fn dumps(v: &Value) -> String {
    let mut s = String::new();
    write(&mut s, v, ", ", ": ");
    s
}

/// `json.dumps(v, separators=(",", ":"))`.
pub fn dumps_compact(v: &Value) -> String {
    let mut s = String::new();
    write(&mut s, v, ",", ":");
    s
}

/// Python's `str(x)` of a JSON value, as the reference formats values into signed messages:
/// strings as themselves, integers in decimal, `None`/`True`/`False`.
pub fn py_str(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".into(),
        Some(Value::Bool(true)) => "True".into(),
        Some(Value::Bool(false)) => "False".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(other) => dumps(other),
    }
}

/// Python's `int(x)` of a JSON value: an integer, or a string of decimal digits (optional sign,
/// surrounding whitespace). None for anything else.
pub fn py_int(v: Option<&Value>) -> Option<i128> {
    match v? {
        Value::Number(n) => n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)),
        Value::Bool(b) => Some(*b as i128),
        Value::String(s) => {
            let t = s.trim();
            let (neg, digits) = match t.as_bytes().first() {
                Some(b'-') => (true, &t[1..]),
                Some(b'+') => (false, &t[1..]),
                _ => (false, t),
            };
            if digits.is_empty() || digits.len() > 30 || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let n: i128 = digits.parse().ok()?;
            Some(if neg { -n } else { n })
        }
        _ => None,
    }
}

/// `py_int` narrowed to a non-negative u64.
pub fn py_u64(v: Option<&Value>) -> Option<u64> {
    py_int(v).and_then(|n| u64::try_from(n).ok())
}

/// Python truthiness of an optional JSON value (`pl.get("sig")` in an `if`).
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Build an ordered JSON object from `(key, value)` pairs.
pub fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    let mut m = Map::with_capacity(N);
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_python() {
        let v = json!({"b": 1, "a": [true, null, "x\u{e9}\n"], "c": {"d": "\u{1F600}"}});
        assert_eq!(dumps(&v), "{\"b\": 1, \"a\": [true, null, \"x\\u00e9\\n\"], \"c\": {\"d\": \"\\ud83d\\ude00\"}}");
        assert_eq!(dumps_compact(&v), "{\"b\":1,\"a\":[true,null,\"x\\u00e9\\n\"],\"c\":{\"d\":\"\\ud83d\\ude00\"}}");
        assert_eq!(py_str(Some(&json!(5))), "5");
        assert_eq!(py_str(None), "None");
        assert_eq!(py_int(Some(&json!(" 12 "))), Some(12));
        assert_eq!(py_int(Some(&json!("1.5"))), None);
    }
}
