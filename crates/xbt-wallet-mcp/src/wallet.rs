//! The wallet behind the tools: B2's signer socket, and nothing else. This process never holds a key
//! (B2's signer, Python or Rust, holds them all) and never reads the hot key's wrapping key.
//!
//! * [`Wallet::call_tool`] forwards a validated tool call to the signer method of the same name,
//!   exactly as B2's `mcp_server.py` does, and packs the answer the way B2 packs it ([`pack`]).
//!   `xbt402_pay` and `ln_pay` can wait for the owner's approval ([`Wallet::pay_waiting`]).
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};
use xbt402::json::{as_big_int, parse, py_float};
use xbt_signer::ipc::Stream;
use xbt_signer::sanitize::{assert_no_key_material, sanitize};

// --- JSON as Python writes it -----------------------------------------------------------------

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
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(out: &mut String, v: &Value, indent: Option<usize>, sort: bool, level: usize) {
    let (item, key) = if indent.is_some() { (",", ": ") } else { (", ", ": ") };
    let nl = |out: &mut String, l: usize| {
        if let Some(n) = indent {
            out.push('\n');
            out.push_str(&" ".repeat(n * l));
        }
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) if n.is_f64() => out.push_str(&py_float(n.as_f64().unwrap_or(0.0))),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) if s.starts_with(NONFINITE) => out.push_str(&s[NONFINITE.len()..]),
        Value::String(s) => write_str(out, s),
        Value::Object(_) if as_big_int(v).is_some() => out.push_str(as_big_int(v).unwrap_or("0")),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Object(m) if m.is_empty() => out.push_str("{}"),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item);
                }
                nl(out, level + 1);
                write(out, x, indent, sort, level + 1);
            }
            nl(out, level);
            out.push(']');
        }
        Value::Object(m) => {
            let mut kv: Vec<_> = m.iter().collect();
            if sort {
                kv.sort_by(|a, b| a.0.cmp(b.0)); // UTF-8 byte order is code-point order, as Python sorts
            }
            out.push('{');
            for (i, (k, x)) in kv.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(item);
                }
                nl(out, level + 1);
                write_str(out, k);
                out.push_str(key);
                write(out, x, indent, sort, level + 1);
            }
            nl(out, level);
            out.push('}');
        }
    }
}

/// `json.dumps(v, indent=2, sort_keys=True)`, integers of any size kept.
pub fn dumps_pretty(v: &Value) -> String {
    let mut s = String::new();
    write(&mut s, v, Some(2), true, 0);
    s
}

/// `json.dumps(v)`, integers of any size kept.
pub fn dumps(v: &Value) -> String {
    let mut s = String::new();
    write(&mut s, v, None, false, 0);
    s
}

/// B2's `_pack`: drop key-named fields and redact key-shaped strings (outside the untrusted provider
/// subtree), refuse anything key-like that is left, and print as B2 prints. Err: the refusal.
pub fn pack(result: Value) -> Result<String, String> {
    let clean = sanitize(result);
    assert_no_key_material(&clean)?;
    Ok(dumps_pretty(&clean))
}

// --- the signer socket --------------------------------------------------------------------------

/// A float Python's `json` reads and writes that JSON has no token for (`NaN`, `Infinity`,
/// `-Infinity`), carried through as a marked string and written back bare.
const NONFINITE: &str = "\u{0}xbt-mcp-nonfinite:";

/// [`parse`], plus Python's `NaN` / `Infinity` / `-Infinity` tokens outside strings.
pub fn parse_py(s: &str) -> serde_json::Result<Value> {
    if !(s.contains("NaN") || s.contains("Infinity")) {
        return parse(s);
    }
    let (mut out, mut in_str, mut esc, mut i) = (Vec::with_capacity(s.len()), false, false, 0);
    let b = s.as_bytes();
    while i < b.len() {
        let c = b[i];
        if in_str {
            in_str = c != b'"' || esc;
            esc = c == b'\\' && !esc;
        } else if c == b'"' {
            in_str = true;
        } else if let Some(t) = ["-Infinity", "Infinity", "NaN"].into_iter().find(|t| b[i..].starts_with(t.as_bytes())) {
            out.extend(format!("\"{}{t}\"", NONFINITE.replace('\u{0}', "\\u0000")).bytes());
            i += t.len();
            continue;
        }
        out.push(c);
        i += 1;
    }
    xbt402::json::parse_slice(&out)
}

/// B2's `SignerClient.call`: one request per connection, `{"id": 1, "method", "params"}` + newline,
/// one line back. Big integers survive both ways (`xbt402::json::parse`).
pub fn signer_call(sock: &Path, timeout: Duration, method: &str, params: &Value) -> Result<Value, String> {
    let io = |e: std::io::Error| format!("signer socket {}: {e}", sock.display());
    let mut s = Stream::connect(sock).map_err(io)?;
    s.set_timeouts(Some(timeout));
    let mut req = Map::new();
    req.insert("id".into(), 1.into());
    req.insert("method".into(), method.into());
    req.insert("params".into(), params.clone());
    s.write_all(format!("{}\n", dumps(&Value::Object(req))).as_bytes()).map_err(io)?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(io)?;
    let resp = parse_py(line.trim()).map_err(|e| format!("signer answer: {e}"))?;
    if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
        return Err(format!("signer error: {}", e.get("message").and_then(Value::as_str).unwrap_or("error")));
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

/// Where B2 looks for the socket: `B2_SIGNER_SOCK`, else `$B2_ROOT/.run/signer.sock`.
pub fn default_sock() -> PathBuf {
    if let Ok(s) = std::env::var("B2_SIGNER_SOCK") {
        return s.into();
    }
    let root = std::env::var("B2_ROOT").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    root.join(".run").join("signer.sock")
}

fn default_timeout() -> Duration {
    Duration::from_secs_f64(std::env::var("B2_SIGNER_TIMEOUT").ok().and_then(|v| v.parse::<f64>().ok()).unwrap_or(60.0))
}

pub struct Wallet {
    pub sock: PathBuf,
    pub timeout: Duration,
    /// AGP-039 `XBT_MCP_APPROVAL_WAIT_S`: how long an over-threshold `xbt402_pay` waits for the
    /// human's approval (in the wallet's web UI) before it answers `needs_human`. 0 (the default) is
    /// B2's behaviour: answer at once.
    pub approval_wait: Duration,
    /// AGP-048 `XBT_MCP_LN=1`: offer `ln_pay` and `ln_status` (the signer must have an LN node).
    pub ln_tools: bool,
    /// `XBT_MCP_TICKETS=1`: offer `ticket_status` and `ticket_stop` (the signer's policy must turn tickets on).
    pub ticket_tools: bool,
}

impl Wallet {
    pub fn new(sock: PathBuf) -> Self {
        let wait = std::env::var("XBT_MCP_APPROVAL_WAIT_S").ok().and_then(|v| v.parse::<f64>().ok()).filter(|w| w.is_finite() && *w > 0.0).unwrap_or(0.0);
        let ln_tools = std::env::var("XBT_MCP_LN").is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
        let ticket_tools = std::env::var("XBT_MCP_TICKETS").is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
        Self { sock, timeout: default_timeout(), approval_wait: Duration::from_secs_f64(wait.min(86_400.0)), ln_tools,
               ticket_tools }
    }

    /// B2's environment: `B2_SIGNER_SOCK` / `B2_ROOT`, `B2_SIGNER_TIMEOUT`. `XBT_MCP_PAYER=local` was
    /// the in-process payer of the on-chain channel, which was removed: a start that still asks for
    /// it is refused, so that nobody runs a wallet believing it pays that way.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("XBT_MCP_PAYER").as_deref() {
            Ok("signer") | Err(_) => Ok(Self::new(default_sock())),
            Ok("local") => Err("XBT_MCP_PAYER=local: the in-process payer paid the on-chain channel, which was removed; unset XBT_MCP_PAYER (the signer pays)".into()),
            Ok(o) => Err(format!("XBT_MCP_PAYER={o}: expected signer, or unset")),
        }
    }

    pub fn signer(&self, method: &str, params: &Value) -> Result<Value, String> {
        signer_call(&self.sock, self.timeout, method, params)
    }

    /// The signer's `xbt402_pay` (or, AGP-048, `ln_pay`); an over-threshold call waits up to
    /// `approval_wait` for the human. Once the human approved in the UI the signer holds a one-time
    /// grant for exactly this call (url, method, max_sats; or the invoice), and the same call again
    /// pays under it. A deny or expiry answers the original `needs_human` with `approval_state`. The
    /// model never sees or needs a signature.
    fn pay_waiting(&self, method: &str, params: &Map<String, Value>) -> Result<Value, String> {
        let args = Value::Object(params.clone());
        let first = self.signer(method, &args)?;
        if self.approval_wait.is_zero() || first.get("verdict").and_then(Value::as_str) != Some("needs_human") {
            return Ok(first);
        }
        let Some(token) = first.get("approval_token").and_then(Value::as_str).map(str::to_string) else { return Ok(first) };
        let until = std::time::Instant::now() + self.approval_wait;
        let mut state = String::from("pending");
        while std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(500));
            state = self.signer("approval_status", &json!({"token": token}))?.get("state").and_then(Value::as_str).unwrap_or("unknown").to_string();
            if state == "approved" {
                let mut paid = self.signer(method, &args)?;
                // a payment the node has not settled yet answers "pending": the grant stays until
                // it is used, so keep calling while the wait lasts
                while paid.get("verdict").and_then(Value::as_str) == Some("pending") && std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_secs(1));
                    paid = self.signer(method, &args)?;
                }
                if let Value::Object(m) = &mut paid {
                    m.insert("waited_for_human".into(), Value::Bool(true));
                }
                return Ok(paid);
            }
            if state != "pending" {
                break;
            }
        }
        let mut out = first;
        if let Value::Object(m) = &mut out {
            m.insert("approval_state".into(), state.into());
        }
        Ok(out)
    }

    /// Run a tool whose arguments passed validation. Ok: the packed text. Err: the reason, which
    /// stays in this process's log; the model gets B2's generic "Error executing tool" line.
    pub fn call_tool(&self, name: &str, mut params: Map<String, Value>) -> Result<String, String> {
        // no byte range asked for: the whole body, and the signer is not sent an empty one
        if params.get("range").and_then(Value::as_str).is_some_and(|r| r.trim().is_empty()) {
            params.remove("range");
        }
        let result = match name {
            "xbt402_pay" | "ln_pay" => self.pay_waiting(name, &params)?,
            _ => self.signer(name, &Value::Object(params))?,
        };
        pack(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xbt_signer::sanitize::UNTRUSTED_KEY;

    #[test]
    fn dumps_like_python() {
        let v = parse(r#"{"b": [1, 2.0, {"z": null, "a": []}], "a": {}, "big": 100000000000000000000000, "u": "é"}"#).unwrap();
        assert_eq!(dumps_pretty(&v), "{\n  \"a\": {},\n  \"b\": [\n    1,\n    2.0,\n    {\n      \"a\": [],\n      \"z\": null\n    }\n  ],\n  \"big\": 100000000000000000000000,\n  \"u\": \"\\u00e9\"\n}");
        assert_eq!(dumps(&v), r#"{"b": [1, 2.0, {"z": null, "a": []}], "a": {}, "big": 100000000000000000000000, "u": "\u00e9"}"#);
    }

    #[test]
    fn pack_strips_keys_keeps_untrusted() {
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let s = pack(json!({"hot_secret": "x", "wif": wif, "n": wif, UNTRUSTED_KEY: {"body": wif, "secret": 1}})).unwrap();
        assert_eq!(s, format!("{{\n  \"n\": \"[redacted]\",\n  \"untrusted_provider_response\": {{\n    \"body\": \"{wif}\",\n    \"secret\": 1\n  }}\n}}"));
    }
}
