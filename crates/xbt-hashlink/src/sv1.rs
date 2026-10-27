//! The few Stratum V1 facts the relay and the meter read. Every other part of a line passes
//! through untouched, so extensions the miner and the gateway agree on (`mining.configure`,
//! version rolling, `mining.extranonce.subscribe`, extra notify fields) need nothing here.

use serde_json::Value;

pub fn parse(line: &str) -> Option<Value> {
    serde_json::from_str(line.trim()).ok()
}

pub fn method(v: &Value) -> Option<&str> {
    v.get("method").and_then(Value::as_str)
}

pub fn params(v: &Value) -> Option<&Vec<Value>> {
    v.get("params").and_then(Value::as_array)
}

/// A response (it has an id and no method).
pub fn is_response(v: &Value) -> bool {
    method(v).is_none() && v.get("id").is_some_and(|i| !i.is_null())
}

/// A response's verdict: `true` only for `"result": true` with no error.
pub fn accepted(v: &Value) -> bool {
    v.get("result") == Some(&Value::Bool(true)) && v.get("error").is_none_or(Value::is_null)
}

/// The id as a key (numbers and strings both occur).
pub fn id_key(v: &Value) -> Option<String> {
    match v.get("id")? {
        Value::Null => None,
        i => Some(i.to_string()),
    }
}

/// `mining.set_difficulty`'s difficulty.
pub fn set_difficulty(v: &Value) -> Option<f64> {
    (method(v)? == "mining.set_difficulty").then(|| params(v)?.first()?.as_f64())?
}

/// `mining.notify`'s job id.
pub fn notify_job(v: &Value) -> Option<String> {
    (method(v)? == "mining.notify").then(|| params(v)?.first()?.as_str().map(str::to_string))?
}

/// `mining.submit`'s job id.
pub fn submit_job(v: &Value) -> Option<String> {
    (method(v)? == "mining.submit").then(|| params(v)?.get(1)?.as_str().map(str::to_string))?
}

/// The hashtaker's gateway credits the hashtaker: `mining.authorize` and `mining.submit` carry the
/// hashtaker's user name in place of the miner's. Returns the rewritten line, or `None` to pass it.
pub fn with_user(v: &Value, user: &str) -> Option<String> {
    match method(v)? {
        "mining.authorize" | "mining.submit" => {
            let mut v = v.clone();
            let p = v.get_mut("params")?.as_array_mut()?;
            *p.first_mut()? = Value::String(user.to_string());
            Some(v.to_string())
        }
        _ => None,
    }
}

/// The miner's worker name from `mining.authorize`.
pub fn authorize_user(v: &Value) -> Option<String> {
    (method(v)? == "mining.authorize").then(|| params(v)?.first()?.as_str().map(str::to_string))?
}

/// Lines the hashmaker never passes to its miners: a gateway must not send them elsewhere.
pub fn dropped_down(v: &Value) -> bool {
    matches!(method(v), Some("client.reconnect"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_rewrites() {
        let n = parse(r#"{"id":null,"method":"mining.notify","params":["j1","00",""]}"#).unwrap();
        assert_eq!(notify_job(&n).as_deref(), Some("j1"));
        let d = parse(r#"{"id":null,"method":"mining.set_difficulty","params":[4096]}"#).unwrap();
        assert_eq!(set_difficulty(&d), Some(4096.0));
        let s = parse(r#"{"id":7,"method":"mining.submit","params":["miner.1","j1","00","01","02"]}"#).unwrap();
        assert_eq!(submit_job(&s).as_deref(), Some("j1"));
        let r = with_user(&s, "hashtaker").unwrap();
        assert_eq!(params(&parse(&r).unwrap()).unwrap()[0], "hashtaker");
        let ok = parse(r#"{"id":7,"result":true,"error":null}"#).unwrap();
        assert!(is_response(&ok) && accepted(&ok) && id_key(&ok).as_deref() == Some("7"));
        let no = parse(r#"{"id":"7","result":false,"error":[23,"low",null]}"#).unwrap();
        assert!(!accepted(&no));
        assert!(!is_response(&n));
    }
}
