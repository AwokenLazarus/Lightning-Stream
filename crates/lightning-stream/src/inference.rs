//! The inference proxy's rules, with no IO: the owner's API keys, the catalogue of models the
//! allowed sellers offer, and which seller a request goes to.
//!
//! The endpoint (an OpenAI-compatible address on the owner's network) is a thin layer over these:
//! it checks the key ([`Keys::check`]), asks the router for an order of sellers ([`Router::order`]),
//! pays the first through the signer, and on a failure before the first byte of an answer tries
//! the next ([`Router::may_fall_back`]). A request is sent to one seller at a time, and never moved
//! once a byte of the answer has arrived, so one answer is never paid for twice.
//!
//! Keys are kept as the SHA-256 of the key, so a copy of the file does not give them away; the key
//! itself is shown to the owner once, when it is made.

use std::collections::HashMap;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The prefix every key carries, so a key is recognised for what it is in a client's settings.
pub const KEY_PREFIX: &str = "sk-stream-";

/// Most fallbacks after the first seller, for one request.
pub const MAX_FALLBACKS: usize = 2;

/// How many recent calls a seller's health is judged on.
pub const HEALTH_WINDOW: usize = 50;

/// Failures in a row after which a seller is skipped for [`COOL_OFF_S`].
pub const FAILS_TO_COOL: u32 = 3;

/// How long a failing seller is left alone before one request tries it again.
pub const COOL_OFF_S: u64 = 300;

/// Within this share of the cheapest price, the faster seller wins (a near-tie, in percent).
pub const NEAR_TIE_PCT: u64 = 20;

fn key_hash(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// A new key: [`KEY_PREFIX`] and 128 random bits, base64url without padding.
pub fn new_key() -> String {
    use base64::Engine as _;
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("the system's random source");
    format!("{KEY_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

/// One API key the owner made for a client app.
#[derive(Debug, Clone, PartialEq)]
pub struct Key {
    /// SHA-256 of the key, hex.
    pub hash: String,
    pub name: String,
    /// The most the key may spend in all, in sats.
    pub limit_sats: u64,
    /// What it has spent, in sats (the sum of its calls' charges).
    pub spent_sats: u64,
    pub revoked: bool,
}

/// Why a key may not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRefusal {
    /// No key, an unknown one, or one revoked: OpenAI's 401.
    Unknown,
    /// The key has spent its limit: 402, and the owner raises the limit.
    LimitReached { limit_sats: u64 },
}

impl KeyRefusal {
    /// The HTTP status and the error body, in the shape OpenAI's clients read.
    pub fn answer(&self) -> (u16, Value) {
        match self {
            Self::Unknown => (401, error_body("invalid_api_key", "authentication_error", "This key is not one this Lightning Stream knows, or it was revoked.")),
            Self::LimitReached { limit_sats } => (402, error_body("limit_reached", "insufficient_quota",
                &format!("This key has spent its limit of {limit_sats} sats. Raise the limit on the AI page of Lightning Stream."))),
        }
    }
}

/// An error in OpenAI's shape: `{"error": {"message", "type", "code"}}`.
pub fn error_body(code: &str, kind: &str, message: &str) -> Value {
    json!({"error": {"message": message, "type": kind, "code": code}})
}

/// The owner's keys.
#[derive(Debug, Default, Clone)]
pub struct Keys {
    keys: Vec<Key>,
}

impl Keys {
    pub fn new(keys: Vec<Key>) -> Self {
        Self { keys }
    }

    /// Makes a key and keeps only its hash: the key itself is returned, to be shown once.
    pub fn make(&mut self, name: &str, limit_sats: u64) -> String {
        let key = new_key();
        self.keys.push(Key { hash: key_hash(&key), name: name.to_string(), limit_sats, spent_sats: 0, revoked: false });
        key
    }

    /// The key an `Authorization` header names, when it may spend `need_sats` more.
    pub fn check(&self, authorization: Option<&str>, need_sats: u64) -> Result<&Key, KeyRefusal> {
        let given = authorization.and_then(|h| h.strip_prefix("Bearer ")).map(str::trim).unwrap_or("");
        if !given.starts_with(KEY_PREFIX) {
            return Err(KeyRefusal::Unknown);
        }
        let h = key_hash(given);
        let k = self.keys.iter().find(|k| crate_ct_eq(k.hash.as_bytes(), h.as_bytes()) && !k.revoked).ok_or(KeyRefusal::Unknown)?;
        if k.spent_sats.saturating_add(need_sats) > k.limit_sats {
            return Err(KeyRefusal::LimitReached { limit_sats: k.limit_sats });
        }
        Ok(k)
    }

    /// What the key may still spend.
    pub fn left(&self, hash: &str) -> u64 {
        self.keys.iter().find(|k| k.hash == hash).map_or(0, |k| k.limit_sats.saturating_sub(k.spent_sats))
    }

    /// Books what a call charged against its key.
    pub fn charge(&mut self, hash: &str, sats: u64) {
        if let Some(k) = self.keys.iter_mut().find(|k| k.hash == hash) {
            k.spent_sats = k.spent_sats.saturating_add(sats);
        }
    }

    pub fn revoke(&mut self, hash: &str) {
        if let Some(k) = self.keys.iter_mut().find(|k| k.hash == hash) {
            k.revoked = true;
        }
    }

    pub fn list(&self) -> &[Key] {
        &self.keys
    }
}

/// A comparison that takes the same time whatever the bytes, for keys.
fn crate_ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// One model at one seller.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub model: String,
    /// The seller's name in the listing, used in `seller/model` to pin.
    pub seller: String,
    /// The seller's route, e.g. `https://shop.example/ai/`.
    pub route: String,
    pub input_per_1k_msat: u64,
    pub output_per_1k_msat: u64,
    /// The route's cap on output tokens.
    pub max_output: u64,
    pub context: Option<u64>,
}

impl Offer {
    /// What a request is expected to cost at most, in msat: input tokens and `max_tokens` of output.
    pub fn bound_msat(&self, input_tokens: u64, max_tokens: u64) -> u64 {
        let out = max_tokens.min(if self.max_output == 0 { max_tokens } else { self.max_output });
        let per = |n: u64, rate: u64| (u128::from(n) * u128::from(rate)).div_ceil(1000);
        u64::try_from(per(input_tokens, self.input_per_1k_msat) + per(out, self.output_per_1k_msat)).unwrap_or(u64::MAX)
    }
}

/// The models of the allowed sellers.
#[derive(Debug, Default, Clone)]
pub struct Catalogue {
    pub offers: Vec<Offer>,
}

impl Catalogue {
    /// The offers of a seller's route, from its `GET /v1/models` answer and its listing's prices.
    pub fn add_seller(&mut self, seller: &str, route: &str, prices: &Value, max_output: u64, models: &Value) {
        let n = |k: &str| prices.get(k).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0);
        let (input, output) = (n("per_1k_input_msat"), n("per_1k_output_msat"));
        self.offers.retain(|o| !(o.seller == seller && o.route == route));
        for m in models.get("data").and_then(Value::as_array).into_iter().flatten() {
            let Some(id) = m.get("id").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 200) else { continue };
            let context = ["context_length", "max_model_len", "context_window"].iter().find_map(|k| m.get(*k).and_then(Value::as_u64));
            self.offers.push(Offer { model: id.to_string(), seller: seller.to_string(), route: route.to_string(),
                                     input_per_1k_msat: input, output_per_1k_msat: output, max_output, context });
        }
    }

    /// `GET /v1/models`: one entry per model, with every seller's price under `x_stream`, which
    /// clients that do not know it leave alone. A model is listed both as `model` (route me) and as
    /// `seller/model` (this seller only).
    pub fn models_json(&self) -> Value {
        let mut ids: Vec<&str> = self.offers.iter().map(|o| o.model.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        let mut data = Vec::new();
        for id in ids {
            let sellers: Vec<Value> = self.offers.iter().filter(|o| o.model == id)
                .map(|o| json!({"seller": o.seller, "per_1k_input_msat": o.input_per_1k_msat, "per_1k_output_msat": o.output_per_1k_msat}))
                .collect();
            data.push(json!({"id": id, "object": "model", "owned_by": "lightning-stream", "x_stream": {"sellers": sellers}}));
        }
        for o in &self.offers {
            data.push(json!({"id": format!("{}/{}", o.seller, o.model), "object": "model", "owned_by": o.seller}));
        }
        json!({"object": "list", "data": data})
    }
}

/// One seller's recent record.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Health {
    /// Times to first token of recent successful calls, in ms, newest last.
    pub ttft_ms: Vec<u64>,
    pub fails_in_a_row: u32,
    /// When the last failure that cooled the seller off happened (seconds since the epoch).
    pub cooled_at: Option<u64>,
    pub ok: u64,
    pub failed: u64,
}

impl Health {
    pub fn median_ttft(&self) -> Option<u64> {
        let mut v = self.ttft_ms.clone();
        v.sort_unstable();
        v.get(v.len() / 2).copied().filter(|_| !v.is_empty())
    }

    /// Whether the seller is resting after failing [`FAILS_TO_COOL`] times in a row.
    pub fn cooling(&self, now: u64) -> bool {
        self.fails_in_a_row >= FAILS_TO_COOL && self.cooled_at.is_some_and(|t| now < t.saturating_add(COOL_OFF_S))
    }
}

/// How one try at a seller ended, for its health and for the fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The answer arrived; its first token after `ttft_ms`.
    Answered { ttft_ms: u64 },
    /// Refused or failed before any byte of the answer (network, 5xx, a 402 the signer would not pay,
    /// no first token in time). Another seller may be tried.
    FailedBeforeAnswer,
    /// Stopped after the answer had begun. The request is not moved.
    CutMidAnswer,
}

/// What the owner set about sellers, overall or for one key.
#[derive(Debug, Clone, Default)]
pub struct Prefs {
    pub pinned: Vec<String>,
    pub blocked: Vec<String>,
}

/// The router: the catalogue, the sellers' health, and the owner's preferences.
#[derive(Debug, Default)]
pub struct Router {
    pub catalogue: Catalogue,
    pub health: HashMap<String, Health>,
    pub prefs: Prefs,
}

impl Router {
    /// The sellers to try for `model`, in order. `model` is a plain id (route me) or `seller/id`
    /// (that seller only). Blocked and resting sellers are left out; pinned ones come first; the
    /// rest go by what this request may cost, with the faster seller first in a near-tie.
    pub fn order(&self, model: &str, input_tokens: u64, max_tokens: u64, now: u64) -> Vec<&Offer> {
        let (want_seller, id) = match model.split_once('/') {
            Some((s, m)) if self.catalogue.offers.iter().any(|o| o.seller == s && o.model == m) => (Some(s), m),
            _ => (None, model),
        };
        let mut c: Vec<&Offer> = self.catalogue.offers.iter()
            .filter(|o| o.model == id && want_seller.is_none_or(|s| o.seller == s))
            .filter(|o| !self.prefs.blocked.contains(&o.seller))
            .filter(|o| !self.health.get(&o.seller).is_some_and(|h| h.cooling(now)))
            .collect();
        let ttft = |o: &Offer| self.health.get(&o.seller).and_then(Health::median_ttft).unwrap_or(u64::MAX / 4);
        let cost = |o: &Offer| o.bound_msat(input_tokens, max_tokens);
        c.sort_by(|a, b| {
            let pa = self.prefs.pinned.contains(&a.seller);
            let pb = self.prefs.pinned.contains(&b.seller);
            pb.cmp(&pa).then_with(|| {
                let (ca, cb) = (cost(a), cost(b));
                let near = ca.max(cb).saturating_mul(100) <= ca.min(cb).saturating_mul(100 + NEAR_TIE_PCT);
                if near { ttft(a).cmp(&ttft(b)).then(ca.cmp(&cb)) } else { ca.cmp(&cb) }
            })
        });
        c.truncate(1 + MAX_FALLBACKS);
        c
    }

    /// Whether, after `outcome`, the request may go to the next seller. Only a failure before any
    /// byte of the answer moves a request: one answer is never paid for at two sellers.
    pub fn may_fall_back(outcome: Outcome) -> bool {
        outcome == Outcome::FailedBeforeAnswer
    }

    /// Books how a try at `seller` ended.
    pub fn record(&mut self, seller: &str, outcome: Outcome, now: u64) {
        let h = self.health.entry(seller.to_string()).or_default();
        match outcome {
            Outcome::Answered { ttft_ms } => {
                h.ok += 1;
                h.fails_in_a_row = 0;
                h.cooled_at = None;
                h.ttft_ms.push(ttft_ms);
                if h.ttft_ms.len() > HEALTH_WINDOW {
                    h.ttft_ms.remove(0);
                }
            }
            Outcome::FailedBeforeAnswer | Outcome::CutMidAnswer => {
                h.failed += 1;
                h.fails_in_a_row += 1;
                if h.fails_in_a_row >= FAILS_TO_COOL {
                    h.cooled_at = Some(now);
                }
            }
        }
    }
}

/// The request's input, bounded as the seller's gateway bounds it (one token per two bytes of the
/// body), and its `max_tokens` (or the given default).
pub fn request_bounds(body: &Value, raw_len: usize, default_max: u64) -> (u64, u64) {
    let input = u64::try_from(raw_len.div_ceil(2)).unwrap_or(u64::MAX);
    let max = ["max_completion_tokens", "max_tokens"].iter().find_map(|k| body.get(*k).and_then(Value::as_u64)).unwrap_or(default_max);
    (input, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat() -> Catalogue {
        let mut c = Catalogue::default();
        let models = json!({"data": [{"id": "llama-3.1-8b", "context_length": 8192}, {"id": "qwen-1.5b"}]});
        c.add_seller("cheap", "https://cheap.example/ai/", &json!({"per_1k_output_msat": 5000}), 1024, &models);
        c.add_seller("fast", "https://fast.example/ai/", &json!({"per_1k_output_msat": 5500}), 1024, &json!({"data": [{"id": "llama-3.1-8b"}]}));
        c.add_seller("dear", "https://dear.example/ai/", &json!({"per_1k_input_msat": 2000, "per_1k_output_msat": 20000}), 1024, &json!({"data": [{"id": "llama-3.1-8b"}]}));
        c
    }

    #[test]
    fn a_key_is_kept_hashed_checked_and_limited() {
        let mut k = Keys::default();
        let key = k.make("Open WebUI", 1000);
        assert!(key.starts_with(KEY_PREFIX) && key.len() == KEY_PREFIX.len() + 22);
        assert!(k.list().iter().all(|x| x.hash != key && !x.hash.contains(&key)), "the key itself is not kept");
        let auth = format!("Bearer {key}");
        let h = k.check(Some(&auth), 10).unwrap().hash.clone();
        assert_eq!(k.check(Some("Bearer sk-stream-nope"), 0), Err(KeyRefusal::Unknown));
        assert_eq!(k.check(None, 0), Err(KeyRefusal::Unknown));
        k.charge(&h, 995);
        assert_eq!(k.left(&h), 5);
        assert_eq!(k.check(Some(&auth), 10), Err(KeyRefusal::LimitReached { limit_sats: 1000 }));
        assert!(k.check(Some(&auth), 5).is_ok());
        k.revoke(&h);
        assert_eq!(k.check(Some(&auth), 0), Err(KeyRefusal::Unknown));
        let (status, body) = KeyRefusal::LimitReached { limit_sats: 1000 }.answer();
        assert_eq!((status, body["error"]["code"].as_str()), (402, Some("limit_reached")));
    }

    #[test]
    fn the_catalogue_lists_each_model_once_and_each_seller_offer_to_pin() {
        let c = cat();
        let m = c.models_json();
        let ids: Vec<&str> = m["data"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap()).collect();
        assert_eq!(ids.iter().filter(|i| **i == "llama-3.1-8b").count(), 1);
        assert!(ids.contains(&"cheap/llama-3.1-8b") && ids.contains(&"fast/llama-3.1-8b") && ids.contains(&"cheap/qwen-1.5b"));
        assert_eq!(m["data"][0]["x_stream"]["sellers"].as_array().unwrap().len(), 3);
        assert_eq!(c.offers.iter().find(|o| o.seller == "cheap" && o.model == "llama-3.1-8b").unwrap().context, Some(8192));
        // a seller's models are replaced when it is read again, not added twice
        let mut c2 = c.clone();
        c2.add_seller("cheap", "https://cheap.example/ai/", &json!({"per_1k_output_msat": 5000}), 1024, &json!({"data": [{"id": "qwen-1.5b"}]}));
        assert_eq!(c2.offers.iter().filter(|o| o.seller == "cheap").count(), 1);
    }

    #[test]
    fn the_cheapest_goes_first_the_faster_wins_a_near_tie_and_a_pin_comes_first() {
        let mut r = Router { catalogue: cat(), ..Default::default() };
        let order = |r: &Router| r.order("llama-3.1-8b", 100, 500, 0).iter().map(|o| o.seller.clone()).collect::<Vec<_>>();
        // no history: by cost; cheap and fast are within 20%, so with equal (unknown) speed cheap leads
        assert_eq!(order(&r), ["cheap", "fast", "dear"]);
        // fast answers its first token far sooner: it wins the near-tie, but not against a much cheaper one
        for _ in 0..5 {
            r.record("fast", Outcome::Answered { ttft_ms: 200 }, 0);
            r.record("cheap", Outcome::Answered { ttft_ms: 2000 }, 0);
            r.record("dear", Outcome::Answered { ttft_ms: 50 }, 0);
        }
        assert_eq!(order(&r), ["fast", "cheap", "dear"]);
        r.prefs.pinned = vec!["dear".into()];
        assert_eq!(order(&r)[0], "dear");
        r.prefs.blocked = vec!["dear".into()];
        assert!(!order(&r).contains(&"dear".to_string()));
        // a seller named in the model is the only one tried
        assert_eq!(r.order("cheap/llama-3.1-8b", 100, 500, 0).iter().map(|o| o.seller.as_str()).collect::<Vec<_>>(), ["cheap"]);
        // an unknown model has no seller
        assert!(r.order("gpt-9", 100, 500, 0).is_empty());
    }

    #[test]
    fn only_a_failure_before_the_answer_moves_a_request_and_a_failing_seller_rests() {
        assert!(Router::may_fall_back(Outcome::FailedBeforeAnswer));
        assert!(!Router::may_fall_back(Outcome::CutMidAnswer));
        assert!(!Router::may_fall_back(Outcome::Answered { ttft_ms: 1 }));
        let mut r = Router { catalogue: cat(), ..Default::default() };
        for _ in 0..FAILS_TO_COOL {
            r.record("cheap", Outcome::FailedBeforeAnswer, 1000);
        }
        let sellers = |r: &Router, now| r.order("llama-3.1-8b", 100, 500, now).iter().map(|o| o.seller.clone()).collect::<Vec<_>>();
        assert!(!sellers(&r, 1000).contains(&"cheap".to_string()), "a seller failing 3 times in a row rests");
        assert!(sellers(&r, 1000 + COOL_OFF_S).contains(&"cheap".to_string()), "and is tried again after the rest");
        r.record("cheap", Outcome::Answered { ttft_ms: 10 }, 1000 + COOL_OFF_S);
        assert_eq!(r.health["cheap"].fails_in_a_row, 0);
    }

    #[test]
    fn a_request_is_bounded_as_the_seller_bounds_it() {
        let o = &cat().offers[0];
        // 2 bytes a token in; output capped by the route
        assert_eq!(request_bounds(&json!({"max_tokens": 300}), 1001, 1024), (501, 300));
        assert_eq!(request_bounds(&json!({}), 10, 256), (5, 256));
        assert_eq!(o.bound_msat(0, 5000), 1024 * 5000 / 1000);
        assert_eq!(cat().offers.iter().find(|o| o.seller == "dear").unwrap().bound_msat(1000, 1000), 2000 + 20000);
    }
}
