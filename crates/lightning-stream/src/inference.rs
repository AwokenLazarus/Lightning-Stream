//! The inference proxy's rules, with no IO: the owner's API keys, the catalogue of models the
//! allowed sellers offer, and which seller a request goes to.
//!
//! The endpoint (an OpenAI-compatible address on the owner's network) is a thin layer over these:
//! it checks the key ([`crate::credentials::Store::check`]), asks the router for an order of sellers ([`Router::order`]),
//! pays the first through the signer, and on a failure before the first byte of an answer tries
//! the next ([`Router::may_fall_back`]). A request is sent to one seller at a time, and never moved
//! once a byte of the answer has arrived, so one answer is never paid for twice.
//!
//! The keys themselves are the shared credential store's ([`crate::credentials`]), one store for
//! AI keys and local links.

use std::collections::HashMap;

use serde_json::{json, Value};
use crate::credentials::Refusal;

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

/// An error in OpenAI's shape: `{"error": {"message", "type", "code"}}`.
pub fn error_body(code: &str, kind: &str, message: &str) -> Value {
    json!({"error": {"message": message, "type": kind, "code": code}})
}

/// The rules of the owner's own spending policy (the signer's `rule` when one refuses a payment): a refusal by one
/// of them is the buyer's limit, not a failure of the seller's.
pub const SPENDING_RULES: [&str; 10] = ["max_per_tx", "daily_budget", "weekly_budget", "per_counterparty", "per_counterparty_daily", "velocity",
                                        "human_threshold", "split_bypass", "ticket_task_budget", "ticket_seller_cap"];

/// Whether `rule` is one of the owner's spending rules ([`SPENDING_RULES`]).
pub fn is_spending_rule(rule: &str) -> bool {
    SPENDING_RULES.contains(&rule)
}

/// Whether a refusal by the spending rule `rule` holds at any seller (a limit on the wallet as a whole), so that no
/// other seller is tried; a limit on one seller leaves the others.
pub fn wallet_wide(rule: &str) -> bool {
    !matches!(rule, "per_counterparty" | "per_counterparty_daily" | "ticket_seller_cap" | "max_per_tx" | "human_threshold" | "split_bypass")
}

/// `n` with a comma between thousands: 20000 is "20,000".
fn thousands(n: u64) -> String {
    let d = n.to_string();
    let mut out = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A payment the owner's spending rule `rule` refused, as OpenAI's clients read it: 402 for a limit on what is
/// spent, 429 for the limit on payments an hour, `spending_limit_reached` with the rule, and words that name the
/// seller, the limit in sats (`limit_sats`, where the wallet said it) and where to raise it. None of the signer's or
/// the seller's own words.
pub fn spending_refusal(rule: &str, limit_sats: Option<u64>, seller: &str) -> (u16, Value) {
    let n = limit_sats.map_or_else(|| "your limit".to_string(), |l| format!("{} sats", thousands(l)));
    let said = match rule {
        "per_counterparty_daily" => format!("You've reached today's limit for {seller} ({n})."),
        "per_counterparty" => format!("You've reached this week's limit for {seller} ({n})."),
        "ticket_seller_cap" => format!("You've reached your limit for {seller} ({n})."),
        "daily_budget" => format!("You've reached today's spending limit ({n}); nothing was paid to {seller}."),
        "weekly_budget" => format!("You've reached this week's spending limit ({n}); nothing was paid to {seller}."),
        "ticket_task_budget" => format!("You've reached the budget for these calls ({n}); nothing was paid to {seller}."),
        "max_per_tx" => format!("A payment to {seller} for this request would be above your largest single payment ({n})."),
        "split_bypass" => format!("Payments to {seller} in the last few minutes add up to more than your largest single payment ({n})."),
        "human_threshold" => format!("A payment to {seller} for this request is at or above the amount you approve first ({n})."),
        "velocity" => format!("You've made as many payments as your spending rules allow in a while; nothing was paid to {seller}. Try again later."),
        _ => format!("Your spending rules refused a payment to {seller}."),
    };
    let message = format!("{said} Raise it in Settings → Spending rules on the Lightning Stream app.");
    let status = if rule == "velocity" { 429 } else { 402 };
    (status, json!({"error": {"message": message, "type": "spending_limit_reached", "code": "spending_limit_reached", "param": null, "rule": rule,
                              "seller": seller, "limit_sats": limit_sats}}))
}

/// A key refused, as OpenAI's clients read it: an unknown or revoked key is 401, a key at its limit
/// 402 with words the client shows.
pub fn refusal_answer(r: &Refusal) -> (u16, Value) {
    match r {
        Refusal::Unknown => (401, error_body("invalid_api_key", "authentication_error", "This key is not one this Lightning Stream knows, or it was revoked.")),
        Refusal::Paused { limit_sats } => (402, error_body("limit_reached", "insufficient_quota",
            &format!("This key has reached its limit of {limit_sats} sats. Raise the limit on the AI page of Lightning Stream."))),
    }
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
    /// What the seller asks for each request, beside its tokens (its listing's `request_msat`).
    pub request_msat: u64,
    /// The route's cap on output tokens.
    pub max_output: u64,
    pub context: Option<u64>,
    /// The seller's listed prices as the most the wallet pays it (`price_ceiling`).
    pub ceiling: Value,
}

impl Offer {
    /// What a request is expected to cost at most, in msat: the seller's price for the request,
    /// input tokens, and `max_tokens` of output.
    pub fn bound_msat(&self, input_tokens: u64, max_tokens: u64) -> u64 {
        let out = max_tokens.min(if self.max_output == 0 { max_tokens } else { self.max_output });
        let per = |n: u64, rate: u64| (u128::from(n) * u128::from(rate)).div_ceil(1000);
        u64::try_from(u128::from(self.request_msat) + per(input_tokens, self.input_per_1k_msat) + per(out, self.output_per_1k_msat)).unwrap_or(u64::MAX)
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
        let n = |k: &str| prices.get(k).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))).unwrap_or(0);
        let (input, output, request) = (n("per_1k_input_msat"), n("per_1k_output_msat"), n("request_msat"));
        self.offers.retain(|o| !(o.seller == seller && o.route == route));
        for m in models.get("data").and_then(Value::as_array).into_iter().flatten() {
            let Some(id) = m.get("id").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 200) else { continue };
            let context = ["context_length", "max_model_len", "context_window"].iter().find_map(|k| m.get(*k).and_then(Value::as_u64));
            self.offers.push(Offer { model: id.to_string(), seller: seller.to_string(), route: route.to_string(),
                                     input_per_1k_msat: input, output_per_1k_msat: output, request_msat: request, max_output, context,
                                     ceiling: xbt402::listing::price_ceiling(prices) });
        }
    }

    /// `GET /v1/models`: one entry per model, with every seller's price under `x_stream`, which
    /// clients that do not know it leave alone. A model is listed both as `model` (route me) and as
    /// `seller/model` (this seller only): the same model, which each entry's `description` says, and
    /// both reach a seller the same way ([`Router::order`]).
    pub fn models_json(&self) -> Value {
        let mut ids: Vec<&str> = self.offers.iter().map(|o| o.model.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        let mut data = Vec::new();
        for id in ids {
            let sellers: Vec<Value> = self.offers.iter().filter(|o| o.model == id)
                .map(|o| json!({"seller": o.seller, "per_1k_input_msat": o.input_per_1k_msat, "per_1k_output_msat": o.output_per_1k_msat,
                                "request_msat": o.request_msat}))
                .collect();
            let pinned: Vec<String> = self.offers.iter().filter(|o| o.model == id).map(|o| format!("{}/{}", o.seller, o.model)).collect();
            let description = format!("{id}, from the cheapest seller you allow that offers it (another if it fails before answering). To use one seller \
                                       only, ask for {}.", pinned.join(" or "));
            data.push(json!({"id": id, "object": "model", "owned_by": "lightning-stream", "description": description, "x_stream": {"sellers": sellers}}));
        }
        for o in &self.offers {
            let description = format!("{} from {} only: the same model as {}, kept to this seller.", o.model, o.seller, o.model);
            data.push(json!({"id": format!("{}/{}", o.seller, o.model), "object": "model", "owned_by": o.seller, "description": description,
                             "x_stream": {"seller": o.seller, "model": o.model}}));
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
        // `seller/model` as listed, whole: a seller's name or a model's id may hold a `/` of its own
        let (want_seller, id) = match self.catalogue.offers.iter().find(|o| model.strip_prefix(o.seller.as_str()).and_then(|r| r.strip_prefix('/')) == Some(o.model.as_str())) {
            Some(o) => (Some(o.seller.as_str()), o.model.as_str()),
            None => (None, model),
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
    /// A seller's price for each request counts in its rank and is shown beside its token prices:
    /// a seller cheap by the token but dear by the request is not taken for the cheapest. Prices
    /// written with spaces around them are read.
    #[test]
    fn a_sellers_price_for_each_request_counts_in_its_rank_and_is_shown() {
        let mut c = super::Catalogue::default();
        let models = serde_json::json!({"data": [{"id": "llama-3.1-8b"}]});
        c.add_seller("by-request", "https://a.example/ai/", &serde_json::json!({"per_1k_output_msat": "1000", "request_msat": " 50000 "}), 1024, &models);
        c.add_seller("by-token", "https://b.example/ai/", &serde_json::json!({"per_1k_output_msat": " 2000 "}), 1024, &models);
        let a = c.offers.iter().find(|o| o.seller == "by-request").unwrap();
        let b = c.offers.iter().find(|o| o.seller == "by-token").unwrap();
        assert_eq!((a.request_msat, b.output_per_1k_msat), (50_000, 2000), "trimmed");
        assert!(a.bound_msat(100, 256) > b.bound_msat(100, 256), "the request's price counts: {} vs {}", a.bound_msat(100, 256), b.bound_msat(100, 256));
        let shown = c.models_json();
        let sellers = shown["data"][0]["x_stream"]["sellers"].as_array().unwrap();
        assert!(sellers.iter().any(|s| s["seller"] == "by-request" && s["request_msat"] == 50_000), "{shown}");
    }

    #[test]
    fn a_sellers_listed_prices_are_what_the_wallet_pays_it_at_most() {
        let mut c = super::Catalogue::default();
        c.add_seller("cheap", "https://cheap.example/ai/", &serde_json::json!({"per_1k_input_msat": "2000", "per_1k_output_msat": 5000}), 1024,
                     &serde_json::json!({"data": [{"id": "llama-3.1-8b"}]}));
        let ceiling = &c.offers[0].ceiling;
        assert_eq!((ceiling["input_per_1k_msat"].as_u64(), ceiling["output_per_1k_msat"].as_u64(), ceiling["request_msat"].as_u64()), (Some(2000), Some(5000), Some(0)));
    }

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
    fn a_seller_qualified_name_is_read_whole_where_a_model_id_holds_a_slash() {
        let mut c = Catalogue::default();
        c.add_seller("Shop: ai", "https://a.example/ai/", &json!({"per_1k_output_msat": 5000}), 1024, &json!({"data": [{"id": "org/model"}]}));
        let r = Router { catalogue: c, ..Default::default() };
        let got = |m: &str| r.order(m, 1, 1, 0).iter().map(|o| (o.seller.clone(), o.model.clone())).collect::<Vec<_>>();
        assert_eq!(got("Shop: ai/org/model"), [("Shop: ai".to_string(), "org/model".to_string())]);
        assert_eq!(got("org/model"), got("Shop: ai/org/model"), "both names route the same");
    }

    #[test]
    fn a_spending_rule_refusal_names_the_seller_the_limit_in_sats_and_where_to_raise_it() {
        let (status, v) = spending_refusal("per_counterparty_daily", Some(20_000), "Genesis");
        let m = v["error"]["message"].as_str().unwrap();
        assert_eq!(status, 402);
        assert_eq!(m, "You've reached today's limit for Genesis (20,000 sats). Raise it in Settings → Spending rules on the Lightning Stream app.");
        assert_eq!(spending_refusal("velocity", None, "Genesis").0, 429);
        for rule in SPENDING_RULES {
            let (_, v) = spending_refusal(rule, Some(1_234_567), "Genesis");
            let m = v["error"]["message"].as_str().unwrap();
            assert!(m.contains("Genesis") && m.contains("Settings → Spending rules") && v["error"]["rule"] == rule, "{rule}: {m}");
            assert!(rule == "velocity" || m.contains("1,234,567 sats"), "{rule}: {m}");
        }
        assert!(spending_refusal("daily_budget", None, "G").1["error"]["message"].as_str().unwrap().contains("(your limit)"));
        assert_eq!((thousands(0), thousands(999), thousands(1000), thousands(5_000)), ("0".into(), "999".into(), "1,000".into(), "5,000".into()));
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
