//! Pricing by the token: an answer of an OpenAI-compatible service (llama.cpp's server, vLLM,
//! Ollama and the others that speak `/v1/chat/completions` and `/v1/completions`) priced by the
//! tokens it reads and writes, not by the request.
//!
//! The seller and the buyer meter the same way, here, on the same bytes, so that each can check
//! the other:
//!
//! * The request is prepared before it reaches the service ([`prepare`]): its output is bounded by
//!   `max_tokens` (the buyer's, or the route's cap when the buyer's is larger or missing), and a
//!   streamed request asks for the token counts at its end (`stream_options.include_usage`).
//! * Before the service is asked, the balance must cover the most the call can cost
//!   ([`TokenRule::bound`]): the request's input at one token per two bytes of the body (more
//!   tokens than any tokenizer makes of a JSON body), and `max_tokens` of output.
//! * A streamed answer (`text/event-stream`) is read event by event ([`Sse`]). Every chunk that
//!   carries text counts one token of output as it goes; the counts the service states at the end
//!   (`usage`) then settle the total ([`settle`]). A whole answer is settled from its `usage`.
//!
//! What the counts are: the service's own. Tokenizers differ from model to model, and only the
//! service knows how many tokens it read and wrote, so the buyer takes the service's `usage` on
//! trust, bounded: input at most one token per two bytes of the request, output at most the
//! request's `max_tokens`. A service that states no `usage` is charged its counted chunks for
//! output and one token per four bytes of the request for input.
use serde_json::{Map, Value};

/// The largest single event of a streamed answer that is read: an event is held whole until it
/// is paid for and sent.
pub const MAX_EVENT: usize = 1 << 20;

/// The largest whole (not streamed) answer that is read: it is held whole until it is paid for.
pub const MAX_WHOLE: usize = 8 << 20;

/// The route's cap on output tokens when the runner names none.
pub const DEFAULT_MAX_OUTPUT: u64 = 1024;

/// A route's rule for tokens. Rates are in millisatoshi per 1,000 tokens, so a price below one
/// msat a token can be stated in whole numbers. A rate of 0 does not charge that side: a seller
/// that prices only what the model writes leaves `input_per_1k_msat` at 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenRule {
    pub input_per_1k_msat: u64,
    pub output_per_1k_msat: u64,
    /// The most tokens of output one request may ask for (`max_tokens`).
    pub max_output: u64,
}

impl TokenRule {
    /// No price by the token.
    pub const NONE: Self = Self { input_per_1k_msat: 0, output_per_1k_msat: 0, max_output: 0 };

    /// Whether the route is priced by the token at all.
    pub fn active(&self) -> bool {
        self.input_per_1k_msat > 0 || self.output_per_1k_msat > 0
    }

    fn per_1k(n: u64, rate: u64) -> Option<u64> {
        u64::try_from((u128::from(n) * u128::from(rate)).div_ceil(1000)).ok()
    }

    /// What `n` tokens of input cost, rounded up over the whole count.
    pub fn input_cost(&self, n: u64) -> Option<u64> {
        Self::per_1k(n, self.input_per_1k_msat)
    }

    /// What `n` tokens of output cost, rounded up over the whole count.
    pub fn output_cost(&self, n: u64) -> Option<u64> {
        Self::per_1k(n, self.output_per_1k_msat)
    }

    /// What `more` tokens of output add once `done` have been charged.
    pub fn output_due(&self, done: u64, more: u64) -> Option<u64> {
        self.output_cost(done.checked_add(more)?)?.checked_sub(self.output_cost(done)?)
    }

    /// The most a request with a body of `body_len` bytes and `max_output` tokens of output can
    /// cost by this rule (the request's own price is not in it).
    pub fn bound(&self, body_len: u64, max_output: u64) -> Option<u64> {
        self.input_cost(input_bound(body_len))?.checked_add(self.output_cost(max_output)?)
    }

    /// What the call costs, its tokens settled (the request's own price is not in it).
    pub fn cost(&self, t: Settled) -> Option<u64> {
        self.input_cost(t.input)?.checked_add(self.output_cost(t.output)?)
    }
}

/// The most tokens of input a request body of `len` bytes is charged for: one per two bytes.
pub fn input_bound(len: u64) -> u64 {
    len.div_ceil(2)
}

/// The tokens of input charged when the service states none: one per four bytes of the body.
pub fn input_guess(len: u64) -> u64 {
    len.div_ceil(4)
}

/// A request made ready for a route priced by the token.
#[derive(Debug, Clone, PartialEq)]
pub struct Prepared {
    /// The body passed on: the buyer's, with its output bounded and, when streamed, the counts asked for.
    pub body: Vec<u8>,
    /// The `max_tokens` the service is sent.
    pub max_output: u64,
    pub stream: bool,
}

/// Bound a request's output at `cap` tokens and, when it streams, ask for the token counts at its
/// end. The body must be a JSON object (a chat or completion request).
pub fn prepare(body: &[u8], cap: u64) -> Result<Prepared, &'static str> {
    let mut v: Map<String, Value> = match serde_json::from_slice(body) {
        Ok(Value::Object(m)) => m,
        _ => return Err("a request to a route priced by the token is a JSON object"),
    };
    let asked = ["max_tokens", "max_completion_tokens"].iter().filter_map(|k| v.get(*k)).find(|x| !x.is_null());
    let max_output = match asked {
        None => cap,
        Some(x) => match x.as_u64() {
            Some(n) if n > 0 => n.min(cap),
            _ => return Err("max_tokens is a whole number above 0"),
        },
    };
    v.insert("max_tokens".into(), max_output.into());
    if v.contains_key("max_completion_tokens") {
        v.insert("max_completion_tokens".into(), max_output.into());
    }
    // llama.cpp's own name for it: never more than the bound either
    if v.get("n_predict").is_some_and(|x| x.as_i64().is_none_or(|n| n < 0 || n as u64 > max_output)) {
        v.insert("n_predict".into(), max_output.into());
    }
    let stream = match v.get("stream") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("stream is true or false"),
    };
    if stream {
        let mut so = match v.remove("stream_options") {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        };
        so.insert("include_usage".into(), true.into());
        v.insert("stream_options".into(), Value::Object(so));
    }
    let body = serde_json::to_vec(&Value::Object(v)).map_err(|_| "the request could not be written again")?;
    Ok(Prepared { body, max_output, stream })
}

/// The counts a service states (`usage`), as far as it states them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub prompt: Option<u64>,
    pub completion: Option<u64>,
}

impl Usage {
    fn read(v: &Value) -> Option<Self> {
        let u = v.get("usage").filter(|u| u.is_object())?;
        Some(Self { prompt: u.get("prompt_tokens").and_then(Value::as_u64), completion: u.get("completion_tokens").and_then(Value::as_u64) })
    }
}

/// The tokens a call is charged for, settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settled {
    pub input: u64,
    pub output: u64,
}

/// Settle a call: the service's counts where it states them, bounded by what the request allows;
/// the chunks counted, and one token per four bytes of the request, where it does not.
pub fn settle(body_len: u64, max_output: u64, counted: u64, usage: Usage) -> Settled {
    Settled {
        input: usage.prompt.map_or(input_guess(body_len), |p| p.min(input_bound(body_len))),
        output: usage.completion.unwrap_or(counted).min(max_output),
    }
}

/// How many tokens of output one chunk or answer carries as text, by the chunks that carry any: a
/// streamed chunk with text in a choice counts one token per such choice.
fn chunk_tokens(v: &Value) -> u64 {
    let carries = |x: Option<&Value>| match x {
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        _ => false,
    };
    v.get("choices").and_then(Value::as_array).into_iter().flatten()
        .filter(|c| {
            let d = c.get("delta");
            carries(d.and_then(|d| d.get("content")))
                || carries(d.and_then(|d| d.get("reasoning_content")))
                || carries(d.and_then(|d| d.get("tool_calls")))
                || carries(c.get("text"))
        })
        .count() as u64
}

/// One event of a streamed answer, whole: its bytes as they arrived, the tokens of output it
/// carries, and the counts it states, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub bytes: Vec<u8>,
    pub tokens: u64,
    pub usage: Option<Usage>,
}

/// A streamed answer (`text/event-stream`), cut into its events as the bytes arrive.
#[derive(Debug, Default)]
pub struct Sse {
    buf: Vec<u8>,
}

impl Sse {
    /// The events `data` completes, in order. `Err`: one event is larger than [`MAX_EVENT`].
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Event>, &'static str> {
        self.buf.extend_from_slice(data);
        let mut out = vec![];
        while let Some(end) = event_end(&self.buf) {
            let bytes: Vec<u8> = self.buf.drain(..end).collect();
            out.push(read_event(bytes));
        }
        if self.buf.len() > MAX_EVENT {
            return Err("an event of the answer is larger than the gateway reads");
        }
        Ok(out)
    }

    /// What is left after the last whole event, as an event (an answer that ended without the
    /// blank line after its last event).
    pub fn rest(&mut self) -> Option<Event> {
        (!self.buf.is_empty()).then(|| read_event(std::mem::take(&mut self.buf)))
    }
}

/// Where the first event in `b` ends (after its blank line), if it has ended.
fn event_end(b: &[u8]) -> Option<usize> {
    let lf = b.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let crlf = b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    match (lf, crlf) {
        (Some(a), Some(c)) => Some(a.min(c)),
        (a, c) => a.or(c),
    }
}

fn read_event(bytes: Vec<u8>) -> Event {
    let text = String::from_utf8_lossy(&bytes);
    let data: Vec<&str> = text.lines().filter_map(|l| l.strip_prefix("data:")).map(|d| d.strip_prefix(' ').unwrap_or(d)).collect();
    let joined = data.join("\n");
    let v: Option<Value> = (!joined.is_empty() && joined.trim() != "[DONE]").then(|| serde_json::from_str(&joined).ok()).flatten();
    let (tokens, usage) = match &v {
        Some(v) => (chunk_tokens(v), Usage::read(v)),
        None => (0, None),
    };
    Event { bytes, tokens, usage }
}

/// A whole answer: the tokens of output by its text (one per four characters) and its counts.
pub fn whole(body: &[u8]) -> (u64, Usage) {
    let Ok(v) = serde_json::from_slice::<Value>(body) else { return (0, Usage::default()) };
    let chars: usize = v.get("choices").and_then(Value::as_array).into_iter().flatten()
        .map(|c| {
            let s = |x: Option<&Value>| x.and_then(Value::as_str).map_or(0, |s| s.chars().count());
            s(c.get("message").and_then(|m| m.get("content"))) + s(c.get("text"))
        })
        .sum();
    ((chars as u64).div_ceil(4), Usage::read(&v).unwrap_or_default())
}

/// A rule in plain words: "10 sat per 1,000 tokens", or with input priced too, "2 sat per 1,000
/// tokens in, 10 sat per 1,000 tokens out".
pub fn price_text(input_per_1k_msat: u64, output_per_1k_msat: u64) -> String {
    let sat = |m: u64| {
        let whole = m / 1000;
        let frac = m % 1000;
        if frac == 0 {
            whole.to_string()
        } else {
            format!("{whole}.{}", format!("{frac:03}").trim_end_matches('0'))
        }
    };
    match (input_per_1k_msat, output_per_1k_msat) {
        (0, 0) => "free".into(),
        (0, o) => format!("{} sat per 1,000 tokens", sat(o)),
        (i, 0) => format!("{} sat per 1,000 tokens in", sat(i)),
        (i, o) => format!("{} sat per 1,000 tokens in, {} sat per 1,000 tokens out", sat(i), sat(o)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn costs_round_up_over_the_whole_count_and_add_up() {
        let r = TokenRule { input_per_1k_msat: 2000, output_per_1k_msat: 10_000, max_output: 512 };
        assert_eq!(r.output_cost(0), Some(0));
        assert_eq!(r.output_cost(1), Some(10));
        assert_eq!(r.output_cost(1000), Some(10_000));
        let cheap = TokenRule { output_per_1k_msat: 1, ..r };
        assert_eq!(cheap.output_cost(1), Some(1));
        assert_eq!(cheap.output_cost(1000), Some(1));
        let mut paid = 0;
        for n in 0..2500 {
            paid += cheap.output_due(n, 1).unwrap();
        }
        assert_eq!(paid, cheap.output_cost(2500).unwrap());
        assert_eq!(r.bound(100, 512), Some(r.input_cost(50).unwrap() + r.output_cost(512).unwrap()));
        assert_eq!(r.cost(Settled { input: 1000, output: 1000 }), Some(12_000));
    }

    #[test]
    fn a_request_is_bounded_and_asks_for_its_counts() {
        let p = prepare(br#"{"model":"m","messages":[],"stream":true}"#, 1024).unwrap();
        let v: Value = serde_json::from_slice(&p.body).unwrap();
        assert_eq!((p.max_output, p.stream), (1024, true));
        assert_eq!(v["max_tokens"], 1024);
        assert_eq!(v["stream_options"]["include_usage"], true);
        let p = prepare(br#"{"max_tokens":9000,"n_predict":-1,"stream_options":{"x":1},"stream":true}"#, 512).unwrap();
        let v: Value = serde_json::from_slice(&p.body).unwrap();
        assert_eq!((v["max_tokens"].as_u64(), v["n_predict"].as_u64()), (Some(512), Some(512)));
        assert_eq!(v["stream_options"], json!({"x": 1, "include_usage": true}));
        let p = prepare(br#"{"max_completion_tokens":20}"#, 512).unwrap();
        assert_eq!((p.max_output, p.stream), (20, false));
        assert!(prepare(b"[1]", 10).is_err());
        assert!(prepare(br#"{"max_tokens":-1}"#, 10).is_err());
        assert!(prepare(br#"{"stream":"yes"}"#, 10).is_err());
    }

    #[test]
    fn a_stream_is_cut_into_events_however_it_arrives() {
        let s = "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n\
                 data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n\
                 data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\r\n\r\n\
                 data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n\n\
                 data: [DONE]\n\n";
        for step in [1, 3, 17, s.len()] {
            let mut sse = Sse::default();
            let mut evs = vec![];
            for c in s.as_bytes().chunks(step) {
                evs.extend(sse.feed(c).unwrap());
            }
            assert!(sse.rest().is_none());
            assert_eq!(evs.len(), 5);
            assert_eq!(evs.iter().map(|e| e.tokens).collect::<Vec<_>>(), vec![0, 1, 1, 0, 0]);
            assert_eq!(evs[3].usage, Some(Usage { prompt: Some(7), completion: Some(2) }));
            assert_eq!(evs.iter().flat_map(|e| e.bytes.clone()).collect::<Vec<_>>(), s.as_bytes());
        }
        let mut sse = Sse::default();
        assert!(sse.feed(&vec![b'x'; MAX_EVENT + 1]).is_err());
    }

    #[test]
    fn a_call_is_settled_from_the_counts_bounded() {
        assert_eq!(settle(100, 50, 9, Usage { prompt: Some(30), completion: Some(10) }), Settled { input: 30, output: 10 });
        // more than the request can be: bounded
        assert_eq!(settle(100, 50, 9, Usage { prompt: Some(999), completion: Some(999) }), Settled { input: 50, output: 50 });
        // no counts: the chunks, and a quarter of the body
        assert_eq!(settle(100, 50, 9, Usage::default()), Settled { input: 25, output: 9 });
        let (t, u) = whole(br#"{"choices":[{"message":{"content":"12345678"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#);
        assert_eq!((t, u), (2, Usage { prompt: Some(3), completion: Some(2) }));
    }

    #[test]
    fn prices_read_plainly() {
        assert_eq!(price_text(0, 10_000), "10 sat per 1,000 tokens");
        assert_eq!(price_text(2000, 10_000), "2 sat per 1,000 tokens in, 10 sat per 1,000 tokens out");
        assert_eq!(price_text(0, 2500), "2.5 sat per 1,000 tokens");
    }
}
