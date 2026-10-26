//! Token counting against a real OpenAI-compatible server, when one is named: set
//! `TOKENS_LIVE_URL` (for example `http://127.0.0.1:8080`, a llama.cpp server) and run with
//! `--ignored`. One small streamed request and one whole one; the chunks counted here must agree
//! with the server's own counts.
use std::io::Read;

#[test]
#[ignore = "needs TOKENS_LIVE_URL, a running OpenAI-compatible server"]
fn counts_agree_with_a_real_server() {
    let base = std::env::var("TOKENS_LIVE_URL").expect("TOKENS_LIVE_URL");
    let url = format!("{}/v1/chat/completions", base.trim_end_matches('/'));
    let ask = br#"{"messages":[{"role":"user","content":"Count from one to twenty in words."}],"stream":true}"#;
    let p = xbt402::tokens::prepare(ask, 64).unwrap();
    let mut body = ureq::post(&url).set("Content-Type", "application/json").send_bytes(&p.body).unwrap().into_reader();
    let mut sse = xbt402::tokens::Sse::default();
    let (mut counted, mut usage, mut buf) = (0u64, None, vec![0u8; 4096]);
    loop {
        let n = body.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        for ev in sse.feed(&buf[..n]).unwrap() {
            counted += ev.tokens;
            usage = ev.usage.or(usage);
        }
    }
    let usage = usage.expect("the server stated its counts at the end");
    println!("streamed: {counted} chunks with text, usage {usage:?}");
    let said = usage.completion.unwrap();
    assert!(said <= 64 && counted <= said && said - counted <= 2, "chunks {counted}, server {said}");
    let whole = ureq::post(&url).set("Content-Type", "application/json")
        .send_bytes(&xbt402::tokens::prepare(br#"{"messages":[{"role":"user","content":"Say hi."}],"max_tokens":16}"#, 64).unwrap().body).unwrap();
    let mut b = vec![];
    whole.into_reader().read_to_end(&mut b).unwrap();
    let (guess, u) = xbt402::tokens::whole(&b);
    println!("whole: guess {guess}, usage {u:?}");
    assert!(u.completion.is_some_and(|c| c <= 16));
}
