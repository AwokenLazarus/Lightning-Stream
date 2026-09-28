//! A Rust payer whose keys live in the signer (AGP-027 interop): xbt402's `Client` with a
//! `RemoteSigner` over the B2 socket. Pays `--calls` requests to `--url`, optionally closes, and
//! prints a JSON report.
//!   xbt-signer-payer --sock SOCK --url URL --network NET [--calls 10] [--capacity 10000]
//!                    [--max-price 1000] [--expiry-blocks 1008] [--close]
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig};
use xbt402::http::UreqTransport;
use xbt402::signer::StateSigner;
use xbt_signer::client::RemoteSigner;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn num(args: &[String], name: &str, d: u64) -> u64 {
    arg(args, name).and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sock = PathBuf::from(arg(&args, "--sock").expect("--sock"));
    let url = arg(&args, "--url").expect("--url");
    let mut cfg = ClientConfig::new(&arg(&args, "--network").expect("--network"));
    cfg.capacity = num(&args, "--capacity", 10_000);
    cfg.max_price = num(&args, "--max-price", 1_000);
    cfg.expiry_blocks = num(&args, "--expiry-blocks", 1_008) as u32;
    cfg.budget_sats = num(&args, "--budget", 1_000_000);
    let remote = RemoteSigner::new(&sock);
    let h = remote.clone();
    let height: xbt402::client::HeightFn = Box::new(move || {
        let v = h.client.call("channels", json!({}))?;
        Ok(v.get("height").and_then(Value::as_u64).unwrap_or(0) as u32)
    });
    let signer: Arc<dyn StateSigner> = Arc::new(remote.clone());
    let mut client = Client::new(cfg, Box::new(UreqTransport::default()), Box::new(remote.clone()), height).with_signer(signer);
    let (origin, _) = split_url(&url);
    let mut calls = vec![];
    let mut report = json!({"ok": false});
    for i in 0..num(&args, "--calls", 1) {
        match client.request("GET", &url, b"") {
            Ok(r) => {
                let ch = &client.channels[&origin];
                let rc = ch.receipts.last().cloned().unwrap_or(Value::Null);
                calls.push(json!({"i": i, "status": r.status, "cum": ch.payer.signed, "receipt": rc}));
            }
            Err(e) => {
                report["error"] = json!({"code": e.code, "msg": e.msg, "at_call": i});
                break;
            }
        }
    }
    if let Some(ch) = client.channels.get(&origin) {
        report["chan"] = ch.payer.params.channel_id().into();
        report["funding_txid"] = ch.payer.params.funding_txid().into();
        report["capacity"] = ch.payer.params.capacity.into();
        report["payer_spk"] = hex::encode(&ch.payer.params.payer_spk).into();
        report["payee_spk"] = hex::encode(&ch.payer.params.payee_spk).into();
        report["signed"] = ch.payer.signed.into();
        report["spent_msat"] = ch.spent_msat.into();
        report["client_holds_secret"] = ch.payer.secret().is_some().into();
        report["refund_hex_len"] = ch.refund_hex.len().into();
    }
    report["calls"] = calls.into();
    if report.get("error").is_none() && args.iter().any(|a| a == "--close") {
        match client.close(&origin) {
            Ok(r) => {
                let txid = r.get("txid").and_then(Value::as_str).unwrap_or("").to_string();
                let chan = report["chan"].as_str().unwrap_or("").to_string();
                report["close"] = r;
                report["mark_closed"] = remote.mark_closed(&chan, &txid).unwrap_or_else(|e| json!({"error": e.msg}));
            }
            Err(e) => report["error"] = json!({"code": e.code, "msg": e.msg, "at": "close"}),
        }
    }
    report["ok"] = report.get("error").is_none().into();
    println!("{report}");
    std::process::exit(if report["ok"] == true { 0 } else { 1 });
}
