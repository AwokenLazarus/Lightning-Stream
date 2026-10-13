//! Offline self-test for the build matrix (scripts/build_matrix.sh): on the target itself, no
//! network, no node, no files. It checks the pinned lottery vectors (embedded here) with this
//! crate, plays a session of draws between a seller and a buyer, and signs and checks a ticket
//! receipt over a request digest. Built for every target to prove the crates link and compute the
//! same there:
//! `cargo build --release --target aarch64-unknown-linux-gnu -p xbt402 --example selftest`.
use serde_json::{json, Value};
use xbt402::lottery::{draw_digest, wins, Buyer, Chain, Kind, Odds, Piece, PieceId, Seller};
use xbt402::ticket::{self, hex32, ticket_hash};
use xbt402::wire::{body_hash, request_digest_v2};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;

const PINNED: &str = include_str!("../../../vectors/lottery_vectors.json");

/// Every check of the pinned vectors that fails, by name.
fn vectors(v: &Value) -> (usize, Vec<String>) {
    let (mut n, mut bad) = (0, vec![]);
    let mut check = |name: String, ok: bool| {
        n += 1;
        if !ok {
            bad.push(name);
        }
    };
    let h32 = |x: &Value| x.as_str().and_then(hex32).unwrap_or([0; 32]);
    let num = |x: &Value| x.as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    for (i, c) in v["chains"].as_array().into_iter().flatten().enumerate() {
        let Ok(mut chain) = Chain::new(h32(&c["seed"]), c["len"].as_u64().unwrap_or(0) as u32) else {
            check(format!("chain {i}"), false);
            continue;
        };
        check(format!("chain {i} anchor"), Some(hex::encode(chain.anchor()).as_str()) == c["anchor"].as_str());
        for (at, want) in c["values"].as_object().into_iter().flatten() {
            let got = at.parse().ok().and_then(|k| chain.value(k)).map(hex::encode);
            check(format!("chain {i} value {at}"), got.as_deref() == want.as_str());
        }
    }
    for t in v["thresholds"].as_array().into_iter().flatten() {
        let got = Odds::new(num(&t["amountMsat"]), num(&t["winMsat"])).map(|o| o.threshold().to_string()).ok();
        check(format!("threshold {}/{}", t["amountMsat"], t["winMsat"]), got.as_deref() == t["threshold"].as_str());
    }
    for (i, d) in v["draws"].as_array().into_iter().flatten().enumerate() {
        let Some(kind) = d["kind"].as_str().and_then(Kind::parse) else {
            check(format!("draw {i} kind"), false);
            continue;
        };
        let p = Piece { id: PieceId { seq: d["seq"].as_u64().unwrap_or(0), kind, k: d["k"].as_u64().unwrap_or(0) }, req: h32(&d["req"]),
                        amount_msat: num(&d["amountMsat"]) };
        let win = num(&d["winMsat"]);
        check(format!("draw {i} piece"), Some(hex::encode(p.digest(win)).as_str()) == d["piece"].as_str());
        let dg = draw_digest(d["session"].as_str().unwrap_or(""), d["draw"].as_u64().unwrap_or(0), &h32(&d["chainValue"]), &h32(&d["value"]), &p.digest(win));
        check(format!("draw {i} digest"), Some(hex::encode(dg).as_str()) == d["d"].as_str());
        check(format!("draw {i} outcome"), Odds::new(p.amount_msat, win).map(|o| wins(&dg, o)).ok() == d["win"].as_bool());
    }
    let a = &v["auth"];
    check("request auth".into(), Some(xbt402::lottery::request_auth(&h32(&a["key"]), a["session"].as_str().unwrap_or(""), a["seq"].as_u64().unwrap_or(0),
                                                                    a["req"].as_str().unwrap_or("")).as_str()) == a["auth"].as_str());
    check("receipt message".into(), Some(hex::encode(xbt402::lottery::receipt_message(&v["receipt"]["fields"])).as_str()) == v["receipt"]["message"].as_str());
    (n, bad)
}

/// A session of 200 draws at odds of 1 in 10: what the buyer verifies is what the seller took,
/// draw for draw. Returns the wins, or why the two disagree.
fn session() -> Result<u64, String> {
    const WIN: u64 = 1_000_000;
    let chain = Chain::new(sha256(b"selftest chain"), 200).map_err(|e| e.code().to_string())?;
    let mut seller = Seller::new("s1", WIN, chain).map_err(|e| e.code().to_string())?;
    let mut buyer = Buyer::new("s1", WIN, seller.anchor(), 200).map_err(|e| e.code().to_string())?;
    let (mut seller_wins, mut buyer_wins) = (0, 0);
    for seq in 0..200u64 {
        let piece = Piece { id: PieceId { seq, kind: Kind::parse("request").ok_or("kind")?, k: 0 }, req: sha256(&seq.to_le_bytes()), amount_msat: WIN / 10 };
        let value = sha256(&[b"buyer value".as_slice(), &seq.to_le_bytes()].concat());
        seller.serve(piece.clone()).map_err(|e| e.code().to_string())?;
        let draw = buyer.issue(piece.clone(), value, 0).map_err(|e| e.code().to_string())?;
        let taken = seller.take(draw, piece.id, piece.amount_msat, &value).map_err(|e| e.code().to_string())?;
        seller_wins += u64::from(taken.won);
        let (drawn, reveal) = seller.reveal().ok_or("nothing to reveal")?;
        buyer_wins += buyer.absorb(drawn, &reveal).map_err(|e| e.code().to_string())?.iter().filter(|o| o.win.is_some()).count() as u64;
    }
    if seller_wins != buyer_wins || buyer.verified() != 200 {
        return Err(format!("the seller counts {seller_wins} wins, the buyer {buyer_wins} over {} verified draws", buyer.verified()));
    }
    Ok(buyer_wins)
}

/// A ticket receipt signed by a seller's key and checked under its public key, bound to a request.
fn receipt() -> bool {
    let sk = ecdsa::secret_key(&sha256(b"selftest receipt key")).expect("a valid key");
    let secret = sha256(b"a ticket's secret");
    let req = request_digest_v2("GET", "https://seller.example/v1/q?a=1", b"");
    let r = json!({"scheme": ticket::SCHEME, "session": hex::encode(&ticket_hash(&secret)[..16]), "seq": 3, "releasedMsat": "1000000", "spentMsat": "2500",
                   "charged": "2500", "req": req, "status": 200, "bodyHash": body_hash(b"the answer")});
    let sig = ecdsa::sign(&sk, &ticket::receipt_message(&r));
    let mut other = r.clone();
    other["charged"] = "2501".into();
    ecdsa::verify(&ecdsa::pubkey(&sk), &ticket::receipt_message(&r), &sig) && !ecdsa::verify(&ecdsa::pubkey(&sk), &ticket::receipt_message(&other), &sig)
}

fn main() {
    let (n, bad) = vectors(&serde_json::from_str(PINNED).expect("pinned vectors parse"));
    for b in &bad {
        eprintln!("FAIL vector check: {b}");
    }
    let played = session();
    let signed = receipt();
    let arch = std::env::consts::ARCH;
    match (&played, bad.is_empty() && signed) {
        (Ok(w), true) => println!("xbt402 selftest OK ({arch}): {n}/{n} lottery vector checks, 200 draws verified by both sides ({w} wins), a ticket receipt signed and checked"),
        _ => {
            println!("xbt402 selftest FAIL ({arch}): {}/{n} vector checks, session {played:?}, receipt {signed}", n - bad.len());
            std::process::exit(1);
        }
    }
}
