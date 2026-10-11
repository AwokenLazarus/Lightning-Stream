//! AGP-102, fourth closure audit, pay-with-work: the provider's relay pull against the relay as
//! shipped (xbt-rs 2e745f2). Written by the area auditor; no code was changed. The other tests of
//! this area are in `crates/xbt-work/tests/agp102_work.rs`.
//!
//! AGP-107 (close-out): the one test here is a `limit_` test now. AGP-106 wrote the item down
//! (WORK 4), so the test states the limit, passes while it holds and fails when someone lifts it.
//!
//! Real HTTP on 127.0.0.1:27800-27803 (the audit's port range for this area).
use std::sync::Arc;
use std::time::Duration;

use xbt402::http::UreqTransport;
use xbt_work::provider::{WorkConfig, WorkProvider};
use xbt_work::receipt::{PrimeKey, WorkReceipt};
use xbt_work::relay;
use xbt_work_relay::{serve, Config, Relay, Store};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";

fn receipt(inv: &str, seq: u64, cum: u64) -> WorkReceipt {
    WorkReceipt { seq, cum_work: cum, shares: seq, first_height: 101, last_height: 102, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) }
}

/// A provider at its shipped defaults with `invoices` invoices that each have a record (one work
/// unit receipted) and a relay with its shipped limits (10 GETs a second for one client, bursts of
/// 40: `Config::default()`, `xbt-work-relay.rs:94-95`) that holds the receipt of each. The provider
/// pulls every 3 s, as `xbt-work-provider` does (`--pull-secs`, default 3). After the first round
/// the Prime pushes a new receipt (49 more work units) for the invoice that sorts last, and the
/// provider pulls four more rounds. Returns (work credited to that invoice by the pulls, the 429s
/// of each round).
fn pull(invoices: usize, port: u16) -> (u64, Vec<usize>) {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let r = Arc::new(Relay::new(Config::default(), Store::memory(10_000, 0)));
    let run = serve(r.clone(), &format!("127.0.0.1:{port}"), Some(&format!("127.0.0.1:{}", port + 1)), 2, Duration::from_secs(3600)).unwrap();
    let cfg = WorkConfig { relay_url: Some(format!("http://{}", run.public)),
                           ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(0x1a00_f0b5, 312_500_000, 150) };
    let wp = WorkProvider::new(cfg).unwrap();
    let push = |rc: &WorkReceipt| {
        let blob = relay::seal(xbt402::json::dumps(&k.sign(rc).unwrap().to_doc()).as_bytes(), PROV, &rc.invoice, None).unwrap();
        r.store.put(&relay::lookup(PROV, &rc.invoice), &blob).unwrap();
    };
    for _ in 0..invoices {
        let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
        let rc = receipt(&inv, 1, 1);
        wp.accept(&k.sign(&rc).unwrap()).unwrap();
        push(&rc);
    }
    let last = wp.invoices().pop().unwrap();
    let t = UreqTransport::default();
    let mut limited = vec![];
    for round in 0..5 {
        if round == 1 {
            push(&receipt(&last, 2, 50));
        }
        let out = wp.refresh(&t);
        limited.push(out.iter().filter(|(_, r)| r.as_ref().is_err_and(|e| e.msg.contains("429"))).count());
        if round < 4 {
            std::thread::sleep(Duration::from_secs(3));
        }
    }
    (wp.balance(&last).map_or(0, |(credited, _)| credited), limited)
}

/// The pull asks the relay for every invoice that has a record (they are kept for ever) and for
/// the newest 64 issued, one GET each, in the same sorted order every round
/// (`provider.rs:744-755, 792-809`). The shipped relay answers one client 10 GETs a second after a
/// burst of 40, so a 3 s round is good for about 30. From the 31st invoice on (71st in the first
/// round) the pull is answered 429, every round, for the same invoices: the ones that sort last
/// are never pulled. Their work is still credited when their payer calls (AGP-097), so nothing is
/// stranded; what is lost is the pull for them (credit before the call, and their receipts in the
/// audit's bound), and the log gets a line for each 429 every round. 64 anonymous invoice requests
/// an hour are enough to keep the pull over the limit without any record.
/// The rule the audit asked for: at its shipped interval, the pull gets a receipt the shipped
/// relay holds within a few rounds. It does not for 120 invoices; control: 20 invoices.
///
/// LIMIT (AGP-107; the fourth audit's list 1 item 16, WORK 4, written down by AGP-106). The audit
/// wrote this as `the_pull_at_its_shipped_interval_gets_every_receipt_...`; its last assertion is
/// turned round. The sentence it pins (`docs/LIMITS.md`, pay with work): "The provider's relay
/// pull asks for every invoice with a record and the 64 newest every 3 seconds; the relay as
/// shipped answers one client 10 requests a second, so past about 30 invoices the same ones are
/// not pulled, and their work is credited only when their payer calls." It fails when the pull
/// reaches the invoice that sorts last (a pull that pages, or a relay limit that fits it): then
/// restore the audit's assertion (`credited == 50`) and drop the sentence.
#[test]
fn limit_past_about_30_invoices_the_pull_at_its_shipped_interval_never_reaches_the_ones_that_sort_last() {
    let (credited, limited) = pull(20, 27802);
    assert_eq!((credited, limited.iter().sum::<usize>()), (50, 0), "control: 20 invoices, the new receipt is pulled in the next round");
    let (credited, limited) = pull(120, 27800);
    eprintln!("120 invoices, five pull rounds 3 s apart against the shipped relay limits: 429s per round {limited:?}; \
               the last invoice's new receipt credited {credited} of 50 work units");
    assert!(limited.iter().all(|n| *n > 0), "every round is answered 429 for some invoices: {limited:?}");
    assert_eq!(credited, 1, "the limit is lifted: the receipt of the invoice that sorts last was pulled (429s per round {limited:?})");
}
