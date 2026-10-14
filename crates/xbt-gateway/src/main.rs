//! xbt-gateway: the stream-ticket seller gateway. One program beside a Lightning node: point it at
//! an HTTP service, set a price per route, and buyers pay piece by piece with stream tickets
//! (`docs/TICKETS.md`).
//!
//!     xbt-gateway <config.json>           run
//!     xbt-gateway --check <config.json>   read the config and the macaroons, say what the caps cost, and exit
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use xbt_gateway::config::Config;
use xbt_gateway::gateway::{unix_now, Gateway};
use xbt_gateway::node::{checked_macaroon, LndRest, Node, CHANNEL_OPS, INFO_OPS, INVOICE_OPS};

fn run(args: &[String]) -> Result<(), String> {
    let (check, path) = match args {
        [flag, path] if flag == "--check" => (true, path),
        [path] if !path.starts_with('-') => (false, path),
        _ => return Err("usage: xbt-gateway [--check] <config.json>".into()),
    };
    let cfg = Config::load(std::path::Path::new(path)).map_err(|e| e.to_string())?;
    // mainnet is asked for twice in the file (`chain` and `mainnet_ack`); a runner who did is told,
    // at every start and every check, what is known to be open there
    for line in cfg.mainnet_notice() {
        eprintln!("xbt-gateway: {line}");
    }
    let read = |p: &std::path::Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let (invoice, info) = (read(&cfg.node.macaroon)?, read(&cfg.node.info_macaroon)?);
    // each macaroon holds its own permissions and, on mainnet, nothing else: a gateway that is
    // broken into can make, settle and cancel invoices and read the node's public state, no more
    // the third is the runner's choice: with it the gateway reads its node's channels and sizes the
    // cap on held tickets itself. It is not asked for by default, because the permission also
    // shows the node's balances, its payments and what it forwarded
    let channels = cfg
        .node
        .channels_macaroon
        .as_deref()
        .map(read)
        .transpose()?;
    let mut checked = vec![
        checked_macaroon(&invoice, "node.macaroon", &INVOICE_OPS, cfg.mainnet()),
        checked_macaroon(&info, "node.info_macaroon", &INFO_OPS, cfg.mainnet()),
    ];
    if let Some(c) = &channels {
        checked.push(checked_macaroon(
            c,
            "node.channels_macaroon",
            &CHANNEL_OPS,
            cfg.mainnet(),
        ));
    }
    for warning in checked {
        if let Some(w) = warning.map_err(|e| e.to_string())? {
            eprintln!("xbt-gateway: warning: {w} (refused on mainnet)");
        }
    }
    let held_sat = u64::from(cfg.caps.max_held).saturating_mul(cfg.caps.ticket_msat) / 1000;
    eprintln!(
        "xbt-gateway: chain {}, {} routes, tickets of {} msat living {} blocks; at most {} sessions ({} per address) of {} tickets",
        cfg.chain,
        cfg.routes.len(),
        cfg.caps.ticket_msat,
        cfg.ticket_blocks,
        cfg.caps.max_sessions,
        cfg.caps.sessions_per_address,
        cfg.caps.max_tickets,
    );
    if cfg.held {
        eprintln!(
            "xbt-gateway: held tickets: buyers can hold up to {} at once, all together ({} sat of this node's inbound capacity, at no cost to them until they are used or cancelled). Each takes one pending payment of the channel it arrives on, and an inbound channel is taken to carry {} of them{}; a buyer beyond the cap is told to wait{}",
            cfg.caps.max_held,
            held_sat,
            cfg.inbound_slots,
            if channels.is_some() { " until the node's own channel list is read" } else { " (caps.inbound_slots)" },
            if cfg.prepaid { " or to buy prepaid tickets" } else { "" }
        );
    }
    if cfg.prepaid {
        eprintln!("xbt-gateway: prepaid tickets: paid in full when they arrive, one at a time, with nothing held on any channel");
    }
    if check {
        return Ok(());
    }
    let node = LndRest::new(
        &cfg.node.rest,
        &invoice,
        &info,
        cfg.node.tls_cert.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    let node = Arc::new(match &channels {
        Some(c) => node.with_channels_macaroon(c),
        None => node,
    });
    let key = xbt402::provider::load_or_create_secret(&cfg.state_dir.join("receipt.key"))
        .map_err(|e| e.to_string())?;
    // the port before anything else: a second gateway, or a port in use, stops here
    let listener =
        TcpListener::bind(&cfg.listen).map_err(|e| format!("listen {}: {e}", cfg.listen))?;
    let mut waited = 0u32;
    while let Err(e) = node.info() {
        if waited.is_multiple_of(15) {
            eprintln!("xbt-gateway: waiting for the node: {e}");
        }
        waited += 1;
        std::thread::sleep(Duration::from_secs(2));
    }
    let gw = Gateway::start(cfg, node, key, Box::new(unix_now)).map_err(|e| e.to_string())?;
    let running = gw.serve(listener).map_err(|e| e.to_string())?;
    eprintln!(
        "xbt-gateway: listening on {}; node {}; receipts signed by {}",
        running.addr,
        gw.terms().pay_to,
        gw.terms().receipt_key
    );
    for t in running.threads {
        // the accept thread ends only when the process is told to stop
        let _ = t.join();
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xbt-gateway: {e}");
            ExitCode::FAILURE
        }
    }
}
