//! xbt-gateway: the stream-ticket seller gateway. One program beside a Lightning node of the lnd
//! family (it speaks lnd's REST interface; a Core Lightning seller is not supported): point it at
//! an HTTP service, set a price per route, and buyers pay piece by piece with stream tickets
//! (`docs/TICKETS.md`).
//!
//!     xbt-gateway <config.json>           run
//!     xbt-gateway --check <config.json>   read the config and the macaroons, say what the caps cost, and exit
//!
//! SIGTERM or SIGINT stops a run: no new connection, the requests in flight get 5 s, then what the
//! book has counted since the last tick goes into the journal, the journal is fsynced and closed,
//! and the gateway exits 0. A request still running after that is cut where a kill would cut it.
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use xbt_gateway::config::Config;
use xbt_gateway::gateway::{unix_now, Gateway};
use xbt_gateway::node::{
    checked_macaroon, LndRest, Node, NodeError, CHANNEL_OPS, INFO_OPS, INVOICE_OPS, NOT_LND,
};

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
        "xbt-gateway: chain {}, {} routes, tickets of {} msat living {} blocks, used while more than {} are left (the node cancels a held one {} before expiry: node.hold_expiry_delta); at most {} sessions ({} per address) of {} tickets",
        cfg.chain,
        cfg.routes.len(),
        cfg.caps.ticket_msat,
        cfg.ticket_blocks,
        cfg.caps.margin_blocks,
        cfg.node.hold_expiry_delta,
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
    if cfg.offers.is_some() {
        eprintln!("xbt-gateway: payment by BOLT 12 offer: one offer of the node, made at the start with no amount, pays prepaid tickets and lottery wins; a payment is credited to the session its payer note names, once. The node's offersrpc is used with node.macaroon ({}); held tickets stay hold invoices", xbt_gateway::node::OFFER_OPS.join(" "));
    }
    eprintln!("xbt-gateway: the node at {} is spoken to over lnd's REST interface: it must be an lnd-family node (Lightning Fork, or lnd). A Core Lightning seller is not supported", cfg.node.rest);
    if check {
        return Ok(());
    }
    // SIGTERM and SIGINT before the first thread (the node client and the gateway start some):
    // a stop is answered at once, also as PID 1 (xbt_svc::shutdown)
    let signals = xbt_svc::shutdown::listen().map_err(|e| format!("signals: {e}"))?;
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
    loop {
        match node.info() {
            Ok(_) => break,
            // another implementation's node: nothing the gateway asks of it would work, and waiting does not help
            Err(NodeError::Refused(m)) if m.starts_with(NOT_LND) => {
                return Err(format!("node.rest {}: {m}", cfg.node.rest))
            }
            Err(e) => {
                if waited.is_multiple_of(15) {
                    eprintln!("xbt-gateway: waiting for the node: {e}");
                }
                waited += 1;
                // nothing is open yet: a stop while waiting is just an exit
                if let Some(sig) = signals.wait_timeout(Duration::from_secs(2)) {
                    eprintln!("xbt-gateway: {} received while waiting for the node: stopped", xbt_svc::shutdown::name(sig));
                    return Ok(());
                }
            }
        }
    }
    let nostr = cfg.nostr.clone().filter(|n| n.publish);
    let nostr_key = match &nostr {
        Some(_) => Some(xbt_gateway::nostr::load_key(&cfg.state_dir)?),
        None => None,
    };
    let gw = Gateway::start(cfg, node, key, Box::new(unix_now)).map_err(|e| e.to_string())?;
    if let (Some(n), Some(k)) = (nostr, nostr_key) {
        eprintln!("xbt-gateway: publishing the listing on Nostr to {} relays every {} s, as Nostr key {}", n.relays.len(), n.republish.as_secs(), k.public_hex());
        xbt_gateway::nostr::spawn(gw.clone(), k, n).map_err(|e| format!("nostr: {e}"))?;
    }
    let running = gw.serve(listener).map_err(|e| e.to_string())?;
    eprintln!(
        "xbt-gateway: listening on {}; an lnd-family node, {}; receipts signed by {}",
        running.addr,
        gw.terms().pay_to,
        gw.terms().receipt_key
    );
    let sig = signals.wait();
    xbt_svc::shutdown::say_stopping("xbt-gateway", sig);
    // the listener first, so that nothing new starts; then the requests in flight; then the book.
    // Gateway::stop journals the counters the book marked since the last tick, fsyncs the journal
    // and closes it: a request still running after the bound then writes no record (a lock that
    // cannot journal is refused, as on a full disk), and a ticket it settled is credited at the
    // next start from the node's word, as every ticket the gateway does not finish is
    let drained = running.stopper().drain(xbt_svc::shutdown::DRAIN);
    gw.stop();
    xbt_svc::shutdown::say_stopped("xbt-gateway", drained);
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
