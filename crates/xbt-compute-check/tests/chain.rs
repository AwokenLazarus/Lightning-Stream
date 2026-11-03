//! A chain's links on one machine, over real iroh links with no relay: a TCP service behind one
//! machine's link answers another machine's loopback port, a key outside the chain is refused, and
//! a stream waits for a chain port that is still starting.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use xbt_compute_check::chain::{self, Card, Counters, Machines, ALPN_CHAIN};
use xbt_compute_check::probe::Peer;
use xbt_iroh_link::{Link, Options, Relays};

fn link() -> Arc<Link> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).unwrap();
    Link::start_alpn(secret, Options { relays: Relays::None, serving: true, private: false, lookup: None }, ALPN_CHAIN).unwrap()
}

fn card(link: &Link, serves: bool) -> Card {
    Card { peer: Peer { id: link.endpoint_id(), relays: Vec::new(), direct: link.hints(Duration::from_secs(2)).direct }, serves }
}

/// Echoes every connection it accepts, on a port chosen now; starts listening after `delay`.
fn echo_later(delay: Duration) -> SocketAddr {
    let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        let listener = TcpListener::bind(addr).unwrap();
        for mut s in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn round_trip(port: SocketAddr, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(port)?;
    s.set_read_timeout(Some(Duration::from_secs(20)))?;
    s.write_all(msg)?;
    let mut got = vec![0u8; msg.len()];
    s.read_exact(&mut got)?;
    Ok(got)
}

#[test]
fn a_chain_port_answers_over_iroh_and_only_to_the_chain() {
    // the shard's port starts listening a second after its link: a stream waits for it
    let upstream = echo_later(Duration::from_secs(1));
    let (shard, user, outsider) = (link(), link(), link());
    let allowed = Arc::new(RwLock::new(HashSet::new()));
    let counters = Arc::new(Counters::default());
    chain::serve(&shard, upstream, allowed.clone(), Duration::from_secs(30), counters.clone());

    let mut machines = Machines { machines: BTreeMap::new() };
    machines.machines.insert("shard0".into(), card(&shard, true));
    machines.machines.insert("client0".into(), card(&user, false));
    allowed.write().unwrap().extend(machines.machines.values().map(|c| c.peer.id.clone()));

    let only_relay: HashSet<String> = ["relay".to_string()].into();
    assert!(chain::forward_all(&user, &user.endpoint_id(), &machines, Some(&only_relay)).unwrap().is_empty(), "no relay here, so no port");
    let ports = chain::forward_all(&user, &user.endpoint_id(), &machines, None).unwrap();
    assert_eq!(ports.keys().collect::<Vec<_>>(), vec!["shard0"], "a user's machine serves nothing, so only the shard gets a port");
    let msg: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(round_trip(ports["shard0"], &msg).unwrap(), msg);
    assert_eq!(round_trip(ports["shard0"], b"second connection").unwrap(), b"second connection");
    assert_eq!(counters.streams_in.load(Ordering::Relaxed), 2);

    let r = chain::report(&user, None, &Counters::default(), &machines, &ports);
    assert_eq!(r.peers["shard0"].path.as_deref(), Some("direct"));

    // a key outside the chain reaches the link but not the port
    let stranger = chain::forward_all(&outsider, &outsider.endpoint_id(), &machines, None).unwrap();
    assert!(round_trip(stranger["shard0"], b"let me in").is_err());
    assert_eq!(counters.refused.load(Ordering::Relaxed), 1);
    assert_eq!(counters.streams_in.load(Ordering::Relaxed), 2);
}
