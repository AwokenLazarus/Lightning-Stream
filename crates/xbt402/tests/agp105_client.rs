//! AGP-105 (fix wave 6, library client and transport): what the audit's own tests
//! (`agp102_client.rs`, `xbt-signer/tests/agp102_signer_client.rs`) do not pin. A URL whose host
//! two parsers could read differently is refused by the client before anything is sent, whatever
//! the transport; the shipped transport keeps a per-request deadline; and the window a payer has
//! to come back for a funded channel, in blocks, at the shipped numbers.
use std::sync::{Arc, Mutex};

use serde_json::json;
use xbt402::client::{Client, ClientConfig, Transport, Wallet, SHIPPED_PAYER_EXPIRY_BLOCKS};
use xbt402::funding::{offer_expiry_blocks, offer_open_floor, FundingPolicy, OWNER_MAX_EXPIRY_BLOCKS};
use xbt402::provider::{HttpResponse, ProviderConfig};
use xbt402::{ChannelError, Result};

const NET: &str = "bip122:11111111111111111111111111111111";

/// An embedder's own transport: it records every URL it is given and answers 404.
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Transport for Recorder {
    fn request(&self, _method: &str, url: &str, _body: &[u8], _headers: &[(String, String)]) -> Result<HttpResponse> {
        self.0.lock().unwrap().push(url.to_string());
        Ok(HttpResponse::new(404, vec![], b"{}".to_vec()))
    }
}

struct NoWallet;

impl Wallet for NoWallet {
    fn fund(&self, _address: &str, _sats: u64) -> Result<(String, u32)> {
        Err(ChannelError::new("wallet_error", "not asked in this test"))
    }
}

/// The rule of item 1 at the client, for a transport that is not the shipped one: a refused URL
/// reaches no transport, and an accepted one reaches it as the one parser read it.
#[test]
fn the_client_gives_a_transport_only_the_url_its_own_parser_read() {
    let seen = Arc::new(Mutex::new(vec![]));
    let mut c = Client::new(ClientConfig::new(NET), Box::new(Recorder(seen.clone())), Box::new(NoWallet), Box::new(|| Ok(1_000)));
    for url in ["http://a.example\\@b.example/v1/q", "http://a.example#@b.example/v1/q", "http://a.example\t@b.example/v1/q", "http:\\\\b.example/v1/q",
                "http://%62.example/v1/q", "http://127.1/v1/q", "http://a.example@b.example@c.example/v1/q", "/v1/q"] {
        assert_eq!(c.request("GET", url, b"").map(|r| r.status).map_err(|e| e.code), Err("bad_request".into()), "{url:?}");
        assert_eq!(c.request_conditional("GET", url, b"").map(|r| r.0.status).map_err(|e| e.code), Err("bad_request".into()), "{url:?}");
    }
    assert!(seen.lock().unwrap().is_empty(), "a refused URL is not probed: {:?}", seen.lock().unwrap());
    assert_eq!(c.request("GET", "HTTP://U@B.Example:80/v1/q?x=1", b"").map(|r| r.status).map_err(|e| e.code), Ok(404));
    assert_eq!(*seen.lock().unwrap(), vec!["http://U@b.example/v1/q?x=1".to_string()]);
}

/// Item 7 in numbers, from the shipped provider's own terms: what the shipped payers ask for,
/// what the channel then gets, and how long a payer has to come back for a channel its signer
/// funded (`funding::offer_open_floor`).
#[test]
fn the_shipped_payers_have_a_week_to_come_back_for_a_funded_channel() {
    let cfg = ProviderConfig::new(NET);
    let p: &FundingPolicy = &cfg.policy;
    let extra = json!({"minExpiryBlocks": p.min_expiry_blocks, "maxExpiryBlocks": p.max_expiry_blocks, "minConf": p.min_conf, "closeMarginBlocks": cfg.close_margin});
    let window = |want: u32| {
        let blocks = offer_expiry_blocks(&extra, want as u64, OWNER_MAX_EXPIRY_BLOCKS).unwrap();
        (blocks, blocks - offer_open_floor(&extra).unwrap())
    };
    assert_eq!(SHIPPED_PAYER_EXPIRY_BLOCKS, 2_016);
    assert_eq!(window(SHIPPED_PAYER_EXPIRY_BLOCKS), (2_016, 1_007), "two weeks asked and given; 1,007 blocks to come back");
    // as it was shipped, and as `ClientConfig::new` still asks: the offer's floor, and one day
    assert_eq!(ClientConfig::new(NET).expiry_blocks, 1_008);
    assert_eq!(window(1_008), (1_153, 144));
    // after the window the coins wait for the refund at the expiry: the rest of the channel's life
    assert_eq!(offer_open_floor(&extra).unwrap(), 1_009);
}

#[cfg(all(feature = "http-client", feature = "http-server"))]
mod sockets {
    use std::io::Read;
    use std::time::{Duration, Instant};

    use xbt402::client::Transport;
    use xbt402::http::UreqTransport;

    /// Item 2's bound at the shipped transport: a server that takes the request and never answers
    /// is given up after the time asked for, not after the agent's 30 s.
    #[test]
    fn the_shipped_transport_keeps_a_requests_own_deadline() {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = vec![];
            for st in l.incoming().flatten() {
                let mut st = st;
                let _ = st.set_read_timeout(Some(Duration::from_millis(200)));
                let _ = st.read(&mut [0u8; 1024]);
                held.push(st); // kept open, never answered
            }
        });
        let t = Instant::now();
        let r = UreqTransport::default().request_within("POST", &format!("http://127.0.0.1:{port}/x402/xbt-channel/lock"), b"{}", &[], Duration::from_millis(400));
        let took = t.elapsed();
        assert_eq!(r.map(|r| r.status).map_err(|e| e.code), Err("transport_error".into()));
        assert!(took >= Duration::from_millis(400) && took < Duration::from_secs(5), "{took:?}");
    }
}
