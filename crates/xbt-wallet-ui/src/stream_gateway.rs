//! The Stream Gateway (DATUM-compatible) that comes with the app: the owner's settings for it, and the config the
//! Hashrate page writes for it (`run/datum/config.json`).
//!
//! The gateway is CONVOY's `datum_gateway` with the masking patch: every job it hands out is masked with a key of
//! its own, and it opens each job to the renter on `/xbt/job`, so a hashmaker can't tell which shares win. The
//! owner picks how its blocks pay:
//!
//! * **solo** (the default): every block it finds pays the owner's own XBT address;
//! * **pool-key**: it mines through Lazarus Pool, keeping the key itself and handing it to the pool with a
//!   block. Its jobs are masked only while the pool takes gateway keys; otherwise they come back `pool-null`
//!   and the renter refuses them.
//!
//! Pools that hold the key themselves (CONVOY-style ABW, mode `abw`) are **not supported yet**: the renter can't
//! check that such a pool changes its key after a block it found, so it refuses their jobs (xbt-hashlink blind.rs).
//!
//! The config holds no secret. The node's RPC credentials are in `rpc.cookie` beside it, which init writes
//! (0600, the gateway's). The API's admin password is left empty: the gateway takes it only from this file, and
//! with none, every admin page and action is off (CONVOY `datum_api.c`). What stays is `/xbt/job` and the
//! dashboard, on 127.0.0.1 only, where only the renter is (`api.xbt_job_allow` empty: loopback only).
use serde_json::{json, Value};
use std::path::Path;

use crate::config::StreamGwSetup;

/// What users see it called. Never "DATUM Gateway" as a product name: that name is not ours.
pub const NAME: &str = "Stream Gateway (DATUM-compatible)";
pub const FILE: &str = "config.json";

/// Lazarus Pool's DATUM server, as `https://pool.lazarus-xbt.xyz/api/pool` gives it.
pub const LAZARUS_HOST: &str = "datum.lazarus-xbt.xyz";
pub const LAZARUS_PORT: u16 = 28915;
pub const LAZARUS_PUBKEY: &str =
    "29120606bbbfdeb0dcb259d13ed1fba9e6ff198ff6a0152cffb7608dc1c266bd17532393738aee7edf9aa0c9ec93b835256971f186da878f77fb3ed273dff30a";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Solo,
    PoolKey,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Solo => "solo",
            Mode::PoolKey => "pool-key",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "solo" => Some(Mode::Solo),
            "pool-key" | "lazarus" => Some(Mode::PoolKey),
            _ => None,
        }
    }
}

/// The owner's choices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub mode: Mode,
    /// Where its blocks pay (solo), or the pool account's address (pool-key).
    pub payout: String,
    pub pool_host: String,
    pub pool_port: u16,
    pub pool_pubkey: String,
    /// `mining.coinbase_unique_id`: one per install, kept.
    pub unique_id: u16,
}

impl Settings {
    pub fn new(mode: Mode, payout: &str) -> Self {
        Self { mode, payout: payout.trim().to_string(), pool_host: LAZARUS_HOST.into(), pool_port: LAZARUS_PORT, pool_pubkey: LAZARUS_PUBKEY.into(),
               unique_id: fresh_unique_id() }
    }
}

fn fresh_unique_id() -> u16 {
    let b = crate::random_bytes::<2>();
    u16::from_be_bytes(b).max(1)
}

/// The bech32 prefix of a chain as the signer names it. An unknown chain is held to mainnet's.
fn hrp(chain: &str) -> &'static str {
    match chain {
        "test" | "testnet" | "testnet4" | "signet" => "tb",
        "regtest" => "bcrt",
        _ => "bc",
    }
}

/// Base58Check: the payload (version byte and hash), when the checksum holds.
fn base58check(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    let mut out: Vec<u8> = vec![];
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in out.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut full = vec![0u8; zeros];
    full.extend(out);
    if full.len() < 5 {
        return None;
    }
    let (payload, sum) = full.split_at(full.len() - 4);
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(Sha256::digest(payload));
    (h[..4] == *sum).then(|| payload.to_vec())
}

/// Check a payout address for this chain: bech32 (`bc1q…`) or bech32m (`bc1p…`) segwit, or a legacy one
/// (`1…`, `3…`; on test chains `m…`, `n…`, `2…`). The words say what is wrong, for the page.
pub fn check_address(addr: &str, chain: &str) -> Result<(), String> {
    let a = addr.trim();
    if a.is_empty() {
        return Err("Enter the XBT address its blocks pay.".into());
    }
    let h = hrp(chain);
    let lower = a.to_ascii_lowercase();
    if lower.starts_with(&format!("{h}1")) {
        return xbt_primitives::address::address_to_spk(a, Some(h))
            .map(|_| ())
            .map_err(|_| "That address doesn't check out: look for a typo.".into());
    }
    if ["bc1", "tb1", "bcrt1"].iter().any(|p| lower.starts_with(p)) {
        return Err(format!("That address is for another network: this node's addresses start with {h}1."));
    }
    let main = h == "bc";
    match base58check(a) {
        Some(p) if p.len() == 21 => {
            let ok = if main { p[0] == 0x00 || p[0] == 0x05 } else { p[0] == 0x6f || p[0] == 0xc4 };
            if ok {
                Ok(())
            } else {
                Err("That address is for another network.".into())
            }
        }
        _ => Err(format!("That isn't an XBT address. It starts with {h}1, or, for an older one, {}.", if main { "1 or 3" } else { "m, n or 2" })),
    }
}

/// A pool server's public key: 128 hex characters.
fn check_pubkey(k: &str) -> Result<(), String> {
    if k.len() == 128 && k.bytes().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("The pool's key is 128 hexadecimal characters (Lazarus Pool's is filled in for you).".into())
    }
}

/// Check the owner's settings before they are written.
pub fn check(s: &Settings, chain: &str) -> Result<(), String> {
    check_address(&s.payout, chain)?;
    if s.mode == Mode::PoolKey {
        if s.pool_host.is_empty() || !s.pool_host.bytes().all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c)) {
            return Err("The pool's address is a host name, like datum.lazarus-xbt.xyz.".into());
        }
        if s.pool_port == 0 {
            return Err("The pool's port is a number, like 28915.".into());
        }
        check_pubkey(&s.pool_pubkey)?;
    }
    Ok(())
}

/// The gateway's config for these settings, in the keys CONVOY's `datum_conf.c` reads. The `xbt` block is the
/// page's own (the gateway reads only its own keys) and holds no secret either.
pub fn config_json(s: &Settings, setup: &StreamGwSetup) -> Value {
    let run = setup.gateway_run_dir.trim_end_matches('/');
    let state = setup.gateway_state_dir.trim_end_matches('/');
    let datum = match s.mode {
        // pool_host has to be said: CONVOY's default is its own pool
        Mode::Solo => json!({"pool_host": "", "pooled_mining_only": false}),
        Mode::PoolKey => json!({
            "pool_host": s.pool_host, "pool_port": s.pool_port, "pool_pubkey": s.pool_pubkey,
            "pool_pass_workers": true, "pool_pass_full_users": false, "pooled_mining_only": true,
        }),
    };
    json!({
        "bitcoind": {
            "rpccookiefile": format!("{run}/rpc.cookie"),
            "rpcurl": setup.rpcurl.clone().unwrap_or_default(),
            "work_update_seconds": 40,
            // no blocknotify from the owner's node app: new blocks are polled for
            "notify_fallback": true,
        },
        "stratum": {"listen_addr": "127.0.0.1", "listen_port": setup.stratum_port},
        "mining": {
            "pool_address": s.payout,
            "coinbase_tag_primary": "Lightning Stream",
            "coinbase_tag_secondary": "Stream Gateway",
            "coinbase_unique_id": s.unique_id,
            // a block it found stays on the volume even if the node's submitblock fails
            "save_submitblocks_dir": format!("{state}/submitblocks"),
        },
        "api": {
            "listen_addr": "127.0.0.1", "listen_port": setup.api_port,
            // empty: no admin pages or actions at all. The gateway reads its password only from this file
            "admin_password": "",
            // loopback only: /xbt/job holds the consensus target
            "xbt_job_allow": "",
            "modify_conf": false,
        },
        "logger": {"log_to_console": true, "log_to_file": false, "log_level_console": 2},
        "datum": datum,
        "xbt": {"mode": s.mode.name(), "pool": if s.mode == Mode::PoolKey { json!("lazarus") } else { Value::Null }},
    })
}

/// The settings in a written config, if there is one.
pub fn read(dir: &Path) -> Option<Settings> {
    let v: Value = serde_json::from_slice(&std::fs::read(dir.join(FILE)).ok()?).ok()?;
    let mode = Mode::from_name(v["xbt"]["mode"].as_str()?)?;
    let mut s = Settings::new(mode, v["mining"]["pool_address"].as_str().unwrap_or(""));
    s.unique_id = v["mining"]["coinbase_unique_id"].as_u64().and_then(|n| u16::try_from(n).ok()).filter(|n| *n > 0).unwrap_or(s.unique_id);
    if mode == Mode::PoolKey {
        let d = &v["datum"];
        s.pool_host = d["pool_host"].as_str().unwrap_or(LAZARUS_HOST).to_string();
        s.pool_port = d["pool_port"].as_u64().and_then(|n| u16::try_from(n).ok()).unwrap_or(LAZARUS_PORT);
        s.pool_pubkey = d["pool_pubkey"].as_str().unwrap_or(LAZARUS_PUBKEY).to_string();
    }
    Some(s)
}

/// Write the config (0640, the folder's group: the gateway reads it by group). The gateway's supervisor sees the
/// new file and restarts it with it.
pub fn write(setup: &StreamGwSetup, s: &Settings, chain: &str) -> Result<(), String> {
    check(s, chain)?;
    if setup.rpcurl.is_none() {
        return Err("This install has no Stream Gateway.".into());
    }
    let mut s = s.clone();
    // the same id across saves: a new one only for a first config
    if let Some(old) = read(&setup.dir) {
        s.unique_id = old.unique_id;
    }
    let text = serde_json::to_string_pretty(&config_json(&s, setup)).unwrap_or_default() + "\n";
    crate::setup::write_shared(&setup.dir, FILE, text.as_bytes()).map_err(|e| format!("The settings could not be saved: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(dir: &Path) -> StreamGwSetup {
        StreamGwSetup { rpcurl: Some("http://xbt-knots_bitcoind_1:8332".into()), dir: dir.to_path_buf(), ..StreamGwSetup::default() }
    }

    const P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const P2TR: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    // the genesis coinbase's address, and a P2SH one
    const P2PKH: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const P2SH: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    #[test]
    fn mainnet_takes_bc1q_bc1p_and_legacy_and_refuses_the_rest() {
        for a in [P2WPKH, P2TR, P2PKH, P2SH, &P2WPKH.to_ascii_uppercase()] {
            assert_eq!(check_address(a, "main"), Ok(()), "{a}");
            assert_eq!(check_address(a, ""), Ok(()), "an unknown chain is held to mainnet's: {a}");
        }
        let typo = P2WPKH.replace("v8f3t4", "v8f3t5");
        let bad = |a: &str, chain: &str| check_address(a, chain).unwrap_err();
        assert!(bad(&typo, "main").contains("typo"));
        assert!(bad("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "main").contains("isn't an XBT address"));
        assert!(bad("", "main").contains("Enter"));
        assert!(bad("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "main").contains("another network"));
        assert!(bad("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "main").contains("another network"));
        assert!(bad("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", "main").contains("another network"), "a testnet legacy address");
        assert!(bad("lnbc1xyz", "main").contains("isn't an XBT address"));
        assert!(bad("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "main").contains("typo"), "v0 with a bech32m checksum");
    }

    #[test]
    fn regtest_and_testnets_take_their_own() {
        assert_eq!(check_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "regtest"), Ok(()));
        assert_eq!(check_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet4"), Ok(()));
        assert_eq!(check_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", "regtest"), Ok(()));
        assert!(check_address(P2WPKH, "regtest").is_err());
        assert!(check_address(P2PKH, "regtest").is_err());
    }

    #[test]
    fn solo_writes_its_own_key_and_no_pool() {
        let t = tempfile::tempdir().unwrap();
        let s = Settings::new(Mode::Solo, P2TR);
        let c = config_json(&s, &setup(t.path()));
        assert_eq!(c["datum"], json!({"pool_host": "", "pooled_mining_only": false}), "CONVOY's default pool is never left in");
        assert_eq!(c["mining"]["pool_address"], P2TR);
        assert_eq!(c["mining"]["save_submitblocks_dir"], "/data/datum/submitblocks");
        assert_eq!(c["bitcoind"], json!({"rpccookiefile": "/data/run/datum/rpc.cookie", "rpcurl": "http://xbt-knots_bitcoind_1:8332",
                                         "work_update_seconds": 40, "notify_fallback": true}));
        assert_eq!(c["stratum"], json!({"listen_addr": "127.0.0.1", "listen_port": 23339}));
        assert_eq!(c["api"], json!({"listen_addr": "127.0.0.1", "listen_port": 7152, "admin_password": "", "xbt_job_allow": "", "modify_conf": false}));
        assert_eq!(c["xbt"], json!({"mode": "solo", "pool": null}));
        assert!(!c.to_string().to_ascii_lowercase().contains("datum gateway"), "never the product name");
    }

    #[test]
    fn pool_key_names_lazarus_and_its_key() {
        let t = tempfile::tempdir().unwrap();
        let mut st = setup(t.path());
        st.api_port = 7153;
        let c = config_json(&Settings::new(Mode::PoolKey, P2WPKH), &st);
        assert_eq!(c["datum"], json!({"pool_host": "datum.lazarus-xbt.xyz", "pool_port": 28915, "pool_pubkey": LAZARUS_PUBKEY,
                                      "pool_pass_workers": true, "pool_pass_full_users": false, "pooled_mining_only": true}));
        assert_eq!(c["mining"]["pool_address"], P2WPKH);
        assert_eq!(c["api"]["listen_port"], 7153, "Linux's port");
        assert_eq!(c["api"]["listen_addr"], "127.0.0.1");
        assert_eq!(c["xbt"], json!({"mode": "pool-key", "pool": "lazarus"}));
    }

    /// No password, cookie or other secret is ever in the file: the node's credentials are only named, by file.
    #[test]
    fn no_secret_in_the_config() {
        let t = tempfile::tempdir().unwrap();
        for mode in [Mode::Solo, Mode::PoolKey] {
            let c = config_json(&Settings::new(mode, P2WPKH), &setup(t.path()));
            assert!(c["bitcoind"].get("rpcuser").is_none() && c["bitcoind"].get("rpcpassword").is_none());
            assert_eq!(c["api"]["admin_password"], "");
            assert!(c["extra_block_submissions"].is_null(), "those URLs carry user:pass");
            assert!(!c["bitcoind"]["rpcurl"].as_str().unwrap().contains('@'), "no credentials in the node's URL");
            // every string in it is a path, an address, a host, a public key or a word
            fn strings(v: &Value, out: &mut Vec<String>) {
                match v {
                    Value::String(s) => out.push(s.clone()),
                    Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
                    Value::Object(o) => o.values().for_each(|x| strings(x, out)),
                    _ => {}
                }
            }
            let mut all = vec![];
            strings(&c, &mut all);
            for s in all {
                assert!(s.is_empty() || s.starts_with('/') || s.starts_with("http://") || s == P2WPKH || s == LAZARUS_PUBKEY || s == LAZARUS_HOST
                            || ["127.0.0.1", "Lightning Stream", "Stream Gateway", "solo", "pool-key", "lazarus"].contains(&s.as_str()), "{s}");
            }
        }
    }

    #[test]
    fn written_settings_read_back_and_keep_their_id() {
        let t = tempfile::tempdir().unwrap();
        let st = setup(t.path());
        assert!(read(t.path()).is_none());
        write(&st, &Settings::new(Mode::Solo, P2PKH), "main").unwrap();
        let first = read(t.path()).unwrap();
        assert_eq!((first.mode, first.payout.as_str()), (Mode::Solo, P2PKH));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(t.path().join(FILE)).unwrap().mode() & 0o777, 0o640);
        }
        let mut lz = Settings::new(Mode::PoolKey, P2WPKH);
        lz.pool_port = 28916;
        write(&st, &lz, "main").unwrap();
        let back = read(t.path()).unwrap();
        assert_eq!((back.mode, back.payout.as_str(), back.pool_port, back.unique_id), (Mode::PoolKey, P2WPKH, 28916, first.unique_id));
        // refused: nothing is written
        assert!(write(&st, &Settings::new(Mode::Solo, "bc1qnotanaddress"), "main").is_err());
        assert_eq!(read(t.path()).unwrap().payout, P2WPKH);
        let mut bad = Settings::new(Mode::PoolKey, P2WPKH);
        bad.pool_pubkey = "abc".into();
        assert!(write(&st, &bad, "main").unwrap_err().contains("128"));
        // no bundled gateway: nothing to write
        let none = StreamGwSetup { rpcurl: None, ..st.clone() };
        assert!(write(&none, &Settings::new(Mode::Solo, P2PKH), "main").is_err());
    }
}
