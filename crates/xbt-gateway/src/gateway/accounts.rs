//! A buyer's own account in a route's service (docs/BUYER-ACCOUNTS.md).
//!
//! A buyer is known to this gateway by the key it proved for a session (`identify`). On the first
//! request of a buyer the gateway has not seen on a route with `accounts`, it has the route's
//! adapter make them an account, once, and keeps what it gets in `accounts.json` (mode 600). Every
//! request of that buyer then goes to the service as that account: the client's own login is
//! replaced, so no buyer acts as another, and a path that names another user is refused.
//!
//! **Fails closed.** When the seller's key is missing, unreadable or refused, no account is made
//! and the request is refused: never sent with the seller's key, nor as anyone else.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::Accounts;

/// One buyer's account in one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub user_id: String,
    pub name: String,
    pub password: String,
    /// What the service gave the account to send with its requests.
    pub token: String,
    /// For a hook's account: the headers to send as the buyer.
    pub headers: Vec<(String, String)>,
}

/// The accounts made so far, by buyer and service, kept in the gateway's state directory.
pub struct Store {
    path: PathBuf,
    map: Mutex<HashMap<String, Account>>,
    /// One account is made at a time: a buyer's requests at once make one account.
    making: Mutex<()>,
}

/// A buyer's handle, as the seller sees it: a short hash of their key.
pub fn handle(buyer: &str) -> String {
    hex::encode(&Sha256::digest(buyer.as_bytes())[..6])
}

fn key_of(buyer: &str, service: &str) -> String {
    format!("{service} {buyer}")
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).redirects(0).build()
}

/// What Jellyfin wants to know of a client that logs in.
const CLIENT: &str = "MediaBrowser Client=\"Lightning Stream\", Device=\"Lightning Stream\", Version=\"1\"";

impl Store {
    pub fn open(dir: &Path) -> Self {
        let path = dir.join("accounts.json");
        let map = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<HashMap<String, Value>>(&t).ok()).unwrap_or_default()
            .into_iter().map(|(k, v)| {
                let s = |f: &str| v.get(f).and_then(Value::as_str).unwrap_or("").to_string();
                let headers = v.get("headers").and_then(Value::as_array).map(|h| h.iter().filter_map(|x| Some((x.get(0)?.as_str()?.to_string(), x.get(1)?.as_str()?.to_string()))).collect())
                    .unwrap_or_default();
                (k, Account { user_id: s("user_id"), name: s("name"), password: s("password"), token: s("token"), headers })
            }).collect();
        Self { path, map: Mutex::new(map), making: Mutex::new(()) }
    }

    fn save(&self, map: &HashMap<String, Account>) {
        use std::io::Write as _;
        let doc: serde_json::Map<String, Value> = map.iter().map(|(k, a)| (k.clone(), json!({"user_id": a.user_id, "name": a.name, "password": a.password,
            "token": a.token, "headers": a.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()}))).collect();
        let tmp = self.path.with_extension("json.tmp");
        let written = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode_600().open(&tmp)?;
            f.write_all(Value::Object(doc).to_string().as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        })();
        if let Err(e) = written {
            eprintln!("accounts: could not keep {}: {e}", self.path.display());
        }
    }

    pub fn get(&self, buyer: &str, service: &str) -> Option<Account> {
        self.map.lock().unwrap_or_else(|p| p.into_inner()).get(&key_of(buyer, service)).cloned()
    }

    fn put(&self, buyer: &str, service: &str, a: Account) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        m.insert(key_of(buyer, service), a);
        self.save(&m);
    }

    /// The buyer's account in the service at `base`, made the first time. `Err`: none could be made.
    pub fn account(&self, cfg: &Accounts, base: &str, buyer: &str) -> Result<Account, String> {
        if let Some(a) = self.get(buyer, base) {
            return Ok(a);
        }
        let _one = self.making.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(a) = self.get(buyer, base) {
            return Ok(a);
        }
        let a = match cfg {
            Accounts::Jellyfin { admin_key_file, libraries } => jellyfin_make(base, &read_key(admin_key_file)?, libraries, buyer)?,
            Accounts::Hook { command } => hook_make(command, buyer)?,
        };
        self.put(buyer, base, a.clone());
        Ok(a)
    }

    /// The account's login, made again (the service refused the one kept: expired or revoked).
    pub fn renew(&self, cfg: &Accounts, base: &str, buyer: &str) -> Result<Account, String> {
        let _one = self.making.lock().unwrap_or_else(|p| p.into_inner());
        let mut a = self.get(buyer, base).ok_or("no account to renew")?;
        match cfg {
            Accounts::Jellyfin { admin_key_file, libraries } => match jellyfin_login(base, &a.name, &a.password, buyer) {
                Ok(token) => a.token = token,
                // the login kept no longer works (the seller removed or changed the user): made anew,
                // still with the seller's key and still only for this buyer; if that fails too, nothing is
                // served as anyone else
                Err(_) => a = jellyfin_make(base, &read_key(admin_key_file)?, libraries, buyer)?,
            },
            Accounts::Hook { command } => a = hook_make(command, buyer)?,
        }
        self.put(buyer, base, a.clone());
        Ok(a)
    }
}

trait Mode600 {
    fn mode_600(&mut self) -> &mut Self;
}

impl Mode600 for std::fs::OpenOptions {
    fn mode_600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt as _;
        self.mode(0o600)
    }
}

/// The seller's key for the service, read for each account made: a key rotated or removed is the
/// one used from then on, or none at all.
fn read_key(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("the service's key ({}): {e}", path.display()))?;
    // a bare key, or a `NAME=key` line as an env file keeps it
    let key = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).map(|l| l.rsplit('=').next().unwrap_or(l).trim().to_string())
        .filter(|k| !k.is_empty() && k.bytes().all(|c| c.is_ascii_alphanumeric()))
        .ok_or_else(|| format!("the service's key ({}) holds no key", path.display()))?;
    Ok(key)
}

fn random_password() -> String {
    let mut b = [0u8; 24];
    getrandom::getrandom(&mut b).expect("OS randomness");
    hex::encode(b)
}

/// A JSON call to the service. `Err`: no answer, or a status that says it failed.
fn call(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&Value>) -> Result<(u16, Value), String> {
    let mut r = agent().request(method, url);
    for (k, v) in headers {
        r = r.set(k, v);
    }
    let sent = match body {
        Some(b) => r.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => r.call(),
    };
    match sent {
        Ok(resp) => {
            let status = resp.status();
            Ok((status, serde_json::from_str(&resp.into_string().unwrap_or_default()).unwrap_or(Value::Null)))
        }
        Err(ureq::Error::Status(code, _)) => Err(format!("the service answered {code}")),
        Err(e) => Err(format!("the service gave no answer: {e}")),
    }
}

/// A Jellyfin user for the buyer: a random password, hidden, no administration, the libraries for
/// sale only, nothing downloaded or deleted; and its login.
fn jellyfin_make(base: &str, key: &str, libraries: &[String], buyer: &str) -> Result<Account, String> {
    let base = base.trim_end_matches('/');
    let admin = [("X-Emby-Token", key)];
    let name = format!("buyer-{}", handle(buyer));
    let password = random_password();
    let user_id = match call("POST", &format!("{base}/Users/New"), &admin, Some(&json!({"Name": name, "Password": password}))) {
        Ok((_, v)) => v.get("Id").and_then(Value::as_str).map(str::to_string).ok_or("Jellyfin made no user")?,
        // a user of that name already (an account kept elsewhere was lost): found, and given a new password
        Err(_) => {
            let (_, users) = call("GET", &format!("{base}/Users"), &admin, None).map_err(|e| format!("Jellyfin's users: {e}"))?;
            let id = users.as_array().into_iter().flatten().find(|u| u.get("Name").and_then(Value::as_str) == Some(name.as_str()))
                .and_then(|u| u.get("Id").and_then(Value::as_str)).map(str::to_string).ok_or("Jellyfin refused to make the buyer's user")?;
            call("POST", &format!("{base}/Users/{id}/Password"), &admin, Some(&json!({"ResetPassword": true})))?;
            call("POST", &format!("{base}/Users/{id}/Password"), &admin, Some(&json!({"CurrentPw": "", "NewPw": password})))?;
            id
        }
    };
    let (_, user) = call("GET", &format!("{base}/Users/{user_id}"), &admin, None)?;
    let mut policy = user.get("Policy").cloned().filter(Value::is_object).ok_or("Jellyfin gave no policy for the buyer's user")?;
    for (k, v) in [("IsAdministrator", json!(false)), ("IsHidden", json!(true)), ("IsDisabled", json!(false)), ("EnableAllFolders", json!(false)),
                   ("EnabledFolders", json!(libraries)), ("EnableContentDeletion", json!(false)), ("EnableContentDeletionFromFolders", json!([])),
                   ("EnableContentDownloading", json!(false)), ("EnableRemoteControlOfOtherUsers", json!(false)), ("EnableSharedDeviceControl", json!(false)),
                   ("EnableLiveTvManagement", json!(false)), ("EnableLiveTvAccess", json!(false)), ("EnablePublicSharing", json!(false)),
                   ("EnableCollectionManagement", json!(false)), ("EnableSubtitleManagement", json!(false)), ("EnableLyricManagement", json!(false)),
                   ("EnableSyncTranscoding", json!(false)), ("EnableMediaConversion", json!(false)), ("EnableAllDevices", json!(true))] {
        policy[k] = v;
    }
    call("POST", &format!("{base}/Users/{user_id}/Policy"), &admin, Some(&policy))?;
    let token = jellyfin_login(base, &name, &password, buyer)?;
    Ok(Account { user_id, name, password, token, headers: vec![] })
}

/// A login for the buyer's Jellyfin user: its token.
fn jellyfin_login(base: &str, name: &str, password: &str, buyer: &str) -> Result<String, String> {
    let client = format!("{CLIENT}, DeviceId=\"ls-{}\"", handle(buyer));
    let (_, v) = call("POST", &format!("{}/Users/AuthenticateByName", base.trim_end_matches('/')), &[("Authorization", &client)],
                      Some(&json!({"Username": name, "Pw": password})))?;
    v.get("AccessToken").and_then(Value::as_str).map(str::to_string).ok_or_else(|| "Jellyfin gave the buyer's user no token".into())
}

/// A hook's account: the seller's program, given the buyer's handle, prints `{"headers": {…}}`.
fn hook_make(command: &Path, buyer: &str) -> Result<Account, String> {
    let out = std::process::Command::new(command).arg(handle(buyer)).output().map_err(|e| format!("the accounts hook: {e}"))?;
    if !out.status.success() {
        return Err(format!("the accounts hook failed ({})", out.status));
    }
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|_| "the accounts hook printed no JSON")?;
    let headers: Vec<(String, String)> = v.get("headers").and_then(Value::as_object).ok_or("the accounts hook gave no headers")?
        .iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
        .filter(|(k, v)| k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') && v.bytes().all(|c| c.is_ascii_graphic() || c == b' ')).collect();
    Ok(Account { user_id: String::new(), name: handle(buyer), password: String::new(), token: String::new(), headers })
}

/// What a buyer's request becomes, sent as their account.
pub enum AsAccount {
    /// Answered here, without the service.
    Answer(u16, Value),
    /// Sent on with this target and these headers, and this body in place of the request's
    /// (`None`: the request's own).
    Send { target: String, headers: Vec<(String, String)>, body: Option<Vec<u8>> },
}

/// Jellyfin: a buyer's request as their own user's. Their token replaces any the client sent (in
/// its headers and in `api_key`); the login page shows them their own user only, with no password;
/// any login is theirs; a path naming another user is refused.
pub fn jellyfin_request(a: &Account, method: &str, target: &str, headers: &[(String, String)]) -> AsAccount {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let lower = path.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("/users/") {
        let id = rest.split('/').next().unwrap_or("");
        if id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()) && id != a.user_id.to_ascii_lowercase() {
            return AsAccount::Answer(403, json!({"error": "path_refused", "message": "another user's"}));
        }
        if id == "public" {
            return AsAccount::Answer(200, json!([{"Name": a.name, "Id": a.user_id, "HasPassword": false, "HasConfiguredPassword": false,
                                                    "HasConfiguredEasyPassword": false, "EnableAutoLogin": false}]));
        }
    }
    let query: Vec<String> = query.split('&').filter(|q| !q.is_empty()).map(|q| {
        let k = q.split('=').next().unwrap_or("");
        if k.eq_ignore_ascii_case("api_key") || k.eq_ignore_ascii_case("apikey") { format!("{k}={}", a.token) } else { q.to_string() }
    }).collect();
    let target = if query.is_empty() { path.to_string() } else { format!("{path}?{}", query.join("&")) };
    let mut out: Vec<(String, String)> = vec![];
    for (k, v) in headers {
        let l = k.to_ascii_lowercase();
        match l.as_str() {
            "x-emby-token" | "x-mediabrowser-token" => {}
            // the client's own fields kept, its token not
            "authorization" | "x-emby-authorization" => out.push((k.clone(), v.split(',').filter(|f| !f.trim().to_ascii_lowercase().starts_with("token=")).collect::<Vec<_>>().join(","))),
            _ => out.push((k.clone(), v.clone())),
        }
    }
    out.push(("X-Emby-Token".into(), a.token.clone()));
    // any login is the buyer's own: the client's name and password are replaced by the account's
    let login = method == "POST" && lower == "/users/authenticatebyname";
    AsAccount::Send { target, headers: out, body: login.then(|| json!({"Username": a.name, "Pw": a.password}).to_string().into_bytes()) }
}

use xbt_svc::http::Request;

use super::{error, Gateway};
use crate::config::Route;
use crate::upstream::{forwarded, Answer};

impl Gateway {
    /// The service a route's requests go to.
    fn service_base(&self, route: &Route) -> String {
        route.upstream.clone().or_else(|| self.cfg.upstream.clone()).unwrap_or_default()
    }

    /// The account `session`'s buyer is served as on `route`. `Ok(None)`: the route gives no
    /// accounts, or the buyer stays anonymous and the route serves its shared guest. `Err`: the
    /// answer that refuses the request (an anonymous buyer where there is no guest; an account that
    /// could not be made, which never falls back to the seller's key or to anyone else's).
    pub(super) fn account_for(&self, route: &Route, session: &str) -> Result<Option<Account>, xbt_svc::http::Response> {
        let Some(cfg) = &route.accounts else { return Ok(None) };
        let buyer = self.buyers.lock().unwrap_or_else(|p| p.into_inner()).get(session).cloned();
        let Some(buyer) = buyer else {
            return if route.upstream_headers.is_empty() {
                Err(error(403, "identify_first", "this service gives each buyer an account: say who you are to this seller first (identify)"))
            } else {
                Ok(None)
            };
        };
        self.accounts.account(cfg, &self.service_base(route), &buyer).map(Some)
            .map_err(|why| error(503, "accounts_unavailable", &format!("the buyer's account could not be made: {why}")))
    }

    /// A request sent as the buyer's account: `Ok(Err(..))` is an answer given here without the
    /// service. A refused login (an expired or revoked token) is made again once.
    pub(super) fn send_as_account(&self, route: &Route, req: &Request, acc: &Account, session: &str) -> Result<Result<Answer, (u16, Value)>, crate::Error> {
        let base = self.service_base(route);
        let up = self.upstreams.get(&base).ok_or_else(|| crate::Error::Upstream("no service for this route".into()))?;
        let target = route.upstream_target(&req.target);
        let send = |a: &Account| -> Result<Result<Answer, (u16, Value)>, crate::Error> {
            match self.as_account(route, a, &req.method, &target, &forwarded(route, &req.headers)) {
                AsAccount::Answer(status, v) => Ok(Err((status, v))),
                AsAccount::Send { target, headers, body } => up.send_as(&req.method, &target, &headers, body.as_deref().unwrap_or(&req.body), route.accept_gzip).map(Ok),
            }
        };
        let first = send(acc)?;
        if !matches!(&first, Ok(ans) if ans.status == 401) {
            return Ok(first);
        }
        let buyer = self.buyers.lock().unwrap_or_else(|p| p.into_inner()).get(session).cloned().unwrap_or_default();
        let Some(cfg) = &route.accounts else { return Ok(first) };
        match self.accounts.renew(cfg, &base, &buyer) {
            Ok(a) => send(&a),
            Err(_) => Ok(first),
        }
    }

    /// The request's target and headers as the account's.
    pub(super) fn as_account(&self, route: &Route, a: &Account, method: &str, target: &str, headers: &[(String, String)]) -> AsAccount {
        match &route.accounts {
            Some(Accounts::Hook { .. }) => {
                let mut h: Vec<(String, String)> = headers.iter().filter(|(k, _)| !a.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(k))).cloned().collect();
                h.extend(a.headers.iter().cloned());
                AsAccount::Send { target: target.to_string(), headers: h, body: None }
            }
            _ => jellyfin_request(a, method, target, headers),
        }
    }
}
