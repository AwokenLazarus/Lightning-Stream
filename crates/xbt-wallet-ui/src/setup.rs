//! The setup pages of a box with no terminal: the wallet's Lightning rail, and the seller gateway.
//!
//! Neither page asks where the Lightning node is: the platform gives its REST address and the
//! certificate the package pins (`XBT_UI_LN_*`, `XBT_UI_GW_*`). The owner pastes only the macaroons
//! they baked in the node's own dashboard, with the permissions named here and no others. The UI
//! writes them into a dir it shares by group with the one reader (the signer; the gateway), and never
//! shows them back. `xbt-supervise` in the reader's container restarts it when a file changes.
use std::collections::HashMap;
use std::path::Path;

use serde_json::{json, Map, Value};
use xbt_gateway::config::{Config as GatewayConfig, MAINNET_ACK, MAINNET_NOTICE};
use xbt_gateway::node::{checked_macaroon, INFO_OPS, INVOICE_OPS};

use crate::app::{App, Ctx};
use crate::html::{esc, json_block, kv, txt};
use crate::server::{Req, Resp};

/// What the wallet's rail macaroon must grant, and nothing more (the signer refuses more on mainnet).
pub const RAIL_OPS: [&str; 4] = ["info:read", "offchain:read", "offchain:write", "onchain:read"];
pub const RAIL_MACAROON: &str = "rail.macaroon";
pub const MAINNET_ACK_FILE: &str = "mainnet-ack";
pub const GW_CONFIG: &str = "config.json";
pub const GW_INVOICES: &str = "invoices.macaroon";
pub const GW_INFO: &str = "info.macaroon";

/// The caps the gateway page writes on mainnet unless the owner sets others: a few buyers at a time,
/// and at most 4 held tickets of 1,000 sat on the node's inbound channels.
pub const MAINNET_CAPS: (u32, u32, u32) = (4, 1, 4);
/// The gateway's own defaults on a test chain (`xbt-gateway`'s config).
pub const TEST_CAPS: (u32, u32, u32) = (30, 2, 15);

/// A macaroon as the node's dashboard shows it: hex, or base64 (standard or URL-safe).
pub fn decode_macaroon(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if t.is_empty() {
        return Err("empty".into());
    }
    if t.len().is_multiple_of(2) && t.bytes().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(&t).map_err(|e| e.to_string());
    }
    let bare = t.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(bare)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(bare))
        .map_err(|_| "neither hex nor base64".to_string())
}

/// Write `name` in the shared dir `dir`: a temp file in the same dir, given the dir's group and mode
/// 0640, then renamed over the old one, so a reader never sees half a file.
pub fn write_shared(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let path = dir.join(name);
    let ctx = |e: std::io::Error| format!("{}: {e}", path.display());
    let md = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !md.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let tmp = dir.join(format!(".{name}.{}", hex::encode(crate::random_bytes::<6>())));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let res = (|| {
        let mut f = o.open(&tmp).map_err(ctx)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            std::os::unix::fs::fchown(&f, None, Some(md.gid())).map_err(ctx)?;
            f.set_permissions(std::fs::Permissions::from_mode(0o640)).map_err(ctx)?;
        }
        std::io::Write::write_all(&mut f, bytes).and_then(|_| f.sync_all()).map_err(ctx)?;
        drop(f);
        std::fs::rename(&tmp, &path).map_err(ctx)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn remove_shared(dir: &Path, name: &str) -> Result<bool, String> {
    let p = dir.join(name);
    match std::fs::remove_file(&p) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// The certificate the package pins, as the owner can compare it with the node's: its SHA-256.
fn cert_line(path: Option<&Path>) -> String {
    match path {
        None => "<span class=\"tag bad\">not given by the platform</span>".into(),
        Some(p) => match std::fs::read_to_string(p) {
            Ok(pem) => {
                use sha2::{Digest, Sha256};
                let b64: String = pem.split("-----BEGIN CERTIFICATE-----").nth(1).and_then(|r| r.split("-----END CERTIFICATE-----").next())
                    .map(|b| b.chars().filter(|c| !c.is_whitespace()).collect()).unwrap_or_default();
                use base64::Engine;
                match base64::engine::general_purpose::STANDARD.decode(b64) {
                    Ok(der) => format!("<code>{}</code> (SHA-256 <code>{}</code>)", esc(&p.display().to_string()), hex::encode(Sha256::digest(&der))),
                    Err(_) => format!("<code>{}</code> <span class=\"tag bad\">holds no certificate</span>", esc(&p.display().to_string())),
                }
            }
            Err(e) => format!("<code>{}</code> <span class=\"tag bad\">{}</span>", esc(&p.display().to_string()), esc(&e.to_string())),
        },
    }
}

fn notice_html(lines: &[&str]) -> String {
    let mut b = String::from("<div class=\"flash warn\"><ul>");
    for l in lines {
        b.push_str(&format!("<li>{}</li>", esc(l.trim_start_matches("- "))));
    }
    b.push_str("</ul></div>");
    b
}

/// What the wallet's page says before mainnet is turned on.
pub const WALLET_MAINNET_NOTICE: [&str; 4] = [
    "This app is new, and has been tested on test networks. With real money it pays from your Lightning node's channels.",
    "The key you give lets the app pay anything your spending rules allow: keep their limits low (the starter rules do).",
    "A payment your rules allow is final: the app checks the seller's prices, not the seller's honesty.",
    "Read the limits of the software (docs/LIMITS.md in the source) before you rely on it.",
];

/// The signer's reason a node is not ready, in words for the owner where a common one is known.
pub(crate) fn plain_reason(r: &str) -> String {
    let l = r.to_ascii_lowercase();
    if l.contains("off in this policy") || l.contains("ln.enabled") {
        "Paying is not turned on in your spending rules yet. Sign the safe starter rules (Settings → Spending rules) to turn it on.".into()
    } else if l.contains("mainnet") && (l.contains("ack") || l.contains("acknowledg")) {
        "Confirm that the app may pay with real money (on Your node).".into()
    } else if l.contains("no usable channel") || l.contains("no channel") {
        "Your node has no channel the app can pay through. Open a channel in your node's app first.".into()
    } else if l.contains("connect") || l.contains("unreachable") || l.contains("refused") {
        "The app can't reach your node. Check that your Lightning node app is running.".into()
    } else if l.contains("macaroon") || l.contains("permission") {
        "The key doesn't have the right permissions. Make a new one as described below.".into()
    } else if r.is_empty() {
        "The app is still checking your node.".into()
    } else {
        format!("Your node said: {r}")
    }
}

/// How long reading the node's certificate for pinning may take.
const PIN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The SHA-256 of a certificate, as the owner compares it: hex in pairs.
fn fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// The card that pins the node's certificate, for a platform that cannot hand it over alone: the
/// certificate the node shows now, its fingerprint for the owner to compare with the node's own
/// page, and one button. Empty where the platform gives the certificate itself.
pub(crate) fn pin_card(csrf: &str, pin: bool, rest: Option<&str>, path: Option<&Path>, action: &str) -> String {
    let (true, Some(rest), Some(path)) = (pin, rest, path) else { return String::new() };
    let had = path.is_file();
    let mut b = format!("<section class=\"card\"><h2>{}</h2>", if had { "Pin the node's certificate again" } else { "Pin the node's certificate" });
    match xbt_gateway::node::peer_certificate(rest, PIN_WAIT) {
        Ok(der) => {
            let fp = fingerprint(&der);
            b.push_str(&format!("<p>{}This is the certificate your Lightning node shows at <code>{}</code>. Compare its fingerprint with the one \
                on the node's own page; pin it only if they match. From then on the wallet talks to this certificate and no other.</p>\
                <p><code>SHA-256 {}</code></p><form method=\"post\" action=\"{}\">{}<input type=\"hidden\" name=\"action\" value=\"pin_cert\">\
                <input type=\"hidden\" name=\"fingerprint\" value=\"{}\"><button>Yes, this is my node: pin it</button></form>",
                if had { "Pin again only if you know the node's certificate changed (a new node, or a certificate it renewed). " } else { "" },
                esc(rest), esc(&fp), esc(action), csrf, esc(&fp)));
        }
        Err(e) => b.push_str(&format!("<p><span class=\"tag bad\">the node's certificate could not be read</span> {}</p>", esc(&e))),
    }
    b.push_str("</section>");
    b
}

/// Pin the certificate the node shows now, if it is the one the owner was shown (`fp`).
pub(crate) fn pin_cert(pin: bool, rest: Option<&str>, path: Option<&Path>, fp: &str) -> Result<String, String> {
    let (true, Some(rest), Some(path)) = (pin, rest, path) else { return Err("this platform gives the node's certificate itself".into()) };
    let der = xbt_gateway::node::peer_certificate(rest, PIN_WAIT)?;
    if fingerprint(&der) != fp {
        return Err("the node now shows another certificate than the one you confirmed: nothing was pinned; look again".into());
    }
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else { return Err("the certificate path has no directory".into()) };
    write_shared(dir, name, xbt_gateway::node::cert_pem(&der).as_bytes())?;
    Ok(format!("Certificate pinned (SHA-256 {fp}). The services that talk to the node restart to use it."))
}

/// The gateway's saved config, pointed again at the node the platform names now. The setup page writes the
/// node's address into the config when the owner saves it; a platform that gives the node by its container
/// address (StartOS: `getContainerIp`) gives a new one when that container is made again, and a config left as
/// it was keeps the gateway dialling an address nobody answers. Run at every start; true when it rewrote.
pub fn follow_node(gw: &crate::config::GatewaySetup) -> Result<bool, String> {
    let Some(rest) = gw.node_rest.as_deref() else { return Ok(false) };
    let Ok(text) = std::fs::read_to_string(gw.dir.join(GW_CONFIG)) else { return Ok(false) };
    let mut c: Value = serde_json::from_str(&text).map_err(|e| format!("{GW_CONFIG}: {e}"))?;
    let Some(node) = c.get_mut("node").and_then(Value::as_object_mut) else { return Ok(false) };
    let mut changed = false;
    if node.get("rest").and_then(Value::as_str) != Some(rest) {
        node.insert("rest".into(), json!(rest));
        changed = true;
    }
    if let Some(cert) = &gw.node_tls_cert {
        let cert = cert.display().to_string();
        if node.get("tls_cert").and_then(Value::as_str) != Some(cert.as_str()) {
            node.insert("tls_cert".into(), json!(cert));
            changed = true;
        }
    }
    if changed {
        let text = serde_json::to_string_pretty(&c).map_err(|e| e.to_string())? + "\n";
        write_shared(&gw.dir, GW_CONFIG, text.as_bytes())?;
    }
    Ok(changed)
}

impl App {
    // --- the wallet: the Lightning rail ------------------------------------------------------------

    fn signer_chain(&self) -> String {
        self.signer.call("health", json!({})).ok().and_then(|h| h.get("chain").and_then(Value::as_str).map(str::to_string)).unwrap_or_default()
    }

    /// The node's state as every page tells it (Home, Setup and Your node read this one answer):
    /// (ready to pay, connected: the app holds a key for the node, why it cannot pay yet in words).
    pub(crate) fn node_state(&self) -> (bool, bool, String) {
        let status = self.signer.call("ln_status", json!({})).unwrap_or_else(|e| json!({"ready": false, "reason": e}));
        let ready = status["ready"] == true;
        let have = self.cfg.ln.dir.join(RAIL_MACAROON).is_file() || status["configured"] == true;
        (ready, have, plain_reason(&txt(status.get("reason").or(status.get("config_error")))))
    }

    pub(crate) fn lightning_page(&self, ctx: &Ctx) -> Resp {
        let ln = &self.cfg.ln;
        let chain = self.signer_chain();
        let status = self.signer.call("ln_status", json!({})).unwrap_or_else(|e| json!({"ready": false, "reason": e}));
        let have = ln.dir.join(RAIL_MACAROON).is_file();
        let acked = ln.dir.join(MAINNET_ACK_FILE).is_file();
        let ready = status["ready"] == true;
        // the keys the app made itself through the box's own node (`node-keys`), with no step by the owner
        let auto = have && crate::node_keys::made_by_box(&ln.dir);
        let main = chain == "main";
        let mut b = String::from(if auto {
            "<p class=\"lead\">The app pays for services through this box's own Lightning node. It connected by itself when it was \
             installed, with a key that can pay only within your spending rules; it cannot open or close channels.</p>"
        } else {
            "<p class=\"lead\">The app pays for services through your own Lightning node. Connect it once with a key \
             you make in your node's app. The key lets the app pay within your spending rules; it cannot open or close channels.</p>"
        });
        let needs_ack = have && main && !acked;
        b.push_str(&format!("<section class=\"status {}\"><p class=\"status-head\">{}</p><p>{}</p></section>",
            if ready { "ok" } else if have { "warn" } else { "bad" },
            if ready && auto { "Connected to your Lightning node" } else if ready { "Connected and ready to pay" }
            else if needs_ack { "Connected: one last step" } else if have { "Connected, not ready yet" } else { "Not connected" },
            if ready { "Nothing to do here.".to_string() }
            else if needs_ack { "Confirm below that the app may pay with real money.".into() }
            else if have { format!("{} If this stays, open the details below.", esc(&plain_reason(&txt(status.get("reason").or(status.get("config_error")))))) }
            else { "Make the key in your node's app and paste it below.".into() }));
        if needs_ack {
            b.push_str(&format!("<form method=\"post\" action=\"./lightning\" class=\"card primary\">{}<input type=\"hidden\" name=\"action\" value=\"ack\">\
                <h2>Pay with real money</h2><p>This is a real Lightning node. Keep your spending rules low while you try the app.</p>\
                <details><summary>Read before you start</summary>{}</details>\
                <label class=\"check\"><input type=\"checkbox\" name=\"ack\" value=\"1\" required> I understand that the app pays with real money, within my spending rules</label>\
                <button>Start paying</button></form>", App::csrf_input(ctx), notice_html(&WALLET_MAINNET_NOTICE)));
        }
        b.push_str(&pin_card(&App::csrf_input(ctx), ln.pin, ln.rest.as_deref(), ln.tls_cert.as_deref(), "./lightning"));
        if main && !auto {
            b.push_str(&format!("<div class=\"flash warn\"><p><strong>This is real money.</strong> Keep your spending rules low while you try the app.</p>\
                <details><summary>Read before you connect</summary>{}</details></div>", notice_html(&WALLET_MAINNET_NOTICE)));
        }
        // the owner's own key: the main form when nothing is connected, under Advanced when the box connected the app
        b.push_str(if auto { "<details class=\"card\"><summary>Advanced: use a key of your own instead</summary>" } else { "" });
        b.push_str(&format!("<form method=\"post\" action=\"./lightning\" class=\"card{}\">{}<input type=\"hidden\" name=\"action\" value=\"save\">\
            <h2>{}</h2>\
            <details><summary>How do I make the key?</summary><ol><li>Open your Lightning node's app (Lightning Fork) and find the page called \
            <em>Macaroons</em>.</li><li>Make a new one with exactly these permissions, and a root key of its own so you can revoke it alone: \
            <code>{}</code></li><li>Copy it and paste it here.</li></ol><p class=\"hint\">Never paste the node's admin key: the app refuses one, \
            and does not need it.</p></details>\
            <label>Key from your node<textarea name=\"macaroon\" rows=\"4\" class=\"mono\" autocomplete=\"off\" required></textarea></label>",
            if have { "" } else { " primary" }, App::csrf_input(ctx), if have { "Replace the key" } else { "Connect your node" }, RAIL_OPS.join(" ")));
        if main {
            b.push_str(&format!("<label>To pay with real money, type: <code>{}</code><input name=\"mainnet_ack\" autocomplete=\"off\" required></label>{}",
                                esc(MAINNET_ACK), if acked { "<p class=\"hint\">You typed it before; type it again to replace the key.</p>" } else { "" }));
        }
        b.push_str(&format!("<button{}>Connect</button></form>", if have { " class=\"secondary\"" } else { "" }));
        b.push_str(if auto { "</details>" } else { "" });
        b.push_str("<details class=\"card\"><summary>Details</summary>");
        b.push_str(&kv(&[
            ("Node address", ln.rest.as_deref().map(|r| format!("<code>{}</code>", esc(r))).unwrap_or_else(|| "<span class=\"pill bad\">not given by this box</span>".into())),
            ("Node certificate", cert_line(ln.tls_cert.as_deref())),
            ("Key", if auto { format!("<span class=\"pill good\">made by the app</span> with only <code>{}</code>, under a root key of its own: \
                              you can revoke it in your node's app ({})", RAIL_OPS.join(" "), esc(&crate::node_keys::root_key_line(&ln.dir, RAIL_MACAROON))) }
                    else if have { "<span class=\"pill good\">stored</span> (never shown again)".into() } else { "<span class=\"pill warn\">none</span>".into() }),
            ("Before you uninstall", {
                let mut ids = crate::node_keys::root_key_ids(&ln.dir);
                ids.extend(crate::node_keys::root_key_ids(&self.cfg.gw.dir));
                if ids.is_empty() { "The app made no keys on your node.".to_string() } else {
                    format!("The keys the app made stay valid on your node after an uninstall. Revoke them in your node's app: root key ids <code>{}</code> \
                             (or <code>lncli deletemacaroonid &lt;id&gt;</code>).", esc(&ids.join(", ")))
                }
            }),
            ("Chain", esc(&chain)),
        ]));
        b.push_str(&format!("<p>What the wallet sees of the node:</p>{}", json_block(&status)));
        if have {
            b.push_str(&format!("<form method=\"post\" action=\"./lightning\">{}<input type=\"hidden\" name=\"action\" value=\"remove\">\
                <h3>Disconnect</h3><p>Removes the key from this box; the app then pays nothing. Revoke it in your node's app too if it may have \
                been copied.</p><button class=\"danger\">Disconnect your node</button></form>", App::csrf_input(ctx)));
        }
        b.push_str("</details>");
        b.push_str("<p class=\"hint\">Your <a href=\"./policy\">spending rules</a> decide whom the app pays and how much: the \
            <a href=\"./policy?template=starter\">safe starter rules</a> turn paying on with low limits.</p>");
        self.page("Your node", ctx, b)
    }

    pub(crate) fn lightning_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let dir = &self.cfg.ln.dir;
        let ln = &self.cfg.ln;
        let result = match f.get("action").map(String::as_str) {
            Some("pin_cert") => pin_cert(ln.pin, ln.rest.as_deref(), ln.tls_cert.as_deref(), f.get("fingerprint").map(String::as_str).unwrap_or("")),
            Some("ack") => (|| {
                if self.signer_chain() != "main" {
                    return Ok("Nothing to confirm on a test network.".to_string());
                }
                if f.get("ack").map(String::as_str) != Some("1") {
                    return Err("Tick the box to confirm that the app pays with real money.".into());
                }
                if !dir.join(RAIL_MACAROON).is_file() {
                    return Err("Your node is not connected yet.".into());
                }
                write_shared(dir, MAINNET_ACK_FILE, format!("{MAINNET_ACK}\n").as_bytes())?;
                Ok("Done. The app can now pay within your spending rules; the status above follows in a few seconds.".into())
            })(),
            Some("remove") => remove_shared(dir, RAIL_MACAROON).map(|had| {
                let _ = remove_shared(dir, MAINNET_ACK_FILE);
                // a key the app made itself is not made again at the next start
                let _ = crate::node_keys::turn_off(dir);
                if had { "Your node is disconnected: its key was removed from this box, and the app pays nothing now.".to_string() } else { "Your node was not connected.".into() }
            }),
            Some("save") => (|| {
                let chain = self.signer_chain();
                let main = chain == "main";
                if main && f.get("mainnet_ack").map(|a| a.trim()) != Some(MAINNET_ACK) {
                    return Err(format!("To pay with real money, type the sentence word for word: {MAINNET_ACK}"));
                }
                let mac = decode_macaroon(f.get("macaroon").map(String::as_str).unwrap_or("")).map_err(|_| "That is not a key: copy it again, whole.".to_string())?;
                // strict on every chain: the page stores only what the rail needs
                checked_macaroon(&mac, "the rail macaroon", &RAIL_OPS, true).map_err(|e| e.to_string())?;
                if main {
                    write_shared(dir, MAINNET_ACK_FILE, format!("{MAINNET_ACK}\n").as_bytes())?;
                }
                write_shared(dir, RAIL_MACAROON, &mac)?;
                Ok("Key saved. The app restarts its payments part to use it; the status above follows in a few seconds.".into())
            })(),
            _ => Err("unknown action".into()),
        };
        match result {
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./lightning")
    }

    // --- the gateway ------------------------------------------------------------------------------

    fn current_gateway(&self) -> Option<Value> {
        std::fs::read_to_string(self.cfg.gw.dir.join(GW_CONFIG)).ok().and_then(|t| serde_json::from_str(&t).ok())
    }

    /// The form's values: what the owner just sent, else the current config, else the defaults.
    fn gateway_values(&self, sent: Option<&HashMap<String, String>>) -> HashMap<String, String> {
        if let Some(f) = sent {
            return f.clone();
        }
        let mut v: HashMap<String, String> = HashMap::new();
        let gw = &self.cfg.gw;
        let (ms, spa, mh) = TEST_CAPS;
        v.insert("chain".into(), "regtest".into());
        v.insert("unit".into(), "request".into());
        v.insert("price_msat".into(), "1000".into());
        v.insert("max_sessions".into(), ms.to_string());
        v.insert("sessions_per_address".into(), spa.to_string());
        v.insert("max_held_tickets".into(), mh.to_string());
        v.insert("proxies".into(), gw.proxies.join(", "));
        if let Some(c) = self.current_gateway() {
            let s = |p: &str| c.pointer(p).map(|x| txt(Some(x)));
            for (k, p) in [("upstream", "/upstream"), ("public_url", "/public_url"), ("chain", "/chain"), ("network", "/network"),
                           ("max_sessions", "/caps/max_sessions"), ("sessions_per_address", "/caps/sessions_per_address"),
                           ("max_held_tickets", "/caps/max_held_tickets")] {
                if let Some(x) = s(p) {
                    v.insert(k.into(), x);
                }
            }
            if let Some(px) = c.pointer("/http/forwarded_address/proxies").and_then(Value::as_array) {
                v.insert("proxies".into(), px.iter().map(|x| txt(Some(x))).collect::<Vec<_>>().join(", "));
            }
            let price = c.pointer("/routes/0/price").cloned().unwrap_or(json!({}));
            let n = |k: &str| price.get(k).and_then(Value::as_u64).unwrap_or(0);
            let (unit, msat) = if n("byte_msat") > 0 { ("mib", n("byte_msat")) } else if n("second_msat") > 0 { ("second", n("second_msat")) } else { ("request", n("request_msat")) };
            v.insert("unit".into(), unit.into());
            v.insert("price_msat".into(), msat.to_string());
        }
        v
    }

    /// The config the form describes; the gateway's own parser is the judge of it.
    fn gateway_config(&self, f: &HashMap<String, String>) -> Result<Value, String> {
        let gw = &self.cfg.gw;
        let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
        let num = |k: &str| -> Result<u64, String> { g(k).parse::<u64>().map_err(|_| format!("{k} is a whole number")) };
        let rest = gw.node_rest.clone().ok_or("the platform gave no Lightning node address (XBT_UI_GW_NODE_REST)")?;
        let public_url = g("public_url").trim_end_matches('/').to_string();
        // https: behind a TLS proxy, listening for it on every address; plain http only for a buyer on this machine
        // (the wallet pays tickets over nothing else, and a gateway on loopback is out of every other container's reach)
        let local = ["http://127.0.0.1", "http://[::1]", "http://localhost"]
            .iter()
            .any(|p| public_url == *p || public_url.strip_prefix(p).is_some_and(|r| r.starts_with(':')));
        if !public_url.starts_with("https://") && !local {
            return Err(format!("Buyers reach you at an https:// address, like https://films.example.com: {public_url} is not https (plain http only as \
                                http://127.0.0.1:{}, for a buyer on this machine)", gw.port));
        }
        let listen = if public_url.starts_with("https://") { format!("0.0.0.0:{}", gw.port) } else { format!("127.0.0.1:{}", gw.port) };
        let chain = g("chain");
        let mut c = Map::new();
        c.insert("listen".into(), json!(listen));
        c.insert("public_url".into(), json!(public_url));
        c.insert("upstream".into(), json!(g("upstream").trim_end_matches('/')));
        c.insert("state_dir".into(), json!(gw.state_dir));
        c.insert("chain".into(), json!(chain));
        if chain == "main" {
            if g("mainnet_ack") != MAINNET_ACK {
                return Err(format!("mainnet needs the acknowledgement, word for word: {MAINNET_ACK}"));
            }
            c.insert("mainnet_ack".into(), json!(MAINNET_ACK));
        } else {
            c.insert("network".into(), json!(g("network")));
        }
        let mut node = json!({"rest": rest, "macaroon": gw.dir.join(GW_INVOICES).display().to_string(),
                              "info_macaroon": gw.dir.join(GW_INFO).display().to_string()});
        if let Some(cert) = &gw.node_tls_cert {
            node["tls_cert"] = json!(cert.display().to_string());
        }
        c.insert("node".into(), node);
        let proxies: Vec<String> = g("proxies").split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
        let behind_proxy = public_url.starts_with("https://");
        // behind a proxy every buyer comes from its address: without the proxy's word for the real one the
        // per-address cap would count all buyers as one, so it is off and the total cap is the bound
        let per_address = if behind_proxy && proxies.is_empty() { 0 } else { num("sessions_per_address")? };
        c.insert("caps".into(), json!({"max_sessions": num("max_sessions")?, "sessions_per_address": per_address,
                                       "max_held_tickets": num("max_held_tickets")?}));
        if !proxies.is_empty() {
            c.insert("http".into(), json!({"forwarded_address": {"header": "x-forwarded-for", "proxies": proxies}}));
        }
        // the page asks for sats; a form that sends millisats (an older page, a script) still works
        let msat = if g("price").is_empty() { num("price_msat")? } else { crate::app::sell::sats_to_msat(&g("price"))? };
        let price = match g("unit").as_str() {
            "request" => json!({"request_msat": msat}),
            "mib" => json!({"byte_msat": msat, "per_bytes": 1_048_576}),
            "second" => json!({"second_msat": msat}),
            _ => return Err("the unit is per request, per MiB or per second".into()),
        };
        c.insert("routes".into(), json!([{"path": "/", "price": price}]));
        let v = Value::Object(c);
        GatewayConfig::from_json(&v).map_err(|e| e.to_string())?;
        Ok(v)
    }

    pub(crate) fn gateway_page(&self, ctx: &Ctx, sent: Option<(&HashMap<String, String>, String)>) -> Resp {
        let gw = &self.cfg.gw;
        let v = self.gateway_values(sent.as_ref().map(|(f, _)| *f));
        let g = |k: &str| esc(v.get(k).map(String::as_str).unwrap_or(""));
        let saved = self.current_gateway().is_some();
        let mut b = String::new();
        if let Some((_, e)) = &sent {
            b.push_str(&App::error_box(e));
        }
        b.push_str("<p class=\"lead\">Sell a service from this box, paid a little at a time over Lightning. Buyers pay before each piece, \
            and this app passes each paid request on to your service.</p>");
        b.push_str(&pin_card(&App::csrf_input(ctx), gw.node_pin, gw.node_rest.as_deref(), gw.node_tls_cert.as_deref(), "./gateway"));
        let health = gw.health_url.as_deref().map(crate::app::http_get);
        let (class, head, next) = match (&health, saved) {
            (_, false) => ("warn", "Not selling yet", "Fill in the form below and save it."),
            (Some(Ok((200, _))) | None, true) => ("ok", "Selling", "Buyers can pay and use your service."),
            (Some(Ok(_)), true) => ("bad", "Not answering", "The selling part of the app answers with an error. Check the settings below."),
            (Some(Err(_)), true) => ("warn", "Starting, or stopped", "It starts by itself in a few seconds; if this stays, restart the app."),
        };
        b.push_str(&format!("<section class=\"status {class}\"><p class=\"status-head\">{head}</p><p>{next}</p></section>"));
        let main = v.get("chain").map(String::as_str) == Some("main");
        if main {
            b.push_str(&format!("<div class=\"flash warn\"><p><strong>This is real money.</strong> Start with low prices and the low limits below.</p>\
                <details><summary>Read the limits</summary>{}</details></div>", notice_html(&MAINNET_NOTICE)));
        }
        let sel = |k: &str, opt: &str| if v.get(k).map(String::as_str) == Some(opt) { " selected" } else { "" };
        let price = v.get("price").cloned().unwrap_or_else(|| v.get("price_msat").and_then(|m| m.trim().parse::<u64>().ok())
            .map(crate::app::sell::msat_to_sats).unwrap_or_default());
        b.push_str(&format!("<form method=\"post\" action=\"./gateway\" class=\"card primary policy\">{}\
            <fieldset><legend>What you sell</legend>\
            <label>Your service's address on this box<input name=\"upstream\" value=\"{}\" class=\"mono\" required placeholder=\"http://10.21.21.50:8080\"></label>\
            <p class=\"hint\">The http:// address other apps on this box use to reach it.</p>\
            <div class=\"price-row\"><label>Price in sats<input name=\"price\" value=\"{}\" inputmode=\"decimal\" required></label>\
            <label>for each<select name=\"unit\"><option value=\"request\"{}>request</option><option value=\"mib\"{}>MiB of data sent</option>\
            <option value=\"second\"{}>second</option></select></label></div></fieldset>\
            <fieldset><legend>Where buyers find you</legend>\
            <label>Your public https:// address<input name=\"public_url\" value=\"{}\" class=\"mono\" required placeholder=\"https://seller.example\"></label>\
            <p class=\"hint\">The secure address that leads to port {} of this app.</p></fieldset>\
            <fieldset><legend>Money</legend><label>Network<select name=\"chain\"><option value=\"regtest\"{}>A test network</option>\
            <option value=\"main\"{}>Real money (mainnet)</option></select></label>\
            <label>Real money only: type <code>{}</code><input name=\"mainnet_ack\" autocomplete=\"off\"></label></fieldset>\
            <fieldset><legend>Keys from your Lightning node{}</legend>\
            <details><summary>How do I make them?</summary><p>In your Lightning node's app, open the page called <em>Macaroons</em> and make two, \
            each with exactly these permissions and a root key of its own:</p>\
            <ul><li>Payment requests: <code>{}</code></li><li>Network time: <code>{}</code></li></ul>\
            <p class=\"hint\">They let this app ask for payments and read the time on the network. They cannot spend your money.</p></details>\
            <label>Payment requests key<textarea name=\"invoices_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\"></textarea></label>\
            <label>Network time key<textarea name=\"info_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\"></textarea></label></fieldset>\
            <details><summary>Advanced</summary>\
            <label>Your proxy's addresses, whose word on the buyer's address the app believes (comma-separated; empty: the limit per buyer is off \
            behind a proxy)<input name=\"proxies\" value=\"{}\" class=\"mono\"></label>\
            <label>Test network only: its id (<code>lightning:</code> and 32 hex)<input name=\"network\" value=\"{}\" class=\"mono\"></label>\
            <label>Buyers at once<input name=\"max_sessions\" value=\"{}\" inputmode=\"numeric\"></label>\
            <label>Buyers at once from one address<input name=\"sessions_per_address\" value=\"{}\" inputmode=\"numeric\"></label>\
            <label>Payments held open at once (1,000 sat each, on your inbound channels)<input name=\"max_held_tickets\" value=\"{}\" inputmode=\"numeric\"></label>\
            <p class=\"hint\">With real money keep these low: {} buyers, {} per address, {} held payments.</p></details>\
            <button>Check and save</button></form>",
            App::csrf_input(ctx), g("upstream"), esc(&price), sel("unit", "request"), sel("unit", "mib"), sel("unit", "second"),
            g("public_url"), gw.port, sel("chain", "regtest"), sel("chain", "main"), esc(MAINNET_ACK),
            if saved { " (leave empty to keep the ones you saved)" } else { "" }, INVOICE_OPS.join(" "), INFO_OPS.join(" "),
            g("proxies"), g("network"), g("max_sessions"), g("sessions_per_address"), g("max_held_tickets"), MAINNET_CAPS.0, MAINNET_CAPS.1, MAINNET_CAPS.2));
        b.push_str("<details class=\"card\"><summary>Details</summary>");
        b.push_str(&kv(&[
            ("Settings", if saved { "<span class=\"pill good\">saved</span>".into() } else { "<span class=\"pill warn\">none yet: the selling part waits for them</span>".into() }),
            ("Selling part", match &health {
                Some(Ok((200, body))) => format!("<span class=\"pill good\">running</span> <code>{}</code>", esc(&crate::html::short(body.trim(), 200))),
                Some(Ok((code, _))) => format!("<span class=\"pill bad\">HTTP {code}</span>"),
                Some(Err(e)) => format!("<span class=\"pill warn\">not answering</span> {}", esc(e)),
                None => "-".into(),
            }),
            ("Lightning node", gw.node_rest.as_deref().map(|r| format!("<code>{}</code>", esc(r))).unwrap_or_else(|| "<span class=\"pill bad\">not given by this box</span>".into())),
            ("Node certificate", cert_line(gw.node_tls_cert.as_deref())),
            ("Keys", format!("payment requests {}, network time {}", if gw.dir.join(GW_INVOICES).is_file() { "stored" } else { "none" },
                             if gw.dir.join(GW_INFO).is_file() { "stored" } else { "none" })),
            // what the gateway can know: its node's word on an invoice, never the channel peer's fulfil
            ("Settled", "<code>settled</code> counts the tickets your node settled, by its own word. It is not yet income: the payment \
                         is yours once the channel peer it came through has taken the preimage, which the gateway does not check".into()),
        ]));
        if let Some(c) = self.current_gateway() {
            b.push_str(&format!("<details><summary>The settings file the selling part reads</summary>{}</details>", json_block(&c)));
        }
        b.push_str("</details>");
        self.page("Sell", ctx, b)
    }

    pub(crate) fn gateway_post(&self, req: &Req, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        match req.path.as_str() {
            "/logout" => {
                self.auth.logout(&ctx.sid);
                return Resp::redirect("./login").header("Set-Cookie", &self.cookie(req, "", 0));
            }
            "/gateway" => {}
            _ => return Resp::text(404, "text/plain", "not found"),
        }
        if f.get("action").map(String::as_str) == Some("pin_cert") {
            let gw = &self.cfg.gw;
            match pin_cert(gw.node_pin, gw.node_rest.as_deref(), gw.node_tls_cert.as_deref(), f.get("fingerprint").map(String::as_str).unwrap_or("")) {
                Ok(m) => self.flash(ctx, true, m),
                Err(e) => self.flash(ctx, false, e),
            }
            return Resp::redirect("./gateway");
        }
        let dir = &self.cfg.gw.dir;
        let mut f = f.clone();
        // a switch to mainnet with the test chain's caps still in the form gets the low ones
        let was_main = self.current_gateway().and_then(|c| c.get("chain").cloned()) == Some(json!("main"));
        if f.get("chain").map(String::as_str) == Some("main") && !was_main {
            let (ms, spa, mh) = TEST_CAPS;
            for (k, test, low) in [("max_sessions", ms, MAINNET_CAPS.0), ("sessions_per_address", spa, MAINNET_CAPS.1), ("max_held_tickets", mh, MAINNET_CAPS.2)] {
                if f.get(k).map(|x| x.trim()) == Some(test.to_string().as_str()) {
                    f.insert(k.into(), low.to_string());
                }
            }
        }
        let result = (|| -> Result<String, String> {
            let cfg = self.gateway_config(&f)?;
            let main = cfg["chain"] == "main";
            let mut macs = vec![];
            for (field, file, ops, what) in [("invoices_macaroon", GW_INVOICES, &INVOICE_OPS[..], "The payment requests key"),
                                             ("info_macaroon", GW_INFO, &INFO_OPS[..], "The network time key")] {
                let text = f.get(field).map(String::as_str).unwrap_or("").trim().to_string();
                if text.is_empty() {
                    if !dir.join(file).is_file() {
                        return Err(format!("{what} is needed: paste it from your Lightning node's app"));
                    }
                    continue;
                }
                let mac = decode_macaroon(&text).map_err(|e| format!("{what}: {e}"))?;
                // strict on every chain: exactly the permissions named, nothing more
                checked_macaroon(&mac, what, ops, true).map_err(|e| e.to_string())?;
                macs.push((file, mac));
            }
            if main && !self.current_gateway().is_some_and(|c| c["chain"] == "main") {
                // a first switch to mainnet: said again in the flash, beside the warning on the page
                eprintln!("xbt-wallet-ui: the gateway's config now says chain main");
            }
            for (file, mac) in macs {
                write_shared(dir, file, &mac)?;
            }
            let text = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())? + "\n";
            write_shared(dir, GW_CONFIG, text.as_bytes())?;
            Ok(if main { "Saved, with real money (mainnet) and the limits shown. Selling restarts with it in a few seconds.".into() }
               else { "Saved. Selling restarts with it in a few seconds.".into() })
        })();
        match result {
            Ok(m) => {
                self.flash(ctx, true, m);
                Resp::redirect("./")
            }
            Err(e) => self.gateway_page(ctx, Some((&f, e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macaroons_in_hex_or_base64() {
        let raw = vec![2u8, 1, 3, 0xff, 0x10];
        assert_eq!(decode_macaroon(&hex::encode(&raw)).unwrap(), raw);
        assert_eq!(decode_macaroon(&format!(" {} \n", hex::encode(&raw))).unwrap(), raw);
        use base64::Engine;
        assert_eq!(decode_macaroon(&base64::engine::general_purpose::STANDARD.encode(&raw)).unwrap(), raw);
        assert_eq!(decode_macaroon(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw)).unwrap(), raw);
        assert!(decode_macaroon("").is_err() && decode_macaroon("not *** base64").is_err());
    }

    #[test]
    fn the_rail_needs_what_the_signer_needs() {
        assert_eq!(RAIL_OPS, xbt_signer::macaroon::NEEDED_OPS);
    }

    #[cfg(unix)]
    #[test]
    fn shared_files_are_0640_and_whole() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        write_shared(t.path(), "x", b"one").unwrap();
        write_shared(t.path(), "x", b"two").unwrap();
        assert_eq!(std::fs::read(t.path().join("x")).unwrap(), b"two");
        assert_eq!(std::fs::metadata(t.path().join("x")).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 1, "no temp file left");
        assert!(write_shared(&t.path().join("missing"), "x", b"").is_err());
    }

    #[test]
    fn a_saved_config_follows_the_node_to_its_new_address() {
        let t = tempfile::tempdir().unwrap();
        let gw = crate::config::GatewaySetup {
            dir: t.path().into(),
            node_rest: Some("https://10.0.3.235:8080".into()),
            node_tls_cert: Some("/data/lightning/tls.cert".into()),
            ..Default::default()
        };
        assert!(!follow_node(&gw).unwrap(), "no config yet: nothing to do");
        let saved = json!({"listen": "0.0.0.0:8402", "node": {"rest": "https://10.0.3.26:8080", "tls_cert": "/data/lightning/tls.cert",
                           "macaroon": "/m/invoices.macaroon"}, "caps": {"max_sessions": 4}});
        std::fs::write(t.path().join(GW_CONFIG), serde_json::to_string(&saved).unwrap()).unwrap();
        assert!(follow_node(&gw).unwrap());
        let now: Value = serde_json::from_str(&std::fs::read_to_string(t.path().join(GW_CONFIG)).unwrap()).unwrap();
        assert_eq!(now["node"]["rest"], "https://10.0.3.235:8080");
        assert_eq!(now["node"]["macaroon"], "/m/invoices.macaroon", "the rest of the config as it was");
        assert_eq!(now["caps"], saved["caps"]);
        assert!(!follow_node(&gw).unwrap(), "already current: not rewritten");
        let none = crate::config::GatewaySetup { node_rest: None, ..gw.clone() };
        assert!(!follow_node(&none).unwrap(), "no address from the platform: left alone");
        std::fs::write(t.path().join(GW_CONFIG), "not json").unwrap();
        assert!(follow_node(&gw).is_err(), "a config it cannot read is reported, not overwritten");
        assert_eq!(std::fs::read_to_string(t.path().join(GW_CONFIG)).unwrap(), "not json");
    }
}
