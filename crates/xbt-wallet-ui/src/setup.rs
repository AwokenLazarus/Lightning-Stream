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
    "This wallet's Lightning rail has run on regtest only. On mainnet it pays real funds from your Lightning node's channels.",
    "The rail macaroon lets the signer pay any invoice your policy allows: keep the policy's caps low (the starter template does).",
    "A payment the policy allows is final: the signer checks the seller's terms, not the seller's honesty.",
    "Read the limits of the software (docs/LIMITS.md in the source) before you rely on it.",
];

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

    pub(crate) fn lightning_page(&self, ctx: &Ctx) -> Resp {
        let ln = &self.cfg.ln;
        let chain = self.signer_chain();
        let status = self.signer.call("ln_status", json!({})).unwrap_or_else(|e| json!({"ready": false, "reason": e}));
        let have = ln.dir.join(RAIL_MACAROON).is_file();
        let acked = ln.dir.join(MAINNET_ACK_FILE).is_file();
        let mut b = String::from("<p>The wallet pays sellers through your Lightning node. It needs the node's address and certificate, which \
            this box gives it, and a macaroon you make in the node's own dashboard (Lightning Fork: <em>Macaroons</em>) with exactly these \
            permissions and no others:</p>");
        b.push_str(&format!("<p><code>{}</code></p>", RAIL_OPS.join(" ")));
        b.push_str("<p>Give it a root key of its own there, so you can revoke it alone. Never paste the node's admin macaroon: the page \
            refuses one, and the wallet does not need it.</p>");
        b.push_str("<section class=\"card\"><h2>The node</h2>");
        b.push_str(&kv(&[
            ("REST address", ln.rest.as_deref().map(|r| format!("<code>{}</code>", esc(r))).unwrap_or_else(|| "<span class=\"tag bad\">not given by the platform</span>".into())),
            ("Certificate (pinned)", cert_line(ln.tls_cert.as_deref())),
            ("Rail macaroon", if have { "<span class=\"tag ok\">stored</span> (never shown again)".into() } else { "<span class=\"tag warn\">none</span>".into() }),
            ("Chain", esc(&chain)),
            ("Rail", if status["ready"] == true { "<span class=\"tag ok\">ready</span>".into() }
                     else { format!("<span class=\"tag bad\">not ready</span> {}", esc(&txt(status.get("reason").or(status.get("config_error"))))) }),
        ]));
        b.push_str(&format!("<details><summary>The signer's view of the rail</summary>{}</details></section>", json_block(&status)));
        b.push_str(&pin_card(&App::csrf_input(ctx), ln.pin, ln.rest.as_deref(), ln.tls_cert.as_deref(), "./lightning"));
        let main = chain == "main";
        if main {
            b.push_str(&notice_html(&WALLET_MAINNET_NOTICE));
        }
        b.push_str(&format!("<form method=\"post\" action=\"./lightning\" class=\"card\">{}<input type=\"hidden\" name=\"action\" value=\"save\">\
            <h2>{}</h2><label>Rail macaroon (hex or base64)<textarea name=\"macaroon\" rows=\"4\" class=\"mono\" autocomplete=\"off\" required></textarea></label>",
            App::csrf_input(ctx), if have { "Replace the rail macaroon" } else { "Connect the rail" }));
        if main {
            b.push_str(&format!("<label>To use the rail on mainnet, type: <code>{}</code><input name=\"mainnet_ack\" autocomplete=\"off\" required></label>{}",
                                esc(MAINNET_ACK), if acked { "<p class=\"hint\">Acknowledged before; type it again to replace the macaroon.</p>" } else { "" }));
        }
        b.push_str("<button>Save; the signer restarts to use it</button></form>");
        if have {
            b.push_str(&format!("<form method=\"post\" action=\"./lightning\" class=\"card\">{}<input type=\"hidden\" name=\"action\" value=\"remove\">\
                <h2>Disconnect</h2><p>Removes the macaroon from this box; the wallet then pays nothing over Lightning. Revoke it in the node's \
                dashboard too if it may have been copied.</p><button>Remove the rail macaroon</button></form>", App::csrf_input(ctx)));
        }
        b.push_str("<p class=\"hint\">The policy decides whom the wallet pays and how much: the <a href=\"./policy?template=starter\">starter template</a> \
            turns the rail and stream tickets on with low caps. Each seller goes on the allowlist with its node id.</p>");
        self.page("Lightning", ctx, b)
    }

    pub(crate) fn lightning_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let dir = &self.cfg.ln.dir;
        let ln = &self.cfg.ln;
        let result = match f.get("action").map(String::as_str) {
            Some("pin_cert") => pin_cert(ln.pin, ln.rest.as_deref(), ln.tls_cert.as_deref(), f.get("fingerprint").map(String::as_str).unwrap_or("")),
            Some("remove") => remove_shared(dir, RAIL_MACAROON).map(|had| {
                let _ = remove_shared(dir, MAINNET_ACK_FILE);
                if had { "Rail macaroon removed: the signer restarts without it.".to_string() } else { "There was no rail macaroon.".into() }
            }),
            Some("save") => (|| {
                let chain = self.signer_chain();
                let main = chain == "main";
                if main && f.get("mainnet_ack").map(|a| a.trim()) != Some(MAINNET_ACK) {
                    return Err(format!("on mainnet the rail needs the acknowledgement, word for word: {MAINNET_ACK}"));
                }
                let mac = decode_macaroon(f.get("macaroon").map(String::as_str).unwrap_or("")).map_err(|e| format!("the macaroon: {e}"))?;
                // strict on every chain: the page stores only what the rail needs
                checked_macaroon(&mac, "the rail macaroon", &RAIL_OPS, true).map_err(|e| e.to_string())?;
                if main {
                    write_shared(dir, MAINNET_ACK_FILE, format!("{MAINNET_ACK}\n").as_bytes())?;
                }
                write_shared(dir, RAIL_MACAROON, &mac)?;
                Ok("Rail macaroon saved. The signer restarts to use it; the rail's state below follows in a few seconds.".into())
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
            return Err(format!("the public URL is the https origin buyers use, behind a TLS proxy: {public_url} is not https (plain http only as \
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
        let msat = num("price_msat")?;
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
        b.push_str("<p>Sell a service on this box per piece: buyers pay with stream tickets over Lightning, and the gateway passes each paid \
            request to your service. It needs two macaroons from your Lightning node's dashboard (Lightning Fork: <em>Macaroons</em>), each with \
            exactly these permissions and a root key of its own:</p>");
        b.push_str(&format!("<ul><li>invoices: <code>{}</code></li><li>height: <code>{}</code></li></ul>", INVOICE_OPS.join(" "), INFO_OPS.join(" ")));
        b.push_str(&pin_card(&App::csrf_input(ctx), gw.node_pin, gw.node_rest.as_deref(), gw.node_tls_cert.as_deref(), "./gateway"));
        b.push_str("<section class=\"card\"><h2>Now</h2>");
        let health = gw.health_url.as_deref().map(|u| match crate::app::http_get(u) {
            Ok((200, body)) => format!("<span class=\"tag ok\">running</span> <code>{}</code>", esc(&crate::html::short(body.trim(), 200))),
            Ok((code, _)) => format!("<span class=\"tag bad\">HTTP {code}</span>"),
            Err(e) => format!("<span class=\"tag warn\">not answering</span> {}", esc(&e)),
        });
        b.push_str(&kv(&[
            ("Config", if saved { "<span class=\"tag ok\">saved</span>".into() } else { "<span class=\"tag warn\">none yet: the gateway waits for it</span>".into() }),
            ("Gateway", health.unwrap_or_else(|| "-".into())),
            ("Lightning node", gw.node_rest.as_deref().map(|r| format!("<code>{}</code>", esc(r))).unwrap_or_else(|| "<span class=\"tag bad\">not given by the platform</span>".into())),
            ("Certificate (pinned)", cert_line(gw.node_tls_cert.as_deref())),
            ("Macaroons", format!("invoices {}, height {}", if gw.dir.join(GW_INVOICES).is_file() { "stored" } else { "none" },
                                  if gw.dir.join(GW_INFO).is_file() { "stored" } else { "none" })),
            // what the gateway can know: its node's word on an invoice, never the channel peer's fulfil
            ("Settled", "<code>settled</code> counts the tickets your node settled, by its own word. It is not yet income: the payment                          is yours once the channel peer it came through has taken the preimage, which the gateway does not check".into()),
        ]));
        if let Some(c) = self.current_gateway() {
            b.push_str(&format!("<details><summary>The config the gateway reads</summary>{}</details>", json_block(&c)));
        }
        b.push_str("</section>");
        let main = v.get("chain").map(String::as_str) == Some("main");
        if main {
            b.push_str(&notice_html(&MAINNET_NOTICE));
        }
        let sel = |k: &str, opt: &str| if v.get(k).map(String::as_str) == Some(opt) { " selected" } else { "" };
        b.push_str(&format!("<form method=\"post\" action=\"./gateway\" class=\"card policy\">{}\
            <fieldset><legend>What you sell</legend>\
            <label>Your service, as this box's network reaches it (<code>http://host:port</code>, optionally with a path)\
            <input name=\"upstream\" value=\"{}\" class=\"mono\" required placeholder=\"http://10.21.21.50:8080\"></label>\
            <label>Price, in millisats<input name=\"price_msat\" value=\"{}\" inputmode=\"numeric\" required></label>\
            <label>Per<select name=\"unit\"><option value=\"request\"{}>request</option><option value=\"mib\"{}>MiB sent</option>\
            <option value=\"second\"{}>second of a response</option></select></label></fieldset>\
            <fieldset><legend>How buyers reach it</legend>\
            <label>The https origin buyers use (<code>https://seller.example</code>): a TLS proxy with a public certificate in front of \
            port {} of this app. Plain <code>http://127.0.0.1:{}</code> only for a buyer on the same machine.\
            <input name=\"public_url\" value=\"{}\" class=\"mono\" required></label>\
            <label>Your proxy's address, whose <code>X-Forwarded-For</code> the gateway believes (comma-separated; empty: the per-buyer \
            cap is off behind a proxy)<input name=\"proxies\" value=\"{}\" class=\"mono\"></label></fieldset>\
            <fieldset><legend>Chain</legend><label>Chain<select name=\"chain\"><option value=\"regtest\"{}>a test chain</option>\
            <option value=\"main\"{}>mainnet (real funds)</option></select></label>\
            <label>Test chain only: its network id (<code>lightning:</code> and 32 hex)<input name=\"network\" value=\"{}\" class=\"mono\"></label>\
            <label>Mainnet only: type <code>{}</code><input name=\"mainnet_ack\" autocomplete=\"off\"></label></fieldset>\
            <fieldset><legend>Caps</legend>\
            <label>Buyers at once<input name=\"max_sessions\" value=\"{}\" inputmode=\"numeric\"></label>\
            <label>Buyers at once from one address<input name=\"sessions_per_address\" value=\"{}\" inputmode=\"numeric\"></label>\
            <label>Held tickets in all (1,000 sat each, held on your inbound channels)<input name=\"max_held_tickets\" value=\"{}\" inputmode=\"numeric\"></label>\
            <p class=\"hint\">On mainnet leave these low: {} buyers, {} per address, {} held tickets.</p></fieldset>\
            <fieldset><legend>Macaroons{}</legend>\
            <label>Invoices (hex or base64)<textarea name=\"invoices_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\"></textarea></label>\
            <label>Height (hex or base64)<textarea name=\"info_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\"></textarea></label></fieldset>\
            <button>Check and save; the gateway restarts with it</button></form>",
            App::csrf_input(ctx), g("upstream"), g("price_msat"), sel("unit", "request"), sel("unit", "mib"), sel("unit", "second"),
            gw.port, gw.port, g("public_url"), g("proxies"), sel("chain", "regtest"), sel("chain", "main"), g("network"), esc(MAINNET_ACK),
            g("max_sessions"), g("sessions_per_address"), g("max_held_tickets"), MAINNET_CAPS.0, MAINNET_CAPS.1, MAINNET_CAPS.2,
            if saved { " (leave empty to keep the stored ones)" } else { "" }));
        self.page("Gateway", ctx, b)
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
            for (field, file, ops, what) in [("invoices_macaroon", GW_INVOICES, &INVOICE_OPS[..], "the invoices macaroon"),
                                             ("info_macaroon", GW_INFO, &INFO_OPS[..], "the height macaroon")] {
                let text = f.get(field).map(String::as_str).unwrap_or("").trim().to_string();
                if text.is_empty() {
                    if !dir.join(file).is_file() {
                        return Err(format!("{what} is needed"));
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
            Ok(if main { "Saved, on mainnet with the caps shown. The gateway restarts with it in a few seconds.".into() }
               else { "Saved. The gateway restarts with it in a few seconds.".into() })
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
