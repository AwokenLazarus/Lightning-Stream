//! The Backups and recovery page: what to save, what is lost without it, and how to get back in.
//!
//! It states only what the app and its docs do: no secret is shown or offered here. Where the app can tell
//! whether an item exists (the approval key, the password, encrypted keys) a pill says so; the shop and
//! listing keys live in other services' folders, which this page cannot see, so it says where they are.

use serde_json::json;

use super::{Ctx, App};
use crate::html::esc;
use crate::server::Resp;

const OK: &str = "<span class=\"tag ok\">saved on this box</span>";

fn item(title: &str, pill: &str, what: &str, lose: &str, save: &str, restore: &str) -> String {
    format!("<section class=\"card\"><h2>{} {pill}</h2><p>{what}</p><p><strong>Without it:</strong> {lose}</p>\
             <p><strong>How to save it:</strong> {save}</p><p><strong>How to get it back:</strong> {restore}</p></section>", esc(title))
}

impl App {
    pub(crate) fn backups_page(&self, ctx: &Ctx) -> Resp {
        let ks = self.call("keystore_status", json!({})).ok();
        let human = ks.as_ref().and_then(|k| k["human_pubkey"].as_str()).unwrap_or("").to_string();
        let approval_pill = match &ks {
            None => String::new(),
            Some(_) if human.is_empty() => "<span class=\"tag bad\">not made yet</span>".to_string(),
            Some(_) => "<span class=\"tag ok\">made</span>".to_string(),
        };
        let password_pill = if self.cfg.password.is_some() {
            "<span class=\"tag ok\">set by your platform</span>".to_string()
        } else if self.cfg.data_dir.join("password.scrypt").is_file() {
            OK.to_string()
        } else {
            "<span class=\"tag bad\">not set</span>".to_string()
        };
        let encrypted_pill = match &ks {
            Some(k) if k["encrypted"] == true => "<span class=\"tag ok\">encrypted</span>".to_string(),
            Some(_) => "<span class=\"tag bad\">not encrypted (test mode)</span>".to_string(),
            None => String::new(),
        };
        let mut b = String::from("<p class=\"lead\">What to save, and how to get back in if something is lost. Nothing secret is shown on this page.</p>");
        b.push_str(&item("Your Lightning node's recovery words and channel backup", "",
            "These belong to your node, in the Lightning Fork app, not to this app. This app does not hold them and cannot show them.",
            "If the node is lost, so are the coins in it and in its channels.",
            "Open the Lightning Fork app and save its recovery words and its channel backup there.",
            "Restore the node in Lightning Fork, with its words and its channel backup. This app then connects to it again on <a href=\"./lightning\">Your node</a>."));
        b.push_str(&item("Your approval key", &approval_pill,
            "The key in your browser that signs your spending rules and approves payments.",
            "You can no longer approve payments or change your rules until you replace the key.",
            "On <a href=\"./keys\">Keys and backup</a>, download the approval key backup when you make the key. Keep it off this computer: a USB stick or paper.",
            "On <a href=\"./keys\">Keys and backup</a>, open <em>Put the enrolled key in this browser</em> and use the backup. It is the key itself, so keep it private. \
             If the backup is gone too, the same page can replace the key, but only with the old key's signature, so there is no way back without one of the two."));
        b.push_str(&item("The app password", &password_pill,
            "The password you type to open this app.",
            "You cannot log in.",
            "Nothing to save but the password. Keep it in a password manager.",
            "Umbrel sets the password: it is shown on the app's page in the Umbrel dashboard. \
             On StartOS, run <em>Reset the web UI password</em>, then <em>Web UI setup code</em>, and choose a new one. \
             On Linux, the password is the <code>LS_UI_PASSWORD</code> line in the <code>.env</code> file of your install folder."));
        b.push_str(&item("Your shop and listing keys", "",
            "Each public listing (your shop, your hashrate, your VPN exit) is signed with a Nostr key kept in a file in the data folder: \
             <code>gateway/nostr.key</code>, <code>hashrate/nostr.key</code> and <code>vpn/nostr.key</code>. This page cannot see those folders, so it cannot say if a file is there.",
            "The listing stays public and you cannot withdraw it. You can make a new key, which publishes a new listing. Relays drop the old one in time.",
            "They are part of the data folder below, so a backup of the folder keeps them. Save the folder before you reinstall or throw this box away.",
            "Put the file back in the same place in the data folder, then start the app again."));
        b.push_str(&item("The wallet's own files", &encrypted_pill,
            "Your spending rules, the sealed keys for the money on this box, the channel book and the records. They are encrypted, and the backup is locked with a passphrase you choose.",
            "The rules and the records are gone. Money held on this box, and the ticket history that makes you the same buyer at every shop, would be lost too.",
            "On <a href=\"./keys\">Keys and backup</a>, use <em>Sign and download the backup</em>. The data folder below holds the same files.",
            "This app has no restore button for that file. Restoring it takes help: put the files back under the wallet's folder and open the sealed key with the passphrase. \
             A platform backup (Umbrel, StartOS) or a copy of the data folder brings it all back at once."));
        b.push_str(&item("The data folder", "",
            "Everything this app keeps: the wallet's files, the shop and listing keys, the password hash and your settings.",
            "A reinstall starts from nothing: new keys, a new buyer at every shop, and listings you cannot withdraw.",
            "On Umbrel and StartOS, the platform's own backup carries it. On Linux, copy the <code>data</code> folder of your install folder (or the folder named by <code>LS_DATA_DIR</code>) while the app is stopped.",
            "Restore the platform backup, or put the folder back where it was, and start the app."));
        b.push_str("<section class=\"card\"><h2>Not shown here</h2><p>The app does not yet say when each item was last saved. Save them again whenever you change a key.</p></section>");
        self.page("Backups", ctx, b)
    }
}
