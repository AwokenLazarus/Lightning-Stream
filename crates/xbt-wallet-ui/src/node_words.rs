//! What the pages say when the XBT node does not give the app what it needs, in one place so the Hashrate card, the
//! checklist and the wallet's flash agree. The signer's `node_status` says why in a word (`problem`); the cause matters
//! because the owner fixes each in a different place: a node that is stopped or at another address is not a node that
//! is running and has refused the app's user name or password (0.2.x said "cannot reach" for both, and the owner
//! looked at the node, which was fine). No user name, password or cookie is ever put in these words.
use serde_json::Value;

/// Why the node is not giving the app what it needs.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Trouble {
    /// Nothing answers: stopped, or the address or port the app has for it is wrong.
    NoConnection,
    /// It answers and refuses the app's user name or password.
    LoginRefused,
    /// It answers that it is still loading.
    Starting,
    /// It answers, and is still catching up with the network.
    Syncing,
    /// It answers and refuses the call, or the signer's words are an older kind.
    Other,
}

/// The trouble, from the signer's `node_status`; `None` when the node is fine, or when its state is not known (the
/// signer itself did not answer: the pages say that elsewhere).
pub fn trouble(status: &Result<Value, String>) -> Option<Trouble> {
    let n = status.as_ref().ok()?;
    if n["reachable"] == true {
        return (n["syncing"] == true).then_some(Trouble::Syncing);
    }
    Some(match n["problem"].as_str() {
        Some("login_refused") => Trouble::LoginRefused,
        Some("starting") => Trouble::Starting,
        Some("no_connection") => Trouble::NoConnection,
        _ => Trouble::Other,
    })
}

/// The words, plain, for the owner. `login_fix` is where to correct the login on this platform (`XBT_UI_NODE_LOGIN_HINT`).
/// Plain text: the caller escapes it.
pub fn words(t: Trouble, login_fix: &str) -> String {
    match t {
        Trouble::NoConnection => "The app cannot connect to your XBT node. Either the node is not running, or the address or port the app has for it is wrong. \
                                  Start the node, or correct its address and port in the app's settings.".into(),
        Trouble::LoginRefused => format!("Your XBT node is running, but it refused the app's user name or password. The node is fine: the login the app uses \
                                          does not match the one the node expects. {login_fix}"),
        Trouble::Starting => "Your XBT node is running but still starting up. Give it a few minutes.".into(),
        Trouble::Syncing => "Your XBT node answers, but it is still catching up with the network. Give it time to finish.".into(),
        Trouble::Other => "Your XBT node answers, but it refused what the app asked. Check the node's own log.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_signers_word_picks_the_trouble() {
        let ok = |v: Value| Ok::<Value, String>(v);
        assert_eq!(trouble(&ok(json!({"reachable": true, "height": 5, "syncing": false}))), None);
        assert_eq!(trouble(&ok(json!({"reachable": true, "height": 5}))), None, "an older signer says nothing of syncing");
        assert_eq!(trouble(&ok(json!({"reachable": true, "syncing": true}))), Some(Trouble::Syncing));
        assert_eq!(trouble(&ok(json!({"reachable": false, "problem": "login_refused"}))), Some(Trouble::LoginRefused));
        assert_eq!(trouble(&ok(json!({"reachable": false, "problem": "no_connection"}))), Some(Trouble::NoConnection));
        assert_eq!(trouble(&ok(json!({"reachable": false, "problem": "starting"}))), Some(Trouble::Starting));
        assert_eq!(trouble(&ok(json!({"reachable": false}))), Some(Trouble::Other));
        assert_eq!(trouble(&Err("signer down".into())), None);
    }

    #[test]
    fn the_words_differ_and_stay_plain() {
        let all = [Trouble::NoConnection, Trouble::LoginRefused, Trouble::Starting, Trouble::Syncing, Trouble::Other];
        let said: Vec<String> = all.iter().map(|t| words(*t, "Fix it there.")).collect();
        for (i, a) in said.iter().enumerate() {
            for b in &said[i + 1..] {
                assert_ne!(a, b);
            }
            assert!(!a.contains("401") && !a.contains("RPC"), "{a}");
        }
        assert!(said[1].contains("running") && said[1].contains("refused") && said[1].contains("Fix it there."), "{}", said[1]);
        assert!(!said[0].contains("refused"), "a node that is away is not one that refused");
    }
}
