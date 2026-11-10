//! What the owner chose for this box's pages: the simple view (Wallet, Shops, Limits, Activity) or
//! every page, and the shops kept as favorites. One small file in the app's data folder; it holds no
//! secret and nothing a payment depends on, so a missing or unreadable file is the defaults.
use serde_json::{json, Value};
use std::path::Path;

pub const FILE: &str = "ui-prefs.json";

/// What a box whose owner never chose shows. Every page, until the simple view is the default for
/// everyone (it becomes that in the release that rolls simple mode out).
pub const ADVANCED_BY_DEFAULT: bool = true;

/// The most favorites kept: a page lists them all.
pub const MAX_FAVORITES: usize = 100;

#[derive(Clone, Debug, PartialEq)]
pub struct Prefs {
    /// Every page (buying, selling, setup) in the menu; off is the simple view.
    pub advanced: bool,
    /// Favorite shops, by origin, in the order they were added.
    pub favorites: Vec<String>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self { advanced: ADVANCED_BY_DEFAULT, favorites: Vec::new() }
    }
}

impl Prefs {
    pub fn is_favorite(&self, origin: &str) -> bool {
        self.favorites.iter().any(|f| f == origin)
    }

    /// Add or remove a favorite. `false`: the list is full, nothing added.
    pub fn set_favorite(&mut self, origin: &str, on: bool) -> bool {
        self.favorites.retain(|f| f != origin);
        if on {
            if self.favorites.len() >= MAX_FAVORITES {
                return false;
            }
            self.favorites.push(origin.to_string());
        }
        true
    }
}

pub fn load(path: &Path) -> Prefs {
    let Some(v) = std::fs::read(path).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { return Prefs::default() };
    Prefs {
        advanced: v["advanced"].as_bool().unwrap_or(ADVANCED_BY_DEFAULT),
        favorites: v["favorites"].as_array().map(|a| a.iter().filter_map(|f| f.as_str().map(str::to_string)).take(MAX_FAVORITES).collect()).unwrap_or_default(),
    }
}

/// Written whole beside the file, then moved over it: a reader never sees half a file.
pub fn save(path: &Path, p: &Prefs) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(&json!({"advanced": p.advanced, "favorites": p.favorites})).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, path)).map_err(|e| format!("could not save your choice: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_choice_is_kept_and_a_missing_or_broken_file_is_the_defaults() {
        let dir = std::env::temp_dir().join(format!("ls-prefs-{}-{}", std::process::id(), crate::now()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE);
        assert_eq!(load(&path), Prefs::default());
        let mut p = Prefs { advanced: !ADVANCED_BY_DEFAULT, favorites: Vec::new() };
        assert!(p.set_favorite("https://a.example", true));
        assert!(p.set_favorite("https://b.example", true));
        assert!(p.set_favorite("https://a.example", true), "adding twice keeps one");
        assert_eq!(p.favorites, ["https://b.example", "https://a.example"]);
        save(&path, &p).unwrap();
        assert_eq!(load(&path), p);
        assert!(p.set_favorite("https://b.example", false));
        assert!(!p.is_favorite("https://b.example") && p.is_favorite("https://a.example"));
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(load(&path), Prefs::default());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_list_of_favorites_has_an_end() {
        let mut p = Prefs::default();
        for i in 0..MAX_FAVORITES {
            assert!(p.set_favorite(&format!("https://{i}.example"), true));
        }
        assert!(!p.set_favorite("https://one-more.example", true));
        assert_eq!(p.favorites.len(), MAX_FAVORITES);
    }
}
