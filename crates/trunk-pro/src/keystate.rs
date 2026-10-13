//! The decryption keys as the running app holds them: loaded from the files the config names, or
//! unlocked with a password typed into the interface (kept in memory only, for as long as the app
//! runs, and wiped by Lock). What this tells a browser is the state and, to the computer's own
//! browser, which keys are held by algorithm, key id and name; never a key or the password.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use trunk_app::config::KeysSettings;
use trunk_core::crypto::KeyStore;

use crate::keyfiles;

/// The least time between two tries at a password.
const TRY_EVERY: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Inner {
    store: Option<Arc<KeyStore>>,
    /// Unlocked by a password typed in (else from the password file).
    from_prompt: bool,
    /// The container the keys are from, as the config names it.
    ekc: String,
    /// Why the files didn't give keys, when the config names both.
    problem: Option<String>,
    /// Counts every change of what is held, for browsers to know to ask again.
    version: u64,
    last_try: Option<Instant>,
    /// Counts every operation that changes what is held (a refresh, a lock, an unlock): an unlock
    /// that was opening the container while one of the others happened is dropped, not applied.
    generation: u64,
}

#[derive(Default)]
pub struct KeyState(Mutex<Inner>);

/// What a refresh or an unlock found: lines for the log (is it a problem, text).
pub type Notes = Vec<(bool, String)>;

impl KeyState {
    /// The keys now held, for a session.
    pub fn store(&self) -> Option<Arc<KeyStore>> {
        self.0.lock().unwrap().store.clone()
    }

    /// Where the key state is: counts every change (a refresh, a lock, an unlock, a config change). Read
    /// it before taking the settings you will act on, and give it back to [`KeyState::refresh_at`] or
    /// [`KeyState::unlock`], so that work begun on settings a newer change has replaced is dropped.
    pub fn generation(&self) -> u64 {
        self.0.lock().unwrap().generation
    }

    /// [`KeyState::refresh`], but only if nothing changed the keys since `started` ([`KeyState::generation`]):
    /// else `s` may be stale, and the newer change has its own refresh coming.
    pub fn refresh_at(&self, started: u64, s: &KeysSettings, config_dir: &Path) -> Notes {
        if self.generation() != started {
            return Notes::new();
        }
        self.refresh_checked(Some(started), s, config_dir)
    }

    /// Bring what is held in line with the config. With a password file the keys are read from
    /// the files; with only a container, what was unlocked by a password stays while the
    /// container is the same one, else it is locked; with neither, nothing is held.
    pub fn refresh(&self, s: &KeysSettings, config_dir: &Path) -> Notes {
        self.refresh_checked(None, s, config_dir)
    }

    fn refresh_checked(&self, started: Option<u64>, s: &KeysSettings, config_dir: &Path) -> Notes {
        let mut g = self.0.lock().unwrap();
        // (Checked again under the lock: a change may have come between the caller's check and here.)
        if started.is_some_and(|n| g.generation != n) {
            return Notes::new();
        }
        // (What the browsers show: which keys, not only how many; a replaced container with as many keys changes it.)
        let shown = |g: &Inner| (g.store.as_ref().map(|k| k.list()), g.from_prompt, g.problem.clone());
        g.generation += 1;
        let before = shown(&g);
        let mut notes = Notes::new();
        if s.ekc_file.trim().is_empty() || s.password_file.trim().is_empty() {
            if !(g.from_prompt && !s.ekc_file.trim().is_empty() && g.ekc == s.ekc_file) {
                g.store = None;
                g.from_prompt = false;
            }
            g.problem = None;
            if s.ekc_file.trim().is_empty() && !s.password_file.trim().is_empty() {
                notes.push((true, "Decryption is off: keys.passwordFile is set but keys.ekcFile is not".into()));
            }
        } else {
            let loaded = keyfiles::load(s, config_dir);
            g.problem = loaded.keys.is_none().then(|| loaded.notes.iter().find(|n| n.0).map_or("no usable keys".to_string(), |n| n.1.clone()));
            g.store = loaded.keys;
            g.from_prompt = false;
            notes = loaded.notes;
        }
        g.ekc = s.ekc_file.clone();
        if before != shown(&g) {
            g.version += 1;
        }
        notes
    }

    /// Open the container the config names with `password`, typed in. The keys are held, in
    /// memory, if it opens; if not, nothing changes. Tries are at least a second apart.
    ///
    /// `started` is [`KeyState::generation`] read BEFORE `s` was taken from the config: if the keys
    /// were changed since (a config change, a lock, a refresh), `s` may be out of date and nothing is installed.
    pub fn unlock(&self, started: u64, s: &KeysSettings, config_dir: &Path, password: &str) -> Result<Notes, String> {
        if s.ekc_file.trim().is_empty() {
            return Err("No key container is set (keys.ekcFile).".into());
        }
        {
            let mut g = self.0.lock().unwrap();
            if g.last_try.is_some_and(|t| t.elapsed() < TRY_EVERY) {
                return Err("Wait a moment before trying again.".into());
            }
            g.last_try = Some(Instant::now());
        }
        if password.is_empty() {
            return Err("Enter the container's password.".into());
        }
        let loaded = keyfiles::open_ekc(&keyfiles::resolve(&s.ekc_file, config_dir), password)?;
        self.commit_unlock(started, s, loaded)
    }

    /// Install what an unlock opened, unless the keys were changed (a lock, a refresh) since it
    /// began at generation `started`: opening the container takes a moment, and what happened in
    /// it wins.
    fn commit_unlock(&self, started: u64, s: &KeysSettings, loaded: keyfiles::Loaded) -> Result<Notes, String> {
        let Some(keys) = loaded.keys else { return Err("The container holds no key this program can use.".into()) };
        let mut g = self.0.lock().unwrap();
        if g.generation != started {
            return Err("The keys were changed while the container was opening; try again.".into());
        }
        g.generation += 1;
        g.store = Some(keys);
        g.from_prompt = true;
        g.ekc = s.ekc_file.clone();
        g.problem = None;
        g.version += 1;
        Ok(loaded.notes)
    }

    /// A change to the keys section of the config is being applied: any unlock still opening a
    /// container is dropped, not installed (call this before anything else is awaited; the refresh
    /// that follows would otherwise be the first thing to invalidate it).
    ///
    /// Returns the generation now: the refresh for this config change is `refresh_at` it, so that
    /// a still newer change drops it.
    pub fn invalidate(&self) -> u64 {
        let mut g = self.0.lock().unwrap();
        g.generation += 1;
        g.generation
    }

    /// Forget what is held (a password file's keys come back at the next refresh). The recorder is
    /// told to take them from every call in progress too.
    pub fn lock(&self) {
        let mut g = self.0.lock().unwrap();
        g.generation += 1;
        if g.store.take().is_some() {
            g.version += 1;
        }
        g.from_prompt = false;
    }

    /// The `keys` message: state only, safe for any browser. `state`: "off" (nothing set),
    /// "locked" (a container, no password yet), "unlocked", "error" (the files didn't open).
    pub fn status_json(&self, s: &KeysSettings) -> Value {
        let g = self.0.lock().unwrap();
        let state = if s.ekc_file.trim().is_empty() {
            "off"
        } else if g.store.is_some() {
            "unlocked"
        } else if g.problem.is_some() {
            "error"
        } else {
            "locked"
        };
        json!({
            "type": "keys",
            "state": state,
            "source": g.store.as_ref().map(|_| if g.from_prompt { "password" } else { "file" }),
            "message": g.problem,
            "count": g.store.as_ref().map_or(0, |k| k.len()),
            "version": g.version,
        })
    }

    /// The `keysList` message: which keys are held, by algorithm, key id and name (not the keys).
    pub fn list_json(&self) -> Value {
        let g = self.0.lock().unwrap();
        let keys: Vec<Value> = g
            .store
            .iter()
            .flat_map(|k| k.list())
            .map(|k| json!({ "algId": k.algid, "keyId": k.kid, "name": k.name, "sln": k.sln, "active": k.active }))
            .collect();
        json!({ "type": "keysList", "version": g.version, "keys": keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("trunk-keystate-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/../trunk-core/src/crypto/testdata/dummy-test-keys.ekc"), d.join("k.ekc")).unwrap();
        d
    }

    fn settings(ekc: &str, pw: &str) -> KeysSettings {
        KeysSettings { ekc_file: ekc.into(), password_file: pw.into(), ..Default::default() }
    }

    fn state(k: &KeyState, s: &KeysSettings) -> String {
        k.status_json(s)["state"].as_str().unwrap().to_string()
    }

    #[test]
    fn nothing_set_is_off_and_a_container_alone_is_locked() {
        let (d, k) = (dir("off"), KeyState::default());
        assert_eq!(state(&k, &settings("", "")), "off");
        k.refresh(&settings("k.ekc", ""), &d);
        assert_eq!(state(&k, &settings("k.ekc", "")), "locked");
        assert!(k.store().is_none());
    }

    #[test]
    fn a_password_unlocks_and_lock_wipes_and_a_wrong_one_changes_nothing() {
        let (d, k) = (dir("unlock"), KeyState::default());
        let s = settings("k.ekc", "");
        k.refresh(&s, &d);
        let version = k.status_json(&s)["version"].as_u64().unwrap();
        assert!(k.unlock(k.generation(), &s, &d, "nope").unwrap_err().contains("could not decrypt"));
        assert_eq!(state(&k, &s), "locked");
        assert_eq!(k.status_json(&s)["version"].as_u64().unwrap(), version);
        // (Tries are spaced.)
        assert!(k.unlock(k.generation(), &s, &d, "testing1234").unwrap_err().contains("Wait"));
        std::thread::sleep(TRY_EVERY + Duration::from_millis(50));
        k.unlock(k.generation(), &s, &d, "testing1234").unwrap();
        let st = k.status_json(&s);
        assert_eq!((st["state"].as_str(), st["source"].as_str(), st["count"].as_u64()), (Some("unlocked"), Some("password"), Some(3)));
        assert!(st["version"].as_u64().unwrap() > version);
        assert!(k.store().is_some());
        // A refresh with the same container keeps what was typed in; another container locks it.
        k.refresh(&s, &d);
        assert!(k.store().is_some());
        k.refresh(&settings("other.ekc", ""), &d);
        assert!(k.store().is_none());
        k.unlock(k.generation(), &s, &d, "testing1234").ok();
        std::thread::sleep(TRY_EVERY + Duration::from_millis(50));
        k.unlock(k.generation(), &s, &d, "testing1234").unwrap();
        k.lock();
        assert_eq!(state(&k, &s), "locked");
        assert!(k.store().is_none());
    }

    #[test]
    fn the_key_list_names_keys_and_the_status_never_does() {
        let (d, k) = (dir("list"), KeyState::default());
        let s = settings("k.ekc", "");
        std::thread::sleep(Duration::from_millis(10));
        k.unlock(k.generation(), &s, &d, "testing1234").unwrap();
        let list = k.list_json();
        assert_eq!(list["keys"].as_array().unwrap().len(), 3);
        assert!(list["keys"][0]["name"].is_string());
        let status = k.status_json(&s).to_string();
        assert!(!status.contains("Key\"") && !status.contains("AES"), "{status}");
        // Nothing in either is key material: 32-hex-digit runs.
        for text in [status, list.to_string()] {
            assert!(!text.as_bytes().windows(16).any(|w| w.iter().all(u8::is_ascii_hexdigit)), "{text}");
        }
    }

    #[test]
    fn a_password_file_is_read_at_refresh_and_a_bad_one_is_an_error_state() {
        let (d, k) = (dir("file"), KeyState::default());
        std::fs::write(d.join("good.pw"), "testing1234\n").unwrap();
        std::fs::write(d.join("bad.pw"), "nope\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["good.pw", "bad.pw"] {
                std::fs::set_permissions(d.join(f), std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let good = settings("k.ekc", "good.pw");
        k.refresh(&good, &d);
        let st = k.status_json(&good);
        assert_eq!((st["state"].as_str(), st["source"].as_str()), (Some("unlocked"), Some("file")));
        let bad = settings("k.ekc", "bad.pw");
        let notes = k.refresh(&bad, &d);
        assert_eq!(state(&k, &bad), "error");
        assert!(k.status_json(&bad)["message"].as_str().unwrap().contains("Decryption is off"));
        assert!(notes.iter().any(|n| n.0));
    }

    /// A lock (or a refresh) that happens while an unlock is opening the container beats it.
    #[test]
    fn an_unlock_does_not_undo_a_lock_that_came_after_it_began() {
        let (d, k) = (dir("race"), KeyState::default());
        let s = settings("k.ekc", "");
        let open = || keyfiles::open_ekc(&d.join("k.ekc"), "testing1234").unwrap();
        // An unlock begins, a lock lands while it opens the container, then it tries to install.
        let started = k.0.lock().unwrap().generation;
        let loaded = open();
        k.lock();
        assert!(k.commit_unlock(started, &s, loaded).unwrap_err().contains("changed while"));
        assert!(k.store().is_none(), "the lock stands");
        // Likewise a refresh (a config change) in the meantime.
        let started = k.0.lock().unwrap().generation;
        let loaded = open();
        k.refresh(&settings("other.ekc", ""), &d);
        assert!(k.commit_unlock(started, &s, loaded).is_err());
        assert!(k.store().is_none());
        // And a config change that is being applied (`invalidate`, before its refresh runs).
        let started = k.0.lock().unwrap().generation;
        let loaded = open();
        k.invalidate();
        assert!(k.commit_unlock(started, &s, loaded).is_err());
        // With nothing in between it takes.
        let started = k.0.lock().unwrap().generation;
        k.commit_unlock(started, &s, open()).unwrap();
        assert!(k.store().is_some());
    }

    /// A reload of settings that a newer config change has replaced is dropped, not applied after it.
    #[test]
    fn a_stale_refresh_does_not_overwrite_a_newer_one() {
        let (d, k) = (dir("stale"), KeyState::default());
        std::fs::write(d.join("pw"), "testing1234\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join("pw"), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let old = settings("k.ekc", "pw");
        let new = settings("", "");
        // The old config's reload begins; a new config (no keys) is applied and refreshed first.
        let started_old = k.generation();
        let started_new = k.invalidate();
        k.refresh_at(started_new, &new, &d);
        assert!(k.store().is_none());
        // Then the old one's reload gets its turn: it must not bring the old keys back.
        assert!(k.refresh_at(started_old, &old, &d).is_empty());
        assert!(k.store().is_none(), "the newer config stands");
        // Two config changes in a row: the first one's refresh is dropped.
        let first = k.invalidate();
        let second = k.invalidate();
        assert!(k.refresh_at(first, &old, &d).is_empty() && k.store().is_none());
        k.refresh_at(second, &old, &d);
        assert!(k.store().is_some(), "the latest change's own refresh applies");
    }
}
