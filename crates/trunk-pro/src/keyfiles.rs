//! The decryption keys from the config's `keys` section: a KFDtool encrypted
//! key container, opened with the password in another file. Nothing here
//! prints a key or the password; an error names a file and what is wrong
//! with it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use trunk_app::config::KeysSettings;
use trunk_core::crypto::{ekc, p25, KeyStore};

/// The longest password file read.
const MAX_PASSWORD_FILE: u64 = 4096;

/// Where `file` is: as given when absolute, else beside the config file.
fn resolve(file: &str, config_dir: &Path) -> PathBuf {
    let p = Path::new(file.trim());
    if p.is_absolute() { p.to_path_buf() } else { config_dir.join(p) }
}

/// Secrets mounted by Docker and Kubernetes are root-owned and world-readable
/// inside the one container that has them; their mode is not ours to ask for.
/// Where the file really is decides (a `..` or a link out of the mount doesn't count).
#[cfg(unix)]
fn is_secret_mount(path: &Path) -> bool {
    std::fs::canonicalize(path).is_ok_and(|real| under_secret_mount(&real))
}

/// Whether `real` (a canonical path) is under a secrets mount.
#[cfg(unix)]
fn under_secret_mount(real: &Path) -> bool {
    real.starts_with("/run/secrets") || real.starts_with("/var/run/secrets")
}

/// A password file other users can read is as good as no password: refuse it
/// (as ssh does a private key), on systems that have modes (Windows doesn't).
#[cfg(unix)]
fn check_password_perms(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{}: not a file", path.display()));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 && !is_secret_mount(path) {
        return Err(format!("{}: mode {mode:03o} lets other users read the password; run: chmod 600 {}", path.display(), path.display()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_password_perms(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("{}: not a file", path.display()));
    }
    Ok(())
}

/// The password on the file's first line (its line ending taken off, nothing else).
fn read_password(path: &Path) -> Result<zeroize::Zeroizing<String>, String> {
    check_password_perms(path)?;
    let len = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.len();
    if len > MAX_PASSWORD_FILE {
        return Err(format!("{}: too large for a password file", path.display()));
    }
    let text = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?);
    // (An editor's byte-order mark isn't part of the password.)
    let first = text.strip_prefix('\u{feff}').unwrap_or(&text).split(['\r', '\n']).next().unwrap_or("");
    if first.is_empty() {
        return Err(format!("{}: the first line, the password, is empty", path.display()));
    }
    Ok(zeroize::Zeroizing::new(first.to_string()))
}

/// What loading found: the keys (None: decryption is off), and lines for the log.
pub struct Loaded {
    pub keys: Option<Arc<KeyStore>>,
    /// (is it a problem, text)
    pub notes: Vec<(bool, String)>,
}

/// Read the keys `s` names. An unset section is no decryption, quietly; a
/// section that is set but can't be used is no decryption, and says why.
pub fn load(s: &KeysSettings, config_dir: &Path) -> Loaded {
    let off = |why: String| Loaded { keys: None, notes: vec![(true, format!("Decryption is off: {why}"))] };
    if s.ekc_file.trim().is_empty() {
        return match s.password_file.trim().is_empty() {
            true => Loaded { keys: None, notes: vec![] },
            false => off("keys.passwordFile is set but keys.ekcFile is not".into()),
        };
    }
    if s.password_file.trim().is_empty() {
        return off("keys.passwordFile (the file with the key container's password) is not set".into());
    }
    let (ekc_path, pw_path) = (resolve(&s.ekc_file, config_dir), resolve(&s.password_file, config_dir));
    let file = match std::fs::read(&ekc_path) {
        Ok(f) => f,
        Err(e) => return off(format!("{}: {e}", ekc_path.display())),
    };
    let password = match read_password(&pw_path) {
        Ok(p) => p,
        Err(e) => return off(e),
    };
    let container = match ekc::parse(&file, &password) {
        Ok(c) => c,
        Err(e) => return off(format!("{}: {e}", ekc_path.display())),
    };
    let mut notes = Vec::new();
    let mut keys = container.keys;
    notes.extend(vet(&mut keys));
    for sk in &container.skipped {
        notes.push((false, format!("Key {:?} not loaded: {}", sk.name, sk.reason)));
    }
    notes.push((false, format!("Decryption keys: {} loaded from {}", keys.len(), ekc_path.display())));
    #[cfg(not(unix))]
    notes.push((false, "The password file's permissions are not checked on this system: keep it readable by you alone".to_string()));
    Loaded { keys: (!keys.is_empty()).then(|| Arc::new(keys)), notes }
}

/// Take out the keys that can never decrypt (an algorithm that isn't supported, a
/// size the algorithm doesn't take), saying so for each.
fn vet(keys: &mut KeyStore) -> Vec<(bool, String)> {
    let mut notes = Vec::new();
    for info in keys.list() {
        let len = keys.get(info.algid, info.kid).map_or(0, |k| k.bytes().len());
        let why = match p25::key_len(info.algid) {
            None => "is for an algorithm that is not supported".to_string(),
            Some(want) if want != len => format!("is {len} bytes, not the {want} that algorithm takes"),
            Some(_) => continue,
        };
        notes.push((true, format!("Key {:?} (algorithm {:#04x}, key id {}) {why}; it is not used", info.name, info.algid, info.kid)));
    }
    keys.retain(|k| p25::key_len(k.algid) == Some(k.bytes().len()));
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use trunk_core::crypto::Key;

    // trunk-core's test container: throwaway keys.
    fn ekc_bytes() -> Vec<u8> {
        std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../trunk-core/src/crypto/testdata/dummy-test-keys.ekc")).unwrap()
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("trunk-keyfiles-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(d: &Path, name: &str, data: impl AsRef<[u8]>, mode: u32) -> String {
        let p = d.join(name);
        std::fs::write(&p, data).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let _ = mode;
        name.to_string()
    }

    fn settings(ekc: &str, pw: &str) -> KeysSettings {
        KeysSettings { ekc_file: ekc.into(), password_file: pw.into(), ..Default::default() }
    }

    #[test]
    fn no_keys_section_is_no_decryption_and_no_noise() {
        let l = load(&KeysSettings::default(), Path::new("/nonexistent"));
        assert!(l.keys.is_none() && l.notes.is_empty());
    }

    #[test]
    fn a_container_and_its_password_load_the_supported_keys() {
        let d = dir("ok");
        let (e, p) = (write(&d, "k.ekc", ekc_bytes(), 0o644), write(&d, "k.pw", "testing1234\n", 0o600));
        let l = load(&settings(&e, &p), &d);
        let keys = l.keys.unwrap();
        // The test container holds ADP, AES-256, DES-OFB and a DES-XL key; DES-XL isn't supported.
        assert_eq!(keys.len(), 3);
        assert!(keys.get(0x9f, 1236).is_none());
        assert!(l.notes.iter().any(|(bad, t)| *bad && t.contains("0x9f")));
        assert!(l.notes.iter().any(|(bad, t)| !*bad && t.contains("3 loaded")));
        assert!(l.notes.iter().all(|(_, t)| !t.contains("testing1234")));
    }

    #[test]
    fn a_password_file_with_crlf_or_extra_lines_gives_its_first_line() {
        let d = dir("lines");
        let e = write(&d, "k.ekc", ekc_bytes(), 0o600);
        for (name, body) in [("a.pw", "testing1234\r\n"), ("b.pw", "testing1234\nsecond line\n"), ("c.pw", "testing1234")] {
            let p = write(&d, name, body, 0o600);
            assert!(load(&settings(&e, &p), &d).keys.is_some(), "{name}");
        }
    }

    #[test]
    fn a_byte_order_mark_is_not_part_of_the_password() {
        let d = dir("bom");
        let e = write(&d, "k.ekc", ekc_bytes(), 0o600);
        let p = write(&d, "k.pw", "\u{feff}testing1234\r\n", 0o600);
        assert!(load(&settings(&e, &p), &d).keys.is_some());
    }

    #[test]
    fn keys_that_can_never_decrypt_are_named_and_left_out() {
        let k = |algid: u8, kid: u16, len: usize| Key::new(algid, kid, format!("key{kid}"), 0, true, vec![0; len]);
        let mut s = KeyStore::new();
        for key in [k(0x84, 1, 32), k(0x84, 2, 16), k(0x81, 3, 8), k(0x81, 4, 7), k(0xaa, 5, 5), k(0x83, 6, 24)] {
            s.insert(key);
        }
        let notes = vet(&mut s);
        assert_eq!(s.list().iter().map(|k| k.kid).collect::<Vec<_>>(), [3, 1, 5]);
        assert_eq!(notes.len(), 3);
        assert!(notes.iter().all(|(bad, _)| *bad));
        assert!(notes.iter().any(|(_, t)| t.contains("key2") && t.contains("16 bytes, not the 32")));
        assert!(notes.iter().any(|(_, t)| t.contains("key6") && t.contains("not supported")));
        assert!(notes.iter().all(|(_, t)| !t.contains("0, 0, 0")));
    }

    #[test]
    fn a_wrong_password_turns_decryption_off_and_says_so() {
        let d = dir("wrong");
        let (e, p) = (write(&d, "k.ekc", ekc_bytes(), 0o600), write(&d, "k.pw", "nope", 0o600));
        let l = load(&settings(&e, &p), &d);
        assert!(l.keys.is_none());
        assert!(l.notes[0].1.starts_with("Decryption is off") && l.notes[0].1.contains("could not decrypt"));
    }

    #[test]
    fn half_set_sections_and_missing_files_say_what_is_missing() {
        let d = dir("half");
        let e = write(&d, "k.ekc", ekc_bytes(), 0o600);
        assert!(load(&settings(&e, ""), &d).notes[0].1.contains("passwordFile"));
        assert!(load(&settings("", "k.pw"), &d).notes[0].1.contains("ekcFile"));
        assert!(load(&settings(&e, "missing.pw"), &d).keys.is_none());
        assert!(load(&settings("missing.ekc", "k.pw"), &d).keys.is_none());
        let empty = write(&d, "empty.pw", "\n", 0o600);
        assert!(load(&settings(&e, &empty), &d).notes[0].1.contains("empty"));
    }

    #[cfg(unix)]
    #[test]
    fn a_password_file_others_can_read_is_refused() {
        let d = dir("perms");
        let e = write(&d, "k.ekc", ekc_bytes(), 0o600);
        for mode in [0o644, 0o640, 0o604, 0o666, 0o660] {
            let p = write(&d, "k.pw", "testing1234", mode);
            let l = load(&settings(&e, &p), &d);
            assert!(l.keys.is_none(), "mode {mode:o}");
            assert!(l.notes[0].1.contains("chmod 600"), "{}", l.notes[0].1);
        }
        // Owner-only modes are all right.
        for mode in [0o600, 0o400] {
            let p = write(&d, "k.pw", "testing1234", mode);
            assert!(load(&settings(&e, &p), &d).keys.is_some(), "mode {mode:o}");
        }
    }

    /// Only a file really inside the secrets mount is exempt, by where it is, not by how its path is spelled.
    #[cfg(unix)]
    #[test]
    fn the_secrets_mount_exemption_is_by_real_location() {
        assert!(under_secret_mount(Path::new("/run/secrets/keys_pw")));
        assert!(under_secret_mount(Path::new("/var/run/secrets/kubernetes.io/x")));
        assert!(!under_secret_mount(Path::new("/tmp/run/secrets/x")));
        let d = dir("mount");
        let f = write(&d, "k.pw", "x", 0o644);
        // A file elsewhere isn't exempt however its path is written; nor is one that isn't there.
        assert!(!is_secret_mount(&d.join(&f)));
        assert!(!is_secret_mount(&d.join("sub/../k.pw")));
        assert!(!is_secret_mount(Path::new("/run/secrets/../nonexistent")));
    }
}
