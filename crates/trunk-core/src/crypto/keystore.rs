//! The keys a recorder can decrypt with, found the way a keyloaded radio or
//! console finds them: by the algorithm id and key id a transmission names.

use std::collections::HashMap;
use std::fmt;

use zeroize::Zeroizing;

/// A traffic key. Its bytes are wiped when it's dropped, and it never prints.
pub struct Key {
    /// P25 algorithm id (0x81 DES-OFB, 0x84 AES-256, 0xAA ADP, …).
    pub algid: u8,
    /// Key id: what the air names.
    pub kid: u16,
    /// The operator's name for it (informational).
    pub name: String,
    /// Storage location number it was loaded under (informational).
    pub sln: u32,
    /// Its keyset is the one in use (a rekey leaves the old one as well).
    pub active: bool,
    bytes: Zeroizing<Vec<u8>>,
}

impl Key {
    pub fn new(algid: u8, kid: u16, name: String, sln: u32, active: bool, bytes: Vec<u8>) -> Self {
        Key { algid, kid, name, sln, active, bytes: Zeroizing::new(bytes) }
    }

    /// The key material, for a cipher.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key {{ algid: {:#04x}, kid: {}, name: {:?}, {} bytes }}", self.algid, self.kid, self.name, self.bytes.len())
    }
}

/// What a key is, without the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub algid: u8,
    pub kid: u16,
    pub name: String,
    pub sln: u32,
    pub active: bool,
}

#[derive(Default)]
pub struct KeyStore {
    keys: HashMap<(u8, u16), Key>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key. When the same algorithm and key id are loaded twice (in
    /// two keysets), the one in the active keyset is kept; between two
    /// alike, the first. Returns false when the key was not kept.
    pub fn insert(&mut self, key: Key) -> bool {
        match self.keys.get(&(key.algid, key.kid)) {
            Some(have) if have.active || !key.active => false,
            _ => {
                self.keys.insert((key.algid, key.kid), key);
                true
            }
        }
    }

    /// The key a transmission names.
    pub fn get(&self, algid: u8, kid: u16) -> Option<&Key> {
        self.keys.get(&(algid, kid))
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether any key is held for the algorithm.
    pub fn has_algorithm(&self, algid: u8) -> bool {
        self.keys.keys().any(|&(a, _)| a == algid)
    }

    /// The keys held, without their bytes, in algorithm and key id order.
    pub fn list(&self) -> Vec<KeyInfo> {
        let mut v: Vec<KeyInfo> = self.keys.values().map(|k| KeyInfo { algid: k.algid, kid: k.kid, name: k.name.clone(), sln: k.sln, active: k.active }).collect();
        v.sort_by_key(|k| (k.algid, k.kid));
        v
    }
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyStore({} keys)", self.keys.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kid: u16, active: bool, b: u8) -> Key {
        Key::new(0x84, kid, format!("k{kid}"), 0, active, vec![b; 32])
    }

    #[test]
    fn active_keyset_wins_a_duplicate() {
        let mut s = KeyStore::new();
        assert!(s.insert(key(7, false, 1)));
        assert!(s.insert(key(7, true, 2)));
        assert!(!s.insert(key(7, false, 3)));
        assert!(!s.insert(key(7, true, 4)));
        assert_eq!(s.get(0x84, 7).unwrap().bytes()[0], 2);
        assert_eq!(s.len(), 1);
        assert!(s.get(0x81, 7).is_none());
        assert!(s.has_algorithm(0x84) && !s.has_algorithm(0x81));
    }

    #[test]
    fn debug_never_shows_key_bytes() {
        let mut s = KeyStore::new();
        s.insert(key(1, true, 0xab));
        assert!(!format!("{:?}{:?}", s, s.get(0x84, 1).unwrap()).contains("ab"));
    }
}
