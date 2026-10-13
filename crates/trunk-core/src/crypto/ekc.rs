//! KFDtool's encrypted key container (`.ekc`), read: bytes and a password in,
//! a [`KeyStore`] out. No I/O, so it runs in the browser too.
//!
//! The file is a little-endian u32 (the length of the XML), then the outer
//! XML compressed. KFDtool writes gzip; the file we were given is zlib, so
//! gzip, zlib and bare deflate are all taken. The XML names a PBKDF2
//! key derivation (HMAC-SHA512, with its own salt and iteration count) and
//! holds an XML-Enc `EncryptedData`: AES-256-CBC, the IV the first 16 bytes
//! of the cipher value, wrapping the inner XML with the keys.
//! From KFDtool's `ContainerUtilities.cs` (MIT) and checked against a
//! container it wrote.

use std::fmt;
use std::io::Read;

use aes::Aes256;
use base64::Engine;
use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use roxmltree::{Document, Node};
use sha2::Sha512;
use zeroize::Zeroizing;

use super::{Key, KeyStore};

const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
/// The most XML taken from a file (real containers are a few KiB).
const MAX_XML: u64 = 16 << 20;
/// The most PBKDF2 iterations honored: KFDtool writes 100 000.
const MAX_ITERATIONS: u32 = 10_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum EkcError {
    /// Not a container: too short, or not compressed XML.
    NotAContainer(String),
    /// A newer container version, or a cipher or key derivation not read.
    Unsupported(String),
    /// The cipher text did not decrypt to a key container.
    WrongPasswordOrCorrupt,
}

impl fmt::Display for EkcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EkcError::NotAContainer(e) => write!(f, "not a key container: {e}"),
            EkcError::Unsupported(e) => write!(f, "unsupported key container: {e}"),
            EkcError::WrongPasswordOrCorrupt => f.write_str("could not decrypt the key container (wrong password, or a damaged file)"),
        }
    }
}

impl std::error::Error for EkcError {}

/// A key in the container that was not loaded, and why (never the key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub reason: &'static str,
}

/// What a container held.
#[derive(Debug)]
pub struct Container {
    pub keys: KeyStore,
    pub skipped: Vec<Skipped>,
}

fn bad(e: impl fmt::Display) -> EkcError {
    EkcError::NotAContainer(e.to_string())
}

fn decompress(data: &[u8]) -> Result<Vec<u8>, EkcError> {
    let mut out = Vec::new();
    let r = if data.starts_with(&[0x1f, 0x8b]) {
        flate2::read::GzDecoder::new(data).take(MAX_XML + 1).read_to_end(&mut out)
    } else if data.len() >= 2 && data[0] & 0x0f == 8 && (u16::from(data[0]) << 8 | u16::from(data[1])).is_multiple_of(31) {
        flate2::read::ZlibDecoder::new(data).take(MAX_XML + 1).read_to_end(&mut out)
    } else {
        flate2::read::DeflateDecoder::new(data).take(MAX_XML + 1).read_to_end(&mut out)
    };
    r.map_err(|e| bad(format!("decompressing: {e}")))?;
    if out.len() as u64 > MAX_XML {
        return Err(bad("larger than a key container can be"));
    }
    Ok(out)
}

fn child<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| c.is_element() && c.tag_name().name() == name)
}

fn text<'a>(n: Node<'a, '_>, name: &str) -> Result<&'a str, EkcError> {
    child(n, name).and_then(|c| c.text()).map(str::trim).ok_or_else(|| bad(format!("no {name}")))
}

fn check_version(root: Node, what: &str) -> Result<(), EkcError> {
    let v = root.attribute("version").ok_or_else(|| bad(format!("{what} has no version")))?;
    match v.split('.').next().and_then(|m| m.parse::<u32>().ok()) {
        Some(1) => Ok(()),
        _ => Err(EkcError::Unsupported(format!("{what} version {v} (this reads 1.x)"))),
    }
}

fn b64(s: &str) -> Result<Vec<u8>, EkcError> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(s).map_err(bad)
}

fn hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Read a container with its password.
pub fn parse(file: &[u8], password: &str) -> Result<Container, EkcError> {
    if file.len() < 5 {
        return Err(bad("too short"));
    }
    let xml = decompress(&file[4..])?;
    let xml = std::str::from_utf8(&xml).map_err(bad)?;
    let doc = Document::parse(xml).map_err(bad)?;
    let root = doc.root_element();
    if root.tag_name().name() != "OuterContainer" {
        return Err(bad("no OuterContainer"));
    }
    check_version(root, "outer container")?;

    let kd = child(root, "KeyDerivation").ok_or_else(|| bad("no KeyDerivation"))?;
    let (alg, hash) = (text(kd, "DerivationAlgorithm")?, text(kd, "HashAlgorithm")?);
    if alg != "PBKDF2" || hash != "SHA512" {
        return Err(EkcError::Unsupported(format!("key derivation {alg} with {hash}")));
    }
    let salt = b64(text(kd, "Salt")?)?;
    let iterations: u32 = text(kd, "IterationCount")?.parse().map_err(bad)?;
    let key_len: usize = text(kd, "KeyLength")?.parse().map_err(bad)?;
    if iterations == 0 || iterations > MAX_ITERATIONS || key_len != 32 {
        return Err(EkcError::Unsupported(format!("{iterations} iterations, {key_len}-byte key")));
    }

    let enc = child(root, "EncryptedData").ok_or_else(|| bad("no EncryptedData"))?;
    let method = child(enc, "EncryptionMethod").and_then(|m| m.attribute("Algorithm")).unwrap_or("");
    if method != AES256_CBC {
        return Err(EkcError::Unsupported(format!("cipher {method}")));
    }
    let cipher_value = child(enc, "CipherData").and_then(|c| child(c, "CipherValue")).and_then(|c| c.text()).ok_or_else(|| bad("no CipherValue"))?;
    let cv = b64(cipher_value)?;
    if cv.len() < 32 || !cv.len().is_multiple_of(16) {
        return Err(bad("cipher text is not whole AES blocks"));
    }
    let (iv, ct) = cv.split_at(16);

    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt, iterations, &mut key[..]);
    let mut plain = Zeroizing::new(ct.to_vec());
    cbc::Decryptor::<Aes256>::new_from_slices(&key[..], iv)
        .map_err(bad)?
        .decrypt_padded::<NoPadding>(&mut plain)
        .map_err(|_| EkcError::WrongPasswordOrCorrupt)?;
    // The pad length is the last byte (PKCS7, and the same count under
    // ISO 10126, whose other pad bytes are random: not checked).
    let pad = *plain.last().ok_or(EkcError::WrongPasswordOrCorrupt)? as usize;
    if pad == 0 || pad > 16 || pad > plain.len() {
        return Err(EkcError::WrongPasswordOrCorrupt);
    }
    let keep = plain.len() - pad;
    plain.truncate(keep);
    let inner_xml = Zeroizing::new(String::from_utf8(plain.to_vec()).map_err(|_| EkcError::WrongPasswordOrCorrupt)?);
    let inner = Document::parse(&inner_xml).map_err(|_| EkcError::WrongPasswordOrCorrupt)?;
    let inner_root = inner.root_element();
    if inner_root.tag_name().name() != "InnerContainer" {
        return Err(EkcError::WrongPasswordOrCorrupt);
    }
    check_version(inner_root, "inner container")?;

    let mut out = Container { keys: KeyStore::new(), skipped: Vec::new() };
    let Some(keys) = child(inner_root, "Keys") else { return Ok(out) };
    for item in keys.children().filter(Node::is_element) {
        let field = |n: &str| item.children().find(|c| c.is_element() && c.tag_name().name() == n).and_then(|c| c.text()).map(str::trim);
        let name = field("Name").unwrap_or("").to_string();
        let flag = |n: &str| field(n) == Some("true");
        let mut skip = |reason| out.skipped.push(Skipped { name: name.clone(), reason });
        // A key-encryption key wraps other keys over the air; it decrypts no voice.
        if flag("KeyTypeKek") {
            skip("a key-encryption key");
            continue;
        }
        let (Some(algid), Some(kid)) = (field("AlgorithmId").and_then(|v| v.parse::<u8>().ok()), field("KeyId").and_then(|v| v.parse::<u16>().ok())) else {
            skip("an algorithm id or key id out of range");
            continue;
        };
        let Some(bytes) = field("Key").and_then(hex) else {
            skip("key bytes that are not hex");
            continue;
        };
        let sln = field("Sln").and_then(|v| v.parse().ok()).unwrap_or(0);
        if !out.keys.insert(Key::new(algid, kid, name.clone(), sln, flag("ActiveKeyset"), bytes)) {
            skip("a second key for the same algorithm and key id");
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway container made with KFDtool for testing; its keys protect nothing.
    const FILE: &[u8] = include_bytes!("testdata/dummy-test-keys.ekc");
    const PASSWORD: &str = "testing1234";

    #[test]
    fn reads_a_kfdtool_container() {
        let c = parse(FILE, PASSWORD).unwrap();
        assert!(c.skipped.is_empty());
        let list = c.keys.list();
        let got: Vec<(u8, u16, &str)> = list.iter().map(|k| (k.algid, k.kid, k.name.as_str())).collect();
        assert_eq!(got, [(0x81, 1237, "DES-OFB_Key"), (0x84, 1235, "AES-256_Key"), (0x9f, 1236, "DES-XL_Key"), (0xaa, 1234, "ADP_Key")]);
        // ADP is a 40-bit key, DES a 56-bit one in 8 bytes, AES-256 32 bytes.
        let len = |a, k| c.keys.get(a, k).unwrap().bytes().len();
        assert_eq!((len(0xaa, 1234), len(0x84, 1235), len(0x9f, 1236), len(0x81, 1237)), (5, 32, 8, 8));
        assert!(c.keys.get(0x84, 1234).is_none());
    }

    #[test]
    fn a_wrong_password_is_refused() {
        assert_eq!(parse(FILE, "testing1235").unwrap_err(), EkcError::WrongPasswordOrCorrupt);
        assert_eq!(parse(FILE, "").unwrap_err(), EkcError::WrongPasswordOrCorrupt);
    }

    #[test]
    fn damaged_files_are_errors_not_panics() {
        assert!(matches!(parse(b"", PASSWORD), Err(EkcError::NotAContainer(_))));
        assert!(matches!(parse(b"hello, world", PASSWORD), Err(EkcError::NotAContainer(_))));
        for cut in [5, 40, FILE.len() / 2, FILE.len() - 1] {
            assert!(parse(&FILE[..cut], PASSWORD).is_err());
        }
        let mut flipped = FILE.to_vec();
        let at = flipped.len() / 2;
        flipped[at] ^= 0x55;
        assert!(parse(&flipped, PASSWORD).is_err());
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(hex("00ff7A"), Some(vec![0, 255, 0x7a]));
        assert_eq!(hex(" 01 "), Some(vec![1]));
        assert_eq!(hex("abc"), None);
        assert_eq!(hex("zz"), None);
        assert_eq!(hex(""), None);
    }
}
