//! P25 voice decryption, Phase 1 and Phase 2: TIA-102.AAAD (Block Encryption
//! Protocol) for DES-OFB (ALGID 0x81) and AES-256 (0x84), and Motorola's ADP
//! (0xAA, RC4, not in that standard).
//!
//! Phase 2 TDMA (see [`Keystream::apply_tdma`]) uses the same keystream, with
//! 18 voice frames of 7 octets in a superframe (TIA-102.AAAD-B). DES-OFB and
//! AES-256 are checked against that standard's worked examples; ADP on Phase 2
//! follows the layout op25 and DSD-FME share.
//!
//! A superframe (an LDU1 and an LDU2) carries 213 octets that are encrypted,
//! numbered 1 to 213 in the standard's tables 5-2, 5-5 and 5-6: 3 reserved,
//! the 8 octets of link control, the 18 IMBE frames of 11 octets, and 4 octets
//! of low-speed data between frames 8 and 9 and between 17 and 18. They are
//! XORed with a keystream; this module makes that keystream
//! ([`Keystream`]) from a key and the message indicator, and tracks which MI
//! a call is on ([`Decryptor`]). Only the 88 information bits of each IMBE
//! frame (u0..u7, after FEC) are encrypted: [`imbe_params_to_bits`] gives
//! them in the order of the standard's octets w0..w10.
//!
//! [`imbe_params_to_bits`]: crate::p25::voice::imbe_params_to_bits

use std::fmt;
use std::sync::Arc;

use aes::Aes256;
use cbc::cipher::{BlockCipherEncrypt, KeyInit};
use des::Des;
use zeroize::{Zeroize, Zeroizing};

use super::KeyStore;
use crate::p25::voice::{EncryptionSync, ALGID_CLEAR};

pub const ALGID_DES_OFB: u8 = 0x81;
pub const ALGID_AES256: u8 = 0x84;
pub const ALGID_ADP: u8 = 0xaa;

/// Encrypted octets in a superframe.
pub const SUPERFRAME_OCTETS: usize = 213;

/// The message indicator as sent: 9 octets, the last reserved (zero).
pub type Mi = [u8; 9];

/// The first 64 bits of an MI: the LFSR's register.
fn lfsr_of(mi: &Mi) -> u64 {
    u64::from_be_bytes(mi[..8].try_into().unwrap())
}

fn mi_of(lfsr: u64) -> Mi {
    let mut mi = [0; 9];
    mi[..8].copy_from_slice(&lfsr.to_be_bytes());
    mi
}

/// One shift of the MI generator (standard figure 3-1): C(x) = 1 + x^15 +
/// x^27 + x^38 + x^46 + x^62 + x^64, the new bit entering at stage 1, the
/// register's least significant bit.
fn lfsr_step(r: u64) -> u64 {
    let fb = ((r >> 63) ^ (r >> 61) ^ (r >> 45) ^ (r >> 37) ^ (r >> 26) ^ (r >> 14)) & 1;
    (r << 1) | fb
}

/// The shift undone: the old stage 64 is the new bit XOR the other taps.
fn lfsr_unstep(r: u64) -> u64 {
    let old_low = r >> 1; // the old bits 62..0, now 63..1
    let fb = r & 1;
    let tap = ((old_low >> 61) ^ (old_low >> 45) ^ (old_low >> 37) ^ (old_low >> 26) ^ (old_low >> 14)) & 1;
    old_low | ((fb ^ tap) << 63)
}

/// The MI of the next superframe: the register shifted 64 times.
pub fn next_mi(mi: &Mi) -> Mi {
    mi_of((0..64).fold(lfsr_of(mi), |r, _| lfsr_step(r)))
}

/// The MI of the superframe before (a receiver that joined mid-call learns
/// its first MI only as the next one, from the LDU2).
pub fn prev_mi(mi: &Mi) -> Mi {
    mi_of((0..64).fold(lfsr_of(mi), |r, _| lfsr_unstep(r)))
}

#[derive(Debug, PartialEq, Eq)]
pub enum CryptError {
    /// Not an algorithm this module has.
    UnsupportedAlgorithm(u8),
    /// A key of the wrong size for its algorithm.
    KeyLength { algid: u8, got: usize, want: usize },
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptError::UnsupportedAlgorithm(a) => write!(f, "algorithm {a:#04x} is not supported"),
            CryptError::KeyLength { algid, got, want } => write!(f, "algorithm {algid:#04x} takes a {want}-byte key, this one has {got}"),
        }
    }
}

impl std::error::Error for CryptError {}

/// Whether [`Keystream`] can make a stream for the algorithm.
pub fn supported(algid: u8) -> bool {
    key_len(algid).is_some()
}

/// The size of a key for the algorithm, bytes (None: not supported).
pub fn key_len(algid: u8) -> Option<usize> {
    match algid {
        ALGID_DES_OFB => Some(8),
        ALGID_AES256 => Some(32),
        ALGID_ADP => Some(5),
        _ => None,
    }
}

/// The keystream for one superframe: `octet(n)` is the one that goes with
/// plain text octet number `n` (1 to 213).
pub struct Keystream(Zeroizing<[u8; SUPERFRAME_OCTETS]>);

/// OFB: the first output (the MI encrypted) is not used; then one block per
/// pass, fed back whole.
fn ofb<C: BlockCipherEncrypt>(cipher: &C, iv: &[u8], out: &mut [u8]) {
    let m = iv.len();
    let mut block = Zeroizing::new(iv.to_vec());
    let mut taken = 0;
    for pass in 0.. {
        let mut b = cbc::cipher::Block::<C>::try_from(&block[..]).expect("a block");
        cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
        // (The cipher's output block is key-derived like the rest: wiped, not left on the stack.)
        b.as_mut_slice().zeroize();
        if pass > 0 {
            let n = (out.len() - taken).min(m);
            out[taken..taken + n].copy_from_slice(&block[..n]);
            taken += n;
        }
        if taken == out.len() {
            break;
        }
    }
}

/// RC4: the stream after dropping the first `skip` outputs.
fn rc4(key: &[u8], skip: usize, out: &mut [u8]) {
    // (The permutation is made from the key: wiped when dropped, as well as cleared below.)
    let mut s: zeroize::Zeroizing<[u8; 256]> = zeroize::Zeroizing::new(std::array::from_fn(|i| i as u8));
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for k in 0..skip + out.len() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let v = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        if k >= skip {
            out[k - skip] = v;
        }
    }
    s.fill(0);
}

impl Keystream {
    /// The superframe whose MI is `mi`, under `key`.
    pub fn new(algid: u8, key: &[u8], mi: &Mi) -> Result<Keystream, CryptError> {
        let want = key_len(algid).ok_or(CryptError::UnsupportedAlgorithm(algid))?;
        if key.len() != want {
            return Err(CryptError::KeyLength { algid, got: key.len(), want });
        }
        let mut out = Zeroizing::new([0u8; SUPERFRAME_OCTETS]);
        match algid {
            ALGID_DES_OFB => ofb(&Des::new_from_slice(key).expect("8-byte key"), &mi[..8], &mut out[..]),
            ALGID_AES256 => {
                // n = 128: the MI, then the one after it (figure 4-2, table 4-1).
                let mut iv = [0u8; 16];
                iv[..8].copy_from_slice(&mi[..8]);
                iv[8..].copy_from_slice(&next_mi(mi)[..8]);
                ofb(&Aes256::new_from_slice(key).expect("32-byte key"), &iv, &mut out[..]);
            }
            _ => {
                // ADP: RC4 keyed with the 40-bit key and the 64-bit MI.
                let mut k = Zeroizing::new([0u8; 13]);
                k[..5].copy_from_slice(key);
                k[5..].copy_from_slice(&mi[..8]);
                // The first 256 outputs are dropped.
                rc4(&k[..], 256, &mut out[..]);
            }
        }
        Ok(Keystream(out))
    }

    /// Decrypt (or encrypt) AMBE+2 frame `f` (0 to 17) of a Phase 2
    /// superframe: its 49 bits (u0..u3, MSB first) with the first 49 bits
    /// of its 7 keystream octets, which follow the first block's. Frame
    /// `f` is `4 * burst + k` in the 4V bursts 0 to 3 and `16 + k` in the 2V.
    pub fn apply_tdma(&self, f: usize, bits: &mut [u8; 49]) {
        debug_assert!(f < TDMA_FRAMES);
        let first = TDMA_OCTETS * f + 1;
        for (i, b) in bits.iter_mut().enumerate() {
            *b ^= (self.octet(first + i / 8) >> (7 - i % 8)) & 1;
        }
    }

    /// The keystream octet for plain text octet number `n` (1 to 213).
    pub fn octet(&self, n: usize) -> u8 {
        self.0[n - 1]
    }

    /// Decrypt (or encrypt: the same) IMBE frame `k` (0 to 8) of an LDU:
    /// its 88 information bits, MSB first as w0..w10.
    pub fn apply(&self, ldu2: bool, k: usize, bits: &mut [u8; 88]) {
        let first = frame_octet(ldu2, k);
        for (i, b) in bits.iter_mut().enumerate() {
            *b ^= (self.octet(first + i / 8) >> (7 - i % 8)) & 1;
        }
    }
}

/// Voice frames in a Phase 2 superframe on one logical channel: four 4V bursts and a 2V.
pub const TDMA_FRAMES: usize = 18;
/// Keystream octets a Phase 2 voice frame takes (56 bits for 49).
const TDMA_OCTETS: usize = 7;

/// The plain text octet number of the first octet of IMBE frame `k` (0 to 8)
/// of an LDU1 or LDU2 (standard tables 5-5 and 5-6): 3 reserved and 8 link
/// control octets come first, 2 low-speed data octets sit before the 9th
/// frame of each LDU.
pub fn frame_octet(ldu2: bool, k: usize) -> usize {
    debug_assert!(k < 9);
    let first = if ldu2 { 113 } else { 12 };
    first + 11 * k + if k == 8 { 2 } else { 0 }
}

/// A call's decryption state: the key named by the call, and the MI of the
/// superframe in progress. Feed it the header (Phase 1's HDU, Phase 2's
/// MAC_PTT) and the encryption sync that ends each superframe (an LDU2's,
/// a 2V burst's ESS); it decrypts frames when it holds the key and knows the MI.
pub struct Decryptor {
    keys: Arc<KeyStore>,
    algid: u8,
    kid: u16,
    /// The MI of the superframe in progress, when known.
    mi: Option<Mi>,
    /// The next superframe's, from this LDU2.
    next: Option<Mi>,
    stream: Option<Keystream>,
}

/// Why a frame was not decrypted.
#[derive(Debug, PartialEq, Eq)]
pub enum Skip {
    /// No key held for the call's algorithm and key id.
    NoKey,
    /// A key, but the MI is not known yet (joined mid-call).
    NoMi,
    /// The held key does not fit the algorithm.
    BadKey,
}

impl Decryptor {
    pub fn new(keys: Arc<KeyStore>) -> Self {
        Decryptor { keys, algid: ALGID_CLEAR, kid: 0, mi: None, next: None, stream: None }
    }

    /// A new call (or a transmission's end).
    pub fn reset(&mut self) {
        self.algid = ALGID_CLEAR;
        self.kid = 0;
        self.mi = None;
        self.next = None;
        self.stream = None;
    }

    /// The algorithm and key id the call names, once seen.
    pub fn key_named(&self) -> Option<(u8, u16)> {
        (self.algid != ALGID_CLEAR).then_some((self.algid, self.kid))
    }

    fn name(&mut self, es: &EncryptionSync) {
        if (es.algid, es.keyid) != (self.algid, self.kid) {
            self.algid = es.algid;
            self.kid = es.keyid;
            self.stream = None;
        }
    }

    /// A header data unit: the first superframe's MI.
    pub fn header(&mut self, es: &EncryptionSync) {
        self.name(es);
        self.next = None;
        self.mi = (es.algid != ALGID_CLEAR).then_some(es.mi);
        self.stream = None;
    }

    /// A superframe's encryption sync (an LDU2's, a Phase 2 ESS): it names
    /// the key and carries the next superframe's MI. A receiver that joined
    /// mid-call has no MI for this superframe yet; it is the one before the sync's.
    pub fn sync(&mut self, es: &EncryptionSync) {
        self.name(es);
        if es.algid == ALGID_CLEAR {
            // Nothing is encrypted now: no MI is kept from what was.
            self.mi = None;
            self.next = None;
            self.stream = None;
            return;
        }
        // This sync is authoritative: the superframe it ends is the one before the MI it carries.
        // (If a whole earlier superframe's sync was missed, the MI held is one behind: rebased here.)
        let current = prev_mi(&es.mi);
        if self.mi != Some(current) {
            self.mi = Some(current);
            self.stream = None;
        }
        self.next = Some(es.mi);
    }

    /// A superframe's voice is done: the next superframe's MI takes over
    /// (stepped from this one when the sync was lost).
    pub fn superframe_done(&mut self) {
        let next = self.next.take().or_else(|| self.mi.as_ref().map(next_mi));
        if next != self.mi {
            self.stream = None;
        }
        self.mi = next;
    }

    /// The keystream of the superframe in progress, made when first needed.
    fn stream(&mut self) -> Result<&Keystream, Skip> {
        let Some(mi) = self.mi else { return Err(Skip::NoMi) };
        if self.stream.is_none() {
            let Some(key) = self.keys.get(self.algid, self.kid) else { return Err(Skip::NoKey) };
            self.stream = Some(Keystream::new(self.algid, key.bytes(), &mi).map_err(|_| Skip::BadKey)?);
        }
        Ok(self.stream.as_ref().unwrap())
    }

    /// Decrypt IMBE frame `k` of the LDU in progress (Phase 1).
    pub fn decrypt(&mut self, ldu2: bool, k: usize, bits: &mut [u8; 88]) -> Result<(), Skip> {
        self.stream()?.apply(ldu2, k, bits);
        Ok(())
    }

    /// Decrypt AMBE+2 frame `f` (0 to 17) of the superframe in progress (Phase 2).
    pub fn decrypt_tdma(&mut self, f: usize, bits: &mut [u8; 49]) -> Result<(), Skip> {
        self.stream()?.apply_tdma(f, bits);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Key;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn mi(s: &str) -> Mi {
        let mut m = [0; 9];
        m[..8].copy_from_slice(&hex(s));
        m
    }

    fn bits(b: &[u8]) -> [u8; 88] {
        std::array::from_fn(|i| (b[i / 8] >> (7 - i % 8)) & 1)
    }

    fn bytes(b: &[u8; 88]) -> Vec<u8> {
        b.chunks(8).map(|c| c.iter().fold(0, |v, &x| (v << 1) | x)).collect()
    }

    // The standard's examples (TIA-102.AAAD tables 3-1, A.4, C.4 and annexes):
    // the header MI, and for each algorithm its key.
    const HEADER_MI: &str = "1234567890ABCDEF";
    const DES_KEY: &str = "0123456789ABCDEF";
    const AES_KEY: &str = "0123456789ABCDEF 23456789ABCDEF01 456789ABCDEF0123 6789ABCDEF012345";
    // Plain text for frames of the examples (the first IMBE frame the standard prints).
    const PLAIN: &str = "0CEE42225F61017B31DF14";

    #[test]
    fn mi_sequence_follows_the_standards_table() {
        // Table 3-1: the header, then superframes 1 to 4.
        let seq = ["1234567890ABCDEF", "6FE2802AA403828B", "FF35B1909449B835", "7EADFBE0D23ECDDF", "34B67525ADEE0EC7"];
        for w in seq.windows(2) {
            assert_eq!(next_mi(&mi(w[0])), mi(w[1]));
            assert_eq!(prev_mi(&mi(w[1])), mi(w[0]));
        }
        // The ninth octet is reserved: it neither feeds the register nor survives.
        let mut m = mi(HEADER_MI);
        m[8] = 0x5a;
        assert_eq!(next_mi(&m)[8], 0);
        assert_eq!(next_mi(&m)[..8], hex("6FE2802AA403828B")[..]);
    }

    #[test]
    fn des_keystream_matches_the_standards_annex_a() {
        let ks = Keystream::new(ALGID_DES_OFB, &hex(DES_KEY), &mi(HEADER_MI)).unwrap();
        // Output registers 2 and 3 (1 is not used); 28 gives the last 5 octets.
        let got = |a: usize, b: usize| (a..=b).map(|n| ks.octet(n)).collect::<Vec<_>>();
        assert_eq!(got(1, 8), hex("5D976A504786581F"));
        assert_eq!(got(9, 16), hex("5B0229C3443694E3"));
        assert_eq!(got(209, 213), hex("8518CD1B78"));
    }

    #[test]
    fn aes_keystream_matches_the_standards_annex_c() {
        let ks = Keystream::new(ALGID_AES256, &hex(AES_KEY), &mi(HEADER_MI)).unwrap();
        let got = |a: usize, b: usize| (a..=b).map(|n| ks.octet(n)).collect::<Vec<_>>();
        assert_eq!(got(1, 16), hex("A4A452206523E33BAD358AF571CB029A"));
        assert_eq!(got(193, 208), hex("321E62FAB980355BFA5EF396BCC07E65"));
        assert_eq!(got(209, 213), hex("B93586017F"));
    }

    #[test]
    fn frames_sit_where_the_standards_tables_put_them() {
        // Tables 5-5 and 5-6: the first octet number of frames 1, 8, 9, 10, 17, 18.
        let at = |ldu2, k| frame_octet(ldu2, k);
        assert_eq!([at(false, 0), at(false, 7), at(false, 8), at(true, 0), at(true, 7), at(true, 8)], [12, 89, 102, 113, 190, 203]);
        // The last frame ends on octet 213.
        assert_eq!(at(true, 8) + 10, SUPERFRAME_OCTETS);
    }

    #[test]
    fn frames_encrypt_as_the_examples_do() {
        let plain = hex(PLAIN);
        let enc = |algid: u8, key: &str, ldu2, k| {
            let ks = Keystream::new(algid, &hex(key), &mi(HEADER_MI)).unwrap();
            let mut b = bits(&plain);
            ks.apply(ldu2, k, &mut b);
            bytes(&b)
        };
        // DES, frame 1 of the standard's example: its printed cipher text.
        assert_eq!(enc(ALGID_DES_OFB, DES_KEY, false, 0), hex("CFAA74B6BC19F901BCB2B1"));
        assert_eq!(enc(ALGID_DES_OFB, DES_KEY, true, 0), hex("BF123D578E32F805832B45"));
        assert_eq!(enc(ALGID_DES_OFB, DES_KEY, true, 8), hex("A3D69DA02D108463FCC46C"));
        // AES, frames 1, 9 (after the low-speed data), 10 and 18.
        assert_eq!(enc(ALGID_AES256, AES_KEY, false, 0), hex("F99F8920C5F2AF84AA046F"));
        assert_eq!(enc(ALGID_AES256, AES_KEY, false, 8), hex("1BD0ED3270EBA533F4078D"));
        assert_eq!(enc(ALGID_AES256, AES_KEY, true, 0), hex("BDBF5996B873293A369BB7"));
        assert_eq!(enc(ALGID_AES256, AES_KEY, true, 8), hex("FF78FEE22104B84EB7DE6B"));
    }

    /// Phase 2: frame f takes octets 7f+1.. of the same keystream, 49 bits of the 56. The
    /// expected values were made by a separate implementation (Python) of the same layout
    /// op25 and DSD-FME use. (TIA-102.AAAD-B's worked examples check DES-OFB and AES-256 separately; ADP has
    /// no standard, and no Phase 2 capture checks it.)
    #[test]
    fn tdma_frames_take_seven_keystream_octets_each() {
        let plain = hex("0CEE42225F6180");
        let enc = |algid: u8, key: &str, f: usize| {
            let ks = Keystream::new(algid, &hex(key), &mi(HEADER_MI)).unwrap();
            let mut b: [u8; 49] = std::array::from_fn(|i| (plain[i / 8] >> (7 - i % 8)) & 1);
            ks.apply_tdma(f, &mut b);
            // The 49 bits as 7 octets, the 56th bit 0.
            let mut o = [0u8; 7];
            for (i, v) in b.iter().enumerate() {
                o[i / 8] |= v << (7 - i % 8);
            }
            o.to_vec()
        };
        type Case<'a> = (u8, &'a str, [(usize, &'a str); 6]);
        let cases: [Case; 3] = [
            (ALGID_DES_OFB, DES_KEY, [(0, "5179287218E780"), (3, "A99CE14124E880"), (4, "05AF41890CCD00"), (15, "02809B38430B00"), (16, "BF123D578E3200"), (17, "725CB673C65900")]),
            (ALGID_AES256, AES_KEY, [(0, "A84A10023A4200"), (3, "77DF3D9A046800"), (4, "44398C43CC7580"), (15, "2364E66A9AB900"), (16, "BDBF5996B87380"), (17, "4DE90681D6BB00")]),
            (ALGID_ADP, "deadbeef69", [(0, "3C6682A2E64800"), (3, "22336E7D52A400"), (4, "D8BFDBEE787F80"), (15, "0142A78D317400"), (16, "536742514F7C00"), (17, "ECA419821AF380")]),
        ];
        for (algid, key, frames) in cases {
            for (f, want) in frames {
                assert_eq!(enc(algid, key, f), hex(want), "algorithm {algid:#04x} frame {f}");
            }
        }
        // Applied twice, it is the plain text again.
        let ks = Keystream::new(ALGID_AES256, &hex(AES_KEY), &mi(HEADER_MI)).unwrap();
        let orig: [u8; 49] = std::array::from_fn(|i| (plain[i / 8] >> (7 - i % 8)) & 1);
        let mut b = orig;
        ks.apply_tdma(9, &mut b);
        assert_ne!(b, orig);
        ks.apply_tdma(9, &mut b);
        assert_eq!(b, orig);
    }

    /// A sync is authoritative: after a whole superframe whose sync was missed, the next one rebases the MI;
    /// a clear sync forgets it.
    #[test]
    fn a_sync_rebases_the_mi_and_a_clear_one_forgets_it() {
        let key = Arc::new({
            let mut s = KeyStore::new();
            s.insert(crate::crypto::Key::new(ALGID_DES_OFB, 7, "k".into(), 0, true, hex(DES_KEY)));
            s
        });
        let es = |mi: Mi, algid: u8| EncryptionSync { algid, keyid: 7, mi };
        let (m1, m2, m3) = (mi(HEADER_MI), next_mi(&mi(HEADER_MI)), next_mi(&next_mi(&mi(HEADER_MI))));
        let mut d = Decryptor::new(key);
        d.header(&es(m1, ALGID_DES_OFB));
        // Superframe 1's whole sync (and its end) was missed. Superframe 2's sync tells m3: the MI now is m2.
        d.sync(&es(m3, ALGID_DES_OFB));
        assert_eq!(d.mi, Some(m2), "rebased, not left one behind");
        d.sync(&es(m3, ALGID_CLEAR));
        assert_eq!((d.mi, d.next), (None, None), "a clear sync forgets the MI");
    }

    #[test]
    fn rc4_matches_the_classic_vector() {
        let mut out = [0u8; 10];
        rc4(b"Key", 0, &mut out);
        assert_eq!(out.to_vec(), hex("EB9F7781B734CA72A719"));
        let mut rest = [0u8; 7];
        rc4(b"Key", 3, &mut rest);
        assert_eq!(rest.to_vec(), hex("81B734CA72A719"));
    }

    #[test]
    fn wrong_sized_keys_and_unknown_algorithms_are_refused() {
        let m = mi(HEADER_MI);
        assert_eq!(Keystream::new(ALGID_AES256, &[0; 16], &m).err(), Some(CryptError::KeyLength { algid: 0x84, got: 16, want: 32 }));
        assert_eq!(Keystream::new(ALGID_DES_OFB, &[0; 7], &m).err(), Some(CryptError::KeyLength { algid: 0x81, got: 7, want: 8 }));
        assert_eq!(Keystream::new(ALGID_ADP, &[0; 8], &m).err(), Some(CryptError::KeyLength { algid: 0xaa, got: 8, want: 5 }));
        assert_eq!(Keystream::new(0x9f, &[0; 8], &m).err(), Some(CryptError::UnsupportedAlgorithm(0x9f)));
        assert!(!supported(0x9f) && supported(0x81));
    }

    fn store() -> Arc<KeyStore> {
        let mut s = KeyStore::new();
        s.insert(Key::new(ALGID_DES_OFB, 7, "des".into(), 0, true, hex(DES_KEY)));
        Arc::new(s)
    }

    fn es(mi: Mi, kid: u16) -> EncryptionSync {
        EncryptionSync { algid: ALGID_DES_OFB, keyid: kid, mi }
    }

    /// One superframe's 18 frames of known plain text, encrypted under `mi`.
    fn superframe(mi: &Mi) -> Vec<[u8; 88]> {
        let ks = Keystream::new(ALGID_DES_OFB, &hex(DES_KEY), mi).unwrap();
        (0..18)
            .map(|f| {
                let mut b = bits(&hex(&format!("{:02X}", f + 1).repeat(11)));
                ks.apply(f >= 9, f % 9, &mut b);
                b
            })
            .collect()
    }

    fn clear(f: usize) -> [u8; 88] {
        bits(&hex(&format!("{:02X}", f + 1).repeat(11)))
    }

    #[test]
    fn a_call_from_its_header_decrypts_across_superframes() {
        let (m1, m2) = (mi(HEADER_MI), next_mi(&mi(HEADER_MI)));
        let mut d = Decryptor::new(store());
        d.header(&es(m1, 7));
        for (sf, m) in [(0, m1), (1, m2)] {
            let frames = superframe(&m);
            for (f, fr) in frames.iter().enumerate().take(9) {
                let mut b = *fr;
                d.decrypt(false, f, &mut b).unwrap();
                assert_eq!(b, clear(f), "superframe {sf} frame {f}");
            }
            // This LDU2 tells the next superframe's MI; its own voice uses this one's.
            d.sync(&es(next_mi(&m), 7));
            for (f, fr) in frames.iter().enumerate().skip(9) {
                let mut b = *fr;
                d.decrypt(true, f - 9, &mut b).unwrap();
                assert_eq!(b, clear(f), "superframe {sf} frame {f}");
            }
            d.superframe_done();
        }
    }

    #[test]
    fn a_receiver_that_joins_at_an_ldu2_finds_its_mi() {
        let (m1, m2) = (mi(HEADER_MI), next_mi(&mi(HEADER_MI)));
        let mut d = Decryptor::new(store());
        // No header, no LDU1: the first thing heard is an LDU2 telling m2.
        d.sync(&es(m2, 7));
        let frames = superframe(&m1);
        for (f, fr) in frames.iter().enumerate().skip(9) {
            let mut b = *fr;
            d.decrypt(true, f - 9, &mut b).unwrap();
            assert_eq!(b, clear(f));
        }
        d.superframe_done();
        let frames = superframe(&m2);
        let mut b = frames[0];
        d.decrypt(false, 0, &mut b).unwrap();
        assert_eq!(b, clear(0));
    }

    #[test]
    fn a_lost_sync_steps_the_mi_on() {
        let (m1, m2) = (mi(HEADER_MI), next_mi(&mi(HEADER_MI)));
        let mut d = Decryptor::new(store());
        d.header(&es(m1, 7));
        d.superframe_done(); // this LDU2's sync did not decode
        let mut b = superframe(&m2)[0];
        d.decrypt(false, 0, &mut b).unwrap();
        assert_eq!(b, clear(0));
    }

    #[test]
    fn no_key_or_no_mi_leaves_the_frame_alone() {
        let m1 = mi(HEADER_MI);
        let mut b = superframe(&m1)[0];
        let before = b;
        // A key id we hold no key for.
        let mut d = Decryptor::new(store());
        d.header(&es(m1, 8));
        assert_eq!(d.decrypt(false, 0, &mut b), Err(Skip::NoKey));
        // Joined at an LDU1: no MI yet.
        let mut d = Decryptor::new(store());
        assert_eq!(d.decrypt(false, 0, &mut b), Err(Skip::NoMi));
        // A clear header holds no MI.
        d.header(&EncryptionSync { algid: 0x80, keyid: 0, mi: [0; 9] });
        assert_eq!(d.decrypt(false, 0, &mut b), Err(Skip::NoMi));
        assert_eq!(b, before);
        assert_eq!(d.key_named(), None);
    }
}
