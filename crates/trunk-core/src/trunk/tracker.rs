//! One voice channel's call tracker (Phase 1): HDU / LDU1 / LDU2 / TDU(LC)
//! frames → encryption and link-control state → IMBE vocoder → audio.
//! Takes receiver-diversity groups: header fields from the best NID, link
//! control / encryption sync from whichever copy decodes, each codeword from
//! the receiver the soft decoder trusted most.

use super::frames::{Codec, VoiceFrame};
use std::sync::Arc;

use crate::crypto::p25::{Decryptor, Skip};
use crate::crypto::KeyStore;
use crate::mbe::{self, Kind, FRAME_SAMPLES};
use crate::p25::alias::{is_alias_lcw, AliasLc, LcAliases};
use crate::p25::diversity::{best_es, best_frame, best_imbe, best_lc, Group};
use crate::p25::frame::{HDU, LDU1, LDU2, TDU, TDULC};
use crate::p25::voice::{decode_hdu, decode_tdulc, imbe_params_to_bits, ldu_codeword_end_bit, EncryptionSync, ALGID_CLEAR};
use super::voice::TrackerOut;


/// Algorithm id when encryption is known but not which cipher.
const ALGID_UNKNOWN: i32 = -1;

/// An LDU1 frame held until the LDU2 after it says which MI it was under.
struct Held {
    k: usize,
    u: [u32; 8],
    e0: u32,
    errs: u32,
    erased: bool,
}

/// Decryption of the current call: the keys, what the call named, and the
/// frames of a joined-mid-call LDU1 waiting for their MI.
struct Crypto {
    dec: Decryptor,
    held: Vec<Held>,
    /// What was last reported to the call: (algorithm, key id, decrypted).
    reported: Option<(u8, u16, bool)>,
}

pub struct VoiceTracker {
    dec: mbe::Decoder,
    active: bool,
    encrypted: bool,
    algid: i32,
    tgid: Option<u32>,
    /// The unit link control named for the current transmission.
    talker: Option<u32>,
    aliases: LcAliases,
    /// Decryption, when keys were given ([`VoiceTracker::set_keys`]).
    crypto: Option<Crypto>,
    call_frames: u64,
    end_s: f64,
    /// Vocoder frames / repeated or muted, over the channel's life.
    pub frames: u64,
    pub bad_frames: u64,
}

impl VoiceTracker {
    pub fn new(rng: mbe::Rng, vocoder: mbe::Profile) -> Self {
        VoiceTracker {
            dec: mbe::Decoder::new(rng, vocoder),
            active: false,
            encrypted: false,
            algid: ALGID_CLEAR as i32,
            tgid: None,
            talker: None,
            aliases: LcAliases::default(),
            crypto: None,
            call_frames: 0,
            end_s: 0.0,
            frames: 0,
            bad_frames: 0,
        }
    }

    /// Decrypt calls whose key `keys` holds. With no keys (or none given) an
    /// encrypted call is as before: flagged, and its voice not decoded.
    pub fn set_keys(&mut self, keys: Arc<KeyStore>) {
        self.crypto = (!keys.is_empty()).then(|| Crypto { dec: Decryptor::new(keys), held: Vec::new(), reported: None });
    }

    /// The talkgroup link control named for the current transmission.
    pub fn talkgroup(&self) -> Option<u32> {
        self.tgid
    }

    /// A frame group at time `t` (s, sample clock).
    pub fn group(&mut self, g: &Group, t: f64, out: &mut Vec<TrackerOut>) {
        let best = best_frame(g);
        match best.nid.duid {
            HDU => {
                let h = decode_hdu(&best.raw);
                self.algid = h.map_or(ALGID_CLEAR as i32, |h| h.es.algid as i32);
                self.start(t, h.map(|h| h.tgid as u32));
                if let (Some(c), Some(h)) = (&mut self.crypto, h) {
                    c.dec.header(&h.es);
                }
            }
            LDU1 | LDU2 => {
                self.touch(t);
                if best.nid.duid == LDU1 {
                    if let Some(lc) = best_lc(g) {
                        if lc.protected {
                            let a = if self.algid == ALGID_CLEAR as i32 { ALGID_UNKNOWN } else { self.algid };
                            self.set_encryption(a, out);
                        } else if lc.lco == 0 || lc.lco == 3 {
                            if let (Some(cur), Some(tg)) = (self.tgid, lc.tgid) {
                                if cur != tg && self.call_frames > 0 {
                                    self.start(t, None);
                                }
                            }
                            if lc.tgid.is_some() {
                                self.tgid = lc.tgid;
                            }
                            if lc.source.is_some_and(|s| s != 0) {
                                self.talker = lc.source;
                            }
                            let svc = lc.svc_opts.unwrap_or(0);
                            if svc & 0x40 != 0 && self.algid == ALGID_CLEAR as i32 {
                                self.set_encryption(ALGID_UNKNOWN, out);
                            }
                            out.push(TrackerOut::Info { source: lc.source, emergency: svc & 0x80 != 0, encrypted: self.encrypted });
                        } else if let Some(a) = self.aliases.lcw(&lc.raw, self.talker, self.tgid) {
                            out.push(TrackerOut::Alias(a));
                        }
                    }
                } else if let Some(es) = best_es(g) {
                    self.set_encryption(es.algid as i32, out);
                    self.ldu2_sync(&es, out);
                }
                // A cut frame (the next sync came early, in every receiver):
                // from the first codeword that fails its FEC or runs past the
                // cut, nothing is trusted — erasures.
                let complete = g.iter().any(|f| f.complete);
                let cut_at = (!complete).then(|| best.raw.len());
                let chosen = best_imbe(g);
                let ldu2 = best.nid.duid == LDU2;
                if ldu2 {
                    // Whatever the LDU1 before it held either has its MI now or never will.
                    self.release_held(out);
                }
                let mut erased = false;
                for (k, p) in chosen.iter().enumerate() {
                    if cut_at.is_some_and(|c| p.errs > 2 || ldu_codeword_end_bit(k) >= c) {
                        erased = true;
                    }
                    self.voice_frame(p.u, p.e0, p.errs, erased, (ldu2, k), out);
                }
                if let (true, Some(c)) = (ldu2, &mut self.crypto) {
                    c.dec.ldu2_done();
                }
            }
            TDU | TDULC => {
                // Link control from whichever receiver's copy decodes. Motorola
                // sends talker aliases here, in the terminators after the voice.
                let lc = g.iter().filter(|f| f.nid.duid == TDULC).find_map(|f| decode_tdulc(&f.raw));
                if let Some(lc) = lc {
                    let sign = if lc.protected {
                        AliasLc::Protected
                    } else if is_alias_lcw(&lc.raw) {
                        AliasLc::Fragment
                    } else {
                        AliasLc::Clear
                    };
                    out.push(TrackerOut::AliasLc(sign));
                }
                if let Some(lc) = lc.filter(|lc| !lc.protected) {
                    if self.active && self.tgid.is_none() {
                        self.tgid = lc.tgid;
                    }
                    if let Some(a) = self.aliases.lcw(&lc.raw, self.talker, self.tgid) {
                        out.push(TrackerOut::Alias(a));
                    }
                }
                self.active = false;
                self.algid = ALGID_CLEAR as i32;
                if let Some(c) = &mut self.crypto {
                    c.dec.reset();
                    c.held.clear();
                }
            }
            _ => {}
        }
    }

    fn start(&mut self, t: f64, tgid: Option<u32>) {
        self.dec.reset();
        self.active = true;
        self.tgid = tgid;
        self.talker = None;
        self.encrypted = self.algid != ALGID_CLEAR as i32;
        self.end_s = t;
        self.call_frames = 0;
        if let Some(c) = &mut self.crypto {
            c.dec.reset();
            c.held.clear();
            c.reported = None;
        }
    }

    fn touch(&mut self, t: f64) {
        if self.active && t - self.end_s > 1.0 {
            // Quiet with no terminator: the next transmission re-learns its cipher.
            self.active = false;
            self.algid = ALGID_CLEAR as i32;
            if let Some(c) = &mut self.crypto {
                c.dec.reset();
                c.held.clear();
            }
        }
        if !self.active {
            self.start(t, None);
        }
        self.end_s = t;
    }

    fn set_encryption(&mut self, algid: i32, out: &mut Vec<TrackerOut>) {
        self.algid = algid;
        if self.active && algid != ALGID_CLEAR as i32 && !self.encrypted {
            self.encrypted = true;
            out.push(TrackerOut::Info { source: None, emergency: false, encrypted: true });
        }
    }

    /// An LDU2's encryption sync, before its voice: it names the key and
    /// the next superframe's MI, which also tells a receiver that joined
    /// mid-call the MI of the superframe it is in.
    fn ldu2_sync(&mut self, es: &EncryptionSync, out: &mut Vec<TrackerOut>) {
        if let Some(c) = &mut self.crypto {
            c.dec.ldu2_sync(es);
        }
        self.release_held(out);
    }

    /// Decrypt the frames of an LDU1 that were waiting for their MI, if it is known now.
    fn release_held(&mut self, out: &mut Vec<TrackerOut>) {
        let Some(held) = self.crypto.as_mut().map(|c| std::mem::take(&mut c.held)).filter(|h| !h.is_empty()) else { return };
        for h in held {
            self.crypto_frame(h.u, h.e0, h.errs, h.erased, (false, h.k), false, out);
        }
    }

    fn voice_frame(&mut self, u: [u32; 8], e0: u32, errs: u32, erased: bool, at: (bool, usize), out: &mut Vec<TrackerOut>) {
        self.frames += 1;
        self.call_frames += 1;
        if self.encrypted {
            self.crypto_frame(u, e0, errs, erased, at, true, out);
            return;
        }
        self.vocode(imbe_params_to_bits(&u), e0, errs, erased, out);
    }

    /// A frame of an encrypted call: decrypted and vocoded when its key and
    /// MI are known, held (an LDU1 with no MI yet, when `may_hold`), or dropped.
    #[allow(clippy::too_many_arguments)]
    fn crypto_frame(&mut self, u: [u32; 8], e0: u32, errs: u32, erased: bool, (ldu2, k): (bool, usize), may_hold: bool, out: &mut Vec<TrackerOut>) {
        let Some(c) = &mut self.crypto else { return };
        let mut bits = imbe_params_to_bits(&u);
        let result = c.dec.decrypt(ldu2, k, &mut bits);
        let named = c.dec.key_named();
        let mut report = |c: &mut Crypto, decrypted| {
            if let Some((a, kid)) = named
                && c.reported != Some((a, kid, decrypted))
            {
                c.reported = Some((a, kid, decrypted));
                out.push(TrackerOut::Crypto { algid: a, key_id: kid, decrypted });
            }
        };
        match result {
            Ok(()) => {
                report(c, true);
                self.vocode(bits, e0, errs, erased, out);
            }
            Err(Skip::NoMi) if may_hold && !ldu2 && c.held.len() < 9 => c.held.push(Held { k, u, e0, errs, erased }),
            Err(Skip::NoMi) => {}
            Err(Skip::NoKey | Skip::BadKey) => report(c, false),
        }
    }

    fn vocode(&mut self, bits: [u8; 88], e0: u32, errs: u32, erased: bool, out: &mut Vec<TrackerOut>) {
        let mut buf = [0f32; FRAME_SAMPLES];
        let kind = self.dec.imbe(&bits, e0, if erased { 0 } else { errs }, erased, &mut buf);
        if kind != Kind::Voice {
            self.bad_frames += 1;
        }
        mbe::to_limited(&mut buf);
        let frame = VoiceFrame { codec: Codec::Imbe, bits: bits.to_vec(), e0, errs, erased, kind };
        out.push(TrackerOut::Audio(buf.to_vec(), frame));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::p25::{next_mi, Keystream, ALGID_DES_OFB};
    use crate::crypto::Key;

    const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const MI: [u8; 9] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0];

    fn keys() -> Arc<KeyStore> {
        let mut s = KeyStore::new();
        s.insert(Key::new(ALGID_DES_OFB, 7, "k".into(), 0, true, KEY.to_vec()));
        Arc::new(s)
    }

    fn es(mi: [u8; 9], kid: u16) -> EncryptionSync {
        EncryptionSync { algid: ALGID_DES_OFB, keyid: kid, mi }
    }

    /// The clear bits of frame `n` (0 to 17) of a superframe: something the vocoder takes.
    fn clear(n: usize) -> [u8; 88] {
        std::array::from_fn(|i| (((i * 7 + n * 13) / 3) & 1) as u8)
    }

    /// u0..u7 for 88 bits (the other way from `imbe_params_to_bits`).
    fn params(bits: &[u8; 88]) -> [u32; 8] {
        let mut u = [0u32; 8];
        let mut p = 0;
        for (k, w) in [12, 12, 12, 12, 11, 11, 11, 7].into_iter().enumerate() {
            for _ in 0..w {
                u[k] = (u[k] << 1) | bits[p] as u32;
                p += 1;
            }
        }
        u[7] <<= 1;
        u
    }

    /// The u words of superframe frame `n` as sent under `mi`.
    fn sent(mi: &[u8; 9], n: usize) -> [u32; 8] {
        let mut b = clear(n);
        Keystream::new(ALGID_DES_OFB, &KEY, mi).unwrap().apply(n >= 9, n % 9, &mut b);
        params(&b)
    }

    fn tracker(with_keys: bool) -> VoiceTracker {
        let mut t = VoiceTracker::new(mbe::lcg(1), mbe::Profile::Enhanced);
        if with_keys {
            t.set_keys(keys());
        }
        t.active = true;
        t.encrypted = true;
        t.algid = ALGID_DES_OFB as i32;
        t
    }

    fn frame_bits(out: &[TrackerOut]) -> Vec<Vec<u8>> {
        out.iter().filter_map(|o| if let TrackerOut::Audio(_, f) = o { Some(f.bits.clone()) } else { None }).collect()
    }

    fn crypto_events(out: &[TrackerOut]) -> Vec<(u8, u16, bool)> {
        out.iter().filter_map(|o| if let TrackerOut::Crypto { algid, key_id, decrypted } = o { Some((*algid, *key_id, *decrypted)) } else { None }).collect()
    }

    #[test]
    fn a_call_with_a_header_is_decrypted_and_says_so_once() {
        let mut t = tracker(true);
        t.crypto.as_mut().unwrap().dec.header(&es(MI, 7));
        let mut out = Vec::new();
        for k in 0..9 {
            t.voice_frame(sent(&MI, k), 0, 0, false, (false, k), &mut out);
        }
        assert_eq!(crypto_events(&out), [(0x81, 7, true)]);
        let got = frame_bits(&out);
        assert_eq!(got.len(), 9);
        for (k, g) in got.iter().enumerate() {
            assert_eq!(g[..], clear(k)[..], "frame {k}");
        }
        // The LDU2: its sync names the next MI, the voice is still this one's.
        t.ldu2_sync(&es(next_mi(&MI), 7), &mut out);
        out.clear();
        for k in 0..9 {
            t.voice_frame(sent(&MI, 9 + k), 0, 0, false, (true, k), &mut out);
        }
        t.crypto.as_mut().unwrap().dec.ldu2_done();
        assert_eq!(frame_bits(&out).iter().enumerate().filter(|(k, g)| g[..] == clear(9 + k)[..]).count(), 9);
        // The next superframe is under the next MI.
        out.clear();
        t.voice_frame(sent(&next_mi(&MI), 0), 0, 0, false, (false, 0), &mut out);
        assert_eq!(frame_bits(&out)[0][..], clear(0)[..]);
        assert!(crypto_events(&out).is_empty());
    }

    #[test]
    fn a_call_joined_at_an_ldu1_waits_for_the_ldu2_for_its_mi() {
        // No header: all that is known is that it is encrypted (protected link control).
        let mut t = tracker(true);
        t.algid = ALGID_UNKNOWN;
        let mut out = Vec::new();
        for k in 0..9 {
            t.voice_frame(sent(&MI, k), 0, 0, false, (false, k), &mut out);
        }
        assert!(out.is_empty(), "nothing is said before the MI is known");
        // The LDU2's sync tells the next MI; the one before it is this superframe's.
        t.ldu2_sync(&es(next_mi(&MI), 7), &mut out);
        assert_eq!(crypto_events(&out), [(0x81, 7, true)]);
        let got = frame_bits(&out);
        assert_eq!(got.len(), 9);
        for (k, g) in got.iter().enumerate() {
            assert_eq!(g[..], clear(k)[..], "held frame {k}");
        }
        out.clear();
        t.voice_frame(sent(&MI, 9), 0, 0, false, (true, 0), &mut out);
        assert_eq!(frame_bits(&out)[0][..], clear(9)[..]);
    }

    #[test]
    fn held_frames_with_no_sync_after_them_are_dropped() {
        let mut t = tracker(true);
        t.algid = ALGID_UNKNOWN;
        let mut out = Vec::new();
        for k in 0..9 {
            t.voice_frame(sent(&MI, k), 0, 0, false, (false, k), &mut out);
        }
        // The LDU2 comes, its sync lost: nothing can be said of these frames.
        t.release_held(&mut out);
        assert!(out.is_empty());
        assert!(t.crypto.as_ref().unwrap().held.is_empty());
    }

    #[test]
    fn a_key_we_do_not_hold_is_reported_and_nothing_is_decoded() {
        let mut t = tracker(true);
        t.crypto.as_mut().unwrap().dec.header(&es(MI, 8));
        let mut out = Vec::new();
        for k in 0..9 {
            t.voice_frame(sent(&MI, k), 0, 0, false, (false, k), &mut out);
        }
        assert!(frame_bits(&out).is_empty());
        assert_eq!(crypto_events(&out), [(0x81, 8, false)]);
    }

    #[test]
    fn with_no_keys_an_encrypted_call_is_as_it_always_was() {
        let mut t = tracker(false);
        let mut out = Vec::new();
        for k in 0..9 {
            t.voice_frame(sent(&MI, k), 0, 0, false, (false, k), &mut out);
        }
        t.ldu2_sync(&es(next_mi(&MI), 7), &mut out);
        assert!(out.is_empty());
        assert_eq!(t.frames, 9);
        // An empty key store is no keys.
        let mut t = tracker(false);
        t.set_keys(Arc::new(KeyStore::new()));
        assert!(t.crypto.is_none());
    }

    #[test]
    fn a_clear_call_never_touches_the_decryptor() {
        let mut t = VoiceTracker::new(mbe::lcg(1), mbe::Profile::Enhanced);
        t.set_keys(keys());
        let mut out = Vec::new();
        let u = params(&clear(0));
        t.voice_frame(u, 0, 0, false, (false, 0), &mut out);
        assert_eq!(frame_bits(&out)[0][..], clear(0)[..]);
        assert!(crypto_events(&out).is_empty());
    }
}
