//! One Phase 2 TDMA voice channel's tracker: slot packets → descramble →
//! burst type → voice codewords (AMBE+2, per logical channel) or MAC PDUs
//! (PTT / END_PTT: who is talking, which cipher). Two logical channels
//! (TDMA slots 0 and 1) share the frequency; each has its own vocoder and
//! burst counting. After op25 p25p2_tdma.cc handle_packet.

use std::sync::Arc;

use super::frames::{Codec, VoiceFrame};
use super::voice::TrackerOut;
use crate::ambe::{decode_vcw, AmbeFrame};
use crate::crypto::p25::{Decryptor, Skip};
use crate::crypto::KeyStore;
use crate::mbe::{self, Kind, FRAME_SAMPLES};
use crate::p25::alias::{is_alias_msg, mac_messages, mac_talker, AliasLc, MacAliases};
use crate::p25::phase2::{
    decode_acch, decode_ess, duid_decode, isch_lookup, parse_mac_ptt, read_ess_a, read_ess_b, xor_mask, Packet, BURST_2V, BURST_4V,
    BURST_FACCH_S, BURST_FACCH_U, BURST_LCCH_S, BURST_SACCH_S, BURST_SACCH_U, BURST_DIBITS, MAC_ACTIVE, MAC_END_PTT, MAC_HANGTIME, MAC_IDLE, MAC_PTT,
    MAC_SIGNAL, SLOT_CHANNEL, SLOT_DIBITS,
};
use crate::p25::voice::{EncryptionSync, ALGID_CLEAR};

/// A slot's decryption: the keys, and what was last reported to its call.
struct Crypto {
    dec: Decryptor,
    /// (algorithm, key id, decrypted), as [`TrackerOut::Crypto`] said it.
    reported: Option<(u8, u16, bool)>,
}

impl Crypto {
    /// A new transmission: nothing named or reported.
    fn reset(&mut self) {
        self.dec.reset();
        self.reported = None;
    }

    fn report(&mut self, c: usize, decrypted: bool, out: &mut Vec<(usize, TrackerOut)>) {
        if let Some((algid, key_id)) = self.dec.key_named()
            && self.reported != Some((algid, key_id, decrypted))
        {
            self.reported = Some((algid, key_id, decrypted));
            out.push((c, TrackerOut::Crypto { algid, key_id, decrypted }));
        }
    }
}

struct Slot {
    dec: mbe::Decoder,
    active: bool,
    encrypted: bool,
    algid: u8,
    burst_id: i32,
    first4v: i32,
    ess_b: [u8; 16],
    next_algid: u8,
    end_s: f64,
    /// Who is talking (MAC_PTT, Group Voice Channel User), until the transmission ends.
    talker: Option<u32>,
    talkgroup: Option<u32>,
    aliases: MacAliases,
    /// Decryption, when keys were given ([`TdmaTracker::set_keys`]).
    crypto: Option<Crypto>,
    /// Whether the call's cipher is known: from its PTT, or an ESS. Joined mid-call it isn't until
    /// the first ESS, at the end of a superframe; with keys, the voice before it is held.
    known: bool,
    /// The 4V bursts' frames since the last superframe's end, held until the cipher is known.
    held: Vec<AmbeFrame>,
}

impl Slot {
    /// The cipher is known now (an ESS): the frames held for it. Of a clear call they are voice,
    /// a little late; of an encrypted one, they are a whole superframe's 4V frames only when 16
    /// were held (so their places are known) and are decrypted then; else they are lost.
    fn release_held(&mut self, c: usize, out: &mut Vec<(usize, TrackerOut)>) {
        let held = std::mem::take(&mut self.held);
        if self.encrypted && held.len() != 16 {
            return;
        }
        for (i, f) in held.into_iter().enumerate() {
            self.voice_frame(c, Some(i), f, out);
        }
    }

    /// One voice frame of logical channel `c`, `idx`th of its superframe
    /// (None: its place isn't known): decrypted when the call is encrypted
    /// and its key and MI are known, vocoded, and given to `out`. What the
    /// vocoder made of it, when it made audio.
    fn voice_frame(&mut self, c: usize, idx: Option<usize>, f: AmbeFrame, out: &mut Vec<(usize, TrackerOut)>) -> Option<Kind> {
        let mut bits = f.bits;
        if self.encrypted {
            let cr = self.crypto.as_mut()?;
            match idx.map(|i| cr.dec.decrypt_tdma(i, &mut bits)) {
                Some(Ok(())) => cr.report(c, true, out),
                Some(Err(Skip::NoKey | Skip::BadKey)) => {
                    cr.report(c, false, out);
                    return None;
                }
                Some(Err(Skip::NoMi)) | None => return None,
            }
        }
        let mut buf = [0f32; FRAME_SAMPLES];
        let kind = self.dec.ambe(&bits, f.errs, &mut buf);
        mbe::to_limited(&mut buf);
        let frame = VoiceFrame { codec: Codec::Ambe, bits: bits.to_vec(), e0: 0, errs: f.errs, erased: false, kind };
        out.push((c, TrackerOut::Audio(buf.to_vec(), frame)));
        Some(kind)
    }

    fn new(rng: mbe::Rng) -> Self {
        Slot {
            dec: mbe::Decoder::new(rng, mbe::Profile::Enhanced),
            active: false,
            encrypted: false,
            algid: ALGID_CLEAR,
            burst_id: -1,
            first4v: -1,
            ess_b: [0; 16],
            next_algid: ALGID_CLEAR,
            end_s: 0.0,
            talker: None,
            talkgroup: None,
            aliases: MacAliases::default(),
            crypto: None,
            known: false,
            held: Vec::new(),
        }
    }
}

pub struct TdmaTracker {
    slots: [Slot; 2],
    mask: Option<Vec<u8>>,
    key: Option<(u32, u32, u32)>,
    /// Use bit reliabilities for the AMBE c1 word.
    pub soft: bool,
    /// Vocoder frames / repeated, muted or erased, over the channel's life.
    pub frames: u64,
    pub bad_frames: u64,
    /// Scrambled bursts seen before the key (WACN / System ID / NAC) was known.
    pub undecodable: u64,
    /// MAC PDUs decoded (PTT, END_PTT, …).
    pub mac_pdus: u64,
}

impl TdmaTracker {
    pub fn new(seed: u32) -> Self {
        TdmaTracker {
            slots: [Slot::new(mbe::lcg(seed)), Slot::new(mbe::lcg(seed ^ 0x5a5a_5a5a))],
            mask: None,
            key: None,
            soft: true,
            frames: 0,
            bad_frames: 0,
            undecodable: 0,
            mac_pdus: 0,
        }
    }

    /// Decrypt calls whose key `keys` holds (on both slots). With none, an
    /// encrypted call is flagged and its voice not decoded, as it always was.
    pub fn set_keys(&mut self, keys: Arc<KeyStore>) {
        for s in &mut self.slots {
            s.crypto = (!keys.is_empty()).then(|| Crypto { dec: Decryptor::new(keys.clone()), reported: None });
        }
    }

    /// The scrambler seed: NAC, System ID, WACN (from the control channel).
    pub fn set_key(&mut self, nac: u32, sys_id: u32, wacn: u32) {
        if self.key != Some((nac, sys_id, wacn)) {
            self.key = Some((nac, sys_id, wacn));
            self.mask = Some(xor_mask(nac, sys_id, wacn));
        }
    }

    /// One slot packet at time `t` (s); what it produced goes to `out` as
    /// (logical channel, output).
    pub fn packet(&mut self, p: &Packet, t: f64, out: &mut Vec<(usize, TrackerOut)>) {
        let c = SLOT_CHANNEL[p.sf_slot];
        let burstp = &p.dibits[10..];
        let kind = duid_decode(burstp);
        if kind < 0 {
            return;
        }
        let scrambled = matches!(kind, BURST_4V | BURST_2V | BURST_SACCH_S | BURST_LCCH_S | BURST_FACCH_S);
        let mut x = [0u8; BURST_DIBITS];
        x.copy_from_slice(&burstp[..BURST_DIBITS]);
        if scrambled {
            let Some(m) = self.mask.as_ref() else {
                self.undecodable += 1;
                return;
            };
            let base = p.sf_slot * SLOT_DIBITS;
            for (i, v) in x.iter_mut().enumerate() {
                *v ^= m[base + i];
            }
        }
        let rel = |a: usize| &p.rel[2 * (10 + a)..2 * (10 + a) + 72];
        let s = &mut self.slots[c];

        if kind == BURST_4V || kind == BURST_2V {
            // op25 track_vb
            let current = (p.sf_slot >> 1) as i32;
            s.burst_id += 1;
            s.burst_id = if kind == BURST_4V { s.burst_id % 5 } else { 4 };
            let last_rc = isch_lookup(&p.dibits);
            if kind == BURST_2V && last_rc >= 0 {
                s.first4v = (current + 1) % 5;
            }
            if s.first4v >= 0 && last_rc >= 0 {
                let mut cs = current;
                if cs < s.first4v {
                    cs += 5;
                }
                cs -= s.first4v;
                if cs != s.burst_id && cs > s.burst_id {
                    s.burst_id = cs;
                }
            }
            if !s.active || t - s.end_s > 1.0 {
                // Joined mid-transmission (no PTT heard): cipher unknown until the ESS.
                s.dec.reset();
                s.active = true;
                s.encrypted = false;
                s.algid = ALGID_CLEAR;
                if let Some(cr) = &mut s.crypto {
                    cr.reset();
                }
                s.known = false;
                s.held.clear();
            }
            s.end_s = t;
            // ESS (op25 handle_4V2V_ess)
            if s.burst_id < 4 {
                let hb = read_ess_b(&x);
                let b = 4 * s.burst_id as usize;
                s.ess_b[b..b + 4].copy_from_slice(&hb);
            } else if let Some(ess) = decode_ess(&s.ess_b, &read_ess_a(&x)) {
                s.next_algid = ess.algid;
                if ess.algid != ALGID_CLEAR {
                    Self::set_encryption(s, c, ess.algid, out);
                }
                // It names the key, and the next superframe's MI (which, to a receiver
                // that joined mid-call, also gives this one's).
                if let Some(cr) = &mut s.crypto {
                    cr.dec.sync(&EncryptionSync { algid: ess.algid, keyid: ess.keyid, mi: ess.mi });
                }
                s.known = true;
                s.release_held(c, out);
            }
            let at: &[usize] = if kind == BURST_4V { &[11, 48, 96, 133] } else { &[11, 48] };
            for (k, &a) in at.iter().enumerate() {
                let f = decode_vcw(&x[a..a + 36], self.soft.then(|| rel(a)));
                self.frames += 1;
                if s.crypto.is_some() && !s.known {
                    // Clear or encrypted isn't known yet: a 4V burst's frames wait for the ESS.
                    if kind == BURST_4V {
                        s.held.push(f);
                        if s.held.len() > 16 {
                            s.held.remove(0);
                        }
                    }
                    continue;
                }
                // Which of the superframe's 18 frames it is: 4 to each 4V burst, the 2V's 2 last
                // (a 4V burst out of step has no place in it).
                let idx = match kind {
                    BURST_4V => (s.burst_id < 4).then(|| s.burst_id as usize * 4 + k),
                    _ => Some(16 + k),
                };
                if s.voice_frame(c, idx, f, out).is_some_and(|k| k != Kind::Voice) {
                    self.bad_frames += 1;
                }
            }
            if kind == BURST_2V {
                // (The superframe is over; what is still held had no ESS to say what it was.)
                s.held.clear();
                let a = s.next_algid;
                Self::set_encryption(s, c, a, out);
                // The superframe is over: the MI its ESS gave (or the LFSR's step) is the next one's.
                if let Some(cr) = &mut s.crypto {
                    cr.dec.superframe_done();
                }
            }
            return;
        }

        if matches!(kind, BURST_SACCH_S | BURST_SACCH_U | BURST_FACCH_S | BURST_FACCH_U) {
            let Some(pdu) = decode_acch(&x, kind == BURST_FACCH_S || kind == BURST_FACCH_U) else { return };
            self.mac_pdus += 1;
            match pdu.opcode {
                MAC_PTT => {
                    let ptt = parse_mac_ptt(&pdu.bytes);
                    s.dec.reset();
                    s.active = true;
                    s.end_s = t;
                    s.algid = ptt.algid;
                    s.encrypted = ptt.algid != ALGID_CLEAR;
                    s.first4v = ((p.sf_slot >> 1) as i32 + pdu.offset as i32 + 1) % 5;
                    s.burst_id = -1;
                    s.talker = (ptt.source != 0).then_some(ptt.source);
                    s.talkgroup = (ptt.group != 0).then_some(ptt.group);
                    if let Some(cr) = &mut s.crypto {
                        cr.reset();
                        cr.dec.header(&EncryptionSync { algid: ptt.algid, keyid: ptt.keyid, mi: ptt.mi });
                    }
                    s.known = true;
                    s.held.clear();
                    out.push((c, TrackerOut::Info { source: (ptt.source != 0).then_some(ptt.source), emergency: false, encrypted: s.encrypted }));
                }
                MAC_END_PTT => {
                    s.active = false;
                    s.algid = ALGID_CLEAR;
                    s.talker = None;
                    if let Some(cr) = &mut s.crypto {
                        cr.reset();
                    }
                    s.known = false;
                    s.held.clear();
                }
                MAC_ACTIVE => s.first4v = if pdu.offset > 4 { 0 } else { pdu.offset as i32 },
                _ => {}
            }
            // The messages a SIGNAL / IDLE / ACTIVE / HANGTIME PDU carries (op25 decode_mac_msg).
            if matches!(pdu.opcode, MAC_SIGNAL | MAC_IDLE | MAC_ACTIVE | MAC_HANGTIME) {
                let bytes = if pdu.opcode == MAC_SIGNAL { &pdu.bytes[..pdu.bytes.len().min(18)] } else { &pdu.bytes[..] };
                for m in mac_messages(bytes) {
                    if let Some(u) = mac_talker(&m) {
                        s.talker = Some(u);
                    }
                    if is_alias_msg(&m) {
                        out.push((c, TrackerOut::AliasLc(AliasLc::MacFragment)));
                    }
                    if let Some(a) = s.aliases.msg(&m, s.talker, s.talkgroup) {
                        out.push((c, TrackerOut::Alias(a)));
                    }
                }
                if pdu.opcode == MAC_HANGTIME {
                    s.talker = None;
                }
            }
        }
    }

    fn set_encryption(s: &mut Slot, c: usize, algid: u8, out: &mut Vec<(usize, TrackerOut)>) {
        s.algid = algid;
        if s.active && algid != ALGID_CLEAR && !s.encrypted {
            s.encrypted = true;
            out.push((c, TrackerOut::Info { source: None, emergency: false, encrypted: true }));
        }
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

    /// The clear bits of frame `n` (0 to 17) of a superframe.
    fn clear(n: usize) -> [u8; 49] {
        std::array::from_fn(|i| (((i * 5 + n * 11) / 2) & 1) as u8)
    }

    /// Frame `n` as sent under `mi`.
    fn sent(mi: &[u8; 9], n: usize) -> AmbeFrame {
        let mut bits = clear(n);
        Keystream::new(ALGID_DES_OFB, &KEY, mi).unwrap().apply_tdma(n, &mut bits);
        AmbeFrame { bits, errs: 0 }
    }

    fn slot(with_keys: bool) -> Slot {
        let mut s = Slot::new(mbe::lcg(1));
        if with_keys {
            s.crypto = Some(Crypto { dec: Decryptor::new(keys()), reported: None });
        }
        s.active = true;
        s.encrypted = true;
        s
    }

    fn audio(out: &[(usize, TrackerOut)]) -> Vec<Vec<u8>> {
        out.iter().filter_map(|(_, o)| if let TrackerOut::Audio(_, f) = o { Some(f.bits.clone()) } else { None }).collect()
    }

    fn events(out: &[(usize, TrackerOut)]) -> Vec<(usize, u8, u16, bool)> {
        out.iter().filter_map(|(c, o)| if let TrackerOut::Crypto { algid, key_id, decrypted } = o { Some((*c, *algid, *key_id, *decrypted)) } else { None }).collect()
    }

    #[test]
    fn a_call_from_its_ptt_is_decrypted_through_the_superframes() {
        let mut s = slot(true);
        s.crypto.as_mut().unwrap().dec.header(&es(MI, 7));
        let mut out = Vec::new();
        for n in 0..18 {
            // This superframe's last burst: its ESS names the next MI before its 2 frames.
            if n == 16 {
                s.crypto.as_mut().unwrap().dec.sync(&es(next_mi(&MI), 7));
            }
            assert!(s.voice_frame(1, Some(n), sent(&MI, n), &mut out).is_some());
        }
        s.crypto.as_mut().unwrap().dec.superframe_done();
        assert_eq!(events(&out), [(1, 0x81, 7, true)], "said once, on the slot's channel");
        let got = audio(&out);
        assert_eq!(got.len(), 18);
        for (n, g) in got.iter().enumerate() {
            assert_eq!(g[..], clear(n)[..], "frame {n}");
        }
        // The next superframe is under the next MI.
        out.clear();
        s.voice_frame(1, Some(0), sent(&next_mi(&MI), 0), &mut out);
        assert_eq!(audio(&out)[0][..], clear(0)[..]);
        assert!(events(&out).is_empty());
    }

    /// Joined mid-superframe: the 4V bursts before the first 2V can't be placed or decrypted;
    /// from the 2V on (its ESS gives the MI), everything is.
    #[test]
    fn a_call_joined_mid_superframe_is_decrypted_from_its_first_2v_burst() {
        let mut s = slot(true);
        let mut out = Vec::new();
        for n in 0..8 {
            assert!(s.voice_frame(0, Some(n), sent(&MI, n), &mut out).is_none(), "no MI yet: frame {n} is dropped");
        }
        assert!(out.is_empty());
        s.crypto.as_mut().unwrap().dec.sync(&es(next_mi(&MI), 7));
        for n in 16..18 {
            s.voice_frame(0, Some(n), sent(&MI, n), &mut out);
        }
        s.crypto.as_mut().unwrap().dec.superframe_done();
        assert_eq!(audio(&out).iter().enumerate().filter(|(i, g)| g[..] == clear(16 + i)[..]).count(), 2);
        out.clear();
        for n in 0..4 {
            s.voice_frame(0, Some(n), sent(&next_mi(&MI), n), &mut out);
        }
        assert_eq!(audio(&out).len(), 4);
    }

    #[test]
    fn a_key_we_do_not_hold_is_reported_once_and_nothing_decoded() {
        let mut s = slot(true);
        s.crypto.as_mut().unwrap().dec.header(&es(MI, 8));
        let mut out = Vec::new();
        for n in 0..18 {
            assert!(s.voice_frame(0, Some(n), sent(&MI, n), &mut out).is_none());
        }
        assert!(audio(&out).is_empty());
        assert_eq!(events(&out), [(0, 0x81, 8, false)]);
    }

    #[test]
    fn a_frame_out_of_place_is_not_decrypted() {
        let mut s = slot(true);
        s.crypto.as_mut().unwrap().dec.header(&es(MI, 7));
        let mut out = Vec::new();
        assert!(s.voice_frame(0, None, sent(&MI, 0), &mut out).is_none());
        assert!(out.is_empty());
    }

    #[test]
    fn with_no_keys_an_encrypted_call_is_as_it_always_was() {
        let mut s = slot(false);
        let mut out = Vec::new();
        for n in 0..18 {
            assert!(s.voice_frame(0, Some(n), sent(&MI, n), &mut out).is_none());
        }
        assert!(out.is_empty());
        let mut t = TdmaTracker::new(1);
        t.set_keys(Arc::new(KeyStore::new()));
        assert!(t.slots.iter().all(|s| s.crypto.is_none()));
        t.set_keys(keys());
        assert!(t.slots.iter().all(|s| s.crypto.is_some()));
    }

    #[test]
    fn a_clear_call_never_touches_the_decryptor() {
        let mut s = slot(true);
        s.encrypted = false;
        let mut out = Vec::new();
        assert!(s.voice_frame(0, Some(3), AmbeFrame { bits: clear(3), errs: 0 }, &mut out).is_some());
        assert_eq!(audio(&out)[0][..], clear(3)[..]);
        assert!(events(&out).is_empty());
    }

    /// What the engine makes of a decrypted call's outputs, superframe after superframe: the
    /// transmission is never left marked encrypted, which would drop its audio when saved.
    #[test]
    fn a_decrypted_call_is_never_left_marked_encrypted() {
        use crate::trunk::record::Transmissions;
        let mut s = slot(true);
        s.crypto.as_mut().unwrap().dec.header(&es(MI, 7));
        let mut tx = Transmissions::default();
        let (mut out, mut mi, mut t, mut samples) = (Vec::new(), MI, 0.0, 0usize);
        // The PTT says the call is encrypted.
        out.push((0, TrackerOut::Info { source: Some(5), emergency: false, encrypted: true }));
        for sf in 0..4 {
            for n in 0..18 {
                if n == 16 {
                    s.crypto.as_mut().unwrap().dec.sync(&es(next_mi(&mi), 7));
                }
                s.voice_frame(0, Some(n), sent(&mi, n), &mut out);
                for (_, o) in out.drain(..).collect::<Vec<_>>() {
                    match o {
                        TrackerOut::Info { encrypted: true, .. } => tx.mark_encrypted(t),
                        TrackerOut::Crypto { decrypted: true, .. } => tx.mark_decrypted(t),
                        TrackerOut::Audio(a, _) => {
                            tx.note(samples, t);
                            samples += a.len();
                        }
                        _ => {}
                    }
                }
                t += 0.02;
            }
            // The superframe's end, as the tracker does it.
            TdmaTracker::set_encryption(&mut s, 0, ALGID_DES_OFB, &mut out);
            assert!(out.is_empty(), "superframe {sf}: an encrypted call is not announced again");
            s.crypto.as_mut().unwrap().dec.superframe_done();
            mi = next_mi(&mi);
        }
        assert!(samples > 0);
        assert!(!tx.current_encrypted());
        assert_eq!(tx.kept(samples, 0.0, 8000), None, "nothing of it is left out");
    }
}
